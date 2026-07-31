import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../src/keys';
import {
  proveDisclosedJson,
  verifyDisclosedJson,
  commitHiddenJson,
  verifyOpenedCommitment,
} from '../src/json-proof';
import { InvalidProofError, InvalidCommitmentError } from '../src/errors';
import { parseJsonDocument, parseJsonFile } from '../src/json-input';

describe('proveDisclosedJson / verifyDisclosedJson', () => {
  it('verifies a simple object', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const json = { userId: 'alice', role: 'admin', timestamp: 1_234_567_890 };
    const env = proveDisclosedJson(privateKey, json);
    expect(verifyDisclosedJson(publicKey, json, env)).toBe(true);
  });

  it('verifies regardless of input key order (canonical JSON)', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const env = proveDisclosedJson(privateKey, { b: 2, a: 1 });
    expect(verifyDisclosedJson(publicKey, { a: 1, b: 2 }, env)).toBe(true);
  });

  it('rejects tampered JSON', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const env = proveDisclosedJson(privateKey, { role: 'user' });
    expect(verifyDisclosedJson(publicKey, { role: 'admin' }, env)).toBe(false);
  });

  it('rejects wrong public key', () => {
    const { privateKey } = generateKeyPair();
    const { publicKey: other } = generateKeyPair();
    const env = proveDisclosedJson(privateKey, { x: 1 });
    expect(verifyDisclosedJson(other, { x: 1 }, env)).toBe(false);
  });

  it('envelope has expected shape', () => {
    const { privateKey } = generateKeyPair();
    const env = proveDisclosedJson(privateKey, { x: 1 });
    expect(env.version).toBe(1);
    expect(env.type).toBe('disclosed');
    expect(typeof env.json_hash).toBe('string');
    expect(typeof env.proof.R).toBe('string');
    expect(typeof env.proof.s).toBe('string');
    expect(typeof env.public_key).toBe('string');
    expect(typeof env.created_at).toBe('number');
    // All binary fields are base64url (no padding)
    for (const field of [env.json_hash, env.proof.R, env.proof.s, env.public_key]) {
      expect(field).not.toMatch(/[=+/]/);
    }
  });

  it('throws on wrong type in envelope', () => {
    const { publicKey } = generateKeyPair();
    const fakeEnv = {
      version: 1 as const,
      type: 'hidden' as const,
      json_hash: '',
      commitment: '',
      proof: { R: '', s: '' },
      public_key: '',
      created_at: 0,
    };
    expect(() => verifyDisclosedJson(publicKey, {}, fakeEnv as any)).toThrow(InvalidProofError);
  });

  it('proves arrays and deeply nested objects', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const json = { items: [1, 'two', { three: true }], meta: { deep: null, n: 0 } };
    const env = proveDisclosedJson(privateKey, json);
    expect(verifyDisclosedJson(publicKey, json, env)).toBe(true);
  });

  it('proves null, boolean, number primitives', () => {
    const { privateKey, publicKey } = generateKeyPair();
    for (const prim of [null, true, false, 0, 42, -1, 3.14]) {
      const env = proveDisclosedJson(privateKey, prim);
      expect(verifyDisclosedJson(publicKey, prim, env)).toBe(true);
    }
  });

  it('is JSON-serialisation round-trippable', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const json = { claim: 'identity', sub: 'alice' };
    const env = proveDisclosedJson(privateKey, json);
    const roundTripped = JSON.parse(JSON.stringify(env));
    expect(verifyDisclosedJson(publicKey, json, roundTripped)).toBe(true);
  });
});

describe('commitHiddenJson / verifyOpenedCommitment', () => {
  it('verifies after opening', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const json = { secret: 'hidden value', amount: 1000 };
    const { envelope, openingKey } = commitHiddenJson(privateKey, json);
    expect(verifyOpenedCommitment(publicKey, envelope, openingKey)).toBe(true);
  });

  it('envelope does NOT contain the JSON content', () => {
    const { privateKey } = generateKeyPair();
    const json = { secret: 'top-secret-string-XYZ' };
    const { envelope } = commitHiddenJson(privateKey, json);
    const serialised = JSON.stringify(envelope);
    expect(serialised).not.toContain('top-secret-string-XYZ');
  });

  it('rejects wrong JSON in opening key', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const { envelope, openingKey } = commitHiddenJson(privateKey, { v: 'original' });
    expect(
      verifyOpenedCommitment(publicKey, envelope, { ...openingKey, json: { v: 'tampered' } }),
    ).toBe(false);
  });

  it('rejects wrong nonce in opening key', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const { envelope, openingKey } = commitHiddenJson(privateKey, { v: 1 });
    // Pad nonce to correct base64url length for a 32-byte value
    const badNonce = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    expect(
      verifyOpenedCommitment(publicKey, envelope, { ...openingKey, nonce: badNonce }),
    ).toBe(false);
  });

  it('rejects wrong public key', () => {
    const { privateKey } = generateKeyPair();
    const { publicKey: other } = generateKeyPair();
    const { envelope, openingKey } = commitHiddenJson(privateKey, { v: 1 });
    expect(verifyOpenedCommitment(other, envelope, openingKey)).toBe(false);
  });

  it('envelope has expected shape', () => {
    const { privateKey } = generateKeyPair();
    const { envelope } = commitHiddenJson(privateKey, { x: 1 });
    expect(envelope.version).toBe(1);
    expect(envelope.type).toBe('hidden');
    expect(typeof envelope.commitment).toBe('string');
    expect(typeof envelope.proof.R).toBe('string');
    expect(typeof envelope.proof.s).toBe('string');
    expect(typeof envelope.public_key).toBe('string');
    expect(typeof envelope.created_at).toBe('number');
    for (const field of [envelope.commitment, envelope.proof.R, envelope.proof.s, envelope.public_key]) {
      expect(field).not.toMatch(/[=+/]/);
    }
  });

  it('different commitments for identical JSON (random nonce per call)', () => {
    const { privateKey } = generateKeyPair();
    const r1 = commitHiddenJson(privateKey, { x: 1 });
    const r2 = commitHiddenJson(privateKey, { x: 1 });
    expect(r1.envelope.commitment).not.toBe(r2.envelope.commitment);
    expect(r1.openingKey.nonce).not.toBe(r2.openingKey.nonce);
  });

  it('throws on wrong type in envelope', () => {
    const { publicKey } = generateKeyPair();
    const fakeEnv = {
      version: 1 as const,
      type: 'disclosed' as const,
      json_hash: '',
      commitment: '',
      proof: { R: '', s: '' },
      public_key: '',
      created_at: 0,
    };
    expect(() =>
      verifyOpenedCommitment(publicKey, fakeEnv as any, { json: {}, nonce: '' }),
    ).toThrow(InvalidCommitmentError);
  });

  it('is JSON-serialisation round-trippable', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const json = { data: 'round-trip test' };
    const { envelope, openingKey } = commitHiddenJson(privateKey, json);
    const rt_env = JSON.parse(JSON.stringify(envelope));
    const rt_key = JSON.parse(JSON.stringify(openingKey));
    expect(verifyOpenedCommitment(publicKey, rt_env, rt_key)).toBe(true);
  });
});

describe('End-to-end identity flows', () => {
  it('binds a proof to a verifier challenge', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const claim = { sub: 'alice' };
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const proof = proveDisclosedJson(privateKey, claim, { challenge });

    expect(verifyDisclosedJson(publicKey, claim, proof, { challenge })).toBe(true);
    expect(
      verifyDisclosedJson(publicKey, claim, proof, { challenge: new Uint8Array([9]) }),
    ).toBe(false);
    expect(() => verifyDisclosedJson(publicKey, claim, proof)).toThrow(InvalidProofError);
  });

  it('rejects values that are not JSON', () => {
    const { privateKey } = generateKeyPair();
    expect(() => proveDisclosedJson(privateKey, undefined)).toThrow(TypeError);
    expect(() => proveDisclosedJson(privateKey, () => 'not JSON')).toThrow(TypeError);
  });

  it('disclosed JSON: generate key, prove claim, verify', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const claim = { sub: 'alice@example.com', role: 'user', iat: 1_700_000_000 };

    const proof = proveDisclosedJson(privateKey, claim);
    expect(verifyDisclosedJson(publicKey, claim, proof)).toBe(true);
    expect(verifyDisclosedJson(publicKey, { ...claim, role: 'admin' }, proof)).toBe(false);
  });

  it('hidden commitment: commit → share envelope → reveal → verify', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const sensitive = { amount: 50_000, recipient: 'bob@example.com' };

    // Prover commits; shares envelope publicly
    const { envelope, openingKey } = commitHiddenJson(privateKey, sensitive);
    const publicEnvelope = JSON.stringify(envelope); // simulate network transfer

    // Verifier cannot read JSON from the envelope
    expect(publicEnvelope).not.toContain('50000');
    expect(publicEnvelope).not.toContain('bob@example.com');

    // Prover later reveals the opening key
    const parsedEnv = JSON.parse(publicEnvelope);
    expect(verifyOpenedCommitment(publicKey, parsedEnv, openingKey)).toBe(true);
  });
});

describe('JSON document input', () => {
  it('parses text and UTF-8 JSON documents', () => {
    expect(parseJsonDocument('{"b":2,"a":1}')).toEqual({ b: 2, a: 1 });
    expect(parseJsonDocument(new TextEncoder().encode('{"ok":true}'))).toEqual({ ok: true });
  });

  it('parses browser-compatible JSON files', async () => {
    const file = new Blob(['{"from":"file"}'], { type: 'application/json' });
    await expect(parseJsonFile(file)).resolves.toEqual({ from: 'file' });
  });

  it('rejects invalid JSON documents', () => {
    expect(() => parseJsonDocument('{')).toThrow(InvalidProofError);
  });
});
