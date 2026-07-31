import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../src/keys';
import { schnorrProve, schnorrVerify, publicKeyFromPrivate, seedToScalar } from '../src/schnorr';
import { InvalidKeyError, InvalidProofError } from '../src/errors';

const DOMAIN = 'test/schnorr/v1';

describe('seedToScalar', () => {
  it('throws on wrong-length seed', () => {
    expect(() => seedToScalar(new Uint8Array(16))).toThrow(InvalidKeyError);
    expect(() => seedToScalar(new Uint8Array(33))).toThrow(InvalidKeyError);
  });

  it('returns a stable non-zero scalar for a given seed', () => {
    const seed = new Uint8Array(32).fill(7);
    const s1 = seedToScalar(seed);
    const s2 = seedToScalar(seed);
    expect(s1).toBe(s2);
    expect(s1).not.toBe(0n);
  });
});

describe('publicKeyFromPrivate', () => {
  it('produces 32-byte output', () => {
    const { privateKey } = generateKeyPair();
    expect(publicKeyFromPrivate(privateKey).length).toBe(32);
  });

  it('is stable', () => {
    const { privateKey, publicKey } = generateKeyPair();
    expect(publicKeyFromPrivate(privateKey)).toEqual(publicKey);
  });

  it('different keys → different public keys', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    expect(kp1.publicKey).not.toEqual(kp2.publicKey);
  });
});

describe('schnorrProve + schnorrVerify', () => {
  it('verifies a valid proof', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello world');
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    expect(schnorrVerify(publicKey, msg, proof, DOMAIN)).toBe(true);
  });

  it('rejects a proof with wrong message', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    expect(schnorrVerify(publicKey, new TextEncoder().encode('HELLO'), proof, DOMAIN)).toBe(false);
  });

  it('rejects a proof with wrong public key', () => {
    const { privateKey } = generateKeyPair();
    const { publicKey: other } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    expect(schnorrVerify(other, msg, proof, DOMAIN)).toBe(false);
  });

  it('rejects a proof with wrong domain', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    expect(schnorrVerify(publicKey, msg, proof, 'test/schnorr/v2')).toBe(false);
  });

  it('rejects tampered scalar s', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);

    const badS = new Uint8Array(proof.s);
    badS[15] ^= 0x42;
    expect(schnorrVerify(publicKey, msg, { ...proof, s: badS }, DOMAIN)).toBe(false);
  });

  it('rejects tampered R (either invalid encoding or wrong proof)', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);

    const badR = new Uint8Array(proof.R);
    badR[0] ^= 0x01;

    // Tampered R is either not a valid Ristretto encoding (throws) or yields wrong proof
    let passed = false;
    try {
      passed = schnorrVerify(publicKey, msg, { ...proof, R: badR }, DOMAIN) === false;
    } catch (e) {
      passed = e instanceof InvalidProofError;
    }
    expect(passed).toBe(true);
  });

  it('produces different R for same inputs (random nonce)', () => {
    const { privateKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const p1 = schnorrProve(privateKey, msg, DOMAIN);
    const p2 = schnorrProve(privateKey, msg, DOMAIN);
    expect(p1.R).not.toEqual(p2.R);
  });

  it('throws on public key that is too short', () => {
    const { privateKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    expect(() => schnorrVerify(new Uint8Array(16), msg, proof, DOMAIN)).toThrow(InvalidProofError);
  });

  it('throws on identity public key (all-zero encoding)', () => {
    const { privateKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    // All-zero bytes = Ristretto255 identity encoding
    expect(() => schnorrVerify(new Uint8Array(32), msg, proof, DOMAIN)).toThrow(InvalidProofError);
  });

  it('rejects s = 0 (all-zero s bytes)', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = new TextEncoder().encode('hello');
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    const badS = new Uint8Array(32); // zero scalar
    expect(schnorrVerify(publicKey, msg, { ...proof, s: badS }, DOMAIN)).toBe(false);
  });

  it('works with empty message', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const proof = schnorrProve(privateKey, new Uint8Array(0), DOMAIN);
    expect(schnorrVerify(publicKey, new Uint8Array(0), proof, DOMAIN)).toBe(true);
  });

  it('works with large message (512-byte hash)', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = new Uint8Array(64).fill(0xab);
    const proof = schnorrProve(privateKey, msg, DOMAIN);
    expect(schnorrVerify(publicKey, msg, proof, DOMAIN)).toBe(true);
  });
});
