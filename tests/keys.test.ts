import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  deriveKeyFromPassphrase,
  encryptKeyTransfer,
  decryptKeyTransfer,
} from '../src/keys';
import { InvalidKeyError, InvalidPayloadError } from '../src/errors';
import { base64url } from '../src/utils';

describe('generateKeyPair', () => {
  it('returns 32-byte private and public keys', () => {
    const { privateKey, publicKey } = generateKeyPair();
    expect(privateKey.length).toBe(32);
    expect(publicKey.length).toBe(32);
  });

  it('generates unique pairs each call', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    expect(kp1.privateKey).not.toEqual(kp2.privateKey);
    expect(kp1.publicKey).not.toEqual(kp2.publicKey);
  });
});

describe('deriveKeyFromPassphrase', () => {
  // Use a low iteration count so tests run quickly; real usage defaults to 600 000
  const fast = { iterations: 1 };
  const SALT = 'AAAAAAAAAAAAAAAAAAAAAA'; // 16 bytes base64url

  it('derives 32-byte keys', () => {
    const { keyPair } = deriveKeyFromPassphrase('pass', { ...fast, salt: SALT });
    expect(keyPair.privateKey.length).toBe(32);
    expect(keyPair.publicKey.length).toBe(32);
  });

  it('is deterministic for the same passphrase and salt', () => {
    const r1 = deriveKeyFromPassphrase('my secret', { ...fast, salt: SALT });
    const r2 = deriveKeyFromPassphrase('my secret', { ...fast, salt: SALT });
    expect(r1.keyPair.privateKey).toEqual(r2.keyPair.privateKey);
    expect(r1.keyPair.publicKey).toEqual(r2.keyPair.publicKey);
  });

  it('different passphrases → different keys', () => {
    const r1 = deriveKeyFromPassphrase('pass-A', { ...fast, salt: SALT });
    const r2 = deriveKeyFromPassphrase('pass-B', { ...fast, salt: SALT });
    expect(r1.keyPair.privateKey).not.toEqual(r2.keyPair.privateKey);
  });

  it('different salts → different keys', () => {
    const SALT2 = 'BBBBBBBBBBBBBBBBBBBBBB';
    const r1 = deriveKeyFromPassphrase('pass', { ...fast, salt: SALT });
    const r2 = deriveKeyFromPassphrase('pass', { ...fast, salt: SALT2 });
    expect(r1.keyPair.privateKey).not.toEqual(r2.keyPair.privateKey);
  });

  it('auto-generates a valid salt when omitted', () => {
    const { salt, keyPair } = deriveKeyFromPassphrase('pass', fast);
    expect(typeof salt).toBe('string');
    expect(base64url.decode(salt).length).toBeGreaterThanOrEqual(8);
    expect(keyPair.privateKey.length).toBe(32);
  });

  it('can re-derive from the returned salt', () => {
    const r1 = deriveKeyFromPassphrase('pass', fast);
    const r2 = deriveKeyFromPassphrase('pass', { ...fast, salt: r1.salt });
    expect(r1.keyPair.privateKey).toEqual(r2.keyPair.privateKey);
  });

  it('throws InvalidKeyError for iterations = 0', () => {
    expect(() => deriveKeyFromPassphrase('pass', { iterations: 0 })).toThrow(InvalidKeyError);
  });

  it('throws InvalidKeyError for non-integer iterations', () => {
    expect(() => deriveKeyFromPassphrase('pass', { iterations: 1.5 })).toThrow(InvalidKeyError);
  });
});

describe('encryptKeyTransfer / decryptKeyTransfer', () => {
  it('round-trips a private key', () => {
    const { privateKey } = generateKeyPair();
    const payload = encryptKeyTransfer(privateKey, 'hunter2');
    const recovered = decryptKeyTransfer(payload, 'hunter2');
    expect(recovered).toEqual(privateKey);
  });

  it('fails with wrong password', () => {
    const { privateKey } = generateKeyPair();
    const payload = encryptKeyTransfer(privateKey, 'correct');
    expect(() => decryptKeyTransfer(payload, 'wrong')).toThrow(InvalidPayloadError);
  });

  it('payload fields are base64url (no padding or +/)', () => {
    const { privateKey } = generateKeyPair();
    const payload = encryptKeyTransfer(privateKey, 'pw');
    for (const field of [payload.salt, payload.nonce, payload.ciphertext]) {
      expect(typeof field).toBe('string');
      expect(field).not.toMatch(/[=+/]/);
    }
    expect(payload.version).toBe(1);
  });

  it('each call produces a different ciphertext (random nonce)', () => {
    const { privateKey } = generateKeyPair();
    const p1 = encryptKeyTransfer(privateKey, 'pw');
    const p2 = encryptKeyTransfer(privateKey, 'pw');
    expect(p1.nonce).not.toBe(p2.nonce);
    expect(p1.ciphertext).not.toBe(p2.ciphertext);
  });

  it('throws InvalidPayloadError on unsupported version', () => {
    const { privateKey } = generateKeyPair();
    const payload = encryptKeyTransfer(privateKey, 'pw');
    expect(() => decryptKeyTransfer({ ...payload, version: 99 as 1 }, 'pw')).toThrow(
      InvalidPayloadError,
    );
  });

  it('throws InvalidKeyError on wrong-length private key', () => {
    expect(() => encryptKeyTransfer(new Uint8Array(16), 'pw')).toThrow(InvalidKeyError);
  });

  it('throws on corrupted ciphertext', () => {
    const { privateKey } = generateKeyPair();
    const payload = encryptKeyTransfer(privateKey, 'pw');
    // Flip a byte in ciphertext
    const raw = base64url.decode(payload.ciphertext);
    raw[0] ^= 0xff;
    expect(() =>
      decryptKeyTransfer({ ...payload, ciphertext: base64url.encode(raw) }, 'pw'),
    ).toThrow(InvalidPayloadError);
  });
});
