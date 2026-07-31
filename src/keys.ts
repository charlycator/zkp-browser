import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { hkdf } from '@noble/hashes/hkdf';
import { sha512 } from '@noble/hashes/sha512';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { InvalidKeyError, InvalidPayloadError } from './errors';
import { base64url, secureRandom } from './utils';
import { publicKeyFromPrivate } from './schnorr';
import type { KeyPair, KeyTransferPayload, PassphraseKeyOptions, DerivedKeyResult } from './types';

const PRIVATE_KEY_BYTES = 32;
const TRANSFER_SALT_BYTES = 16;
const TRANSFER_NONCE_BYTES = 12; // ChaCha20-Poly1305 (IETF) nonce
const TRANSFER_KEY_BYTES = 32;
const PBKDF2_ITERATIONS_DEFAULT = 600_000;

const HKDF_INFO_IDENTITY = new TextEncoder().encode('zkp-browser/v1/identity-key');
const HKDF_INFO_TRANSFER = new TextEncoder().encode('zkp-browser/v1/key-transfer');

/** Generate a cryptographically random Ristretto255 key pair. */
export function generateKeyPair(): KeyPair {
  const privateKey = secureRandom(PRIVATE_KEY_BYTES);
  const publicKey = publicKeyFromPrivate(privateKey);
  return { privateKey, publicKey };
}

/**
 * Derive a deterministic key pair from a passphrase.
 *
 * Key-stretching pipeline:
 *   PBKDF2-SHA512(passphrase, salt, iterations) → 64-byte stretched key
 *   HKDF-SHA512(stretched, salt, 'zkp-browser/v1/identity-key') → 32-byte private key
 *
 * Store `result.salt` alongside the user record. Supply it as `options.salt` to
 * re-derive the same key on any device.
 */
export function deriveKeyFromPassphrase(
  passphrase: string,
  options: PassphraseKeyOptions = {},
): DerivedKeyResult {
  const iterations = options.iterations ?? PBKDF2_ITERATIONS_DEFAULT;
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new InvalidKeyError('iterations must be a positive integer');
  }

  const salt =
    options.salt !== undefined ? base64url.decode(options.salt) : secureRandom(TRANSFER_SALT_BYTES);
  if (salt.length < 8) {
    throw new InvalidKeyError('Salt must be at least 8 bytes');
  }

  const ikm = new TextEncoder().encode(passphrase);
  // PBKDF2: slow brute-force resistance
  const stretched = pbkdf2(sha512, ikm, salt, { c: iterations, dkLen: 64 });
  // HKDF: domain-separated extraction of the private key seed
  const privateKey = hkdf(sha512, stretched, salt, HKDF_INFO_IDENTITY, PRIVATE_KEY_BYTES);
  const publicKey = publicKeyFromPrivate(privateKey);

  return { keyPair: { privateKey, publicKey }, salt: base64url.encode(salt) };
}

/**
 * Encrypt a private key for one-time transfer (e.g. via QR code).
 *
 * Key derivation: PBKDF2-SHA512(password, salt) → HKDF → 32-byte ChaCha20 key.
 * Authenticated encryption: ChaCha20-Poly1305 (256-bit key, 96-bit nonce).
 *
 * The returned payload is a plain JSON object whose binary fields are base64url
 * strings — suitable for embedding in a QR code or sending over any text channel.
 */
export function encryptKeyTransfer(
  privateKey: Uint8Array,
  password: string,
): KeyTransferPayload {
  if (privateKey.length !== PRIVATE_KEY_BYTES) {
    throw new InvalidKeyError(
      `Private key must be ${PRIVATE_KEY_BYTES} bytes, got ${privateKey.length}`,
    );
  }

  const salt = secureRandom(TRANSFER_SALT_BYTES);
  const nonce = secureRandom(TRANSFER_NONCE_BYTES);

  const transferKey = _deriveTransferKey(password, salt);
  const ciphertext = chacha20poly1305(transferKey, nonce).encrypt(privateKey);

  return {
    version: 1,
    salt: base64url.encode(salt),
    nonce: base64url.encode(nonce),
    ciphertext: base64url.encode(ciphertext),
  };
}

/**
 * Decrypt a key-transfer payload to recover the private key.
 * Throws `InvalidPayloadError` on wrong password, corrupted payload, or version mismatch.
 */
export function decryptKeyTransfer(
  payload: KeyTransferPayload,
  password: string,
): Uint8Array {
  if (payload.version !== 1) {
    throw new InvalidPayloadError(`Unsupported key-transfer payload version: ${payload.version}`);
  }

  let salt: Uint8Array;
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    salt = base64url.decode(payload.salt);
    nonce = base64url.decode(payload.nonce);
    ciphertext = base64url.decode(payload.ciphertext);
  } catch (err) {
    throw new InvalidPayloadError('Malformed payload: base64url decode failed', { cause: err });
  }

  if (salt.length !== TRANSFER_SALT_BYTES) {
    throw new InvalidPayloadError(
      `Invalid salt length: expected ${TRANSFER_SALT_BYTES}, got ${salt.length}`,
    );
  }
  if (nonce.length !== TRANSFER_NONCE_BYTES) {
    throw new InvalidPayloadError(
      `Invalid nonce length: expected ${TRANSFER_NONCE_BYTES}, got ${nonce.length}`,
    );
  }

  const transferKey = _deriveTransferKey(password, salt);
  let privateKey: Uint8Array;
  try {
    privateKey = chacha20poly1305(transferKey, nonce).decrypt(ciphertext);
  } catch (err) {
    throw new InvalidPayloadError(
      'Decryption failed: wrong password or corrupted payload',
      { cause: err },
    );
  }

  if (privateKey.length !== PRIVATE_KEY_BYTES) {
    throw new InvalidPayloadError(
      `Decrypted key has unexpected length: ${privateKey.length}`,
    );
  }
  return privateKey;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _deriveTransferKey(password: string, salt: Uint8Array): Uint8Array {
  const ikm = new TextEncoder().encode(password);
  const stretched = pbkdf2(sha512, ikm, salt, { c: PBKDF2_ITERATIONS_DEFAULT, dkLen: 64 });
  return hkdf(sha512, stretched, salt, HKDF_INFO_TRANSFER, TRANSFER_KEY_BYTES);
}
