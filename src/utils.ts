import { randomBytes } from '@noble/hashes/utils';
import { canonicalize } from 'json-canonicalize';

/** CSPRNG — works in Node.js and browsers via @noble/hashes */
export function secureRandom(n: number): Uint8Array {
  return randomBytes(n);
}

// ---------------------------------------------------------------------------
// base64url (no padding, URL-safe alphabet — RFC 4648 §5)
// Uses btoa/atob which are available globally in Node 16+ and all browsers.
// ---------------------------------------------------------------------------

export const base64url = {
  encode(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    const b64 = btoa(binary);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  decode(str: string): Uint8Array {
    if (typeof str !== 'string') throw new TypeError('base64url input must be a string');
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  },
};

// ---------------------------------------------------------------------------
// Canonical JSON — RFC 8785 JSON Canonicalization Scheme.
// ---------------------------------------------------------------------------

export function canonicalJson(value: unknown): string {
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
    throw new TypeError('Value is not representable as JSON');
  }
  return canonicalize(value);
}

// ---------------------------------------------------------------------------
// Byte utilities
// ---------------------------------------------------------------------------

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

/** Interpret bytes as an unsigned big-endian integer. */
export function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** Encode a non-negative bigint as exactly `len` big-endian bytes. Throws on overflow. */
export function bigIntToBytesBE(n: bigint, len: number): Uint8Array {
  if (n < 0n) throw new RangeError('bigint must be non-negative');
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v > 0n) throw new RangeError(`bigint ${n} overflows ${len} bytes`);
  return out;
}

/**
 * Constant-time byte-array equality check.
 * Runs in O(n) regardless of content to avoid timing attacks.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
