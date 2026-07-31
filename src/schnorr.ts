/**
 * Schnorr proof of knowledge of discrete logarithm over Ristretto255.
 *
 * Protocol (Sigma / Fiat-Shamir non-interactive):
 *   Prove:   P = x·G
 *   Commit:  r ←$ [1, l-1],  R = r·G
 *   Challenge: c = H(domain ‖ P ‖ R ‖ message) mod l
 *   Response:  s = (r + c·x) mod l
 *   Proof: (R, s)
 *
 *   Verify: s·G = R + c·P
 *
 * Domain separation prevents proofs from being replayed across different
 * protocol contexts. The message is bound into the challenge.
 *
 * Security: honest-verifier zero-knowledge + extractability under the
 * discrete-log assumption over Ristretto255 (prime-order group, cofactor 1).
 */

import { RistrettoPoint } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { InvalidKeyError, InvalidProofError } from './errors';
import { concatBytes, bytesToBigIntBE, bigIntToBytesBE, secureRandom } from './utils';
import type { SchnorrProofBytes } from './types';

// Ristretto255 / Ed25519 group order l (prime)
const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
const SCALAR_BYTES = 32;
const POINT_BYTES = 32;
// Over-sample 64 bytes to achieve negligible bias when reducing mod l (2^512 >> l)
const NONCE_SAMPLE_BYTES = 64;

function modL(n: bigint): bigint {
  return ((n % L) + L) % L;
}

/**
 * Derive the Ristretto255 group scalar from a 32-byte private key seed.
 * Domain-separated SHA-512 hash, reduced mod l.
 * Throws if the derived scalar is zero (probability 1/l ≈ 2^−252).
 */
export function seedToScalar(privKey: Uint8Array): bigint {
  if (privKey.length !== SCALAR_BYTES) {
    throw new InvalidKeyError(
      `Private key must be ${SCALAR_BYTES} bytes, got ${privKey.length}`,
    );
  }
  const tag = new TextEncoder().encode('zkp-browser/v1/ristretto-scalar\x00');
  const hash = sha512(concatBytes(tag, privKey));
  const s = modL(bytesToBigIntBE(hash));
  if (s === 0n) {
    throw new InvalidKeyError('Derived scalar is zero — catastrophic key failure; regenerate key');
  }
  return s;
}

/** Compute the Ristretto255 public key from a 32-byte private key seed. */
export function publicKeyFromPrivate(privKey: Uint8Array): Uint8Array {
  return new Uint8Array(RistrettoPoint.BASE.multiply(seedToScalar(privKey)).toRawBytes());
}

/**
 * Fiat-Shamir challenge hash.
 *
 * H_challenge = SHA-512( domainLen(1 byte) ‖ domain ‖ P ‖ R ‖ message ) mod l
 *
 * The one-byte domain length prefix provides domain separation at minimal cost.
 * Domain strings are limited to 255 UTF-8 bytes.
 */
function challengeHash(
  domain: string,
  publicKey: Uint8Array,
  R: Uint8Array,
  message: Uint8Array,
): bigint {
  const domainBytes = new TextEncoder().encode(domain);
  if (domainBytes.length > 255) throw new RangeError('Domain must be ≤ 255 UTF-8 bytes');
  const header = new Uint8Array([domainBytes.length]);
  const hash = sha512(concatBytes(header, domainBytes, publicKey, R, message));
  return modL(bytesToBigIntBE(hash));
}

/**
 * Generate a Schnorr proof for `message` under `privKey` in `domain`.
 *
 * @param privKey  32-byte private key seed
 * @param message  Arbitrary bytes bound into the challenge (e.g. SHA-512 of JSON)
 * @param domain   Protocol domain string for separation (e.g. 'zkp-browser/v1/disclosed-json')
 */
export function schnorrProve(
  privKey: Uint8Array,
  message: Uint8Array,
  domain: string,
): SchnorrProofBytes {
  const x = seedToScalar(privKey);
  const P = new Uint8Array(RistrettoPoint.BASE.multiply(x).toRawBytes());

  // Sample random nonce r ∈ [1, l-1]; retry on astronomically unlikely r=0
  let r = 0n;
  let R = new Uint8Array(POINT_BYTES);
  for (let attempt = 0; attempt < 128; attempt++) {
    r = modL(bytesToBigIntBE(secureRandom(NONCE_SAMPLE_BYTES)));
    if (r !== 0n) {
      R = new Uint8Array(RistrettoPoint.BASE.multiply(r).toRawBytes());
      break;
    }
  }
  if (r === 0n) throw new InvalidKeyError('CSPRNG failure: could not generate non-zero nonce');

  const c = challengeHash(domain, P, R, message);
  const s = modL(r + c * x);

  return { R, s: bigIntToBytesBE(s, SCALAR_BYTES) };
}

/**
 * Verify a Schnorr proof.
 *
 * Throws `InvalidProofError` when inputs are structurally malformed.
 * Returns `false` when the proof does not satisfy the verification equation.
 *
 * @param publicKey  32-byte Ristretto255 public key
 * @param message    The same message bytes used during `schnorrProve`
 * @param proof      The (R, s) proof pair
 * @param domain     Must match the domain used during `schnorrProve`
 */
export function schnorrVerify(
  publicKey: Uint8Array,
  message: Uint8Array,
  proof: SchnorrProofBytes,
  domain: string,
): boolean {
  if (publicKey.length !== POINT_BYTES) {
    throw new InvalidProofError(
      `Public key must be ${POINT_BYTES} bytes, got ${publicKey.length}`,
    );
  }
  if (proof.R.length !== POINT_BYTES) {
    throw new InvalidProofError(`Proof R must be ${POINT_BYTES} bytes, got ${proof.R.length}`);
  }
  if (proof.s.length !== SCALAR_BYTES) {
    throw new InvalidProofError(`Proof s must be ${SCALAR_BYTES} bytes, got ${proof.s.length}`);
  }

  // Decode public key — throws on invalid Ristretto encoding
  let P: InstanceType<typeof RistrettoPoint>;
  try {
    P = RistrettoPoint.fromHex(publicKey);
  } catch (err) {
    throw new InvalidProofError('Invalid public key encoding', { cause: err });
  }
  if (P.equals(RistrettoPoint.ZERO)) {
    throw new InvalidProofError('Public key must not be the identity point');
  }

  // Decode proof commitment R
  let Rpt: InstanceType<typeof RistrettoPoint>;
  try {
    Rpt = RistrettoPoint.fromHex(proof.R);
  } catch (err) {
    throw new InvalidProofError('Invalid proof R encoding', { cause: err });
  }

  // Decode and range-check scalar s ∈ [1, l-1]
  const s = bytesToBigIntBE(proof.s);
  if (s === 0n || s >= L) return false;

  const c = challengeHash(domain, publicKey, proof.R, message);

  // Verify: s·G  ==  R + c·P
  const lhs = RistrettoPoint.BASE.multiply(s);
  const rhs = c === 0n ? Rpt : Rpt.add(P.multiply(c));

  return lhs.equals(rhs);
}
