/**
 * JSON proof operations: disclosed integrity proofs and hidden commitments.
 *
 * Disclosed JSON proof
 * ────────────────────
 * Proves that the holder of private key x produced this proof AND it is bound
 * to the exact canonical form of `json`.  The JSON is visible to the verifier.
 *
 *   message = SHA-512(canonicalJson(json))
 *   proof   = Schnorr(privKey, message, domain='zkp-browser/v1/disclosed-json')
 *
 * Hidden commitment + opening
 * ────────────────────────────
 * The prover commits to a JSON value without revealing it.  The commitment
 * binds identity AND content but hides content until the opening key is shared.
 *
 *   nonce      = random(32)
 *   commitment = SHA-512(canonicalJson(json) ‖ nonce)   [hiding + binding]
 *   proof      = Schnorr(privKey, commitment, domain='zkp-browser/v1/hidden-commitment')
 *
 * Only after the prover shares the opening key { json, nonce } and the verifier
 * calls `verifyOpenedCommitment` should the JSON be considered proven.
 */

import { sha512 } from '@noble/hashes/sha512';
import { InvalidProofError, InvalidCommitmentError } from './errors';
import { base64url, canonicalJson, concatBytes, bytesEqual, secureRandom } from './utils';
import { schnorrProve, schnorrVerify, publicKeyFromPrivate } from './schnorr';
import type {
  SchnorrProofBytes,
  SchnorrProofJson,
  DisclosedJsonProof,
  HiddenCommitment,
  CommitResult,
  CommitmentOpeningKey,
  JsonProofOptions,
} from './types';

const DOMAIN_DISCLOSED = 'zkp-browser/v1/disclosed-json';
const DOMAIN_HIDDEN = 'zkp-browser/v1/hidden-commitment';
const COMMITMENT_NONCE_BYTES = 32;
const CHALLENGE_DOMAIN = new TextEncoder().encode('zkp-browser/v1/proof-context');

// ---------------------------------------------------------------------------
// Internal codec
// ---------------------------------------------------------------------------

function encodeProof(p: SchnorrProofBytes): SchnorrProofJson {
  return { R: base64url.encode(p.R), s: base64url.encode(p.s) };
}

function decodeProof(p: SchnorrProofJson): SchnorrProofBytes {
  return { R: base64url.decode(p.R), s: base64url.decode(p.s) };
}

function proofMessage(message: Uint8Array, challenge?: Uint8Array): Uint8Array {
  if (challenge === undefined) return message;
  if (challenge.length === 0) throw new InvalidProofError('Challenge must not be empty');
  return sha512(concatBytes(CHALLENGE_DOMAIN, message, challenge));
}

function decodeChallenge(value: string | undefined): Uint8Array | undefined {
  if (value === undefined) return undefined;
  const challenge = base64url.decode(value);
  if (challenge.length === 0) throw new InvalidProofError('Challenge must not be empty');
  return challenge;
}

function resolveVerificationChallenge(
  envelopeChallenge: Uint8Array | undefined,
  suppliedChallenge: Uint8Array | undefined,
): Uint8Array | undefined {
  if (envelopeChallenge !== undefined && suppliedChallenge === undefined) {
    throw new InvalidProofError(
      'Proof is challenge-bound; supply the verifier challenge in options',
    );
  }
  if (
    suppliedChallenge !== undefined &&
    envelopeChallenge !== undefined &&
    !bytesEqual(suppliedChallenge, envelopeChallenge)
  ) {
    return undefined;
  }
  return suppliedChallenge;
}

// ---------------------------------------------------------------------------
// Disclosed JSON proofs
// ---------------------------------------------------------------------------

/**
 * Create a Schnorr proof for a disclosed JSON value.
 *
 * Proves: prover knows private key x  AND  the proof is bound to exactly this JSON.
 * The JSON itself is NOT stored in the envelope — callers share it alongside.
 */
export function proveDisclosedJson(
  privKey: Uint8Array,
  json: unknown,
  options: JsonProofOptions = {},
): DisclosedJsonProof {
  const jsonHash = sha512(new TextEncoder().encode(canonicalJson(json)));
  const proof = schnorrProve(privKey, proofMessage(jsonHash, options.challenge), DOMAIN_DISCLOSED);
  const publicKey = publicKeyFromPrivate(privKey);

  return {
    version: 1,
    type: 'disclosed',
    json_hash: base64url.encode(jsonHash),
    proof: encodeProof(proof),
    public_key: base64url.encode(publicKey),
    created_at: Date.now(),
    ...(options.challenge === undefined
      ? {}
      : { challenge: base64url.encode(options.challenge) }),
  };
}

/**
 * Verify a disclosed JSON proof.
 *
 * Returns `true` iff:
 *   1. SHA-512(canonical(json)) matches the stored `json_hash`
 *   2. The Schnorr proof is valid for `publicKey` and `json_hash`
 *
 * Throws `InvalidProofError` on structurally malformed envelopes.
 */
export function verifyDisclosedJson(
  publicKey: Uint8Array,
  json: unknown,
  envelope: DisclosedJsonProof,
  options: JsonProofOptions = {},
): boolean {
  if (envelope.version !== 1) {
    throw new InvalidProofError(`Unsupported disclosed-proof version: ${envelope.version}`);
  }
  if (envelope.type !== 'disclosed') {
    throw new InvalidProofError(`Expected type 'disclosed', got '${envelope.type}'`);
  }

  const expectedHash = sha512(new TextEncoder().encode(canonicalJson(json)));

  let storedHash: Uint8Array;
  try {
    storedHash = base64url.decode(envelope.json_hash);
  } catch (err) {
    throw new InvalidProofError('Malformed json_hash in envelope', { cause: err });
  }

  // Step 1: constant-time comparison of JSON hash
  if (!bytesEqual(expectedHash, storedHash)) return false;

  // Step 2: verify Schnorr proof
  let proof: SchnorrProofBytes;
  try {
    proof = decodeProof(envelope.proof);
  } catch (err) {
    throw new InvalidProofError('Malformed proof fields in envelope', { cause: err });
  }

  const envelopeChallenge = decodeChallenge(envelope.challenge);
  const challenge = resolveVerificationChallenge(envelopeChallenge, options.challenge);
  if (challenge === undefined && envelopeChallenge !== undefined) return false;
  return schnorrVerify(publicKey, proofMessage(expectedHash, challenge), proof, DOMAIN_DISCLOSED);
}

// ---------------------------------------------------------------------------
// Hidden commitment + opening
// ---------------------------------------------------------------------------

/**
 * Commit to a hidden JSON value.
 *
 * Returns:
 *  - `envelope`: share publicly at any time; it does not reveal the JSON.
 *  - `openingKey`: keep secret until the prover is ready to reveal.
 *
 * The Schnorr proof inside the envelope proves the prover's identity at
 * commit time but does NOT prove the JSON content until the commitment is opened.
 */
export function commitHiddenJson(
  privKey: Uint8Array,
  json: unknown,
  options: JsonProofOptions = {},
): CommitResult {
  const jsonBytes = new TextEncoder().encode(canonicalJson(json));
  const nonce = secureRandom(COMMITMENT_NONCE_BYTES);

  // Commitment: SHA-512(canonical_json ‖ nonce)
  //   Hiding:  nonce is secret until opening
  //   Binding: SHA-512 collision resistance
  const commitment = sha512(concatBytes(jsonBytes, nonce));
  const proof = schnorrProve(privKey, proofMessage(commitment, options.challenge), DOMAIN_HIDDEN);
  const publicKey = publicKeyFromPrivate(privKey);

  const envelope: HiddenCommitment = {
    version: 1,
    type: 'hidden',
    commitment: base64url.encode(commitment),
    proof: encodeProof(proof),
    public_key: base64url.encode(publicKey),
    created_at: Date.now(),
    ...(options.challenge === undefined
      ? {}
      : { challenge: base64url.encode(options.challenge) }),
  };

  const openingKey: CommitmentOpeningKey = {
    json,
    nonce: base64url.encode(nonce),
  };

  return { envelope, openingKey };
}

/**
 * Verify an opened commitment.
 *
 * Call this AFTER the prover shares the opening key.  Returns `true` iff:
 *   1. SHA-512(canonical(openingKey.json) ‖ nonce) == envelope.commitment
 *   2. The Schnorr proof in the envelope is valid for `publicKey` and the commitment
 *
 * Only when this returns `true` is the JSON content considered proven.
 *
 * Throws `InvalidCommitmentError` on structurally malformed inputs.
 */
export function verifyOpenedCommitment(
  publicKey: Uint8Array,
  envelope: HiddenCommitment,
  openingKey: CommitmentOpeningKey,
  options: JsonProofOptions = {},
): boolean {
  if (envelope.version !== 1) {
    throw new InvalidCommitmentError(
      `Unsupported hidden-commitment version: ${envelope.version}`,
    );
  }
  if (envelope.type !== 'hidden') {
    throw new InvalidCommitmentError(`Expected type 'hidden', got '${envelope.type}'`);
  }

  let storedCommitment: Uint8Array;
  try {
    storedCommitment = base64url.decode(envelope.commitment);
  } catch (err) {
    throw new InvalidCommitmentError('Malformed commitment in envelope', { cause: err });
  }

  let nonce: Uint8Array;
  try {
    nonce = base64url.decode(openingKey.nonce);
  } catch (err) {
    throw new InvalidCommitmentError('Malformed nonce in opening key', { cause: err });
  }

  // Step 1: recompute and compare commitment (constant-time)
  const jsonBytes = new TextEncoder().encode(canonicalJson(openingKey.json));
  const expectedCommitment = sha512(concatBytes(jsonBytes, nonce));
  if (!bytesEqual(expectedCommitment, storedCommitment)) return false;

  // Step 2: verify Schnorr proof using the commitment as the message
  let proof: SchnorrProofBytes;
  try {
    proof = decodeProof(envelope.proof);
  } catch (err) {
    throw new InvalidCommitmentError('Malformed proof fields in envelope', { cause: err });
  }

  const envelopeChallenge = decodeChallenge(envelope.challenge);
  const challenge = resolveVerificationChallenge(envelopeChallenge, options.challenge);
  if (challenge === undefined && envelopeChallenge !== undefined) return false;
  return schnorrVerify(
    publicKey,
    proofMessage(storedCommitment, challenge),
    proof,
    DOMAIN_HIDDEN,
  );
}
