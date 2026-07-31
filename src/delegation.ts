/**
 * v2 Per-Device Identity: Ed25519 root delegated to Ristretto255 device keys.
 *
 * ## Architecture (hybrid Ed25519 + Ristretto255 Schnorr)
 *
 * Root key (Device 1):   Ed25519 — standard, audited, 64-byte signatures.
 *                         Signs device delegations; never sent to other devices.
 * Device key (each dev): Ristretto255 — reuses existing Schnorr ZKP machinery.
 *                         Private key stays on the device that generated it.
 *
 * ## Delegation flow (one-time, per new device)
 *
 *   1. Device 2 calls generateDeviceKeyPair() locally.
 *   2. Device 2 sends its Ristretto255 public key (+ optional metadata) to Device 1
 *      via QR code, copy-paste, or any out-of-band channel.
 *   3. Device 1 (root) calls createDeviceDelegation(rootPrivKey, devicePubKey, opts).
 *      The root private key never leaves Device 1.
 *   4. Device 1 sends the signed DeviceDelegation back to Device 2.
 *   5. Device 2 stores its device private key + the signed delegation locally.
 *
 * ## Authentication flow (per verifier session, repeatable)
 *
 *   1. Verifier issues a fresh, unpredictable challenge (≥ 16 random bytes).
 *   2. Device 2 calls createDeviceProof(devicePrivKey, delegation, challenge).
 *   3. Verifier calls verifyDeviceProof(rootPublicKey, proof, challenge):
 *      a. Verifies Ed25519 root signature on delegation payload.
 *      b. Checks delegation expiry if present.
 *      c. Verifies Ristretto255 Schnorr proof bound to delegation + challenge.
 *   4. Verifier marks the challenge consumed to prevent replay.
 *   5. Optionally, verifier calls isDelegationRevoked() against its revocation set.
 *
 * ## Domain separation
 *
 *   Delegation signing:  'zkp-browser/v2/device-delegation'
 *   Device Schnorr proof: 'zkp-browser/v2/device-proof'
 *
 * ## Revocation guidance
 *
 *   Revocation is application-level. The verifier maintains a set of revoked
 *   device public keys (base64url). After successful verifyDeviceProof, call
 *   isDelegationRevoked(proof.delegation, revokedKeys). To revoke a device,
 *   add its delegation.payload.device_public_key to the persistent set.
 *   For time-bounded trust, set expiresAt in DeviceDelegationOptions.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { InvalidDelegationError, InvalidKeyError } from './errors'
import { base64url, canonicalJson, concatBytes, bytesEqual, secureRandom } from './utils'
import { schnorrProve, schnorrVerify } from './schnorr'
import { generateKeyPair } from './keys'
import type {
  KeyPair,
  RootKeyPair,
  DeviceDelegation,
  DelegationPayload,
  DeviceProof,
  DeviceDelegationOptions,
  SchnorrProofBytes,
} from './types'

const ROOT_KEY_BYTES = 32
const DEVICE_KEY_BYTES = 32
const ED25519_SIG_BYTES = 64
const DELEGATION_DOMAIN = 'zkp-browser/v2/device-delegation'
const DEVICE_PROOF_DOMAIN = 'zkp-browser/v2/device-proof'

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/**
 * Generate an Ed25519 root key pair for v2 per-device identity mode.
 *
 * Keep the private key on Device 1 only. Use it exclusively to sign device
 * delegations. Distribute the public key as the trusted root identity anchor.
 */
export function generateRootKeyPair(): RootKeyPair {
  const privateKey = secureRandom(ROOT_KEY_BYTES)
  const publicKey = new Uint8Array(ed25519.getPublicKey(privateKey))
  return { privateKey, publicKey }
}

/**
 * Generate a Ristretto255 device key pair for per-device identity (v2).
 *
 * Alias for `generateKeyPair()` with a canonical v2 name. Call this on each
 * new device — the private key must never leave the device.
 */
export function generateDeviceKeyPair(): KeyPair {
  return generateKeyPair()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Compute the signable byte string for a delegation payload.
 *
 * Format: uint8(len(domain)) ‖ domain_bytes ‖ canonical_json_bytes(payload)
 *
 * Prepending the domain length + bytes matches the pattern used in Schnorr
 * challengeHash and prevents cross-protocol use of the signature.
 */
function _delegationSignable(payload: DelegationPayload): Uint8Array {
  const domainBytes = new TextEncoder().encode(DELEGATION_DOMAIN)
  if (domainBytes.length > 255) throw new RangeError('Domain must be ≤ 255 UTF-8 bytes')
  const header = new Uint8Array([domainBytes.length])
  const payloadBytes = new TextEncoder().encode(canonicalJson(payload))
  return concatBytes(header, domainBytes, payloadBytes)
}

/**
 * Compute the Schnorr proof message for a device proof.
 *
 * message = SHA-512(uint8(len(domain)) ‖ domain ‖ canonical_json(delegation) ‖ challenge)
 *
 * Including the delegation in the message binds the proof to exactly that
 * delegation; a revoked delegation cannot be substituted.
 */
function _deviceProofMessage(
  delegation: DeviceDelegation,
  challenge: Uint8Array,
): Uint8Array {
  const domainBytes = new TextEncoder().encode(DEVICE_PROOF_DOMAIN)
  if (domainBytes.length > 255) throw new RangeError('Domain must be ≤ 255 UTF-8 bytes')
  const header = new Uint8Array([domainBytes.length])
  const delegationBytes = new TextEncoder().encode(canonicalJson(delegation))
  return sha512(concatBytes(header, domainBytes, delegationBytes, challenge))
}

// ---------------------------------------------------------------------------
// Delegation creation and verification
// ---------------------------------------------------------------------------

/**
 * Create a signed device delegation (called by Device 1 / root).
 *
 * The delegation authorizes `devicePublicKey` to authenticate on behalf of
 * the root identity. It is safe to send to Device 2 over any channel.
 *
 * @param rootPrivKey     32-byte Ed25519 private key seed (stays on Device 1)
 * @param devicePublicKey 32-byte Ristretto255 device public key (from Device 2)
 * @param options         Optional label, metadata, expiry
 */
export function createDeviceDelegation(
  rootPrivKey: Uint8Array,
  devicePublicKey: Uint8Array,
  options: DeviceDelegationOptions = {},
): DeviceDelegation {
  if (rootPrivKey.length !== ROOT_KEY_BYTES) {
    throw new InvalidKeyError(
      `Root private key must be ${ROOT_KEY_BYTES} bytes, got ${rootPrivKey.length}`,
    )
  }
  if (devicePublicKey.length !== DEVICE_KEY_BYTES) {
    throw new InvalidKeyError(
      `Device public key must be ${DEVICE_KEY_BYTES} bytes, got ${devicePublicKey.length}`,
    )
  }

  const rootPublicKey = new Uint8Array(ed25519.getPublicKey(rootPrivKey))

  const payload: DelegationPayload = {
    version: 2,
    root_public_key: base64url.encode(rootPublicKey),
    device_public_key: base64url.encode(devicePublicKey),
    created_at: options.createdAt ?? Date.now(),
    ...(options.deviceId !== undefined ? { device_id: options.deviceId } : {}),
    ...(options.metadata !== undefined ? { metadata: options.metadata } : {}),
    ...(options.expiresAt !== undefined ? { expires_at: options.expiresAt } : {}),
  }

  const signable = _delegationSignable(payload)
  const signature = new Uint8Array(ed25519.sign(signable, rootPrivKey))

  return {
    version: 2,
    type: 'device-delegation',
    payload,
    signature: base64url.encode(signature),
  }
}

/**
 * Verify a device delegation's Ed25519 root signature.
 *
 * Returns `true` iff the delegation was produced by the root private key
 * matching `rootPublicKey` and the payload's `root_public_key` field matches.
 *
 * Note: does NOT check `expires_at`. Use `verifyDeviceProof` for full
 * authentication including expiry, or check `payload.expires_at` manually.
 *
 * Throws `InvalidDelegationError` on structurally malformed envelopes.
 *
 * @param rootPublicKey 32-byte Ed25519 root public key (trusted; from your store)
 * @param delegation    The DeviceDelegation envelope to validate
 */
export function verifyDeviceDelegation(
  rootPublicKey: Uint8Array,
  delegation: DeviceDelegation,
): boolean {
  if (delegation.version !== 2) {
    throw new InvalidDelegationError(
      `Unsupported delegation version: ${delegation.version}`,
    )
  }
  if (delegation.type !== 'device-delegation') {
    throw new InvalidDelegationError(
      `Expected type 'device-delegation', got '${delegation.type}'`,
    )
  }

  let payloadRootPub: Uint8Array
  try {
    payloadRootPub = base64url.decode(delegation.payload.root_public_key)
  } catch (err) {
    throw new InvalidDelegationError(
      'Malformed root_public_key in delegation payload',
      { cause: err },
    )
  }
  if (!bytesEqual(payloadRootPub, rootPublicKey)) return false

  let sig: Uint8Array
  try {
    sig = base64url.decode(delegation.signature)
  } catch (err) {
    throw new InvalidDelegationError('Malformed delegation signature', { cause: err })
  }
  if (sig.length !== ED25519_SIG_BYTES) {
    throw new InvalidDelegationError(
      `Delegation signature must be ${ED25519_SIG_BYTES} bytes, got ${sig.length}`,
    )
  }

  const signable = _delegationSignable(delegation.payload)
  try {
    return ed25519.verify(sig, signable, rootPublicKey)
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Device proof creation and verification
// ---------------------------------------------------------------------------

/**
 * Create a device proof (called by Device 2 at authentication time).
 *
 * Proves possession of the device private key bound to:
 *   1. The signed delegation (prevents use with a different/revoked delegation)
 *   2. The verifier's challenge (prevents replay)
 *
 * @param devicePrivKey 32-byte Ristretto255 device private key seed
 * @param delegation    Signed delegation received from root
 * @param challenge     Fresh unpredictable bytes from the verifier (≥ 1 byte)
 */
export function createDeviceProof(
  devicePrivKey: Uint8Array,
  delegation: DeviceDelegation,
  challenge: Uint8Array,
): DeviceProof {
  if (challenge.length === 0) {
    throw new InvalidDelegationError('Challenge must not be empty')
  }

  const message = _deviceProofMessage(delegation, challenge)
  const rawProof = schnorrProve(devicePrivKey, message, DEVICE_PROOF_DOMAIN)

  return {
    version: 2,
    type: 'device-proof',
    delegation,
    proof: {
      R: base64url.encode(rawProof.R),
      s: base64url.encode(rawProof.s),
    },
    challenge: base64url.encode(challenge),
    created_at: Date.now(),
  }
}

/**
 * Verify a device proof (called by the verifier / Device 1).
 *
 * Performs these checks in order:
 *   1. Challenge in proof matches the supplied `challenge`
 *   2. Delegation Ed25519 root signature is valid for `rootPublicKey`
 *   3. Delegation `expires_at` has not passed (if set)
 *   4. Device Ristretto255 Schnorr proof is valid for the delegation's device key
 *
 * Returns `true` only when all checks pass.
 * Returns `false` on invalid proof, wrong root key, challenge mismatch, or expiry.
 * Throws `InvalidDelegationError` on structurally malformed envelopes.
 * Throws `InvalidProofError` (from schnorrVerify) on malformed Schnorr fields.
 *
 * ⚠️  After a successful verification, mark the challenge consumed to prevent
 *     replay attacks. This library does not maintain the verifier's replay cache.
 *
 * @param rootPublicKey 32-byte Ed25519 root public key (trusted; from your store)
 * @param deviceProof   The DeviceProof envelope from Device 2
 * @param challenge     The exact challenge bytes you issued to Device 2
 */
export function verifyDeviceProof(
  rootPublicKey: Uint8Array,
  deviceProof: DeviceProof,
  challenge: Uint8Array,
): boolean {
  if (deviceProof.version !== 2) {
    throw new InvalidDelegationError(
      `Unsupported device-proof version: ${deviceProof.version}`,
    )
  }
  if (deviceProof.type !== 'device-proof') {
    throw new InvalidDelegationError(
      `Expected type 'device-proof', got '${deviceProof.type}'`,
    )
  }
  if (challenge.length === 0) {
    throw new InvalidDelegationError('Challenge must not be empty')
  }

  let storedChallenge: Uint8Array
  try {
    storedChallenge = base64url.decode(deviceProof.challenge)
  } catch (err) {
    throw new InvalidDelegationError('Malformed challenge in device proof', { cause: err })
  }
  if (!bytesEqual(storedChallenge, challenge)) return false

  if (!verifyDeviceDelegation(rootPublicKey, deviceProof.delegation)) return false

  const { expires_at } = deviceProof.delegation.payload
  if (expires_at !== undefined && Date.now() > expires_at) return false

  let devicePublicKey: Uint8Array
  try {
    devicePublicKey = base64url.decode(deviceProof.delegation.payload.device_public_key)
  } catch (err) {
    throw new InvalidDelegationError(
      'Malformed device_public_key in delegation',
      { cause: err },
    )
  }

  let proof: SchnorrProofBytes
  try {
    proof = {
      R: base64url.decode(deviceProof.proof.R),
      s: base64url.decode(deviceProof.proof.s),
    }
  } catch (err) {
    throw new InvalidDelegationError(
      'Malformed Schnorr proof fields in device proof',
      { cause: err },
    )
  }

  const message = _deviceProofMessage(deviceProof.delegation, challenge)
  return schnorrVerify(devicePublicKey, message, proof, DEVICE_PROOF_DOMAIN)
}

// ---------------------------------------------------------------------------
// Revocation utilities
// ---------------------------------------------------------------------------

/**
 * Check if a device delegation has been revoked by the application.
 *
 * Revocation is application-level. The verifier maintains a persistent set of
 * revoked device public keys (base64url Ristretto255 points). Use after a
 * successful `verifyDeviceProof`:
 *
 * ```ts
 * const revokedKeys = new Set<string>(loadRevokedKeysFromStorage())
 * const ok = verifyDeviceProof(rootPubKey, proof, challenge)
 *   && !isDelegationRevoked(proof.delegation, revokedKeys)
 * ```
 *
 * To revoke a device, add `delegation.payload.device_public_key` to the set
 * and persist it. There is no central revocation service — the verifier alone
 * decides which device keys to trust.
 */
export function isDelegationRevoked(
  delegation: DeviceDelegation,
  revokedDeviceKeys: ReadonlySet<string>,
): boolean {
  return revokedDeviceKeys.has(delegation.payload.device_public_key)
}
