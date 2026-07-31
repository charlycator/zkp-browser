import { describe, it, expect } from 'vitest'
import {
  generateKeyPair,
  generateDeviceKeyPair,
  generateRootKeyPair,
  createDeviceDelegation,
  verifyDeviceDelegation,
  createDeviceProof,
  verifyDeviceProof,
  isDelegationRevoked,
  proveDisclosedJson,
  verifyDisclosedJson,
} from '../src/index'
import { InvalidDelegationError, InvalidKeyError, InvalidProofError } from '../src/errors'
import { base64url } from '../src/utils'

const challenge = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

describe('generateRootKeyPair', () => {
  it('produces correct key sizes and unique pairs', () => {
    const kp1 = generateRootKeyPair()
    const kp2 = generateRootKeyPair()
    expect(kp1.privateKey.length).toBe(32)
    expect(kp1.publicKey.length).toBe(32)
    expect(kp1.privateKey).not.toEqual(kp2.privateKey)
    expect(kp1.publicKey).not.toEqual(kp2.publicKey)
  })
})

describe('generateDeviceKeyPair', () => {
  it('matches generateKeyPair behavior', () => {
    const kp1 = generateDeviceKeyPair()
    const kp2 = generateKeyPair()
    expect(kp1.privateKey.length).toBe(32)
    expect(kp1.publicKey.length).toBe(32)
    expect(kp2.privateKey.length).toBe(32)
    expect(kp2.publicKey.length).toBe(32)
    expect(kp1.privateKey).not.toEqual(kp2.privateKey)
  })
})

describe('createDeviceDelegation / verifyDeviceDelegation', () => {
  it('creates and verifies a signed delegation', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey, {
      deviceId: 'phone',
      metadata: { platform: 'ios' },
      createdAt: 123,
      expiresAt: 456,
    })

    expect(delegation.version).toBe(2)
    expect(delegation.type).toBe('device-delegation')
    expect(delegation.payload.device_id).toBe('phone')
    expect(delegation.payload.metadata).toEqual({ platform: 'ios' })
    expect(delegation.payload.created_at).toBe(123)
    expect(delegation.payload.expires_at).toBe(456)
    expect(verifyDeviceDelegation(root.publicKey, delegation)).toBe(true)
  })

  it('throws InvalidKeyError for wrong-length keys', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    expect(() => createDeviceDelegation(new Uint8Array(31), device.publicKey)).toThrow(InvalidKeyError)
    expect(() => createDeviceDelegation(root.privateKey, new Uint8Array(31))).toThrow(InvalidKeyError)
  })

  it('returns false for wrong root key or tampering', () => {
    const root = generateRootKeyPair()
    const otherRoot = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)

    expect(verifyDeviceDelegation(otherRoot.publicKey, delegation)).toBe(false)
    expect(
      verifyDeviceDelegation(root.publicKey, {
        ...delegation,
        payload: { ...delegation.payload, device_id: 'tampered' },
      }),
    ).toBe(false)

    const sig = base64url.decode(delegation.signature)
    sig[0] ^= 0xff
    expect(
      verifyDeviceDelegation(root.publicKey, {
        ...delegation,
        signature: base64url.encode(sig),
      }),
    ).toBe(false)
  })

  it('throws for wrong version or type', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)

    expect(() => verifyDeviceDelegation(root.publicKey, { ...delegation, version: 1 as 2 })).toThrow(
      InvalidDelegationError,
    )
    expect(
      () => verifyDeviceDelegation(root.publicKey, { ...delegation, type: 'wrong' as 'device-delegation' }),
    ).toThrow(InvalidDelegationError)
  })
})

describe('createDeviceProof / verifyDeviceProof', () => {
  it('creates and verifies a happy-path proof', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const proof = createDeviceProof(device.privateKey, delegation, challenge)

    expect(proof.version).toBe(2)
    expect(proof.type).toBe('device-proof')
    expect(verifyDeviceProof(root.publicKey, proof, challenge)).toBe(true)
  })

  it('throws on empty challenge during proof creation', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    expect(() => createDeviceProof(device.privateKey, delegation, new Uint8Array())).toThrow(
      InvalidDelegationError,
    )
  })

  it('rejects challenge mismatch, wrong root key, tampered device key, tampered proof, and expiry', () => {
    const root = generateRootKeyPair()
    const otherRoot = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const otherDevice = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const proof = createDeviceProof(device.privateKey, delegation, challenge)

    expect(verifyDeviceProof(root.publicKey, proof, new Uint8Array([9]))).toBe(false)
    expect(verifyDeviceProof(otherRoot.publicKey, proof, challenge)).toBe(false)

    const wrongDelegation = createDeviceDelegation(root.privateKey, otherDevice.publicKey)
    const wrongProof = createDeviceProof(device.privateKey, wrongDelegation, challenge)
    expect(verifyDeviceProof(root.publicKey, wrongProof, challenge)).toBe(false)

    const badR = base64url.decode(proof.proof.R)
    badR[0] ^= 0xff
    expect(
      () =>
        verifyDeviceProof(root.publicKey, {
          ...proof,
          proof: { ...proof.proof, R: base64url.encode(badR) },
        }, challenge),
    ).toThrow(InvalidProofError)

    const badS = base64url.decode(proof.proof.s)
    badS[0] ^= 0xff
    expect(
      verifyDeviceProof(root.publicKey, {
        ...proof,
        proof: { ...proof.proof, s: base64url.encode(badS) },
      }, challenge),
    ).toBe(false)

    const expired = createDeviceDelegation(root.privateKey, device.publicKey, { expiresAt: Date.now() - 1 })
    const expiredProof = createDeviceProof(device.privateKey, expired, challenge)
    expect(verifyDeviceProof(root.publicKey, expiredProof, challenge)).toBe(false)
  })

  it('throws for wrong version or type', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const proof = createDeviceProof(device.privateKey, delegation, challenge)

    expect(() => verifyDeviceProof(root.publicKey, { ...proof, version: 1 as 2 }, challenge)).toThrow(
      InvalidDelegationError,
    )
    expect(
      () => verifyDeviceProof(root.publicKey, { ...proof, type: 'wrong' as 'device-proof' }, challenge),
    ).toThrow(InvalidDelegationError)
  })

  it('round-trips through JSON serialization', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const proof = createDeviceProof(device.privateKey, delegation, challenge)
    const roundTrip = JSON.parse(JSON.stringify(proof))
    expect(verifyDeviceProof(root.publicKey, roundTrip, challenge)).toBe(true)
  })

  it('throws on malformed fields', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const proof = createDeviceProof(device.privateKey, delegation, challenge)

    expect(
      () => verifyDeviceDelegation(root.publicKey, { ...delegation, signature: '*' }),
    ).toThrow(InvalidDelegationError)
    expect(
      () =>
        verifyDeviceProof(root.publicKey, {
          ...proof,
          challenge: '*',
        }, challenge),
    ).toThrow(InvalidDelegationError)
    expect(
      () =>
        verifyDeviceDelegation(root.publicKey, {
          ...delegation,
          payload: { ...delegation.payload, root_public_key: '*' },
        }),
    ).toThrow(InvalidDelegationError)
    expect(
      () =>
        verifyDeviceProof(root.publicKey, {
          ...proof,
          proof: { R: '*', s: proof.proof.s },
        }, challenge),
    ).toThrow(InvalidDelegationError)
  })
})

describe('isDelegationRevoked', () => {
  it('checks revoked and unrevoked keys', () => {
    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const revoked = new Set<string>([delegation.payload.device_public_key])
    expect(isDelegationRevoked(delegation, revoked)).toBe(true)
    expect(isDelegationRevoked(delegation, new Set<string>())).toBe(false)
  })
})

describe('v1 and v2 coexistence', () => {
  it('v1 and v2 work independently end-to-end', () => {
    const v1 = generateKeyPair()
    const claim = { mode: 'v1', ok: true }
    const v1Proof = proveDisclosedJson(v1.privateKey, claim, { challenge })
    expect(verifyDisclosedJson(v1.publicKey, claim, v1Proof, { challenge })).toBe(true)

    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const v2Proof = createDeviceProof(device.privateKey, delegation, challenge)
    expect(verifyDeviceProof(root.publicKey, v2Proof, challenge)).toBe(true)
  })

  it('proves disclosed json and verifies device proof in the same process', () => {
    const v1 = generateKeyPair()
    const v1Proof = proveDisclosedJson(v1.privateKey, { mixed: 'mode' }, { challenge })

    const root = generateRootKeyPair()
    const device = generateDeviceKeyPair()
    const delegation = createDeviceDelegation(root.privateKey, device.publicKey)
    const v2Proof = createDeviceProof(device.privateKey, delegation, challenge)

    expect(verifyDisclosedJson(v1.publicKey, { mixed: 'mode' }, v1Proof, { challenge })).toBe(true)
    expect(verifyDeviceProof(root.publicKey, v2Proof, challenge)).toBe(true)
  })
})
