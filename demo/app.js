import {
  base64url,
  deriveKeyFromPassphrase,
  proveDisclosedJson,
  verifyDisclosedJson,
  generateRootKeyPair,
  generateDeviceKeyPair,
  createDeviceDelegation,
  verifyDeviceDelegation,
  createDeviceProof,
  verifyDeviceProof,
} from '../dist/index.mjs'
import QRCode from 'qrcode'
import { Html5Qrcode } from 'html5-qrcode'

const DEVICE_1 = 'demo:device1:'
const DEVICE_2 = 'demo:device2:'
const V2_ROOT = 'demo:v2:root:'
const V2_DEVICE = 'demo:v2:device:'
const $ = (id) => document.querySelector(`#${id}`)
let scanner

function log(message) {
  $('status').textContent += `
${message}`
}

function required(value, message) {
  if (!value) throw new Error(message)
  return value
}

function run(action) {
  try {
    const result = action()
    if (result instanceof Promise) result.catch((error) => log(`ERROR: ${error.message}`))
  } catch (error) {
    log(`ERROR: ${error instanceof Error ? error.message : String(error)}`)
  }
}

async function showQr(text) {
  required(text, 'Create the envelope first')
  $('qr-section').hidden = false
  $('qr-canvas').hidden = false
  $('scanner').hidden = true
  await QRCode.toCanvas($('qr-canvas'), text, { width: 360, margin: 2 })
}

async function scanQr(targetId) {
  $('qr-section').hidden = false
  $('qr-canvas').hidden = true
  $('scanner').hidden = false
  scanner = new Html5Qrcode('scanner')
  await scanner.start(
    { facingMode: 'environment' },
    { fps: 10, qrbox: { width: 250, height: 250 } },
    async (decodedText) => {
      $(targetId).value = decodedText
      await scanner.stop()
      scanner.clear()
      scanner = undefined
      $('qr-section').hidden = true
      log(`QR scanned into ${targetId}.`)
    },
    () => {},
  )
}

async function closeScanner() {
  if (scanner) {
    await scanner.stop()
    scanner.clear()
    scanner = undefined
  }
  $('qr-section').hidden = true
}

function device1Setup() {
  const created = deriveKeyFromPassphrase($('passphrase').value)
  localStorage.setItem(`${DEVICE_1}salt`, created.salt)
  localStorage.setItem(`${DEVICE_1}privateKey`, base64url.encode(created.keyPair.privateKey))
  localStorage.setItem(`${DEVICE_1}publicKey`, base64url.encode(created.keyPair.publicKey))
  $('pairing-request').value = ''
  $('proof-response').value = ''
  $('data-export').value = ''
  $('device1-export').disabled = true
  log('Device 1 identity created and stored locally.')
}

function device1Data() {
  const data = {
    user: 'alice',
    preferences: { theme: 'dark', notifications: true },
    createdAt: new Date().toISOString(),
  }
  localStorage.setItem(`${DEVICE_1}data`, JSON.stringify(data))
  log('Device 1 sample data stored locally.')
}

function device1PairingRequest() {
  const publicKey = required(
    localStorage.getItem(`${DEVICE_1}publicKey`),
    'Create Device 1 identity first',
  )
  const salt = required(localStorage.getItem(`${DEVICE_1}salt`), 'Missing Device 1 salt')
  const challenge = base64url.encode(crypto.getRandomValues(new Uint8Array(32)))
  const request = {
    version: 1,
    type: 'pair-request',
    publicKey,
    salt,
    challenge,
    claim: { action: 'pair-device', device: 'device-2' },
  }
  $('pairing-request').value = JSON.stringify(request, null, 2)
  log('Pairing request created. Copy it into Device 2.')
}

function device2CreateProof() {
  const request = JSON.parse(required($('pairing-input').value, 'Paste the pairing request first'))
  if (request.version !== 1 || request.type !== 'pair-request') {
    throw new Error('Invalid pairing request')
  }
  const derived = deriveKeyFromPassphrase($('passphrase').value, { salt: request.salt })
  if (base64url.encode(derived.keyPair.publicKey) !== request.publicKey) {
    throw new Error('Passphrase does not derive Device 1 identity')
  }
  const proof = proveDisclosedJson(
    derived.keyPair.privateKey,
    request.claim,
    { challenge: base64url.decode(request.challenge) },
  )
  const response = { version: 1, type: 'pair-response', proof }
  $('proof-output').value = JSON.stringify(response, null, 2)
  localStorage.setItem(`${DEVICE_2}privateKey`, base64url.encode(derived.keyPair.privateKey))
  localStorage.setItem(`${DEVICE_2}publicKey`, base64url.encode(derived.keyPair.publicKey))
  log('Device 2 created a proof. Copy it into Device 1.')
}

function device1Verify() {
  const request = JSON.parse(required($('pairing-request').value, 'Create a pairing request first'))
  const response = JSON.parse(required($('proof-response').value, 'Paste the proof response first'))
  const usedChallengeKey = `${DEVICE_1}used:${request.challenge}`
  if (localStorage.getItem(usedChallengeKey) === 'true') {
    throw new Error('Pairing challenge was already consumed')
  }
  const publicKey = base64url.decode(
    required(localStorage.getItem(`${DEVICE_1}publicKey`), 'Create Device 1 identity first'),
  )
  const trusted = verifyDisclosedJson(
    publicKey,
    request.claim,
    response.proof,
    { challenge: base64url.decode(request.challenge) },
  )
  if (!trusted) throw new Error('Device 1 rejected Device 2 proof')
  localStorage.setItem(usedChallengeKey, 'true')
  localStorage.setItem(`${DEVICE_1}trustedDevice2`, 'true')
  $('device1-export').disabled = false
  log('Device 1 trusts Device 2. The proof matched the fresh challenge.')
}

async function encryptionKey(privateKey) {
  const digest = await crypto.subtle.digest('SHA-256', privateKey)
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

async function device1Export() {
  if (localStorage.getItem(`${DEVICE_1}trustedDevice2`) !== 'true') {
    throw new Error('Verify Device 2 before exporting')
  }
  const privateKey = base64url.decode(
    required(localStorage.getItem(`${DEVICE_1}privateKey`), 'Missing Device 1 private key'),
  )
  const data = required(localStorage.getItem(`${DEVICE_1}data`), 'Create sample data first')
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await encryptionKey(privateKey)
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(data),
  )
  const payload = {
    version: 1,
    type: 'data-export',
    iv: base64url.encode(iv),
    ciphertext: base64url.encode(new Uint8Array(ciphertext)),
  }
  $('data-export').value = JSON.stringify(payload, null, 2)
  $('device2-import').disabled = false
  log('Encrypted data export created. Copy it into Device 2.')
}

async function device2Import() {
  const payload = JSON.parse(required($('export-input').value, 'Paste the encrypted export first'))
  if (payload.version !== 1 || payload.type !== 'data-export') {
    throw new Error('Invalid data export')
  }
  const privateKey = base64url.decode(
    required(localStorage.getItem(`${DEVICE_2}privateKey`), 'Create Device 2 proof first'),
  )
  const key = await encryptionKey(privateKey)
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64url.decode(payload.iv) },
    key,
    base64url.decode(payload.ciphertext),
  )
  const data = new TextDecoder().decode(plaintext)
  localStorage.setItem(`${DEVICE_2}data`, data)
  log(`Device 2 decrypted and imported: ${data}`)
}

function v2RootSetup() {
  const root = generateRootKeyPair()
  localStorage.setItem(`${V2_ROOT}privateKey`, base64url.encode(root.privateKey))
  localStorage.setItem(`${V2_ROOT}publicKey`, base64url.encode(root.publicKey))
  $('v2-root-public').value = JSON.stringify({ root_public_key: base64url.encode(root.publicKey) }, null, 2)
  log('v2 root identity created on Device 1.')
}

function v2DeviceSetup() {
  const device = generateDeviceKeyPair()
  localStorage.setItem(`${V2_DEVICE}privateKey`, base64url.encode(device.privateKey))
  localStorage.setItem(`${V2_DEVICE}publicKey`, base64url.encode(device.publicKey))
  log('v2 device key created on Device 2.')
}

function v2EnrollmentRequest() {
  const devicePublicKey = required(
    localStorage.getItem(`${V2_DEVICE}publicKey`),
    'Create the v2 device key first',
  )
  const request = {
    version: 2,
    type: 'device-enrollment-request',
    device_public_key: devicePublicKey,
    device_id: $('v2-device-id').value || undefined,
    metadata: { demo: true },
    created_at: Date.now(),
  }
  $('v2-request').value = JSON.stringify(request, null, 2)
  $('v2-request-input').value = $('v2-request').value
  log('v2 enrollment request created on Device 2.')
}

function v2SignDelegation() {
  const rootPrivateKey = base64url.decode(
    required(localStorage.getItem(`${V2_ROOT}privateKey`), 'Create the v2 root identity first'),
  )
  const request = JSON.parse(required($('v2-request-input').value, 'Paste the enrollment request first'))
  if (request.version !== 2 || request.type !== 'device-enrollment-request') {
    throw new Error('Invalid v2 enrollment request')
  }
  const delegation = createDeviceDelegation(
    rootPrivateKey,
    base64url.decode(request.device_public_key),
    {
      deviceId: request.device_id,
      metadata: request.metadata,
      expiresAt: Date.now() + 15 * 60 * 1000,
    },
  )
  $('v2-delegation').value = JSON.stringify(delegation, null, 2)
  $('v2-delegation-input').value = $('v2-delegation').value
  log('v2 signed delegation created on Device 1.')
}

function v2CreateChallenge() {
  const challenge = {
    version: 2,
    type: 'device-challenge',
    challenge: base64url.encode(crypto.getRandomValues(new Uint8Array(32))),
    created_at: Date.now(),
  }
  $('v2-challenge-value').value = JSON.stringify(challenge, null, 2)
  $('v2-challenge-input').value = $('v2-challenge-value').value
  log('v2 verifier challenge created on Device 1.')
}

function v2VerifyDelegationOnDevice() {
  const rootPublicKey = base64url.decode(
    required(localStorage.getItem(`${V2_ROOT}publicKey`), 'Create the v2 root identity first'),
  )
  const delegation = JSON.parse(required($('v2-delegation-input').value, 'Paste the delegation first'))
  const ok = verifyDeviceDelegation(rootPublicKey, delegation)
  if (!ok) throw new Error('Device 2 rejected the delegation')
  log('Device 2 verified the v2 delegation signature from Device 1.')
}

function v2CreateProof() {
  const devicePrivateKey = base64url.decode(
    required(localStorage.getItem(`${V2_DEVICE}privateKey`), 'Create the v2 device key first'),
  )
  const delegation = JSON.parse(required($('v2-delegation-input').value, 'Paste the delegation first'))
  const challengeEnvelope = JSON.parse(
    required($('v2-challenge-input').value, 'Paste the verifier challenge first'),
  )
  if (challengeEnvelope.version !== 2 || challengeEnvelope.type !== 'device-challenge') {
    throw new Error('Invalid v2 challenge envelope')
  }
  const rootPublicKey = base64url.decode(
    required(localStorage.getItem(`${V2_ROOT}publicKey`), 'Create the v2 root identity first'),
  )
  if (!verifyDeviceDelegation(rootPublicKey, delegation)) {
    throw new Error('Device 2 rejected the delegation')
  }
  const proof = createDeviceProof(
    devicePrivateKey,
    delegation,
    base64url.decode(challengeEnvelope.challenge),
  )
  $('v2-proof').value = JSON.stringify(proof, null, 2)
  $('v2-proof-input').value = $('v2-proof').value
  log('Device 2 created a v2 device proof bound to the challenge.')
}

function v2VerifyProof() {
  const rootPublicKey = base64url.decode(
    required(localStorage.getItem(`${V2_ROOT}publicKey`), 'Create the v2 root identity first'),
  )
  const challengeEnvelope = JSON.parse(
    required($('v2-challenge-value').value, 'Create the verifier challenge first'),
  )
  const proof = JSON.parse(required($('v2-proof-input').value, 'Paste the device proof first'))
  const ok = verifyDeviceProof(rootPublicKey, proof, base64url.decode(challengeEnvelope.challenge))
  if (!ok) throw new Error('Device 1 rejected the v2 device proof')
  log('Device 1 accepted the v2 device proof and delegation.')
}

$('device1-setup').addEventListener('click', () => run(device1Setup))
$('device1-data').addEventListener('click', () => run(device1Data))
$('device1-request').addEventListener('click', () => run(device1PairingRequest))
$('device1-request-qr').addEventListener('click', () => run(() => showQr($('pairing-request').value)))
$('device1-proof-scan').addEventListener('click', () => run(() => scanQr('proof-response')))
$('device2-prove').addEventListener('click', () => run(device2CreateProof))
$('device2-request-scan').addEventListener('click', () => run(() => scanQr('pairing-input')))
$('device2-proof-qr').addEventListener('click', () => run(() => showQr($('proof-output').value)))
$('device1-verify').addEventListener('click', () => run(device1Verify))
$('device1-export').addEventListener('click', () => run(device1Export))
$('device2-import').addEventListener('click', () => run(device2Import))
$('v2-root-setup').addEventListener('click', () => run(v2RootSetup))
$('v2-device-setup').addEventListener('click', () => run(v2DeviceSetup))
$('v2-enrollment-request').addEventListener('click', () => run(v2EnrollmentRequest))
$('v2-sign-delegation').addEventListener('click', () => run(v2SignDelegation))
$('v2-challenge').addEventListener('click', () => run(v2CreateChallenge))
$('v2-create-proof').addEventListener('click', () => run(v2CreateProof))
$('v2-verify-proof').addEventListener('click', () => run(v2VerifyProof))
$('v2-request-qr').addEventListener('click', () => run(() => showQr($('v2-request').value)))
$('v2-request-scan').addEventListener('click', () => run(() => scanQr('v2-request-input')))
$('v2-delegation-qr').addEventListener('click', () => run(() => showQr($('v2-delegation').value)))
$('v2-delegation-scan').addEventListener('click', () => run(() => scanQr('v2-delegation-input')))
$('v2-challenge-qr').addEventListener('click', () => run(() => showQr($('v2-challenge-value').value)))
$('v2-challenge-scan').addEventListener('click', () => run(() => scanQr('v2-challenge-input')))
$('v2-proof-qr').addEventListener('click', () => run(() => showQr($('v2-proof').value)))
$('v2-proof-scan').addEventListener('click', () => run(() => scanQr('v2-proof-input')))
$('close-scanner').addEventListener('click', () => run(closeScanner))
