import {
  base64url,
  deriveKeyFromPassphrase,
  proveDisclosedJson,
  verifyDisclosedJson,
} from '../dist/index.mjs';
import QRCode from 'qrcode';
import { Html5Qrcode } from 'html5-qrcode';

const DEVICE_1 = 'demo:device1:';
const DEVICE_2 = 'demo:device2:';
const $ = (id) => document.querySelector(`#${id}`);
let scanner;

function log(message) {
  $('status').textContent += `\n${message}`;
}

function required(value, message) {
  if (!value) throw new Error(message);
  return value;
}

function run(action) {
  try {
    const result = action();
    if (result instanceof Promise) result.catch((error) => log(`ERROR: ${error.message}`));
  } catch (error) {
    log(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function showQr(text) {
    required(text, 'Create the envelope first');
    $('qr-section').hidden = false;
    $('qr-canvas').hidden = false;
    $('scanner').hidden = true;
    await QRCode.toCanvas($('qr-canvas'), text, { width: 360, margin: 2 });
  }

async function scanQr(targetId) {
    $('qr-section').hidden = false;
    $('qr-canvas').hidden = true;
    $('scanner').hidden = false;
    scanner = new Html5Qrcode('scanner');
    await scanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      async (decodedText) => {
        $(targetId).value = decodedText;
        await scanner.stop();
        scanner.clear();
        scanner = undefined;
        $('qr-section').hidden = true;
        log(`QR scanned into ${targetId}.`);
      },
      () => {},
    );
  }

async function closeScanner() {
    if (scanner) {
      await scanner.stop();
      scanner.clear();
      scanner = undefined;
    }
    $('qr-section').hidden = true;
}

function device1Setup() {
  const created = deriveKeyFromPassphrase($('passphrase').value);
  localStorage.setItem(`${DEVICE_1}salt`, created.salt);
  localStorage.setItem(`${DEVICE_1}privateKey`, base64url.encode(created.keyPair.privateKey));
  localStorage.setItem(`${DEVICE_1}publicKey`, base64url.encode(created.keyPair.publicKey));
  $('pairing-request').value = '';
  $('proof-response').value = '';
  $('data-export').value = '';
  $('device1-export').disabled = true;
  log('Device 1 identity created and stored locally.');
}

function device1Data() {
  const data = {
    user: 'alice',
    preferences: { theme: 'dark', notifications: true },
    createdAt: new Date().toISOString(),
  };
  localStorage.setItem(`${DEVICE_1}data`, JSON.stringify(data));
  log('Device 1 sample data stored locally.');
}

function device1PairingRequest() {
  const publicKey = required(
    localStorage.getItem(`${DEVICE_1}publicKey`),
    'Create Device 1 identity first',
  );
  const salt = required(localStorage.getItem(`${DEVICE_1}salt`), 'Missing Device 1 salt');
  const challenge = base64url.encode(crypto.getRandomValues(new Uint8Array(32)));
  const request = {
    version: 1,
    type: 'pair-request',
    publicKey,
    salt,
    challenge,
    claim: { action: 'pair-device', device: 'device-2' },
  };
  $('pairing-request').value = JSON.stringify(request);
  log('Pairing request created. Copy it into Device 2.');
}

function device2CreateProof() {
  const request = JSON.parse(required($('pairing-input').value, 'Paste the pairing request first'));
  if (request.version !== 1 || request.type !== 'pair-request') {
    throw new Error('Invalid pairing request');
  }
  const derived = deriveKeyFromPassphrase($('passphrase').value, { salt: request.salt });
  if (base64url.encode(derived.keyPair.publicKey) !== request.publicKey) {
    throw new Error('Passphrase does not derive Device 1 identity');
  }
  const proof = proveDisclosedJson(
    derived.keyPair.privateKey,
    request.claim,
    { challenge: base64url.decode(request.challenge) },
  );
  const response = { version: 1, type: 'pair-response', proof };
  $('proof-output').value = JSON.stringify(response);
  localStorage.setItem(`${DEVICE_2}privateKey`, base64url.encode(derived.keyPair.privateKey));
  localStorage.setItem(`${DEVICE_2}publicKey`, base64url.encode(derived.keyPair.publicKey));
  log('Device 2 created a proof. Copy it into Device 1.');
}

function device1Verify() {
  const request = JSON.parse(required($('pairing-request').value, 'Create a pairing request first'));
  const response = JSON.parse(required($('proof-response').value, 'Paste the proof response first'));
  const usedChallengeKey = `${DEVICE_1}used:${request.challenge}`;
  if (localStorage.getItem(usedChallengeKey) === 'true') {
    throw new Error('Pairing challenge was already consumed');
  }
  const publicKey = base64url.decode(
    required(localStorage.getItem(`${DEVICE_1}publicKey`), 'Create Device 1 identity first'),
  );
  const trusted = verifyDisclosedJson(
    publicKey,
    request.claim,
    response.proof,
    { challenge: base64url.decode(request.challenge) },
  );
  if (!trusted) throw new Error('Device 1 rejected Device 2 proof');
  localStorage.setItem(usedChallengeKey, 'true');
  localStorage.setItem(`${DEVICE_1}trustedDevice2`, 'true');
  $('device1-export').disabled = false;
  log('Device 1 trusts Device 2. The proof matched the fresh challenge.');
}

async function encryptionKey(privateKey) {
  const digest = await crypto.subtle.digest('SHA-256', privateKey);
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function device1Export() {
  if (localStorage.getItem(`${DEVICE_1}trustedDevice2`) !== 'true') {
    throw new Error('Verify Device 2 before exporting');
  }
  const privateKey = base64url.decode(
    required(localStorage.getItem(`${DEVICE_1}privateKey`), 'Missing Device 1 private key'),
  );
  const data = required(localStorage.getItem(`${DEVICE_1}data`), 'Create sample data first');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(privateKey);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(data),
  );
  const payload = {
    version: 1,
    type: 'data-export',
    iv: base64url.encode(iv),
    ciphertext: base64url.encode(new Uint8Array(ciphertext)),
  };
  $('data-export').value = JSON.stringify(payload);
  $('device2-import').disabled = false;
  log('Encrypted data export created. Copy it into Device 2.');
}

async function device2Import() {
  const payload = JSON.parse(required($('export-input').value, 'Paste the encrypted export first'));
  if (payload.version !== 1 || payload.type !== 'data-export') {
    throw new Error('Invalid data export');
  }
  const privateKey = base64url.decode(
    required(localStorage.getItem(`${DEVICE_2}privateKey`), 'Create Device 2 proof first'),
  );
  const key = await encryptionKey(privateKey);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64url.decode(payload.iv) },
    key,
    base64url.decode(payload.ciphertext),
  );
  const data = new TextDecoder().decode(plaintext);
  localStorage.setItem(`${DEVICE_2}data`, data);
  log(`Device 2 decrypted and imported: ${data}`);
}

$('device1-setup').addEventListener('click', () => run(device1Setup));
$('device1-data').addEventListener('click', () => run(device1Data));
$('device1-request').addEventListener('click', () => run(device1PairingRequest));
$('device1-request-qr').addEventListener('click', () => run(() => showQr($('pairing-request').value)));
$('device1-proof-scan').addEventListener('click', () => run(() => scanQr('proof-response')));
$('device2-prove').addEventListener('click', () => run(device2CreateProof));
$('device2-request-scan').addEventListener('click', () => run(() => scanQr('pairing-input')));
$('device2-proof-qr').addEventListener('click', () => run(() => showQr($('proof-output').value)));
$('device1-verify').addEventListener('click', () => run(device1Verify));
$('device1-export').addEventListener('click', () => run(device1Export));
$('device2-import').addEventListener('click', () => run(device2Import));
$('close-scanner').addEventListener('click', () => run(closeScanner));
