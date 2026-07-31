import {
  base64url,
  deriveKeyFromPassphrase,
  proveDisclosedJson,
  verifyDisclosedJson,
} from '../dist/index.mjs';

const DEVICE_1 = 'demo:device1:';
const DEVICE_2 = 'demo:device2:';
const status = document.querySelector('#status');
const transferButton = document.querySelector('#transfer');

function log(message) {
  status.textContent += `\n${message}`;
}

function required(value, name) {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function passphrase() {
  return required(document.querySelector('#passphrase').value, 'Passphrase');
}

function createDevice1() {
  const created = deriveKeyFromPassphrase(passphrase());
  localStorage.setItem(`${DEVICE_1}salt`, created.salt);
  localStorage.setItem(`${DEVICE_1}privateKey`, base64url.encode(created.keyPair.privateKey));
  localStorage.setItem(`${DEVICE_1}publicKey`, base64url.encode(created.keyPair.publicKey));
  log('Device 1 identity created and stored.');
  log(`Trusted public key: ${localStorage.getItem(`${DEVICE_1}publicKey`)}`);
}

function seedData() {
  const data = {
    user: 'alice',
    preferences: { theme: 'dark', notifications: true },
    createdAt: new Date().toISOString(),
  };
  localStorage.setItem(`${DEVICE_1}data`, JSON.stringify(data));
  log('Device 1 sample data stored.');
}

function pairDevice2() {
  const salt = required(localStorage.getItem(`${DEVICE_1}salt`), 'Create Device 1 identity first');
  const publicKey = base64url.decode(
    required(localStorage.getItem(`${DEVICE_1}publicKey`), 'Device 1 public key'),
  );
  const device2 = deriveKeyFromPassphrase(passphrase(), { salt });
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const claim = { action: 'pair-device', device: 'device-2' };
  const proof = proveDisclosedJson(device2.keyPair.privateKey, claim, { challenge });
  const trusted = verifyDisclosedJson(publicKey, claim, proof, { challenge });

  if (!trusted) throw new Error('Device 1 rejected Device 2');
  localStorage.setItem(`${DEVICE_2}trusted`, 'true');
  transferButton.disabled = false;
  log('Device 1 verified Device 2: proof accepted for a fresh challenge.');
}

function transferData() {
  if (localStorage.getItem(`${DEVICE_2}trusted`) !== 'true') {
    throw new Error('Pair Device 2 before transferring data');
  }
  const data = required(localStorage.getItem(`${DEVICE_1}data`), 'Create sample data first');
  localStorage.setItem(`${DEVICE_2}data`, data);
  log(`Device 2 imported: ${data}`);
}

function run(action) {
  try {
    action();
  } catch (error) {
    log(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
  }
}

document.querySelector('#setup').addEventListener('click', () => run(createDevice1));
document.querySelector('#seed-data').addEventListener('click', () => run(seedData));
document.querySelector('#pair').addEventListener('click', () => run(pairDevice2));
transferButton.addEventListener('click', () => run(transferData));
