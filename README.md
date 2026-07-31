# zkp-browser

A TypeScript library for **identity and device trust** using **Schnorr zero-knowledge proofs** over **Ristretto255**.  
Works in Node.js (16+) and modern browsers. Ships as both CommonJS (`dist/index.js`) and ES module (`dist/index.mjs`).

---

## Contents

- [Cryptography overview](#cryptography-overview)
- [Offline device-to-device sync](#offline-device-to-device-sync)
- [Per-device identity (v2)](#per-device-identity-v2)
- [Security model](#security-model)
- [API reference](#api-reference)
- [Quick start](#quick-start)
- [Security notes and caveats](#security-notes-and-caveats)
- [Running the browser demo](#running-the-browser-demo)

---

## Running the browser demo

Build and serve the demo locally:

```bash
npm install
npm run demo
```

Open <http://localhost:4173/demo/> in **two separate browsers** (or two private
windows). Use the same passphrase in both. Perform these steps:

1. In Browser 1, click **Create Device 1 identity** and **Create sample data**.
2. In Browser 1, click **Create pairing request**, then copy its JSON.
3. In Browser 2, paste the request and click **Create proof**.
4. Copy Browser 2's proof response into Browser 1 and click **Verify Device 2**.
5. In Browser 1, click **Export data after trust**.
6. Copy the encrypted export into Browser 2 and click **Decrypt and import data**.

Do not use two ordinary tabs in the same browser when testing isolation:
same-browser tabs normally share the same origin storage. Two separate
browsers or separate private browsing sessions provide independent storage.
The data must be copied manually between the labeled text areas:

| Envelope | Copy from | Paste into |
|---|---|---|
| Pairing request | Browser 1: **Pairing request** | Browser 2: **Pairing request from Device 1** |
| Proof response | Browser 2: **Proof response** | Browser 1: **Proof response from Device 2** |
| Data export | Browser 1: **Encrypted data export** | Browser 2: **Encrypted data export from Device 1** |

The demo supports both copy/paste and QR codes. Use **Show pairing QR** and
**Show proof QR** to display envelopes, or use the scan buttons to read them
with the camera. Camera access requires `localhost` or HTTPS and browser
permission. The demo exercises separate browser LocalStorage instances,
passphrase derivation, challenge-bound proof generation and verification, and
an AES-GCM-encrypted JSON transfer. A separate **Per-Device Identity (v2)**
section demonstrates root-key delegation to a per-device key. WebRTC is not
included; it is an alternative transport for production deployment.

---

## Cryptography overview

| Primitive | Algorithm | Rationale |
|-----------|-----------|-----------|
| Identity keys | Ristretto255 (Schnorr proof) | Prime-order group, no cofactor, avoids Ed25519 malleability |
| Schnorr proof | Fiat-Shamir non-interactive sigma protocol | Real proof of knowledge of discrete log; not a signature disguised as ZKP |
| Key derivation (passphrase) | PBKDF2-SHA-512 (600 000 iter) → HKDF-SHA-512 | Brute-force resistance + domain separation |
| Key transfer (device onboarding) | ChaCha20-Poly1305, key from PBKDF2+HKDF | Authenticated encryption, 256-bit security |
| Hash function | SHA-512 | 512-bit commitment and message binding |
| Domain separation | 1-byte length-prefix + ASCII domain tag in challenge | Prevents cross-protocol proof reuse |
| Serialisation | base64url (no padding) | JSON- and QR-safe; no `+` `/` `=` characters |
| Canonical JSON | RFC 8785 JSON Canonicalization Scheme | Deterministic binding to JSON values |

### Schnorr protocol

```
private key seed → x = H(domain ‖ seed) mod l    (l = Ristretto255 group order)
public key P = x · G

Prove(x, message, domain):
  r ←$ [1, l-1]
  R = r · G
  c = SHA-512(domainLen ‖ domain ‖ P ‖ R ‖ message) mod l
  s = (r + c·x) mod l
  proof = (R, s)

Verify(P, message, domain, proof):
  c = SHA-512(domainLen ‖ domain ‖ P ‖ R ‖ message) mod l
  check: s·G == R + c·P
```

This is a honest-verifier zero-knowledge proof of knowledge under the discrete-log assumption.

### Proof domains

| Domain string | Usage |
|---|---|
| `zkp-browser/v1/disclosed-json` | Disclosed JSON integrity proof |
| `zkp-browser/v1/hidden-commitment` | Hidden commitment (before opening) |

---

## Offline device-to-device sync

This library supports a web app with no login service, backend, or database.
Each browser has separate `localStorage`; Browser 2 cannot read Browser 1's
storage merely by opening the same URL. The application must pair the devices
and transfer an export explicitly.

### Trust model

Browser 1 is the initial trust anchor. On first use it generates an identity
keypair:

```ts
const identity = generateKeyPair();
```

Store the private key encrypted locally and keep the public key as the
identity identifier. Browser 2 must obtain the same identity secret through
passphrase derivation or encrypted one-time transfer. Independently generated
random keypairs will not match.

The proof establishes that Browser 2 knows the private key associated with
Browser 1's trusted public key. It does not prove who is physically operating
the browser, so the user must authorize initial setup and pairing.

### Identity lifecycle in the web app

Device 1 must create the identity only once, during first-time application
setup when the user creates the passphrase. Do not generate a new identity on
every application launch:

```ts
const salt = localStorage.getItem('identity-salt');

if (salt === null) {
  const created = deriveKeyFromPassphrase(firstPassphrase);
  localStorage.setItem('identity-salt', created.salt);
  localStorage.setItem('identity-public-key', base64url.encode(created.keyPair.publicKey));
  // Store the private key encrypted; do not store the passphrase.
}
```

On subsequent launches, ask the user for the passphrase, load the stored salt,
and derive the same keypair:

```ts
const storedSalt = localStorage.getItem('identity-salt');
const storedPublicKey = localStorage.getItem('identity-public-key');
if (!storedSalt || !storedPublicKey) {
  throw new Error('Identity setup is incomplete');
}

const unlocked = deriveKeyFromPassphrase(passphrase, { salt: storedSalt });
const publicKey = base64url.encode(unlocked.keyPair.publicKey);
if (publicKey !== storedPublicKey) {
  throw new Error('Incorrect passphrase');
}
```

The application may use the passphrase it already collected for unlocking the
app, but it should not persist that passphrase in `localStorage`. Store the
salt and public key, and keep the passphrase and decrypted private key in
memory only where possible. A new salt or passphrase creates a different
identity and will no longer match previously paired devices.

### Recommended pairing flow

1. Browser 2 creates a fresh unpredictable challenge and sends a pairing
   request to Browser 1 through QR, copy/paste, or another local channel.
2. Browser 1 asks the user to approve the pairing.
3. Browser 2 obtains the identity secret and creates a challenge-bound proof:

   ```ts
   const proof = proveDisclosedJson(
     identity.privateKey,
     { action: 'pair-device' },
     { challenge },
   );
   ```

4. Browser 2 sends the proof back. Browser 1 verifies it against its stored
   public key, never the `public_key` field from the envelope:

   ```ts
   const trusted = verifyDisclosedJson(
     identity.publicKey,
     { action: 'pair-device' },
     proof,
     { challenge },
   );
   ```

5. Browser 1 checks that the challenge has not already been consumed. Only
   after successful verification and user approval should it export data.
6. Browser 1 sends an authenticated encrypted export, and Browser 2 imports
   it into its own origin's `localStorage`.

The library supplies key and proof primitives. The application implements the
pairing UI, QR encoding/decoding, challenge tracking, data-export format, and
transport.

### Enrollment option A: passphrase derivation

Both browsers derive the same identity keypair from the same passphrase and
salt:

```ts
// Browser 1: initial setup
const created = deriveKeyFromPassphrase(passphrase);
localStorage.setItem('identity-salt', created.salt);
// Store created.keyPair.privateKey encrypted and retain its public key.

// Browser 2: pairing
const salt = receivedSalt;
const derived = deriveKeyFromPassphrase(passphrase, { salt });
// derived.keyPair.publicKey must match Browser 1's trusted public key.
```

The salt is not secret, but it is required for deterministic derivation.
PBKDF2 slows guessing; it cannot make a weak passphrase strong. Prefer a
high-entropy recovery secret or password-manager-generated passphrase.

### Enrollment option B: encrypted QR transfer

Browser 1 can encrypt its private key for a one-time transfer:

```ts
const payload = encryptKeyTransfer(
  identity.privateKey,
  oneTimeTransferPassword,
);
// Encode JSON.stringify(payload) as a QR code.
```

Browser 2 scans and decrypts it:

```ts
const privateKey = decryptKeyTransfer(
  scannedPayload,
  oneTimeTransferPassword,
);
const publicKey = publicKeyFromPrivate(privateKey);
```

The payload uses authenticated encryption, but the transfer password must be
delivered securely and separately. Generate a fresh payload and password for
every transfer, expire the pairing request, and mark it single-use. Anyone
with both the payload and password can recover the identity private key.

### Transferring LocalStorage data

For a small export, QR codes or copy/paste are sufficient. For a large export,
use a WebRTC data channel; without a backend, WebRTC signaling can still be
performed manually through QR or copy/paste.

Never send raw `localStorage` contents over an unencrypted channel. A transfer
envelope should include the consumed pairing challenge, an explicit schema
version, and an authenticated encrypted data payload. This library does not
yet implement the complete QR/WebRTC transport or a `localStorage` sync
helper; those belong in the web app around these primitives.

`localStorage` and JavaScript-visible keys remain accessible to malicious
JavaScript running under the same origin. Use HTTPS, a strict Content
Security Policy, dependency auditing, and encrypted IndexedDB where
appropriate.

---

## Per-device identity (v2)

### Which model should your application use?

There are two different meanings of “same user” in this library:

| Mode | How devices are recognized | Same passphrase required? | Main trade-off |
|---|---|---:|---|
| **v1 shared identity** | Every device has the same private key | **Yes** | Simple, but one leaked device key affects every device |
| **v2 per-device identity** | Device 1 approves each device key with a root key | **No** | Safer isolation, but every new device requires approval |

For a multi-device web app where one user wants to access the same data without
a backend, **v2 is recommended**. The passphrase protects and unlocks the root
identity on Device 1; it is not copied to Device 2. Device 2 can use a
different local passphrase to protect its own private key.

The important security statement is:

> A successful v2 proof means “this device owns a key previously approved by
> the trusted Device 1,” not “the browser proved the user's real-world
> identity.”

There is no centralized login, server, or database in this model. Device 1 is
the initial trust anchor, and the user must approve each new device. After
verification, the web app—not this library—must send selected data through an
authenticated encrypted transfer and store it in Device 2's LocalStorage.

### What happens when the web app opens?

On Device 1, create the root identity only once during first-time setup. Ask
for the user's passphrase on later launches and use it to unlock the encrypted
root private key. Never generate a new root identity on every launch and never
store the passphrase as plaintext in LocalStorage.

On a new Device 2:

1. Generate a new device keypair locally.
2. Send the device public key to Device 1 by QR code, copy/paste, or another
   local channel.
3. Device 1 asks the user to approve the device and signs a delegation.
4. Send the signed delegation back to Device 2.
5. Store the device private key and delegation on Device 2.
6. For each future data request, Device 1 sends a fresh challenge.
7. Device 2 returns the delegation and a proof of its own private key.
8. Device 1 verifies the proof, checks revocation, and transfers data only
   after success.

v2 adds a backward-compatible per-device identity mode. Instead of copying the
same private key to every device, Device 1 keeps a long-term **Ed25519 root
key** and signs a **delegation** for each device's own **Ristretto255** key.
Authentication still uses the existing Schnorr proof machinery, but each device
now proves possession of its *own* private key.

### Overview

- **Root identity:** Ed25519 key pair on Device 1 only.
- **Per-device keys:** Ristretto255 key pairs, one per browser/device.
- **Delegation:** root signs canonical JSON authorizing a device public key.
- **Authentication:** device creates a Schnorr proof bound to both the signed
  delegation and the verifier's fresh challenge.

This gives a QR-friendly enrollment flow without ever sending the root private
key to a second device.

### First-time new-device enrollment flow

1. **Device 2** generates a fresh device key:

   ```ts
   const device = generateDeviceKeyPair()
   ```

2. **Device 2** sends Device 1 its `device.publicKey` plus an optional
   human-readable label and metadata via QR, copy/paste, or another local
   channel.

3. **Device 1** signs a delegation with the root private key:

   ```ts
   const root = generateRootKeyPair()
   const delegation = createDeviceDelegation(root.privateKey, device.publicKey, {
     deviceId: 'iPhone 14 Pro',
     metadata: { platform: 'ios' },
     expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
   })
   ```

4. **Device 1** sends the signed `delegation` back to Device 2.
5. **Device 2** stores its device private key and the signed delegation.

The exchange is QR-code friendly because the enrollment request and delegation
are plain JSON with base64url-encoded binary fields.

### Authentication flow

1. **Verifier** issues a fresh unpredictable challenge.
2. **Device 2** creates a proof bound to both the challenge and its signed
   delegation:

   ```ts
   const challenge = crypto.getRandomValues(new Uint8Array(32))
   const proof = createDeviceProof(device.privateKey, delegation, challenge)
   ```

3. **Verifier** checks the root signature, optional expiry, and device proof:

   ```ts
   const ok = verifyDeviceProof(root.publicKey, proof, challenge)
   ```

4. After success, the verifier must mark the challenge consumed to prevent
   replay.

### Revocation guidance

Revocation is application-level. Keep a persistent set of revoked device public
keys and check it after `verifyDeviceProof` succeeds:

```ts
const revokedKeys = new Set<string>(loadRevokedKeysFromStorage())
const ok = verifyDeviceProof(root.publicKey, proof, challenge)
  && !isDelegationRevoked(proof.delegation, revokedKeys)
```

To revoke a device, add `delegation.payload.device_public_key` to the set.
For time-bounded trust, also set `expiresAt` when creating the delegation.

### v2 API reference

```ts
import {
  generateRootKeyPair,
  generateDeviceKeyPair,
  createDeviceDelegation,
  verifyDeviceDelegation,
  createDeviceProof,
  verifyDeviceProof,
  isDelegationRevoked,
} from 'zkp-browser'
```

- `generateRootKeyPair() → RootKeyPair` — creates the Ed25519 root key pair.
- `generateDeviceKeyPair() → KeyPair` — creates a Ristretto255 device key pair.
- `createDeviceDelegation(rootPrivKey, devicePublicKey, options?) → DeviceDelegation`
- `verifyDeviceDelegation(rootPublicKey, delegation) → boolean`
- `createDeviceProof(devicePrivKey, delegation, challenge) → DeviceProof`
- `verifyDeviceProof(rootPublicKey, deviceProof, challenge) → boolean`
- `isDelegationRevoked(delegation, revokedKeys) → boolean`

### Demo note

The original browser pairing flow in the demo is **v1** (shared identity via
passphrase-derived pairing). The new **Per-Device Identity (v2)** section shows
root-key delegation and challenge-bound device proofs.

---

## Security model

- **Verifier trusts the stored public key.** In v1 this is the user's stored Ristretto255 public key; in v2 it is the stored Ed25519 root public key. Never trust keys carried only inside envelopes.
- **v1 and v2 trust models differ.** v1 shares one identity private key across devices via passphrase derivation or one-time transfer. v2 keeps the root private key on Device 1 and delegates distinct per-device Ristretto255 keys.
- **Hidden commitments are not proven until opened.** The `HiddenCommitment` envelope proves the prover's *identity* at commit time but does **not** prove the JSON content until `verifyOpenedCommitment` is called with the opening key.
- **Passphrase-derived keys require the salt.** Store `DerivedKeyResult.salt` alongside the user record; without it the key cannot be re-derived.
- **Never persist the passphrase in `localStorage`.** Ask for it when unlocking the app, then derive or decrypt the identity key in memory.
- **Key-transfer payloads are single-use.** Generate a fresh payload for each transfer; do not reuse passwords across transfers.
- **Use a fresh verifier challenge.** Pass `{ challenge }` to proof creation and verification. If no challenge is supplied, the API supports legacy self-contained proofs that are replayable and must not be used for device authentication.

---

## API reference

### Key operations

```ts
import {
  generateKeyPair,
  deriveKeyFromPassphrase,
  encryptKeyTransfer,
  decryptKeyTransfer,
} from 'zkp-browser';
```

#### `generateKeyPair() → KeyPair`

Generates a fresh random Ristretto255 key pair.

#### `deriveKeyFromPassphrase(passphrase, options?) → DerivedKeyResult`

Deterministically derives a key pair from a passphrase using PBKDF2-SHA-512 + HKDF.

```ts
const { keyPair, salt } = deriveKeyFromPassphrase('correct horse battery staple');
// store salt; re-derive with same passphrase+salt on other devices
```

Options:
- `salt?: string` — base64url 16-byte salt. Auto-generated and returned if omitted.
- `iterations?: number` — PBKDF2 rounds (default: 600 000).

#### `encryptKeyTransfer(privateKey, password) → KeyTransferPayload`

Encrypts a private key for one-time transfer (e.g. scanning as a QR code).

```ts
const payload = encryptKeyTransfer(kp.privateKey, 'one-time-transfer-password');
// payload is plain JSON with base64url fields — safe in a QR code
```

#### `decryptKeyTransfer(payload, password) → Uint8Array`

Recovers the private key from a transfer payload. Throws `InvalidPayloadError` on wrong password or corruption.

---

### JSON proofs

```ts
import {
  proveDisclosedJson,
  verifyDisclosedJson,
  commitHiddenJson,
  verifyOpenedCommitment,
} from 'zkp-browser';
```

JSON objects and JSON files use the same proof functions. Parse a browser
`File` first:

```ts
import { parseJsonFile, proveDisclosedJson } from 'zkp-browser';

const value = await parseJsonFile(file);
const proof = proveDisclosedJson(privateKey, value, { challenge });
```

#### `proveDisclosedJson(privKey, json, options?) → DisclosedJsonProof`

Proves the holder of `privKey` committed to this exact JSON value.  
The JSON is visible; the proof binds identity + content.

```ts
const envelope = proveDisclosedJson(kp.privateKey, { role: 'admin', sub: 'alice' });
```

#### `verifyDisclosedJson(publicKey, json, envelope, options?) → boolean`

Verifies a disclosed JSON proof. Returns `false` on invalid proof; throws on malformed envelope.

> ⚠️ Use your **stored** public key, not `envelope.public_key`.

`parseJsonFile(file)` reads a browser `File`/`Blob` and parses its JSON.
`parseJsonDocument(textOrBytes)` parses a JSON string or UTF-8 byte array.

#### `commitHiddenJson(privKey, json) → CommitResult`

Commits to a JSON value without revealing it.

```ts
const { envelope, openingKey } = commitHiddenJson(kp.privateKey, { amount: 50000 });
// Share envelope publicly — it reveals nothing about the JSON
// Keep openingKey secret until ready to reveal
```

#### `verifyOpenedCommitment(publicKey, envelope, openingKey) → boolean`

Verifies an opened commitment. Returns `true` only when:
1. `SHA-512(canonical(json) ‖ nonce)` equals the stored commitment
2. The Schnorr proof is valid for the given public key and commitment

> ⚠️ Do **not** treat the JSON as proven until this function returns `true`.

---

### Low-level Schnorr

```ts
import { schnorrProve, schnorrVerify, publicKeyFromPrivate } from 'zkp-browser';

const proof = schnorrProve(privKey, messageBytes, 'my-app/v1/my-domain');
const ok = schnorrVerify(pubKey, messageBytes, proof, 'my-app/v1/my-domain');
```

Use a globally-unique domain string to prevent cross-protocol proof forgery.

---

### Utilities

```ts
import { base64url, canonicalJson } from 'zkp-browser';

base64url.encode(bytes);   // Uint8Array → string
base64url.decode(str);     // string → Uint8Array

canonicalJson({ b: 2, a: 1 }); // → '{"a":1,"b":2}'
```

### Error types

All errors extend `ZkpError`. Import and check with `instanceof`:

```ts
import { InvalidKeyError, InvalidProofError, InvalidCommitmentError, InvalidPayloadError, InvalidDelegationError } from 'zkp-browser';
```

---

## Quick start

```ts
import {
  generateKeyPair,
  proveDisclosedJson,
  verifyDisclosedJson,
  commitHiddenJson,
  verifyOpenedCommitment,
} from 'zkp-browser';

// ── Prover side ──────────────────────────────────────────────────────────────
const { privateKey, publicKey } = generateKeyPair();

// Prove identity + disclosed claim
const claim = { sub: 'alice@example.com', role: 'user', iat: Math.floor(Date.now() / 1000) };
const challenge = crypto.getRandomValues(new Uint8Array(32));
const proof = proveDisclosedJson(privateKey, claim, { challenge });

// ── Verifier side (has stored publicKey) ─────────────────────────────────────
console.log(verifyDisclosedJson(publicKey, claim, proof, { challenge })); // true
console.log(verifyDisclosedJson(publicKey, { ...claim, role: 'admin' }, proof, { challenge })); // false

// ── Hidden commitment ─────────────────────────────────────────────────────────
const { envelope, openingKey } = commitHiddenJson(privateKey, { amount: 50_000 });
// envelope: share now — content is hidden
// openingKey: reveal later

// Later, prover reveals openingKey to verifier:
console.log(verifyOpenedCommitment(publicKey, envelope, openingKey)); // true
```

---

## Security notes and caveats

- **This software has not undergone a formal third-party security audit.** Use in production at your own risk.
- **Choose the right mode.** v1 is simpler but shares one private key across devices. v2 reduces key-sharing by using an Ed25519 root plus per-device Ristretto255 keys.
- **Replay protection is challenge-driven.** The verifier must generate a fresh unpredictable challenge, verify against that exact challenge, and mark it consumed. The library binds the challenge into the proof but cannot maintain the verifier's replay cache.
- **Proof envelopes include `public_key` for convenience.** Always verify against your *stored* public key, not the one in the envelope.
- **Passphrase entropy matters.** The PBKDF2 work factor protects against offline brute-force, but a weak passphrase is still weak. Use a passphrase manager or diceware.
- **Key-transfer passwords are single-use.** Reusing a transfer password across multiple transfers allows an observer to link transfers.
- **Dependencies.** This library relies exclusively on the `@noble` family of cryptographic primitives (Paul Miller), which are widely audited, zero-dependency, and pure-JS/TS.
