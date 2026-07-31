# zkp-browser

A TypeScript library for **identity and device trust** using **Schnorr zero-knowledge proofs** over **Ristretto255**.  
Works in Node.js (16+) and modern browsers. Ships as both CommonJS (`dist/index.js`) and ES module (`dist/index.mjs`).

---

## Contents

- [Cryptography overview](#cryptography-overview)
- [Offline device-to-device sync](#offline-device-to-device-sync)
- [Security model](#security-model)
- [API reference](#api-reference)
- [Quick start](#quick-start)
- [Security notes and caveats](#security-notes-and-caveats)

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

## Security model

- **Verifier trusts the stored public key.** The verifier must obtain the user's public key through a trusted channel (registration, PKI, etc.) and use that stored copy — not the `public_key` field inside a proof envelope, which is informational only.
- **Devices share the same identity private key (v1).** Multi-device synchronisation via the key-transfer mechanism or passphrase derivation.
- **Hidden commitments are not proven until opened.** The `HiddenCommitment` envelope proves the prover's *identity* at commit time but does **not** prove the JSON content until `verifyOpenedCommitment` is called with the opening key.
- **Passphrase-derived keys require the salt.** Store `DerivedKeyResult.salt` alongside the user record; without it the key cannot be re-derived.
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
import { InvalidKeyError, InvalidProofError, InvalidCommitmentError, InvalidPayloadError } from 'zkp-browser';
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

- **This is v1 software.** It has not undergone a formal third-party security audit. Use in production at your own risk.
- **Single private key per identity (v1).** All devices for a user share the same private key. Future versions may support per-device keys with linkable proofs.
- **Replay protection is challenge-driven.** The verifier must generate a fresh unpredictable challenge, verify against that exact challenge, and mark it consumed. The library binds the challenge into the proof but cannot maintain the verifier's replay cache.
- **Proof envelopes include `public_key` for convenience.** Always verify against your *stored* public key, not the one in the envelope.
- **Passphrase entropy matters.** The PBKDF2 work factor protects against offline brute-force, but a weak passphrase is still weak. Use a passphrase manager or diceware.
- **Key-transfer passwords are single-use.** Reusing a transfer password across multiple transfers allows an observer to link transfers.
- **Dependencies.** This library relies exclusively on the `@noble` family of cryptographic primitives (Paul Miller), which are widely audited, zero-dependency, and pure-JS/TS.
