/** Ristretto255 key pair */
export interface KeyPair {
  /** 32-byte private key seed — keep secret */
  privateKey: Uint8Array;
  /** 32-byte Ristretto255 public key (compressed point) */
  publicKey: Uint8Array;
}

/** Raw Schnorr proof components (binary) */
export interface SchnorrProofBytes {
  /** 32-byte Ristretto255 nonce commitment R = r·G */
  R: Uint8Array;
  /** 32-byte scalar response s = r + c·x mod l */
  s: Uint8Array;
}

/** JSON-serialisable Schnorr proof (all binary fields as base64url) */
export interface SchnorrProofJson {
  R: string;
  s: string;
}

/**
 * Proof envelope for a *disclosed* JSON value.
 * The JSON is visible; the proof binds identity to the exact JSON content.
 */
export interface DisclosedJsonProof {
  version: 1;
  type: 'disclosed';
  /** base64url SHA-512 of the canonical JSON bytes */
  json_hash: string;
  /** Schnorr proof of knowledge of x, with message = json_hash */
  proof: SchnorrProofJson;
  /** base64url Ristretto255 public key */
  public_key: string;
  /** Optional verifier-issued challenge bound into the proof. */
  challenge?: string;
  /** Unix timestamp (ms) when the proof was created */
  created_at: number;
}

/**
 * Commitment envelope for a *hidden* JSON value.
 * The JSON is NOT revealed; only the commitment hash is stored.
 * Do NOT claim the JSON is proven until `verifyOpenedCommitment` succeeds
 * with both the envelope and the opening key.
 */
export interface HiddenCommitment {
  version: 1;
  type: 'hidden';
  /** base64url SHA-512(canonical_json_bytes ‖ nonce) */
  commitment: string;
  /** Schnorr proof of knowledge of x, with message = commitment */
  proof: SchnorrProofJson;
  /** base64url Ristretto255 public key */
  public_key: string;
  /** Optional verifier-issued challenge bound into the proof. */
  challenge?: string;
  /** Unix timestamp (ms) when the commitment was created */
  created_at: number;
}

/**
 * Opening key for a hidden commitment.
 * Keep secret until the prover is ready to reveal the JSON.
 */
export interface CommitmentOpeningKey {
  /** The original JSON value that was committed */
  json: unknown;
  /** base64url 32-byte nonce used to form the commitment */
  nonce: string;
}

/** Return value of `commitHiddenJson` */
export interface CommitResult {
  /** Public envelope — safe to share at any time */
  envelope: HiddenCommitment;
  /** Opening key — keep secret until reveal time */
  openingKey: CommitmentOpeningKey;
}

/** Encrypted one-time key-transfer payload (QR-safe, all binary as base64url) */
export interface KeyTransferPayload {
  version: 1;
  /** base64url 16-byte PBKDF2 salt */
  salt: string;
  /** base64url 12-byte ChaCha20-Poly1305 nonce */
  nonce: string;
  /** base64url ChaCha20-Poly1305 ciphertext ‖ 16-byte auth-tag */
  ciphertext: string;
}

/** Options for `deriveKeyFromPassphrase` */
export interface PassphraseKeyOptions {
  /**
   * base64url-encoded 16-byte salt.
   * Generated and returned when omitted; supply the returned value to re-derive
   * the same key on another device.
   */
  salt?: string;
  /** PBKDF2 iteration count (default: 600 000). Must be ≥ 1. */
  iterations?: number;
}

/** Return value of `deriveKeyFromPassphrase` */
export interface DerivedKeyResult {
  keyPair: KeyPair;
  /** base64url salt — store alongside the user record to allow re-derivation */
  salt: string;
}

/** Verifier context for preventing proof replay. */
export interface JsonProofOptions {
  /**
   * Fresh, unpredictable bytes supplied by the verifier. The verifier should
   * pass the same value to verification and reject reused challenges.
   */
  challenge?: Uint8Array;
}
