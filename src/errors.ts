/**
 * Explicit error hierarchy for zkp-browser.
 * Callers can distinguish error kinds without inspecting message strings.
 */

/** Options mirroring ES2022's ErrorOptions without requiring lib.es2022.error. */
interface ZkpErrorInit {
  cause?: unknown;
}

export class ZkpError extends Error {
  /** The underlying cause of this error, if any. */
  cause?: unknown;

  constructor(message: string, options?: ZkpErrorInit) {
    super(message);
    this.name = 'ZkpError';
    this.cause = options?.cause;
  }
}

/** Private key is missing, malformed, or derived an invalid scalar. */
export class InvalidKeyError extends ZkpError {
  constructor(message: string, options?: ZkpErrorInit) {
    super(message, options);
    this.name = 'InvalidKeyError';
  }
}

/** Proof structure is malformed or the verification equation does not hold. */
export class InvalidProofError extends ZkpError {
  constructor(message: string, options?: ZkpErrorInit) {
    super(message, options);
    this.name = 'InvalidProofError';
  }
}

/** Commitment envelope is malformed or the opening does not match the stored commitment. */
export class InvalidCommitmentError extends ZkpError {
  constructor(message: string, options?: ZkpErrorInit) {
    super(message, options);
    this.name = 'InvalidCommitmentError';
  }
}

/** Key-transfer payload is malformed, version-unsupported, or decryption failed. */
export class InvalidPayloadError extends ZkpError {
  constructor(message: string, options?: ZkpErrorInit) {
    super(message, options);
    this.name = 'InvalidPayloadError';
  }
}
