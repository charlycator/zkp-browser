// Public API — re-export everything users need

export type {
  KeyPair,
  SchnorrProofBytes,
  SchnorrProofJson,
  DisclosedJsonProof,
  HiddenCommitment,
  CommitmentOpeningKey,
  CommitResult,
  KeyTransferPayload,
  PassphraseKeyOptions,
  DerivedKeyResult,
  JsonProofOptions,
  RootKeyPair,
  DelegationPayload,
  DeviceDelegation,
  DeviceDelegationOptions,
  DeviceProof,
} from './types';

export {
  ZkpError,
  InvalidKeyError,
  InvalidProofError,
  InvalidCommitmentError,
  InvalidPayloadError,
  InvalidDelegationError,
} from './errors';

export {
  generateKeyPair,
  deriveKeyFromPassphrase,
  encryptKeyTransfer,
  decryptKeyTransfer,
} from './keys';

export { publicKeyFromPrivate, schnorrProve, schnorrVerify } from './schnorr';

export {
  proveDisclosedJson,
  verifyDisclosedJson,
  commitHiddenJson,
  verifyOpenedCommitment,
} from './json-proof';

export { base64url, canonicalJson } from './utils';

export { parseJsonFile, parseJsonDocument } from './json-input';

export {
  generateRootKeyPair,
  generateDeviceKeyPair,
  createDeviceDelegation,
  verifyDeviceDelegation,
  createDeviceProof,
  verifyDeviceProof,
  isDelegationRevoked,
} from './delegation';
