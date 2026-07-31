import { InvalidProofError } from './errors';

/**
 * Parse a UTF-8 JSON document before passing the resulting value to a proof
 * function. In browsers, `File` is a `Blob`; the same API also accepts any
 * Blob-like object exposed by a compatible runtime.
 */
export async function parseJsonFile(file: Blob): Promise<unknown> {
  if (!file || typeof file.text !== 'function') {
    throw new InvalidProofError('Expected a readable Blob or File');
  }

  const text = await file.text();
  try {
    return JSON.parse(text) as unknown;
  } catch (cause) {
    throw new InvalidProofError('File does not contain valid JSON', { cause });
  }
}

/** Parse a JSON document supplied as text or UTF-8 bytes. */
export function parseJsonDocument(document: string | Uint8Array): unknown {
  const text =
    typeof document === 'string'
      ? document
      : new TextDecoder().decode(document);
  try {
    return JSON.parse(text) as unknown;
  } catch (cause) {
    throw new InvalidProofError('Document does not contain valid JSON', { cause });
  }
}
