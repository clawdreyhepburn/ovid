import { generateKeyPair, exportJWK, importJWK } from 'jose';
import type { KeyPair } from './types.js';

export interface GenerateKeypairOptions {
  /**
   * Whether the private key material can be exported (e.g. via exportJWK).
   *
   * Default **false**. Child agent keys must not be serializable into
   * transcripts, logs, or spawn task text. Only set true when the caller
   * intentionally needs to persist a root/orchestrator key to disk.
   */
  extractable?: boolean;
}

/**
 * Generate an Ed25519 keypair for OVID.
 *
 * Private keys are **non-extractable by default** (C5). Callers that need
 * to persist a root key must pass `{ extractable: true }` explicitly.
 */
export async function generateKeypair(
  options: GenerateKeypairOptions = {},
): Promise<KeyPair> {
  const extractable = options.extractable === true;
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable,
  });
  return { publicKey, privateKey };
}

export async function exportPublicKeyBase64(publicKey: KeyPair['publicKey']): Promise<string> {
  const jwk = await exportJWK(publicKey);
  // x is the raw public key in base64url
  return jwk.x!;
}

export async function importPublicKeyBase64(base64: string): Promise<CryptoKey> {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: base64 };
  return importJWK(jwk, 'EdDSA') as Promise<CryptoKey>;
}
