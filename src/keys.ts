import { generateKeyPair, exportJWK, importJWK } from 'jose';
import type { KeyPair } from './types.js';

export async function generateKeypair(): Promise<KeyPair> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
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
