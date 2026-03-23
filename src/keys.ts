import { generateKeyPair, exportJWK } from 'jose';
import type { KeyPair } from './types.js';

export async function generateKeypair(): Promise<KeyPair> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  return { publicKey, privateKey };
}

export async function exportPublicKeyBase64(publicKey: KeyPair['publicKey']): Promise<string> {
  const jwk = await exportJWK(publicKey);
  // x is the raw public key in base64url
  return jwk.x!;
}
