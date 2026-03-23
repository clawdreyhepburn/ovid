import { generateKeyPair, exportJWK } from 'jose';
export async function generateKeypair() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    return { publicKey, privateKey };
}
export async function exportPublicKeyBase64(publicKey) {
    const jwk = await exportJWK(publicKey);
    // x is the raw public key in base64url
    return jwk.x;
}
