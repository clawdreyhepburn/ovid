import { describe, it, expect } from 'vitest';
import { SignJWT, jwtVerify } from 'jose';
import { generateKeypair, exportPublicKeyBase64, importPublicKeyBase64 } from '../src/index.js';

describe('generateKeypair', () => {
  it('produces a keypair with public and private keys', async () => {
    const kp = await generateKeypair();
    expect(kp.publicKey).toBeDefined();
    expect(kp.privateKey).toBeDefined();
  });

  it('produces unique keypairs', async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    const pub1 = await exportPublicKeyBase64(kp1.publicKey);
    const pub2 = await exportPublicKeyBase64(kp2.publicKey);
    expect(pub1).not.toBe(pub2);
  });

  it('exports a base64url public key string', async () => {
    const kp = await generateKeypair();
    const pub = await exportPublicKeyBase64(kp.publicKey);
    expect(typeof pub).toBe('string');
    expect(pub.length).toBeGreaterThan(0);
  });

  it('round-trip: generate → export → import → verify signature', async () => {
    const kp = await generateKeypair();
    const pubBase64 = await exportPublicKeyBase64(kp.publicKey);
    const importedKey = await importPublicKeyBase64(pubBase64);

    // Sign with original private key
    const jwt = await new SignJWT({ test: true })
      .setProtectedHeader({ alg: 'EdDSA' })
      .sign(kp.privateKey);

    // Verify with imported public key
    const { payload } = await jwtVerify(jwt, importedKey);
    expect(payload.test).toBe(true);
  });
});
