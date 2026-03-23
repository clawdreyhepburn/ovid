import { describe, it, expect } from 'vitest';
import { generateKeypair, exportPublicKeyBase64 } from '../src/index.js';

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
});
