import { describe, it, expect } from 'vitest';
import { createOvid, generateKeypair, verifyOvid } from '../src/index.js';

describe('verifyOvid', () => {
  it('verifies a valid OVID', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      role: 'worker',
      issuer: 'root',
    });
    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.principal).toBe(ovid.claims.sub);
    expect(result.role).toBe('worker');
    expect(result.expiresIn).toBeGreaterThan(0);
  });

  it('rejects tampered JWT', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      role: 'worker',
      issuer: 'root',
    });
    const tampered = ovid.jwt.slice(0, -5) + 'XXXXX';
    const result = await verifyOvid(tampered, keys.publicKey);
    expect(result.valid).toBe(false);
  });

  it('rejects JWT signed with wrong key', async () => {
    const keys = await generateKeypair();
    const otherKeys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      role: 'worker',
      issuer: 'root',
    });
    const result = await verifyOvid(ovid.jwt, otherKeys.publicKey);
    expect(result.valid).toBe(false);
  });

  it('rejects expired OVID', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      role: 'worker',
      issuer: 'root',
      ttlSeconds: -1,
    });
    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(false);
  });
});
