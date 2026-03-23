import { describe, it, expect } from 'vitest';
import { createOvid, generateKeypair, verifyOvid } from '../src/index.js';
import type { CedarMandate } from '../src/config.js';

const testMandate: CedarMandate = {
  rarFormat: 'cedar',
  policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
};

describe('verifyOvid', () => {
  it('verifies a valid OVID with mandate', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      mandate: testMandate,
      issuer: 'root',
    });
    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.principal).toBe(ovid.claims.sub);
    expect(result.mandate).toEqual(testMandate);
    expect(result.expiresIn).toBeGreaterThan(0);
  });

  it('rejects tampered JWT', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      mandate: testMandate,
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
      mandate: testMandate,
      issuer: 'root',
    });
    const result = await verifyOvid(ovid.jwt, otherKeys.publicKey);
    expect(result.valid).toBe(false);
  });

  it('rejects expired OVID', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      mandate: testMandate,
      issuer: 'root',
      ttlSeconds: -1,
    });
    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(false);
  });
});
