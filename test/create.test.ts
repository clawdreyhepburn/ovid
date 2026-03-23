import { describe, it, expect } from 'vitest';
import { createOvid, generateKeypair, verifyOvid } from '../src/index.js';

describe('createOvid', () => {
  it('issues a valid OVID JWT', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      role: 'coder',
      scope: { tools: { allow: ['read_file', 'write'] } },
      issuer: 'root',
    });
    expect(ovid.jwt).toContain('.');
    expect(ovid.claims.role).toBe('coder');
    expect(ovid.claims.ovid_version).toBe(1);
    expect(ovid.claims.parent_chain).toEqual([]);

    // Verify it
    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.role).toBe('coder');
  });

  it('rejects child scope wider than parent', async () => {
    const parentKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: parentKeys,
      role: 'orchestrator',
      scope: { tools: { allow: ['read_file'] } },
      issuer: 'root',
      ttlSeconds: 3600,
    });

    await expect(createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      role: 'worker',
      scope: { tools: { allow: ['read_file', 'exec'] } },
    })).rejects.toThrow('Scope attenuation violation');
  });

  it('rejects child lifetime exceeding parent', async () => {
    const parentKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: parentKeys,
      role: 'orchestrator',
      scope: {},
      issuer: 'root',
      ttlSeconds: 60,
    });

    await expect(createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      role: 'worker',
      scope: {},
      ttlSeconds: 3600,
    })).rejects.toThrow('Lifetime attenuation violation');
  });

  it('builds parent chain correctly', async () => {
    const rootKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: rootKeys,
      role: 'orchestrator',
      scope: { tools: { allow: ['read_file', 'write'] } },
      issuer: 'clawdrey',
      ttlSeconds: 3600,
    });

    const child = await createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      role: 'reviewer',
      scope: { tools: { allow: ['read_file'] } },
      ttlSeconds: 1800,
    });

    expect(child.claims.parent_chain).toEqual(['clawdrey']);
    expect(child.claims.parent_ovid).toBe(parent.claims.jti);
  });
});
