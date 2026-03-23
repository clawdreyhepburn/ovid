import { describe, it, expect } from 'vitest';
import { createOvid, generateKeypair, verifyOvid } from '../src/index.js';

describe('createOvid', () => {
  it('issues a valid OVID JWT', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      role: 'coder',
      issuer: 'root',
    });
    expect(ovid.jwt).toContain('.');
    expect(ovid.claims.role).toBe('coder');
    expect(ovid.claims.ovid_version).toBe(1);
    expect(ovid.claims.parent_chain).toEqual([]);

    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.role).toBe('coder');
  });

  it('rejects child lifetime exceeding parent', async () => {
    const parentKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: parentKeys,
      role: 'orchestrator',
      issuer: 'root',
      ttlSeconds: 60,
    });

    await expect(createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      role: 'worker',
      ttlSeconds: 3600,
    })).rejects.toThrow('Lifetime attenuation violation');
  });

  it('builds parent chain correctly', async () => {
    const rootKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: rootKeys,
      role: 'orchestrator',
      issuer: 'clawdrey',
      ttlSeconds: 3600,
    });

    const child = await createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      role: 'reviewer',
      ttlSeconds: 1800,
    });

    expect(child.claims.parent_chain.length).toBe(1);
    expect(child.claims.parent_ovid).toBe(parent.claims.jti);
  });

  it('rejects chain depth exceeding max', async () => {
    const rootKeys = await generateKeypair();
    let current = await createOvid({
      issuerKeys: rootKeys,
      role: 'root',
      issuer: 'clawdrey',
      ttlSeconds: 3600,
      maxChainDepth: 2,
    });

    current = await createOvid({
      issuerKeys: current.keys,
      issuerOvid: current,
      role: 'child',
      ttlSeconds: 1800,
      maxChainDepth: 2,
    });

    await expect(createOvid({
      issuerKeys: current.keys,
      issuerOvid: current,
      role: 'grandchild',
      ttlSeconds: 900,
      maxChainDepth: 2,
    })).rejects.toThrow('Chain depth');
  });
});
