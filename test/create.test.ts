import { describe, it, expect } from 'vitest';
import { createOvid, generateKeypair, verifyOvid } from '../src/index.js';
import type { CedarMandate } from '../src/types.js';

const testMandate: CedarMandate = {
  rarFormat: 'cedar',
  policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
};

const wideMandate: CedarMandate = {
  rarFormat: 'cedar',
  policySet: 'permit(principal, action, resource);',
};

describe('createOvid', () => {
  it('issues a valid OVID JWT with mandate', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      mandate: testMandate,
      issuer: 'root',
    });
    expect(ovid.jwt).toContain('.');
    expect(ovid.claims.mandate).toEqual(testMandate);
    expect(ovid.claims.ovid_version).toBe('0.2.0');
    expect(ovid.claims.parent_chain).toEqual([]);

    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.mandate).toEqual(testMandate);
  });

  it('rejects missing or invalid mandate', async () => {
    const keys = await generateKeypair();
    await expect(createOvid({
      issuerKeys: keys,
      mandate: { rarFormat: 'cedar', policySet: '' },
      issuer: 'root',
    })).rejects.toThrow('mandate is required');

    await expect(createOvid({
      issuerKeys: keys,
      mandate: { rarFormat: 'not-cedar' as any, policySet: 'permit;' },
      issuer: 'root',
    })).rejects.toThrow('mandate is required');
  });

  it('rejects child lifetime exceeding parent', async () => {
    const parentKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: parentKeys,
      mandate: wideMandate,
      issuer: 'root',
      ttlSeconds: 60,
    });

    await expect(createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      mandate: testMandate,
      ttlSeconds: 3600,
    })).rejects.toThrow('Lifetime attenuation violation');
  });

  it('builds parent chain correctly', async () => {
    const rootKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: rootKeys,
      mandate: wideMandate,
      issuer: 'clawdrey',
      ttlSeconds: 3600,
    });

    const child = await createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      mandate: testMandate,
      ttlSeconds: 1800,
    });

    expect(child.claims.parent_chain.length).toBe(1);
    expect(child.claims.parent_ovid).toBe(parent.claims.jti);
    expect(child.claims.mandate).toEqual(testMandate);
  });

  it('rejects chain depth exceeding max', async () => {
    const rootKeys = await generateKeypair();
    let current = await createOvid({
      issuerKeys: rootKeys,
      mandate: wideMandate,
      issuer: 'clawdrey',
      ttlSeconds: 3600,
    });

    current = await createOvid({
      issuerKeys: current.keys,
      issuerOvid: current,
      mandate: testMandate,
      ttlSeconds: 1800,
    });

    // Default max depth is 5, so build up to it
    for (let i = 0; i < 3; i++) {
      current = await createOvid({
        issuerKeys: current.keys,
        issuerOvid: current,
        mandate: testMandate,
        ttlSeconds: 900,
      });
    }

    // This should be depth 6, exceeding max 5
    await expect(createOvid({
      issuerKeys: current.keys,
      issuerOvid: current,
      mandate: testMandate,
      ttlSeconds: 600,
    })).rejects.toThrow('Chain depth');
  });
});
