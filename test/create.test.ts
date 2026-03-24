import { describe, it, expect } from 'vitest';
import { createOvid, renewOvid, generateKeypair, verifyOvid, validateCedarSyntax } from '../src/index.js';
import type { AuthorizationDetail } from '../src/types.js';

const testDetail: AuthorizationDetail = {
  type: 'agent_mandate',
  rarFormat: 'cedar',
  policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
};

const wideDetail: AuthorizationDetail = {
  type: 'agent_mandate',
  rarFormat: 'cedar',
  policySet: 'permit(principal, action, resource);',
};

describe('createOvid', () => {
  it('issues a valid OVID JWT with authorization_details', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      authorizationDetails: testDetail,
      issuer: 'root',
    });
    expect(ovid.jwt).toContain('.');
    expect(ovid.claims.authorization_details).toHaveLength(1);
    expect(ovid.claims.authorization_details[0].policySet).toBe(testDetail.policySet);
    expect(ovid.claims.authorization_details[0].ovid_version).toBe('0.3.0');
    expect(ovid.claims.authorization_details[0].parent_chain).toEqual([]);

    const result = await verifyOvid(ovid.jwt, keys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.mandate.policySet).toBe(testDetail.policySet);
  });

  it('accepts legacy mandate field', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      mandate: testDetail,
      issuer: 'root',
    });
    expect(ovid.claims.authorization_details).toHaveLength(1);
    expect(ovid.claims.authorization_details[0].policySet).toBe(testDetail.policySet);
  });

  it('rejects missing or invalid mandate', async () => {
    const keys = await generateKeypair();
    await expect(createOvid({
      issuerKeys: keys,
      authorizationDetails: { type: 'agent_mandate', rarFormat: 'cedar', policySet: '' },
      issuer: 'root',
    })).rejects.toThrow('mandate is required');

    await expect(createOvid({
      issuerKeys: keys,
      authorizationDetails: { type: 'agent_mandate', rarFormat: 'not-cedar' as any, policySet: 'permit;' },
      issuer: 'root',
    })).rejects.toThrow('mandate is required');

    await expect(createOvid({
      issuerKeys: keys,
      authorizationDetails: { rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' } as any,
      issuer: 'root',
    })).rejects.toThrow('mandate is required');
  });

  it('rejects child lifetime exceeding parent', async () => {
    const parentKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: parentKeys,
      authorizationDetails: wideDetail,
      issuer: 'root',
      ttlSeconds: 60,
    });

    await expect(createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      authorizationDetails: testDetail,
      ttlSeconds: 3600,
    })).rejects.toThrow('Lifetime attenuation violation');
  });

  it('builds parent chain correctly', async () => {
    const rootKeys = await generateKeypair();
    const parent = await createOvid({
      issuerKeys: rootKeys,
      authorizationDetails: wideDetail,
      issuer: 'clawdrey',
      ttlSeconds: 3600,
    });

    const child = await createOvid({
      issuerKeys: parent.keys,
      issuerOvid: parent,
      authorizationDetails: testDetail,
      ttlSeconds: 1800,
    });

    expect(child.claims.authorization_details[0].parent_chain!.length).toBe(1);
    expect(child.claims.parent_ovid).toBe(parent.claims.jti);
    expect(child.claims.authorization_details[0].policySet).toBe(testDetail.policySet);
  });

  it('rejects chain depth exceeding max', async () => {
    const rootKeys = await generateKeypair();
    let current = await createOvid({
      issuerKeys: rootKeys,
      authorizationDetails: wideDetail,
      issuer: 'clawdrey',
      ttlSeconds: 3600,
    });

    current = await createOvid({
      issuerKeys: current.keys,
      issuerOvid: current,
      authorizationDetails: testDetail,
      ttlSeconds: 1800,
    });

    for (let i = 0; i < 3; i++) {
      current = await createOvid({
        issuerKeys: current.keys,
        issuerOvid: current,
        authorizationDetails: testDetail,
        ttlSeconds: 900,
      });
    }

    await expect(createOvid({
      issuerKeys: current.keys,
      issuerOvid: current,
      authorizationDetails: testDetail,
      ttlSeconds: 600,
    })).rejects.toThrow('Chain depth');
  });

  it('rejects policy with no permit or forbid', async () => {
    const keys = await generateKeypair();
    await expect(createOvid({
      issuerKeys: keys,
      authorizationDetails: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'not cedar at all' },
      issuer: 'root',
    })).rejects.toThrow('Invalid Cedar policy syntax');
  });

  it('rejects policy missing semicolons', async () => {
    const keys = await generateKeypair();
    await expect(createOvid({
      issuerKeys: keys,
      authorizationDetails: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource)' },
      issuer: 'root',
    })).rejects.toThrow('Invalid Cedar policy syntax');
  });

  it('rejects policy with unmatched parens', async () => {
    const keys = await generateKeypair();
    await expect(createOvid({
      issuerKeys: keys,
      authorizationDetails: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource;' },
      issuer: 'root',
    })).rejects.toThrow('Invalid Cedar policy syntax');
  });

  it('accepts multiple valid policies', async () => {
    const keys = await generateKeypair();
    const multiPolicy = `
      permit(principal, action == Ovid::Action::"read_file", resource);
      forbid(principal, action == Ovid::Action::"exec", resource);
    `;
    const ovid = await createOvid({
      issuerKeys: keys,
      authorizationDetails: { type: 'agent_mandate', rarFormat: 'cedar', policySet: multiPolicy },
      issuer: 'root',
    });
    expect(ovid.jwt).toContain('.');
  });

  it('accepts array of authorization details', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      authorizationDetails: [testDetail, wideDetail],
      issuer: 'root',
    });
    expect(ovid.claims.authorization_details).toHaveLength(2);
    expect(ovid.claims.authorization_details[0].ovid_version).toBe('0.3.0');
    expect(ovid.claims.authorization_details[1].policySet).toBe(wideDetail.policySet);
  });
});

describe('renewOvid', () => {
  it('renews a token with same mandate and sub but new exp', async () => {
    const keys = await generateKeypair();
    const original = await createOvid({
      issuerKeys: keys,
      authorizationDetails: testDetail,
      issuer: 'root',
      ttlSeconds: 60,
    });

    await new Promise(r => setTimeout(r, 50));

    const renewed = await renewOvid(original, keys, 120);

    expect(renewed.claims.sub).toBe(original.claims.sub);
    expect(renewed.claims.iss).toBe(original.claims.iss);
    expect(renewed.claims.authorization_details[0].policySet).toBe(
      original.claims.authorization_details[0].policySet,
    );
    expect(renewed.claims.exp).toBeGreaterThanOrEqual(original.claims.exp);

    const result = await verifyOvid(renewed.jwt, keys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.mandate.policySet).toBe(testDetail.policySet);
  });
});

describe('validateCedarSyntax', () => {
  it('valid policy passes', () => {
    const result = validateCedarSyntax('permit(principal, action, resource);');
    expect(result.valid).toBe(true);
  });

  it('empty string rejected', () => {
    const result = validateCedarSyntax('');
    expect(result.valid).toBe(false);
  });

  it('"not cedar at all" rejected', () => {
    const result = validateCedarSyntax('not cedar at all');
    expect(result.valid).toBe(false);
  });

  it('missing semicolons rejected', () => {
    const result = validateCedarSyntax('permit(principal, action, resource)');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('semicolon');
  });

  it('unmatched parens rejected', () => {
    const result = validateCedarSyntax('permit(principal, action, resource;');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('parenthesis');
  });

  it('unmatched quotes rejected', () => {
    const result = validateCedarSyntax('permit(principal, action == "read, resource);');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('quote');
  });

  it('multiple valid policies pass', () => {
    const result = validateCedarSyntax(`
      permit(principal, action == Ovid::Action::"read_file", resource);
      forbid(principal, action == Ovid::Action::"exec", resource);
    `);
    expect(result.valid).toBe(true);
  });
});
