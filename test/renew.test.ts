import { describe, it, expect } from 'vitest';
import { createOvid, renewOvid, generateKeypair, verifyOvid } from '../src/index.js';
import type { AuthorizationDetail } from '../src/types.js';

const detail: AuthorizationDetail = {
  type: 'agent_mandate',
  rarFormat: 'cedar',
  policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
};

const wideDetail: AuthorizationDetail = {
  type: 'agent_mandate',
  rarFormat: 'cedar',
  policySet: 'permit(principal, action, resource);',
};

describe('renewOvid strictness (v0.4.0)', () => {
  it('renews a root token when issuerKeys matches the root link', async () => {
    const rootKeys = await generateKeypair();
    const original = await createOvid({
      issuerKeys: rootKeys,
      authorizationDetails: detail,
      issuer: 'root',
      ttlSeconds: 60,
    });

    // Wait a moment so the renewed token has a later iat/exp.
    await new Promise(r => setTimeout(r, 10));

    const renewed = await renewOvid(original, rootKeys, 7200);
    expect(renewed.claims.sub).toBe(original.claims.sub);
    expect(renewed.claims.exp).toBeGreaterThan(original.claims.exp);

    // The renewed token should verify against the same trusted root.
    const result = await verifyOvid(renewed.jwt, {
      trustedRoots: [rootKeys.publicKey],
    });
    expect(result.valid).toBe(true);
  });

  it('rejects renewal with a different keypair (trust laundering attack)', async () => {
    // Attack: an attacker takes someone else's token and tries to re-root it
    // under their own keys, reusing the sub/issuer labels.
    const rootKeys = await generateKeypair();
    const attackerKeys = await generateKeypair();

    const legitToken = await createOvid({
      issuerKeys: rootKeys,
      authorizationDetails: detail,
      issuer: 'trusted-service',
      ttlSeconds: 60,
    });

    await expect(
      renewOvid(legitToken, attackerKeys, 7200)
    ).rejects.toThrow(/issuerKeys does not match/i);
  });

  it('rejects renewal of a chained (non-root) token', async () => {
    const rootKeys = await generateKeypair();
    const root = await createOvid({
      issuerKeys: rootKeys,
      authorizationDetails: wideDetail,
      issuer: 'root',
      ttlSeconds: 3600,
    });
    const child = await createOvid({
      issuerKeys: root.keys,
      issuerOvid: root,
      authorizationDetails: detail,
      ttlSeconds: 1800,
    });

    // Even with the correct root keys, a child token can't be renewed.
    await expect(
      renewOvid(child, rootKeys, 3600)
    ).rejects.toThrow(/chained.*non-root/i);
  });

  it('rejects renewal of a legacy (pre-0.4.0) token shape', async () => {
    // Simulate a v0.3.x-shaped token: parent_chain is a string[] instead of
    // a ChainLink[]. We construct one by hand since createOvid always emits
    // v0.4.0 now.
    const rootKeys = await generateKeypair();
    const legit = await createOvid({
      issuerKeys: rootKeys,
      authorizationDetails: detail,
      issuer: 'root',
      ttlSeconds: 60,
    });

    // Mutate a copy's parent_chain into the legacy string[] shape.
    const legacyShaped = structuredClone(legit);
    (legacyShaped.claims.authorization_details[0] as any).parent_chain = [];
    (legacyShaped.claims.authorization_details[0] as any).ovid_version = '0.3.0';

    await expect(
      renewOvid(legacyShaped, rootKeys, 3600)
    ).rejects.toThrow(/legacy.*pre-0\.4\.0/i);
  });
});
