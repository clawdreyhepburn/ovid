/**
 * Test that the parent-child delegation flow produces tokens matching
 * the blog post "What OVID Kept From SPIFFE".
 */
import { describe, it, expect } from 'vitest';
import { createOvid, generateKeypair, exportPublicKeyBase64, verifyOvid } from '../src/index.js';
import type { AuthorizationDetail, ChainLink } from '../src/types.js';

const ROOT_ISSUER = 'clawdrey';

describe('parent-child delegation (blog-faithful)', () => {
  it('root token has single-link self-signed chain with iss=clawdrey', async () => {
    const orchestratorKeys = await generateKeypair();
    const orchestratorPub = await exportPublicKeyBase64(orchestratorKeys.publicKey);

    const root = await createOvid({
      issuerKeys: orchestratorKeys,
      agentId: ROOT_ISSUER,
      issuer: ROOT_ISSUER,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
      ttlSeconds: 3600,
    });

    expect(root.claims.iss).toBe(ROOT_ISSUER);
    expect(root.claims.sub).toBe(ROOT_ISSUER);

    const detail = root.claims.authorization_details[0];
    const chain: ChainLink[] = detail.parent_chain;
    expect(chain).toHaveLength(1);
    expect(chain[0].sub).toBe(ROOT_ISSUER);
    expect(chain[0].agent_pub).toBe(orchestratorPub);
    expect(detail.agent_pub).toBe(orchestratorPub);
  });

  it('child token has 2-link chain: root→child, parent-signed', async () => {
    const orchestratorKeys = await generateKeypair();
    const orchestratorPub = await exportPublicKeyBase64(orchestratorKeys.publicKey);

    // Mint root
    const root = await createOvid({
      issuerKeys: orchestratorKeys,
      agentId: ROOT_ISSUER,
      issuer: ROOT_ISSUER,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
      ttlSeconds: 3600,
    });

    // Mint child delegated from root
    const child = await createOvid({
      issuerKeys: orchestratorKeys,
      issuerOvid: root,
      issuer: ROOT_ISSUER,
      agentId: `${ROOT_ISSUER}/inbox-summarizer-9d2b`,
      mandate: {
        type: 'agent_mandate',
        rarFormat: 'cedar',
        policySet: 'permit(principal, action == Ovid::Action::"read_email", resource);',
      },
      ttlSeconds: 300,
    });

    expect(child.claims.iss).toBe(ROOT_ISSUER);
    expect(child.claims.sub).toBe(`${ROOT_ISSUER}/inbox-summarizer-9d2b`);

    const detail = child.claims.authorization_details[0];
    const chain: ChainLink[] = detail.parent_chain;

    // Chain: [root, child] = 2 links
    expect(chain).toHaveLength(2);

    // Link 0: root (same as root token's chain[0])
    expect(chain[0].sub).toBe(ROOT_ISSUER);
    expect(chain[0].agent_pub).toBe(orchestratorPub);

    // Link 1: child (fresh key, different from root)
    expect(chain[1].sub).toBe(`${ROOT_ISSUER}/inbox-summarizer-9d2b`);
    expect(chain[1].agent_pub).not.toBe(orchestratorPub);

    // The leaf agent_pub matches the child link
    expect(detail.agent_pub).toBe(chain[1].agent_pub);
  });

  it('child exp is clamped inside root exp', async () => {
    const keys = await generateKeypair();

    const root = await createOvid({
      issuerKeys: keys,
      agentId: ROOT_ISSUER,
      issuer: ROOT_ISSUER,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
      ttlSeconds: 3600,
    });

    const child = await createOvid({
      issuerKeys: keys,
      issuerOvid: root,
      issuer: ROOT_ISSUER,
      agentId: `${ROOT_ISSUER}/worker-abc`,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
      ttlSeconds: 300,
    });

    expect(child.claims.exp).toBeLessThanOrEqual(root.claims.exp);
    expect(child.claims.iat).toBeGreaterThanOrEqual(root.claims.iat);
  });

  it('child that exceeds parent exp is rejected', async () => {
    const keys = await generateKeypair();

    const root = await createOvid({
      issuerKeys: keys,
      agentId: ROOT_ISSUER,
      issuer: ROOT_ISSUER,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
      ttlSeconds: 60, // very short root
    });

    await expect(
      createOvid({
        issuerKeys: keys,
        issuerOvid: root,
        issuer: ROOT_ISSUER,
        agentId: `${ROOT_ISSUER}/greedy-child`,
        mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
        ttlSeconds: 3600, // tries to outlive parent
      }),
    ).rejects.toThrow(/attenuation/i);
  });

  it('child token verifies against orchestrator trustedRoots', async () => {
    const keys = await generateKeypair();

    const root = await createOvid({
      issuerKeys: keys,
      agentId: ROOT_ISSUER,
      issuer: ROOT_ISSUER,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
      ttlSeconds: 3600,
    });

    const child = await createOvid({
      issuerKeys: keys,
      issuerOvid: root,
      issuer: ROOT_ISSUER,
      agentId: `${ROOT_ISSUER}/verifiable-child`,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
      ttlSeconds: 300,
    });

    // Verify the child JWT using the orchestrator's public key as trust root
    const result = await verifyOvid(child.jwt, {
      trustedRoots: [keys.publicKey],
      maxChainDepth: 5,
    });

    expect(result.valid).toBe(true);
    expect(result.principal).toBe(`${ROOT_ISSUER}/verifiable-child`);
  });
});
