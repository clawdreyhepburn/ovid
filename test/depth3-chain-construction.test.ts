/**
 * Depth-3 chain-construction invariant (FIX-DESIGN.md §5c).
 *
 * Locks in the Q1 invariant that made the depth-3 fix non-trivial:
 *   - A grandchild's leaf chain link MUST be signed with its IMMEDIATE PARENT's
 *     private key (createOvid `issuerKeys` = parent keys, `issuerOvid` = parent
 *     token). Doing so yields a 3-link chain root→child→grandchild that verifies.
 *   - If the grandchild leaf is signed with ROOT's key instead of the parent's
 *     (the tempting-but-wrong "thread only the claims, keep signing with root"
 *     shortcut), verification MUST fail, because verifyV04 checks link i against
 *     chain[i-1].agent_pub.
 */
import { describe, it, expect } from 'vitest';
import { createOvid, generateKeypair, exportPublicKeyBase64, verifyOvid } from '../src/index.js';

const ROOT = 'clawdrey';

async function mintRoot() {
  const rootKeys = await generateKeypair();
  const root = await createOvid({
    issuerKeys: rootKeys,
    agentId: ROOT,
    issuer: ROOT,
    mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
    ttlSeconds: 3600,
  });
  return { rootKeys, root };
}

async function mintChild(root: any) {
  // depth-2 child: signed with ROOT's keys (root is the parent here)
  return createOvid({
    issuerKeys: root.keys,
    issuerOvid: root,
    agentId: `${ROOT}/depth2-readonly`,
    mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action in [Ovid::Action::"read"], resource);' },
    ttlSeconds: 1800,
  });
}

describe('depth-3 chain construction (parent-signed leaf invariant)', () => {
  it('root→child→grandchild, each leaf parent-signed, verifies with chain.length===3', async () => {
    const { rootKeys, root } = await mintRoot();
    const child = await mintChild(root);
    expect(child.claims.iss).toBe(ROOT);

    // depth-3 grandchild: signed with the CHILD's freshly-generated keys.
    const grandchild = await createOvid({
      issuerKeys: child.keys,         // ← PARENT (child) keys sign the leaf
      issuerOvid: child,
      agentId: `${ROOT}/depth3-reader`,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action in [Ovid::Action::"read"], resource);' },
      ttlSeconds: 300,
    });

    // iss now reflects the real immediate parent, not root.
    expect(grandchild.claims.iss).toBe(`${ROOT}/depth2-readonly`);

    const verified = await verifyOvid(grandchild.jwt, {
      trustedRoots: [rootKeys.publicKey],
      maxChainDepth: 5,
    });
    expect(verified.valid).toBe(true);
    expect(verified.chain).toEqual([
      ROOT,
      `${ROOT}/depth2-readonly`,
      `${ROOT}/depth3-reader`,
    ]);
    expect(verified.chain).toHaveLength(3);
  });

  it('TAMPER: grandchild leaf signed with ROOT keys (not parent) must fail verification', async () => {
    const { rootKeys, root } = await mintRoot();
    const child = await mintChild(root);

    // Wrong-signer grandchild: chain prefix says the child is the parent, but
    // the leaf link is signed with ROOT's key instead of the child's key.
    const tampered = await createOvid({
      issuerKeys: rootKeys,           // ← WRONG signer: root, but issuerOvid is child
      issuerOvid: child,
      agentId: `${ROOT}/depth3-forged`,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action in [Ovid::Action::"read"], resource);' },
      ttlSeconds: 300,
    });

    const verified = await verifyOvid(tampered.jwt, {
      trustedRoots: [rootKeys.publicKey],
      maxChainDepth: 5,
    });
    expect(verified.valid).toBe(false);
  });
});
