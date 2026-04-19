import { SignJWT } from 'jose';
import { generateKeypair, exportPublicKeyBase64 } from './keys.js';
import { validateCedarSyntax } from './validate.js';
import { signChainLink, isChainLinkArray } from './chain.js';
import type {
  CreateOvidOptions,
  OvidToken,
  OvidClaims,
  KeyPair,
  AuthorizationDetail,
  ChainLink,
} from './types.js';

const DEFAULT_TTL = 1800;
const DEFAULT_MAX_CHAIN_DEPTH = 5;
const OVID_VERSION = '0.4.0';

export async function createOvid(options: CreateOvidOptions): Promise<OvidToken> {
  const {
    issuerKeys,
    issuerOvid,
    ttlSeconds = DEFAULT_TTL,
    kid,
    issuer,
  } = options;

  // Accept either authorizationDetails or legacy mandate field
  let details: AuthorizationDetail[];
  if (options.authorizationDetails) {
    details = Array.isArray(options.authorizationDetails)
      ? [...options.authorizationDetails]
      : [options.authorizationDetails];
  } else if (options.mandate) {
    details = [options.mandate];
  } else {
    throw new Error('authorizationDetails (or legacy mandate) is required');
  }

  // Validate each detail
  for (const detail of details) {
    if (!detail || detail.rarFormat !== 'cedar' || !detail.policySet || !detail.type) {
      throw new Error('mandate is required with type, rarFormat "cedar", and a non-empty policySet');
    }
    const syntaxResult = validateCedarSyntax(detail.policySet);
    if (!syntaxResult.valid) {
      throw new Error(`Invalid Cedar policy syntax: ${syntaxResult.error}`);
    }
  }

  const parentClaims = issuerOvid?.claims;
  const maxChainDepth = DEFAULT_MAX_CHAIN_DEPTH;

  // Lifetime attenuation (child exp cannot exceed parent exp)
  const now = Math.floor(Date.now() / 1000);
  const childExp = now + ttlSeconds;
  if (parentClaims && childExp > parentClaims.exp) {
    throw new Error('Lifetime attenuation violation: child expiry exceeds parent expiry');
  }

  // ── Decide identities ──
  //
  // Root (no issuerOvid):
  //   - issuerKeys IS the root's binding keypair. agentKeys === issuerKeys.
  //   - The root's ChainLink is self-signed with issuerKeys.privateKey.
  //   - JWT is signed with agentKeys.privateKey (== issuerKeys.privateKey).
  //   - Returned `keys` = issuerKeys; the root uses the same keypair to
  //     anchor itself in trustedRoots AND to sign children's chain links.
  //
  // Child (with issuerOvid):
  //   - agentKeys: freshly generated for the new agent.
  //   - Chain link for the child is signed by issuerKeys.privateKey
  //     (= the parent's signing key). This is the parent's attestation.
  //   - JWT is signed by agentKeys.privateKey (= the child's own fresh key).
  //     The child authors its own JWT; the parent only attests the chain link.
  //     verify.ts requires the JWT signature to verify against the leaf
  //     link's agent_pub, which is exactly agentKeys.publicKey.
  const isRoot = !parentClaims;
  const agentKeys: KeyPair = isRoot ? issuerKeys : await generateKeypair();
  const agentPub = await exportPublicKeyBase64(agentKeys.publicKey);

  const issuerName = issuer ?? parentClaims?.sub ?? 'root';
  const agentId = options.agentId ?? `${issuerName}/agent-${randomHex(4)}`;

  // ── Build chain ──
  const parentDetail = parentClaims?.authorization_details?.[0];
  const parentChainRaw = parentDetail?.parent_chain;
  let existingChain: ChainLink[];
  if (!parentClaims) {
    existingChain = [];
  } else if (isChainLinkArray(parentChainRaw)) {
    existingChain = parentChainRaw;
  } else {
    // Parent is a v0.3.x legacy token with string[] parent_chain. We can't
    // retrofit signatures onto links we didn't make. Minting a v0.4.0 child
    // under such a parent would produce a chain with no verifiable root,
    // so we refuse rather than emit something that claims to be verifiable
    // but isn't.
    throw new Error(
      'Cannot mint v0.4.0 child under legacy (pre-0.4.0) parent: ' +
      'parent_chain lacks cryptographic attestations. ' +
      'Re-mint the parent with v0.4.0 first.'
    );
  }

  if (existingChain.length + 1 > maxChainDepth) {
    throw new Error(`Chain depth ${existingChain.length + 1} exceeds max ${maxChainDepth}`);
  }

  // The new link for THIS agent, signed by the parent (or self-signed for root).
  const thisLink: ChainLink = {
    sub: agentId,
    agent_pub: agentPub,
    iat: now,
    exp: childExp,
    sig: await signChainLink(
      { sub: agentId, agent_pub: agentPub, iat: now, exp: childExp },
      issuerKeys.privateKey,
    ),
  };

  const parent_chain: ChainLink[] = [...existingChain, thisLink];

  // Set OVID extensions on the first detail
  details[0] = {
    ...details[0],
    parent_chain,
    agent_pub: agentPub,
    ovid_version: OVID_VERSION,
  };

  const claims: OvidClaims = {
    jti: agentId,
    iss: issuerName,
    sub: agentId,
    iat: now,
    exp: childExp,
    authorization_details: details,
    ...(parentClaims ? { parent_ovid: parentClaims.jti } : {}),
  };

  const header = { alg: 'EdDSA' as const, typ: 'ovid+jwt' };
  const finalHeader = kid ? { ...header, kid } : header;

  // Sign the JWT with the AGENT's own private key (the same key bound in the
  // leaf ChainLink). The parent's attestation lives in the chain link; the
  // JWT signature proves the leaf agent authored this specific token payload.
  // For roots, agentKeys === issuerKeys, so this matches pre-0.4.0 behavior.
  // For children, this is a change: children now sign their own JWTs (in
  // v0.3.x the parent signed the child's JWT, which meant the child couldn't
  // prove sole authorship of its own token payload).
  const jwt = await new SignJWT({ ...claims })
    .setProtectedHeader(finalHeader)
    .setIssuedAt(claims.iat)
    .setExpirationTime(claims.exp)
    .setJti(claims.jti)
    .setIssuer(claims.iss)
    .setSubject(claims.sub)
    .sign(agentKeys.privateKey);

  return { jwt, claims, keys: agentKeys };
}

/**
 * Renew an OVID token's expiry without changing its mandate or identity.
 *
 * Renewal semantics in v0.4.0:
 *   - ONLY roots can be renewed. The caller must pass the SAME issuerKeys
 *     that anchor the root link in its trustedRoots. We verify this by
 *     checking issuerKeys.publicKey matches chain[0].agent_pub.
 *   - Chained (non-root) tokens CANNOT be renewed in place, because only
 *     the parent holds the private key needed to attest a new chain link
 *     for the child. Ask the parent to mint a new child token instead.
 *   - Legacy (pre-0.4.0) tokens with string[] parent_chain are rejected:
 *     we can't prove they were originally rooted under issuerKeys without
 *     a ChainLink. Re-mint them fresh with createOvid({ issuerKeys, ... })
 *     instead of renewing.
 *
 * This strictness prevents trust laundering — without the root-key match
 * check, a caller could pass any OVID token plus their own keys and get
 * back a freshly-rooted token that reuses the original sub/issuer labels.
 */
export async function renewOvid(
  existingToken: OvidToken,
  issuerKeys: KeyPair,
  ttlSeconds?: number,
): Promise<OvidToken> {
  const detail = existingToken.claims.authorization_details?.[0];
  const chain = detail?.parent_chain;

  if (!isChainLinkArray(chain)) {
    throw new Error(
      'Cannot renew a legacy (pre-0.4.0) OVID token: parent_chain lacks ' +
      'cryptographic attestations required to prove root identity. ' +
      'Mint a fresh token with createOvid() instead.'
    );
  }

  if (chain.length > 1) {
    throw new Error(
      'Cannot renew a chained (non-root) OVID token: only the parent can reissue. ' +
      'Ask the parent to mint a new child token instead.'
    );
  }

  // Verify issuerKeys actually IS the root's keypair. Without this check, any
  // caller could re-root someone else's token under their own key.
  const issuerPub = await exportPublicKeyBase64(issuerKeys.publicKey);
  if (issuerPub !== chain[0].agent_pub) {
    throw new Error(
      'renewOvid: issuerKeys does not match the root link\'s agent_pub. ' +
      'Only the original root keypair can renew a root token.'
    );
  }

  return createOvid({
    issuerKeys,
    authorizationDetails: existingToken.claims.authorization_details.map(d => ({
      type: d.type,
      rarFormat: d.rarFormat,
      policySet: d.policySet,
    })),
    agentId: existingToken.claims.sub,
    issuer: existingToken.claims.iss,
    ttlSeconds,
  });
}

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}
