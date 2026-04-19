import { jwtVerify, decodeJwt } from 'jose';
import type {
  OvidResult,
  VerifyOvidOptions,
  OvidClaims,
  AuthorizationDetail,
  ChainLink,
} from './types.js';
import { EMPTY_AUTHORIZATION_DETAIL } from './types.js';
import {
  verifyChainLink,
  importLinkPublicKey,
  trustedRootMatches,
  isChainLinkArray,
} from './chain.js';

const DEFAULT_MAX_CHAIN_DEPTH = 5;

// Deduplicate deprecation warnings so consumers don't get flooded.
let warnedSingleKeyOverload = false;
let warnedLegacyToken = false;

/**
 * Verify an OVID JWT against a set of trusted root public keys.
 *
 * In the preferred (options-based) form:
 *
 *   verifyOvid(jwt, { trustedRoots: [rootPub], maxChainDepth: 5 })
 *
 * A legacy single-key overload is retained for v0.3.x backward compatibility:
 *
 *   verifyOvid(jwt, rootPub)            // deprecated
 *   verifyOvid(jwt, rootPub, options)   // deprecated
 *
 * Both forms warn once per process.
 */
export async function verifyOvid(
  jwt: string,
  options: VerifyOvidOptions,
): Promise<OvidResult>;
export async function verifyOvid(
  jwt: string,
  issuerPublicKey: CryptoKey,
  options?: Partial<VerifyOvidOptions>,
): Promise<OvidResult>;
export async function verifyOvid(
  jwt: string,
  keyOrOptions: CryptoKey | VerifyOvidOptions,
  legacyOptions?: Partial<VerifyOvidOptions>,
): Promise<OvidResult> {
  // Resolve to the normalized options form.
  const opts: VerifyOvidOptions = isVerifyOptions(keyOrOptions)
    ? keyOrOptions
    : toOptionsFromSingleKey(keyOrOptions, legacyOptions);

  if (!Array.isArray(opts.trustedRoots) || opts.trustedRoots.length === 0) {
    return invalid();
  }
  const maxChainDepth = opts.maxChainDepth ?? DEFAULT_MAX_CHAIN_DEPTH;

  try {
    // ── Peek at payload to decide which verification path to take. ──
    // We can't trust anything from the peek until we've verified a signature.
    const payloadPeek = safeDecodeJwt(jwt);
    if (!payloadPeek) return invalid();

    const detailPeek = payloadPeek.authorization_details?.[0];
    const version = detailPeek?.ovid_version;
    const chainValue = detailPeek?.parent_chain;

    if (version === '0.4.0' && isChainLinkArray(chainValue)) {
      return await verifyV04(jwt, chainValue, opts.trustedRoots, maxChainDepth);
    }

    // ── Legacy path: v0.3.x / v0.2.x / missing version. ──
    // Chain is not cryptographically walkable. We fall back to the original
    // single-key semantics: verify the JWT signature against SOME trusted
    // root; any match anchors the token. We emit a deprecation warning.
    if (!warnedLegacyToken) {
      warnedLegacyToken = true;
      // eslint-disable-next-line no-console
      console.warn(
        '[ovid] verifying a legacy (pre-0.4.0) token: parent_chain is not cryptographically ' +
        'verified. Re-issue tokens with @clawdreyhepburn/ovid >= 0.4.0 for chain verification.'
      );
    }
    return await verifyLegacy(jwt, opts.trustedRoots);
  } catch {
    return invalid();
  }
}

// ──────────────────────────────────────────────────────────────────────────
// v0.4.0 path: nested-signature chain verification
// ──────────────────────────────────────────────────────────────────────────

async function verifyV04(
  jwt: string,
  chain: ChainLink[],
  trustedRoots: CryptoKey[],
  maxChainDepth: number,
): Promise<OvidResult> {
  if (chain.length < 1 || chain.length > maxChainDepth) return invalid();

  // Anchor: find a trustedRoot whose exported public key matches chain[0].agent_pub.
  let anchorKey: CryptoKey | null = null;
  for (const root of trustedRoots) {
    if (await trustedRootMatches(root, chain[0].agent_pub)) {
      anchorKey = root;
      break;
    }
  }
  if (!anchorKey) return invalid();

  // Root link: self-signed with its own agent_pub. Verify against anchorKey.
  if (!(await verifyChainLink(chain[0], anchorKey))) return invalid();

  // Walk: each subsequent link is signed by its parent's agent_pub.
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1];
    const child = chain[i];

    // Lifetime attenuation across the chain.
    if (child.exp > parent.exp) return invalid();
    if (child.iat < parent.iat) return invalid();

    const parentKey = await importLinkPublicKey(parent.agent_pub);
    if (!(await verifyChainLink(child, parentKey))) return invalid();
  }

  // Verify the JWT signature with the leaf link's agent_pub. The leaf IS
  // the attested keypair for the current token's subject, so this is the
  // only key that can legitimately have signed this JWT.
  const leaf = chain[chain.length - 1];
  const leafKey = await importLinkPublicKey(leaf.agent_pub);

  let payload: OvidClaims;
  try {
    const result = await jwtVerify(jwt, leafKey, { algorithms: ['EdDSA'] });
    payload = result.payload as unknown as OvidClaims;
  } catch {
    return invalid();
  }

  // JWT subject must match the leaf link.
  if (payload.sub !== leaf.sub) return invalid();

  // Token expiry vs wall clock.
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = payload.exp - now;
  if (expiresIn <= 0) return invalid();

  // JWT exp must not exceed leaf link's exp. Without this, a child could
  // claim a longer lifetime than the parent attested.
  if (payload.exp > leaf.exp) return invalid();

  // JWT iat must not predate leaf link's iat. Without this, a child could
  // backdate its own JWT to fake provenance (appearing to exist before the
  // parent actually attested it). payload.iat < leaf.iat means the child's
  // own JWT claims an earlier issue time than the parent's attestation
  // window — that's impossible if the parent truly authorized the child.
  if (typeof payload.iat === 'number' && payload.iat < leaf.iat) return invalid();

  const detail = payload.authorization_details?.[0];
  if (!detail || !detail.policySet) return invalid();

  const mandate: AuthorizationDetail = {
    ...detail,
    type: detail.type || 'agent_mandate',
  };

  return {
    valid: true,
    principal: payload.sub,
    mandate,
    chain: chain.map(l => l.sub),
    expiresIn,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Legacy path: pre-0.4.0 tokens
// ──────────────────────────────────────────────────────────────────────────

async function verifyLegacy(jwt: string, trustedRoots: CryptoKey[]): Promise<OvidResult> {
  // Try each trusted root until one verifies the JWT signature.
  let payload: OvidClaims | null = null;
  for (const key of trustedRoots) {
    try {
      const result = await jwtVerify(jwt, key, { algorithms: ['EdDSA'] });
      payload = result.payload as unknown as OvidClaims;
      break;
    } catch {
      // try next
    }
  }
  if (!payload) return invalid();

  const claims = payload;

  // Back-compat: hoist old v0.2.x top-level mandate into authorization_details.
  const legacyTop = payload as any;
  if (legacyTop.mandate && !claims.authorization_details) {
    claims.authorization_details = [{
      type: legacyTop.mandate.type || 'agent_mandate',
      rarFormat: legacyTop.mandate.rarFormat,
      policySet: legacyTop.mandate.policySet,
      parent_chain: legacyTop.parent_chain,
      agent_pub: legacyTop.agent_pub,
      ovid_version: legacyTop.ovid_version,
    }];
  }

  if (!Array.isArray(claims.authorization_details) || claims.authorization_details.length === 0) {
    return invalid();
  }

  const mandateDetail =
    claims.authorization_details.find(d => d.type === 'agent_mandate') ??
    claims.authorization_details[0];

  const version = mandateDetail.ovid_version;
  // Legacy path accepts 0.2.0, 0.3.0, 0.3.1, missing, or numeric 1.
  if (
    version &&
    version !== '0.3.0' &&
    version !== '0.3.1' &&
    version !== '0.2.0' &&
    (version as unknown) !== 1
  ) {
    return invalid();
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = claims.exp - now;
  if (expiresIn <= 0) return invalid();

  if (version && !mandateDetail.policySet) return invalid();

  const mandate: AuthorizationDetail = {
    ...mandateDetail,
    type: mandateDetail.type || 'agent_mandate',
  };

  // Flatten legacy string[] chain; if somehow it's already ChainLink[], use .sub.
  const rawChain = mandateDetail.parent_chain ?? [];
  const chain: string[] = Array.isArray(rawChain)
    ? rawChain.map((c: any) => (typeof c === 'string' ? c : c?.sub ?? ''))
    : [];

  return {
    valid: true,
    principal: claims.sub,
    mandate,
    chain,
    expiresIn,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

function isVerifyOptions(x: unknown): x is VerifyOvidOptions {
  return (
    typeof x === 'object' &&
    x !== null &&
    Array.isArray((x as VerifyOvidOptions).trustedRoots)
  );
}

function toOptionsFromSingleKey(
  key: CryptoKey,
  legacy?: Partial<VerifyOvidOptions>,
): VerifyOvidOptions {
  if (!warnedSingleKeyOverload) {
    warnedSingleKeyOverload = true;
    // eslint-disable-next-line no-console
    console.warn(
      '[ovid] verifyOvid(jwt, issuerPublicKey) is deprecated. ' +
      'Use verifyOvid(jwt, { trustedRoots: [issuerPublicKey] }) instead.'
    );
  }
  return {
    trustedRoots: [key],
    ...(legacy?.maxChainDepth !== undefined ? { maxChainDepth: legacy.maxChainDepth } : {}),
  };
}

function safeDecodeJwt(jwt: string): OvidClaims | null {
  try {
    return decodeJwt(jwt) as unknown as OvidClaims;
  } catch {
    return null;
  }
}

function invalid(): OvidResult {
  return {
    valid: false,
    principal: '',
    mandate: EMPTY_AUTHORIZATION_DETAIL,
    chain: [],
    expiresIn: 0,
  };
}
