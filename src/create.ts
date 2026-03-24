import { SignJWT } from 'jose';
import { generateKeypair, exportPublicKeyBase64 } from './keys.js';
import { validateCedarSyntax } from './validate.js';
import type { CreateOvidOptions, OvidToken, OvidClaims, KeyPair, AuthorizationDetail } from './types.js';

const DEFAULT_TTL = 1800;
const DEFAULT_MAX_CHAIN_DEPTH = 5;

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

  // Check lifetime attenuation
  if (parentClaims) {
    const now = Math.floor(Date.now() / 1000);
    const childExp = now + ttlSeconds;
    if (childExp > parentClaims.exp) {
      throw new Error('Lifetime attenuation violation: child expiry exceeds parent expiry');
    }
  }

  // Check chain depth — extract parent_chain from first authorization detail
  const parentDetail = parentClaims?.authorization_details?.[0];
  const parentChain = parentClaims
    ? [...(parentDetail?.parent_chain ?? []), parentClaims.sub]
    : [];
  if (parentChain.length >= maxChainDepth) {
    throw new Error(`Chain depth ${parentChain.length + 1} exceeds max ${maxChainDepth}`);
  }

  // Generate keypair for the new agent
  const agentKeys = await generateKeypair();
  const agentPub = await exportPublicKeyBase64(agentKeys.publicKey);

  const issuerName = issuer ?? parentClaims?.sub ?? 'root';
  const agentId = options.agentId ?? `${issuerName}/agent-${randomHex(4)}`;

  const now = Math.floor(Date.now() / 1000);

  // Set OVID extensions on the first detail
  details[0] = {
    ...details[0],
    parent_chain: parentChain,
    agent_pub: agentPub,
    ovid_version: '0.3.0',
  };

  const claims: OvidClaims = {
    jti: agentId,
    iss: issuerName,
    sub: agentId,
    iat: now,
    exp: now + ttlSeconds,
    authorization_details: details,
    ...(parentClaims ? { parent_ovid: parentClaims.jti } : {}),
  };

  const header = { alg: 'EdDSA' as const, typ: 'ovid+jwt' };
  const finalHeader = kid ? { ...header, kid } : header;

  const jwt = await new SignJWT({ ...claims })
    .setProtectedHeader(finalHeader)
    .setIssuedAt(claims.iat)
    .setExpirationTime(claims.exp)
    .setJti(claims.jti)
    .setIssuer(claims.iss)
    .setSubject(claims.sub)
    .sign(issuerKeys.privateKey);

  return { jwt, claims, keys: agentKeys };
}

export async function renewOvid(
  existingToken: OvidToken,
  issuerKeys: KeyPair,
  ttlSeconds?: number,
): Promise<OvidToken> {
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
