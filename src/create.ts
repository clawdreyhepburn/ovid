import { SignJWT } from 'jose';
import { generateKeypair, exportPublicKeyBase64 } from './keys.js';
import { defaultAuditLogger } from './audit.js';
import type { CreateOvidOptions, OvidToken, OvidClaims } from './types.js';

const DEFAULT_TTL = 1800;
const DEFAULT_MAX_CHAIN_DEPTH = 5;

export async function createOvid(options: CreateOvidOptions): Promise<OvidToken> {
  const {
    issuerKeys,
    issuerOvid,
    mandate,
    ttlSeconds = DEFAULT_TTL,
    kid,
    issuer,
  } = options;

  if (!mandate || mandate.rarFormat !== 'cedar' || !mandate.policySet) {
    throw new Error('mandate is required with rarFormat "cedar" and a non-empty policySet');
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

  // Check chain depth
  const parentChain = parentClaims
    ? [...parentClaims.parent_chain, parentClaims.sub]
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

  const claims: OvidClaims = {
    jti: agentId,
    iss: issuerName,
    sub: agentId,
    iat: now,
    exp: now + ttlSeconds,
    ovid_version: '0.2.0',
    parent_chain: parentChain,
    ...(parentClaims ? { parent_ovid: parentClaims.jti } : {}),
    agent_pub: agentPub,
    mandate,
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

  const logger = options.auditLogger ?? defaultAuditLogger;
  logger.logIssuance(claims);

  return { jwt, claims, keys: agentKeys };
}

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}
