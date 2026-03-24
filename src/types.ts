/**
 * Cedar policy set embedded in OVID tokens.
 *
 * Inspired by draft-cecchetti-oauth-rar-cedar-02, adapted for agent mandates.
 * Differences from the RAR draft:
 *   - `type` is an application-defined string (RAR requires it per RFC 9396)
 *   - Embedded directly in JWT `mandate` claim, not in `authorization_details` array
 *   - Designed for agent-to-agent delegation, not OAuth client-to-AS flow
 */
export interface CedarMandate {
  /** Application-defined type (required by RFC 9396 authorization_details) */
  type: string
  /** Must be "cedar" to use this profile */
  rarFormat: 'cedar'
  /** Cedar policy text — the agent's mandate */
  policySet: string
}

export interface OvidClaims {
  jti: string;
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  ovid_version: string;
  parent_chain: string[];
  parent_ovid?: string;
  agent_pub: string;
  mandate: CedarMandate;
}

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface CreateOvidOptions {
  issuerKeys: KeyPair;
  issuerOvid?: { jwt: string; claims: OvidClaims };
  agentId?: string;
  mandate: CedarMandate;
  ttlSeconds?: number;
  kid?: string;
  issuer?: string;
}

export interface VerifyOvidOptions {
  trustedRoots: CryptoKey[];
  maxChainDepth?: number;
}

export interface OvidResult {
  valid: boolean;
  principal: string;
  mandate: CedarMandate;
  chain: string[];
  expiresIn: number;
}

export interface OvidToken {
  jwt: string;
  claims: OvidClaims;
  keys: KeyPair;
}
