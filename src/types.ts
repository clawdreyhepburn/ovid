/** Cedar policy set in RAR format (draft-cecchetti-oauth-rar-cedar) */
export interface CedarMandate {
  rarFormat: 'cedar'
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

  // Legacy field — kept for backward compatibility with audit DB
  // New code should use mandate.policySet instead
  role?: string;
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
