export interface OvidClaims {
  jti: string;
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  ovid_version: number;
  role: string;
  parent_chain: string[];
  parent_ovid?: string;
  agent_pub: string;
}

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface CreateOvidOptions {
  issuerKeys: KeyPair;
  issuerOvid?: { jwt: string; claims: OvidClaims };
  agentId?: string;
  role: string;
  ttlSeconds?: number;
  maxChainDepth?: number;
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
  role: string;
  chain: string[];
  expiresIn: number;
}

export interface OvidToken {
  jwt: string;
  claims: OvidClaims;
  keys: KeyPair;
}
