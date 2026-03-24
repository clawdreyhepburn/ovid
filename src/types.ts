/**
 * RFC 9396 authorization_details entry for OVID agent mandates.
 *
 * Per draft-cecchetti-oauth-rar-cedar-02, adapted for agent mandates.
 * The `authorization_details` JWT claim is registered in RFC 9396 Section 9.2.
 */
export interface AuthorizationDetail {
  /** Application-defined type (required by RFC 9396) */
  type: string
  /** Must be "cedar" to use this profile */
  rarFormat: 'cedar'
  /** Cedar policy text — the agent's mandate */
  policySet: string
  /** OVID delegation chain (optional — only present for OVID-minted tokens) */
  parent_chain?: string[]
  /** Agent's public key, base64-encoded (optional) */
  agent_pub?: string
  /** OVID version that minted this token (optional) */
  ovid_version?: string
}

/** @deprecated Use AuthorizationDetail */
export type CedarMandate = AuthorizationDetail;

export interface OvidClaims {
  jti: string;
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  authorization_details: AuthorizationDetail[];
  /** @deprecated Only present on legacy v0.2.x tokens before migration */
  parent_ovid?: string;
}

export const EMPTY_AUTHORIZATION_DETAIL: AuthorizationDetail = {
  type: 'agent_mandate',
  rarFormat: 'cedar',
  policySet: '',
};

/** @deprecated Use EMPTY_AUTHORIZATION_DETAIL */
export const EMPTY_MANDATE = EMPTY_AUTHORIZATION_DETAIL;

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface CreateOvidOptions {
  issuerKeys: KeyPair;
  /** @deprecated Use authorizationDetails instead */
  mandate?: AuthorizationDetail;
  /** RFC 9396 authorization details — single or array */
  authorizationDetails?: AuthorizationDetail | AuthorizationDetail[];
  issuerOvid?: { jwt: string; claims: OvidClaims };
  agentId?: string;
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
  mandate: AuthorizationDetail;
  chain: string[];
  expiresIn: number;
}

export interface OvidToken {
  jwt: string;
  claims: OvidClaims;
  keys: KeyPair;
}
