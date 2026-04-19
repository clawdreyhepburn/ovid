/**
 * A single link in the OVID delegation chain.
 *
 * In ovid_version 0.4.0+, `parent_chain` is an array of ChainLink objects
 * rather than plain `sub` strings. Each link carries a cryptographic
 * attestation from its parent binding (sub, agent_pub, iat, exp), enabling
 * verifiers to walk the chain back to a trusted root without needing the
 * intermediate JWTs.
 *
 * Canonical signed bytes for `sig` (MUST be byte-exact for interop):
 *   "ovid-chain-link/v1\n" + sub + "\n" + agent_pub + "\n" + iat + "\n" + exp
 * encoded as UTF-8. `iat` and `exp` are decimal integers with no leading
 * zeros. The signature algorithm is Ed25519 (EdDSA); `sig` is the raw
 * 64-byte signature encoded as base64url (no padding).
 *
 * Root links are self-signed: the `sig` verifies against the same key
 * named by `agent_pub`. The verifier anchors the chain by requiring the
 * root link's `agent_pub` to correspond to a key in `trustedRoots`.
 */
export interface ChainLink {
  /** The agent subject this link represents */
  sub: string;
  /** base64url-encoded Ed25519 public key bound to `sub` */
  agent_pub: string;
  /** Issued-at (unix seconds). Must be >= parent link's iat. */
  iat: number;
  /** Expiry (unix seconds). Must be <= parent link's exp. */
  exp: number;
  /** base64url-encoded Ed25519 signature by PARENT's agent_pub over canonical bytes. */
  sig: string;
}

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
  /**
   * OVID delegation chain.
   * - In ovid_version 0.4.0+: ChainLink[] with cryptographic attestations.
   * - In ovid_version <= 0.3.x: string[] of `sub` identifiers (no linkage).
   * Represented here as a union so verifiers can branch on shape.
   */
  parent_chain?: ChainLink[] | string[]
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
  /** Accepted root public keys. A token is only valid if its chain anchors to one of these. */
  trustedRoots: CryptoKey[];
  /** Maximum chain depth to accept (default 5). */
  maxChainDepth?: number;
}

export interface OvidResult {
  valid: boolean;
  principal: string;
  mandate: AuthorizationDetail;
  /**
   * Flattened chain for consumers: `sub` identifiers in delegation order
   * (root first, leaf last). For full chain data (agent_pub, iat, exp,
   * sig), inspect `mandate.parent_chain`.
   */
  chain: string[];
  expiresIn: number;
}

export interface OvidToken {
  jwt: string;
  claims: OvidClaims;
  keys: KeyPair;
}
