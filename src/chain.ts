/**
 * OVID delegation chain — ChainLink signing and verification.
 *
 * Introduced in ovid_version 0.4.0. Each link is a compact attestation from
 * a parent agent binding a child's (sub, agent_pub, iat, exp). Walking the
 * chain proves cryptographic delegation from a trusted root to the leaf
 * without requiring the intermediate JWTs.
 *
 * Canonical signed bytes (MUST be byte-exact for interop):
 *
 *   "ovid-chain-link/v1\n" + sub + "\n" + agent_pub + "\n" + iat + "\n" + exp
 *
 * UTF-8 encoded. `iat` and `exp` are rendered as decimal integers with no
 * leading zeros or padding (i.e. `String(value)`). The signature is raw
 * Ed25519 (EdDSA) over those bytes, encoded as base64url without padding.
 */
import { importJWK, exportJWK } from 'jose';
import type { ChainLink } from './types.js';

const CHAIN_LINK_PREFIX = 'ovid-chain-link/v1\n';

/** Build the exact byte string that a ChainLink's `sig` covers. */
export function canonicalChainLinkBytes(params: {
  sub: string;
  agent_pub: string;
  iat: number;
  exp: number;
}): Uint8Array {
  const text =
    CHAIN_LINK_PREFIX +
    params.sub + '\n' +
    params.agent_pub + '\n' +
    String(params.iat) + '\n' +
    String(params.exp);
  return new TextEncoder().encode(text);
}

/**
 * Copy a Uint8Array's contents into a freshly-allocated ArrayBuffer.
 * Works around strict TypeScript lib.dom typing where WebCrypto wants
 * `BufferSource` backed by ArrayBuffer rather than the Uint8Array generic
 * `ArrayBufferLike` union (which includes SharedArrayBuffer).
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

/** base64url-encode a Uint8Array (no padding). */
function toBase64Url(bytes: Uint8Array): string {
  // Node's Buffer handles this; we avoid importing it to stay browser-friendly.
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  // btoa is available in Node 16+ globally.
  const b64 = globalThis.btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** base64url-decode to Uint8Array. */
function fromBase64Url(input: string): Uint8Array {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const binary = globalThis.atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Sign a ChainLink payload with an Ed25519 private key (the parent's signing key).
 * Returns the `sig` value as a base64url string.
 */
export async function signChainLink(
  payload: { sub: string; agent_pub: string; iat: number; exp: number },
  signerPrivateKey: CryptoKey,
): Promise<string> {
  const msg = toArrayBuffer(canonicalChainLinkBytes(payload));
  // WebCrypto: subtle.sign over Ed25519 curve. `jose` imported our key as
  // EdDSA; the runtime exposes it via globalThis.crypto.subtle.
  const sigBytes = new Uint8Array(
    await globalThis.crypto.subtle.sign('Ed25519', signerPrivateKey, msg)
  );
  return toBase64Url(sigBytes);
}

/**
 * Verify a ChainLink's signature was produced by the given verifier public key
 * over the canonical byte string for the link's (sub, agent_pub, iat, exp).
 */
export async function verifyChainLink(
  link: ChainLink,
  verifierPublicKey: CryptoKey,
): Promise<boolean> {
  const msg = toArrayBuffer(
    canonicalChainLinkBytes({
      sub: link.sub,
      agent_pub: link.agent_pub,
      iat: link.iat,
      exp: link.exp,
    })
  );
  const sig = toArrayBuffer(fromBase64Url(link.sig));
  try {
    return await globalThis.crypto.subtle.verify('Ed25519', verifierPublicKey, sig, msg);
  } catch {
    return false;
  }
}

/**
 * Import a base64url Ed25519 public key (as stored in ChainLink.agent_pub) into
 * a CryptoKey usable for signature verification.
 */
export async function importLinkPublicKey(agent_pub: string): Promise<CryptoKey> {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: agent_pub } as const;
  return (await importJWK(jwk, 'EdDSA')) as CryptoKey;
}

/**
 * Compare a trustedRoots CryptoKey against a base64url-encoded public key
 * from a ChainLink's agent_pub. Returns true if they represent the same key.
 *
 * This is the anchoring check — it decides whether a root ChainLink is one
 * the verifier trusts.
 */
export async function trustedRootMatches(
  trustedKey: CryptoKey,
  agent_pub: string,
): Promise<boolean> {
  try {
    const jwk = await exportJWK(trustedKey);
    return typeof jwk.x === 'string' && jwk.x === agent_pub;
  } catch {
    return false;
  }
}

/** Type guard: is the parent_chain value already in the new ChainLink[] shape? */
export function isChainLinkArray(
  value: unknown,
): value is ChainLink[] {
  if (!Array.isArray(value)) return false;
  if (value.length === 0) return false;
  const first = value[0];
  return (
    typeof first === 'object' &&
    first !== null &&
    typeof (first as any).sub === 'string' &&
    typeof (first as any).agent_pub === 'string' &&
    typeof (first as any).sig === 'string'
  );
}
