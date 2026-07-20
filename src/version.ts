/**
 * OVID wire-protocol version vs package version.
 *
 * CRITICAL (stack review C4):
 *   `ovid_version` on a token is a **protocol / shape switch**, not the npm
 *   package semver. `verifyOvid` branches on it:
 *     - chain-protocol versions → nested ChainLink walk (crypto path)
 *     - legacy versions / missing → single-key JWT verify (no chain crypto)
 *
 *   Never set `ovid_version` from `package.json`. Bumping the package (0.4.2,
 *   0.4.3, …) must not change the token field unless the **wire shape**
 *   actually changes — and then `CHAIN_PROTOCOL_VERSIONS` must be updated in
 *   the same commit so verify still takes the crypto path.
 *
 *   Package version lives only in package.json / CHANGELOG / npm.
 */

/** Wire-format protocol version stamped into newly minted tokens. */
export const OVID_PROTOCOL_VERSION = '0.4.0' as const;

/**
 * Protocol versions that use nested-signature ChainLink verification.
 * Add a new entry only when minting a new wire shape that verify understands.
 */
export const CHAIN_PROTOCOL_VERSIONS: ReadonlySet<string> = new Set([
  OVID_PROTOCOL_VERSION,
]);

/** True when `ovid_version` should take the v0.4+ chain verification path. */
export function isChainProtocolVersion(version: unknown): version is string {
  return typeof version === 'string' && CHAIN_PROTOCOL_VERSIONS.has(version);
}
