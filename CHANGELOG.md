# Changelog

## [0.4.0] - 2026-04-19

Security-hardening release. Addresses findings #1, #2, and #10 from the
verified code review.

### Breaking Changes
- `verifyOvid` signature changed to `verifyOvid(jwt, options)` where
  `options` is `{ trustedRoots: CryptoKey[]; maxChainDepth?: number }`.
  The single-key overload `verifyOvid(jwt, publicKey)` still works via
  a deprecation shim (warns once per process).
- `parent_chain` format changed from `string[]` to `ChainLink[]`. Each
  link carries `{ sub, agent_pub, iat, exp, sig }` where `sig` is the
  parent's Ed25519 signature over the link. Pre-0.4.0 tokens continue
  to verify via the legacy code path with a deprecation warning.
- Child agents now sign their own JWTs with a fresh keypair (was: parent
  signed child's JWT). The parent's attestation lives in the chain link.
- `renewOvid` requires `issuerKeys.publicKey` to match the root link's
  `agent_pub`. Rejects chained tokens and legacy-shaped tokens
  unconditionally.

### Added
- Nested-signature chain verification with leaf-to-root walk.
- `maxChainDepth` option on `verifyOvid` to cap delegation depth.
- JWT `iat` backdating check: leaf JWT `iat` must be `>=` leaf chain
  link's `iat`.
- Lifetime attenuation enforcement along the chain (each link's `exp`
  must be `<=` parent's `exp`, `iat` must be `>=` parent's `iat`).
- `src/chain.ts` exporting `ChainLink`, `signChainLink`,
  `verifyChainLink`, and canonical serialization helpers.
- README section: "What OVID verifies — and what it doesn't". Explicitly
  states that mandate attenuation is OVID-ME's job.
- `ovid_version` is now a single named constant (was: scattered
  literals); matches `package.json`.

### Tests
- 41/41 pass. 12 new tests for chain verification, renewal strictness,
  and legacy compatibility.

## [0.2.0] - 2026-03-23

### Breaking Changes
- Mandates replace roles: `CreateOvidOptions.role` removed, use `mandate: CedarMandate` instead
- `OvidResult.role` removed, use `OvidResult.mandate` instead
- `ovid_version` changed from numeric `1` to string `"0.2.0"`
- Audit logging removed from core library (moved to @clawdreyhepburn/ovid-me)

### Added
- `CedarMandate` type following draft-cecchetti-oauth-rar-cedar format
- `validateCedarSyntax()` for policy text validation at token creation
- `importPublicKeyBase64()` for cross-domain key import
- Cedar policy validation in `createOvid()` (rejects malformed policies)

### Removed
- `role` claim (replaced by `mandate`)
- `auditLogger` parameter from `createOvid`/`verifyOvid`
- Audit, config, dashboard code (moved to @clawdreyhepburn/ovid-me)

## [0.1.0] - 2026-03-22
- Initial release: Ed25519 JWT signing, parent chains, role-based claims
