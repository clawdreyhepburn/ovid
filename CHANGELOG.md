# Changelog

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
