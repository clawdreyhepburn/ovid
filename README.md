<p align="center">
  <h1 align="center">🪪 OVID</h1>
  <p align="center"><strong>Cryptographic identity for AI agents.</strong></p>
  <p align="center">
    Ed25519 signed JWTs with delegation chains — tells you exactly who a sub-agent is, who created it, and when it expires.
  </p>
  <p align="center">
    <a href="#the-problem">The Problem</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#api">API</a> •
    <a href="#mandate-evaluation">Mandate Evaluation</a> •
    <a href="docs/SECURITY.md">Security Guide</a> •
    <a href="#faq">FAQ</a>
  </p>
</p>

---

## The Problem

When an AI agent spawns a sub-agent, the sub-agent inherits everything — API keys, credentials, tool access, filesystem. The code reviewer has a credit card. The browser worker can send tweets. The research agent can read every file on the machine.

This is [ambient authority](https://en.wikipedia.org/wiki/Ambient_authority), and it's the same mistake we made with Unix root shells, shared browser cookies, and unsandboxed containers. The fix has always been the same: **explicit, attenuated credentials.**

OVID gives every sub-agent its own identity document — a signed JWT that says who it is, what mandate it carries, who created it, and when it expires. The spawning agent signs it. The chain is verifiable back to the human.

Read more: [Your Sub-Agents Are Running With Scissors](https://clawdrey.com/blog/your-sub-agents-are-running-with-scissors.html)

## How It Works

```
Human (root of trust)
  │
  │ delegates authority to
  ▼
Primary Agent (long-lived, has keypair)
  │
  │ issues OVID to
  ▼
Sub-Agent (ephemeral, carries OVID JWT with Cedar mandate)
  │
  │ can issue derived OVID to
  ▼
Sub-Sub-Agent (shorter lifetime, auditable chain)
```

**Four principles:**

1. **The spawner is the attestor.** You trust a sub-agent because you trust the thing that created it — and that trust is cryptographically verifiable.
2. **Lifetime can only shorten.** A child's OVID can't outlive its parent's. When the parent expires, everything downstream expires.
3. **Identity is self-contained.** An OVID carries everything needed for verification. No database. No central server. No network calls.
4. **The chain is the proof.** Each OVID embeds its full parent chain. Walk it back to the root and verify every signature.

## Quick Start

### Install

```bash
npm install @clawdreyhepburn/ovid
```

### Issue an OVID

```typescript
import { generateKeypair, createOvid } from '@clawdreyhepburn/ovid';

// Primary agent creates a keypair (do this once, persist it)
const primaryKeys = await generateKeypair();

// Spawn a sub-agent with a signed identity and Cedar mandate
const reviewer = await createOvid({
  issuerKeys: primaryKeys,
  issuer: 'clawdrey',
  mandate: {
    rarFormat: 'cedar',
    policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
  },
  ttlSeconds: 1800, // 30 minutes
});

console.log(reviewer.jwt);                // standard JWT string
console.log(reviewer.claims.mandate);      // Cedar policy set
console.log(reviewer.claims.parent_chain); // []
```

### Verify an OVID

```typescript
import { verifyOvid } from '@clawdreyhepburn/ovid';

const result = await verifyOvid(reviewer.jwt, primaryKeys.publicKey);

if (result.valid) {
  console.log(result.principal);  // "clawdrey/agent-7f3a"
  console.log(result.mandate);    // { rarFormat: 'cedar', policySet: '...' }
  console.log(result.chain);      // []
  console.log(result.expiresIn);  // seconds until expiry
}
```

### Delegation chains

Sub-agents can issue OVIDs to their own sub-agents:

```typescript
const helper = await createOvid({
  issuerKeys: reviewer.keys,
  issuerOvid: reviewer,
  mandate: {
    rarFormat: 'cedar',
    policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
  },
  ttlSeconds: 600, // shorter than parent ✅
});

console.log(helper.claims.parent_chain); // ["clawdrey/agent-7f3a"]
```

## API

### `generateKeypair(): Promise<KeyPair>`
Generates an Ed25519 keypair using the Web Crypto API.

### `exportPublicKeyBase64(key: CryptoKey): Promise<string>`
Exports a public key as a base64url string.

### `createOvid(options: CreateOvidOptions): Promise<OvidToken>`
Issues a new OVID JWT.

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `issuerKeys` | `KeyPair` | yes | — | Issuing agent's keypair |
| `issuerOvid` | `OvidToken` | no | — | Parent's OVID (omit for root) |
| `mandate` | `CedarMandate` | yes | — | Cedar policy set |
| `issuer` | `string` | no | — | Issuer ID |
| `agentId` | `string` | no | auto | Unique agent ID |
| `ttlSeconds` | `number` | no | `1800` | Time to live |
| `kid` | `string` | no | — | Key ID for JWT header |

### `verifyOvid(jwt, issuerPublicKey, options?): Promise<OvidResult>`
Verifies an OVID JWT's signature and claims. Returns `{ valid, principal, mandate, chain, expiresIn }`.

---

## Mandate Evaluation

**Looking for Cedar policy evaluation, enforcement, audit logging, and a forensics dashboard?**

See **[@clawdreyhepburn/ovid-me](https://github.com/clawdreyhepburn/ovid-me)** (OVID Mandate Evaluation) — reads mandates from verified OVID tokens, evaluates tool calls against Cedar policies, provides three enforcement modes (enforce/dry-run/shadow), and includes a full audit + dashboard system.

---

## OVID JWT Format

### Header
```json
{ "alg": "EdDSA", "typ": "ovid+jwt" }
```

### Payload
```json
{
  "jti": "clawdrey/agent-7f3a",
  "iss": "clawdrey",
  "sub": "clawdrey/agent-7f3a",
  "iat": 1711987200,
  "exp": 1711989000,
  "ovid_version": "0.2.0",
  "parent_chain": [],
  "agent_pub": "base64url-ed25519-public-key",
  "mandate": {
    "rarFormat": "cedar",
    "policySet": "permit(principal, action == Ovid::Action::\"read_file\", resource);"
  }
}
```

---

## Development

```bash
git clone https://github.com/clawdreyhepburn/ovid.git
cd ovid
npm install
npm test        # 12 tests via vitest
npm run build   # TypeScript → dist/
```

### Project structure

```
ovid/
├── src/
│   ├── index.ts       # Public API exports
│   ├── keys.ts        # Ed25519 keypair generation
│   ├── create.ts      # OVID issuance with lifetime attenuation
│   ├── verify.ts      # Signature verification and claims validation
│   └── types.ts       # TypeScript interfaces (including CedarMandate)
├── test/
│   ├── keys.test.ts
│   ├── create.test.ts
│   └── verify.test.ts
├── docs/
│   └── SECURITY.md
├── ARCHITECTURE.md
├── LICENSE
├── NOTICE
└── package.json
```

---

## License

Copyright 2026 Clawdrey Hepburn LLC. Licensed under [Apache-2.0](LICENSE).

---

<p align="center">
  <em>OVID — <strong>O</strong>penClaw <strong>V</strong>erifiable <strong>I</strong>dentity <strong>D</strong>ocuments.</em>
</p>
