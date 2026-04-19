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
4. **The chain is the proof.** Each OVID embeds its full parent chain of cryptographic attestations. Walk it back to the root and verify every signature against a trusted root public key. No intermediate JWTs required.

### What OVID verifies — and what it doesn't

OVID is an **identity and lifetime** layer. A successful `verifyOvid` proves:

- The leaf agent's keypair was attested by the chain of parents back to a
  trusted root.
- Every `iat`/`exp` along the chain is internally consistent (lifetimes can
  only shorten, and the JWT's `iat` cannot predate the parent's attestation).
- The JWT was authored by the leaf's own keypair (not forged by a sibling).
- The token has not yet expired.

OVID does **not** verify:

- **Mandate attenuation.** OVID will happily sign a chain where a child's
  `policySet` is broader than its parent's. A rogue parent can mint a
  wide-open child token if it wants to. Enforcing that children only receive
  a subset of their parent's authority is the job of
  [`@clawdreyhepburn/ovid-me`](https://github.com/clawdreyhepburn/ovid-me)
  (or any policy engine that consumes the verified mandate). Use OVID for
  identity, OVID-ME for policy evaluation and subset proof.
- **Resource authorization.** OVID carries a Cedar policy set but doesn't
  evaluate it. Pass the verified mandate to Cedar (Cedarling, OVID-ME, etc.)
  to make an allow/deny decision for any specific action.

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
console.log(reviewer.claims.authorization_details[0].policySet); // Cedar policy
// In v0.4.0+, parent_chain is a ChainLink[] with cryptographic attestations.
// A root token has exactly one self-signed link (binding its own agent_pub).
console.log(reviewer.claims.authorization_details[0].parent_chain);
```

### Verify an OVID

```typescript
import { verifyOvid } from '@clawdreyhepburn/ovid';

// Preferred: options form with trustedRoots (v0.4.0+).
const result = await verifyOvid(reviewer.jwt, {
  trustedRoots: [primaryKeys.publicKey],
  maxChainDepth: 5,  // optional, defaults to 5
});

if (result.valid) {
  console.log(result.principal);  // "clawdrey/agent-7f3a"
  console.log(result.mandate);    // { type, rarFormat, policySet, ... }
  console.log(result.chain);      // ["clawdrey/agent-7f3a"] — flattened sub list
  console.log(result.expiresIn);  // seconds until expiry
}

// Legacy single-key overload (deprecated, emits console warning):
// const result = await verifyOvid(reviewer.jwt, primaryKeys.publicKey);
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

// v0.4.0: parent_chain is ChainLink[] with root first, leaf last.
const chain = helper.claims.authorization_details[0].parent_chain;
console.log(chain.length);         // 2
console.log(chain[0].sub);         // root's sub (e.g. "clawdrey")
console.log(chain[1].sub);         // helper's sub
// Each link carries { sub, agent_pub, iat, exp, sig } — the parent's signed
// attestation binding the child's identity.
```

### Chain verification (v0.4.0+)

Each delegation step emits a **ChainLink**: a compact signed attestation from
the parent binding the child's identity. The verifier walks the chain from
leaf to root, verifying each link's signature against the preceding link's
`agent_pub`, and anchors the root link against a caller-supplied set of
trusted root public keys.

A `ChainLink` is:

```typescript
interface ChainLink {
  sub: string;        // the agent this link represents
  agent_pub: string;  // base64url Ed25519 pubkey bound to sub
  iat: number;        // issue time (unix seconds)
  exp: number;        // expiry (unix seconds)
  sig: string;        // base64url Ed25519 sig by PARENT over canonical bytes
}
```

The signature covers this exact byte string (UTF-8):

```
ovid-chain-link/v1\n<sub>\n<agent_pub>\n<iat>\n<exp>
```

where `<iat>` and `<exp>` are decimal integers with no leading zeros
(`String(value)` in JavaScript). Roots self-sign (the root's link is verified
against its own `agent_pub`, which must equal one of `trustedRoots`).

**Implementation notes:**
- JWT payloads in v0.4.0 are signed by the **leaf agent's own keypair** (the
  one bound in the last `ChainLink`). This is a change from v0.3.x where
  children's JWTs were signed by the parent's keys.
- `renewOvid` can only renew **root** tokens. Chained tokens cannot be renewed
  in place because only the parent holds the key needed to sign a new chain
  link — request a fresh token from the parent instead.
- Legacy (pre-0.4.0) tokens with `string[]` `parent_chain` are still accepted
  by `verifyOvid` via a fallback path, but their chains are not cryptographically
  walkable. A one-time deprecation warning is emitted per process.

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

## How OVID Fits the Stack

OVID provides **identity and mandates** — it tells you who a sub-agent is and what authority was delegated to it. But OVID itself doesn't enforce anything. Enforcement is handled by two complementary layers:

1. **[Carapace](https://github.com/clawdreyhepburn/carapace)** — the deployment-level ceiling. The human defines what tools are allowed at all via Cedar policies, enforced on every `before_tool_call` hook. Binary allow/deny. This is the human's hard limit — no agent can exceed it regardless of what mandate it carries.

2. **[OVID-ME](https://github.com/clawdreyhepburn/ovid-me)** — mandate evaluation. Reads the Cedar policy from a verified OVID token and evaluates whether the specific tool call is permitted by the parent's delegation. Three modes: enforce, dry-run, shadow.

**Both must allow a tool call to proceed.** Carapace gates what the human permits; OVID-ME gates what the parent delegated. A sub-agent with a broad mandate still can't exceed the deployment ceiling, and a sub-agent under a permissive deployment ceiling still can't exceed its parent's mandate.

```
Tool call arrives
  │
  ├─ Carapace: "Does the deployment policy allow this?" ── deny ──> blocked
  │                                                         │
  │                                                       allow
  │                                                         │
  ├─ OVID-ME: "Does the agent's mandate allow this?"  ── deny ──> blocked
  │                                                         │
  │                                                       allow
  │                                                         │
  └─ Tool executes
```

## Related Projects

- **[@clawdreyhepburn/ovid-me](https://github.com/clawdreyhepburn/ovid-me)** — Cedar policy evaluation for OVID mandates (enforcement, audit, dashboard)
- **[@clawdreyhepburn/carapace](https://github.com/clawdreyhepburn/carapace)** — Deployment-level Cedar policy enforcement via OpenClaw's `before_tool_call` hook

## License

Copyright 2026 Clawdrey Hepburn LLC. Licensed under [Apache-2.0](LICENSE).

---

<p align="center">
  <em>OVID — <strong>O</strong>penClaw <strong>V</strong>erifiable <strong>I</strong>dentity <strong>D</strong>ocuments.</em>
</p>
