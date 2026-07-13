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

## New here? Read this first (no background assumed)

**What is this, in one sentence?** OVID is a small software library that gives each automated AI helper its own tamper-proof **ID badge**, so you always know who a helper is, who created it, what it's allowed to do, and when its access expires.

**Why does that matter?** When an AI assistant is given a big job, it often spawns smaller **helper programs** ("sub-agents") to handle pieces of it. By default, each helper inherits *all* the power of the thing that created it — like handing a house-painter the keys to your house, car, and bank account when they only needed one room. OVID replaces that with a specific, limited, unforgeable badge for each helper.

**A few terms you'll see, in plain English:**

- **Agent / sub-agent** — an automated AI worker. A "sub-agent" is a helper spawned by another agent.
- **Badge / identity document / "OVID"** — a small signed file that proves who a helper is and what it may do. (OVID = **O**penClaw **V**erifiable **I**dentity **D**ocument.)
- **Mandate** — the list of allowed actions printed on the badge.
- **Signing / cryptographic signature** — unforgeable digital math (the same kind that secures websites) that makes a badge impossible to fake or alter.
- **Chain** — because a helper can spawn its own helper, badges link together in a traceable chain leading back to you, the human.
- **JWT** — a common, standard file format for signed digital tokens. An OVID badge *is* a JWT with some extra fields. You don't need to know the format to use the library.

**What OVID does and doesn't do:** OVID *issues and verifies* badges (identity + expiry + traceability). It does **not** by itself stop a helper from misbehaving — that enforcement is a separate, companion job. See [How OVID Fits the Stack](#how-ovid-fits-the-stack). Think: OVID prints and validates the ID card; a separate security desk checks it at every door.

The rest of this README goes deeper and is aimed at developers integrating the library. If you just want the OpenClaw plugin that does all of this automatically, see **[@clawdreyhepburn/openclaw-ovid](https://github.com/clawdreyhepburn/openclaw-ovid)**.

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

### `verifyOvid(jwt, options): Promise<OvidResult>`
Verifies an OVID JWT's signature and full delegation chain. The modern form takes an options object:

```typescript
verifyOvid(jwt, { trustedRoots: [rootPublicKey], maxChainDepth: 5 });
```

Returns `{ valid, principal, mandate, chain, expiresIn }`. A legacy single-key overload `verifyOvid(jwt, publicKey)` still works but is deprecated and emits a one-time warning.

---

## Mandate Evaluation

**Looking for Cedar policy evaluation, enforcement, audit logging, and a forensics dashboard?**

See **[@clawdreyhepburn/ovid-me](https://github.com/clawdreyhepburn/ovid-me)** (OVID Mandate Evaluation) — reads mandates from verified OVID tokens, evaluates tool calls against Cedar policies, provides three enforcement modes (enforce/dry-run/shadow), and includes a full audit + dashboard system.

---

## OVID JWT Format

An OVID is a JWT compliant with [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), signed with EdDSA (Ed25519), with the dedicated media type `ovid+jwt`. The mandate travels in the `authorization_details` claim ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396)) using the `cedar` profile from [draft-cecchetti-oauth-rar-cedar-02](https://datatracker.ietf.org/doc/html/draft-cecchetti-oauth-rar-cedar-02).

### Header
```json
{ "alg": "EdDSA", "typ": "ovid+jwt" }
```

| Claim | Required | Notes |
|-------|----------|-------|
| `alg` | yes | Always `EdDSA` (Ed25519). |
| `typ` | yes | Always `ovid+jwt`. Distinguishes OVIDs from generic JWTs at parse time. |

### Payload — root token

A root token (depth 1) is one a top-level agent issues to itself. Its `parent_chain` contains exactly one self-signed `ChainLink`, anchoring the chain to a `trustedRoots` key supplied at verify time.

```json
{
  "jti": "clawdrey/agent-7f3a",
  "iss": "clawdrey",
  "sub": "clawdrey/agent-7f3a",
  "iat": 1777561629,
  "exp": 1777563429,
  "authorization_details": [
    {
      "type": "agent_mandate",
      "rarFormat": "cedar",
      "policySet": "permit(principal, action == Ovid::Action::\"read_file\", resource);",
      "parent_chain": [
        {
          "sub": "clawdrey/agent-7f3a",
          "agent_pub": "AVQXD2Fw6fdYMoFCMsYxTZ-km-Z9ZmmoBnlLIWOdPjo",
          "iat": 1777561629,
          "exp": 1777563429,
          "sig": "KxbNAyLTXYPW6uBXrwPOwrw1h976K8SJZqeNZWF7WmreFEPKTgm0p-4I1m--16x-l16jWcoCPtszJ-pND3HUCw"
        }
      ],
      "agent_pub": "AVQXD2Fw6fdYMoFCMsYxTZ-km-Z9ZmmoBnlLIWOdPjo",
      "ovid_version": "0.4.1"
    }
  ]
}
```

### Payload — delegated token (depth 2)

When a parent agent spawns a child, the child gets a fresh keypair and a new OVID with a `parent_chain` that grows by one link. The new link is signed by the parent's `agent_pub` and binds the child's `sub` and `agent_pub`. Lifetime is attenuated: `iat` and `exp` are clamped inside the parent's window.

```json
{
  "jti": "clawdrey/agent-7f3a/reviewer-9d2b",
  "iss": "clawdrey",
  "sub": "clawdrey/agent-7f3a/reviewer-9d2b",
  "iat": 1777561629,
  "exp": 1777562229,
  "authorization_details": [
    {
      "type": "agent_mandate",
      "rarFormat": "cedar",
      "policySet": "permit(principal, action == Ovid::Action::\"read_file\", resource == Ovid::Resource::\"/tmp/report.md\");",
      "parent_chain": [
        {
          "sub": "clawdrey/agent-7f3a",
          "agent_pub": "AVQXD2Fw6fdYMoFCMsYxTZ-km-Z9ZmmoBnlLIWOdPjo",
          "iat": 1777561629,
          "exp": 1777563429,
          "sig": "KxbNAyLTXYPW6uBXrwPOwrw1h976K8SJZqeNZWF7WmreFEPKTgm0p-4I1m--16x-l16jWcoCPtszJ-pND3HUCw"
        },
        {
          "sub": "clawdrey/agent-7f3a/reviewer-9d2b",
          "agent_pub": "4-1bUD-aCMszelJA_ZN15hwEWEf_yuU0mz1vq9qFDI4",
          "iat": 1777561629,
          "exp": 1777562229,
          "sig": "pGmrWMsdRy1A_jYjo7SmO1s1TGMd2rvQlvvkP2O1cKGoysbwVpJKcItiDhACTZsT588V7P4I6g_eggqKOYCLCg"
        }
      ],
      "agent_pub": "4-1bUD-aCMszelJA_ZN15hwEWEf_yuU0mz1vq9qFDI4",
      "ovid_version": "0.4.1"
    }
  ]
}
```

### Multi-hop chains (depth 3 and beyond)

A helper can spawn its own helper, which can spawn another, and so on. Each hop adds one signed link. The verifier walks the whole chain and enforces two rules **at every step**, not just the first:

- **Lifetime can only shorten** — each link's expiry is clamped inside its parent's.
- **Each link is signed by its immediate parent's key** — a grandchild's link must be signed by its parent, not by the root. A link signed by the wrong key fails verification.

This means the traceable chain-of-custody holds no matter how deep the delegation goes (up to `maxChainDepth`, default 5). The companion library [`@clawdreyhepburn/ovid-me`](https://github.com/clawdreyhepburn/ovid-me) additionally proves that each hop's *permissions* only ever narrow — a grandchild can never hold more authority than its parent, and that is checked with a formal proof engine at issuance time.

### Top-level claims

| Claim | Type | Required | Notes |
|-------|------|----------|-------|
| `jti` | `string` | yes | JWT ID. By convention the agent's path-style identifier (`<parent>/<child>`). |
| `iss` | `string` | yes | Issuer ID — the human or organization the root agent serves. |
| `sub` | `string` | yes | Subject — the agent this token identifies. Equal to `jti` for OVIDs. |
| `iat` | `number` | yes | Issued-at, unix seconds. Must be `>=` parent's `iat`. |
| `exp` | `number` | yes | Expiry, unix seconds. Must be `<=` parent's `exp` (lifetime attenuation). |
| `authorization_details` | `AuthorizationDetail[]` | yes | RFC 9396 carrier for the agent's mandate(s). OVID currently issues exactly one entry. |
| `parent_ovid` | `string` | legacy only | Pre-0.4.x tokens recorded the parent's `sub` here. Modern verifiers ignore it; the source of truth is `authorization_details[0].parent_chain`. |

### `authorization_details` entry (the mandate)

Each entry is an `AuthorizationDetail` — RFC 9396 with the `cedar` profile from `draft-cecchetti-oauth-rar-cedar-02`.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `type` | `string` | yes (RFC 9396) | Always `agent_mandate` for OVID. |
| `rarFormat` | `"cedar"` | yes | Selects the Cedar profile. |
| `policySet` | `string` | yes | Cedar policy text. The agent's mandate. |
| `parent_chain` | `ChainLink[]` | yes (v0.4.0+) | Cryptographic delegation chain, root first, leaf last. Pre-0.4 tokens used `string[]` of `sub`s and are accepted via a fallback path but are not cryptographically verifiable. |
| `agent_pub` | `string` | yes | Base64url Ed25519 public key bound to this token's `sub`. Equal to the leaf link's `agent_pub`. |
| `ovid_version` | `string` | yes (modern) | OVID library version that minted this token. Verifiers branch on this for shape compatibility. |

### `ChainLink`

Each link is a parent-signed attestation that some `sub` controls some `agent_pub` for some validity window.

| Field | Type | Notes |
|-------|------|-------|
| `sub` | `string` | Subject this link represents. |
| `agent_pub` | `string` | Base64url Ed25519 public key bound to `sub`. |
| `iat` | `number` | Issued-at. Must be `>=` parent link's `iat`. |
| `exp` | `number` | Expiry. Must be `<=` parent link's `exp`. |
| `sig` | `string` | Base64url Ed25519 signature over the canonical bytes below, produced by the **parent** link's `agent_pub`. The root link is self-signed. |

Canonical signed bytes (UTF-8, byte-exact for interop):

```
ovid-chain-link/v1\n<sub>\n<agent_pub>\n<iat>\n<exp>
```

`iat` and `exp` are decimal integers with no leading zeros.

### Verification

`verifyOvid(jwt, { trustedRoots, maxChainDepth })` (the preferred form) checks, in order:

1. JWT signature (EdDSA) using `issuerPublicKey`.
2. `typ === "ovid+jwt"`.
3. `iat`, `exp` against current time.
4. `parent_chain` is non-empty and bounded by `maxChainDepth` (default 5).
5. The leaf link's `sub` and `agent_pub` match the token's `sub` and `authorization_details[0].agent_pub`.
6. Each link's `iat`/`exp` is within its parent's window (lifetime attenuation).
7. Each non-root link's `sig` verifies under its parent's `agent_pub`.
8. The root link is self-signed and its `agent_pub` is a member of `trustedRoots`.

A token that fails any check returns `{ valid: false, ... }`. A passing token returns `{ valid: true, principal, mandate, chain, expiresIn }`.

---

## Development

```bash
git clone https://github.com/clawdreyhepburn/ovid.git
cd ovid
npm install
npm test        # 48 tests via vitest
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
│   ├── verify.test.ts
│   ├── chain.test.ts
│   ├── renew.test.ts
│   ├── delegation.test.ts
│   └── depth3-chain-construction.test.ts   # multi-hop chain soundness
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
