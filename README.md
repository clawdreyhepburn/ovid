<p align="center">
  <h1 align="center">🪪 OVID</h1>
  <p align="center"><strong>Identity documents for AI agents.</strong></p>
  <p align="center">
    Cryptographically signed, short-lived credentials that tell you exactly who a sub-agent is, what it's allowed to do, and who created it.
  </p>
  <p align="center">
    <a href="#the-problem">The Problem</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#api">API</a> •
    <a href="#carapace-integration">Carapace Integration</a> •
    <a href="#faq">FAQ</a>
  </p>
</p>

---

## The Problem

When an AI agent spawns a sub-agent, the sub-agent inherits everything — API keys, credentials, tool access, filesystem. The code reviewer has a credit card. The browser worker can send tweets. The research agent can read every file on the machine.

This is [ambient authority](https://en.wikipedia.org/wiki/Ambient_authority), and it's the same mistake we made with Unix root shells, shared browser cookies, and unsandboxed containers. The fix has always been the same: **explicit, scoped, attenuated credentials.**

OVID gives every sub-agent its own identity document — a signed JWT that says who it is, what role it plays, who created it, and when it expires. The spawning agent signs it. The scope can only narrow. The chain is verifiable back to the human.

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
Sub-Agent (ephemeral, carries OVID JWT)
  │
  │ can issue derived OVID to
  ▼
Sub-Sub-Agent (narrower scope, shorter lifetime)
```

**Five principles:**

1. **The spawner is the attestor.** You trust a sub-agent because you trust the thing that created it — and that trust is cryptographically verifiable.

2. **Scope can only narrow.** A child's permissions must be a subset of its parent's. The library rejects anything else at issuance time.

3. **Lifetime can only shorten.** A child's OVID can't outlive its parent's. When the parent expires, everything downstream expires.

4. **Identity is self-contained.** An OVID carries everything needed for verification. No database. No central server. No network calls.

5. **The chain is the proof.** Each OVID embeds its full parent chain. Walk it back to the root and verify every signature.

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

// Spawn a sub-agent with a scoped identity
const reviewer = await createOvid({
  issuerKeys: primaryKeys,
  issuer: 'clawdrey',
  role: 'code-reviewer',
  scope: {
    tools: { allow: ['read_file', 'mcp_call'], deny: ['exec', 'write'] },
    paths: { allow: ['/projects/carapace/**'] },
  },
  ttlSeconds: 1800, // 30 minutes
});

// reviewer.jwt is a standard JWT string:
// eyJhbGciOiJFZERTQSIsInR5cCI6Im92aWQrand0In0.eyJqdGki...
console.log(reviewer.jwt);
console.log(reviewer.claims.role);        // "code-reviewer"
console.log(reviewer.claims.parent_chain); // ["clawdrey"]
```

### Verify an OVID

```typescript
import { verifyOvid } from '@clawdreyhepburn/ovid';

const result = await verifyOvid(reviewer.jwt, {
  trustedRoots: [primaryKeys.publicKey],
});

if (result.valid) {
  console.log(result.principal);  // "clawdrey/reviewer-7f3a"
  console.log(result.role);       // "code-reviewer"
  console.log(result.scope);      // { tools: { allow: [...], deny: [...] } }
  console.log(result.chain);      // ["clawdrey"]
  console.log(result.expiresIn);  // seconds until expiry
}
```

### Delegation chains

Sub-agents can issue further-scoped OVIDs to their own sub-agents:

```typescript
// The code reviewer spawns a read-only helper
const helper = await createOvid({
  issuerKeys: reviewer.keys,
  issuerOvid: reviewer,           // parent's OVID
  role: 'reader',
  scope: {
    tools: { allow: ['read_file'] },  // narrower than parent ✅
  },
  ttlSeconds: 600, // 10 minutes (shorter than parent ✅)
});

console.log(helper.claims.parent_chain); // ["clawdrey", "clawdrey/reviewer-7f3a"]

// This would throw — 'exec' isn't in parent's allow list:
await createOvid({
  issuerKeys: reviewer.keys,
  issuerOvid: reviewer,
  role: 'hacker',
  scope: {
    tools: { allow: ['read_file', 'exec'] }, // ❌ exceeds parent scope
  },
});
// Error: Scope attenuation violation: child scope exceeds parent
```

### Any JWT library can read it

OVIDs are standard JWTs. No custom parser needed:

```typescript
import * as jose from 'jose';

const { payload } = await jose.jwtVerify(reviewer.jwt, parentPublicKey, {
  algorithms: ['EdDSA'],
});
console.log(payload.role);          // "code-reviewer"
console.log(payload.ovid_version);  // 1
```

Or paste it into [jwt.io](https://jwt.io) and inspect the claims.

---

## API

### `generateKeypair(): Promise<KeyPair>`

Generates an Ed25519 keypair using the Web Crypto API.

### `exportPublicKeyBase64(key: CryptoKey): Promise<string>`

Exports a public key as a base64 string (for embedding in OVID claims).

### `createOvid(options: CreateOvidOptions): Promise<OvidToken>`

Issues a new OVID JWT.

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `issuerKeys` | `KeyPair` | yes | — | Issuing agent's keypair |
| `issuerOvid` | `OvidToken` | no | — | Parent's OVID (omit for primary agent) |
| `role` | `string` | yes | — | Freeform role label |
| `scope` | `OvidScope` | yes | — | Permitted tools, shell, API, paths |
| `issuer` | `string` | no | — | Issuer ID (required if no `issuerOvid`) |
| `agentId` | `string` | no | auto-generated | Unique agent ID |
| `ttlSeconds` | `number` | no | `1800` | Time to live (30 min default) |
| `maxChainDepth` | `number` | no | `5` | Maximum delegation depth |
| `kid` | `string` | no | — | Key ID for the JWT header |

**Throws** if:
- Child scope exceeds parent scope (attenuation violation)
- Child TTL exceeds parent's remaining lifetime
- Chain depth exceeds `maxChainDepth`

### `verifyOvid(jwt: string, options: VerifyOvidOptions): Promise<OvidResult>`

Verifies an OVID JWT's signature and claims.

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `trustedRoots` | `CryptoKey[]` | yes | Public keys of trusted root agents |
| `maxChainDepth` | `number` | no | Maximum allowed chain depth |

Returns `OvidResult` with `valid`, `principal`, `role`, `scope`, `chain`, `expiresIn`.

### `isSubsetScope(child: OvidScope, parent: OvidScope): boolean`

Checks whether a child scope is a valid subset of a parent scope. Used internally by `createOvid()` to enforce attenuation at issuance, but exported for custom validation.

**Important:** Scope in OVID is *advisory metadata* — it records the intended permissions, but OVID does not enforce access control at runtime. Enforcement is the job of a policy engine like [Cedar/Carapace](https://github.com/clawdreyhepburn/carapace). The attenuation check at issuance time guarantees that a child's *claimed* scope never exceeds its parent's, but the actual authorization decision happens elsewhere.

Rules:
- Allow lists: child must be a subset of parent's allows
- Deny lists: child must be a superset of parent's denies (child must deny at least everything parent denies)
- Missing category in parent = no restriction (child can have anything)

---

## OVID JWT Format

### Header

```json
{
  "alg": "EdDSA",
  "typ": "ovid+jwt"
}
```

### Payload

```json
{
  "jti": "clawdrey/reviewer-7f3a",
  "iss": "clawdrey",
  "sub": "clawdrey/reviewer-7f3a",
  "iat": 1711987200,
  "exp": 1711989000,
  "ovid_version": 1,
  "role": "code-reviewer",
  "scope": {
    "tools": { "allow": ["read_file", "mcp_call"], "deny": ["exec"] },
    "paths": { "allow": ["/projects/carapace/**"] }
  },
  "parent_chain": ["clawdrey"],
  "parent_ovid": "clawdrey/orchestrator-2b1c",
  "agent_pub": "MCowBQYDK2VwAyEA..."
}
```

| Claim | Type | Description |
|-------|------|-------------|
| `jti` | string | Unique OVID identifier |
| `iss` | string | Issuing (parent) agent's ID |
| `sub` | string | This agent's ID |
| `iat` | number | Issued at (unix seconds) |
| `exp` | number | Expires at (unix seconds) |
| `ovid_version` | number | Format version (`1`) |
| `role` | string | Freeform role label |
| `scope` | object | Authorized tools, shell, API, paths |
| `parent_chain` | string[] | Full delegation chain back to root |
| `parent_ovid` | string | Parent's OVID `jti` |
| `agent_pub` | string | This agent's Ed25519 public key (for issuing derived OVIDs) |

### Why JWTs? Why Ed25519?

**JWTs** because every identity system speaks JWT. Standard libraries in every language, debuggable at jwt.io, and [Cedarling](https://github.com/JanssenProject/jans/tree/main/jans-cedarling) evaluates them natively — so Carapace integration is free.

**Ed25519** because it's fast (~30μs to sign, ~70μs to verify), small (32-byte keys, 64-byte signatures), requires no infrastructure (no CA, no OCSP), and is IANA-registered for JOSE ([RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)).

---

## Carapace Integration

OVID is the identity layer. [Carapace](https://github.com/clawdreyhepburn/carapace) is the enforcement layer. Together:

1. Primary agent spawns a sub-agent and issues an OVID
2. Sub-agent passes its OVID JWT to Carapace via `X-OVID-Token` header
3. Carapace extracts claims and passes them as Cedar context
4. Cedar policies evaluate against role, parent chain, depth, attestation status
5. Carapace returns a **three-valued decision**: DENY, ALLOW (proven), or ALLOW (unproven)

```cedar
// Only code reviewers spawned by clawdrey can read files in the carapace project
permit(
  principal is Jans::Workload,
  action == Jans::Action::"use_tool",
  resource is Jans::Tool
) when {
  context.agent_role == "code-reviewer" &&
  context.agent_parent_chain.contains("clawdrey") &&
  resource.project == "carapace"
};
```

**Without Carapace**, OVID still works as a standalone identity library. Verify OVIDs in your own code and make access decisions however you like.

---

## Roles

Roles are freeform strings. OVID doesn't define or enforce a role taxonomy — each deployment defines roles that make sense for its domain.

The `role` claim is for **human readability and audit trails**. Authorization comes from `scope` (in standalone mode) or from Cedar policies (with Carapace). Cedar policies can reference either or both.

| Domain | Example roles |
|--------|--------------|
| Software engineering | `architect`, `coder`, `code-reviewer`, `security-reviewer`, `browser-worker` |
| Accounting | `auditor`, `bookkeeper`, `tax-preparer`, `reconciler` |
| Creative | `researcher`, `drafter`, `editor`, `publisher` |

---

## What This Is NOT

- **Not SPIFFE.** SPIFFE is infrastructure-grade workload identity. OVID is lightweight agent credentials for multi-agent orchestration. Different problem, different scale.
- **Not a Verifiable Credential.** OVIDs are not W3C VCs. No JSON-LD, no DIDs. Standard JWTs with custom claims, purpose-built for agent-to-agent trust.
- **Not authentication.** OVID is about identity and provenance. Transport-layer auth (TLS, OpenClaw sessions) is assumed.
- **Not access control.** OVID provides identity and scope claims. Access control decisions are made by Cedar/Carapace, OpenClaw's native tool policy, or your own code.

---

## Security Considerations

1. **Private key storage.** The primary agent's Ed25519 key is the root of trust. Protect it. Restricted file permissions, credential directory, don't log it.

2. **Short-lived by design.** Default TTL is 30 minutes. Short-lived credentials are the primary revocation mechanism — no CRL infrastructure needed.

3. **Chain depth.** Deep chains (>3 levels) are hard to audit. Default max is 5. The library warns on chains deeper than 3.

4. **Scope completeness.** Scope is only as good as its coverage. If a tool isn't listed, it isn't gated. Carapace integration closes this gap with Cedar's default-deny.

5. **Clock dependence.** Expiry relies on system clock. Single-machine deployments (typical for agents) don't have skew issues. For distributed deployments, use conservative TTLs.

---

## FAQ

**Why not just use tool allowlists at spawn time?**

Allowlists tell the runtime what to restrict, but they don't give the sub-agent a verifiable credential. The sub-agent can't prove its own scope. There's no attenuation guarantee across delegation chains. And there's no audit trail. See [the blog post](https://clawdrey.com/blog/your-sub-agents-are-running-with-scissors.html).

**Why not SPIFFE/SVIDs?**

SPIFFE assumes a SPIRE server, a control plane, and Kubernetes or VMs. Most agents run on laptops or Mac minis. OVID needs zero infrastructure — just a keypair.

**Do I need Carapace to use OVID?**

No. OVID is a standalone identity library. You can verify OVIDs and make access decisions in your own code. Carapace adds Cedar-based policy enforcement and formal attenuation proofs, but it's optional.

**What happens when an OVID expires?**

The sub-agent's identity becomes unverifiable. Any system checking the OVID will reject it. The credential solves itself — like milk, but on purpose.

---

## Development

```bash
git clone https://github.com/clawdreyhepburn/ovid.git
cd ovid
npm install
npm test        # 20 tests via vitest
npm run build   # TypeScript → dist/
```

### Project structure

```
ovid/
├── src/
│   ├── index.ts       # Public API exports
│   ├── keys.ts        # Ed25519 keypair generation
│   ├── create.ts      # OVID issuance with scope/lifetime attenuation
│   ├── verify.ts      # Signature verification and claims validation
│   ├── scope.ts       # Scope subset logic
│   └── types.ts       # TypeScript interfaces
├── test/
│   ├── keys.test.ts   # Keypair generation tests
│   ├── create.test.ts # Issuance and attenuation tests
│   ├── verify.test.ts # Verification tests
│   └── scope.test.ts  # Scope subset tests
├── docs/
│   └── ...
├── ARCHITECTURE.md    # Full design document
├── LICENSE            # Apache-2.0
└── package.json
```

---

## Contributors

| Avatar | Name | Role |
|--------|------|------|
| <img src="https://github.com/ClawdreyHepburn.png" width="50"> | **Clawdrey Hepburn** ([@ClawdreyHepburn](https://x.com/ClawdreyHepburn)) | Creator, primary author |
| <img src="https://github.com/Sarahcec.png" width="50"> | **Sarah Cecchetti** ([@Sarahcec](https://github.com/Sarahcec)) | Co-creator, architecture |
| <img src="https://github.com/nynymike.png" width="50"> | **Michael Schwartz** ([@nynymike](https://github.com/nynymike)) | Cedarling / Gluu |

---

## License

Copyright 2026 Clawdrey Hepburn LLC. Licensed under [Apache-2.0](LICENSE).

---

<p align="center">
  <em>OVID — <strong>O</strong>penClaw <strong>V</strong>erifiable <strong>I</strong>dentity <strong>D</strong>ocuments. Also a Roman poet who wrote extensively about transformation. Make of that what you will.</em>
</p>
<p align="center">
  <strong>Identity documents for AI agents.</strong>
</p>
