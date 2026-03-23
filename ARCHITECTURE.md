# OVID Architecture
## OpenClaw Verifiable Identity Documents

### The Problem

When an AI agent spawns a sub-agent, the sub-agent inherits access it doesn't need. A browser worker can send tweets. A code reviewer can delete files. A research agent can execute shell commands.

Most multi-agent frameworks treat all agents in a swarm as equally trusted. That's not a security model — it's the absence of one.

### The Solution

OVID gives every sub-agent a cryptographically signed identity document at spawn time. The document asserts:

- **Who** the agent is (unique identifier)
- **What role** it plays (code-reviewer, browser-worker, etc.)
- **Who created it** (the parent agent, forming a verifiable chain)
- **When it expires** (bounded lifetime)

The document is signed by the parent agent's private key and can be verified by anyone with the parent's public key. No central server. No infrastructure. The trust hierarchy IS the agent hierarchy.

OVID is **pure identity**. It answers "who is this agent?" — not "what is this agent allowed to do?" Authorization decisions (tool access, resource permissions, API scoping) belong to the policy layer: Carapace/Cedar, OpenClaw's native tool policy, or your own code.

---

## Trust Model

```
Human (root of trust)
  │
  │ delegates authority to
  ▼
Primary Agent (long-lived, has keypair)
  │
  │ issues OVID to
  ▼
Sub-Agent (ephemeral, carries OVID)
  │
  │ can issue derived OVID to
  ▼
Sub-Sub-Agent (shorter lifetime)
```

**Core principles:**

1. **The spawner is the attestor.** You trust a sub-agent because you trust the thing that created it, and that trust is cryptographically verifiable.

2. **Lifetime can only shorten.** A sub-agent's OVID cannot outlive its parent's. When the parent expires, all descendants expire.

3. **Identity is self-contained.** An OVID carries everything needed for verification. No database lookups, no central authority, no network calls.

4. **The chain is the proof.** Each OVID embeds its full parent chain. Any verifier can walk the chain back to the root (primary agent) and confirm every signature.

---

## OVID Document Format

OVIDs are JWTs (RFC 7519) signed with EdDSA (Ed25519). This means every OVID is a standard JWT that any JWT library can parse and verify — no custom serialization, no bespoke crypto.

### JWT Header

```json
{
  "alg": "EdDSA",
  "typ": "ovid+jwt",
  "kid": "clawdrey-primary-2026"
}
```

- `typ: "ovid+jwt"` distinguishes OVIDs from other JWTs in the ecosystem
- `kid` identifies the signing key for rotation support

### JWT Claims (Payload)

```json
{
  "jti": "clawdrey/reviewer-7f3a",
  "iss": "clawdrey",
  "sub": "clawdrey/reviewer-7f3a",
  "iat": 1711987200,
  "exp": 1711989000,

  "ovid_version": 1,
  "role": "code-reviewer",
  "parent_chain": ["sarah", "clawdrey"],
  "parent_ovid": "clawdrey/orchestrator-2b1c",
  "agent_pub": "MCowBQYDK2VwAyEA..."
}
```

Standard JWT claims:
- `jti` — unique OVID identifier
- `iss` — issuing (parent) agent's id
- `sub` — this agent's id (same as `jti`)
- `iat` — issued at (unix seconds)
- `exp` — expires at (unix seconds)

OVID-specific claims:
- `ovid_version` — format version (1)
- `role` — agent role label
- `parent_chain` — full delegation chain back to the human
- `parent_ovid` — parent's OVID `jti` (absent for primary agent)
- `agent_pub` — this agent's Ed25519 public key (for issuing derived OVIDs)

### Why JWTs with Ed25519?

**JWTs because:**
- Every identity system speaks JWT — zero integration friction
- Standard libraries in every language (jose, jsonwebtoken, nimbus, etc.)
- The IIW/IETF community already has tooling, debuggers (jwt.io), and mental models
- Cedarling (Gluu's WASM engine) already evaluates JWTs natively — free Carapace integration
- Claims are extensible without breaking verifiers

**Ed25519 (EdDSA) because:**
- **Fast:** ~30μs to sign, ~70μs to verify
- **Small:** 32-byte keys, 64-byte signatures
- **No infrastructure:** No CA, no certificate chains, no OCSP responders
- **JOSE-standard:** EdDSA is registered in the IANA JOSE algorithms registry (RFC 8037)
- **Quantum note:** Not post-quantum, but neither is anything else in practical JWT use today. OVIDs are short-lived (minutes, not years), so the window for quantum attack is minimal

---

## Roles

Roles are freeform strings. The OVID library does not define or enforce a role taxonomy — each deployment defines roles that make sense for its domain. An agent helping a software engineer will have different roles than one helping an accountant or an architect.

The `role` claim is for **identity and audit trails** — it says what kind of agent this is. Authorization decisions (which tools this role can use, which files it can access) are made by the policy layer (Cedar, OpenClaw tool policy, or your own code), not by OVID itself.

### Example: Software Engineering Agent

| Role | Description |
|------|------------|
| `architect` | designs systems, reviews structure |
| `coder` | writes and tests code |
| `code-reviewer` | reviews code, files issues |
| `security-reviewer` | audits code for vulnerabilities |
| `browser-worker` | interacts with web UIs |

### Example: Accounting Agent

| Role | Description |
|------|------------|
| `auditor` | reviews financial documents |
| `bookkeeper` | manages ledger entries |
| `tax-preparer` | prepares and files tax forms |
| `reconciler` | reconciles bank feeds with ledger |

### Example: Creative Agent

| Role | Description |
|------|------------|
| `researcher` | gathers reference material |
| `drafter` | writes initial drafts |
| `editor` | revises and polishes drafts |
| `publisher` | publishes finished work |

---

## Operations

### Issuing an OVID

```typescript
import { createOvid, generateKeypair } from '@clawdreyhepburn/ovid';

// Primary agent creates its keypair once (persisted)
const parentKeys = generateKeypair();

// Spawn a sub-agent with a verifiable identity
const reviewerOvid = createOvid({
  issuerKeys: parentKeys,
  issuerOvid: parentOvid,        // optional: absent for primary agent
  role: 'code-reviewer',
  ttlSeconds: 1800,              // 30 minutes
});

// reviewerOvid.jwt is a standard JWT string:
// eyJhbGciOiJFZERTQSIsInR5cCI6Im92aWQrand9.eyJqdGki...
```

### Verifying an OVID

```typescript
import { verifyOvid } from '@clawdreyhepburn/ovid';

// Pass the JWT string — library handles EdDSA verification
const result = verifyOvid(reviewerOvid.jwt, {
  trustedRoots: [primaryAgentPublicKey]
});

if (result.valid) {
  console.log(result.principal);   // "clawdrey/reviewer-7f3a"
  console.log(result.role);        // "code-reviewer"
  console.log(result.chain);       // ["sarah", "clawdrey"]
  console.log(result.expiresIn);   // seconds until expiry
}

// Any standard JWT library can also decode it:
// jose.jwtVerify(reviewerOvid.jwt, parentPublicKey, { algorithms: ['EdDSA'] })
```

Verification checks:
1. Signature is valid (Ed25519 verify against issuer's public key)
2. Parent chain signatures are valid (walk the chain)
3. Root of chain is in `trustedRoots`
4. Not expired
5. Lifetime does not exceed parent's lifetime

---

## Revocation

OVID uses **short-lived credentials** as the primary revocation mechanism:

- Default TTL: 30 minutes (configurable per role)
- Sub-agents are ephemeral — when the task ends, the OVID is meaningless
- Parent can refuse to issue new OVIDs (soft revocation)

For cases where immediate revocation is needed:

- **Revocation list:** The issuing agent maintains an in-memory set of revoked OVID ids
- **Cascade revocation:** Revoking a parent OVID implicitly revokes all descendants
- No external infrastructure needed — the list lives in the issuing agent's process

---

## Integration Points

### Standalone (no Carapace)

OVID works as a pure identity library. Your code issues and verifies identities, then makes its own authorization decisions:

```typescript
const ovid = verifyOvid(subagentOvid, { trustedRoots });
if (!ovid.valid) throw new Error('Untrusted sub-agent');

// OVID tells you WHO this agent is.
// YOUR code (or Cedar) decides what it's allowed to do.
if (ovid.role !== 'code-reviewer') {
  throw new Error(`Role ${ovid.role} not authorized for this operation`);
}
```

### With Carapace (Cedar integration)

When used with Carapace, OVID identity claims flow into the Cedar evaluation context. OVID provides the **principal identity**; Cedar policies make the **authorization decision**:

```cedar
// Cedar uses OVID identity to authorize actions
permit(
  principal is Agent,
  action == Action::"execute",
  resource == Tool::"read_file"
) when {
  principal.role == "code-reviewer" &&
  principal has parentChain &&
  principal.parentChain.contains("clawdrey")
};

// Cedar controls tool access — not OVID
forbid(
  principal is Agent,
  action == Action::"execute",
  resource == Tool::"exec"
) when {
  principal.role == "code-reviewer"
};
```

The `ovid-cedar` adapter maps OVID identity fields to Cedar entity attributes:

| OVID field | Cedar attribute | Type |
|-----------|----------------|------|
| `id` | `principal` | `Agent::"<id>"` |
| `role` | `principal.role` | String |
| `parentChain` | `principal.parentChain` | Set<String> |
| `issuer` | `principal.issuer` | String |
| `expiresAt` | `principal.expiresAt` | Long |

Authorization attributes (allowed tools, permitted paths, API access) are defined in Cedar policies and entities — not in the OVID itself.

### With OpenClaw

OVID hooks into OpenClaw's sub-agent lifecycle:

1. **At spawn time:** Before `sessions_spawn` executes, generate an OVID for the sub-agent based on the requested role
2. **In the sub-agent's context:** The OVID is injected as session metadata, providing verifiable identity to any policy enforcement layer
3. **At tool execution time:** Carapace evaluates Cedar policies using the OVID principal's identity claims (role, chain, issuer) to decide whether the action is permitted
4. **At completion:** The OVID expires naturally or is revoked when the sub-agent session ends

---

## What This Is NOT

- **Not a replacement for SPIFFE.** SPIFFE is an infrastructure-grade workload identity system. OVID is a lightweight agent credential for multi-agent orchestration. Different problem, different scale.
- **Not a VC (Verifiable Credential).** OVIDs are not W3C VCs. They don't use JSON-LD, DID methods, or VC data model. They're standard JWTs with custom claims, purpose-built for agent-to-agent trust within a single deployment.
- **Not authentication.** OVID is about identity and provenance. It assumes the transport layer handles authentication (OpenClaw sessions, TLS, etc.).
- **Not authorization.** OVID provides identity claims — who this agent is, what role it plays, who vouches for it. Authorization decisions (what tools it can use, what files it can access) belong to Cedar, OpenClaw's native tool policy, or your own code. Identity is not authorization.

---

## Security Considerations

1. **Private key storage:** The primary agent's Ed25519 private key must be protected. It's the root of trust for all OVIDs. Store it in the agent's credential directory with restricted permissions.

2. **Key rotation:** Primary agent keys should be rotated periodically. Old keys go into a `previousKeys` set for verifying OVIDs issued before rotation. Rotation frequency depends on deployment — monthly is reasonable.

3. **Identity is not authorization.** OVID tells you who an agent is; it does not tell you what that agent is allowed to do. A verified OVID with role "code-reviewer" is not itself a grant of any permissions — the policy layer must map that identity to concrete access decisions. Deploying OVID without a policy layer (Cedar, OpenClaw tool policy, or equivalent) means identity is informational only.

4. **Time-based attacks:** OVIDs rely on system clock for expiry. In a single-machine deployment (typical for OpenClaw), clock skew isn't a concern. For distributed deployments, use conservative TTLs.

5. **Chain depth:** Deep chains (>3 levels) are hard to audit. The library warns on chains deeper than 3 and rejects chains deeper than 5 by default (configurable).
