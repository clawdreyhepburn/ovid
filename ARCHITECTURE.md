# OVID Architecture
## OpenClaw Verifiable Identity Documents

### The Problem

When an AI agent spawns a sub-agent, the sub-agent inherits access it doesn't need. A browser worker can send tweets. A code reviewer can delete files. A research agent can execute shell commands.

Most multi-agent frameworks treat all agents in a swarm as equally trusted. That's not a security model — it's the absence of one.

### The Solution

OVID gives every sub-agent a cryptographically signed identity document at spawn time. The document asserts:

- **Who** the agent is (unique identifier)
- **What role** it plays (code-reviewer, browser-worker, etc.)
- **What scope** it has (which resources, tools, or domains)
- **Who created it** (the parent agent, forming a verifiable chain)
- **When it expires** (bounded lifetime)

The document is signed by the parent agent's private key and can be verified by anyone with the parent's public key. No central server. No infrastructure. The trust hierarchy IS the agent hierarchy.

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
Sub-Sub-Agent (narrower scope, shorter lifetime)
```

**Core principles:**

1. **The spawner is the attestor.** You trust a sub-agent because you trust the thing that created it, and that trust is cryptographically verifiable.

2. **Scope can only narrow.** A sub-agent's permissions must be a subset of its parent's. Escalation is structurally impossible — the library rejects any OVID that exceeds its parent's scope.

3. **Lifetime can only shorten.** A sub-agent's OVID cannot outlive its parent's. When the parent expires, all descendants expire.

4. **Identity is self-contained.** An OVID carries everything needed for verification. No database lookups, no central authority, no network calls.

5. **The chain is the proof.** Each OVID embeds its full parent chain. Any verifier can walk the chain back to the root (primary agent) and confirm every signature.

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
  "scope": {
    "tools": { "allow": ["read_file", "mcp_call"], "deny": ["exec", "write"] },
    "shell": { "deny": ["rm", "curl"] },
    "paths": { "allow": ["/Users/*/projects/repo-a/**"] }
  },
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
- `scope` — authorized tools, shell commands, API domains, filesystem paths
- `parent_chain` — full delegation chain back to the human
- `parent_ovid` — parent's OVID `jti` (absent for primary agent)
- `agent_pub` — this agent's Ed25519 public key (for issuing derived OVIDs)

### Scope Structure

```typescript
interface OvidScope {
  tools?: {
    allow?: string[];      // tool names or patterns (e.g., "read_file", "github/*")
    deny?: string[];       // explicit denials (deny wins over allow)
  };
  shell?: {
    allow?: string[];      // binary names (e.g., "git", "npm")
    deny?: string[];       // e.g., "rm", "curl"
  };
  api?: {
    allow?: string[];      // domain names (e.g., "api.github.com")
    deny?: string[];       // e.g., "*.social-media.com"
  };
  paths?: {
    allow?: string[];      // filesystem paths (e.g., "/Users/*/projects/repo-a/**")
    deny?: string[];       // e.g., "~/.ssh/**", "~/.openclaw/credentials/**"
  };
  custom?: Record<string, string[]>;  // extensible for future scope types
}
```

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

The `role` claim is for **human readability and audit trails**. Authorization comes from the `scope`, not the role name. Cedar policies can reference either or both.

### Example: Software Engineering Agent

| Role | Typical scope |
|------|--------------|
| `architect` | read files, search web, no code execution |
| `coder` | read/write files, git, run tests, no deployment |
| `code-reviewer` | read-only, file issues, no modifications |
| `security-reviewer` | read-only, static analysis tools |
| `browser-worker` | browser on specified domains, no exec |

### Example: Accounting Agent

| Role | Typical scope |
|------|--------------|
| `auditor` | read financial docs, query databases, no writes |
| `bookkeeper` | read/write ledger entries, no bank API access |
| `tax-preparer` | read all, write tax forms, submit to IRS API |
| `reconciler` | read bank feeds + ledger, flag discrepancies |

### Example: Creative Agent

| Role | Typical scope |
|------|--------------|
| `researcher` | web search, read reference docs |
| `drafter` | write files, no publish |
| `editor` | read/write drafts, no publish |
| `publisher` | read drafts, publish to CMS, post to social |

**Scope templates** are an optional convenience. The library ships a few common templates (e.g., `readOnly`, `noExec`, `webOnly`) that you can use as starting points, but you're never required to use them.

---

## Operations

### Issuing an OVID

```typescript
import { createOvid, generateKeypair } from '@clawdreyhepburn/ovid';

// Primary agent creates its keypair once (persisted)
const parentKeys = generateKeypair();

// Spawn a sub-agent with a scoped identity
const reviewerOvid = createOvid({
  issuerKeys: parentKeys,
  issuerOvid: parentOvid,        // optional: absent for primary agent
  role: 'code-reviewer',
  scope: {
    tools: { allow: ['read_file', 'mcp_call'], deny: ['exec', 'write'] },
    paths: { allow: ['/Users/*/projects/repo-a/**'] },
  },
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
  console.log(result.scope);       // { tools: { allow: [...], deny: [...] } }
  console.log(result.chain);       // ["sarah", "clawdrey"]
  console.log(result.expiresIn);   // seconds until expiry
}

// Any standard JWT library can also decode it:
// jose.jwtVerify(reviewerOvid.jwt, parentPublicKey, { algorithms: ['EdDSA'] })
```
```

Verification checks:
1. Signature is valid (Ed25519 verify against issuer's public key)
2. Parent chain signatures are valid (walk the chain)
3. Root of chain is in `trustedRoots`
4. Not expired
5. Scope is a subset of parent's scope (attenuation)

### Scope Attenuation

When a sub-agent issues a derived OVID, the library enforces that the child's scope is a subset of the parent's:

```
Parent scope: { tools: { allow: ["read_file", "write", "exec"] } }
Child scope:  { tools: { allow: ["read_file"] } }           ✅ Valid (subset)
Child scope:  { tools: { allow: ["read_file", "browser"] } } ❌ Rejected (browser not in parent)
```

This is enforced at issuance time, not just verification. You can't create an invalid OVID.

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

OVID works as a pure identity library. Your code issues, verifies, and makes decisions:

```typescript
const ovid = verifyOvid(subagentOvid, { trustedRoots });
if (!ovid.valid) throw new Error('Untrusted sub-agent');
if (!ovid.scope.tools.allow.includes(requestedTool)) {
  throw new Error(`Tool ${requestedTool} not in scope for role ${ovid.role}`);
}
```

### With Carapace (Cedar integration)

When used with Carapace, OVIDs map to Cedar principals:

```cedar
// The OVID becomes the principal
permit(
  principal is Agent,
  action == Action::"execute",
  resource == Tool::"read_file"
) when {
  principal.role == "code-reviewer" &&
  principal has parentChain &&
  principal.parentChain.contains("clawdrey")
};

// Deny escalation attempts
forbid(
  principal is Agent,
  action == Action::"execute",
  resource == Tool::"exec"
) when {
  principal.role == "code-reviewer"
};
```

The `ovid-cedar` adapter maps OVID fields to Cedar entity attributes:

| OVID field | Cedar attribute | Type |
|-----------|----------------|------|
| `id` | `principal` | `Agent::"<id>"` |
| `role` | `principal.role` | String |
| `parentChain` | `principal.parentChain` | Set<String> |
| `scope.tools.allow` | `principal.allowedTools` | Set<String> |
| `scope.tools.deny` | `principal.deniedTools` | Set<String> |
| `issuer` | `principal.issuer` | String |
| `expiresAt` | `principal.expiresAt` | Long |

### With OpenClaw

OVID hooks into OpenClaw's sub-agent lifecycle:

1. **At spawn time:** Before `sessions_spawn` executes, generate an OVID for the sub-agent based on the requested role
2. **In the sub-agent's context:** The OVID is injected as session metadata, available to any policy enforcement layer
3. **At tool execution time:** If Carapace is present, the OVID principal is used for Cedar evaluation. If not, the OVID scope can drive OpenClaw's native `tools.allow`/`tools.deny`
4. **At completion:** The OVID expires naturally or is revoked when the sub-agent session ends

---

## What This Is NOT

- **Not a replacement for SPIFFE.** SPIFFE is an infrastructure-grade workload identity system. OVID is a lightweight agent credential for multi-agent orchestration. Different problem, different scale.
- **Not a VC (Verifiable Credential).** OVIDs are not W3C VCs. They don't use JSON-LD, DID methods, or VC data model. They're standard JWTs with custom claims, purpose-built for agent-to-agent trust within a single deployment.
- **Not authentication.** OVID is about authorization and provenance. It assumes the transport layer handles authentication (OpenClaw sessions, TLS, etc.).
- **Not access control.** OVID provides identity and scope claims. Access control decisions are made by Cedar, OpenClaw's native tool policy, or your own code.

---

## Security Considerations

1. **Private key storage:** The primary agent's Ed25519 private key must be protected. It's the root of trust for all OVIDs. Store it in the agent's credential directory with restricted permissions.

2. **Key rotation:** Primary agent keys should be rotated periodically. Old keys go into a `previousKeys` set for verifying OVIDs issued before rotation. Rotation frequency depends on deployment — monthly is reasonable.

3. **Scope completeness:** The scope system is only as good as its coverage. If a sub-agent can bypass scope via a tool that OVID doesn't gate (e.g., a built-in tool with no policy hook), the scope is advisory, not enforceable. Carapace integration closes this gap.

4. **Time-based attacks:** OVIDs rely on system clock for expiry. In a single-machine deployment (typical for OpenClaw), clock skew isn't a concern. For distributed deployments, use conservative TTLs.

5. **Chain depth:** Deep chains (>3 levels) are hard to audit. The library warns on chains deeper than 3 and rejects chains deeper than 5 by default (configurable).
