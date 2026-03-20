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

```typescript
interface Ovid {
  // Identity
  id: string;              // unique identifier (e.g., "clawdrey/reviewer-7f3a")
  version: 1;              // format version

  // Role & Scope
  role: string;            // "code-reviewer" | "coder" | "browser-worker" | etc.
  scope: OvidScope;        // what this agent is permitted to do

  // Provenance
  issuer: string;          // parent agent's id
  parentChain: string[];   // full chain: ["sarah", "clawdrey", "orchestrator"]
  parentOvidId?: string;   // parent's OVID id (absent for primary agent)

  // Lifetime
  issuedAt: number;        // unix timestamp (seconds)
  expiresAt: number;       // unix timestamp (seconds)

  // Cryptographic binding
  publicKey: string;       // this agent's Ed25519 public key (base64)
  issuerPublicKey: string; // parent's Ed25519 public key (base64)
  signature: string;       // Ed25519 signature over the canonical document (base64)
}

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

### Serialization

OVIDs are serialized as JSON. The signature covers the canonical JSON encoding of all fields except `signature` itself (fields sorted alphabetically, no whitespace).

### Why Ed25519?

- **Fast:** ~30μs to sign, ~70μs to verify
- **Small:** 32-byte keys, 64-byte signatures
- **No infrastructure:** No CA, no certificate chains, no OCSP responders
- **Widely available:** Node.js crypto, libsodium, every platform

---

## Role Taxonomy (v1)

Roles are labels that map to default scope templates. They're a convenience — you can always override the scope directly.

| Role | Description | Default tool access | Default shell | Default API |
|------|-------------|-------------------|---------------|-------------|
| `architect` | Design and planning | read_file, web_search, web_fetch | none | any |
| `coder` | Write and test code | read_file, write, edit, exec, process | git, npm, node, python | api.github.com |
| `code-reviewer` | Review code, file issues | read_file, mcp_call(github/*) | git (read-only) | api.github.com |
| `security-reviewer` | Security analysis | read_file, exec(static analysis only) | grep, rg, semgrep | none |
| `browser-worker` | Web browsing tasks | browser, web_fetch | none | specified domains |
| `social-media` | Social media engagement | web_fetch | none | api.x.com |
| `research` | Information gathering | web_search, web_fetch, read_file | none | any |
| `admin` | Full access (use sparingly) | all | all | all |

Roles are not hierarchical — they're flat labels. Authorization comes from the scope, not the role name. The role is for human readability and audit trails.

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
```

### Verifying an OVID

```typescript
import { verifyOvid } from '@clawdreyhepburn/ovid';

const result = verifyOvid(ovid, { trustedRoots: [primaryAgentPublicKey] });

if (result.valid) {
  console.log(result.principal);   // "clawdrey/reviewer-7f3a"
  console.log(result.role);        // "code-reviewer"
  console.log(result.scope);       // { tools: { allow: [...], deny: [...] } }
  console.log(result.chain);       // ["sarah", "clawdrey"]
  console.log(result.expiresIn);   // seconds until expiry
}
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
- **Not a VC (Verifiable Credential).** OVIDs are not W3C VCs. They don't use JSON-LD, DID methods, or VC data model. They're purpose-built for agent-to-agent trust within a single deployment.
- **Not authentication.** OVID is about authorization and provenance. It assumes the transport layer handles authentication (OpenClaw sessions, TLS, etc.).
- **Not access control.** OVID provides identity and scope claims. Access control decisions are made by Cedar, OpenClaw's native tool policy, or your own code.

---

## Security Considerations

1. **Private key storage:** The primary agent's Ed25519 private key must be protected. It's the root of trust for all OVIDs. Store it in the agent's credential directory with restricted permissions.

2. **Key rotation:** Primary agent keys should be rotated periodically. Old keys go into a `previousKeys` set for verifying OVIDs issued before rotation. Rotation frequency depends on deployment — monthly is reasonable.

3. **Scope completeness:** The scope system is only as good as its coverage. If a sub-agent can bypass scope via a tool that OVID doesn't gate (e.g., a built-in tool with no policy hook), the scope is advisory, not enforceable. Carapace integration closes this gap.

4. **Time-based attacks:** OVIDs rely on system clock for expiry. In a single-machine deployment (typical for OpenClaw), clock skew isn't a concern. For distributed deployments, use conservative TTLs.

5. **Chain depth:** Deep chains (>3 levels) are hard to audit. The library warns on chains deeper than 3 and rejects chains deeper than 5 by default (configurable).
