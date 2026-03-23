# OVID Architecture

## Overview

OVID (OpenClaw Verifiable Identity Documents) provides portable, cryptographically signed identity and mandate tokens for AI agent hierarchies. An OVID token answers two questions: **who is this agent?** and **what is it allowed to do?**

## Core Concepts

### Mandates, Not Roles

Agents don't have roles. They have mandates — specific, task-scoped Cedar policy sets signed by their parent at spawn time. A mandate describes exactly what the agent is permitted to do, not what category it belongs to.

```
"You can read files in /src and /test, write to /test only, run npm test. Nothing else."
```

This is expressed as a Cedar policy set embedded directly in the OVID token, following the [Cedar Profile for OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/draft-cecchetti-oauth-rar-cedar/) format:

```json
{
  "mandate": {
    "rarFormat": "cedar",
    "policySet": "permit(principal, action == Ovid::Action::\"read_file\", resource) when { resource.path like \"/src/*\" || resource.path like \"/test/*\" }; permit(principal, action == Ovid::Action::\"write_file\", resource) when { resource.path like \"/test/*\" }; permit(principal, action == Ovid::Action::\"exec\", resource) when { resource.command == \"npm\" }; forbid(principal, action, resource);"
  }
}
```

### Two Enforcement Layers

OVID is designed to work alongside a deployment-level policy engine (such as Carapace), not replace it:

| Layer | Who writes it | What it does | Scope |
|-------|--------------|--------------|-------|
| **Deployment policy** (e.g., Carapace) | Human operator | Defines the ceiling — absolute boundaries no agent can exceed | Deployment-wide |
| **OVID mandate** | Parent agent | Defines the floor — task-specific constraints for this agent | Per-agent, portable |

Both layers evaluate every tool call. Both must allow. A sub-agent is constrained by whichever is more restrictive.

### Issuance-Time Proof

When a parent agent mints an OVID for a sub-agent, OVID verifies that the proposed mandate is a **provable subset** of the parent's effective permissions. This happens once at spawn time:

1. OVID queries the parent's effective policy via a `PolicySource` interface
2. OVID runs a formal subset proof: is every permission granted by the mandate also granted by the parent's policy?
3. If provably yes → mint the OVID
4. If not provable → refuse to mint (configuration error, not a runtime ambiguity)

This eliminates runtime ambiguity. If an OVID was minted, its mandate is guaranteed to be within the parent's bounds.

### PolicySource Interface

OVID doesn't know or care what provides the deployment-level policies. It depends on a single interface:

```typescript
interface PolicySource {
  /** Return the effective Cedar policy set for the given principal */
  getEffectivePolicy(principal: string): Promise<string>
}
```

Carapace can implement this. So can a static file, a remote policy server, or anything else that can produce Cedar policy text. OVID is standalone.

## Token Format

OVID tokens are JWTs (EdDSA/Ed25519) carrying identity + mandate:

```
Header: { "typ": "ovid+jwt", "alg": "EdDSA" }
Payload: {
  "iss": "<parent agent ID>",
  "sub": "<this agent's ID>",
  "iat": <issued-at>,
  "exp": <expiry>,
  "ovid_version": "0.2.0",
  "parent_chain": ["root", "parent"],
  "parent_ovid": "<parent's OVID JWT, if not root>",
  "agent_pub": "<this agent's Ed25519 public key, base64>",
  "mandate": {
    "rarFormat": "cedar",
    "policySet": "<Cedar policy text>"
  }
}
```

### Key Claims

- **`iss`** — the parent who signed this token
- **`sub`** — this agent's identity
- **`parent_chain`** — full delegation chain back to the root (human)
- **`agent_pub`** — this agent's public key (for signing child OVIDs)
- **`mandate`** — Cedar policy set defining what this agent can do

### Why Embedded Policies

The mandate is embedded as plain text, not a URL. Sub-agents are ephemeral (often seconds to minutes), may cross domain boundaries, and must not depend on network availability for enforcement. The token is self-contained: any verifier needs only the token and the parent's public key.

Mandate format follows [draft-cecchetti-oauth-rar-cedar](https://datatracker.ietf.org/doc/draft-cecchetti-oauth-rar-cedar/) for interoperability with OAuth 2.0 ecosystems.

## Cryptographic Identity

The identity chain serves two purposes:

1. **Provenance**: Prove that this agent was spawned by a specific parent, all the way back to the human root
2. **Mandate trust**: The mandate is only meaningful because it's signed by a known parent — without the signature, it's an unsigned JSON blob anyone could forge

Each agent holds an Ed25519 keypair. The parent signs the child's OVID (including the child's public key). The child can then sign OVIDs for its own sub-agents, with mandates that are provable subsets of its own mandate.

## Enforcement Flow

```
Spawn time:
  Parent writes mandate (Cedar policy set)
  → OVID queries PolicySource for parent's effective policy
  → Subset proof: mandate ⊆ parent's policy?
  → If proven: mint OVID token
  → If not: refuse (error)

Runtime (every tool call):
  Agent requests action
  → OVID evaluates action against mandate → allow/deny
  → Deployment engine evaluates action against ceiling → allow/deny
  → Both must allow
```

## Audit

OVID provides append-only audit logging:

- **Tier 1**: JSONL file logger (opt-in via `OVID_AUDIT_LOG` env var)
- **Tier 2**: SQLite database with structured queries (issuance, decisions, chains)
- **Tier 3**: Web dashboard with timeline, delegation tree, Sankey flow, policy usage, action breakdown

Every OVID issuance and mandate evaluation is recorded for forensics.

## Design Principles

1. **Self-contained tokens**: No external dependencies for verification or enforcement
2. **Mandate, not role**: Task-specific policies, not categorical labels
3. **Issuance-time proof**: Verify attenuation once at spawn, not per-request
4. **Interface, not implementation**: OVID depends on `PolicySource`, not on any specific policy engine
5. **Short-lived by default**: Credentials expire in ~30 minutes; revocation via TTL, not CRL
6. **Portable across domains**: OVID tokens work anywhere the verifier has the parent's public key
