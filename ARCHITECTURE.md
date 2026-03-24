# OVID Architecture

## Overview

OVID (OpenClaw Verifiable Identity Documents) provides portable, cryptographically signed identity and mandate tokens for AI agent hierarchies. An OVID token answers two questions: **who is this agent?** and **what is it allowed to do?**

## Core Concepts

### Mandates, Not Roles

Agents don't have roles. They have mandates — specific, task-scoped Cedar policy sets signed by their parent at spawn time. A mandate describes exactly what the agent is permitted to do, not what category it belongs to.

```
"You can read files in /src and /test, write to /test only, run npm test. Nothing else."
```

This is expressed as a Cedar policy set embedded directly in the OVID token, inspired by [draft-cecchetti-oauth-rar-cedar-02](https://datatracker.ietf.org/doc/draft-cecchetti-oauth-rar-cedar/) (Cedar Profile for OAuth 2.0 Rich Authorization Requests):

> **Key differences from the draft:** OVID embeds mandates in JWT claims rather than OAuth `authorization_details` arrays, adds a required `type` field per RFC 9396, and is designed for agent-to-agent delegation rather than client-to-AS OAuth flows.

```json
{
  "mandate": {
    "rarFormat": "cedar",
    "policySet": "permit(principal, action == Ovid::Action::\"read_file\", resource) when { resource.path like \"/src/*\" || resource.path like \"/test/*\" }; permit(principal, action == Ovid::Action::\"write_file\", resource) when { resource.path like \"/test/*\" }; permit(principal, action == Ovid::Action::\"exec\", resource) when { resource.command == \"npm\" }; forbid(principal, action, resource);"
  }
}
```

### Two Enforcement Layers

OVID tokens are designed to work alongside a deployment-level policy engine (such as [Carapace](https://github.com/clawdreyhepburn/carapace)), not replace it. OVID carries the mandate; evaluation and enforcement happen elsewhere:

| Layer | Who writes it | What it does | Scope |
|-------|--------------|--------------|-------|
| **Deployment policy** (e.g., [Carapace](https://github.com/clawdreyhepburn/carapace)) | Human operator | Defines the ceiling — absolute boundaries no agent can exceed (binary allow/deny) | Deployment-wide |
| **OVID mandate** (evaluated by [OVID-ME](https://github.com/clawdreyhepburn/ovid-me)) | Parent agent | Defines the floor — task-specific constraints for this agent | Per-agent, portable |

Both layers evaluate every tool call. Both must allow. A sub-agent is constrained by whichever is more restrictive.

**OVID itself does not evaluate mandates.** It creates and verifies identity tokens that carry mandates. For mandate evaluation, subset proofs, and audit logging, see [OVID-ME](https://github.com/clawdreyhepburn/ovid-me).

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

Mandate format is inspired by [draft-cecchetti-oauth-rar-cedar-02](https://datatracker.ietf.org/doc/draft-cecchetti-oauth-rar-cedar/) (Cedar Profile for OAuth 2.0 Rich Authorization Requests). Key differences: OVID embeds mandates in JWT claims rather than OAuth `authorization_details` arrays and is designed for agent-to-agent delegation rather than client-to-AS OAuth flows.

## Cryptographic Identity

The identity chain serves two purposes:

1. **Provenance**: Prove that this agent was spawned by a specific parent, all the way back to the human root
2. **Mandate trust**: The mandate is only meaningful because it's signed by a known parent — without the signature, it's an unsigned JSON blob anyone could forge

Each agent holds an Ed25519 keypair. The parent signs the child's OVID (including the child's public key). The child can then sign OVIDs for its own sub-agents, with mandates that are provable subsets of its own mandate.

## Enforcement Flow

OVID handles token creation and verification. Mandate evaluation is performed by [OVID-ME](https://github.com/clawdreyhepburn/ovid-me):

```
Spawn time (OVID):
  Parent writes mandate (Cedar policy set)
  → OVID creates and signs the token
  → Token carries mandate + identity + parent chain

Spawn time (OVID-ME, optional):
  → OVID-ME queries PolicySource for parent's effective policy
  → Subset proof: mandate ⊆ parent's policy?
  → If proven: proceed. If not: refuse to mint.

Runtime (OVID-ME + Carapace):
  Agent requests action
  → OVID-ME evaluates action against mandate → allow/deny
  → Carapace evaluates action against deployment ceiling → allow/deny
  → Both must allow
```

## Audit

Audit logging is provided by [OVID-ME](https://github.com/clawdreyhepburn/ovid-me):

- **Tier 1**: JSONL file logger
- **Tier 2**: SQLite database with structured queries (issuance, decisions, chains)
- **Tier 3**: Web dashboard with timeline, delegation tree, Sankey flow, policy usage, action breakdown

## Design Principles

1. **Self-contained tokens**: No external dependencies for verification or enforcement
2. **Mandate, not role**: Task-specific policies, not categorical labels
3. **Issuance-time proof**: Verify attenuation once at spawn, not per-request
4. **Interface, not implementation**: OVID depends on `PolicySource`, not on any specific policy engine
5. **Short-lived by default**: Credentials expire in ~30 minutes; revocation via TTL, not CRL
6. **Portable across domains**: OVID tokens work anywhere the verifier has the parent's public key
