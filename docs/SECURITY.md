# Security Considerations

Honest guidance on what OVID protects, what it doesn't, and how to avoid the mistakes that make identity systems useless.

**The short version:** OVID gives your sub-agents verifiable identity. It does not give them access control. Identity without enforcement is an audit trail, not a security boundary. If you need enforcement, pair OVID with [Carapace](https://github.com/clawdreyhepburn/carapace).

---

## Table of Contents

- [What OVID Protects Against](#what-ovid-protects-against)
- [What OVID Does NOT Protect Against](#what-ovid-does-not-protect-against)
- [Private Key Management](#private-key-management)
- [TTL and Revocation](#ttl-and-revocation)
- [Chain Depth](#chain-depth)
- [Clock Security](#clock-security)
- [Claim Visibility](#claim-visibility)
- [Threat Model](#threat-model)
- [Recommended Deployment Patterns](#recommended-deployment-patterns)

---

## What OVID Protects Against

**Identity spoofing.** Without OVID, any sub-agent can claim to be anything. With OVID, the sub-agent carries a signed credential from its parent. The parent's public key proves the credential is genuine. You can verify the entire delegation chain back to the root.

**Phantom agents.** Sub-agents that appear from nowhere with no provenance. Every OVID has an issuer, a parent chain, and a timestamp. If a sub-agent can't present a valid OVID, it has no verified identity.

**Lifetime creep.** A sub-agent that outlives its purpose. OVID enforces lifetime attenuation at issuance — a child credential can't outlive its parent's. When the parent expires, the child is already expired (or will be soon).

**Chain depth abuse.** Unbounded delegation chains where sub-agents spawn sub-agents spawn sub-agents. OVID enforces a maximum chain depth (default: 5). Deeper than that and `createOvid()` throws.

**Post-incident forensics.** When something goes wrong, the OVID JWT is a self-contained forensic artifact. It tells you who the agent was, who created it, what role it claimed, when it was issued, and the full delegation chain — all cryptographically verifiable after the fact.

---

## What OVID Does NOT Protect Against

Be honest about these. OVID is an identity layer. It has deliberate boundaries.

**Unauthorized actions.** An OVID proves who an agent is. It does not control what the agent does. A sub-agent with a valid OVID and the role `code-reviewer` can still delete your production database if nothing enforces the "code-reviewer" role at the tool level. You need a policy engine (Cedar/Carapace) for authorization.

**Compromised parent agents.** If a parent agent is compromised, it can issue valid OVIDs for any role. The OVID is only as trustworthy as the issuer. OVID can't protect against a compromised root of trust — no credential system can.

**Prompt injection.** A sub-agent that gets prompt-injected through fetched content will still have a valid OVID. The credential is real. The agent's behavior is not. OVID helps with forensics (you know exactly which agent went rogue) but doesn't prevent the injection.

**Exfiltration within permitted scope.** Even with identity + authorization, a sub-agent with legitimate read access to a file can exfiltrate its contents through a permitted channel. Identity and authorization are necessary but not sufficient — content inspection (like network-level DLP) is a separate layer.

**Key theft.** If an attacker steals the primary agent's private key, they can forge OVIDs. See [Private Key Management](#private-key-management).

---

## Private Key Management

The primary agent's Ed25519 private key is the root of trust for the entire delegation hierarchy. If it's compromised, everything downstream is compromised.

### Do

- **Restrict file permissions.** The key file should be readable only by the agent's process.

  ```bash
  # macOS / Linux
  chmod 600 /path/to/agent-keys.json
  chown $(whoami) /path/to/agent-keys.json
  ```

- **Store keys in a dedicated credential directory.** Not in the workspace. Not in a config file. Not anywhere the agent might accidentally include them in a log or commit.

- **Use a separate key per primary agent.** Don't share keys across agents. If one is compromised, you only lose one delegation tree.

- **Rotate keys periodically.** Generate a new keypair and re-issue OVIDs. Old keys should be deleted, not archived.

### Don't

- **Don't log keys.** Not in debug output, not in audit logs, not in error messages.
- **Don't embed keys in environment variables** if the agent can read its own environment (most can).
- **Don't commit keys to git.** Add your key directory to `.gitignore`. Check with `git log --all -p -- '*.key' '*.pem' '*private*'` to make sure nothing slipped through.
- **Don't transmit keys over unencrypted channels.** Ed25519 private keys are 32 bytes. They're easy to exfiltrate if exposed.

### Future: Hardware-Backed Keys

Ed25519 is supported by hardware security modules (HSMs) and secure enclaves. A future version of OVID could integrate with platform keystores (macOS Keychain, FIDO2 tokens, TPMs) so the private key never exists in extractable form. This is not implemented today.

---

## TTL and Revocation

OVID uses short-lived credentials as the primary revocation mechanism. There is no Certificate Revocation List (CRL), no OCSP responder, no revocation database. When an OVID expires, it's gone.

### Recommended TTLs

| Use case | TTL | Rationale |
|----------|-----|-----------|
| Ephemeral sub-agent (one task) | 5–15 minutes | Task-scoped. Expires shortly after expected completion. |
| Session worker (ongoing task) | 30 minutes | Default. Balances utility with exposure window. |
| Long-running job | 1–2 hours | Use sparingly. Longer TTLs = longer exposure if compromised. |
| Never | > 24 hours | Don't do this. If you need a credential that lasts a day, rethink your architecture. |

### The Exposure Window Problem

If a sub-agent is compromised at minute 1 of a 30-minute OVID, you have 29 minutes of exposure. There's no way to revoke the credential early — you have to wait for expiry.

Mitigations:
- **Use shorter TTLs for high-risk operations.** A deploy agent should have a 5-minute OVID, not a 30-minute one.
- **Pair with Carapace.** Even if the OVID is valid, Cedar policies can deny specific actions. Revocation at the policy layer is instant.
- **Monitor the audit log.** Suspicious behavior from a known agent identity can trigger alerts before the OVID expires.

### The `ttlSeconds: 86400` Footgun

Nothing in OVID prevents you from setting `ttlSeconds: 86400` (24 hours). The library doesn't enforce a maximum TTL. This is intentional — we don't know your use case. But if you're setting TTLs longer than 2 hours, ask yourself why, and consider whether a credential refresh pattern would be better.

---

## Chain Depth

Each OVID embeds its full parent chain. The default maximum depth is 5.

### Why Limit Depth?

- **Audit complexity.** A chain of depth 5 means 5 signatures to verify and 5 issuers to reason about. Deeper chains become harder to audit and debug.
- **Trust dilution.** Each hop in the chain is a point where trust could be misplaced. The root trusts the primary agent. The primary agent trusts its sub-agent. Does the root trust the sub-agent's sub-agent's sub-agent? Maybe. Can a human reason about that trust chain? Probably not.
- **Verification cost.** Each level adds an Ed25519 verification (~70μs). At depth 5, that's ~350μs — negligible. At depth 50 (if you override the limit), it's still fast, but the audit problem is real.

### Recommendations

- **Depth 1–2:** Normal operation. Primary agent spawns task-specific workers.
- **Depth 3:** Orchestration patterns. An orchestrator spawns a planner, the planner spawns workers.
- **Depth 4–5:** Complex workflows. Consider whether the architecture could be flattened.
- **Depth > 5:** Override the default at your own risk. Document why.

---

## Clock Security

OVID expiry depends on the system clock. The `exp` claim is a Unix timestamp, and `verifyOvid()` compares it to `Date.now()`.

### Single-Machine Deployments

Most AI agents run on a single machine (laptop, Mac mini, CI runner). Clock skew is not an issue — there's only one clock.

### Distributed Deployments

If OVIDs are issued on one machine and verified on another, clock skew matters. A 30-second skew on a 5-minute TTL is significant.

Mitigations:
- **Use NTP.** All machines should sync to the same time source.
- **Add a clock skew tolerance** in your verification logic (OVID doesn't build this in — add a buffer when checking `expiresIn`).
- **Use conservative TTLs.** A 30-minute TTL absorbs more skew than a 5-minute one.

### Clock Manipulation

A compromised agent on the same machine could theoretically manipulate the system clock to extend an OVID's validity. This is an OS-level attack — if the attacker can change the system clock, they can do far worse. Mitigation is OS hardening, not OVID-level.

---

## Claim Visibility

OVIDs are **signed, not encrypted.** The JWT payload is base64url-encoded, which is encoding, not encryption. Anyone with the JWT string can decode the claims and read:

- The agent's role
- The agent's ID
- The full parent chain
- The issuer
- The agent's public key
- Issuance and expiry timestamps

### What This Means

- **Don't put secrets in claims.** No API keys, no passwords, no PII, no internal hostnames you want to keep private.
- **Role names are visible.** If your role taxonomy reveals sensitive organizational structure, consider using opaque role identifiers instead of descriptive names.
- **Parent chains reveal topology.** The chain shows who spawned whom. In sensitive environments, this delegation structure might itself be sensitive.

### If You Need Confidentiality

Use JWE (JSON Web Encryption) to wrap the OVID in an encrypted envelope. OVID doesn't implement this — it's a straightforward layer to add with the `jose` library if your deployment requires it.

---

## Threat Model

### Agents OVID Trusts

| Agent | Trust Assumption |
|-------|-----------------|
| Root agent (primary) | Fully trusted. Holds the root keypair. If compromised, everything is compromised. |
| Parent agent (any level) | Trusted to issue accurate role claims for its children. If a parent lies about a child's role, the OVID is "valid" but misleading. |

### Agents OVID Does NOT Trust

| Agent | Why |
|-------|-----|
| The sub-agent itself | OVID doesn't trust agents to self-report. The identity comes from the parent, not the child. |
| Sibling agents | One sub-agent can't forge another's OVID. Each has a unique keypair and a parent-signed credential. |
| External systems | OVID makes no assumptions about external systems. Verification requires the issuer's public key. |

### Attack Surface Summary

| Attack | OVID's Role | Mitigation |
|--------|-------------|------------|
| Sub-agent impersonation | **Prevents.** Signature verification proves identity. | — |
| Credential forging | **Prevents** (without key theft). Ed25519 signatures are unforgeable without the private key. | Protect private keys. |
| Key theft | **Does not prevent.** Stolen keys = forged OVIDs. | OS hardening, file permissions, key rotation. |
| Privilege escalation | **Does not prevent.** OVID has no scope/authorization. | Pair with Carapace/Cedar. |
| Prompt injection | **Does not prevent.** Agent behavior ≠ agent identity. | Content filtering, sandboxing. |
| Lifetime extension | **Prevents** (at issuance). Child can't outlive parent. | Short TTLs. |
| Clock manipulation | **Does not prevent.** Relies on system clock. | OS hardening, NTP. |

---

## Recommended Deployment Patterns

### Pattern 1: OVID + Carapace (Recommended)

The full stack. OVID provides identity, Carapace provides Cedar-based authorization with three-valued decisions.

```
Agent spawns sub-agent
  → createOvid() with role + TTL
  → Sub-agent passes X-OVID-Token to Carapace proxy
  → Carapace extracts claims → Cedar context
  → Cedar evaluates: role + parentChain + resource attributes
  → Three-valued decision: DENY / ALLOW (proven) / ALLOW (unproven)
  → Audit log: OVID JWT + decision + timestamp
```

**When to use:** Production deployments where you need both identity and access control.

### Pattern 2: OVID Standalone (Audit Trail)

OVID without a policy engine. Every sub-agent has verifiable identity, but nothing enforces authorization. The value is forensics — when something goes wrong, you know exactly who did it.

```
Agent spawns sub-agent
  → createOvid() with role + TTL
  → Sub-agent carries OVID but nothing checks it at runtime
  → If incident occurs: verify OVID, trace chain, identify responsible agent
```

**When to use:** Development, experimentation, or environments where you want to add identity before committing to a full policy engine.

### Pattern 3: OVID + Custom Enforcement

Use OVID's `verifyOvid()` in your own middleware to make authorization decisions. No Carapace required.

```typescript
const result = await verifyOvid(token, trustedKey);
if (!result.valid) throw new Error('Invalid identity');
if (result.role !== 'code-reviewer') throw new Error('Wrong role');
if (result.chain.length > 2) throw new Error('Too deep');
// Proceed with request
```

**When to use:** When you have your own authorization logic and just need the identity primitive.

---

<p align="center">
  <em>Security is a stack, not a layer. OVID is one layer. Build the rest.</em>
</p>
