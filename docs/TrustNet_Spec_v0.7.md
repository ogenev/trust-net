# TrustNet for OpenClaw Personal Agents — Local‑First Specification

**Document version:** 0.7 (Draft — OpenClaw‑first local direction)  
**Date:** 2026-02-18  
**Status:** Implementation spec update (Local‑First MVP: OpenClaw trust‑to‑act + receipts; Optional: local verifiable roots/proofs; Later: server/chain)

**Upgrades:** This document supersedes *TrustNet Spec v0.6* by re‑prioritizing Local Mode (personal agents) as the default MVP path and moving ERC‑8004 + RootRegistry anchoring to later phases.

---

## Table of Contents

1. Abstract  
2. What Changed vs v0.6  
3. Scope, Non‑goals, and Design Principles  
4. Threat Model and Trust Assumptions  
5. System Overview  
6. Identity and Discovery (Local‑First)  
7. Contexts (Agent Collaboration)  
8. Trust Signals and Evidence (Receipts‑First)  
9. Storage and Data Model (Local)  
10. Decision Rules (Trust‑to‑Act)  
11. OpenClaw Integration (Gateway Enforcement)  
12. User Journey and Adoption UX  
13. Packaging and Local Installation  
14. Interop and Upgrade Paths (Server/Chain Later)  
15. MVP Build Plan (Local‑First Phases)  
16. Appendices (Schemas and Config)

---

## 1. Abstract

OpenClaw personal agents increasingly behave like **operators**: they execute commands, modify files, message humans, and delegate tasks. The safety question becomes:

> **Should this agent be allowed to do this action right now — and can the user understand why?**

**TrustNet** is a *trust‑to‑act* layer for OpenClaw that provides:

- **Context‑scoped trust** (trust for messaging ≠ trust for code execution).
- **Decider‑relative trust** (no global reputation; each user/owner decides whose opinions matter).
- **Why‑by‑default** explainability (the exact edges used to decide).
- **Safe enforcement** (ALLOW / ASK / DENY) at the gateway boundary.

**Local‑First Direction (v0.7):**
- Default to **Local Mode**: decisions computed locally; no network required.
- Default identity is **local agent identity** (`agentRef`) rather than ERC‑8004 wallet identity.
- “Proofs/roots” become an **optional advanced mode** (local verifiable), not a mandatory MVP dependency.
- Server/chain modes remain compatible and are kept as upgrade paths.

---

## 2. What Changed vs v0.6

### 2.1 Strategic change

- **MVP priority flipped**: from “ERC‑8004 hybrid + RootRegistry anchoring” to **OpenClaw‑first Local Mode** (personal agents).
- **On‑chain anchoring is no longer required for MVP**. It becomes a later “portable/public” profile.

### 2.2 Architectural changes

- Introduce a **Local Trust Engine** (in the OpenClaw plugin/runtime) that can compute decisions directly from local `edges_latest` (no prover required).
- Add an **Agent Card** artifact for discovery and sharing (QR/link/contact share).
- Add **Trust Circles** (policy presets) as a first‑class UX primitive (Only me / My contacts / OpenClaw Verified / Custom).
- Add **Interaction Receipts** as the primary evidence primitive for personal agents (used for audit + trust suggestions).
- Make the Rust **indexer/root builder/prover** optional:
  - **Local‑Lite**: no indexer, no prover.
  - **Local‑Verifiable**: optional local root builder + prover sidecar for proofs/roots.
  - **Local‑Chain‑Sync**: indexer only for power users (not MVP).

### 2.3 Compatibility kept from v0.6

The following are retained conceptually, with minor adaptations:
- Context string format and `contextId = keccak256(contextString)`.
- Edge levels `{-2,-1,0,+1,+2}` with **hard veto** semantics for `-2`.
- Deterministic, explainable, monotonic **2‑hop** scoring (D→E→T) plus direct override (D→T).
- Optional Sparse Merkle Map commitments + proofs as a verifiable mode.

---

## 3. Scope, Non‑goals, and Design Principles

### 3.1 Scope (what v0.7 standardizes)

This spec standardizes:

- Local identity (`agentRef`) and discovery (Agent Cards).
- Context registry for agent collaboration.
- Trust edges and levels; direct overrides and veto.
- Local decision rule + thresholds mapping to ALLOW/ASK/DENY + constraints.
- OpenClaw enforcement flow (hook points, prompts, receipts).
- Receipt format and how receipts contribute to trust UX.
- Optional local verifiable roots/proofs profile (SMM + manifests) for audit portability.

### 3.2 Non‑goals (Local‑First MVP)

Local‑First MVP explicitly excludes:

- Mandatory on‑chain anchoring or RootRegistry cross‑checks.
- Mandatory ERC‑8004 ingestion and agentId→wallet binding.
- Token incentives, staking, slashing, or “global reputation”.
- ZK proofs.
- Automatic trust changes without user approval (the system may recommend, but the user confirms).

### 3.3 Design principles

1) **Local‑first**: safe and useful with no network access.  
2) **User‑controlled**: the user/owner is the decider by default; trust changes require explicit approval.  
3) **Context isolation**: trust never bleeds across contexts.  
4) **Explainability**: decisions return “why” edges and (optionally) receipt references.  
5) **Safe failure**: if enforcement or verification fails, default to ASK or DENY per risk tier.  
6) **Progressive hardening**: advanced modes (proofs/roots, server, chain) are optional upgrades that do not change the UX surface.

---

## 4. Threat Model and Trust Assumptions

### 4.1 Attacker capabilities (local‑first)

Assume attackers can:
- Create many fake agents (sybil).
- Attempt prompt injection to trick the user into granting trust.
- Attempt to impersonate an agent (spoof identity) if discovery is weak.
- Attempt to tamper with local storage if the machine is compromised.
- Attempt to social‑engineer the user to share a malicious Agent Card.

### 4.2 TrustNet posture

TrustNet is not a “truth oracle”. It is a **decision framework**:
- Trust edges are user‑entered or from trusted circles (decider‑relative).
- Enforcement occurs at the OpenClaw gateway boundary.
- Optional verifiable mode provides cryptographic audit material, but does not solve a fully compromised device.

### 4.3 What this MVP defends against

- Accidental high‑risk tool execution by unknown/untrusted agents.
- Silent escalation of capabilities without explicit user approval.
- Lack of accountability (“why did it run?”) via receipts.

---

## 5. System Overview

### 5.1 Roles (local‑first defaults)

- **Owner (O)**: the human user controlling the OpenClaw instance.
- **Decider (D)**: the principal that decides (defaults to Owner/O’s TrustNet instance).
- **Target (T)**: another agent identity being evaluated (remote or local).
- **Endorser (E)**: a principal whose ratings D chooses to count (contacts, OpenClaw verified program, org security, etc.).

### 5.2 Components

A Local‑First deployment includes:

1) **OpenClaw Gateway Enforcement**  
   - Maps tool calls → contexts  
   - Requests a TrustNet decision  
   - Enforces ALLOW/ASK/DENY + constraints  
2) **Local Trust Store**  
   - `edges_latest` (SQLite)  
   - receipts log (JSONL or SQLite)  
3) **Local Trust Engine**  
   - Deterministic decision computation from local edges  
   - “Why” explanations  

Optional components:

4) **Local Verifiable Engine (trustnetd)**  
   - Builds periodic roots/manifests  
   - Generates membership/non‑membership proofs  
5) **Import/Export Layer**  
   - Agent Cards  
   - Trust packs / endorsements bundles (signed)  

### 5.3 Deployment profiles (normative)

- **Profile L0 — Local‑Lite (MVP default)**  
  - No indexer, no prover  
  - Decisions computed directly from local `edges_latest`  
  - Receipts recorded locally  

- **Profile L1 — Local‑Verifiable (optional)**  
  - Adds local root builder + prover (sidecar)  
  - Same decisions, but can emit verifiable bundles for audit  

- **Profile S — Server Mode (later)**  
  - Shared indexer/root builder/API for teams/orgs  

- **Profile C — Chain/Portable Mode (later)**  
  - ERC‑8004 and/or on‑chain edge signals  
  - Root anchoring on-chain (RootRegistry)  

---

## 6. Identity and Discovery (Local‑First)

### 6.1 Keys

Local identity uses two keys:

- **OwnerKey**: represents the user/owner. Used to sign trust changes and optional exports.
- **AgentKey**: per agent instance key. Used to sign Agent Cards and optionally sign receipts if the agent itself is the actor.

Keys MUST be stored outside the model runtime (OS keychain / secure enclave / separate signer process).

### 6.2 PrincipalId (local)

In Local‑First mode, the actionable identity is:

- **agentRef**: `agentRef = sha256(agentPublicKey)` (32 bytes)

Define:
- `principalId = agentRef` (already 32 bytes)

### 6.3 Agent Card (discovery primitive)

An **Agent Card** is a signed JSON document used to share and verify agent identity.

Purposes:
- discovery (endpoints, capabilities)
- anti‑impersonation (signatures bind identity to metadata)
- UX (human‑readable agent profile)

**Normative fields**:
- `type = "openclaw.agentCard.v1"`
- `agentRef` (bytes32 hex)
- `displayName` (string)
- `endpoints` (array of URLs or A2A/MCP identifiers)
- `capabilities` (contexts supported, as context strings)
- `policyManifestHash` (optional bytes32)
- `issuedAt` (RFC3339 string)
- `signatures`:
  - `agentSig` (AgentKey signature)
  - `ownerSig` (OwnerKey signature)

Agent Cards SHOULD be shareable via:
- QR code
- deep link
- contact share file

### 6.4 Identity binding and rotation

- AgentKey rotation MUST update Agent Card and preserve `agentRef` only if public key remains the same.
- If public key changes, a new `agentRef` is created. The Owner MAY publish a **binding** record:
  - “old agentRef → new agentRef” signed by OwnerKey.
- Trust edges are keyed to `agentRef` (PrincipalId) and are not automatically transferred unless the user approves.

### 6.5 Optional wallet binding (later / optional)

If an agent also has a wallet identity:
- a wallet address MAY be added as an auxiliary identifier in the Agent Card
- binding MUST be proven by signature from the wallet or by an attestation signed by OwnerKey.

Wallet binding is NOT required for Local‑First MVP.

---

## 7. Contexts (Agent Collaboration)

### 7.1 Context string format

Canonical context strings MUST have the form:

`trustnet:ctx:<capability>:v<integer>`

`contextId = keccak256(utf8(contextString))`

### 7.2 OpenClaw‑first context registry (recommended)

Define a minimal set aligned with personal agent collaboration:

- `trustnet:ctx:agent-collab:messaging:v1`
- `trustnet:ctx:agent-collab:files:read:v1`
- `trustnet:ctx:agent-collab:files:write:v1`
- `trustnet:ctx:agent-collab:code-exec:v1`
- `trustnet:ctx:agent-collab:delegation:v1` (planning/acting on your behalf)
- `trustnet:ctx:agent-collab:data-share:v1`

A deployment MAY alias legacy contexts (e.g., `trustnet:ctx:code-exec:v1`) to the new set, but the user‑facing UX SHOULD use the agent‑collab names.

### 7.3 Tool → context mapping (OpenClaw)

The OpenClaw integration MUST maintain a deterministic mapping from tool calls to contexts, e.g.:

- `exec` → `trustnet:ctx:agent-collab:code-exec:v1` (high risk)
- `fs.read` → `trustnet:ctx:agent-collab:files:read:v1` (medium)
- `fs.write` → `trustnet:ctx:agent-collab:files:write:v1` (high/medium depending on path)
- `messaging.send` → `trustnet:ctx:agent-collab:messaging:v1` (medium)
- `delegate.*` → `trustnet:ctx:agent-collab:delegation:v1` (high)

---

## 8. Trust Signals and Evidence (Receipts‑First)

### 8.1 Canonical trust edge

TrustNet’s core fact remains an edge:

`(rater, target, contextId) -> EdgeValue`

Where:
- `rater` is a PrincipalId (agentRef in local mode)
- `target` is a PrincipalId (agentRef)
- `contextId` is bytes32
- `EdgeValue.level ∈ {-2,-1,0,+1,+2}`

### 8.2 Levels and semantics

- `+2` strong trust (allow with minimal friction)
- `+1` trust (usually ASK→ALLOW depending on risk)
- `0` unknown/neutral
- `-1` distrust (usually ASK/DENY)
- `-2` veto (hard deny)

### 8.3 Trust Circles (policy primitive)

A **Trust Circle** is a UX+policy preset that determines which raters/endorsers count:

- **Only me**: count only direct edges from the Owner/Decider.
- **My contacts**: count ratings from contacts the user explicitly approved as endorsers.
- **OpenClaw Verified** (optional): count ratings from an OpenClaw verification principal.
- **Custom**: user selects endorsers.

Internally, Trust Circles are implemented as edges:
- `D→E` edges represent endorsers the decider counts.

### 8.4 Evidence: Interaction Receipts

In Local‑First mode, the primary evidence is **Interaction Receipts** emitted by OpenClaw on tool calls.

Receipts SHOULD include:
- `receiptId` (uuid)
- timestamp
- `targetAgentRef`
- `contextId`
- tool name
- hashes of args/result (no raw secrets)
- decision (allow/ask/deny)
- whether user approved
- optional constraints applied
- optional “why edges” snapshot
- signature by OwnerKey (recommended)

Receipts provide:
- audit history (“what happened?”)
- trust suggestions (“this agent succeeded 10 times without incident”)
- evidence commitments (in Local‑Verifiable mode)

### 8.5 Evidence gating (optional per context)

A policy MAY require evidence for positive trust in high‑risk contexts:

- If `requiresReceipts == true` for a context, then:
  - positive indirect trust (`E→T > 0`) SHOULD be considered only if it references receipt evidence (via `evidenceHash` or receipt counters)
  - direct `D→T` may still be allowed as user override (configurable)

In Local‑Lite mode, evidence gating is implemented using receipt counts and timestamps (not cryptographic).
In Local‑Verifiable mode, evidence may be committed via hashes and roots.

### 8.6 Import/export of trust

Local mode SHOULD support:
- exporting a signed “trust pack” (set of edges) for backup/migration
- importing a trust pack with explicit user confirmation

The MVP SHOULD NOT automatically merge third‑party trust packs into high‑risk contexts without user confirmation.

---

## 9. Storage and Data Model (Local)

### 9.1 Tables (recommended)

- `edges_latest`  
  Key: `(rater, target, contextId)`  
  Value: `{ level, updatedAt, evidenceRef? }`

- `edges_raw` (optional)  
  Append‑only log of changes for audit and undo.

- `receipts`  
  Append‑only tool receipts.

- `agents`  
  Stores imported Agent Cards and local metadata.

### 9.2 Latest‑wins reduction

Local mode uses simple latest‑wins:
- the newest update (by local monotonic timestamp) wins for each edge key.

---

## 10. Decision Rules (Trust‑to‑Act)

### 10.1 Inputs

For a decision on `(D, T, contextId)` gather:

- direct edge `D→T` (default 0 if missing)
- choose an endorser `E` (if any) based on `D→E` and `E→T` edges

### 10.2 Hard veto rule (normative)

If `D→T == -2` in the context, decision MUST be **DENY**.

### 10.3 Recommended monotonic scoring rule (default)

Let:
- `lDT = level(D→T)` (0 if absent)
- `lDE = level(D→E)` (0 if absent)
- `lET = level(E→T)` (0 if absent)

Compute:
1) if `lDT == -2`: DENY
2) `base = 0`
3) if `lDE > 0 AND lET > 0`: `base = min(lDE, lET)`
4) if `lDT > 0`: `score = max(base, lDT)` else `score = base`

### 10.4 Endorser selection (deterministic)

Eligible endorsers are those with `lDE > 0`.

Choose E maximizing `min(lDE, lET)`. Tie‑break by smallest `keccak256(E)` or lexical `agentRef`.

### 10.5 Threshold mapping

Per context policy defines:
- `allowThreshold` (default 2 for high‑risk; 1 for low‑risk)
- `askThreshold` (default 1)

Mapping:
- score ≥ allowThreshold → **ALLOW**
- score ≥ askThreshold → **ASK**
- else → **DENY**

### 10.6 Constraints

Decisions SHOULD include constraints, e.g.:
- code exec: allowlisted commands, working dir, ttlSeconds
- file write: path allowlist, size caps
- messaging: destinations allowlist, ttlSeconds

Constraints are enforced by OpenClaw.

### 10.7 Safe failure modes

If TrustNet cannot compute a decision (DB error, corrupted state):
- high risk contexts default to **ASK** or **DENY** per config (recommended: ASK for consumer, DENY for enterprise)
- low risk contexts default to ASK

---

## 11. OpenClaw Integration (Gateway Enforcement)

### 11.1 Enforcement point

TrustNet must run at the gateway boundary:
- before a tool executes
- after a tool executes (receipt)

Whether implemented as a plugin or core feature, the required behavior is identical.

### 11.2 Runtime flow (normative)

On tool call attempt:

1) Map tool call → `(contextId, riskTier, constraintsTemplate)`
2) Identify target agent principal (`agentRef`) from the interaction/session
3) Compute decision locally (Profile L0) OR request from local sidecar (Profile L1)
4) Enforce:
   - ALLOW → run tool under constraints
   - ASK → show user prompt; if approved, run under constraints
   - DENY → block
5) Emit receipt (always for high‑risk, configurable for others)

### 11.3 User prompt (ASK)

ASK UI SHOULD support:
- Allow once
- Allow for N minutes (TTL)
- Always allow for this context (writes a `D→T` edge)
- Deny once
- Block (writes `D→T = -2`)

Prompt SHOULD show:
- agent identity (from Agent Card)
- context and tool summary
- “Why” (best explanation available)

### 11.4 Rating commands (optional)

Provide commands like:
- `/trustnet trust <agent> <context> [once|always]`
- `/trustnet block <agent> <context>`
- `/trustnet endorse <endorser> <context> +2`
- `/trustnet status <agent>`

LLM may suggest commands, but **user must confirm** before the plugin writes edges.

---

## 12. User Journey and Adoption UX

### 12.1 First run

- Create OwnerKey + AgentKey
- Create user’s own Agent Card
- Default policy:
  - Unknown agent + high risk → ASK
  - Unknown agent + medium risk → ASK
  - Unknown agent + low risk → ASK or ALLOW with strict constraints (configurable)

### 12.2 Adding another agent (Agent Card exchange)

- Import Agent Card (QR/link)
- Verify signatures
- Show agent profile
- Default to “Require approval”

### 12.3 First interaction

- Tool request triggers ASK prompt
- User chooses allow once / always / block
- Receipt recorded

### 12.4 Ongoing

- TrustNet shows:
  - per‑context trust badge (Blocked / Untrusted / Unknown / Trusted / Verified*)
  - recent receipts
  - suggested trust upgrades/downgrades (never automatic)

(*) “Verified” is a UX label meaning “high trust + evidence present,” not a global truth claim.

---

## 13. Packaging and Local Installation

### 13.1 Local‑Lite (no Rust required)

In Profile L0:
- Plugin implements scoring and storage in TypeScript/Node
- Uses SQLite for `edges_latest` + receipts

### 13.2 Optional Rust sidecar (Local‑Verifiable)

If Local‑Verifiable mode is enabled:
- plugin spawns `trustnetd` locally (`127.0.0.1`)
- plugin calls localhost API for:
  - `GET /v1/decision`
  - optionally `GET /v1/root` and `GET /v1/proof`
- proofs/roots are stored locally for audit/export

**Installation requirement:** users MUST NOT need to install Rust.
Distribution MUST be via:
- bundled prebuilt binaries, or
- platform‑specific npm optional dependencies.

### 13.3 Indexer (Local‑Chain‑Sync) — NOT MVP

If chain sync is enabled:
- run an indexer worker with explicit RPC config
- this is an advanced “developer mode” only

---

## 14. Interop and Upgrade Paths (Server/Chain Later)

### 14.1 Server mode

Teams/orgs may want:
- shared policy
- centralized receipts
- admin controls

Server mode can reuse:
- the same edge model
- the same decision rule
- optional roots/proofs for verifiability

### 14.2 Chain/portable mode

Chain mode can later introduce:
- ERC‑8004 ingestion
- public stamping via ResponseAppended
- root anchoring via RootRegistry

Local‑First MVP does not depend on this.

### 14.3 Migration

A local deployment SHOULD support:
- export/import of edges_latest
- export/import of Agent Cards
- export/import of receipts (redacted/hashes only)

---

## 15. MVP Build Plan (Local‑First Phases)

### Phase L0 — Local‑Lite TrustNet (must ship)
Deliver:
- local SQLite store
- local scoring + decisions
- OpenClaw enforcement (ALLOW/ASK/DENY)
- receipts

### Phase L1 — Agent Cards + Trust Circles
Deliver:
- Agent Card exchange/import/verify
- Trust circles UX (Only me / My contacts / Verified / Custom)
- per-context badges

### Phase L2 — Receipts UX + Trust suggestions
Deliver:
- timeline of receipts
- “upgrade trust?” suggestions (user-approved)
- incident report workflow → block/veto

### Phase L3 — Local‑Verifiable (optional)
Deliver:
- local trustnetd
- local roots/proofs + manifests
- exportable audit bundle

### Phase S — Server (later)
Deliver:
- shared TrustNet service for teams

### Phase C — Chain/portable (later)
Deliver:
- ERC‑8004 + RootRegistry anchored profile

---

## 16. Appendices

### Appendix A — Agent Card schema (OpenClaw)

```json
{
  "type": "openclaw.agentCard.v1",
  "agentRef": "0x<32 bytes>",
  "displayName": "Alice’s Agent",
  "endpoints": ["a2a://...", "https://..."],
  "capabilities": [
    "trustnet:ctx:agent-collab:messaging:v1",
    "trustnet:ctx:agent-collab:code-exec:v1"
  ],
  "policyManifestHash": "0x<32 bytes optional>",
  "issuedAt": "2026-02-18T00:00:00Z",
  "signatures": {
    "agentSig": "base64(...)",
    "ownerSig": "base64(...)"
  }
}
```

### Appendix B — Edge record (local)

```json
{
  "type": "trustnet.edge.v1",
  "rater": "0x<agentRef 32 bytes>",
  "target": "0x<agentRef 32 bytes>",
  "contextId": "0x<32 bytes>",
  "level": 1,
  "updatedAt": 1739836800,
  "evidenceRef": {
    "kind": "receiptCount",
    "count": 12,
    "since": 1737000000
  }
}
```

### Appendix C — Interaction Receipt (local)

```json
{
  "type": "trustnet.receipt.v1",
  "receiptId": "uuid",
  "createdAt": "2026-02-18T12:34:56Z",
  "target": "0x<agentRef>",
  "contextId": "0x<32 bytes>",
  "tool": "exec",
  "argsHash": "0x<32 bytes>",
  "resultHash": "0x<32 bytes>",
  "decision": "ask",
  "userApproved": true,
  "constraints": { "ttlSeconds": 60 },
  "why": {
    "edgeDT": { "level": 0 },
    "edgeDE": { "level": 0 },
    "edgeET": { "level": 0 }
  },
  "ownerSig": "base64(...)"
}
```

### Appendix D — Plugin config (example)

```json5
{
  "trustnet": {
    "mode": "local-lite",  // local-lite | local-verifiable
    "dbPath": "./.trustnet/trustnet.sqlite",
    "riskDefaults": {
      "high": { "fail": "ask" },
      "medium": { "fail": "ask" },
      "low": { "fail": "ask" }
    },
    "thresholds": {
      "trustnet:ctx:agent-collab:code-exec:v1": { "allow": 2, "ask": 1 },
      "trustnet:ctx:agent-collab:files:write:v1": { "allow": 2, "ask": 1 },
      "trustnet:ctx:agent-collab:messaging:v1": { "allow": 1, "ask": 1 }
    },
    "trustCircles": {
      "default": "onlyMe",
      "endorsers": {
        "myContacts": ["0x<agentRef of contact endorser>"],
        "openclawVerified": ["0x<agentRef of OpenClaw verifier>"]
      }
    },
    "sidecar": {
      "enabled": false,
      "apiBaseUrl": "http://127.0.0.1:8088",
      "binaryPath": "./bin/trustnetd"
    }
  }
}
```

---

**End of document.**
