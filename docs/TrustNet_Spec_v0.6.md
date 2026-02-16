# TrustNet for AI Agents — Unified Architecture, Specification, and MVP Plan

**Document version:** 0.6 (Draft)  
**Date:** 2026-02-03  
**Status:** Implementation-spec draft (Initial MVP: OpenClaw + code-exec on ERC‑8004 hybrid; Later: payments + non‑ERC‑8004 agents)
**Derived from:** TrustNet for OpenClaw Agents v0.3 (2026-01-30) and TrustNet on ERC‑8004 v1.0 (2025-10-26)  

---

## Table of Contents

1. Abstract  
2. Scope, Non-goals, and Design Principles  
3. Threat Model and Trust Assumptions  
4. System Overview  
5. Core Concepts and Terminology  
6. Identity and Registration  
7. Contexts (Capability Namespaces)  
8. Trust Signals and Evidence  
9. Indexing, Normalization, and Latest-Wins Reduction  
10. Commitment: Graph Root + Root Manifest  
11. Proofs (Membership, Non-membership, Bundles, Compression)  
12. Decision Rules (Trust-to-Act)  
13. Gateway Integration (Generic)  
14. Integration with OpenClaw  
15. On-chain Contracts (RootRegistry Required in Initial MVP Release)
16. Off-chain Services (Server Mode)  
17. MVP Build Plan (Ship + Verify)  
18. Verification Plan (Correctness, Security, Performance)  
19. Appendices (Schemas, DB tables, Test vectors)

---

## 1. Abstract

AI agents are shifting from “chat” to **operators**: they run commands, modify data, message humans, and can trigger payments.
The safety question becomes:

> **Should this agent be allowed to do this action _right now_ — and can we prove why?**

**TrustNet** is an auditable “trust-to-act” layer for agent gateways and (optionally) smart contracts:

- **Context-scoped trust** (trust for payments ≠ trust for code execution).
- **Decider-relative trust** (no global score; each gateway chooses whose ratings count).
- **Verifiable proofs** (tiny bundles verifiable against a committed `graphRoot`).
- **Why-by-default** explainability (the exact edges used to allow/ask/deny).

TrustNet is designed to work in three deployment modes:

1) **Local mode** (single machine; no network required)  
2) **Server mode** (org/shared; proofs + roots served by a TrustNet service)  
3) **Chain mode** (signals and/or root anchored on-chain; portable across orgs)

This document is an implementation-spec to build an MVP, ship it, and verify the idea end-to-end.

---

## 2. Scope, Non-goals, and Design Principles

### 2.1 Scope (what this spec standardizes)

This spec standardizes:

- The **canonical rating edge** model and levels.
- How to derive **context identifiers**.
- How to normalize **identities** into a common `PrincipalId`.
- How to ingest ratings from multiple **signal channels**.
- How to reduce signals to **latest-wins** edges.
- How to commit the edge set into a **Sparse Merkle Map** root (`graphRoot`) with reproducible manifests.
- Proof formats for **membership**, **non-membership**, and **decision bundles**.
- A **deterministic decision rule** and policy thresholds mapping to **ALLOW / ASK / DENY**.
- The enforcement flow for gateways, including an **OpenClaw plugin** reference integration.

### 2.2 Non-goals (MVP)

TrustNet MVP intentionally excludes:

- Token incentives, staking, or slashing.
- Global “universal reputation” or leaderboards.
- ZK privacy proofs (future-ready, not MVP).
- Fully trustless on-chain indexing (the indexer/root builder is off-chain, but reproducible).
- Initial-MVP payment execution enforcement and payment policy rollout (deferred to a later phase after OpenClaw `code-exec` launch).
- Native support for **targets that are not ERC‑8004 registered** (post-MVP; see §6.4 and Milestone 5 in §17).
- A non‑ERC‑8004 “wallet feedback + response” on-chain standard (post-MVP; see §8.7).
- Non-EVM identities and cross-chain identity binding (post-MVP).

### 2.3 Design principles

1) **Deterministic and reproducible**: independent parties can recompute roots from public inputs (or signed logs) using a published Root Manifest.  
2) **Decider-relative**: there is no global score; each gateway/contract is a decider and chooses anchors/endorsers it counts.  
3) **Context isolation**: ratings never bleed across capability namespaces.  
4) **Explainability first**: decisions always return “why edges.”  
5) **Safe failure modes**: if verification fails, default to ASK or DENY depending on risk tier.  
6) **Minimal cryptographic surface**: hashes + signatures + Merkle proofs, no exotic crypto required.


### 2.4 MVP focus and rollout plan

This spec is intentionally **ERC‑8004-first** with an OpenClaw-first MVP sequence:

- **Phase A0 (initial MVP):** OpenClaw gateway integration + `trustnet:ctx:code-exec:v1` enforcement. Targets are **ERC‑8004 registered agents** resolved to an actionable `agentWallet`. Hybrid verification uses ERC‑8004 `NewFeedback` + `ResponseAppended`, and trust-to-act uses compact `D→E→T` edges committed in the Sparse Merkle Map.
- **Phase A1 (later phase):** payments contexts and optional on-chain payment enforcement modules.
- **Phase B (post-MVP):** add support for targets that are **not** ERC‑8004 registered (wallet-only agents and other identity systems) by introducing alternative feedback/stamp channels and binding strategies (see §6.4 and §8.7).

This keeps the MVP compatible with existing ERC‑8004 agents while leaving a clean path to support non‑ERC‑8004 agents later.


---

## 3. Threat Model and Trust Assumptions

### 3.1 Attacker capabilities

Assume attackers can:

- Create many fake identities (sybil).
- Publish misleading positive ratings if your policy accepts them.
- Attempt prompt injection to trick an agent/gateway into changing policy or publishing ratings.
- Attempt to serve false proofs/roots via a compromised API.
- Exploit chain reorganizations if indexing is naïve.
- Attempt replay of old proofs or old roots.

### 3.2 TrustNet’s posture

TrustNet is **trust-minimized**, not “truth from nowhere”:

- It treats ratings as **public or signed signals**, then aggregates them deterministically.
- A decider’s policy defines whose ratings matter.
- Every allow/deny is backed by **verifiable** proof material (or local-only state in local mode).

### 3.3 What TrustNet defends against (when configured correctly)

- Accidental tool execution by untrusted agents (gateway enforcement).
- Silent policy drift (policy manifests + receipts + root manifests).
- API tampering (proof verification against a root anchored on-chain or signed by a trusted publisher).
- Reputation spoofing outside your trust anchors (decider-relative filtering).

### 3.4 What TrustNet does not defend against by itself

- Malicious endorsers that the decider chooses to trust.
- Compromised gateways or compromised operator machines.
- Data exfiltration via allowed tools (must be handled by tool policy and sandboxing).

---

## 4. System Overview

### 4.1 Planes

- **Identity plane**: how agents/deciders/endorsers are represented and discovered.
- **Signals plane**: how ratings, feedback, and evidence are emitted and ingested.
- **Decision plane**: how a gateway decides ALLOW/ASK/DENY for a specific action.

### 4.2 Components

A full TrustNet deployment may include:

1) **Gateway plugin / policy enforcement point**  
2) **Signals store** (`edges_raw`, `edges_latest`)  
3) **Indexer** (ingests chain logs and/or private logs)  
4) **Root builder** (builds `graphRoot` epochs + manifests)  
5) **Proof/Decision API** (serves proofs and explainable decisions)  
6) **On-chain root anchor** (RootRegistry; required for the initial MVP release profile)
7) Optional **on-chain verifier** (TrustPathVerifier / library)

### 4.3 Deployment modes

#### Local mode
- Runs entirely on one machine.
- Ratings stored locally; decisions computed locally.
- Optionally still produces a root + proofs for consistency testing.

#### Server mode (org/shared)
- A TrustNet service hosts the indexer, root builder, and proof API.
- Gateways verify proofs locally against the published root.
- Dev-only profile: roots MAY be authenticated by a configured root publisher signature.
- Initial MVP release profile: roots MUST be anchored on-chain in RootRegistry, and gateways MUST cross-check `(epoch, graphRoot, manifestHash)` against that anchor before enforcing high-risk actions.

#### Chain mode (portable/public)
- Ratings are emitted on-chain (e.g., `EdgeRated`) and/or via ERC‑8004 `NewFeedback`.
- A root publisher builds roots from chain logs and publishes them to RootRegistry.
- Gateways verify proofs against RootRegistry’s latest root.

---

## 5. Core Concepts and Terminology

### 5.1 Roles

- **Decider (D)**: the policy anchor (a gateway org, SecOps, FinOps, DAO council, etc.) that decides whether a target can act.
- **Endorser (E)**: a trust anchor whose opinion the decider counts (e.g., a marketplace, auditor, validator network, or senior operator).
- **Verifier (V)**: a principal that publishes **public verification stamps** about underlying interactions (payments, jobs, validations), typically by appending responses to feedback in a hybrid model. A verifier MAY also publish derived trust edges. In many deployments the same actor is both **E** and **V**.
- **Target (T)**: the actionable identity being gated (see §6: ActorPrincipalId vs SubjectId).
- **Client (C)**: a counterparty who interacts with the target and may leave feedback. Clients are generally **not** treated as endorsers unless explicitly trusted by a decider.
- **Rater**: any principal that emits a rating edge (often D or E/V, but not required).

### 5.2 Rating levels

A **rating level** is an integer:

`level ∈ { -2, -1, 0, +1, +2 }`

Normative semantics:

- `+2` = strong trust (allow high-risk actions if policy permits)
- `+1` = trust (allow medium risk or allow with tighter constraints)
- `0`  = neutral / unknown (default)
- `-1` = distrust (should lead to ASK or DENY depending on context)
- `-2` = **veto** (hard deny in the relevant context)

> **Important:** In this unified spec, `-2` is reserved for veto semantics: if a decider has a direct `D→T = -2` in a context, the decision MUST be `DENY` regardless of other endorsements.

### 5.3 Contexts

A **context** is a capability namespace. Trust is never mixed across contexts.

Examples:

- `trustnet:ctx:code-exec:v1`
- `trustnet:ctx:writes:v1`
- `trustnet:ctx:messaging:v1`
- `trustnet:ctx:payments:v1` (later-phase / optional)

Contexts are represented on-chain and in proofs as `bytes32 contextId` (see §7).

### 5.4 Canonical edge

TrustNet’s core fact is an edge:

`(rater, target, contextId) -> EdgeValue`

where `EdgeValue` contains at minimum `level`, and SHOULD contain `updatedAt` and (optional) `evidenceHash` (§10.2).

---

## 6. Identity and Registration

TrustNet MVP is **ERC‑8004-first**:

- Targets are expected to be **ERC‑8004 registered agents**.
- Trust-to-act decisions are made against the agent’s actionable **`agentWallet`** (an EVM address) resolved from the ERC‑8004 Identity Registry at the indexed block height.
- Hybrid verification uses ERC‑8004 `NewFeedback` (claims) + `ResponseAppended` (public stamps).

Support for non‑ERC‑8004 targets (wallet-only agents and other identity schemes) is deferred to post‑MVP (see §6.4 and §8.7).

### 6.1 PrincipalId and SubjectId

TrustNet distinguishes two identity notions:

- `ActorPrincipalId` (also referred to as `PrincipalId` in this spec): a **32-byte** (`bytes32`) identifier for an **actionable signing authority** (the key/wallet that can actually authorize tool calls, payments, or on-chain transactions). `ActorPrincipalId` is what appears in TrustNet edges and Merkle keys.
- `SubjectId`: a **32-byte** (`bytes32`) identifier for a **stable subject identity** (an “agent identity record”) that may survive key rotation or endpoint changes. `SubjectId` is used for discovery and evidence linkage, but MUST NOT be used directly for action authorization unless it is bound to an `ActorPrincipalId`.

#### 6.1.1 `PrincipalId` / `ActorPrincipalId` encoding rules

- **EVM address** (`0x` + 20 bytes):
  - `principalId = bytes32(leftPad20(address))` (i.e., 12 zero bytes + 20 address bytes).

**MVP note:** Phase A supports EVM-address principals only for trust-to-act. Other principal encodings are post-MVP.
- **Local AgentRef** (`sha256(agentPublicKey)`) (post-MVP extension):
  - `principalId = agentRef` (already 32 bytes).

#### 6.1.2 `SubjectId` encoding rules (recommended)

- **ERC‑8004 subject** (stable across wallet rotation):
  - `subjectId = keccak256(abi.encodePacked(uint256(chainId), address(erc8004IdentityRegistry), uint256(agentId)))`
- **Other subject schemes** (optional):
  - `subjectId = keccak256(utf8("did:" + didString))` (if you adopt DIDs later)

#### 6.1.3 Binding rule (critical)

- Gateways and smart contracts MUST make allow/ask/deny decisions against an **`ActorPrincipalId`**.
- If a signal is expressed in terms of a **`SubjectId`** (e.g., ERC‑8004 `agentId`), an indexer/root builder MUST define a deterministic **binding strategy** to map subject → actor.

**MVP binding strategy (recommended):** resolve `agentId → agentWallet` at the indexed block height, and use that resolved wallet as the `target` `PrincipalId` for trust-to-act decisions.

> Rationale: actions at gateways and contracts are typically authorized by a signing key/wallet, not by a token id.

### 6.2 Local-first identity (Mode L) (post-MVP)

**Post-MVP note:** this section is a planned extension for non‑ERC‑8004 targets and local deployments. The Phase A MVP does not require local-first identities.

Local-first mode is for gateways like OpenClaw running agents on a machine.

**Keys**
- `AgentKey`: per-agent signing key.
- `OwnerKey`: user/org key controlling policy + rating publication approvals.

**AgentRef**
- `agentRef = sha256(agentPublicKey)` (32 bytes).
- `principalId = agentRef`.

**AgentDescriptor (signed JSON)**
An AgentDescriptor binds:
- `agentRef`
- agent endpoint(s) (OpenClaw gateway endpoint, A2A card, MCP, etc.)
- declared contexts/capabilities
- `policyManifestHash` (hash of tool policy + approvals config)
- signatures by AgentKey and OwnerKey

Purpose:
- discovery
- ownership proof
- auditable linkage between “this agent” and “this tool policy”

### 6.3 Portable identity (Mode P) via ERC‑8004 (MVP)

**MVP requirement:** targets MUST be resolvable via an ERC‑8004 Identity Registry to an actionable `agentWallet`.

If using ERC‑8004 identity:

- Use the ERC‑8004 identity registry to resolve:
  - `agentId` → `agentWallet` (or equivalent signing authority)
- The gateway uses the resolved `agentWallet` as the actionable identity.

### 6.4 Post-MVP: Non‑ERC‑8004 targets (wallet-only agents and other identity systems)

Phase B expands TrustNet beyond ERC‑8004 registered agents. The key requirements are:

1) **Actionable identity stays the same:** trust-to-act is always evaluated against an `ActorPrincipalId` (typically an EVM address).
2) **Stable discovery identity becomes optional:** if an agent is not ERC‑8004 registered, you can still gate it by wallet address, but you may want a stable `SubjectId` for discovery, metadata, and key rotation.

Recommended Phase B approach (in increasing complexity):

- **Wallet-only target (minimal):** treat the agent’s EVM address as both the actionable `ActorPrincipalId` and the discovery identity. This enables `D→E→T` decisions immediately, but does not provide rich metadata or portable “agent profiles”.
- **Signed Agent Descriptor:** allow a wallet-only agent to publish a signed JSON descriptor (endpoints, capabilities, metadata URI) and define `subjectId = keccak256(descriptorHash)` with a binding `subjectId ↔ actorWallet` proven by signature.
- **External identity systems:** support DID/VC-based agent identities by introducing a subject-to-actor binding strategy analogous to the ERC‑8004 `agentWalletAtBlock` policy.

**Hybrid caveat:** ERC‑8004 provides `ResponseAppended` as a standardized public stamping mechanism. For non‑ERC‑8004 targets, Phase B must introduce an alternative stamping channel (see §8.7).

### 6.5 Key rotation and revocation

TrustNet MUST support:

- **Key rotation:** OwnerKey can rotate AgentKey and update AgentDescriptor.
- **Revocation / veto:** publish a direct edge `D→T = -2` in a context.
- **Local kill-switch:** disabling the plugin must immediately stop enforcement decisions and stop emitting signals.

---

## 7. Contexts (Capability Namespaces)

### 7.1 Context string format

Canonical context strings MUST have the form:

`trustnet:ctx:<capability>:v<integer>`

Examples:
- `trustnet:ctx:code-exec:v1`
- `trustnet:ctx:payments:v1` (later-phase / optional in initial MVP)

### 7.2 Deriving contextId

`contextId = keccak256( utf8(contextString) )`

### 7.3 Context registry (recommended)

A TrustNet deployment SHOULD publish a **Context Registry**:

- A JSON list of canonical context strings (and optional human docs).
- `contextRegistryHash = keccak256(canonical_json_bytes)`.

The Root Manifest SHOULD include `contextRegistryHash` so verifiers know exactly which contexts exist and how they hash.

---

## 8. Trust Signals and Evidence

TrustNet ingests signals from one or more channels into canonical records.

A key hybrid design goal is:

- **Open publication** (anyone can write feedback), and
- **Public verification stamps** (verifiers append responses that mark feedback as verified/spam/refunded/etc.),
- while **trust-to-act** decisions are still made from a compact set of committed trust edges.

### 8.1 Canonical normalized records

#### 8.1.1 Canonical `RatingEvent` (trust edge)

A TrustNet **edge** is normalized into:

- `rater: PrincipalId` (actionable signer)
- `target: PrincipalId` (actionable signer)
- `contextId: bytes32`
- `level: int8 (-2..+2)`
- `evidenceHash: bytes32 (optional, default 0)`
- `evidenceUri: string (optional, not committed)`
- `source: enum { EDGE_RATED, ERC8004_TRUST_EDGE, PRIVATE_LOG }`
- `observedAt: uint64` (monotonic-ish ordering key; see §9.3)
- `sig: bytes (required for PRIVATE_LOG; optional otherwise)`

> Note: `evidenceUri` is a convenience pointer; only `evidenceHash` is committed (if present).

#### 8.1.2 Canonical `FeedbackSignal` (ERC‑8004 NewFeedback) (hybrid evidence input)

In hybrid deployments, ERC‑8004 `NewFeedback` items are often **inputs** to verification and scoring rather than direct trust edges.

A normalized feedback record SHOULD include:

- `chainId`
- `erc8004Reputation: address`
- `erc8004Identity: address (optional but recommended)`
- `agentId: uint256`
- `clientAddress: address`
- `feedbackIndex: uint256`
- `value, valueDecimals`
- `tag1, tag2, endpoint: string`
- `feedbackURI: string`
- `feedbackHash: bytes32`
- `observedAt` (chain ordering tuple; §9.3)
- derived (optional): `subjectId` (see §6.1.2)

Feedback signals are **not** committed into the TrustNet Sparse Merkle Map unless they are re-expressed as `RatingEvent` edges (see §8.3).

#### 8.1.3 Canonical `FeedbackResponseSignal` (ERC‑8004 ResponseAppended) (hybrid verification stamp)

In hybrid deployments, ERC‑8004 `ResponseAppended` records are the canonical **public verification stamps**.

A normalized response record SHOULD include:

- `chainId`
- `erc8004Reputation: address`
- `agentId: uint256`
- `clientAddress: address`
- `feedbackIndex: uint256`
- `responder: address`
- `responseURI: string`
- `responseHash: bytes32`
- `observedAt` (chain ordering tuple; §9.3)

### 8.2 Channel A: TrustNet-native on-chain event (EdgeRated)

A minimal on-chain trust-edge signal:

```solidity
event EdgeRated(
  address indexed rater,
  address indexed target,
  int8    level,        // -2..+2
  bytes32 indexed contextId
);
```

This is ideal for:
- curator edges (`D→E`)
- direct overrides (`D→T`)
- emergency veto (`D→T = -2`)

Evidence:
- For MVP, evidence MAY be off-chain.
- For high-stakes contexts, prefer emitting edges via ERC‑8004 (Channel B1) or PRIVATE_LOG so `evidenceHash` can be committed.

### 8.3 Channel B1: ERC‑8004 trust edges (NewFeedback → RatingEvent)

ERC‑8004 can be used to publish TrustNet edges via `giveFeedback(...)`, by using dedicated tags and endpoint values.

When ingesting ERC‑8004 `NewFeedback` as a **TrustNet edge**, TrustNet MUST apply a deterministic mapping into a `RatingEvent`.

**Ingestion guard (normative):**
- `endpoint == "trustnet"` AND
- `tag2 == "trustnet:v1"`

> Note: In ERC‑8004, `tag1` and `tag2` are **strings**. Do not hash them for comparison.

**Context parsing (normative):**
- If `tag1` matches the canonical context string format (see §7.1), then:
  - `contextId = keccak256(utf8(tag1))`
- Else if `tag1` is a hex string of length 66 (`0x` + 64 hex chars), then:
  - `contextId = bytes32(tag1)` (direct encoding)
- Else: reject as invalid TrustNet edge input.

**Target resolution (MVP recommendation):**
- Resolve `agentId → agentWallet` using the ERC‑8004 identity registry at the indexed block height.
- Set `target = principalId(agentWallet)`.

If an ERC‑8004 identity registry is not configured, deployments MAY fall back to a `SubjectId`-only mode, but such edges are not directly usable for **trust-to-act** gating without an additional binding proof (non-MVP).

**Mapping:**
- `rater = principalId(clientAddress)`
- `target = principalId(agentWallet)` (preferred; see above)
- `level = quantize(value / 10^valueDecimals)` (see Quantization below)
- `evidenceUri/evidenceHash` come from `feedbackURI/feedbackHash` (if present)
- `source = ERC8004_TRUST_EDGE`

**Quantization (default buckets):**
Interpret `score = value / 10^valueDecimals` as a number in `[0,100]` and map:

- 80..100 → +2
- 60..79  → +1
- 40..59  →  0
- 20..39  → -1
- 0..19   → -2

A deployment MAY choose a different quantizer, but it MUST be included in the Root Manifest and MUST be versioned.

### 8.4 Channel B2: ERC‑8004 verification stamps (ResponseAppended) (hybrid)

ERC‑8004 allows anyone to append responses to feedback via `appendResponse(...)`, which emits `ResponseAppended(...)`.

In TrustNet hybrid mode:

- `NewFeedback` is the **claim** (“I interacted with agent X and rate it Y”).
- `ResponseAppended` is the **public stamp** (“this feedback corresponds to a verified job/payment/validation”, “this was refunded”, “this is spam”, etc.).

**Normalization:**
- TrustNet SHOULD ingest `ResponseAppended` into `FeedbackResponseSignal` records (§8.1.3).
- Responses are **not** directly mapped into `RatingEvent` edges.

**TrustNet verification response schema (recommended):**
- Verifiers SHOULD use a canonical JSON document (see Appendix E) and publish:
  - `responseURI` → the JSON
  - `responseHash = keccak256(canonical_json_bytes)`

TrustNet does not define a single global truth set of verifiers. Which responders matter is **decider-relative**:
- A decider MAY treat certain responders as trusted verifiers (via its own `D→V` edges and/or local allowlists).
- Other responders can be ignored.

### 8.5 Channel C: Private append-only log (org mode)

Server mode supports a private endpoint:

- `POST /v1/ratings`

The request body is a signed `RatingEvent` (see Appendix A).

Rules:
- The server MUST validate signature for PRIVATE_LOG events.
- The server MUST store all accepted events append-only (auditable).
- The server MUST include the private log stream id + append position in the Root Manifest for reproducibility within the org.

### 8.6 Evidence and receipts

TrustNet decisions are stronger when they can link to **evidence**.

#### 8.6.1 ActionReceipts (gateway evidence)

MVP recommendation:
- Gateways emit **ActionReceipts** for high-risk tool calls:
  - tool name, args hash, result hash
  - contextId, decider, target
  - decision, score, why edges used
  - epoch + graphRoot used
  - timestamp and policyManifestHash
  - signature by OwnerKey / gateway key

Receipts can later be summarized into ratings by humans or auditors.

#### 8.6.2 Evidence bundles for derived edges (hybrid)

In hybrid deployments, `evidenceHash` on an `E→T` edge SHOULD commit to an **Evidence Bundle** that explains how that edge was derived (exec runs/jobs/payments/validated work).

Recommended content for an Evidence Bundle:
- pointers to verified feedback entries: `(chainId, erc8004Reputation, agentId, clientAddress, feedbackIndex)`
- pointers to verification stamps: `(responder, responseHash)` for those feedback entries
- optional pointers to escrow/job receipts (tx hashes / job ids)
- derivation policy id + parameters (time window, min amounts, dispute handling, etc.)

See Appendix E for a recommended JSON schema.

---


### 8.7 Post-MVP: Signals for non‑ERC‑8004 targets

Phase B adds support for targets that are **not** ERC‑8004 registered. The main change is that you lose the standardized ERC‑8004 `(agentId, feedbackIndex) + ResponseAppended` anchoring mechanism.

TrustNet can still support these targets in two complementary ways:

1) **Verifier-only trust edges (minimal, recommended first):**
   - Verifiers/marketplaces publish `E→T` trust edges directly where `T` is a wallet address (Channel A `EdgeRated` or Channel C `PRIVATE_LOG`).
   - `evidenceHash` commits to an Evidence Bundle that points to receipts from external payment/job systems (on-chain tx hashes, escrow job ids, off-chain invoices, etc.).
   - This preserves the 2-hop `D→E→T` proof model without requiring an open feedback stream.

2) **Wallet-feedback + wallet-response contracts (full hybrid):**
   - Introduce TrustNet-native contracts that replicate the ERC‑8004 pattern but target a wallet:
     - `WalletFeedbackSubmitted(targetWallet, client, value, tag1, tag2, endpoint, feedbackURI, feedbackHash)`
     - `WalletResponseAppended(targetWallet, client, feedbackIndex, responder, responseURI, responseHash)`
   - This restores “open feedback + public stamps” for non‑ERC‑8004 targets.

Which path to choose depends on whether you need **public client feedback** for wallet-only agents or whether verifier/marketplace attestations are sufficient.

## 9. Indexing, Normalization, and Latest-Wins Reduction

### 9.1 Storage tables (conceptual)

- `edges_raw`: immutable ingested `RatingEvent` trust edges (from Channel A, Channel B1, Channel C)
- `edges_latest`: latest trust edge per `(rater, target, contextId)` (input to root construction)

Hybrid (recommended, evidence/audit):
- `feedback_raw`: ingested ERC‑8004 `NewFeedback` records (including non-TrustNet tags)
- `feedback_responses_raw`: ingested ERC‑8004 `ResponseAppended` records
- `feedback_verified` (optional): materialized view joining feedback + trusted verification stamps

### 9.2 Reorg handling (chain sources)

If ingesting chain logs, indexers MUST either:

- wait for safe/finalized blocks (preferred), **or**
- support `removed=true` log retractions by rolling back affected events and rebuilding `edges_latest` for impacted keys.

#### 9.2.1 Chain indexing loop (EVM JSON-RPC `eth_getLogs`) (implementation detail)

If you ingest EVM logs, the recommended indexer loop is:

1) Persist `lastIndexedBlock` in the DB (per chain + per contract stream).  
2) On each tick, fetch `latestBlock` and set:

- `toBlock = latestBlock - confirmations`

3) For each contract/event stream you ingest, query logs in **chunks** (RPC providers often limit range/response size):

- TrustGraph `EdgeRated`:
  - `address = <TrustGraphAddress>`
  - `topics[0] = keccak256("EdgeRated(address,address,int8,bytes32)")`
- ERC‑8004 Reputation `NewFeedback`:
  - `address = <ERC8004ReputationAddress>`
  - `topics[0] = keccak256("NewFeedback(...)")` (exact signature depends on the deployed contract)

4) Decode each log and store in `edges_raw` with at minimum:
- `blockNumber`, `transactionIndex`, `logIndex`, `txHash`
- decoded `(rater, target, contextId, level)` (after channel mapping)
- optional `evidenceUri/evidenceHash`
- `removed` flag (if your RPC returns it)

5) Update `edges_latest` by comparing `(blockNumber, txIndex, logIndex)`.

6) Set `lastIndexedBlock = toBlock` only after successfully processing all chunks.

**Block timestamps (optional, for TTL):**
- To enforce TTL by real time, you also need `block.timestamp` for each log’s block.  
  Fetch block headers via `eth_getBlockByHash/Number` and cache `blockNumber → timestamp`.

**Operational notes:**
- Always retry chunk failures with backoff.
- Use idempotent inserts (unique constraint on `(chainId, txHash, logIndex)`).
- If you want stronger reorg handling without `removed=true`, index only finalized blocks on chains that support it.


### 9.3 Ordering key (`observedAt`)

For **chain events**, define ordering tuple:

`order = (blockNumber, transactionIndex, logIndex)`

For **private log** events, define ordering tuple:

`order = (serverSeq)` where `serverSeq` is a strictly increasing integer assigned by the server.

To unify ordering across sources, define:

`observedAt = encode_u64(sourceId, order)` (implementation-defined)  
and define latest-wins using lexicographic comparison:
1) compare source type + chainId/streamId
2) then compare order tuple

**MVP simplification:** run separate graphs per deployment mode (server-only or chain-only) to avoid cross-source ordering complexity.

### 9.4 Latest-wins reduction

For each unique key `(rater, target, contextId)`, keep only the newest event.

Tie-breaking:
- If order tuple is equal (should not occur), break ties by tx hash (chain) or request hash (private).

### 9.5 Freshness / expiry pruning (important improvement)

If your policy needs “recent endorsements only,” freshness MUST be enforced by **root construction**, not only by API logic.

Recommended approach:
- Maintain `updatedAt` metadata for each latest edge (block number and/or timestamp).
- For each context, configure a TTL (seconds or blocks).
- When building `edges_latest_for_root`, treat edges older than TTL as neutral (drop them).

The TTL policy MUST be included in the Root Manifest so recomputation matches.

---

## 10. Commitment: Graph Root + Root Manifest

### 10.1 Sparse Merkle Map (SMM)

TrustNet commits the latest edge set into a Sparse Merkle Map keyed by the edge identity.

**Leaf key:**
- `edgeKey = keccak256( raterPrincipalId || targetPrincipalId || contextId )`

**Tree depth:** 256 bits.

**Default value:** neutral (`level=0`) with zero metadata.

**Empty leaf hash (non-membership):** `bytes32(0)`.

In this v0.5 MVP, leaves that are not present in the map are represented by an **empty leaf**
whose `leafHash` is `bytes32(0)`. Verifiers MUST interpret an empty leaf as the default value
(neutral with zero metadata).

### 10.2 Leaf value encoding (recommended improvement)

To support verifiable freshness and evidence, the leaf value SHOULD commit to more than just `level`.

Define:

- `levelEnc = uint8(level + 2)` mapping -2..+2 → 0..4
- `updatedAtEnc`: `uint64` (recommended: chain block number or unix timestamp; 0 if unknown)
- `evidenceHash`: `bytes32` (0 if none)

Define leaf payload:

`leafValue = levelEnc || updatedAtEnc || evidenceHash`  (1 + 8 + 32 = 41 bytes)

Hashing scheme (domain-separated):

- **Membership leaf:** `leafHash = keccak256( 0x00 || edgeKey || leafValue )`
- **Empty leaf (non-membership):** `leafHash = bytes32(0)` (and `leafValue` is omitted/empty)
- `nodeHash = keccak256( 0x01 || left || right )`

This keeps proofs small but makes TTL and evidence commitments verifiable by recomputation.

> MVP fallback: if you want the smallest possible leaf, you MAY commit only `levelEnc` (1 byte). If you do, TTL cannot be verified cryptographically and must be treated as a best-effort policy check.

### 10.3 Root Manifest (normative)

For each epoch, the root publisher MUST publish a Root Manifest containing enough data to recompute the root.

A Root Manifest MUST include:

- `specVersion` (e.g., `"trustnet-spec-0.6"`)
- `epoch` (uint64)
- `graphRoot` (bytes32)
- `sourceMode` (`local|server|chain`)
- `sources`:
  - for chain mode: `{chainId, contracts, fromBlock, toBlock, toBlockHash, confirmations}`
  - for server mode: `{streamId, fromSeq, toSeq, streamHash}` (or equivalent)
- `contextRegistryHash`
- `ttlPolicy` (per-context TTL and semantics)
- `defaultEdgeValue` (explicitly: neutral)
- `leafValueFormat` (e.g., `levelOnlyV1` or `levelUpdatedAtEvidenceV1`)
- `softwareVersion` (git commit hash / build id)
- `createdAt` timestamp

If the root includes ERC‑8004-derived trust edges (Channel B1), the manifest MUST additionally include:

- `erc8004TrustEdgeGuard`:
  - required strings: `{ "endpoint": "trustnet", "tag2": "trustnet:v1" }`
  - accepted `tag1` formats: `"contextString"` and/or `"bytes32Hex"`
- `erc8004QuantizationPolicy` (how `(value,valueDecimals)` maps to `level`)
- `erc8004TargetBindingPolicy` (how ERC‑8004 subject identities bind to actionable principals):
  - recommended: `{ "type": "agentWalletAtBlock", "identityRegistry": "0x...", "atBlock": <toBlock> }`

### 10.4 Manifest hashing and canonicalization (important improvement)

If you publish `manifestHash` on-chain or use it in signatures, you MUST define canonical serialization.

Recommendation:
- Use **RFC 8785 JSON Canonicalization Scheme (JCS)** for JSON manifests.
- `manifestHash = keccak256( canonical_json_bytes )`

### 10.5 Root authenticity

A gateway MUST only accept a root if it is authenticated:

- **Chain mode:** root is fetched from on-chain RootRegistry (or another trusted on-chain anchor).
- **Server mode:** root MUST be signed by a configured `RootPublisherKey` and include `manifestHash`.

For the initial MVP release profile, gateways MUST additionally verify that the served root matches RootRegistry state
for the same epoch. Publisher signatures remain useful as defense-in-depth.


### 10.6 Root builder algorithm (normative behavior)

A root builder MUST produce a deterministic `graphRoot` from `edges_latest_for_root`:

1) **Select inputs**:
   - Start from `edges_latest`.
   - Apply TTL pruning per context (see §9.5).
   - Normalize all identities to `PrincipalId` (see §6.1).
   - Normalize context strings → `contextId` (see §7).

2) **Compute leaves**:
   - For each edge tuple `(rater, target, contextId)` compute `edgeKey`.
   - Encode `leafValue` using the configured `leafValueFormat`.
   - Compute `leafHash = keccak256(0x00 || edgeKey || leafValue)` for included leaves.

3) **Build the sparse tree**:
   - Tree depth is 256.
   - Default node hashes MUST be precomputed for each level starting from the empty leaf hash (`bytes32(0)`) at height 0.
   - Leaves not present are treated as empty (`leafHash = bytes32(0)`) and MUST be interpreted as the default value (neutral).

4) **Publish outputs**:
   - `graphRoot`
   - `epoch`
   - Root Manifest (with canonical serialization + `manifestHash`)

**Epoch choice (practical):**
- MVP recommendation: `epoch = floor(unixTimeSeconds / epochSeconds)` with `epochSeconds = 3600`.
- If using chain mode, also record `toBlock` and `toBlockHash` in the Root Manifest; this is what makes recomputation crisp.

**Determinism checklist:**
- Canonical JSON for manifests (RFC 8785).
- Stable endorser selection tie-breaks (§12.4).
- No nondeterministic ordering: sort leaves by `edgeKey` before building (even if your tree builder doesn’t need it).


---

## 11. Proofs (Membership, Non-membership, Bundles, Compression)

### 11.1 Membership proof (single edge)

A membership proof asserts:
- a particular `(rater, target, contextId)` maps to a specific `leafValue`
- and the leaf is consistent with `graphRoot`.

Proof contents:
- `edgeKey` inputs (rater, target, contextId) or already-hashed key
- `leafValue` (committed fields; membership proofs only)
- `siblings[]` array of 32-byte hashes (one per tree level), OR a compressed form (§11.4)

Verifier recomputes:
- `leafHash`
- walks up using siblings and key bits to reconstruct `graphRoot`

### 11.2 Non-membership proof

In a Sparse Merkle Map, a non-membership proof is a proof that the leaf at `edgeKey` equals the **default value** (neutral).

Implementation: identical to membership proof but:
- `leafHash` at the bottom is the empty leaf hash (`bytes32(0)`), and
- `leafValue` is omitted/empty (it is not committed in the proof).

Verifiers MUST interpret non-membership as the default value (neutral with zero metadata).

### 11.3 Decision proof bundle (2-hop)

A TrustNet decision for `(D, T, contextId)` returns a proof bundle containing at minimum:

- `proof_DE`: proof for edge `(D→E)`
- `proof_ET`: proof for edge `(E→T)`
- `proof_DT`: proof for direct edge `(D→T)` (membership or non-membership)
- `epoch` and `graphRoot` (or reference to RootRegistry state)
- `why` object containing decoded edge values used

All proofs MUST be against the same `epoch` and `graphRoot` and MUST use the same `contextId`.

### 11.4 Proof compression (recommended)

Sparse Merkle proofs are 256 siblings in the worst case. Many siblings are the default hash at that level. You can compress proofs by:

- Precomputing `defaultNodeHash[level]` for each tree level.
- Including a `bitmap` (256 bits) indicating which sibling positions are **non-default**.
- Including only the list of non-default siblings in order.

This reduces bandwidth for sparse trees and makes on-chain verification cheaper.

MVP: you MAY ship uncompressed proofs first, and add compression as an optimization.

### 11.5 Canonical JSON proof formats (recommended for MVP interoperability)

Even if you later add binary encodings, having a canonical JSON shape makes debugging and integration fast.

#### 11.5.1 `SmmProofV1` (single edge proof)

Uncompressed:

```json
{
  "type": "trustnet.smmProof.v1",
  "edgeKey": "0x<32 bytes>",
  "contextId": "0x<32 bytes>",
  "rater": "0x<32 bytes principalId>",
  "target": "0x<32 bytes principalId>",
  "isMembership": true,
  "leafValue": {
    "level": 2,
    "updatedAt": 12345678,
    "evidenceHash": "0x<32 bytes>",
    "evidenceVerified": true
  },
  "siblings": ["0x<32 bytes>", "... 256 total ..."],
  "format": "uncompressed"
}
```

Compressed:

```json
{
  "type": "trustnet.smmProof.v1",
  "edgeKey": "0x<32 bytes>",
  "contextId": "0x<32 bytes>",
  "rater": "0x<32 bytes principalId>",
  "target": "0x<32 bytes principalId>",
  "isMembership": true,
  "leafValue": {
    "level": 2,
    "updatedAt": 12345678,
    "evidenceHash": "0x<32 bytes>",
    "evidenceVerified": true
  },
  "bitmap": "0x<32 bytes bitset for 256 levels>",
  "siblings": ["0x<32 bytes>", "... only non-default ..."],
  "format": "bitmap"
}
```

Rules:
- `edgeKey` MUST equal `keccak256(rater || target || contextId)`.
- `isMembership` MUST be `true` for membership proofs and `false` for non-membership proofs.
- If `isMembership=true`, `leafValue` MUST be present and MUST match the root’s `leafValueFormat`.
- If `isMembership=false`, `leafValue` SHOULD be omitted and the verifier MUST treat the leaf as the default value (neutral) with `leafHash = bytes32(0)`.
- If `leafValue.updatedAt` is not used, it MUST be `0`.
- `leafValue.level` MUST be in `[-2..+2]`.
- `leafValue.evidenceVerified` is optional. If present, it indicates whether the evidence hash was verified
  via trusted stamps (see §8.4 / Appendix E). If absent, verification is unknown and policy may treat
  evidence as unverified.

#### 11.5.2 `DecisionBundleV1` (2-hop decision response)

```json
{
  "type": "trustnet.decisionBundle.v1",
  "epoch": 123,
  "graphRoot": "0x<32 bytes>",
  "manifestHash": "0x<32 bytes>",
  "decider": "0x<32 bytes principalId>",
  "target": "0x<32 bytes principalId>",
  "contextId": "0x<32 bytes>",
  "decision": "allow",
  "score": 2,
  "thresholds": { "allow": 2, "ask": 1 },
  "endorser": "0x<32 bytes principalId>",
  "why": {
    "edgeDE": { "level": 2, "updatedAt": 123, "evidenceHash": "0x..." },
    "edgeET": { "level": 2, "updatedAt": 124, "evidenceHash": "0x...", "evidenceVerified": true },
    "edgeDT": { "level": 0, "updatedAt": 0, "evidenceHash": "0x000..." }
  },
  "constraints": { "ttlSeconds": 300 },
  "proofs": {
    "DE": { "...": "SmmProofV1" },
    "ET": { "...": "SmmProofV1" },
    "DT": { "...": "SmmProofV1" }
  }
}
```

Verifier behavior:
- The gateway MUST recompute `score` from the decoded `why` edges and reject the bundle if it doesn’t match.
- The gateway MUST verify that all proofs bind to the same `graphRoot` and `epoch`.
- If constraints are present, the gateway MUST enforce them or treat decision as ASK/DENY.
- If no eligible endorser exists, `endorser` MUST be omitted. In that case, `DE`/`ET` proofs MAY be omitted,
  and `why.edgeDE` / `why.edgeET` MUST be neutral (level 0, updatedAt 0, evidenceHash = 0x00…00).
- `why.edge*.evidenceVerified` MAY be included to indicate verification status for evidence-gated policies.

---

## 12. Decision Rules (Trust-to-Act)

TrustNet decisions come in two layers:

1) **Score computation** from edges  
2) **Policy mapping** score → ALLOW/ASK/DENY (and constraints)

### 12.1 Hard veto rule (normative)

If the direct edge `D→T` exists with `level == -2` in the context, the decision MUST be `DENY`.

### 12.2 Recommended monotonic scoring rule (safe default)

This rule is designed to be monotonic and hard to game.

Let the decoded edges be:

- `edgeDT`: edge `(D→T)` (membership or default)
- `edgeDE`: edge `(D→E)` (membership or default)
- `edgeET`: edge `(E→T)` (membership or default)

Let:
- `lDT` = level of `edgeDT` (0 if absent)
- `lDE` = level of `edgeDE` (0 if absent)
- `lET` = level of `edgeET` (0 if absent)

#### Evidence gating (recommended; hybrid-friendly)

A gateway policy MAY declare that a context **requires evidence** for positive trust.

If `requiresEvidence == true` for the context, the verifier MUST apply:

- If `lET > 0` and `edgeET.evidenceHash == 0x00…00`, treat `lET := 0`
- If `lET > 0` and `edgeET.evidenceHash != 0x00…00` but the evidence is **not verified** by trusted
  verification stamps (see §8.4 / Appendix E), treat `lET := 0`
- If `lDT > 0` and `edgeDT.evidenceHash == 0x00…00`, the gateway SHOULD treat `lDT := 0`
  (configurable; some deployments allow deciders to self-override without evidence)
- If `lDT > 0` and `edgeDT.evidenceHash != 0x00…00` but the evidence is **not verified** by trusted
  verification stamps, the gateway SHOULD treat `lDT := 0` (configurable)

The hard veto rule still applies regardless of evidence.

#### Compute

1) If `lDT == -2`: **DENY**  
2) Else `base = 0`  
3) If `lDE > 0` AND `lET > 0`: `base = min(lDE, lET)`  
4) If `lDT > 0`: `score = max(base, lDT)` else `score = base`

Properties:
- No negative propagation (prevents sign-flip weirdness).
- Direct positive override can only increase trust.
- Direct veto dominates.
- Evidence gating prevents “unbacked” positive endorsements from granting ALLOW in high-risk contexts.

### 12.3 Legacy “product” scoring rule (optional compatibility)

If you already implemented the earlier product-style formula, you MAY support it behind a `scoringRule` flag in policy/manifests. For safety, still apply the **hard veto** rule first.

### 12.4 Endorser selection (deterministic)

Given a decider D and target T, the proof API chooses an endorser E subject to policy constraints:

Eligibility:
- `lDE > 0` (decider endorses E in this context)
- E is on an optional allowlist (policy)

Selection:
- Choose E maximizing `min(lDE, lET)` (or equivalent score contribution)
- Deterministic tie-breaker: choose the E with the smallest `keccak256(E)` (or lexical PrincipalId)

The chosen E and its edges MUST be returned in the decision proof bundle.

### 12.5 Policy thresholds and outcomes

A policy defines thresholds per context:

- `allowThreshold` (e.g., 2)
- `askThreshold` (e.g., 1)
- default deny

Mapping:

- if `score >= allowThreshold` → **ALLOW**
- else if `score >= askThreshold` → **ASK**
- else → **DENY**

### 12.6 Constraints (very useful for MVP)

Decisions SHOULD include **constraints** so “ALLOW” can be bounded:

Examples:
- code-exec: `{ allowedCommands: [...], ttlSeconds: 60 }`
- writes: `{ allowedPaths: ["./src/**"], maxBytes: 50000 }`
- messaging: `{ allowedDestinations: [...], ttlSeconds: 300 }`
- payments (later-phase): `{ maxAmountUsd: 50, ttlSeconds: 300 }`

Constraints are enforced by the gateway, not by TrustNet itself.

### 12.7 k-of-n / quorum policies (post-MVP or advanced)

For high-risk contexts, a decider may require:
- `k` independent endorsers E1..En each providing `lDEi > 0` and `lEiT > 0`.

This requires returning multiple proof bundles or a multi-proof. It can be added after MVP.

---

## 13. Gateway Integration (Generic)

Any gateway can integrate TrustNet if it can:

1) Map an attempted action/tool call to a `contextId` and risk tier.
2) Identify the `target` principal (the agent’s signing identity).
3) Fetch and verify a TrustNet decision proof bundle.
4) Enforce ALLOW/ASK/DENY and constraints.
5) Emit receipts for audit.

### 13.1 Gateway enforcement flow (normative)

On each attempted action:

1) **Classify**: `(toolName, args) -> (contextId, riskTier, constraintsTemplate)`  
2) **Decide**: request a decision bundle for `(decider=D, target=T, contextId=X)`  
3) **Verify**:
   - fetch authenticated root (RootRegistry or signed root)
   - verify all proofs against `graphRoot`
   - compute score locally and compare to the response (must match)
4) **Enforce**:
   - ALLOW → proceed
   - ASK → require explicit operator approval
   - DENY → block
5) **Receipt**: emit an ActionReceipt referencing epoch/root and why edges used.

### 13.2 Safe failure modes

If TrustNet API is unreachable, root is unauthenticated, or proof verification fails:

- For high-risk contexts (code-exec, and payments when enabled): default **DENY** (or ASK if you prefer human fallback).
- For low-risk contexts: default **ASK**.

This choice must be explicit in gateway config.

---

## 14. Integration with OpenClaw

OpenClaw is a strong enforcement surface because it provides hook points before and after tool calls, and includes host-level exec approvals.
The initial MVP focus in this section is `code-exec`; payment contexts are a later-phase extension.

### 14.1 Plugin hooks

The TrustNet plugin uses:

- `before_tool_call`: decide allow/ask/deny
- `after_tool_call` and `tool_result_persist`: emit receipts/evidence
- `message_received`: handle `/trustnet` commands (rate, endorse, veto)

### 14.2 Tool → context mapping

The plugin MUST maintain a deterministic mapping:

- tool name patterns → contextId
- riskTier per tool
- optional constraints templates per tool

Example mapping:

- `exec` → `trustnet:ctx:code-exec:v1` (high risk)
- `fs.write` → `trustnet:ctx:writes:v1` (medium risk)
- `messaging.send` → `trustnet:ctx:messaging:v1` (medium risk)

### 14.3 Enforcement mapping in OpenClaw

- **ALLOW**: plugin returns “continue”
- **ASK**: plugin invokes OpenClaw approval UX (and exec approvals for command execution)
- **DENY**: plugin blocks tool call and logs the Why

### 14.4 Rating publication UX (safe pattern)

The plugin may implement commands:

- `/trustnet rate <agent> <context> <level> [evidenceURI]`
- `/trustnet endorse <endorser> <context> +2`
- `/trustnet veto <agent> <context>`

Safety rules:
- The LLM may *suggest* a rating, but the plugin MUST require operator approval (or a tightly scoped automation rule).
- Signing keys/wallets must not be directly accessible to the model runtime. Prefer an external signer daemon or hardware wallet.

### 14.5 OpenClaw-specific receipts

For each high-risk tool call, emit an ActionReceipt containing:

- tool name and hashed args
- tool result hash (or error)
- decision: allow/ask/deny
- score and thresholds
- why edges (D→E, E→T, D→T)
- epoch, graphRoot, manifestHash
- agent identity + policyManifestHash
- signature

This becomes excellent evidence for later ratings.

---

## 15. On-chain Contracts (RootRegistry Required in Initial MVP Release)

For the initial MVP release profile, RootRegistry anchoring is required.
Other contracts remain optional and can be phased in later.

### 15.1 TrustGraph (events-only)

Optional minimal contract emitting `EdgeRated`.

### 15.2 RootRegistry (root anchoring)

Stores latest `{epoch, graphRoot, manifestHash, manifestURI}` and emits `RootPublished`.

### 15.3 TrustPathVerifier (library)

A Solidity library (or contract) that:
- verifies proof bundle paths against `graphRoot`
- checks same `contextId` across edges
- applies scoring rule + thresholds

Initial-MVP note: OpenClaw `code-exec` rollout still verifies proofs off-chain at the gateway.
On-chain verifier/payment guards are later-phase additions.

---

## 16. Off-chain Services (Server Mode)

A minimal TrustNet server consists of:

- Database: SQLite (dev) or Postgres (prod)
- Indexer worker
- Root builder worker
- HTTP API serving roots, manifests, proofs, and decisions
- Optional object store for manifests and evidence

### 16.1 API endpoints (sketch)

- `GET /v1/root` → `{ "epoch": 123, "graphRoot": "0x…", "manifestUri": "...", "manifestHash": "0x…", "publisherSig": "..." }`
- `GET /v1/contexts` → list of canonical contexts
- `GET /v1/decision?decider=<D>&target=<T>&contextId=<X>` → decision bundle
- `GET /v1/proof?key=<edgeKey>` → membership/non-membership proof (debug)
- `POST /v1/ratings` → append private RatingEvent (server mode)


### 16.2 Root endpoint requirements (normative)

`GET /v1/root` MUST return enough data for a gateway to authenticate and cache the current root:

- `epoch` (uint64)
- `graphRoot` (bytes32 hex string)
- `manifestUri` (string; may be inline for MVP)
- `manifestHash` (bytes32)
- `publisherSig` (required in server mode; signature over `epoch || graphRoot || manifestHash`)
- `publisherKeyId` (optional; useful if rotating publisher keys)

Gateways SHOULD:
- cache by `epoch`
- refuse roots where `epoch` decreases
- verify `publisherSig` before accepting the root (server mode)

For the initial MVP release profile, gateways MUST also cross-check `epoch/graphRoot/manifestHash` against
RootRegistry before enforcing high-risk actions.

### 16.3 Decision endpoint requirements (normative)

`GET /v1/decision?decider=<principalId>&target=<principalId>&contextId=<bytes32>` MUST:

- validate the inputs (hex length, allowed contexts)
- choose endorser deterministically (§12.4)
- return a `DecisionBundleV1` (§11.5.2)
  - if the deployment performs evidence verification, the response MAY include `evidenceVerified`
    in `why.edge*` and/or `leafValue` objects to signal verification status
    (gateways should treat missing `evidenceVerified` as unverified in evidence-gated contexts)

The server MUST NOT require that the gateway “trust the score”:
- the gateway recomputes `score` from the proof material and MUST reject mismatches.

### 16.4 Publishing endpoint (server mode)

`POST /v1/ratings` accepts `RatingEvent` objects.

MVP minimum server-side validation:
- signature is valid for `rater`
- `level` is in `[-2..+2]`
- `contextId` is in the configured context registry
- request size limits (DoS protection)

### 16.5 Error semantics

All endpoints SHOULD return structured errors:

```json
{
  "error": {
    "code": "invalid_proof",
    "message": "…",
    "details": { "field": "…" }
  }
}
```

Recommended error codes:
- `invalid_request`
- `unknown_context`
- `root_unavailable`
- `proof_unavailable`
- `invalid_signature`
- `internal_error`


---

## 17. MVP Build Plan (Ship + Verify)

This is a practical sequence that proves the core idea quickly.

### 17.0 MVP profile (Phase A0: OpenClaw + code-exec on ERC‑8004 hybrid)

The **Phase A0 initial MVP** defined by this spec assumes:

- **Targets are ERC‑8004 registered**: a target agent is identified by an `agentId` in an ERC‑8004 Identity Registry and is bound to an actionable **`agentWallet`** (EVM address) at the indexed block height.
- **Hybrid verification is ERC‑8004-native**:
  - clients publish interaction claims via `NewFeedback` (any tags/endpoint),
  - verifiers publish public stamps via `ResponseAppended` using `trustnet.verification.v1` (Appendix E).
- **Trust-to-act uses compact edges** committed into the Sparse Merkle Map:
  - `D→E` edges define which verifiers/endorsers the decider counts,
  - `E→T` edges are published (typically by verifiers) and SHOULD carry `evidenceHash` commitments to Evidence Bundles.
- **Root authenticity is anchored on-chain**: enforcement-time verification MUST cross-check served roots against RootRegistry.

**Not in Phase A0 initial MVP:** payments policy rollout/on-chain payment guards, targets that are not ERC‑8004 registered, and non‑ERC‑8004 public stamping channels (Phase A1/B; see §6.4, §8.7, and Milestone 5 in §17).

### 17.1 MVP definition (smallest thing that validates the thesis)

To “verify the idea,” the initial MVP MUST demonstrate:

1) An OpenClaw gateway blocks/allows a real `exec` tool call based on TrustNet.
2) The gateway can show an operator a compact **Why** (which endorsers and edges were used).  
3) The decision can be verified **cryptographically** against a root that is cross-checked against RootRegistry.
4) Tampering with either the proof or root causes verification failure (no silent bypass).

Everything else (on-chain verifier, payments enforcement modules, multi-publisher quorums) is optional until the above is solid. The **MVP profile in this spec assumes ERC‑8004 integration with mandatory anchoring**; see §17.0.

### 17.2 Suggested repo layout (pragmatic)

- `spec/` — this document + JSON schema + test vectors  
- `sdk/` — SMM hashing + proof verification (TS + Rust or Go)  
- `server/` — indexer + root builder + API  
- `plugin-openclaw/` — TrustNet plugin (enforcement + receipts)  
- `contracts/` — TrustGraph + RootRegistry (+ verifier optional)  
- `test/` — end-to-end scenarios and golden vectors  

### 17.3 Definition of done (per milestone)

Each milestone is “done” only when:
- there is an automated integration test proving the behavior end-to-end, and
- the artifacts (roots/manifests/proofs/receipts) are persisted for later audit.


### Milestone 0 — OpenClaw enforcement harness (required for initial MVP)

Deliverables:
- TrustNet plugin for OpenClaw:
  - tool→context mapping
  - allow/ask/deny enforcement
  - local policy config
  - local storage of `edges_latest` (seeded manually)
  - ActionReceipt emission
- CLI commands to add local edges (endorse, rate, veto)

Success criteria:
- You can run two agents, assign trust edges, and see tool calls blocked/allowed with clear Why.

### Milestone 1 — Roots + proofs + verification (server baseline)

Deliverables:
- TrustNet server:
  - private log ingest endpoint with signatures
  - `edges_raw` + `edges_latest` tables
  - root builder producing epoch roots + Root Manifests
  - decision endpoint returning proof bundles
- Plugin verifies:
  - root authenticity (publisher signature)
  - Merkle proofs
  - score computation matches response

Success criteria:
- One gateway can verify another gateway’s decision bundle without trusting the server.

### Milestone 2 — ERC‑8004 ingestion + target binding (MVP requirement)

Deliverables:
- Indexer ingests ERC‑8004 logs:
  - Identity Registry resolution (`agentId → agentWallet` at block)
  - Reputation Registry `NewFeedback` (store as `feedback_raw` for audit/derivation)
  - Reputation Registry `ResponseAppended` (store as `feedback_responses_raw`)
- Root builder supports Channel B1 “trust edges via ERC‑8004”:
  - enforce guard `endpoint="trustnet"` and `tag2="trustnet:v1"`
  - parse `tag1` as context string or bytes32
  - resolve `agentId → agentWallet` (binding policy) and map into `edges_latest`
- Root Manifest commits:
  - ERC‑8004 contract addresses
  - binding policy (`agentWalletAtBlock`)
  - quantization policy for `(value,valueDecimals) → level`

Success criteria:
- TrustNet can gate an ERC‑8004 registered agent (by its `agentWallet`) using trust edges published via ERC‑8004.

### Milestone 3 — Hybrid stamping + derived verifier edges (MVP requirement)

Deliverables:
- Implement a verifier stamping flow:
  - verifiers append `trustnet.verification.v1` responses to feedback (Appendix E)
  - verifiers publish/update `E→T` trust edges that commit an `evidenceHash` referencing an Evidence Bundle (Appendix E)
- Implement `feedback_verified` (optional but recommended):
  - materialize “verified feedback” per trusted verifier responders
- Expose evidence in the Why UI:
  - show `evidenceHash` (and an `evidenceUri` link if available)
- Enable evidence gating in the gateway policy for high-risk contexts (code-exec first; payments later).

Success criteria:
- A decider can require that positive `E→T` trust used for ALLOW is backed by verifiable evidence commitments, while raw unverified feedback does not grant high-risk permissions.

### Milestone 4 — RootRegistry anchoring + testnet rehearsal (required for initial MVP release)

Deliverables:
- Deploy RootRegistry on a testnet.
- Root publisher posts roots to RootRegistry.
- Gateway verifies against RootRegistry root.

Optional (nice-to-have):
- Deploy TrustGraph (events-only) and publish `EdgeRated` overrides on-chain.

Success criteria:
- A third party can recompute the root from chain logs + manifest, and the gateway’s decisions verify against an on-chain root anchor in normal runtime flow.

### Milestone 5 — Post-MVP: non‑ERC‑8004 targets (wallet-only agents)

Deliverables:
- Support `target` principals that are **not** ERC‑8004 registered (wallet-only agents):
  - verifiers publish `E→T` edges directly about wallet targets (Channel A or Channel C), with evidence bundles pointing to payment/job receipts from non‑ERC‑8004 systems.
- If you need “full hybrid” (open feedback + public stamps) for wallet-only targets:
  - introduce wallet-feedback and wallet-response contracts (see §8.7).

Success criteria:
- TrustNet can gate wallet-only agents without requiring ERC‑8004 registration, while preserving auditability via evidence commitments.


---

## 18. Verification Plan (Correctness, Security, Performance)

### 18.1 Correctness tests (must-have)

1) **Merkle test vectors**:
   - fixed set of edges → known root
   - membership proof verifies
   - tampered leafValue fails
2) **Latest-wins reduction**:
   - two events same tuple → newest wins by order tuple
3) **Decision invariants**:
   - hard veto always denies
   - contexts never mix
   - deterministic endorser selection tie-break holds
4) **Offline reproducibility**:
   - recompute root from manifest + inputs; root matches

### 18.2 Security tests (must-have)

- API spoofing: wrong root / proof rejected by verifier.
- Prompt injection: ensure no rating publication without explicit approval.
- Key isolation: signer keys not readable by model runtime.
- Reorg simulation (chain mode): ensure no “phantom edges” survive removed logs.

### 18.3 Performance targets (practical)

- Decision verification at gateway:
  - ≤ 10 ms for proof verification in common languages (cached default nodes)
- Decision API response size:
  - manageable (< 50 KB) even uncompressed
- Root cadence:
  - hourly for MVP; configurable

### 18.4 MVP demo scenarios (recommended)

- **Code exec**: only strongly trusted agent can run `exec`; others require approval or deny.
- **Writes**: trusted agent can modify allowlisted paths; others are blocked or escalated.
- **Emergency veto**: publish `D→T=-2` and show the next root causes DENY everywhere.
- **Later-phase payments**: trusted agent allowed to pay ≤ $50; untrusted agent denied.

---

## 19. Appendices

### Appendix A — Private RatingEvent schema (server mode)

```json
{
  "type": "trustnet.rating.v1",
  "rater": "0x…",
  "target": "0x…",
  "contextId": "0x…",
  "level": 1,
  "evidenceURI": "ipfs://…",
  "evidenceHash": "0x…",
  "createdAt": "2026-02-03T00:00:00Z",
  "signature": "0x…"
}
```

**Signature semantics (MVP):**
- Define `unsignedEvent` as the same JSON object **without** the `signature` field.
- Define `signingBytes = JCS(unsignedEvent)` (RFC 8785).
- `rater` MUST be an **EVM address** (20 bytes), and `signature` MUST be an ECDSA/secp256k1 signature (65 bytes) over `signingBytes` using Ethereum `personal_sign` / EIP‑191 semantics.
- The server MUST recover the signer from `signature` and reject the event if the recovered address does not match `rater`.

**Post-MVP extension:** support `agentRef:<bytes32>` raters with ed25519 signatures for local-first identities (see §6.2).

### Appendix B — Root Manifest schema (sketch)

```json
{
  "specVersion": "trustnet-spec-0.6",
  "epoch": 123,
  "graphRoot": "0x…",
  "manifestHash": "0x…",
  "sourceMode": "chain",
  "sources": {
    "chainId": 11155111,
    "contracts": {
      "trustGraph": "0x…",
      "erc8004Reputation": "0x…",
      "erc8004Identity": "0x…",
      "rootRegistry": "0x…"
    },
    "window": {
      "fromBlock": 123,
      "toBlock": 456,
      "toBlockHash": "0x…"
    },
    "confirmations": 32
  },
  "contextRegistryHash": "0x…",
  "erc8004TrustEdgeGuard": {
    "endpoint": "trustnet",
    "tag2": "trustnet:v1",
    "tag1Formats": ["contextString", "bytes32Hex"]
  },
  "erc8004TargetBindingPolicy": {
    "type": "agentWalletAtBlock",
    "identityRegistry": "0x…",
    "atBlock": 456
  },
  "erc8004QuantizationPolicy": {
    "type": "buckets",
    "buckets": [80, 60, 40, 20]
  },
  "ttlPolicy": {
    "trustnet:ctx:code-exec:v1": { "ttlSeconds": 604800 },
    "trustnet:ctx:writes:v1": { "ttlSeconds": 2592000 },
    "trustnet:ctx:messaging:v1": { "ttlSeconds": 604800 }
  },
  "leafValueFormat": "levelUpdatedAtEvidenceV1",
  "defaultEdgeValue": { "level": 0 },
  "softwareVersion": "git:…",
  "createdAt": "2026-02-03T00:00:00Z"
}
```

### Appendix C — OpenClaw plugin config (example)

```json5
{
  "plugins": {
    "entries": {
      "trustnet": {
        "enabled": true,
        "mode": "chain", // local|server|chain (initial MVP release uses RootRegistry anchoring)
        "apiBaseUrl": "http://127.0.0.1:8088",
        "rpcUrl": "https://sepolia.infura.io/v3/YOUR_KEY",
        "rootRegistry": "0xROOTREGISTRY...",
        "publisherAddress": "0xPUBLISHER...",
        "policy": {
          "decider": "0xDECIDER…",
          "thresholds": {
            "trustnet:ctx:code-exec:v1": { "allow": 2, "ask": 1 },
            "trustnet:ctx:writes:v1": { "allow": 1, "ask": 0 },
            "trustnet:ctx:messaging:v1": { "allow": 0, "ask": 0 }
          },
          "evidenceRequirements": {
            "trustnet:ctx:code-exec:v1": { "requireEvidenceForPositiveET": true }
          },
          "fallback": {
            "highRisk": "deny",
            "mediumRisk": "ask",
            "lowRisk": "ask"
          }
        }
      }
    }
  }
}
```

### Appendix D — Test vectors (decision rule)

Assume:
- missing edges = 0
- hard veto applies

1) `lDT=0, lDE=+2, lET=+1` → base=1 → score=1  
2) `lDT=0, lDE=+2, lET=+2` → base=2 → score=2  
3) `lDT=-2, lDE=+2, lET=+2` → DENY  
4) `lDT=+1, lDE=+2, lET=+2` → base=2 → score=2 (direct doesn’t reduce)

---

### Appendix E — Hybrid verification response and evidence bundle schemas (recommended)

This appendix defines recommended JSON documents for:

1) ERC‑8004 `appendResponse(...)` payloads (“verification stamps”), and  
2) off-chain Evidence Bundles committed by `evidenceHash` on `E→T` trust edges.

These schemas are **recommended**, not mandatory, but adopting them makes verification and interoperability much easier.

#### E.1 `trustnet.verification.v1` (ERC‑8004 response JSON)

This JSON is intended to be published at `responseURI` and committed by:

- `responseHash = keccak256(JCS(json_bytes))` (RFC 8785 JSON Canonicalization Scheme)

Minimal fields:

```json
{
  "type": "trustnet.verification.v1",
  "status": "verified",
  "context": "trustnet:ctx:code-exec:v1",
  "receipt": {
    "type": "execRun",
    "provider": "openclaw",
    "runId": "run_12345",
    "commandHash": "0x…",
    "resultHash": "0x…"
  },
  "notes": "optional human note",
  "createdAt": "2026-02-03T00:00:00Z"
}
```

Normative rules:
- `type` MUST be `"trustnet.verification.v1"`.
- `status` MUST be one of: `"verified" | "rejected" | "refunded" | "disputed" | "spam"`.
- `context` SHOULD be the canonical context string (see §7.1). Verifiers MAY additionally include `contextId`, but `context` is preferred for human readability.
- `receipt` MUST be present for `status="verified"` and SHOULD be present for `"refunded"` / `"disputed"` when applicable.
- The responder address on-chain (from `ResponseAppended.responder`) is the canonical verifier identity; the JSON MAY include `verifier` for readability but it is not trusted unless cross-checked.

Receipt types (recommended union):
- `escrowJob`: `{ chainId, contract, jobId, txHash? }`
- `evmPayment`: `{ chainId, txHash, from?, to?, value?, asset?, decimals? }`
- `execRun`: `{ provider, runId, commandHash, resultHash }`
- `offchain`: `{ provider, receiptId, signedBy?, signatureRef? }`

#### E.2 `trustnet.evidenceBundle.v1` (off-chain evidence committed by `evidenceHash`)

This JSON is intended to be published at an `evidenceUri` and committed by:

- `evidenceHash = keccak256(JCS(json_bytes))`

It explains how a verifier/endorser derived an `E→T` edge.

Example:

```json
{
  "type": "trustnet.evidenceBundle.v1",
  "verifier": "0x…",
  "context": "trustnet:ctx:code-exec:v1",
  "window": { "from": "2026-01-01T00:00:00Z", "to": "2026-02-01T00:00:00Z" },
  "inputs": [
    {
      "feedbackRef": {
        "chainId": 11155111,
        "erc8004Reputation": "0x…",
        "agentId": "42",
        "clientAddress": "0x…",
        "feedbackIndex": "7"
      },
      "verificationRef": {
        "responder": "0x…",
        "responseHash": "0x…"
      }
    }
  ],
  "derivation": {
    "policyId": "openclaw-code-exec-v1",
    "params": { "minVerifiedRuns": 3, "allowlistMatchRequired": true }
  },
  "output": {
    "level": 2,
    "stats": { "verifiedCount": 14, "successRate": 0.93 }
  }
}
```

Normative rules:
- `type` MUST be `"trustnet.evidenceBundle.v1"`.
- `verifier` SHOULD match the rater of the edge (`E`) that carries this `evidenceHash`.
- Each `inputs[i].verificationRef.responseHash` SHOULD correspond to an on-chain `ResponseAppended` event whose JSON hashes to that value, and whose `status="verified"` (or other status consistent with the derivation).
- The Evidence Bundle MUST be sufficient for an independent auditor to reproduce the `output` under the stated `derivation.policyId` + `params`, given access to the referenced on-chain events.

Practical note:
- Gateways do not need to download and validate the full evidence bundle on every action. The commitment (`evidenceHash`) enables later audit, dispute resolution, and secondary scoring.

---

**End of document**
