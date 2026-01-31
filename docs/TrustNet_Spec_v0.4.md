# TrustNet for AI Agents — Unified Architecture, Specification, and MVP Plan

**Document version:** 0.4 (Draft)  
**Date:** 2026-01-31  
**Status:** Implementation-spec draft (MVP-focused)  
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
15. On-chain Contracts (Optional for MVP)  
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

### 2.3 Design principles

1) **Deterministic and reproducible**: independent parties can recompute roots from public inputs (or signed logs) using a published Root Manifest.  
2) **Decider-relative**: there is no global score; each gateway/contract is a decider and chooses anchors/endorsers it counts.  
3) **Context isolation**: ratings never bleed across capability namespaces.  
4) **Explainability first**: decisions always return “why edges.”  
5) **Safe failure modes**: if verification fails, default to ASK or DENY depending on risk tier.  
6) **Minimal cryptographic surface**: hashes + signatures + Merkle proofs, no exotic crypto required.

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
6) Optional **on-chain root anchor** (RootRegistry)  
7) Optional **on-chain verifier** (TrustPathVerifier / library)

### 4.3 Deployment modes

#### Local mode
- Runs entirely on one machine.
- Ratings stored locally; decisions computed locally.
- Optionally still produces a root + proofs for consistency testing.

#### Server mode (org/shared)
- A TrustNet service hosts the indexer, root builder, and proof API.
- Gateways verify proofs locally against the published root.
- Roots MUST be either:
  - anchored on-chain **or**
  - signed by a configured root publisher key.

#### Chain mode (portable/public)
- Ratings are emitted on-chain (e.g., `EdgeRated`) and/or via ERC‑8004 `NewFeedback`.
- A root publisher builds roots from chain logs and publishes them to RootRegistry.
- Gateways verify proofs against RootRegistry’s latest root.

---

## 5. Core Concepts and Terminology

### 5.1 Roles

- **Decider (D)**: the policy anchor (a gateway org, SecOps, FinOps, DAO council, etc.) that decides whether a target can act.
- **Endorser (E)**: a curator/auditor/lead whose opinion the decider counts.
- **Target (T)**: typically the agent identity being gated.
- **Rater**: any principal that emits a rating edge (often D or E, but not required).

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

- `trustnet:ctx:payments:v1`
- `trustnet:ctx:code-exec:v1`
- `trustnet:ctx:writes:v1`
- `trustnet:ctx:messaging:v1`

Contexts are represented on-chain and in proofs as `bytes32 contextId` (see §7).

### 5.4 Canonical edge

TrustNet’s core fact is an edge:

`(rater, target, contextId) -> EdgeValue`

where `EdgeValue` contains at minimum `level`, and SHOULD contain `updatedAt` and (optional) `evidenceHash` (§10.2).

---

## 6. Identity and Registration

TrustNet supports both local-first identities and portable on-chain identities.

### 6.1 PrincipalId (unified identity representation)

To unify identity modes, TrustNet defines:

- `PrincipalId`: **32 bytes** (`bytes32`) stable identifier used in indexing and Merkle keys.

Encoding rules:

- **EVM address** (`0x` + 20 bytes):
  - `principalId = bytes32( leftPad20(address) )` (i.e., 12 zero bytes + 20 address bytes).
- **Local AgentRef** (`sha256(agentPublicKey)`):
  - `principalId = agentRef` (already 32 bytes).
- **ERC‑8004 agentId** (ERC‑721 token id) MUST NOT be used directly as principalId for action gating.
  - Instead, resolve to an EVM `agentWallet` (or a declared signing key) and use that address as principalId.

> Rationale: actions at gateways and contracts are typically authorized by a signing key/wallet, not by a token id.

### 6.2 Local-first identity (Mode L)

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

### 6.3 Portable identity (Mode P) via ERC‑8004

If using ERC‑8004 identity:

- Use the ERC‑8004 identity registry to resolve:
  - `agentId` → `agentWallet` (or equivalent signing authority)
- The gateway uses the resolved `agentWallet` as the actionable identity.

### 6.4 Key rotation and revocation

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
- `trustnet:ctx:payments:v1`
- `trustnet:ctx:code-exec:v1`

### 7.2 Deriving contextId

`contextId = keccak256( utf8(contextString) )`

### 7.3 Context registry (recommended)

A TrustNet deployment SHOULD publish a **Context Registry**:

- A JSON list of canonical context strings (and optional human docs).
- `contextRegistryHash = keccak256(canonical_json_bytes)`.

The Root Manifest SHOULD include `contextRegistryHash` so verifiers know exactly which contexts exist and how they hash.

---

## 8. Trust Signals and Evidence

TrustNet ingests signals from one or more channels into a canonical model.

### 8.1 Canonical RatingEvent

Every ingested signal MUST normalize into:

- `rater: PrincipalId`
- `target: PrincipalId`
- `contextId: bytes32`
- `level: int8 (-2..+2)`
- `evidenceHash: bytes32 (optional, default 0)`
- `evidenceUri: string (optional, not committed)`
- `source: enum { EDGE_RATED, ERC8004_FEEDBACK, PRIVATE_LOG }`
- `observedAt: uint64` (monotonic-ish ordering key; see §9.3)
- `sig: bytes (required for PRIVATE_LOG; optional otherwise)`

### 8.2 Channel A: TrustNet-native on-chain event (EdgeRated)

A minimal on-chain signal:

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
- For MVP, evidence MAY be off-chain (e.g., stored as a receipt in an org system).
- If evidence is important, prefer Channel B (ERC‑8004 feedback) or include an additional attestation system post-MVP.

### 8.3 Channel B: ERC‑8004 feedback (NewFeedback) mapping

When ingesting ERC‑8004 `NewFeedback`, TrustNet MUST apply a deterministic mapping into a RatingEvent.

**Ingestion guard (recommended):**
- Only ingest feedback if a dedicated tag indicates TrustNet semantics, e.g.:
  - `tag2 == keccak256("trustnet:v1")`

**Mapping:**
- `rater = principalId(clientAddress)`
- `target = principalId( agentWallet(agentId) )` (resolved via ERC‑8004 identity)
- `contextId = tag1` (tag1 should be the TrustNet `contextId`)
- `level = quantize(value)` (see below)
- `evidenceUri/evidenceHash` from feedback URI/hash fields if present

**Quantization (default buckets):**
- 80..100 → +2
- 60..79  → +1
- 40..59  →  0
- 20..39  → -1
- 0..19   → -2

A deployment MAY choose a different quantizer, but:
- it MUST be included in the Root Manifest and
- MUST be versioned (so recomputation is possible).

### 8.4 Channel C: Private append-only log (org mode)

Server mode supports a private endpoint:

- `POST /v1/ratings`

The request body is a signed RatingEvent (see Appendix A).

Rules:
- The server MUST validate signature for PRIVATE_LOG events.
- The server MUST store all accepted events append-only (auditable).
- The server MUST include the private log stream id + append position in the Root Manifest for reproducibility within the org.

### 8.5 Evidence and receipts

TrustNet decisions are stronger when they can link to **evidence**.

MVP recommendation:
- Gateways emit **ActionReceipts** for high-risk tool calls:
  - tool name, args hash, result hash
  - contextId, decider, target
  - decision, score, why edges used
  - epoch + graphRoot used
  - timestamp and policyManifestHash
  - signature by OwnerKey / gateway key

Receipts can later be summarized into ratings by humans or auditors.

---

## 9. Indexing, Normalization, and Latest-Wins Reduction

### 9.1 Storage tables (conceptual)

- `edges_raw`: immutable ingested RatingEvents
- `edges_latest`: latest event per `(rater, target, contextId)`

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

### 10.2 Leaf value encoding (recommended improvement)

To support verifiable freshness and evidence, the leaf value SHOULD commit to more than just `level`.

Define:

- `levelEnc = uint8(level + 2)` mapping -2..+2 → 0..4
- `updatedAtEnc`: `uint64` (recommended: chain block number or unix timestamp; 0 if unknown)
- `evidenceHash`: `bytes32` (0 if none)

Define leaf payload:

`leafValue = levelEnc || updatedAtEnc || evidenceHash`  (1 + 8 + 32 = 41 bytes)

Hashing scheme (domain-separated):

- `leafHash = keccak256( 0x00 || edgeKey || leafValue )`
- `nodeHash = keccak256( 0x01 || left || right )`

This keeps proofs small but makes TTL and evidence commitments verifiable by recomputation.

> MVP fallback: if you want the smallest possible leaf, you MAY commit only `levelEnc` (1 byte). If you do, TTL cannot be verified cryptographically and must be treated as a best-effort policy check.

### 10.3 Root Manifest (normative)

For each epoch, the root publisher MUST publish a Root Manifest containing enough data to recompute the root.

A Root Manifest MUST include:

- `specVersion` (e.g., `"trustnet-spec-0.4"`)
- `epoch` (uint64)
- `graphRoot` (bytes32)
- `sourceMode` (`local|server|chain`)
- `sources`:
  - for chain mode: `{chainId, contracts, fromBlock, toBlock, toBlockHash, confirmations}`
  - for server mode: `{streamId, fromSeq, toSeq, streamHash}` (or equivalent)
- `contextRegistryHash`
- `quantizationPolicy` (for ERC‑8004 mapping)
- `ttlPolicy` (per-context TTL and semantics)
- `defaultEdgeValue` (explicitly: neutral)
- `leafValueFormat` (e.g., `levelOnlyV1` or `levelUpdatedAtEvidenceV1`)
- `softwareVersion` (git commit hash / build id)
- `createdAt` timestamp

### 10.4 Manifest hashing and canonicalization (important improvement)

If you publish `manifestHash` on-chain or use it in signatures, you MUST define canonical serialization.

Recommendation:
- Use **RFC 8785 JSON Canonicalization Scheme (JCS)** for JSON manifests.
- `manifestHash = keccak256( canonical_json_bytes )`

### 10.5 Root authenticity

A gateway MUST only accept a root if it is authenticated:

- **Chain mode:** root is fetched from on-chain RootRegistry (or another trusted on-chain anchor).
- **Server mode:** root MUST be signed by a configured `RootPublisherKey` and include `manifestHash`.


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
   - Compute `leafHash = keccak256(0x00 || edgeKey || leafValue)`.

3) **Build the sparse tree**:
   - Tree depth is 256.
   - Default node hashes MUST be precomputed for each level for the default leaf.
   - Leaves not present are treated as default.

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
- `leafValue` (committed fields)
- `siblings[]` array of 32-byte hashes (one per tree level), OR a compressed form (§11.4)

Verifier recomputes:
- `leafHash`
- walks up using siblings and key bits to reconstruct `graphRoot`

### 11.2 Non-membership proof

In a Sparse Merkle Map, a non-membership proof is a proof that the leaf at `edgeKey` equals the **default value** (neutral).

Implementation: identical to membership proof but `leafValue` is default.

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
  "leafValue": {
    "level": 2,
    "updatedAt": 12345678,
    "evidenceHash": "0x<32 bytes>"
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
  "leafValue": {
    "level": 2,
    "updatedAt": 12345678,
    "evidenceHash": "0x<32 bytes>"
  },
  "bitmap": "0x<32 bytes bitset for 256 levels>",
  "siblings": ["0x<32 bytes>", "... only non-default ..."],
  "format": "bitmap"
}
```

Rules:
- `edgeKey` MUST equal `keccak256(rater || target || contextId)`.
- `leafValue` MUST match the root’s `leafValueFormat`.
- If `updatedAt` is not used, it MUST be `0`.
- `level` MUST be in `[-2..+2]`.

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
    "edgeET": { "level": 2, "updatedAt": 124, "evidenceHash": "0x..." },
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

---

## 12. Decision Rules (Trust-to-Act)

TrustNet decisions come in two layers:

1) **Score computation** from edges  
2) **Policy mapping** score → ALLOW/ASK/DENY (and constraints)

### 12.1 Hard veto rule (normative)

If the direct edge `D→T` exists with `level == -2` in the context, the decision MUST be `DENY`.

### 12.2 Recommended monotonic scoring rule (safe default)

This rule is designed to be monotonic and hard to game.

Let:
- `lDT` = level of `D→T` (0 if absent)
- `lDE` = level of `D→E` (0 if absent)
- `lET` = level of `E→T` (0 if absent)

Compute:

1) If `lDT == -2`: DENY  
2) Else `base = 0`  
3) If `lDE > 0` AND `lET > 0`: `base = min(lDE, lET)`  
4) If `lDT > 0`: `score = max(base, lDT)` else `score = base`

Properties:
- No negative propagation (prevents sign-flip weirdness).
- Direct positive override can only increase trust.
- Direct veto dominates.

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
- payments: `{ maxAmountUsd: 50, ttlSeconds: 300 }`
- code-exec: `{ allowedCommands: [...], ttlSeconds: 60 }`
- writes: `{ allowedPaths: ["./src/**"], maxBytes: 50000 }`

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

- For high-risk contexts (payments, code-exec): default **DENY** (or ASK if you prefer human fallback).
- For low-risk contexts: default **ASK**.

This choice must be explicit in gateway config.

---

## 14. Integration with OpenClaw

OpenClaw is a strong enforcement surface because it provides hook points before and after tool calls, and includes host-level exec approvals.

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
- `payments.send` → `trustnet:ctx:payments:v1` (high risk)
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

## 15. On-chain Contracts (Optional for MVP)

If you want portable, on-chain verifiable trust-to-act:

### 15.1 TrustGraph (events-only)

Minimal contract emitting `EdgeRated`.

### 15.2 RootRegistry (root anchoring)

Stores latest `{epoch, graphRoot, manifestHash, manifestURI}` and emits `RootPublished`.

### 15.3 TrustPathVerifier (library)

A Solidity library (or contract) that:
- verifies proof bundle paths against `graphRoot`
- checks same `contextId` across edges
- applies scoring rule + thresholds

MVP note: on-chain verifier is optional; you can validate the idea off-chain first.

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

### 16.3 Decision endpoint requirements (normative)

`GET /v1/decision?decider=<principalId>&target=<principalId>&contextId=<bytes32>` MUST:

- validate the inputs (hex length, allowed contexts)
- choose endorser deterministically (§12.4)
- return a `DecisionBundleV1` (§11.5.2)

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

### 17.1 MVP definition (smallest thing that validates the thesis)

To “verify the idea,” the MVP MUST demonstrate:

1) A gateway blocks/allows a real tool call based on TrustNet.  
2) The gateway can show an operator a compact **Why** (which endorsers and edges were used).  
3) The decision can be verified **cryptographically** against a root (server mode or chain mode).  
4) Tampering with either the proof or root causes verification failure (no silent bypass).

Everything else (on-chain verifier, ERC‑8004 ingestion, multi-publisher quorums) is optional until the above is solid.

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


### Milestone 1 — Gateway enforcement works (local mode)
Deliverables:
- TrustNet plugin for OpenClaw:
  - tool→context mapping
  - allow/ask/deny enforcement
  - local policy config
  - local storage of edges_latest (seeded manually)
  - ActionReceipt emission
- CLI commands to add local edges (endorse, rate, veto)

Success criteria:
- You can run two agents, assign trust edges, and see tool calls blocked/allowed with clear Why.

### Milestone 2 — Roots + proofs + verification (server mode)
Deliverables:
- TrustNet server:
  - private log ingest endpoint with signatures
  - edges_raw + edges_latest tables
  - root builder producing epoch roots + Root Manifests
  - decision endpoint returning proof bundles
- Plugin verifies:
  - root authenticity (publisher signature)
  - Merkle proofs
  - score computation matches response

Success criteria:
- One gateway can verify another gateway’s decision bundle without trusting the server.

### Milestone 3 — Chain anchoring (optional, but strong demo)
Deliverables:
- Deploy TrustGraph and RootRegistry on a testnet.
- Plugin can publish `EdgeRated` via a safe signer flow.
- Indexer ingests chain logs and builds roots.
- Root publisher posts roots to RootRegistry.
- Gateway verifies against RootRegistry root.

Success criteria:
- A third party can recompute the root from chain logs + manifest, and the gateway’s decisions verify.

### Milestone 4 — ERC‑8004 feedback ingestion (optional)
Deliverables:
- Ingest `NewFeedback` with guard tag
- Quantize and map into edges_latest
- Show “richer feedback” (evidence URI/hash) in Why panel

Success criteria:
- TrustNet can combine curator edges and feedback edges into explainable allow/deny.

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

- **Payments**: trusted agent allowed to pay ≤ $50; untrusted agent denied; unknown agent asked.
- **Code exec**: only strongly trusted agent can run `exec`; others require approval.
- **Emergency veto**: publish `D→T=-2` and show the next root causes DENY everywhere.

---

## 19. Appendices

### Appendix A — Private RatingEvent schema (server mode)

```json
{
  "type": "trustnet.rating.v1",
  "rater": "0x… or agentRef:…",
  "target": "0x… or agentRef:…",
  "contextId": "0x…",
  "level": 1,
  "evidenceURI": "ipfs://…",
  "evidenceHash": "0x…",
  "createdAt": "2026-01-30T12:34:56Z",
  "signature": "base64..."
}
```

### Appendix B — Root Manifest schema (sketch)

```json
{
  "specVersion": "trustnet-spec-0.4",
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
  "quantizationPolicy": {
    "type": "buckets",
    "buckets": [80, 60, 40, 20]
  },
  "ttlPolicy": {
    "trustnet:ctx:payments:v1": { "ttlSeconds": 2592000 },
    "trustnet:ctx:code-exec:v1": { "ttlSeconds": 604800 }
  },
  "leafValueFormat": "levelUpdatedAtEvidenceV1",
  "defaultEdgeValue": { "level": 0 },
  "softwareVersion": "git:…",
  "createdAt": "2026-01-31T00:00:00Z"
}
```

### Appendix C — OpenClaw plugin config (example)

```json5
{
  "plugins": {
    "entries": {
      "trustnet": {
        "enabled": true,
        "mode": "server", // local|server|chain
        "apiBaseUrl": "http://127.0.0.1:8088",
        "rootPublisherPubKey": "base64:…",
        "policy": {
          "decider": "0xDECIDER…",
          "thresholds": {
            "trustnet:ctx:payments:v1": { "allow": 1, "ask": 0 },
            "trustnet:ctx:code-exec:v1": { "allow": 2, "ask": 1 }
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

**End of document**
