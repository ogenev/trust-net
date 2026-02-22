# TrustNet — Explainable, Decider‑Relative Trust Proofs for ERC‑8004 Agents

**Version:** 1.1 (MVP implementer spec)  
**Date:** Feb 22, 2026  
**License (docs):** CC BY‑SA 4.0  

> **What changed vs v1.0:** fixed ERC‑8004 field types/signatures, clarified ingestion + revocations, corrected the scoring rule to avoid “enemy‑of‑my‑enemy” sign flips, and specified an implementable Sparse Merkle Tree + compact proof format.

---

## Abstract

**TrustNet** is a portable, **explainable “trust‑to‑act” layer** for autonomous agents. It lets gateways and smart contracts
**admit or deny** an action (e.g., *pay ≤ $50*, *run CI/CD*, *modify CRM data*) using:

- **public, ERC‑8004‑native trust signals** (identity + reputation events),
- a **small proof** against a committed root,
- and a **deterministic, decider‑relative rule** (“as seen by *this* decider”).

TrustNet is intentionally minimal:

- **Ratings as edges**: `D→E` (decider→endorser), `E→T` (endorser→target agent), plus an optional direct override `D→T`,
  all scoped by **context** (capability namespace).
- **Commitment**: a single **Sparse Merkle Tree Map** root (`graphRoot`) over the **latest effective** edge per `(rater, target, context)`.
- **Proof**: a **2‑hop path proof** (`D→E`, `E→T`, and optional `D→T`) plus an explanation (“Why”) that names the exact edges used.

No tokens. No global social score. No ZK required for MVP (future‑ready).

---

## 0) Motivation

Agent systems now call tools, write code, move money, and act on behalf of users and DAOs. Traditional ACLs or opaque global
scores don’t travel across apps, teams, and chains.

TrustNet answers:

> *“From **my** point of view (decider), may **this agent** perform **this capability** now — and **why**?”*

We scope trust by **context**, compute it via a **transparent two‑hop rule**, and verify it with **Merkle proofs**.

---

## 1) Goals (MVP)

1. **Decider‑relative trust** — scores are always “as seen by” a chosen **decider/anchor**.
2. **Explainable decisions** — every allow/deny returns a short **Why** with the exact edges used.
3. **Context isolation** — ratings are bound to a capability namespace (e.g., `payments`, `code-exec`) to avoid cross‑capability privilege escalation.
4. **Single root, compact proofs** — one commitment root; proofs are compact (sparse‑tree “bitmap + siblings”) and verifiable off‑chain or on‑chain.
5. **ERC‑8004 compatible** — TrustNet *consumes* ERC‑8004 Identity + Reputation signals; TrustNet adds only a small commitment/proof layer.

**Non‑goals (MVP)**  
No tokens, staking mechanics, private/ZK proofs, universal ranking, or “one score to rule them all”.

---

## 2) ERC‑8004 Compatibility (what we consume)

TrustNet is compatible with ERC‑8004’s three registries and *does not* require changes to them:

- **Identity Registry**: use `agentId` (ERC‑721 tokenId) and optional on‑chain metadata such as `agentWallet` (when set).  
- **Reputation Registry**: ingest `NewFeedback` / `FeedbackRevoked` / `ResponseAppended` events that match TrustNet tagging.
- **Validation Registry (optional)**: may be ingested later as additional signals, but is not required for MVP.

> ERC‑8004’s Reputation Registry uses a signed fixed‑point `value` (`int128`) plus `valueDecimals` (`0..18`) and optional `tag1` / `tag2`, plus optional `feedbackURI` / `feedbackHash` emitted in events. See the ERC‑8004 draft spec for exact interfaces and event fields.

---

## 3) Entities & Identifiers

- **Decider `D`** — an anchor that sets policy (e.g., FinOps, SecOps, ProtocolCouncil).
- **Endorser `E`** — a curator/auditor/team‑lead *trusted by D* to speak about targets.
- **Target `T`** — typically the **agent** being gated.

### 3.1 Agent identity forms

TrustNet can gate either:

- **By agent wallet address** (fastest for on‑chain gates): `T = agentWallet(agentId)` when set, or
- **By agentId** (strongest semantic identity): `T = (identityRegistry, agentId)` (recommended for gateways/off‑chain decisions).

**MVP recommendation:** if your on‑chain contract gates `msg.sender`, treat `T = msg.sender` and require the caller to be the agent’s `agentWallet` (checked off‑chain or by calling the Identity Registry).

### 3.2 Context

- **Context string (`contextTag`)** — a canonical string used in ERC‑8004 `tag1`, e.g. `trustnet:ctx:payments:v1`.
- **Context id (`contextId`)** — `bytes32 = keccak256(bytes(contextTag))`, used inside TrustNet proofs and Merkle keys.

Canonical contexts (v1):
- `trustnet:ctx:global:v1`
- `trustnet:ctx:payments:v1`
- `trustnet:ctx:code-exec:v1`
- `trustnet:ctx:writes:v1`
- `trustnet:ctx:defi-exec:v1`

---

## 4) Data Model

### 4.1 TrustNet edge rating event (on‑chain, events‑only)

This is TrustNet’s own minimal edge event for `D→E` and optional direct overrides `D→T`.

```solidity
event EdgeRated(
  address indexed rater,
  address indexed target,
  int8    level,        // −2..+2
  bytes32 indexed contextId
);
```

**Semantics:** the latest event per `(rater, target, contextId)` prevails (ordered by `(blockNumber, txIndex, logIndex)`).

### 4.2 ERC‑8004 feedback → TrustNet edge (normative ingestion)

ERC‑8004 Reputation feedback is appended and can be revoked, so TrustNet defines a *selection rule* that turns many feedback
entries into one effective `E→T` edge.

**TrustNet tagging (MVP):**

- `tag2` MUST equal the literal string: `trustnet:v1`
- `tag1` MUST equal the literal context string: `trustnet:ctx:<name>:v1` (one of the canonical contexts, or a registered custom context)

**Trust score encoding inside ERC‑8004 feedback (MVP):**

- `valueDecimals` MUST be `0`
- `value` MUST be in `[0, 100]` (inclusive)
- `value` is interpreted as a 0–100 trust score where 0 is worst and 100 is best

**Mapping to TrustNet `level ∈ {−2,−1,0,+1,+2}`:**
- `80..100 → +2`
- `60..79  → +1`
- `40..59  →  0`
- `20..39  → −1`
- `0..19   → −2`

**Edge mapping:**
- `rater = clientAddress` (the ERC‑8004 feedback submitter)
- `target = agentWallet(agentId)` *or* `target = agentKey(agentId)` (see §3.1)
- `contextId = keccak256(bytes(tag1))`
- `level = quantize(value)`

**Latest‑effective selection rule (per `(rater, agentId, contextTag)`):**
- Consider only feedback entries with TrustNet tags and valid encoding.
- Ignore entries that are revoked (`isRevoked == true` / `FeedbackRevoked` seen).
- Pick the **latest** remaining entry (highest `(blockNumber, txIndex, logIndex)`; or equivalently the latest `feedbackIndex` for that rater/agent when available).
- If none remain: treat the edge as **absent** (default `level = 0`).

**Evidence:**
- `feedbackURI` / `feedbackHash` (when provided) are surfaced in the **Why** panel.

### 4.3 Optional receipts (off‑chain)

Deciders and gateways MAY maintain an off‑chain receipt log (success/error/violation, timestamps, context) and periodically
publish summarized ratings as `EdgeRated` events.

---

## 5) Commitment & Proofs

### 5.1 Sparse Merkle Tree Map (SMT‑Map)

TrustNet commits to the latest effective edges using a sparse Merkle tree keyed by a 256‑bit key.

- **Key preimage:** `rater ∥ target ∥ contextId`
- **Key:** `K = keccak256( abi.encodePacked(rater, target, contextId) )`
- **Value:** `V = uint8(level + 2)` maps `−2..+2 → 0..4`

**Hashing (domain separated):**
- `H_leaf  = keccak256( 0x00 ∥ K ∥ V )`
- `H_node  = keccak256( 0x01 ∥ left ∥ right )`
- `H_empty = keccak256( 0x02 )`

Tree depth is **256** (one bit per level, derived from `K`).

**Default semantics (normative):** if a key has **no leaf**, its edge is treated as **absent**, which implies `level = 0`
(neutral) for scoring.

### 5.2 Compact sparse Merkle proof format (MVP)

A full sparse proof is 256 sibling hashes; this is too large for practical calldata. TrustNet uses a compact format that only
includes **non‑default** siblings plus a 256‑bit bitmap.

```json
{
  "leaf": { "K": "0x..", "V": 4 },            // for membership proofs
  "isAbsent": false,                          // true => the leaf is empty (no edge set)
  "bitmap": "0x..(256-bit)",                  // bit i=1 => sibling for level i is present in `siblings`
  "siblings": ["0x..", "0x..", "..."]         // siblings in ascending level order (i=0,1,2...)
}
```

**Notes (normative):**
- `K` can be **re‑derived** by the verifier from `(rater, target, contextId)`; it MAY be omitted from calldata if the
  verifier recomputes it.
- Levels are counted **from the leaf upward**: `i = 0` is the leaf’s immediate sibling, `i = 255` is the top‑most sibling.
- Bit selection uses `K` interpreted as a `uint256` with **bit 0 = least significant bit**.
- `siblings[]` MUST contain exactly `popcount(bitmap)` hashes.

**Default subtree hashes:**
- `defaultHash[0] = H_empty`
- `defaultHash[i+1] = H_node(defaultHash[i], defaultHash[i])`

**Verification algorithm (informative pseudocode):**
```
K = keccak256(abi.encodePacked(rater, target, contextId))

h = isAbsent ? H_empty : keccak256(0x00 || K || V)

j = 0
for i in 0..255:
  sib = ((bitmap >> i) & 1 == 1) ? siblings[j++] : defaultHash[i]
  if ((K >> i) & 1 == 0):  h = keccak256(0x01 || h   || sib)   // h is left child
  else:                    h = keccak256(0x01 || sib || h)     // h is right child

require(h == graphRoot)
```

For **non‑membership** (absence) proofs, set `isAbsent = true` and omit `V` (or set it to 0 and ignore it).

### 5.3 Two‑hop TrustPathProof

A score from **Decider `D`** to **Target `T`** via **Endorser `E`** within one context:

- Proof for `D→E` (MUST be present to use that endorser)
- Proof for `E→T`
- Proof for `D→T` (may be absent; direct override)

All proofs MUST use the same `contextId`.

**TrustPathProof (conceptual):**
```json
{
  "graphRoot": "0x..",
  "epoch": 123,
  "contextId": "0xCTX..",
  "D": "0x..", "E": "0x..", "T": "0x..",
  "DE": { "level": 2, "proof": { ... } },
  "ET": { "level": 1, "proof": { ... } },
  "DT": { "level": 0, "isAbsent": true, "proof": { ... } }
}
```

---

## 6) Scoring (normative)

Let `l ∈ {−2, −1, 0, +1, +2}`.

### 6.1 Safety rule (avoid sign‑flip “enemy‑of‑my‑enemy”)

`D→E` is a *trust-in-endorser* edge. A decider who distrusts an endorser MUST NOT become *more* likely to trust a target because
that endorser also distrusts the target.

Therefore, the path contribution uses only **non‑negative** decider→endorser trust:

```
lDEpos         = max(lDE, 0)
path           = lDEpos * lET
scoreNumerator = 2*lDT + path
score          = clamp( scoreNumerator / 2 , −2, +2 )
```

- Division is **integer toward zero** (EVM semantics).
- Clamp saturates to `[-2, +2]`.

### 6.2 Examples

| lDT | lDE | lET | path (=max(lDE,0)*lET) | Numerator | Score |
|:--:|:--:|:--:|:--:|:--:|:--:|
|  0 | +1 | +1 |  1 |  1 |  0 |
|  0 | +2 | +1 |  2 |  2 | +1 |
|  0 | +2 | +2 |  4 |  4 | +2 |
| −2 | +2 | +2 |  4 |  0 |  0 |
|  0 | −2 | −2 |  0 |  0 |  0 *(no sign flip)* |

---

## 7) On‑chain Components (minimal)

### 7.1 TrustGraph (events‑only)
- Emits `EdgeRated` for curator edges and direct overrides.
- No storage, no scoring; minimal gas.

### 7.2 RootRegistry
- Stores the active `{graphRoot, epoch}` and the **authorized publisher(s)**.
- MUST enforce monotonically increasing `epoch`.

**MVP recommendation:** publisher is a multisig‑controlled key; later upgrade to multi‑publisher quorum or challenge game.

### 7.3 TrustPathVerifier (library)
- Verifies the three SMT proofs against `graphRoot`.
- Enforces same `contextId` across leaves.
- Computes `score` per §6 and optionally `require(score ≥ threshold)`.

---

## 8) Off‑chain Components (TrustNet service)

### 8.1 Indexer (deterministic)
- Ingests:
  - ERC‑8004 Reputation events: `NewFeedback`, `FeedbackRevoked`, `ResponseAppended`
  - TrustGraph `EdgeRated`
- Normalizes TrustNet feedback by the rules in §4.2.
- Maintains the latest effective edge per `(rater, target, contextId)`.
- Builds the SMT root and publishes `{graphRoot, epoch}` to RootRegistry.

### 8.2 Root Manifest (for reproducibility)

Publish a manifest alongside each root so anyone can recompute it from public logs:

```json
{
  "chainId": 11155111,
  "contracts": {
    "identityRegistry": "0x..",
    "reputationRegistry": "0x..",
    "validationRegistry": "0x..",
    "trustGraph": "0x..",
    "rootRegistry": "0x.."
  },
  "window": { "fromBlock": 123, "toBlock": 456, "toBlockHash": "0x.." },
  "trustnet": {
    "tag2": "trustnet:v1",
    "contexts": ["trustnet:ctx:payments:v1", "..."],
    "quantizer": [80, 60, 40, 20],
    "valueDecimals": 0
  },
  "smt": {
    "depth": 256,
    "hashLeaf": "keccak256(0x00||K||V)",
    "hashNode": "keccak256(0x01||L||R)",
    "hashEmpty": "keccak256(0x02)"
  },
  "version": "trustnet-v1.1"
}
```

### 8.3 Score API (read‑only)
- `GET /v1/root` → `{ epoch, graphRoot, manifest }`
- `GET /v1/contexts` → canonical + registered contexts
- `GET /v1/score/:decider/:target?contextTag=...`
  - Returns `{ score, epoch, why, proof }`
  - `why` MUST include the exact source events (txHash/logIndex) and any `feedbackURI/Hash`.

**Endorser selection (MVP):** choose the endorser `E` that maximizes `scoreNumerator` (§6), with stable tie‑break (e.g., lowest address).

### 8.4 Gateway / policy engine
- Verifies proof off‑chain (fast path) or on‑chain (hard gates).
- Applies thresholds by context:
  - `payments`: require `score ≥ +1` from any decider in `{FinOps, Platform}`
  - `code-exec`: require `score ≥ +2` from k‑of‑n `{SecOps, Platform, TeamLead}` (post‑MVP helper)

Issues short‑lived grants (JWT/API tokens) and optionally writes receipts.

---

## 9) Policies & Flows (examples)

### 9.1 Payments ≤ $50 (off‑chain)
- `FinOps→CFO = +2`
- `CFO→PayBot = +1` (ERC‑8004 TrustNet feedback in `trustnet:ctx:payments:v1`)
- Direct `FinOps→PayBot` absent (0)

Score: `path=2*1=2`, `score=+1` → **ALLOW** with $50 cap and TTL 5 minutes.  
Why: *FinOps→CFO +2; CFO→PayBot +1; no direct override.*

### 9.2 Code‑exec (on‑chain PR run)
- Require `score ≥ +2` in `trustnet:ctx:code-exec:v1`
- `SecOps→Auditor +2`, `Auditor→RepoBot +2` ⇒ score `+2`
- Contract verifies `TrustPathVerifier` against RootRegistry root; caches admission for that epoch.

### 9.3 DeFi re‑balance (on‑chain)
- `ProtocolCouncil` as decider; require `score ≥ +1` in `trustnet:ctx:defi-exec:v1`.

---

## 10) Security, Privacy, & Integrity

- **Anchors required** — high‑impact gates MUST restrict acceptable deciders (and optionally require k‑of‑n).
- **No sign‑flip** — decider distrust of endorsers cannot create positive trust (§6.1).
- **Direct override respected** — a strong negative `D→T` prevents positive admission for positive thresholds.
- **Context binding** — all proof leaves share the same `contextId`.
- **Revocations respected** — revoked ERC‑8004 feedback MUST be ignored (§4.2).
- **Reorg safety** — indexer waits N confirmations; epochs strictly increase.
- **Privacy** — scope by context; avoid PII; evidence is referenced by URI + hash.

**Trust model (MVP):** reproducible but not fully trustless. The root publisher can be audited via manifests; harden later via:
- multi‑publisher quorum,
- challenge/fraud‑proof game,
- zk‑indexed root (future).

---

## 11) Performance Notes

- Off‑chain verification is fast (hashing a few dozen siblings per proof in typical sparse trees).
- On‑chain verification cost depends on proof size; compact proofs are recommended and can be further optimized with multiproofs (post‑MVP).
- Root cadence: hourly for MVP; can move to event‑driven with debounce.

---

## 12) Open‑Source Split

- **Open (MIT/Apache‑2.0)**: contracts (TrustGraph, RootRegistry, TrustPathVerifier), SMT libs, SDKs, reference indexer & API, spec & test vectors.
- **Commercial add‑ons**: HA indexer, proof compression/multiproofs, policy UI, managed Score API with SLAs, premium risk connectors, zk proving.

---

## 13) Roadmap (post‑MVP)

- k‑of‑n aggregation helpers and multiproofs on‑chain,
- richer context registries and governance,
- Validation Registry ingestion (validator→agent edges),
- attestations (TEE/SCITT/RATS),
- optional ZK threshold proofs (hide endorser, reveal only “≥ threshold”).

---

## 14) Test Vectors

Assume missing edges are absent ⇒ `level = 0`.

1. `lDT=0, lDE=+2, lET=+1` → `path=2` → `score=+1`
2. `lDT=0, lDE=+2, lET=+2` → `path=4` → `score=+2`
3. `lDT=−2, lDE=+2, lET=+2` → `num=0` → `score=0`
4. `lDT=0, lDE=+1, lET=+1` → `num=1` → `score=0`
5. `lDT=0, lDE=−2, lET=−2` → `path=0` → `score=0` *(no sign‑flip)*

---

## 15) License & Acknowledgements

- **Code**: MIT (contracts) + Apache‑2.0 (libs/SDKs/server).
- **Docs**: CC BY‑SA 4.0.
- **Built for** ERC‑8004 ecosystems; thanks to early adopters & reviewers.
