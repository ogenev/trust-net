# TrustNet — Verifiable, Explainable Reputation for AI Agents (on ERC‑8004)

**Version:** 1.0 (MVP)  
**Date:** Oct 26, 2025  
**License (docs):** CC BY‑SA 4.0

---

## Abstract

**TrustNet** is a portable, **explainable “trust‑to‑act” layer** for AI agents. It enables gateways and smart contracts to
**admit or deny** an agent’s action (e.g., *pay ≤ $50*, *run CI/CD*, *modify CRM data*) using a **small proof** and a **deterministic, decider‑relative** rule.

TrustNet builds on **ERC‑8004**:
- uses 8004 **Identity** to anchor agent IDs,
- ingests 8004 **Reputation (NewFeedback)** events as signals,
- optionally consumes **Validation** results.

The core of TrustNet is tiny and auditable:
- **Ratings**: signed edges among addresses (deciders, endorsers, targets) scoped by **context** (capability namespace).
- **Commitment**: a single **Sparse Merkle Map** (SMM) root (`graphRoot`) over the *latest* ratings.
- **Proof**: a **2‑hop** membership proof (`D→E`, `E→T`, plus direct `D→T`) with a fixed **integer** scoring rule.
- **Why‑by‑default**: every decision returns the two edges used, so humans can see *who* vouched and *why* it passed.

No tokens. No global social score. No ZK required for MVP (future‑ready).

---

## 0) Motivation

Agent systems now call tools, write code, move money, and act on behalf of users and DAOs. Traditional ACLs or opaque global scores don’t travel across apps and chains. TrustNet answers:

> *“From **my** point of view (decider), may **this agent** perform **this capability** now — and **why**?”*

We scope trust by **context**, compute it via a **transparent two‑hop rule**, and verify it with **small Merkle proofs**.

---

## 1) Goals (MVP)

1. **Decider‑relative trust** — scores are always “as seen by” a chosen **decider/anchor** (e.g., FinOps, SecOps).
2. **Explainable decisions** — every allow/deny ships a short **Why** showing the two edges and the direct override.
3. **Context isolation** — ratings are bound to a **contextId** (e.g., `payments`, `code-exec`, `writes`) to avoid cross‑capability privilege escalation.
4. **Single root, tiny proofs** — one SMM commitment; 2‑hop proofs verify off‑chain and on‑chain.
5. **Open, composable, ERC‑8004‑native** — identities and feedback live on Ethereum; TrustNet adds proofs and policy.

**Non‑goals (MVP)**  
No tokens, staking mechanics, ZK private proofs, or universal ranking. We score **behavioral trust** for **specific capabilities**.

---

## 2) Entities & Identifiers

- **Decider `D`** — an anchor that sets policy (e.g., FinOps, SecOps, ProtocolCouncil).
- **Endorser `E`** — a curator/auditor/team‑lead bridging `D` to `T`.
- **Target `T`** — typically the **agent** being gated.
- **Agent identity** — `agentId` (ERC‑721) plus optional `agentWallet` from 8004 **Identity** metadata.
- **Context `contextId`** — `bytes32` capability namespace:
  `global`, `payments`, `code-exec`, `writes`, `defi-exec` (see §8.4).
- **Address form** — EVM `address` for `D`, `E`, `T` (20 bytes). When using `agentId`, bind it to `agentWallet` if needed for on‑chain gating.

---

## 3) Data Model

### 3.1 Canonical TrustNet rating event (on‑chain, events‑only)
```solidity
event EdgeRated(
  address indexed rater,
  address indexed target,
  int8    level,        // −2..+2
  bytes32 indexed contextId
);
```
- **Semantics**: the **latest** event per `(rater, target, contextId)` prevails (ordered by `(block, txIndex, logIndex)`).
- **Usage**: for **curator edges** (`D→E`) and **direct overrides** (`D→T`).

### 3.2 ERC‑8004 feedback → TrustNet edge (ingestion mapping)
`NewFeedback(agentId, client, score0_100, tag1, tag2, fileUri, fileHash, …)`

- **Guard**: only ingest if `tag2 == keccak256("trustnet:v1")`.
- **Map**:
  - `rater = client`
  - `target = agentWallet(agentId)` (from 8004 Identity metadata; if absent, use internal `AgentKey`)
  - `contextId = tag1`
  - `level = quantize(score0_100)` via fixed buckets:
    - `80..100 → +2`
    - `60..79  → +1`
    - `40..59  →  0`
    - `20..39  → −1`
    - `0..19   → −2`
- **Evidence**: `fileUri/fileHash` can link receipts or audit notes; shown in the Why panel.

### 3.3 Optional: InteractionReceipt (off‑chain)
Deciders can summarize behavior into ratings using signed receipts (success/error/violation, risk, ts, context).

---

## 4) Commitment & Proofs

### 4.1 Sparse Merkle Map (SMM)
- **Key**: `K = keccak256( rater ∥ target ∥ contextId )`
- **Value**: `V = uint8(level + 2)` maps `−2..+2` → `0..4` (1 byte)
- **Leaf**:  `H_leaf  = keccak256( 0x00 ∥ K ∥ V )`
- **Inner**: `H_node  = keccak256( 0x01 ∥ left ∥ right )` *(positional)*
- **Default**: unseen keys are **neutral** (`level=0 → V=2`). Proofs may demonstrate **non‑membership** for `D→T`.

An off‑chain **Indexer** keeps the latest edges, builds the SMM, and publishes `{graphRoot, epoch}` to **RootRegistry**.

### 4.2 Two‑hop proof
A score from **Decider `D`** to **Target `T`** via **Endorser `E`** in a **context**:

- Membership for `D→E`, `E→T`
- Membership **or** non‑membership for `D→T` (direct override)
- All three **share the same `contextId`**

**TrustPathProof (conceptual)**
```json
{
  "graphRoot": "0x..", "epoch": 123,
  "contextId": "0xCTX..",
  "D": "0x..", "E": "0x..", "T": "0x..",
  "lDE": 2, "merkleDE": [...],
  "lET": 1, "merkleET": [...],
  "lDT": 0, "merkleDT": [...], "dtIsAbsent": true
}
```

---

## 5) Scoring (normative)

Let `l ∈ {−2, −1, 0, +1, +2}`.

```
sumProducts    = lDE * lET
scoreNumerator = 2*lDT + sumProducts
score          = clamp( scoreNumerator / 2 , −2, +2 )
```

- Division is **integer toward zero** (EVM semantics).
- Clamp saturates to `[-2, +2]`.
- Deterministic examples:

| lDT | lDE | lET | Numerator | Score |
|:--:|:--:|:--:|:--:|:--:|
|  0 | +1 | +1 |  1 |  0 |
|  0 | +2 | +1 |  2 | +1 |
|  0 | +2 | +2 |  4 | +2 |
| −2 | +2 | +2 |  0 |  0 |

---

## 6) On‑chain Components

### 6.1 TrustGraph (events‑only)
- Emits `EdgeRated` to record curator and override edges.
- No storage, no scoring, minimal gas.

### 6.2 RootRegistry
- Stores active `{graphRoot, epoch}` (monotonically increasing).
- On chain anchor; verifiers check proofs against this root.

### 6.3 TrustPathVerifier (library)
- Verifies the three SMM paths against `graphRoot`.
- Enforces **same context** across leaves.
- Computes the **deterministic score**, or `require(score ≥ threshold)`.

> *Pattern*: contracts verify once per epoch and cache `admitted[D][T][epoch] = true`.

---

## 7) Off‑chain Components

### 7.1 Indexer
- Ingests ERC‑8004 `NewFeedback` (with guard on `tag2`) and TrustGraph `EdgeRated`.
- Maintains **latest‑wins** per `(rater, target, context)` using `(block, txIndex, logIndex)`.
- Builds SMM → publishes `{graphRoot, epoch}` (e.g., hourly).

**Root Manifest (published alongside root)**
```json
{
  "chainId": 11155111,
  "contracts": { "e8004Identity": "0x..", "e8004Reputation": "0x..", "trustGraph": "0x.." },
  "window": { "fromBlock": 123, "toBlock": 456, "toBlockHash": "0x.." },
  "quantizer": [80,60,40,20],
  "defaultLevel": 0,
  "contextRegistryHash": "0x..",
  "version": "trustnet-v1"
}
```
This enables **independent recomputation** of the root from public logs.

### 7.2 Score API (read‑only)
- `GET /v1/root` → `{ epoch, graphRoot, manifest }`
- `GET /v1/context` → list of canonical contexts
- `GET /v1/score/:decider/:target?contextId=0x...`
  - Returns `{ score, epoch, path:{endorser,lDE,lET,lDT}, proof:{...} }`
  - Chooses **best endorser** by maximizing numerator; stable tie‑breaks.

### 7.3 Gateway / Policy Engine
- Verifies proof (off‑chain or on‑chain), applies thresholds:
  - `payments`: require `≥ +1` from any of `{FinOps, Platform}`
  - `code-exec`: require `≥ +2` from k‑of‑n `{SecOps, Platform, TeamLead}`
- Issues short‑lived **grants** (JWT/API tokens); records receipts.

---

## 8) Policies & Flows

### 8.1 Payments ≤ $50 (off‑chain)
- `FinOps→CFO = +2`, `CFO→PayBot = +1` (8004 feedback), direct `FinOps→PayBot = 0`.
- Score `= (0 + 2)/2 = +1` → **ALLOW**, grant with $50 cap, TTL 5 min.
- Why: *FinOps→CFO +2; CFO→PayBot +1; direct 0* (link to receipt via `fileUri`).

### 8.2 Code‑exec (on‑chain PR run)
- Require `≥ +2` from k‑of‑n `{SecOps, Platform, TeamLead}`.
- `SecOps→Auditor +2`, `Auditor→RepoBot +2` ⇒ +2; others may be neutral.
- Contract verifies TrustPathVerifier; caches admission for this epoch.

### 8.3 DeFi re‑balance (on‑chain)
- `ProtocolCouncil` as decider; require `≥ +1` in `defi-exec`.

### 8.4 Contexts (canonical)
`keccak256("trustnet:ctx:global:v1")`, `…:payments:v1`, `…:code-exec:v1`, `…:writes:v1`, `…:defi-exec:v1`.

---

## 9) Security, Privacy, & Integrity

- **Anchors required** — sensitive gates must restrict deciders to allow‑listed anchors or councils (k‑of‑n).
- **Direct veto respected** — `D→T = −2` neutralizes positive paths.
- **Context binding** — all proof leaves share the same `contextId`.
- **Default semantics** — missing `D→T` means **0**; non‑membership proof allowed.
- **Reorg safety** — indexer waits N confirmations; epochs strictly increase.
- **Privacy** — scope by context; avoid PII; evidence lives as hashed URIs when needed.

**Trust model (MVP)** — *trust‑minimized, reproducible*: inputs are public logs; transform is deterministic; roots can be recomputed by anyone using the **Root Manifest**. Hardening options:
- multi‑publisher quorum,
- edge‑set Merkle commitment,
- challenge game (fraud‑proof),
- zk‑indexed root (future).

---

## 10) Performance Notes

- Off‑chain verify: O(tree depth) hashing; typical < 1 ms per path when cached.
- On‑chain verify: three membership paths; target ≤ ~300k gas (once per epoch; reuse via cache).
- Root cadence: hourly (MVP); can be event‑driven with debounce.

---

## 11) Open‑Source Split

- **Open (MIT/Apache‑2.0)**: contracts (TrustGraph, RootRegistry, TrustPathVerifier), SMM libs, SDKs, reference indexer & API, spec & test vectors.
- **Commercial add‑ons**: HA indexer, proof compression/multiproofs, Policy Studio UI, managed Score API with SLAs, premium risk connectors, ZK proving service.

---

## 12) Roadmap (post‑MVP)

- k‑of‑n & median aggregation helpers on‑chain,
- **3‑hop** (or path‑diversity) option for discovery (keep 2‑hop for gates),
- EAS/Sign mirrors of ratings; DID adapters,
- Attestation adapters (TEE/SCITT/RATS),
- ZK threshold proofs (hide endorser, reveal only “≥ threshold”).

---

## 13) Test Vectors

Assume `contextId = global`, missing edges = 0.

1. `lDT=0, lDE=+2, lET=+1` → `num=2` → `score=+1`
2. `lDT=0, lDE=+2, lET=+2` → `num=4` → `score=+2`
3. `lDT=−2, lDE=+2, lET=+2` → `num=0` → `score=0`
4. `lDT=0, lDE=+1, lET=+1` → `num=1` → `score=0`

---

## 14) License & Acknowledgements

- **Code**: MIT (contracts) + Apache‑2.0 (libs/SDKs/server).
- **Docs**: CC BY‑SA 4.0.
- **Built for** ERC‑8004 ecosystems; thanks to early adopters & reviewers.
