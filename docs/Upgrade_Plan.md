# TrustNet MVP Upgrade Plan (Legacy `trust-net` repo → Unified Spec MVP v0.4)

**Goal:** adapt the legacy repository `trust-net` to the **TrustNet Unified Spec MVP v0.4** and produce an implementable, testable plan to **ship + verify** the MVP.

This document is written as an *engineering upgrade guide*:
- what you already have in the legacy repo
- what the v0.4 MVP needs
- the concrete refactor steps (with file-level pointers)
- verification & “definition of done” checklists

---

## 0) What “MVP shipped” means (practical)

You can call a TrustNet service (or run locally) and get back a **decision bundle**:

- `ALLOW` / `ASK` / `DENY` for `(decider, target, context)`
- the selected endorser (optional) and the used levels `lDE`, `lET`, `lDT`
- Merkle proofs for those three edges
- the epoch root + manifest + signature

A gateway/plugin can then verify, offline:
- the root authenticity (signature or chain anchor)
- each Merkle proof against that root
- the scoring rule and thresholds
- the freshness/TTL policy

…and enforce the action.

---

## 1) Legacy repo audit (what you can reuse)

### 1.1 Rust workspace (`/crates`)
- `core/`  
  Types (`Level`, `ContextId`), hashing (`compute_edge_key`, `compute_leaf_hash`), quantizer, canonical contexts.
- `smm/`  
  Sparse Merkle Map implementation (`Smm`, `SmmBuilder`, `SmmProof`). Currently “simple” (empty nodes hash to 0) and leaf value is 1 byte.
- `indexer/`  
  SQLite storage, log listener for **NewFeedback** (custom ABI), latest-wins update into `edges`, periodic SMM building, and **root publishing** to on-chain `RootRegistry`.
- `api/`  
  Read-only HTTP server (Axum) with endpoints like `/v1/score`, `/v1/proof`, `/v1/rating`. Uses an in-memory SMM cache rebuilt from DB.

### 1.2 Solidity (`/solidity`)
- `TrustGraph.sol` emits `EdgeRated` events (events-only trust edges).
- `RootRegistry.sol` stores `{epoch, root}` on-chain.
- `TrustPathVerifier.sol` verifies proofs and computes **legacy product scoring**.

**Observation:** The Rust indexer currently ingests only `NewFeedback` logs and does not ingest `TrustGraph.EdgeRated` yet.

---

## 2) Unified Spec MVP v0.4 deltas (what must change)

At a minimum for the v0.4 MVP:
1. **Identity model:** move from `address` to `PrincipalId (bytes32)` for rater/endorser/target.
2. **Decision semantics:** hard veto (`lDT == -2`) must be `DENY`; *endorsements do not propagate negative trust*.
3. **Leaf value format:** commit more than just 1 byte (at least level; optionally `updatedAt` + `evidenceHash`).
4. **Storage model:** introduce `edges_raw` (append-only) + `edges_latest` (latest-wins), and a deterministic ordering tuple.
5. **Root manifest + root authenticity:** server-mode roots must be signed; chain-mode roots anchored in `RootRegistry` can be additionally signed.
6. **API:** add `/v1/root` + `/v1/decision` returning a DecisionBundle; keep `/v1/score` only as a legacy alias if needed.
7. **Proof verification vectors:** cross-language vectors to guarantee Rust/TS/Solidity compute identical hashes & proofs.

---

## 3) Gap analysis (legacy → v0.4) with concrete pointers

### 3.1 PrincipalId
- Legacy: `Address` (20 bytes) everywhere (`core/types.rs`, `core/hashing.rs`, DB schema, API params).
- v0.4: `PrincipalId` (32 bytes) with deterministic encoding:
  - EVM address is left-padded to 32 bytes
  - non-EVM identities can be `agentRef:` etc (server/local only)

**Impact:** This touches *everywhere* the rater/target is stored or hashed:
- `core/hashing.rs::compute_edge_key`
- all DB tables and queries
- API request/response schemas

### 3.2 Scoring & decisioning
- Legacy API: computes integer score via product rule and returns `score: i8`.
- v0.4: decision is `ALLOW|ASK|DENY` with monotonic scoring:
  - `lDT == -2` ⇒ **DENY** (regardless of endorsers)
  - `lDT > 0` ⇒ direct score = `lDT`
  - else via endorsers: pick best `min(lDE, lET)` but only if `lDE>0 && lET>0`

**Impact:** update:
- `crates/api/src/main.rs` scoring logic
- `solidity/TrustPathVerifier.sol` (if you keep on-chain verifier)

### 3.3 Merkle map correctness & performance
Legacy `smm/` is a good starting point but needs two upgrades:
1) consistent “default hash per level” model (for correctness + proof compression), and  
2) leaf-value bytes (not only `u8`).

**Impact:** `crates/smm/src/{builder.rs,node.rs,proof.rs}` and `core/hashing.rs`.

### 3.4 Storage
Legacy DB stores only the reduced latest edge in `edges` table.
v0.4 wants:
- `edges_raw` (append-only stream; supports reorg safety / audit)
- `edges_latest` derived by deterministic latest-wins

**Impact:** `crates/indexer/migrations/*`, `crates/indexer/src/storage/*`, and API queries.

### 3.5 Root manifest + signature
Legacy stores `manifest` as a string, but there is no `manifestHash` nor publisher signature.
v0.4: gateway must verify root authenticity.

**Impact:** extend epoch record schema and API `/v1/root`.

---

## 4) Recommended target architecture (minimal but spec-aligned)

### 4.1 Keep your Rust workspace, but add an “engine” crate

Suggested crates (minimal disruption):
- `trustnet-core` (existing): types + hashing + canonical contexts
- `trustnet-smm` (existing): SMM + proofs (upgrade)
- `trustnet-engine` (NEW): decision selection + thresholds + deterministic tie-breaks
- `trustnet-server` (rename `api` or keep `api`): HTTP endpoints `/v1/root` and `/v1/decision`
- `trustnet-indexer` (existing): optional chain ingestion + root building

### 4.2 Run mode strategy (ship fastest)
- **Milestone A (Local mode):** manually seed `edges_latest` and run a gateway/plugin against local DB (no chain).
- **Milestone B (Server mode):** add private log ingest + root signing + proofs + verified decision bundles.
- **Milestone C (Chain mode):** extend indexer to ingest `TrustGraph.EdgeRated` + publish roots on-chain.

---

## 5) Step-by-step implementation plan (ordered)

### Step 1 — Introduce PrincipalId (core + API + storage types)
1. Add `PrincipalId([u8;32])` to `crates/core/src/types.rs`
   - helpers: `from_evm_address(Address)`, `to_evm_address_opt()`
   - parsing from string: `"0x…"`, `"agentRef:…"` (server/local only)
2. Replace all `Address` usages for rater/target in:
   - DB models
   - API request/response
   - hashing functions
3. Update `compute_edge_key` to hash:
   - `keccak256( raterPrincipalId || targetPrincipalId || contextId )`

**Deliverable:** compilation passes; unit tests for address→principal conversion.

---

### Step 2 — Storage schema upgrade: `edges_raw` + `edges_latest`
1. Add a new migration (do NOT mutate the old one):
   - `edges_raw` append-only:
     - `id INTEGER PRIMARY KEY AUTOINCREMENT`
     - `rater_pid BLOB(32)`, `target_pid BLOB(32)`, `context_id BLOB(32)`
     - `level_i8 INTEGER`
     - `updated_at_u64 INTEGER` (unix seconds)
     - `evidence_hash BLOB(32)` (nullable or default 0)
     - `source TEXT` (`server`, `trust_graph`, `erc8004`)
     - ordering tuple fields:
       - chain: `block_number`, `tx_index`, `log_index`, `tx_hash`
       - server: `seq` (or reuse id)
   - `edges_latest` reduced:
     - primary key `(rater_pid, target_pid, context_id)`
     - stores the winning row’s `level`, `updated_at`, `evidence_hash`, `source`, and its ordering tuple
2. Implement “latest-wins upsert” function in `crates/indexer/src/storage/edge.rs`:
   - compare ordering tuple, update only if newer
3. Add query `get_edges_latest_for_root(epoch_time, ttl_policy)`.

**Deliverable:** deterministic reduction is unit-tested.

---

### Step 3 — SMM v1 upgrade (hashes + leafValue bytes + proofs)
1. Change SMM API from `(key: B256, value: u8)` to `(key: B256, leaf_value: Vec<u8>)`.
2. Implement **default hashes per level**:
   - `default[0] = 0x00..00` (empty leaf)
   - `default[h+1] = keccak256(0x01 || default[h] || default[h])`
3. Make proof verification use default hashes (enables compressed proofs later).
4. Define leaf value encoding used by *this MVP*:
   - MVP-min: `levelEnc (1 byte)`
   - MVP+ (recommended): `levelEnc (1) + updatedAtEnc (8) + evidenceHash (32)` = 41 bytes
5. Add test vectors for:
   - compute_edge_key
   - leaf hash
   - root for a tiny set of edges
   - membership proof verification
   - non-membership proof verification

**Deliverable:** `trustnet-smm` passes vectors and roundtrip proof tests.

---

### Step 4 — Root builder + manifest + signature (server mode)
1. Create a `RootBuilder` module (can live in `indexer/` or new `server/`):
   - input: `edges_latest_for_root` (after TTL filtering)
   - output: `(epoch, graphRoot, manifestJsonCanonical, manifestHash, publisherSig)`
2. Manifest must include (minimal):
   - `specVersion`, `epoch`, `graphRoot`
   - `sourceMode` (`server` / `chain`)
   - `ttlPolicy`, `quantizer`, `contextsHash`
   - `window` / `streamRange` (depending on mode)
3. Sign `(epoch || graphRoot || manifestHash)` with a configured publisher key.
4. Store epoch record in DB with those fields.

**Deliverable:** `/v1/root` returns a signed root bundle and the verifier can validate it.

---

### Step 5 — Decision engine (v0.4 rule) + `/v1/decision`
1. Implement `trustnet-engine`:
   - compute `lDT` (direct edge proof)
   - find candidate endorsers:
     - `lDE>0` and `lET>0`
     - scoreCandidate = `min(lDE, lET)`
     - tie-break deterministic (e.g., by endorser principalId bytes ascending)
2. Threshold policy (per context):
   - `allow ≥ allowThreshold`
   - `ask  ≥ askThreshold`
   - else deny
3. API `/v1/decision` returns:
   - decision + score + endorser (optional)
   - proofs for DT, DE, ET
   - root bundle (or root reference) needed to verify

**Deliverable:** gateway can verify response without trusting server.

---

### Step 6 — Keep/upgrade chain mode (optional but aligns with legacy repo)
1. Extend `indexer` to ingest `TrustGraph.EdgeRated` logs.
2. For chain signals: set `updatedAt` from block timestamp (RPC), and ordering tuple from `(block, txIndex, logIndex)`.
3. Publish roots to on-chain `RootRegistry` (legacy already does this).
4. Optionally extend `RootRegistry` to store `manifestHash` and/or a `manifestURI`.

**Deliverable:** chain-anchored roots are verifiable by third parties.

---

## 6) Verification plan (must-have tests)

### 6.1 Unit & vector tests
- SMM hashing vectors (Rust and Solidity/TS)
- proof tampering fails
- latest-wins reduction correct ordering
- decision invariants:
  - `lDT=-2` always denies
  - endorsers never propagate negative trust
  - context mismatch denies/invalid

### 6.2 End-to-end tests (recommended)
Spin up:
- SQLite DB
- server
- seed 5–20 edges
- build root
- request `/v1/decision`
- verify bundle in a separate verifier module

---

## 7) Migration strategy (how to adapt without pain)

- Keep legacy tables in place; add new migrations for v0.4 tables.
- If ‘old data’ matters: re-index from source (chain logs/private log) into new schema.
- Keep legacy endpoints (`/v1/score`) as a compatibility shim that calls the new engine but returns `score`.

---

## 8) What to postpone safely (don’t block MVP)

- Proof compression (bitmap) — can ship uncompressed 256-sibling proofs first.
- ERC-8004 ingestion — can be added after server+gateway verification works.
- Multi-publisher quorum roots — later.

---

## Appendix A — Minimal v0.4 DB schema sketch (SQLite)

```sql
CREATE TABLE edges_raw (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rater_pid BLOB NOT NULL,
  target_pid BLOB NOT NULL,
  context_id BLOB NOT NULL,
  level_i8 INTEGER NOT NULL,
  updated_at_u64 INTEGER NOT NULL,
  evidence_hash BLOB,
  source TEXT NOT NULL,

  -- chain ordering (nullable for server mode)
  chain_id INTEGER,
  block_number INTEGER,
  tx_index INTEGER,
  log_index INTEGER,
  tx_hash BLOB,

  -- server ordering (nullable for chain mode)
  seq INTEGER
);

CREATE TABLE edges_latest (
  rater_pid BLOB NOT NULL,
  target_pid BLOB NOT NULL,
  context_id BLOB NOT NULL,
  level_i8 INTEGER NOT NULL,
  updated_at_u64 INTEGER NOT NULL,
  evidence_hash BLOB,
  source TEXT NOT NULL,

  chain_id INTEGER,
  block_number INTEGER,
  tx_index INTEGER,
  log_index INTEGER,
  tx_hash BLOB,
  seq INTEGER,

  PRIMARY KEY (rater_pid, target_pid, context_id)
);

CREATE TABLE epochs (
  epoch INTEGER PRIMARY KEY,
  graph_root BLOB NOT NULL,
  manifest_json TEXT NOT NULL,
  manifest_hash BLOB NOT NULL,
  publisher_sig BLOB NOT NULL,
  edge_count INTEGER NOT NULL,
  created_at_u64 INTEGER NOT NULL
);
```

---

## Appendix B — Minimal `/v1/decision` response (shape)

```json
{
  "decision": "ALLOW|ASK|DENY",
  "score": 2,
  "contextId": "0x..",
  "decider": "0x..",
  "target": "0x..",
  "endorser": "0x.. or null",

  "root": {
    "epoch": 123,
    "graphRoot": "0x..",
    "manifest": { "...": "..." },
    "manifestHash": "0x..",
    "publisherSig": "base64..."
  },

  "proofs": {
    "dt": { "isMembership": true|false, "key": "0x..", "leafValue": "0x..", "siblings": ["0x.."] },
    "de": { "...": "..." },
    "et": { "...": "..." }
  },

  "why": {
    "lDT": 0,
    "lDE": 2,
    "lET": 1
  }
}
```

---

## Appendix C — Decision algorithm (pseudocode)

```
if lDT == -2: return DENY
if lDT > 0: score = lDT
else:
  score = max_{E} min(lDE, lET) over E where lDE>0 and lET>0
decision = ALLOW if score >= allowThreshold
        = ASK   if score >= askThreshold
        = DENY  otherwise
```

