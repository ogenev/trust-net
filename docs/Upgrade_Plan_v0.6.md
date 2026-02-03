# TrustNet Upgrade Plan (v0.6 Spec)

**Goal:** adapt the current `trust-net` repo to **TrustNet Spec v0.6 (Draft)** while preserving the existing v0.4-compatible pipeline and shipping a verifiable MVP (ERC-8004-first).

**Spec:** `docs/TrustNet_Spec_v0.6.md`

---

## 0) Baseline snapshot (what already exists)

### Rust workspace
- `crates/core`: PrincipalId, ContextId, leaf value encoding (41 bytes), hashing.
- `crates/smm`: Sparse Merkle Map with default hashes and membership/non-membership proofs.
- `crates/engine`: v0.4 decision rule (hard veto, positive-only endorsements).
- `crates/indexer`: chain ingest for `EdgeRated` + ERC-8004 `NewFeedback` (legacy ABI), `edges_raw` + `edges_latest`, root publishing, root manifest (v0.4).
- `crates/api`: `/v1/root`, `/v1/decision`, `/v1/proof`, `/v1/ratings`.
- `crates/verifier`: offline verifier for v0.4 response shapes + action receipts.

### Solidity
- `TrustGraph.sol`, `RootRegistry.sol`, `TrustPathVerifier.sol`, `TrustNetContexts.sol` (v0.4 contexts).

---

## 1) v0.6 deltas vs current repo (high level)

1) **ERC-8004 ingestion semantics**
   - v0.6 requires tag/endpoint *strings*, `tag2 == "trustnet:v1"`, and `endpoint == "trustnet"`.
   - `tag1` can be a context string or `0x` hex string; current parser treats `tag1` as bytes32.
   - v0.6 uses `value` + `valueDecimals` instead of `score` u8; quantization policy must be in manifest.
   - `agentId → agentWallet` binding (identity registry lookup) is required for actionable targets.
   - ResponseAppended events must be ingested into `feedback_responses_raw`.

2) **Identity**
   - v0.6 introduces `SubjectId` vs `ActorPrincipalId` (PrincipalId). Current code only has PrincipalId.
   - Binding policy must be explicit (agentWalletAtBlock).

3) **Contexts**
   - v0.6 canonical set includes `messaging` and excludes `defi-exec`.
   - Context registry hash should reflect the canonical list used by this implementation.

4) **Root Manifest**
   - v0.6 requires `specVersion=trustnet-spec-0.6`, `contextRegistryHash`, `ttlPolicy`, `leafValueFormat`.
   - v0.6 adds ERC-8004 guard + quantization + target binding policy fields.
   - Canonical hashing should use RFC 8785 (JCS) JSON.

5) **Decision/Policy**
   - v0.6 adds evidence gating (require evidence for positive ET/DT based on policy).
   - Decision responses should include `constraints` and `type` fields.

6) **Proof format**
   - v0.6 standardizes JSON proof shape with `type`, `format`, optional compression (bitmap).

7) **OpenClaw integration**
   - v0.6 expects an OpenClaw plugin (or reference implementation) and ActionReceipts.

---

## 2) Upgrade plan (ordered phases)

### Phase 1 — Spec & constants alignment (low risk)

1. Update canonical contexts to match v0.6
   - Add `trustnet:ctx:messaging:v1` and its hash.
   - Remove `defi-exec` from the canonical registry.
   - Update allowlists and registries:
     - `crates/core/src/constants.rs`
     - `crates/indexer/src/root_manifest.rs` (context registry hash)
     - `crates/api/src/main.rs` (context allowlist)
     - `solidity/TrustNetContexts.sol`
   - Add tests confirming hashes.

2. Update spec version strings and doc references
   - `crates/indexer/src/root_manifest.rs` specVersion.
   - Optional: update `README.md` and `crates/indexer/ARCHITECTURE.md` references to v0.6.

**Deliverable:** contexts + manifest version updated with tests.

---

### Phase 2 — Identity & signal model (core + schema)

1. Add `SubjectId` type and binding metadata
   - `crates/core/src/types.rs` (SubjectId, binding policy enum).
   - `crates/core/src/hashing.rs` helper(s) for SubjectId derivation.

2. Extend canonical `RatingEvent` model
   - Add `evidence_uri`, `observed_at`, `source` enum values aligned to v0.6.
   - Keep `evidence_hash` committed; `evidence_uri` stored but not committed.

3. Migrations (new tables + columns)
   - New tables: `feedback_raw`, `feedback_responses_raw`, optional `feedback_verified`.
   - Extend `edges_raw` / `edges_latest` with `evidence_uri`, `observed_at`, optional `subject_id`.
   - Update unique indexes for chain events (already partly in place).
   - Files:
     - `crates/indexer/migrations/*`
     - `crates/indexer/src/storage/*`

**Deliverable:** schema can store v0.6 canonical records and bindings.

---

### Phase 3 — ERC-8004 ingestion to spec v0.6

1. Update ERC-8004 ABI parsing
   - `crates/indexer/src/listener/events.rs`
   - Use string `tag1`, `tag2`, `endpoint` per ERC-8004 (v0.6 guard rules).

2. Implement TrustNet guard + context parsing
   - `endpoint == "trustnet"` AND `tag2 == "trustnet:v1"`.
   - `tag1`:
     - if context string → `contextId = keccak256(utf8(tag1))`
     - else if `0x` hex bytes32 → parse directly

3. Identity binding (agentWallet)
   - Resolve `agentId → agentWallet` using ERC-8004 Identity Registry at block height.
   - Use resolved wallet as `target` PrincipalId (MVP requirement).

4. Ingest `ResponseAppended`
   - Normalize and store `feedback_responses_raw`.

5. ObservedAt ordering
   - Standardize `observed_at` per §9.3 and apply in latest-wins reduction.

**Deliverable:** ERC-8004 events ingested exactly per v0.6 mapping with binding.

---

### Phase 4 — Root manifest + root builder (v0.6)

1. Manifest fields
   - Add `erc8004TrustEdgeGuard`, `erc8004QuantizationPolicy`, `erc8004TargetBindingPolicy`.
   - Include `contextRegistryHash`, `ttlPolicy`, `leafValueFormat`.

2. Canonical hashing
   - Implement JSON canonicalization (RFC 8785 / JCS) for manifestHash.

3. Root builder policy
   - Apply per-context TTL at root build time.
   - Ensure leafValue format is consistent with manifest.

**Deliverable:** `/v1/root` returns v0.6-compliant manifest + hash.

---

### Phase 5 — Decision engine + policy (evidence gating + constraints)

1. Evidence gating
   - Per-context policy for `requireEvidenceForPositiveET` and optional `requireEvidenceForPositiveDT`.
   - Treat missing evidence as neutral for positive edges (per v0.6).

2. Constraints
   - Add `constraints` to decision responses, sourced from policy config.

3. Optional legacy scoring
   - Keep legacy product rule behind a flag, if needed for compatibility.

Files:
- `crates/engine/src/lib.rs`
- `crates/api/src/main.rs`

**Deliverable:** DecisionBundleV1 includes constraints + evidence gating is enforced.

---

### Phase 6 — Proof formats + verifier updates

1. Proof JSON shape
   - Add `type` and `format` fields; keep uncompressed as default.
   - (Optional) add bitmap compression.

2. Verifier updates
   - Validate `DecisionBundleV1` shape + evidence gating.
   - Validate manifestHash via JCS.

Files:
- `crates/api/src/main.rs`
- `crates/verifier/src/lib.rs`
- `crates/smm/src/proof.rs` (optional compression helpers)

**Deliverable:** offline verifier accepts v0.6 responses.

---

### Phase 7 — Solidity alignment (optional but recommended)

1. Update `TrustNetContexts.sol` to include `messaging` and canonical list.
2. Update `TrustPathVerifier.sol` to follow v0.6 evidence gating rules (if kept).
3. Verify `RootRegistry.sol` fields align with manifest hash and optional URI (already mostly aligned).

**Deliverable:** on-chain artifacts match v0.6 assumptions.

---

### Phase 8 — OpenClaw integration & receipts (reference)

1. Add `plugin-openclaw/` reference implementation or stub.
2. Implement ActionReceipt emission:
   - include decision bundle + root bundle + `policyManifestHash` + tool call hashes.
3. Add example config and mapping from tool names to contexts.

**Deliverable:** end-to-end enforcement + receipt flow for OpenClaw.

---

### Phase 9 — Tests & vectors

1. Update test vectors:
   - edgeKey hash, leaf hash, root hash, proof verification.
2. ERC-8004 ingestion tests:
   - tag/endpoint guard, context parsing, agentWallet binding.
3. Evidence gating + constraints tests.
4. End-to-end decision bundle verification test.

Files:
- `crates/core/tests/*`
- `crates/smm/tests/*`
- `crates/indexer/tests/*`
- `crates/api/tests/*`
- `crates/verifier/tests/*`

**Deliverable:** CI-ready tests covering v0.6 invariants.

---

## 3) Migration strategy

- Add new migrations rather than mutating old ones.
- Keep v0.4 data as-is; re-index if you need v0.6 semantics.
- Provide a one-time backfill script to populate `observed_at` and new tables from `edges_raw`.

---

## 4) Definition of done (v0.6 MVP)

A gateway can:
- Fetch `/v1/root` and verify the manifest hash + root authenticity.
- Fetch `/v1/decision` and verify proofs + score + constraints.
- Enforce evidence-gated ALLOW/ASK/DENY for `payments`, `code-exec`, `writes`, `messaging`.
- Optionally ingest ERC-8004 signals and bind agentId → agentWallet.
