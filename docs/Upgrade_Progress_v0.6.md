# TrustNet v0.6 Upgrade Progress

Last updated: 2026-02-04

Status legend: TODO, IN PROGRESS, DONE, N/A

## Baseline (already in repo)

- DONE: PrincipalId + ContextId types (`crates/core`)
- DONE: Sparse Merkle Map with default hashes + proofs (`crates/smm`)
- DONE: edges_raw + edges_latest schema (v0.4) (`crates/indexer/migrations`)
- DONE: v0.4 decision engine + API endpoints (`crates/engine`, `crates/api`)

## Upgrade checklist (v0.6 deltas)

- DONE: Add `messaging` context, update context registry hash, and refresh allowlists (core + api + solidity).
- DONE: Introduce `SubjectId` and binding policy metadata (core types + hashing helpers).
- DONE: Extend `RatingEvent` model with `evidence_uri`, `observed_at`, `source`.
- DONE: Update ERC-8004 ABI parsing to string `tag1/tag2/endpoint`, `value/valueDecimals` (indexer listener).
- DONE: Implement TrustNet guard: `endpoint == "trustnet"` and `tag2 == "trustnet:v1"`.
- DONE: Implement context parsing from string or hex for ERC-8004.
- DONE: Resolve `agentId -> agentWallet` at block height (identity registry) and use wallet PrincipalId.
- DONE: Ingest `ResponseAppended` into `feedback_responses_raw`.
- DONE: Verify `ResponseAppended` payloads and store verified stamps in `feedback_verified`.
- DONE: Add tables: `feedback_raw`, `feedback_responses_raw`, `feedback_verified`.
- DONE: Extend edges tables with `evidence_uri`, `observed_at`, optional `subject_id`.
- DONE: Add `observed_at` ordering for latest-wins reduction.
- DONE: Update Root Manifest to spec v0.6 fields (`erc8004TrustEdgeGuard`, `erc8004QuantizationPolicy`, `erc8004TargetBindingPolicy`).
- DONE: Implement JCS canonicalization for manifest hashing.
- DONE: Add evidence gating in decision engine (require **verified** evidence for positive ET/DT by context).
- DONE: Add constraints to DecisionBundle responses.
- DONE: Update proof JSON format (`type`, `format`) with uncompressed proofs.
- DONE: Update verifier to enforce v0.6 decision + proof requirements.
- DONE: Update `TrustNetContexts.sol` and optionally `TrustPathVerifier.sol` for v0.6.
- DONE: Add OpenClaw plugin reference + ActionReceipt emission.
- DONE: Add/refresh test vectors and end-to-end verification tests.

## Open questions / decisions
- Do we need bitmap-compressed proofs for MVP, or ship uncompressed first?
- Should evidence gating apply to `DT` by default or only to `ET`?
- How to model `observed_at` across mixed sources if chain + private log are combined?
