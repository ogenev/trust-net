# TrustNet v0.7 Implementation Tracker

Last updated: 2026-02-19
Spec baseline: `docs/TrustNet_Spec_v0.7.md`
Tracking scope: OpenClaw-first Local Mode (L0 default), then L1 features, then optional local-verifiable.

## Purpose
This document is the single source of truth for planning and tracking v0.7 implementation work.
Update this file after each implemented item so status, evidence, and validation stay current.

## Update Protocol (Required After Each Implementation)
1. Change item `Status` in the backlog table.
2. Add completion date and implementation evidence (PR/commit and key file paths).
3. Add a short entry in `Implementation Log`.
4. Record validation command results (or failures) in `Validation Log`.

## Status Legend
- `Planned`: not started
- `In Progress`: actively being implemented
- `Blocked`: waiting on dependency/decision
- `Done`: merged and validated

## Milestones
- Sprint 1 (2026-02-19 to 2026-02-26): L0 local-first runtime must ship
- Sprint 2 (2026-02-27 to 2026-03-06): L1 identity and trust circles
- Sprint 3 (2026-03-09 to 2026-03-13): optional local-verifiable sidecar/API polish

## Backlog
| ID | Priority | Sprint | Task | Status | Owner | Target Date | Evidence (PR/Commit) | Notes |
|---|---|---|---|---|---|---|---|---|
| TN-001 | P0 | Sprint 1 | Flip repo/docs default from v0.6 anchored-first to v0.7 local-first | Done | Codex | 2026-02-20 | 59bd553 (2026-02-18) | Merged and pushed |
| TN-002 | P0 | Sprint 1 | Refactor plugin config to mode-based (`local-lite`, `local-verifiable`) | Done | Codex | 2026-02-20 | a4241be (2026-02-18) | Merged and pushed |
| TN-003 | P0 | Sprint 1 | Replace default context registry with strict v0.7 `agent-collab` contexts (no legacy aliases) | Done | Codex | 2026-02-21 | fe2a44f (2026-02-18) | Merged and pushed |
| TN-004 | P0 | Sprint 1 | Add local trust store (`edges_latest`, `receipts`, `agents`) for plugin runtime | Done | Codex | 2026-02-21 | d6eedc4 (2026-02-18) | Merged and pushed |
| TN-005 | P0 | Sprint 1 | Implement local decision engine in plugin (same scoring semantics as Rust engine) | Done | Codex | 2026-02-22 | 3912811 (2026-02-18) | Merged and pushed |
| TN-006 | P0 | Sprint 1 | Replace plugin `before_tool_call` flow with local compute for L0 | Done | Codex | 2026-02-22 | 2241b5d (2026-02-18) | Merged and pushed |
| TN-007 | P0 | Sprint 1 | Implement ASK actions writing trust edges (`allow once/ttl/always/block`) | Done | Codex | 2026-02-23 | 82a12e8 (2026-02-18) | Merged and pushed |
| TN-008 | P0 | Sprint 1 | Switch receipt format to v0.7 local receipt and persist for high risk calls | Done | Codex | 2026-02-24 | b48ff1c (2026-02-18) | Merged and pushed |
| TN-009 | P0 | Sprint 1 | Rewrite plugin integration tests for local-first behavior | Done | Codex | 2026-02-25 | e693946 (2026-02-18) | Merged and pushed |
| TN-010 | P1 | Sprint 2 | Add Trust Circles policy model (`onlyMe`, `myContacts`, `openclawVerified`, `custom`) | Done | Codex | 2026-03-02 | 411a55a (2026-02-19) | Merged and pushed |
| TN-011 | P1 | Sprint 2 | Add Agent Card import/verify/store (`openclaw.agentCard.v1`) | Done | Codex | 2026-03-03 | 6e6d776 (2026-02-19) | Merged and pushed |
| TN-012 | P1 | Sprint 2 | Add trust management commands/workflows (`trust`, `block`, `endorse`, `status`) | In Progress | Codex | 2026-03-05 | local-uncommitted (2026-02-19) | Durable confirmation tickets + trust workflow actions implemented and validated; pending commit |
| TN-013 | P2 | Sprint 3 | Make sidecar/API proof flow optional for `local-verifiable` mode only | Planned | TBD | 2026-03-10 | - | L1/L0 unaffected |
| TN-014 | P2 | Sprint 3 | Update API decision contract for optional-proof mode | Planned | TBD | 2026-03-11 | - | Keep compatibility path |
| TN-015 | P2 | Sprint 3 | Update verifier/CLI for v0.7 local receipt while keeping legacy receipt compatibility | Planned | TBD | 2026-03-12 | - | Dual-format parsing |

## Current Sprint Focus
- Sprint 1 P0 (TN-001 through TN-009) is complete and merged.
- Sprint 2 progress: TN-010 and TN-011 are complete and merged.
- TN-012 is now active (trust management workflows with explicit confirmation).

## Definition of Done
An item may move to `Done` only when all apply:
1. Implementation merged.
2. Acceptance behavior validated with tests.
3. Tracker updated with evidence and validation logs.

## Validation Commands
Rust workspace validation (run when Rust code changes are included):
```bash
cargo nextest run --workspace
cargo +nightly fmt --all
RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked
```

Plugin validation (run when plugin changes are included):
```bash
cd plugin-openclaw
npm test
```

## Validation Log
| Date | Scope | Command | Result | Notes |
|---|---|---|---|---|
| 2026-02-18 | Tracker setup | N/A | PASS | Initial tracker created |
| 2026-02-18 | Workspace baseline | `cargo nextest run --workspace` | PASS | 135 passed, 0 failed |
| 2026-02-18 | Workspace baseline | `cargo +nightly fmt --all` | PASS | No formatting changes required |
| 2026-02-18 | Workspace baseline | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-001 | `cargo nextest run --workspace` | PASS | 135 passed, 0 failed |
| 2026-02-18 | TN-001 | `cargo +nightly fmt --all` | PASS | PASS (no formatting changes required) |
| 2026-02-18 | TN-001 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | PASS (no warnings/errors) |
| 2026-02-18 | TN-001 | `cd plugin-openclaw && npm test` | PASS | 4 passed, 0 failed |
| 2026-02-18 | TN-002 | `cd plugin-openclaw && npm test` | PASS | 6 passed, 0 failed |
| 2026-02-18 | TN-002 | `cargo nextest run --workspace` | PASS | 135 passed, 0 failed |
| 2026-02-18 | TN-002 | `cargo +nightly fmt --all` | PASS | No formatting changes required |
| 2026-02-18 | TN-002 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-003 | `cd plugin-openclaw && npm test` | PASS | 6 passed, 0 failed |
| 2026-02-18 | TN-003 | `cd solidity && forge test --match-contract TrustNetContextsTest` | PASS | 10 passed, 0 failed |
| 2026-02-18 | TN-003 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-003 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-003 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-004 | `cd plugin-openclaw && npm test` | PASS | 7 passed, 0 failed |
| 2026-02-18 | TN-004 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-004 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-004 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-005 | `cd plugin-openclaw && npm test` | PASS | 14 passed, 0 failed |
| 2026-02-18 | TN-005 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-005 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-005 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-006 | `cd plugin-openclaw && npm test` | PASS | 16 passed, 0 failed |
| 2026-02-18 | TN-006 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-006 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-006 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-007 | `cd plugin-openclaw && npm test` | PASS | 21 passed, 0 failed |
| 2026-02-18 | TN-007 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-007 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-007 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-008 | `cd plugin-openclaw && npm test` | PASS | 24 passed, 0 failed |
| 2026-02-18 | TN-008 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-008 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-008 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-009 | `cd plugin-openclaw && npm test` | PASS | 25 passed, 0 failed |
| 2026-02-18 | TN-009 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-009 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-009 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-18 | TN-010 | `cd plugin-openclaw && npm test` | PASS | 33 passed, 0 failed |
| 2026-02-18 | TN-010 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-18 | TN-010 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-18 | TN-010 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-19 | TN-011 | `cd plugin-openclaw && npm test` | PASS | 43 passed, 0 failed |
| 2026-02-19 | TN-011 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-19 | TN-011 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-19 | TN-011 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |
| 2026-02-19 | TN-012 | `cd plugin-openclaw && npm test` | PASS | 56 passed, 0 failed |
| 2026-02-19 | TN-012 | `cargo nextest run --workspace` | PASS | 138 passed, 0 failed |
| 2026-02-19 | TN-012 | `cargo +nightly fmt --all` | PASS | Formatting clean |
| 2026-02-19 | TN-012 | `RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked` | PASS | No warnings/errors |

## Implementation Log
| Date | IDs | Summary | Key Files | Follow-ups |
|---|---|---|---|---|
| 2026-02-18 | TN-PLAN | Initial v0.7 backlog tracker created | `docs/TrustNet_v0.7_Implementation_Tracker.md` | Start TN-001 |
| 2026-02-18 | TN-001 | Flipped repo/docs baseline language to v0.7 local-first and reframed chain/server as compatibility paths | `README.md`, `plugin-openclaw/README.md`, `plugin-openclaw/package.json`, `docs/Server_Smoke_Test.md`, `docs/Chain_Smoke_Test.md`, `docs/Base_Sepolia_Dress_Rehearsal.md` | Start TN-002 |
| 2026-02-18 | TN-002 | Added mode-based plugin config (`local-lite` default, `local-verifiable` anchored), made chain fields optional for local-lite, and added regression coverage for both modes | `plugin-openclaw/src/internal.js`, `plugin-openclaw/index.js`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5`, `plugin-openclaw/README.md`, `plugin-openclaw/test/integration.test.js` | Start TN-003 |
| 2026-02-18 | TN-003 | Replaced canonical registry with v0.7 `agent-collab` contexts across core/api/indexer/plugin/solidity, removed legacy context acceptance, and updated vectors/tests/tool maps | `crates/core/src/constants.rs`, `crates/api/src/server.rs`, `crates/indexer/src/root_manifest.rs`, `crates/indexer/src/listener/events.rs`, `crates/verifier/src/lib.rs`, `plugin-openclaw/tool_map.example.json`, `solidity/TrustNetContexts.sol`, `solidity/test/TrustNetContexts.t.sol` | Start TN-004 |
| 2026-02-18 | TN-004 | Added local SQLite trust store in plugin runtime, wired decider/target agent tracking and receipt persistence, and added coverage for schema/latest-wins behavior | `plugin-openclaw/src/store.js`, `plugin-openclaw/index.js`, `plugin-openclaw/src/internal.js`, `plugin-openclaw/test/store.test.js`, `plugin-openclaw/test/integration.test.js`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5`, `plugin-openclaw/README.md` | Start TN-005 |
| 2026-02-18 | TN-005 | Added a local decision engine module with Rust-equivalent scoring semantics (hard veto, positive-only pathing, deterministic tie-break, threshold mapping) plus evidence-gated variant and parity tests | `plugin-openclaw/src/decision-engine.js`, `plugin-openclaw/test/decision-engine.test.js`, `plugin-openclaw/README.md` | Start TN-006 |
| 2026-02-18 | TN-006 | Switched `local-lite` `before_tool_call` to local SQLite-based decision compute, made `apiBaseUrl` optional in L0, and added local-only integration coverage plus store query helpers | `plugin-openclaw/index.js`, `plugin-openclaw/src/store.js`, `plugin-openclaw/src/internal.js`, `plugin-openclaw/test/integration.test.js`, `plugin-openclaw/test/store.test.js`, `plugin-openclaw/testing/helpers.js`, `plugin-openclaw/README.md`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5` | Start TN-007 |
| 2026-02-18 | TN-007 | Implemented ticketed ASK retry actions and trust-edge persistence (`allow_once`, `allow_ttl`, `allow_always`, `block`) with TTL edge expiry handling in local store reads plus regression coverage | `plugin-openclaw/index.js`, `plugin-openclaw/src/ask-actions.js`, `plugin-openclaw/src/store.js`, `plugin-openclaw/test/ask-actions.test.js`, `plugin-openclaw/test/store.test.js`, `plugin-openclaw/README.md`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5` | Start TN-008 |
| 2026-02-18 | TN-008 | Switched high-risk persistence to the v0.7 local receipt shape, attached local-verifiable receipt metadata when available, and removed legacy pending receipt fallback format | `plugin-openclaw/index.js`, `plugin-openclaw/src/local-receipt.js`, `plugin-openclaw/test/integration.test.js`, `plugin-openclaw/test/local-receipt.test.js`, `plugin-openclaw/README.md`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5` | Start TN-009 |
| 2026-02-18 | TN-009 | Rewrote integration coverage to local-first defaults (including implicit `local-lite` mode), with `local-verifiable` as explicit opt-in behavior, and aligned test fixture defaults with v0.7 runtime expectations | `plugin-openclaw/test/integration.test.js`, `plugin-openclaw/testing/helpers.js` | Commit TN-009 and start TN-010 |
| 2026-02-18 | TN-010 | Added Trust Circles policy model in local-lite (`onlyMe`, `myContacts`, `openclawVerified`, `custom`), wired endorser filtering before local scoring, updated plugin config schema/examples, and added preset/filter regression coverage plus ASK-flow fixture updates for the new default | `plugin-openclaw/src/trust-circles.js`, `plugin-openclaw/index.js`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5`, `plugin-openclaw/README.md`, `plugin-openclaw/test/trust-circles.test.js`, `plugin-openclaw/test/integration.test.js`, `plugin-openclaw/test/ask-actions.test.js`, `plugin-openclaw/testing/helpers.js` | Commit TN-010 and start TN-011 |
| 2026-02-19 | TN-011 | Added runtime Agent Card import/verify/store for `openclaw.agentCard.v1`, including `agentRef=sha256(agentPubKey)` binding checks, dual signature verification (`agentSig` + `ownerSig`), trusted-owner policy, and status/list workflows | `plugin-openclaw/src/agent-cards.js`, `plugin-openclaw/index.js`, `plugin-openclaw/src/store.js`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5`, `plugin-openclaw/README.md`, `plugin-openclaw/test/agent-cards.test.js`, `plugin-openclaw/test/agent-card-actions.test.js`, `plugin-openclaw/test/store.test.js`, `plugin-openclaw/testing/helpers.js` | Start TN-012 |
| 2026-02-19 | TN-012 | Implemented trust management workflow actions (`trust`, `block`, `endorse`, `status`) with durable SQLite confirmation tickets and replay/expiry enforcement, plus status reads and trust-circle-filtered candidate visibility | `plugin-openclaw/src/trust-workflows.js`, `plugin-openclaw/index.js`, `plugin-openclaw/src/store.js`, `plugin-openclaw/openclaw.plugin.json`, `plugin-openclaw/config.example.json5`, `plugin-openclaw/README.md`, `plugin-openclaw/test/trust-workflows.test.js`, `plugin-openclaw/test/trust-workflow-actions.test.js`, `plugin-openclaw/test/store.test.js`, `plugin-openclaw/testing/helpers.js` | Commit TN-012 and start TN-013 |
