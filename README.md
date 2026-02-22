# TrustNet

> **Verifiable, explainable trust-to-act for AI agents (TrustNet v1.1).**
> ERC-8004 ingestion + on-chain root anchoring with deterministic score proofs.

## Spec Baseline (v1.1)

This repo now tracks **TrustNet v1.1** as the implementation target:
- Primary spec: `docs/TRUSTNET_v1.1.md`
- Test vectors: `docs/Test_Vectors_v1.1.json`

TrustNet core properties remain:
- **Context-scoped trust** (payments != code exec).
- **Decider-relative trust** (no global score; policy chooses whose ratings count).
- **Why-by-default** explainability (exact edges used to ALLOW/ASK/DENY).

## Deployment Profiles

- **Server/Chain (default MVP):** deterministic indexer, rooted SMT commitments, `/v1/score` proof API.
- **Server-only ingestion:** signed `POST /v1/ratings` + local root publishing via CLI.
- **Anchored verification:** optional root cross-checks against `RootRegistry`.

Current codebase note:
- `plugin-openclaw/` is intentionally out of scope for current MVP alignment work.
- `docs/Server_Smoke_Test.md`, `docs/Chain_Smoke_Test.md`, and `docs/Base_Sepolia_Dress_Rehearsal.md` cover validation flows.

## Operator CLI

Use the unified `trustnet` operator CLI (`crates/cli`):

- `trustnet root` - build/insert root epochs from DB for shared/verifiable profiles
- `trustnet rate` - sign `trustnet.rating.v1` payloads
- `trustnet verify` - verify score bundles against roots (and optionally cross-check anchored roots via `--rpc-url --root-registry --epoch`)
- `trustnet receipt` - build signed action receipts
- `trustnet verify-receipt` - verify signed receipts

Run with Cargo:

```bash
cargo run -p trustnet-cli -- --help
```

## HTTP API

The current API surface:

- `GET /v1/root` -> `{ epoch, graphRoot, manifest( or manifestUri ), manifestHash, publisherSig }`
- `GET /v1/contexts` -> canonical v1.1 contexts
- `GET /v1/score/:decider/:target?contextTag=<tag>` -> `{ score, epoch, why, proof }`
- `GET /v1/proof?key=<edgeKey>` -> debug membership/non-membership proof
- `POST /v1/ratings` -> append signed `trustnet.rating.v1` (server mode)

## Contracts

Contracts remain available for anchored/chain profiles:

- `TrustGraph` - emits `EdgeRated(rater, target, level, contextId)` events.
- `RootRegistry` - anchors `{epoch, graphRoot, manifestHash (and optional manifestUri)}`.
- `TrustPathVerifier` - on-chain proof + score verifier.
- `TrustNetPaymentsGuardModule` - optional on-chain ETH payment guard module.

## Smoke Tests And Rehearsals

- Server-mode compatibility guide: `docs/Server_Smoke_Test.md`
- Chain-mode compatibility guide (Anvil): `docs/Chain_Smoke_Test.md`
- Base Sepolia compatibility dress rehearsal: `docs/Base_Sepolia_Dress_Rehearsal.md`
- Automated server smoke test:

```bash
cargo test -p trustnet-api --test server_smoke
```

- Automated chain smoke script:

```bash
./scripts/chain_smoke_anvil.sh
```

- Automated Base Sepolia rehearsal script:

```bash
./scripts/base_sepolia_public_rehearsal.sh
```

## OpenClaw Plugin

`plugin-openclaw/` contains the OpenClaw enforcement plugin package and integration tests.
It is intentionally not part of the v1.1 MVP migration scope.

Run plugin integration tests:

```bash
cd plugin-openclaw
npm test
```
