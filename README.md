# TrustNet

> **Verifiable, explainable trust-to-act for AI agents (TrustNet Spec v0.7).**
> Default profile is now local-first (L0): decisions are computed locally, with optional verifiable and chain profiles.

## Spec Baseline (v0.7)

This repo now tracks **TrustNet Spec v0.7** as the default implementation target:
- Primary spec: `docs/TrustNet_Spec_v0.7.md`

Implementation tracking and rollout status:
- `docs/TrustNet_v0.7_Implementation_Tracker.md`

TrustNet core properties remain:
- **Context-scoped trust** (payments != code exec).
- **Decider-relative trust** (no global score; policy chooses whose ratings count).
- **Why-by-default** explainability (exact edges used to ALLOW/ASK/DENY).

## Deployment Profiles (v0.7)

- **Local-Lite (L0, default):** local trust store + local decision computation. No mandatory `/v1/root`, publisher signature, or RootRegistry check.
- **Local-Verifiable (optional):** local decisions plus optional root/proof generation and verification.
- **Server/Chain compatibility (optional):** shared API + anchored root validation for integration and legacy flows.

Current codebase note:
- v0.6 server/chain paths are still present while Sprint 1 tasks (`TN-002` through `TN-009`) migrate OpenClaw runtime behavior to local-first.
- `docs/Server_Smoke_Test.md`, `docs/Chain_Smoke_Test.md`, and `docs/Base_Sepolia_Dress_Rehearsal.md` are compatibility guides, not the default v0.7 path.

## Operator CLI

Use the unified `trustnet` operator CLI (`crates/cli`):

- `trustnet root` - build/insert root epochs from DB for shared/verifiable profiles
- `trustnet rate` - sign `trustnet.rating.v1` payloads
- `trustnet verify` - verify decision bundles against roots (and optionally cross-check anchored roots via `--rpc-url --root-registry --epoch`)
- `trustnet receipt` - build signed action receipts
- `trustnet verify-receipt` - verify signed receipts

Run with Cargo:

```bash
cargo run -p trustnet-cli -- --help
```

## HTTP API

The current API surface remains available for shared/compatibility profiles:

- `GET /v1/root` -> `{ epoch, graphRoot, manifest( or manifestUri ), manifestHash, publisherSig }`
- `GET /v1/contexts` -> canonical contexts (and/or `contextId` hashes)
- `GET /v1/decision?decider=<principalId>&target=<principalId>&contextId=<bytes32>` -> `DecisionBundleV1`
- `GET /v1/proof?key=<edgeKey>` -> debug membership/non-membership proof
- `POST /v1/ratings` -> append signed `trustnet.rating.v1` (server mode)

## Contracts

Contracts remain available for anchored/chain profiles:

- `TrustGraph` - emits `EdgeRated(rater, target, level, contextId)` events.
- `RootRegistry` - anchors `{epoch, graphRoot, manifestHash (and optional manifestUri)}`.
- `TrustPathVerifier` - optional on-chain verifier.
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
The v0.7 target is local-first runtime behavior; anchored verification remains available as a compatibility path during migration.

Run plugin integration tests:

```bash
cd plugin-openclaw
npm test
```
