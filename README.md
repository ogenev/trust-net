# TrustNet

> **Verifiable, explainable trust-to-act for AI agents (TrustNet Spec v0.6, draft).**  
> Gate actions using a deterministic decision rule plus cryptographic proofs against a committed `graphRoot`.

## Spec (v0.6)

This repo targets **TrustNet Spec v0.6 (draft)** and the ERC‑8004‑first MVP profile:
- Spec: `docs/TrustNet_Spec_v0.6.md`
- Upgrade plan: `docs/Upgrade_Plan_v0.6.md`
- Progress tracker: `docs/Upgrade_Progress_v0.6.md`

TrustNet’s core properties:
- **Context-scoped trust** (payments ≠ code exec).
- **Decider-relative trust** (no global score; policy chooses whose ratings count).
- **Verifiable “Why”** (exact edges used to ALLOW/ASK/DENY, with Merkle proofs).

## Deployment modes (v0.6)

- **Local mode:** single machine; decisions computed locally (roots/proofs optional).
- **Server mode:** roots are signed by a configured root publisher key; gateways verify manifest hashes and signatures.
- **Chain mode:** roots are anchored on-chain (RootRegistry) and can also be signed; proofs verify against the anchored root.

## Operator CLI

Use the unified `trustnet` operator CLI (`crates/cli`):

- `trustnet root` - build/insert server-mode root from DB
- `trustnet rate` - sign `trustnet.rating.v1` payloads
- `trustnet verify` - verify decision bundle against root
- `trustnet receipt` - build signed action receipt
- `trustnet verify-receipt` - verify signed receipt

Run with Cargo:

```bash
cargo run -p trustnet-cli -- --help
```

## HTTP API (v0.6)

- `GET /v1/root` → `{ epoch, graphRoot, manifest( or manifestUri ), manifestHash, publisherSig }`
- `GET /v1/contexts` → canonical contexts (and/or their `contextId` hashes)
- `GET /v1/decision?decider=<principalId>&target=<principalId>&contextId=<bytes32>` → `DecisionBundleV1` (ALLOW|ASK|DENY + why + constraints + proofs)
- `GET /v1/proof?key=<edgeKey>` → debug membership/non-membership proof
- `POST /v1/ratings` → append signed `trustnet.rating.v1` (server mode)

## Contracts (chain mode, optional for MVP)

- `TrustGraph`: emits `EdgeRated(rater, target, level, contextId)` (events-only).
- `RootRegistry`: anchors `{epoch, graphRoot, manifestHash (and optional manifestUri)}`.
- `TrustPathVerifier`: optional on-chain verifier (off-chain verification is sufficient for MVP).

## Indexing + root building (v0.6)

1) **Ingest** chain and/or server signals into `edges_raw`, including ERC‑8004 `NewFeedback` with guard `endpoint == "trustnet"` and `tag2 == "trustnet:v1"`, plus `ResponseAppended` verification stamps  
2) **Normalize** `tag1 → contextId`, `agentId → agentWallet` (identity registry), and record evidence hashes, URIs, and observed ordering  
3) **Reduce latest-wins** into `edges_latest` per `(rater, target, contextId)`  
4) **Build root**: commit latest edges into a Sparse Merkle Map (`graphRoot`) plus Root Manifest + JCS `manifestHash`  
5) **Serve decisions**: choose endorser deterministically and return a verifiable decision bundle with constraints

## Smoke test

- Guide: `docs/Server_Smoke_Test.md`
- Automated in-process smoke test:

```bash
cargo test -p trustnet-api --test server_smoke
```
