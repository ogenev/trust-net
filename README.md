# TrustNet

> **Verifiable, explainable trust-to-act for AI agents (TrustNet Spec v0.6, draft).**  
> Gate actions using a deterministic decision rule plus cryptographic proofs against a committed `graphRoot`.

## Spec (v0.6)

This repo targets **TrustNet Spec v0.6 (draft)** and the ERC‑8004‑first MVP profile:
- Spec: `docs/TrustNet_Spec_v0.6.md`

Current MVP implementation focus:
- **OpenClaw gateway integration first** (runtime enforcement surface).
- **`trustnet:ctx:code-exec:v1` first** for high-risk command execution.
- **Mandatory RootRegistry anchoring** for the initial MVP release profile.
- Payments enforcement modules remain available in-repo but are **deferred** from the initial MVP rollout.

TrustNet’s core properties:
- **Context-scoped trust** (payments ≠ code exec).
- **Decider-relative trust** (no global score; policy chooses whose ratings count).
- **Verifiable “Why”** (exact edges used to ALLOW/ASK/DENY, with Merkle proofs).

## Deployment modes (v0.6)

- **Local mode:** single machine; decisions computed locally (roots/proofs optional).
- **Server mode:** roots are signed by a configured root publisher key; gateways verify manifest hashes and signatures.
- **Chain mode:** roots are anchored on-chain (RootRegistry) and can also be signed; proofs verify against the anchored root.

Release profile note:
- **Initial MVP release profile uses hybrid mode**: server components for ingestion/decision plus **mandatory chain anchor verification** against `RootRegistry` for high-risk enforcement.

## Operator CLI

Use the unified `trustnet` operator CLI (`crates/cli`):

- `trustnet root` - build/insert server-mode root from DB
- `trustnet rate` - sign `trustnet.rating.v1` payloads
- `trustnet verify` - verify decision bundle against root and, for the initial MVP release profile, cross-check on-chain root via `--rpc-url --root-registry --epoch`
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

## Contracts (Initial MVP Release: RootRegistry Required)

- `TrustGraph`: emits `EdgeRated(rater, target, level, contextId)` (events-only).
- `RootRegistry`: anchors `{epoch, graphRoot, manifestHash (and optional manifestUri)}`. **Required in the initial MVP release profile**.
- `TrustPathVerifier`: optional on-chain verifier (off-chain verification is sufficient for MVP).
- `TrustNetPaymentsGuardModule`: optional on-chain enforcement module for native ETH payments (ALLOW-only with replay, deadline, cap, and root freshness checks). Included for later-phase payment gating, not initial OpenClaw MVP scope.

## Indexing + root building (v0.6)

1) **Ingest** chain and/or server signals into `edges_raw`, including ERC‑8004 `NewFeedback` with guard `endpoint == "trustnet"` and `tag2 == "trustnet:v1"`, plus `ResponseAppended` verification stamps  
2) **Normalize** `tag1 → contextId`, `agentId → agentWallet` (identity registry), and record evidence hashes, URIs, and observed ordering  
3) **Reduce latest-wins** into `edges_latest` per `(rater, target, contextId)`  
4) **Build root**: commit latest edges into a Sparse Merkle Map (`graphRoot`) plus Root Manifest + JCS `manifestHash`  
5) **Serve decisions**: choose endorser deterministically and return a verifiable decision bundle with constraints

## Smoke test

- Chain-mode guide (anvil E2E, initial MVP release baseline): `docs/Chain_Smoke_Test.md`
- Server-mode guide (local/dev-only): `docs/Server_Smoke_Test.md`
- Automated in-process server-mode smoke test:

```bash
cargo test -p trustnet-api --test server_smoke
```

- Automated chain-mode anvil smoke script:

```bash
./scripts/chain_smoke_anvil.sh
```
