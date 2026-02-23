# TrustNet

> **Verifiable, explainable trust-to-act for AI agents (TrustNet v1.1).**
> ERC-8004 ingestion + deterministic score proofs anchored by root commitments.

## Spec Baseline

This repository targets **TrustNet v1.1**.

- Spec: [docs/TRUSTNET_v1.1.md](docs/TRUSTNET_v1.1.md)
- Test vectors: [docs/Test_Vectors_v1.1.json](docs/Test_Vectors_v1.1.json)

Core v1.1 properties:

- **Context-scoped trust** (`payments` is isolated from `code-exec`).
- **Decider-relative trust** (no global score; score is "as seen by decider D").
- **Why-by-default** explainability (`edgeDE`, `edgeET`, `edgeDT` + proofs).

## Current Implementation (v1.1)

- Chain ingestion for:
  - `TrustGraph.EdgeRated`
  - ERC-8004 `NewFeedback`
  - ERC-8004 `FeedbackRevoked`
  - ERC-8004 `ResponseAppended`
- Latest-wins edge reduction with deterministic chain ordering.
- Sparse Merkle Map (SMM) root building and proof serving.
- Root manifest v1.1 hashing/signing and optional `RootRegistry` anchoring.
- Server-mode private log ingestion via signed `trustnet.rating.v1` payloads.
- Offline verification (`trustnet verify`) and signed action receipts.

Scoring rule implemented by `trustnet-engine`:

```text
lDEpos = max(lDE, 0)
path   = lDEpos * lET
score  = clamp((2*lDT + path)/2, -2, +2)
```

## TrustNet v1.1 Ingestion Rules

For ERC-8004 `NewFeedback -> TrustNet edge` mapping, current implementation enforces:

- `tag2 == "trustnet:v1"` (literal string match).
- `tag1` must be a valid `trustnet:ctx:*:v1` context tag.
- `valueDecimals == 0`
- `value in [0, 100]` (quantized to `level in [-2..+2]`).

`feedback_raw` stores all observed ERC-8004 feedback events from the configured contract, while edge materialization into `edges_latest` only happens for TrustNet-compatible entries.

## Components

- `trustnet-indexer` (`crates/indexer`)
  - Chain sync, ingestion, SMM rebuild, root publish.
- `trustnet-api` (`crates/api`)
  - Read API (`/v1/root`, `/v1/contexts`, `/v1/score`, `/v1/proof`)
  - Optional write API (`POST /v1/ratings`) in server mode.
- `trustnet` CLI (`crates/cli`)
  - `root`, `rate`, `verify`, `receipt`, `verify-receipt`, `vectors`.

## Deployment Modes

- `chain` mode:
  - Ingest on-chain events with `trustnet-indexer`.
  - Serve queries from `trustnet-api` against the same DB.
- `server` mode:
  - Ingest signed private events with `POST /v1/ratings`.
  - Build/insert roots via `trustnet root`.

Important guardrail: a single DB is locked to one mode (`chain` or `server`); do not mix both in the same SQLite file.

## HTTP API Surface

- `GET /health` -> `"OK"`
- `GET /v1/root` -> latest root bundle (`epoch`, `graphRoot`, `edgeCount`, `manifestHash`, `publisherSig`, plus `manifestUri`/`manifest` when present)
- `GET /v1/contexts` -> canonical v1.1 contexts plus observed custom contexts
- `GET /v1/score/:decider/:target?contextTag=<trustnet:ctx:*:v1>` -> score bundle (`score`, `epoch`, `why`, `proof`)
- `GET /v1/proof?key=<0x-bytes32>` -> SMM proof payload
- `POST /v1/ratings` -> append signed `trustnet.rating.v1` event (requires `TRUSTNET_API_WRITE_ENABLED=1`)

## Operator CLI

Run help:

```bash
cargo run -p trustnet-cli -- --help
```

Common commands:

```bash
# Build/insert server-mode root epoch from DB
cargo run -p trustnet-cli -- root --database-url sqlite://trustnet.db --publisher-key 0x...

# Sign trustnet.rating.v1 payload
cargo run -p trustnet-cli -- rate --private-key 0x... --target 0x... --context trustnet:ctx:code-exec:v1 --level 2

# Verify /v1/root + /v1/score bundle
cargo run -p trustnet-cli -- verify --root /tmp/root.json --bundle /tmp/score.json
```

## Contracts

Anchored/chain profile contracts:

- `TrustGraph` (emits `EdgeRated`)
- `RootRegistry` (anchors epoch root + manifest hash/URI)
- `TrustPathVerifier` (on-chain proof verification)
- `TrustNetPaymentsGuardModule` (optional payment guard)

## Base Sepolia Deployment

Current Base Sepolia (`chainId=84532`) deployment values:

- TrustNet contracts:
  - `RootRegistry`: `0x91b1C12C2858E29243c89C9d1e006123d9751F6d`
  - `TrustGraph`: `0x7589cBFa3D615A1fcdEE2005b6c00daca70901f9`
- Official ERC-8004 public contracts used by rehearsal scripts:
  - `IdentityRegistry`: `0x8004A818BFB912233c491871b3d84c89A494BD9e`
  - `ReputationRegistry`: `0x8004B663056A597Dffe9eCcC1965A193B7388713`

## Validation Flows

- Server-mode smoke guide: [docs/Server_Smoke_Test.md](docs/Server_Smoke_Test.md)
- Chain-mode smoke guide (Anvil): [docs/Chain_Smoke_Test.md](docs/Chain_Smoke_Test.md)
- Base Sepolia public rehearsal guide: [docs/Base_Sepolia_Dress_Rehearsal.md](docs/Base_Sepolia_Dress_Rehearsal.md)

Automation:

```bash
# Server-mode integration smoke test
cargo test -p trustnet-api --test server_smoke

# Chain-mode smoke script
./scripts/chain_smoke_anvil.sh

# Base Sepolia public rehearsal script
./scripts/base_sepolia_public_rehearsal.sh
```

## OpenClaw Plugin

`plugin-openclaw/` contains the OpenClaw plugin and integration tests and is intentionally outside the core v1.1 MVP migration scope.

```bash
cd plugin-openclaw
npm run lint
npm run typecheck
npm test
```
