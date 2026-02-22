# TrustNet Indexer

Event ingestion service for TrustNet - listens to ERC-8004 and EdgeRated events, stores edges with latest-wins semantics, builds Sparse Merkle Maps, and publishes roots to RootRegistry.

## Modular Architecture

TrustNet is split into separate services for better scalability:

```
┌──────────────────────────────┐
│  trustnet-indexer (this)    │
│                              │
│  ┌─────────────────┐         │
│  │  Event Listener │ ← Ethereum RPC
│  │   (tokio task)  │   EdgeRated + NewFeedback + ResponseAppended
│  └────────┬────────┘         │
│           │                  │
│      ┌────▼──────┐           │
│      │  Storage  │ ← SQLite  │
│      │  (edges +│   latest-wins
│      │  feedback)│
│      └────┬──────┘           │
│           │                  │
│      ┌────▼──────────┐       │
│      │ Root Publisher│       │
│      │ (tokio task)  │       │
│      │ Hourly + manual       │
│      └───────┬───────┘       │
│              │               │
│              ▼               │
│        RootRegistry          │
│        (on-chain)            │
└──────────────────────────────┘
         │
         │ Shared DB
         │
┌────────▼──────────────────────┐
│   trustnet-api (separate)    │
│   Serves HTTP API            │
│   • GET /v1/root             │
│   • GET /v1/contexts         │
│   • GET /v1/score            │
│   • GET /v1/proof            │
│   • POST /v1/ratings         │
└───────────────────────────────┘
```

## Features

- **Focused responsibility** - event ingestion and root publishing only
- **Tokio-based async** - concurrent event processing and publishing
- **SQLite storage** - lightweight, embedded database with latest-wins semantics
- **Alloy Ethereum client** - modern, type-safe Ethereum RPC integration
- **Automatic root publishing** - configurable hourly publishing + manual trigger
- **CLI interface** - run, status, manual publishing, database initialization
- **Verification stamps** - optional ResponseAppended validation + `feedback_verified`

**Note:** For API queries, use the separate `trustnet-api` service which reads from the same database.

## Installation

### Prerequisites

- Rust 1.75+ with cargo
- SQLite 3.35+

### Build from source

```bash
cd crates/indexer
cargo build --release
```

Binary will be at `target/release/trustnet-indexer`

## Quick Start

### 1. Initialize database

```bash
cargo run -- init-db --database-url sqlite://trustnet.db
```

### 2. Configure

Copy example config:

```bash
cp indexer.toml.example indexer.toml
```

Edit `indexer.toml` and set:
- RPC URL (Sepolia endpoint)
- Contract addresses (TrustGraph, RootRegistry, ERC-8004) as non-zero deployed values
- Publisher private key
- Database path

### 3. Run indexer

```bash
cargo run -- run --config indexer.toml
```

Or with debug logging:

```bash
cargo run -- run --config indexer.toml --debug
```

### 4. Check status

In another terminal:

```bash
cargo run -- status --config indexer.toml
```

### 5. Manual root publishing

```bash
cargo run -- publish-root --config indexer.toml
```

This command is for **chain-mode** on-chain root publication.
For **server-mode** signed roots, use the unified CLI:

```bash
cargo run -p trustnet-cli -- root --database-url sqlite://trustnet.db --publisher-key 0x...
```

End-to-end server-mode flow is documented in `docs/Server_Smoke_Test.md`.
End-to-end chain-mode (anvil) flow is documented in `docs/Chain_Smoke_Test.md`.
Base Sepolia public-traffic release rehearsal flow is documented in `docs/Base_Sepolia_Dress_Rehearsal.md`.

## Configuration

See `indexer.toml.example` for full configuration options.

Key settings:
- `network.rpc_url` - Ethereum RPC endpoint
- `contracts.*` - Contract addresses
- `publisher.private_key` - Publisher wallet private key (keep secure!)
- `publisher.publish_interval_secs` - Auto-publish interval (default: 3600 = 1 hour)
- `publisher.manifest_output_dir` - Local directory where canonical manifests are written
- `publisher.manifest_public_base_uri` - Public URI base anchored in RootRegistry
- `database.url` - SQLite database path
- `sync.start_block` - Block to start indexing from

## Related Services

This indexer works alongside the TrustNet API service:

- **trustnet-api** - HTTP API server (reads from same DB)
  - `GET /v1/root` - Get current graph root and epoch
  - `GET /v1/score/:decider/:target?contextTag=<tag>` - Score bundle with proofs
  - `GET /v1/contexts` - List canonical context IDs
  - `GET /v1/proof?key=<edgeKey>` - SMM proof by key
  - `POST /v1/ratings` - Append signed rating event (server mode)

## Development

### Run tests

```bash
cargo test -p trustnet-indexer
```

### Run with debug logging

```bash
RUST_LOG=trustnet_indexer=debug,tower_http=debug cargo run -- run
```

### Check code

```bash
cargo check -p trustnet-indexer
```

## Implementation Status (v1.1)

- ✅ Chain ingestion for `EdgeRated`, ERC‑8004 `NewFeedback`, `FeedbackRevoked`, and `ResponseAppended`
- ✅ Latest-wins reduction with observed ordering
- ✅ Sparse Merkle Map root building + publishing to RootRegistry
- ✅ Root Manifest v1.1 fields with JCS hashing
- ✅ Optional verification of `trustnet.verification.v1` response payloads

## License

MIT OR Apache-2.0
