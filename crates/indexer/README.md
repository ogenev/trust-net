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
│  │   (tokio task)  │   EdgeRated + NewFeedback
│  └────────┬────────┘         │
│           │                  │
│      ┌────▼──────┐           │
│      │  Storage  │ ← SQLite  │
│      │  (edges)  │   latest-wins
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
│   • GET /v1/score            │
│   • GET /v1/context          │
└───────────────────────────────┘
```

## Features

- **Focused responsibility** - event ingestion and root publishing only
- **Tokio-based async** - concurrent event processing and publishing
- **SQLite storage** - lightweight, embedded database with latest-wins semantics
- **Alloy Ethereum client** - modern, type-safe Ethereum RPC integration
- **Automatic root publishing** - configurable hourly publishing + manual trigger
- **CLI interface** - run, status, manual publishing, database initialization

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
- Contract addresses (TrustGraph, RootRegistry, ERC-8004)
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

## Configuration

See `indexer.toml.example` for full configuration options.

Key settings:
- `network.rpc_url` - Ethereum RPC endpoint
- `contracts.*` - Contract addresses
- `publisher.private_key` - Publisher wallet private key (keep secure!)
- `publisher.publish_interval_secs` - Auto-publish interval (default: 3600 = 1 hour)
- `database.url` - SQLite database path
- `sync.start_block` - Block to start indexing from

## Related Services

This indexer works alongside other TrustNet services:

- **trustnet-api** - HTTP API server (reads from same DB)
  - `GET /v1/root` - Get current graph root and epoch
  - `GET /v1/score/:observer/:target?contextId=0x...` - Get trust score with proof
  - `GET /v1/context` - List canonical context IDs

- **trustnet-cli** - Offline tools for testing
  - `build-root` - Build Merkle root from files
  - `prove` - Generate proofs offline
  - `verify` - Verify proofs

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

## Implementation Status

### ✅ Phase 1: Project setup and dependencies
- Cargo.toml with all dependencies (tokio, alloy, sqlx, anyhow, etc.)
- Main.rs with tokio runtime
- CLI interface with clap (run, publish-root, status, init-db)
- Logging setup with tracing
- Modular architecture (indexer separated from API)

### 🚧 Phase 2: Database schema and storage layer (TODO)
### 🚧 Phase 3: Configuration management (TODO)
### 🚧 Phase 4: Event listener with Alloy (TODO)
### 🚧 Phase 5: Event processor with latest-wins logic (TODO)
### 🚧 Phase 6: SMM builder integration (TODO)
### 🚧 Phase 7: Root publisher to RootRegistry (TODO)
### 🚧 Phase 8: Implement trustnet-api service (separate) (TODO)
### 🚧 Phase 9: Main loop orchestration (TODO)
### 🚧 Phase 10: Testing and documentation (TODO)

## License

MIT OR Apache-2.0
