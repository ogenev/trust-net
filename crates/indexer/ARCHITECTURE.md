# TrustNet Architecture (Spec v0.4 target)

## Overview

TrustNet uses a **modular architecture** with separate binaries for chain ingestion and HTTP serving.

This repo is upgrading to match:
- Spec: `docs/TrustNet_Spec_v0.6.md`
- Upgrade plan: `docs/Upgrade_Plan_v0.6.md`

```
┌──────────────────────────────┐
│  trustnet-indexer            │  ← Event ingestion & root publishing
│  (writes to DB)              │
└──────────────┬───────────────┘
               │
               │ SQLite (shared; dev)
               │
┌──────────────▼───────────────┐
│  trustnet-api                │  ← HTTP API server (v0.4 target: roots + decision bundles)
│  (reads DB; server mode may write) │
└──────────────────────────────┘

```

## Components

### 1. trustnet-indexer (Event Ingestion)

**Purpose:** ingest on-chain signals (chain mode) and keep storage state up to date.

**Responsibilities:**
- Poll Ethereum RPC for new blocks
- Ingest `EdgeRated` events from TrustGraph contract (TrustNet-native)
- Ingest ERC‑8004 feedback events (guarded by `tag2 == keccak256("trustnet:v1")`) and map deterministically to TrustNet `RatingEvent`
- Append all accepted signals to `edges_raw` (append-only)
- Reduce into `edges_latest` with deterministic latest-wins ordering
- (Chain mode) publish roots to RootRegistry on-chain (and optionally sign roots/manifests)

**Storage:** Writes to SQLite (`edges_raw`, `edges_latest`, `epochs`, `sync_state`)

**CLI Commands:**
- `run` - Start indexer service
- `publish-root` - Manually trigger root publishing
- `status` - Show sync status
- `init-db` - Initialize database

**Dependencies:**
- `trustnet-core` - Core types
- `trustnet-smm` - Sparse Merkle Map
- `alloy` - Ethereum RPC
- `sqlx` - Database (SQLite)
- `tokio` - Async runtime

---

### 2. trustnet-api (HTTP API Server)

**Purpose:** serve authenticated roots/manifests and verifiable decision bundles.

**Responsibilities:**
- Serve `GET /v1/root` (epoch + `graphRoot` + `manifestHash` + publisher signature in server mode)
- Serve `GET /v1/decision` returning a `DecisionBundleV1`:
  - deterministic endorser selection
  - proofs for `D→E`, `E→T`, and `D→T` (membership or non-membership)
  - “why” edges used and thresholds
- (Server mode) accept `POST /v1/ratings` to append signed `RatingEvent` to `edges_raw`

**Storage:** Reads from SQLite (server mode additionally writes)

**API Endpoints (v0.4 target):**
- `GET /v1/root`
- `GET /v1/contexts`
- `GET /v1/decision?decider=<principalId>&target=<principalId>&contextId=<bytes32>`
- `GET /v1/proof?key=<edgeKey>` (debug)
- `POST /v1/ratings` (server mode)

**Dependencies:**
- `trustnet-core` - Core types
- `trustnet-smm` - SMM verification and proof generation
- `axum` - HTTP server
- `sqlx` - Database (SQLite; read-only today, write-enabled in server mode)

---

## Data Flow

### Chain mode (on-chain → DB → roots)

```
Ethereum (Sepolia)
    │
    │ Events: EdgeRated (+ optional ERC‑8004 feedback mapping)
    │
    ▼
┌───────────────────┐
│ trustnet-indexer  │
│                   │
│ 1. Append to      │
│    edges_raw      │
│ 2. Reduce to      │
│    edges_latest   │
│ 3. Build root +   │
│    manifest       │
│ 4. Publish root   │
│    (RootRegistry) │
└─────────┬─────────┘
          │
          ▼
    SQLite Database
    (edges_raw, edges_latest, epochs, sync_state)
```

### Server mode (private log → roots → decision bundles)

```
Client/Gateway
    │
    │ POST /v1/ratings  (signed RatingEvent)
    ▼
┌───────────────────┐
│ trustnet-api      │
│                   │
│ 1. Validate sig   │
│ 2. Append raw     │
│ 3. Reduce latest  │
│ 4. Build root +   │
│    sign manifest  │
└─────────┬─────────┘
          │
          ▼
    SQLite Database
```

### Decision query flow (offline-verifiable)

```
Client (HTTP)
    │
    │ GET /v1/decision?decider=...&target=...&contextId=...
    │
    ▼
┌───────────────────┐
│  trustnet-api     │
│                   │
│ 1. Read latest    │
│    edges + epoch  │
│ 2. Select endorser│
│    deterministically│
│ 3. Return proofs  │
│    + why + root   │
└─────────┬─────────┘
          │
          ▼
    SQLite Database
```

---

## Deployment

### Development (Single Machine)

```bash
# Terminal 1: Start indexer
cd crates/indexer
cargo run -- run --config indexer.toml

# Terminal 2: Start API server
cd crates/api
cargo run -- --database-url sqlite://../../trustnet.db --port 3000
```

### Production (Separate Hosts)

```
┌─────────────────┐
│  Host 1         │
│  Indexer        │
│  + SQLite DB    │
└────────┬────────┘
         │
         │ NFS/Network Storage
         │
┌────────▼────────┐
│  Host 2         │
│  API Server 1   │ ← Load Balancer
└─────────────────┘

┌─────────────────┐
│  Host 3         │
│  API Server 2   │ ← Load Balancer
└─────────────────┘
```

**Benefits:**
- Scale API servers horizontally (read-only)
- Indexer runs on single node (writes)
- Shared database via NFS or network storage

---

## Why Modular?

### Scalability
- API servers can scale independently (read replicas)
- Indexer runs once (single source of truth)

### Separation of Concerns
- Indexer: blockchain interaction, write operations
- API: query serving, read operations, proof generation via SMM

### Development
- Work on API without running indexer
- Test proof generation via SMM independently

### Security
- API servers can be public-facing
- Indexer can be behind firewall
- Publisher keys only on the root-builder host (indexer for chain mode; server for server mode)

---

## Shared Database Schema

Both indexer and server access the same database. Spec v0.4 introduces an append-only raw table plus a reduced latest table:

```sql
CREATE TABLE edges_raw (...);
CREATE TABLE edges_latest (...);

CREATE TABLE epochs (... graph_root, manifest_json, manifest_hash, publisher_sig, ...);

-- Sync state
CREATE TABLE sync_state (...);
```

**Access patterns:**
- Indexer: Read + Write
- Server: Read (and Write in server mode)

---

## Future Enhancements

### PostgreSQL Migration
Replace SQLite with PostgreSQL for:
- Better concurrent reads
- Replication (read replicas)
- Advanced indexing

### Multi-Publisher
Support multiple indexers with consensus:
- Quorum voting on roots
- Fraud proofs for disputes

### ZK Proofs
Add zero-knowledge proving:
- Hide endorser identity
- Prove score ≥ threshold without revealing edges

---

## Summary

| Service | Purpose | Reads DB | Writes DB | HTTP |
|---------|---------|----------|-----------|------|
| **indexer** | Event ingestion | ✅ | ✅ | ❌ |
| **server** | Roots + decision bundles | ✅ | ✅* | ✅ |

\* Writes DB in server mode (private log ingestion and/or root building).
