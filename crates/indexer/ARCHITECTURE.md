# TrustNet Architecture (Spec v1.1 target)

## Overview

TrustNet uses a **modular architecture** with separate binaries for chain ingestion and HTTP serving.

This repo targets:
- Spec: `docs/TRUSTNET_v1.1.md`

```
┌──────────────────────────────┐
│  trustnet-indexer            │  ← Event ingestion & root publishing
│  (writes to DB)              │
└──────────────┬───────────────┘
               │
               │ SQLite (shared; dev)
               │
┌──────────────▼───────────────┐
│  trustnet-api                │  ← HTTP API server (roots + score bundles)
│  (reads DB; server mode may write) │
└──────────────────────────────┘

```

## Components

### 1. trustnet-indexer (Event Ingestion)

**Purpose:** ingest on-chain signals (chain mode) and keep storage state up to date.

**Responsibilities:**
- Poll Ethereum RPC for new blocks
- Ingest `EdgeRated` events from TrustGraph contract (TrustNet-native)
- Ingest ERC‑8004 feedback events (guarded by `tag2 == "trustnet:v1"`) and map deterministically to TrustNet edges
- Parse canonical `tag1` context strings and quantize `(value, valueDecimals)` into TrustNet levels
- Ingest `FeedbackRevoked` and recompute effective latest edges
- Resolve `agentId → agentWallet` using the identity registry (if configured)
- Ingest `ResponseAppended` into `feedback_responses_raw`
- Optionally verify `responseURI` payloads (`trustnet.verification.v1`) and persist verified stamps in `feedback_verified`
- Append all accepted signals to `edges_raw` (append-only)
- Reduce into `edges_latest` with deterministic latest-wins ordering (`observedAt`)
- (Chain mode) publish roots to RootRegistry on-chain (and sign roots/manifests)

**Storage:** Writes to SQLite (`edges_raw`, `edges_latest`, `feedback_raw`, `feedback_responses_raw`, `feedback_verified`, `epochs`, `sync_state`)

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
- `reqwest` - Response verification fetches (when enabled)

---

### 2. trustnet-api (HTTP API Server)

**Purpose:** serve authenticated roots/manifests and verifiable score bundles.

**Responsibilities:**
- Serve `GET /v1/root` (epoch + `graphRoot` + `manifestHash` + publisher signature)
- Serve `GET /v1/score/:decider/:target?contextTag=...` returning `{ score, epoch, why, proof }` with deterministic endorser selection and DE/ET/DT proofs
- Apply evidence gating when configured, using verified stamps in `feedback_verified` if present
- (Server mode) accept `POST /v1/ratings` to append signed `trustnet.rating.v1` to `edges_raw`

**Storage:** Reads from SQLite (server mode additionally writes)

**API Endpoints (v1.1):**
- `GET /v1/root`
- `GET /v1/contexts`
- `GET /v1/score/:decider/:target?contextTag=<tag>`
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
    │ Events: EdgeRated + ERC‑8004 NewFeedback + FeedbackRevoked + ResponseAppended
    │
    ▼
┌───────────────────┐
│ trustnet-indexer  │
│                   │
│ 1. Append to      │
│    edges_raw      │
│    feedback_raw   │
│    feedback_responses_raw │
│ 2. Verify response│
│    payloads (opt) │
│    → feedback_verified │
│ 3. Reduce to      │
│    edges_latest   │
│ 4. Build root +   │
│    manifest       │
│ 5. Publish root   │
│    (RootRegistry) │
└─────────┬─────────┘
          │
          ▼
    SQLite Database
    (edges_raw, edges_latest, feedback_raw, feedback_responses_raw, feedback_verified, epochs, sync_state)
```

### Server mode (private log → score bundles)

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
│ 4. (External)     │
│    root builder   │
│    publishes epoch│
└─────────┬─────────┘
          │
          ▼
    SQLite Database
```

### Score query flow (offline-verifiable)

```
Client (HTTP)
    │
    │ GET /v1/score/:decider/:target?contextTag=...
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

Chain and server modes use separate databases (enforced by `deployment_mode`). The schema includes append-only raw tables plus reduced latest tables and verification stamps:

```sql
CREATE TABLE edges_raw (...);
CREATE TABLE edges_latest (...);
CREATE TABLE feedback_raw (...);
CREATE TABLE feedback_responses_raw (...);
CREATE TABLE feedback_verified (...);

CREATE TABLE epochs (... graph_root, manifest_json, manifest_hash, publisher_sig, ...);

-- Sync state
CREATE TABLE sync_state (...);
```

**Access patterns:**
- Indexer (chain mode): Read + Write
- API (server mode): Read + Write (private log ingestion)

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
| **server** | Roots + score bundles | ✅ | ✅* | ✅ |

\* Writes DB in server mode (private log ingestion and/or root building).
