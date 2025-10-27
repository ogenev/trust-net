-- Initial schema for TrustNet indexer
-- This migration creates tables for storing edges, sync state, and published epochs

-- Edges table: stores trust ratings with latest-wins semantics
-- Primary key on (rater, target, context_id) ensures one rating per triple
CREATE TABLE IF NOT EXISTS edges (
    -- The rater (observer/curator) address (20 bytes)
    rater BLOB NOT NULL,

    -- The target (hinge/agent) address (20 bytes)
    target BLOB NOT NULL,

    -- Context ID (32 bytes) - capability namespace
    context_id BLOB NOT NULL,

    -- Trust level: -2 to +2 (stored as integer)
    level INTEGER NOT NULL CHECK (level >= -2 AND level <= 2),

    -- Block coordinates for latest-wins ordering
    block_number INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    log_index INTEGER NOT NULL,

    -- Timestamp when this edge was ingested
    ingested_at INTEGER NOT NULL DEFAULT (unixepoch()),

    -- Source: 'trust_graph' or 'erc8004'
    source TEXT NOT NULL CHECK (source IN ('trust_graph', 'erc8004')),

    -- Optional: transaction hash where this edge was emitted
    tx_hash BLOB,

    PRIMARY KEY (rater, target, context_id)
) STRICT;

-- Index for querying edges by rater (observer-centric queries)
CREATE INDEX IF NOT EXISTS idx_edges_rater
ON edges(rater, context_id);

-- Index for querying edges by target (agent-centric queries)
CREATE INDEX IF NOT EXISTS idx_edges_target
ON edges(target, context_id);

-- Index for ordering by block coordinates (latest-wins resolution)
CREATE INDEX IF NOT EXISTS idx_edges_block_coords
ON edges(block_number, tx_index, log_index);

-- Epochs table: stores published Merkle roots
CREATE TABLE IF NOT EXISTS epochs (
    -- Epoch number (monotonically increasing, starts at 1)
    epoch INTEGER PRIMARY KEY CHECK (epoch > 0),

    -- Sparse Merkle Map root hash (32 bytes)
    graph_root BLOB NOT NULL UNIQUE,

    -- Block number at which this epoch was published
    published_at_block INTEGER NOT NULL,

    -- Timestamp of publication
    published_at INTEGER NOT NULL DEFAULT (unixepoch()),

    -- Transaction hash of the publishRoot call
    tx_hash BLOB,

    -- Number of edges included in this epoch
    edge_count INTEGER NOT NULL DEFAULT 0,

    -- Manifest JSON (for reproducibility)
    manifest TEXT
) STRICT;

-- Sync state table: tracks indexer progress
CREATE TABLE IF NOT EXISTS sync_state (
    -- Singleton row (always id = 1)
    id INTEGER PRIMARY KEY CHECK (id = 1),

    -- Last fully processed block number
    last_block_number INTEGER NOT NULL DEFAULT 0,

    -- Hash of the last processed block (for reorg detection)
    last_block_hash BLOB NOT NULL,

    -- Timestamp of last sync update
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),

    -- Chain ID (for safety)
    chain_id INTEGER NOT NULL
) STRICT;

-- Initialize sync_state with default values
-- This will be updated by the indexer during first run
INSERT INTO sync_state (id, last_block_number, last_block_hash, chain_id)
VALUES (1, 0, X'0000000000000000000000000000000000000000000000000000000000000000', 0)
ON CONFLICT(id) DO NOTHING;

-- Blocks table: optional, for storing block metadata (reorg detection)
CREATE TABLE IF NOT EXISTS blocks (
    -- Block number
    block_number INTEGER PRIMARY KEY,

    -- Block hash (32 bytes)
    block_hash BLOB NOT NULL UNIQUE,

    -- Parent block hash (for chain validation)
    parent_hash BLOB NOT NULL,

    -- Block timestamp
    timestamp INTEGER NOT NULL,

    -- Number of relevant events in this block
    event_count INTEGER NOT NULL DEFAULT 0,

    -- When this block was indexed
    indexed_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- Index for reorg detection (parent hash lookup)
CREATE INDEX IF NOT EXISTS idx_blocks_parent_hash
ON blocks(parent_hash);
