-- TrustNet Spec v0.4 schema additions
--
-- Adds append-only raw event table and reduced latest-wins table keyed by
-- (rater_pid, target_pid, context_id), where rater/target are PrincipalId (32 bytes).

-- Append-only raw edges (auditable ingestion stream)
CREATE TABLE IF NOT EXISTS edges_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Canonical edge identity
    rater_pid BLOB NOT NULL,     -- 32 bytes
    target_pid BLOB NOT NULL,    -- 32 bytes
    context_id BLOB NOT NULL,    -- 32 bytes

    -- Canonical edge value
    level_i8 INTEGER NOT NULL CHECK (level_i8 >= -2 AND level_i8 <= 2),
    updated_at_u64 INTEGER NOT NULL,                 -- unix seconds
    evidence_hash BLOB NOT NULL DEFAULT (zeroblob(32)),

    -- Signal source
    source TEXT NOT NULL CHECK (source IN ('trust_graph', 'erc8004', 'private_log')),

    -- Chain ordering (nullable for server mode)
    chain_id INTEGER,
    block_number INTEGER,
    tx_index INTEGER,
    log_index INTEGER,
    tx_hash BLOB,

    -- Server ordering (nullable for chain mode)
    server_seq INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS idx_edges_raw_key
ON edges_raw(rater_pid, target_pid, context_id);

CREATE INDEX IF NOT EXISTS idx_edges_raw_order_chain
ON edges_raw(chain_id, block_number, tx_index, log_index);

CREATE INDEX IF NOT EXISTS idx_edges_raw_order_server
ON edges_raw(server_seq);

-- Reduced latest-wins edges (one row per canonical key)
CREATE TABLE IF NOT EXISTS edges_latest (
    rater_pid BLOB NOT NULL,     -- 32 bytes
    target_pid BLOB NOT NULL,    -- 32 bytes
    context_id BLOB NOT NULL,    -- 32 bytes

    level_i8 INTEGER NOT NULL CHECK (level_i8 >= -2 AND level_i8 <= 2),
    updated_at_u64 INTEGER NOT NULL,
    evidence_hash BLOB NOT NULL DEFAULT (zeroblob(32)),
    source TEXT NOT NULL CHECK (source IN ('trust_graph', 'erc8004', 'private_log')),

    -- Chain ordering (nullable for server mode)
    chain_id INTEGER,
    block_number INTEGER,
    tx_index INTEGER,
    log_index INTEGER,
    tx_hash BLOB,

    -- Server ordering (nullable for chain mode)
    server_seq INTEGER,

    PRIMARY KEY (rater_pid, target_pid, context_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_edges_latest_rater
ON edges_latest(rater_pid, context_id);

CREATE INDEX IF NOT EXISTS idx_edges_latest_target
ON edges_latest(target_pid, context_id);

CREATE INDEX IF NOT EXISTS idx_edges_latest_order_chain
ON edges_latest(chain_id, block_number, tx_index, log_index);

CREATE INDEX IF NOT EXISTS idx_edges_latest_order_server
ON edges_latest(server_seq);

-- Epoch metadata extensions for v0.4 (nullable for legacy epochs).
ALTER TABLE epochs ADD COLUMN manifest_json TEXT;
ALTER TABLE epochs ADD COLUMN manifest_hash BLOB;
ALTER TABLE epochs ADD COLUMN publisher_sig BLOB;
ALTER TABLE epochs ADD COLUMN created_at_u64 INTEGER;
