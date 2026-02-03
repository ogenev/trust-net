-- TrustNet Spec v0.6 schema additions
--
-- Adds subject identifiers, evidence URIs, observed ordering, and feedback tables.

ALTER TABLE edges_raw ADD COLUMN evidence_uri TEXT;
ALTER TABLE edges_raw ADD COLUMN observed_at_u64 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE edges_raw ADD COLUMN subject_id BLOB;

ALTER TABLE edges_latest ADD COLUMN evidence_uri TEXT;
ALTER TABLE edges_latest ADD COLUMN observed_at_u64 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE edges_latest ADD COLUMN subject_id BLOB;

-- ERC-8004 feedback (raw ingestion, including non-TrustNet tags).
CREATE TABLE IF NOT EXISTS feedback_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    chain_id INTEGER NOT NULL,
    erc8004_reputation BLOB NOT NULL,   -- 20 bytes
    erc8004_identity BLOB,              -- 20 bytes (optional)

    agent_id BLOB NOT NULL,             -- 32 bytes (uint256)
    client_address BLOB NOT NULL,       -- 20 bytes
    feedback_index BLOB NOT NULL,       -- 32 bytes (uint256)

    value_u256 BLOB NOT NULL,           -- 32 bytes (uint256)
    value_decimals INTEGER NOT NULL,

    tag1 TEXT NOT NULL,
    tag2 TEXT NOT NULL,
    endpoint TEXT NOT NULL,

    feedback_uri TEXT,
    feedback_hash BLOB NOT NULL,        -- 32 bytes

    subject_id BLOB,                    -- 32 bytes (optional)
    observed_at_u64 INTEGER NOT NULL,

    block_number INTEGER,
    tx_index INTEGER,
    log_index INTEGER,
    tx_hash BLOB,

    UNIQUE(chain_id, tx_hash, log_index)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_feedback_raw_order
ON feedback_raw(chain_id, block_number, tx_index, log_index);

CREATE INDEX IF NOT EXISTS idx_feedback_raw_agent
ON feedback_raw(agent_id, client_address, feedback_index);

-- ERC-8004 response stamps (public verification responses).
CREATE TABLE IF NOT EXISTS feedback_responses_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    chain_id INTEGER NOT NULL,
    erc8004_reputation BLOB NOT NULL,   -- 20 bytes

    agent_id BLOB NOT NULL,             -- 32 bytes (uint256)
    client_address BLOB NOT NULL,       -- 20 bytes
    feedback_index BLOB NOT NULL,       -- 32 bytes (uint256)

    responder BLOB NOT NULL,            -- 20 bytes
    response_uri TEXT,
    response_hash BLOB NOT NULL,        -- 32 bytes

    observed_at_u64 INTEGER NOT NULL,

    block_number INTEGER,
    tx_index INTEGER,
    log_index INTEGER,
    tx_hash BLOB,

    UNIQUE(chain_id, tx_hash, log_index)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_feedback_responses_order
ON feedback_responses_raw(chain_id, block_number, tx_index, log_index);

CREATE INDEX IF NOT EXISTS idx_feedback_responses_feedback
ON feedback_responses_raw(agent_id, client_address, feedback_index);

-- Optional materialized view table for verified feedback (populated by a pipeline step).
CREATE TABLE IF NOT EXISTS feedback_verified (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    chain_id INTEGER NOT NULL,
    erc8004_reputation BLOB NOT NULL,

    agent_id BLOB NOT NULL,
    client_address BLOB NOT NULL,
    feedback_index BLOB NOT NULL,

    responder BLOB NOT NULL,
    response_hash BLOB NOT NULL,

    observed_at_u64 INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_feedback_verified_feedback
ON feedback_verified(agent_id, client_address, feedback_index);
