-- TrustNet v1.1 spec revocation support for ERC-8004 feedback ingestion.
--
-- FeedbackRevoked events are stored append-only and used to recompute effective
-- edges by excluding revoked feedback entries.

CREATE TABLE IF NOT EXISTS feedback_revocations_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    chain_id INTEGER NOT NULL,
    erc8004_reputation BLOB NOT NULL,   -- 20 bytes

    agent_id BLOB NOT NULL,             -- 32 bytes (uint256)
    client_address BLOB NOT NULL,       -- 20 bytes
    feedback_index BLOB NOT NULL,       -- 32 bytes (uint256)

    observed_at_u64 INTEGER NOT NULL,

    block_number INTEGER,
    tx_index INTEGER,
    log_index INTEGER,
    tx_hash BLOB,

    UNIQUE(chain_id, tx_hash, log_index)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_feedback_revocations_feedback
ON feedback_revocations_raw(chain_id, agent_id, client_address, feedback_index);

CREATE INDEX IF NOT EXISTS idx_feedback_revocations_order
ON feedback_revocations_raw(chain_id, block_number, tx_index, log_index);
