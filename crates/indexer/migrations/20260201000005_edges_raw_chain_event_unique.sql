-- TrustNet v0.4 spec §9.2.1: idempotent chain ingestion.
--
-- Enforce uniqueness for on-chain logs so replays/retries don't duplicate `edges_raw`.
--
-- Unique identity (recommended): (chain_id, tx_hash, log_index)

-- If duplicates exist (from pre-constraint ingestion), keep the earliest row id.
DELETE FROM edges_raw
WHERE chain_id IS NOT NULL
  AND tx_hash IS NOT NULL
  AND log_index IS NOT NULL
  AND id NOT IN (
    SELECT MIN(id)
    FROM edges_raw
    WHERE chain_id IS NOT NULL
      AND tx_hash IS NOT NULL
      AND log_index IS NOT NULL
    GROUP BY chain_id, tx_hash, log_index
  );

-- Enforce idempotency for chain events.
CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_raw_chain_event_unique
ON edges_raw(chain_id, tx_hash, log_index);
