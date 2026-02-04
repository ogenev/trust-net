-- Ensure verified feedback stamps are idempotent.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_feedback_verified
ON feedback_verified(chain_id, agent_id, client_address, feedback_index, responder, response_hash);
