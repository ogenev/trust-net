-- TrustNet Spec v0.4 server-mode additions
--
-- Store the raw signed RatingEvent payload for PRIVATE_LOG ingestion so the append-only log
-- is auditable and reproducible within an org.

ALTER TABLE edges_raw ADD COLUMN event_json TEXT;
ALTER TABLE edges_raw ADD COLUMN signature BLOB;

