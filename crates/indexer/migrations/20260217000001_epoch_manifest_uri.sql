-- Add explicit manifest URI storage for hosted root manifests.
--
-- Prior versions used a fixed "inline" marker in APIs/on-chain publishes.
-- MVP release requires storing and serving a real manifest URI.

ALTER TABLE epochs ADD COLUMN manifest_uri TEXT;
