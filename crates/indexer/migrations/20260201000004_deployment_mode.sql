-- TrustNet v0.4 MVP guardrail: prevent mixed-source roots in a single DB.
--
-- A single `edges_latest` table cannot represent two independent latest-wins orderings
-- (chain block coords vs server seq) without formalizing cross-source `observedAt`.
--
-- For MVP, deployments MUST be either:
-- - "chain": only chain sources (trust_graph, erc8004)
-- - "server": only private_log (server mode)
--
-- This table is claimed by the first writer and enforced by services.

CREATE TABLE IF NOT EXISTS deployment_mode (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    mode TEXT NOT NULL CHECK (mode IN ('server', 'chain')),
    set_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
