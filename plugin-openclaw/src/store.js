import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const MIN_TRUST_LEVEL = -2;
const MAX_TRUST_LEVEL = 2;
const VALID_DECISIONS = new Set(["allow", "ask", "deny"]);
const DEFAULT_LIST_LIMIT = 20;

function ensureNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function ensureTrustLevel(value) {
  if (!Number.isInteger(value) || value < MIN_TRUST_LEVEL || value > MAX_TRUST_LEVEL) {
    throw new Error(
      `edge level must be an integer between ${MIN_TRUST_LEVEL} and ${MAX_TRUST_LEVEL}`,
    );
  }
  return value;
}

function normalizeTimestamp(value) {
  if (value === undefined || value === null) {
    return Date.now();
  }
  if (!Number.isInteger(value) || value < 0) {
    throw new Error("timestamp must be a non-negative integer when set");
  }
  return value;
}

function encodeJson(value) {
  return value === undefined ? null : JSON.stringify(value);
}

function decodeJson(value, fieldName) {
  if (value === undefined || value === null) {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${fieldName} contains invalid JSON`);
  }
}

function normalizePositiveInteger(value, fieldName, fallback) {
  if (value === undefined || value === null) {
    return fallback;
  }
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive integer when set`);
  }
  return value;
}

function readEdgeExpiryMs(evidenceRef) {
  if (typeof evidenceRef !== "string" || evidenceRef.trim().length === 0) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(evidenceRef);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return undefined;
    }
    const raw =
      parsed.expiresAtU64 ??
      parsed.expiresAtMs ??
      parsed.expiresAt ??
      parsed.expiry ??
      parsed.expiryMs;
    if (!Number.isInteger(raw) || raw <= 0) {
      return undefined;
    }
    return raw;
  } catch {
    return undefined;
  }
}

function isEdgeExpired(evidenceRef, nowMs) {
  const expiresAtMs = readEdgeExpiryMs(evidenceRef);
  if (expiresAtMs === undefined) {
    return false;
  }
  return expiresAtMs <= nowMs;
}

function loadDatabaseSync() {
  try {
    const sqlite = require("node:sqlite");
    if (typeof sqlite.DatabaseSync !== "function") {
      throw new Error("node:sqlite.DatabaseSync is unavailable");
    }
    return sqlite.DatabaseSync;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`node:sqlite is required for local trust store support (${reason})`);
  }
}

function initializeSchema(db) {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS edges_latest (
      rater TEXT NOT NULL,
      target TEXT NOT NULL,
      context_id TEXT NOT NULL,
      level_i8 INTEGER NOT NULL CHECK (level_i8 >= -2 AND level_i8 <= 2),
      updated_at_u64 INTEGER NOT NULL,
      evidence_ref TEXT,
      source TEXT NOT NULL,
      PRIMARY KEY (rater, target, context_id)
    );

    CREATE INDEX IF NOT EXISTS idx_edges_latest_rater_context
    ON edges_latest(rater, context_id);

    CREATE INDEX IF NOT EXISTS idx_edges_latest_target_context
    ON edges_latest(target, context_id);

    CREATE TABLE IF NOT EXISTS receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT,
      call_key TEXT NOT NULL,
      session_key TEXT,
      decider TEXT NOT NULL,
      target TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      context_id TEXT NOT NULL,
      decision TEXT NOT NULL CHECK (decision IN ('allow', 'ask', 'deny')),
      epoch INTEGER,
      created_at_u64 INTEGER NOT NULL,
      receipt_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_receipts_receipt_id
    ON receipts(receipt_id)
    WHERE receipt_id IS NOT NULL;

    CREATE INDEX IF NOT EXISTS idx_receipts_target_context_created
    ON receipts(target, context_id, created_at_u64 DESC);

    CREATE TABLE IF NOT EXISTS agents (
      principal_id TEXT PRIMARY KEY,
      display_name TEXT,
      agent_card_json TEXT,
      metadata_json TEXT,
      source TEXT NOT NULL,
      first_seen_at_u64 INTEGER NOT NULL,
      last_seen_at_u64 INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_agents_last_seen
    ON agents(last_seen_at_u64 DESC);

    CREATE TABLE IF NOT EXISTS workflow_tickets (
      ticket TEXT PRIMARY KEY,
      ticket_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      source TEXT NOT NULL,
      created_at_u64 INTEGER NOT NULL,
      expires_at_u64 INTEGER NOT NULL,
      consumed_at_u64 INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_workflow_tickets_expiry
    ON workflow_tickets(expires_at_u64);

    CREATE INDEX IF NOT EXISTS idx_workflow_tickets_consumed
    ON workflow_tickets(consumed_at_u64);
  `);
}

export function openTrustStore(trustStorePath) {
  const resolvedPath = path.resolve(ensureNonEmptyString(trustStorePath, "trustStorePath"));
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });

  const DatabaseSync = loadDatabaseSync();
  const db = new DatabaseSync(resolvedPath);
  initializeSchema(db);

  const upsertEdgeStatement = db.prepare(`
    INSERT INTO edges_latest (
      rater,
      target,
      context_id,
      level_i8,
      updated_at_u64,
      evidence_ref,
      source
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(rater, target, context_id) DO UPDATE SET
      level_i8 = excluded.level_i8,
      updated_at_u64 = excluded.updated_at_u64,
      evidence_ref = excluded.evidence_ref,
      source = excluded.source
    WHERE excluded.updated_at_u64 >= edges_latest.updated_at_u64
  `);

  const upsertAgentStatement = db.prepare(`
    INSERT INTO agents (
      principal_id,
      display_name,
      agent_card_json,
      metadata_json,
      source,
      first_seen_at_u64,
      last_seen_at_u64
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(principal_id) DO UPDATE SET
      display_name = COALESCE(excluded.display_name, agents.display_name),
      agent_card_json = COALESCE(excluded.agent_card_json, agents.agent_card_json),
      metadata_json = COALESCE(excluded.metadata_json, agents.metadata_json),
      source = excluded.source,
      last_seen_at_u64 = excluded.last_seen_at_u64
  `);

  const insertReceiptStatement = db.prepare(`
    INSERT INTO receipts (
      receipt_id,
      call_key,
      session_key,
      decider,
      target,
      tool_name,
      context_id,
      decision,
      epoch,
      created_at_u64,
      receipt_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const selectEdgeLatestStatement = db.prepare(`
    SELECT
      level_i8,
      updated_at_u64,
      evidence_ref
    FROM edges_latest
    WHERE rater = ?
      AND target = ?
      AND context_id = ?
    LIMIT 1
  `);

  const selectEndorserCandidatesStatement = db.prepare(`
    SELECT
      de.target AS endorser,
      de.level_i8 AS level_de,
      de.evidence_ref AS de_evidence_ref,
      COALESCE(et.level_i8, 0) AS level_et,
      et.updated_at_u64 AS et_updated_at_u64,
      et.evidence_ref AS et_evidence_ref
    FROM edges_latest AS de
    LEFT JOIN edges_latest AS et
      ON et.rater = de.target
      AND et.target = ?
      AND et.context_id = de.context_id
    WHERE de.rater = ?
      AND de.context_id = ?
      AND de.level_i8 > 0
      AND de.target <> ?
    ORDER BY de.target ASC
  `);

  const insertWorkflowTicketStatement = db.prepare(`
    INSERT INTO workflow_tickets (
      ticket,
      ticket_type,
      payload_json,
      source,
      created_at_u64,
      expires_at_u64,
      consumed_at_u64
    ) VALUES (?, ?, ?, ?, ?, ?, NULL)
  `);

  const selectWorkflowTicketStatement = db.prepare(`
    SELECT
      ticket,
      ticket_type,
      payload_json,
      source,
      created_at_u64,
      expires_at_u64,
      consumed_at_u64
    FROM workflow_tickets
    WHERE ticket = ?
    LIMIT 1
  `);

  const consumeWorkflowTicketStatement = db.prepare(`
    UPDATE workflow_tickets
    SET consumed_at_u64 = ?
    WHERE ticket = ?
      AND consumed_at_u64 IS NULL
  `);

  const deleteExpiredWorkflowTicketsStatement = db.prepare(`
    DELETE FROM workflow_tickets
    WHERE expires_at_u64 <= ?
      AND consumed_at_u64 IS NULL
  `);

  const selectDirectEdgesByRaterTargetStatement = db.prepare(`
    SELECT
      context_id,
      level_i8,
      updated_at_u64,
      evidence_ref,
      source
    FROM edges_latest
    WHERE rater = ?
      AND target = ?
    ORDER BY updated_at_u64 DESC, context_id ASC
    LIMIT ?
  `);

  const selectDirectEdgesByRaterTargetContextStatement = db.prepare(`
    SELECT
      context_id,
      level_i8,
      updated_at_u64,
      evidence_ref,
      source
    FROM edges_latest
    WHERE rater = ?
      AND target = ?
      AND context_id = ?
    ORDER BY updated_at_u64 DESC
    LIMIT ?
  `);

  const selectAgentByPrincipalStatement = db.prepare(`
    SELECT
      principal_id,
      display_name,
      agent_card_json,
      metadata_json,
      source,
      first_seen_at_u64,
      last_seen_at_u64
    FROM agents
    WHERE principal_id = ?
    LIMIT 1
  `);

  const selectAgentsStatement = db.prepare(`
    SELECT
      principal_id,
      display_name,
      agent_card_json,
      metadata_json,
      source,
      first_seen_at_u64,
      last_seen_at_u64
    FROM agents
    WHERE agent_card_json IS NOT NULL
    ORDER BY last_seen_at_u64 DESC, principal_id ASC
    LIMIT ?
  `);

  function mapAgentRow(row) {
    if (!row) {
      return undefined;
    }
    return {
      principalId: row.principal_id,
      displayName: row.display_name ?? null,
      agentCard: decodeJson(row.agent_card_json, "agents.agent_card_json"),
      metadata: decodeJson(row.metadata_json, "agents.metadata_json"),
      source: row.source,
      firstSeenAt: Number(row.first_seen_at_u64),
      lastSeenAt: Number(row.last_seen_at_u64),
    };
  }

  return {
    path: resolvedPath,
    upsertEdgeLatest(edge) {
      const row = edge ?? {};
      upsertEdgeStatement.run(
        ensureNonEmptyString(row.rater, "edge.rater"),
        ensureNonEmptyString(row.target, "edge.target"),
        ensureNonEmptyString(row.contextId, "edge.contextId").toLowerCase(),
        ensureTrustLevel(row.level),
        normalizeTimestamp(row.updatedAt),
        typeof row.evidenceRef === "string" && row.evidenceRef.trim().length > 0
          ? row.evidenceRef.trim()
          : null,
        ensureNonEmptyString(row.source ?? "local", "edge.source"),
      );
    },
    upsertAgent(agent) {
      const row = agent ?? {};
      const timestamp = normalizeTimestamp(row.seenAt);
      upsertAgentStatement.run(
        ensureNonEmptyString(row.principalId, "agent.principalId"),
        typeof row.displayName === "string" && row.displayName.trim().length > 0
          ? row.displayName.trim()
          : null,
        encodeJson(row.agentCard),
        encodeJson(row.metadata),
        ensureNonEmptyString(row.source ?? "runtime", "agent.source"),
        timestamp,
        timestamp,
      );
    },
    insertReceipt(receipt) {
      const row = receipt ?? {};
      const decision = ensureNonEmptyString(row.decision, "receipt.decision").toLowerCase();
      if (!VALID_DECISIONS.has(decision)) {
        throw new Error("receipt.decision must be one of: allow, ask, deny");
      }

      insertReceiptStatement.run(
        typeof row.receiptId === "string" && row.receiptId.trim().length > 0
          ? row.receiptId.trim()
          : null,
        ensureNonEmptyString(row.callKey, "receipt.callKey"),
        typeof row.sessionKey === "string" && row.sessionKey.trim().length > 0
          ? row.sessionKey.trim()
          : null,
        ensureNonEmptyString(row.decider, "receipt.decider"),
        ensureNonEmptyString(row.target, "receipt.target"),
        ensureNonEmptyString(row.toolName, "receipt.toolName"),
        ensureNonEmptyString(row.contextId, "receipt.contextId").toLowerCase(),
        decision,
        row.epoch === undefined || row.epoch === null
          ? null
          : normalizeTimestamp(Number(row.epoch)),
        normalizeTimestamp(row.createdAt),
        JSON.stringify(row.receipt ?? null),
      );
    },
    getEdgeLatest(edgeRef) {
      const input = edgeRef ?? {};
      const row = selectEdgeLatestStatement.get(
        ensureNonEmptyString(input.rater, "edgeRef.rater"),
        ensureNonEmptyString(input.target, "edgeRef.target"),
        ensureNonEmptyString(input.contextId, "edgeRef.contextId").toLowerCase(),
      );
      if (!row) {
        return undefined;
      }
      if (isEdgeExpired(row.evidence_ref, Date.now())) {
        return undefined;
      }
      return {
        level: Number(row.level_i8),
        updatedAt: Number(row.updated_at_u64),
        evidenceRef: row.evidence_ref ?? null,
      };
    },
    listEndorserCandidates(query) {
      const input = query ?? {};
      const rows = selectEndorserCandidatesStatement.all(
        ensureNonEmptyString(input.target, "query.target"),
        ensureNonEmptyString(input.decider, "query.decider"),
        ensureNonEmptyString(input.contextId, "query.contextId").toLowerCase(),
        ensureNonEmptyString(input.target, "query.target"),
      );
      return rows.map((row) => {
        const nowMs = Date.now();
        const levelDe = isEdgeExpired(row.de_evidence_ref, nowMs) ? 0 : Number(row.level_de);
        const levelEt = isEdgeExpired(row.et_evidence_ref, nowMs) ? 0 : Number(row.level_et);
        return {
          endorser: row.endorser,
          levelDe,
          levelEt,
          etUpdatedAt:
            row.et_updated_at_u64 === null || row.et_updated_at_u64 === undefined
              ? null
              : Number(row.et_updated_at_u64),
          etHasEvidence:
            typeof row.et_evidence_ref === "string" && row.et_evidence_ref.trim().length > 0,
        };
      });
    },
    getAgent(query) {
      const input = query ?? {};
      const row = selectAgentByPrincipalStatement.get(
        ensureNonEmptyString(input.principalId, "query.principalId"),
      );
      return mapAgentRow(row);
    },
    listAgents(query) {
      const input = query ?? {};
      const limit = normalizePositiveInteger(input.limit, "query.limit", 20);
      const rows = selectAgentsStatement.all(limit);
      return rows.map((row) => mapAgentRow(row));
    },
    insertWorkflowTicket(ticketRecord) {
      const row = ticketRecord ?? {};
      const createdAt = normalizeTimestamp(row.createdAt);
      const expiresAt = normalizeTimestamp(row.expiresAt);
      if (expiresAt <= createdAt) {
        throw new Error("ticket.expiresAt must be greater than ticket.createdAt");
      }
      insertWorkflowTicketStatement.run(
        ensureNonEmptyString(row.ticket, "ticket.ticket"),
        ensureNonEmptyString(row.ticketType, "ticket.ticketType"),
        JSON.stringify(row.payload ?? null),
        ensureNonEmptyString(row.source ?? "workflow", "ticket.source"),
        createdAt,
        expiresAt,
      );
    },
    consumeWorkflowTicket(ticketRef) {
      const input = ticketRef ?? {};
      const ticket = ensureNonEmptyString(input.ticket, "ticketRef.ticket");
      const nowMs = normalizeTimestamp(input.nowMs);
      const row = selectWorkflowTicketStatement.get(ticket);
      if (!row || row.consumed_at_u64 !== null || Number(row.expires_at_u64) <= nowMs) {
        return undefined;
      }

      const result = consumeWorkflowTicketStatement.run(nowMs, ticket);
      if (!result || result.changes !== 1) {
        return undefined;
      }

      return {
        ticket: row.ticket,
        ticketType: row.ticket_type,
        payload: decodeJson(row.payload_json, "workflow_tickets.payload_json"),
        source: row.source,
        createdAt: Number(row.created_at_u64),
        expiresAt: Number(row.expires_at_u64),
        consumedAt: nowMs,
      };
    },
    pruneExpiredWorkflowTickets(query) {
      const input = query ?? {};
      const nowMs = normalizeTimestamp(input.nowMs);
      const result = deleteExpiredWorkflowTicketsStatement.run(nowMs);
      return Number(result?.changes ?? 0);
    },
    listDirectEdges(query) {
      const input = query ?? {};
      const limit = normalizePositiveInteger(input.limit, "query.limit", DEFAULT_LIST_LIMIT);
      const contextId =
        input.contextId === undefined || input.contextId === null
          ? undefined
          : ensureNonEmptyString(input.contextId, "query.contextId").toLowerCase();
      const rows =
        contextId === undefined
          ? selectDirectEdgesByRaterTargetStatement.all(
              ensureNonEmptyString(input.rater, "query.rater"),
              ensureNonEmptyString(input.target, "query.target"),
              limit,
            )
          : selectDirectEdgesByRaterTargetContextStatement.all(
              ensureNonEmptyString(input.rater, "query.rater"),
              ensureNonEmptyString(input.target, "query.target"),
              contextId,
              limit,
            );

      const nowMs = Date.now();
      return rows
        .filter((row) => !isEdgeExpired(row.evidence_ref, nowMs))
        .map((row) => ({
          contextId: row.context_id,
          level: Number(row.level_i8),
          updatedAt: Number(row.updated_at_u64),
          evidenceRef: row.evidence_ref ?? null,
          source: row.source,
        }));
    },
    close() {
      db.close();
    },
  };
}
