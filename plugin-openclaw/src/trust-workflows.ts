import crypto from "node:crypto";

import { filterCandidatesByTrustCircle } from "./trust-circles.js";

export const TRUST_WORKFLOW_ACTION_TRUST = "trust";
export const TRUST_WORKFLOW_ACTION_BLOCK = "block";
export const TRUST_WORKFLOW_ACTION_ENDORSE = "endorse";
export const TRUST_WORKFLOW_ACTION_STATUS = "status";
export const TRUST_WORKFLOW_ACTION_CONFIRM = "confirm";
export const TRUST_WORKFLOW_ACTION_CANCEL = "cancel";

const TRUST_WORKFLOW_ACTIONS = new Set([
  TRUST_WORKFLOW_ACTION_TRUST,
  TRUST_WORKFLOW_ACTION_BLOCK,
  TRUST_WORKFLOW_ACTION_ENDORSE,
  TRUST_WORKFLOW_ACTION_STATUS,
  TRUST_WORKFLOW_ACTION_CONFIRM,
  TRUST_WORKFLOW_ACTION_CANCEL,
]);

const TRUST_WORKFLOW_CONFIG_KEYS = new Set(["confirmationTtlSeconds"]);
const WORKFLOW_TICKET_TYPE_MUTATION = "trustnet.trustWorkflow.mutation.v1";
const DEFAULT_CONFIRMATION_TTL_SECONDS = 300;
const MIN_CONFIRMATION_TTL_SECONDS = 30;
const MAX_CONFIRMATION_TTL_SECONDS = 86_400;
const MIN_STATUS_LIMIT = 1;
const MAX_STATUS_LIMIT = 100;
const DEFAULT_STATUS_LIMIT = 20;
const HEX_BYTES32_RE = /^0x[a-fA-F0-9]{64}$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function ensureRecord(value, fieldName) {
  if (!isRecord(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value;
}

function ensureKnownKeys(value, allowedKeys, fieldName) {
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`${fieldName}.${key} is not supported`);
    }
  }
}

function ensureNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function canonicalizePrincipalId(value, fieldName) {
  const trimmed = ensureNonEmptyString(value, fieldName);
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return trimmed;
}

function normalizeContextId(value, fieldName) {
  const contextId = ensureNonEmptyString(value, fieldName).toLowerCase();
  if (!HEX_BYTES32_RE.test(contextId)) {
    throw new Error(`${fieldName} must be a 32-byte hex string`);
  }
  return contextId;
}

function normalizeTrustLevel(value, fieldName) {
  if (!Number.isInteger(value)) {
    throw new Error(`${fieldName} must be an integer`);
  }
  if (value !== 1 && value !== 2) {
    throw new Error(`${fieldName} must be 1 or 2`);
  }
  return value;
}

function normalizeStatusLimit(value) {
  if (value === undefined || value === null) {
    return DEFAULT_STATUS_LIMIT;
  }
  if (!Number.isInteger(value)) {
    throw new Error("trustnetTrustAction.limit must be an integer when set");
  }
  if (value < MIN_STATUS_LIMIT || value > MAX_STATUS_LIMIT) {
    throw new Error(
      `trustnetTrustAction.limit must be between ${MIN_STATUS_LIMIT} and ${MAX_STATUS_LIMIT}`,
    );
  }
  return value;
}

function normalizeOptionalBoolean(value, fieldName, fallback) {
  if (value === undefined || value === null) {
    return fallback;
  }
  if (typeof value !== "boolean") {
    throw new Error(`${fieldName} must be a boolean when set`);
  }
  return value;
}

export function parseTrustWorkflowPolicy(pluginConfigRaw) {
  const pluginConfig = ensureRecord(pluginConfigRaw ?? {}, "pluginConfig");
  const trustWorkflowsRaw = pluginConfig.trustWorkflows;
  if (trustWorkflowsRaw === undefined || trustWorkflowsRaw === null) {
    return {
      confirmationTtlSeconds: DEFAULT_CONFIRMATION_TTL_SECONDS,
    };
  }
  const trustWorkflows = ensureRecord(trustWorkflowsRaw, "pluginConfig.trustWorkflows");
  ensureKnownKeys(trustWorkflows, TRUST_WORKFLOW_CONFIG_KEYS, "pluginConfig.trustWorkflows");

  const rawTtlSeconds = trustWorkflows.confirmationTtlSeconds;
  if (rawTtlSeconds === undefined || rawTtlSeconds === null) {
    return {
      confirmationTtlSeconds: DEFAULT_CONFIRMATION_TTL_SECONDS,
    };
  }
  if (!Number.isInteger(rawTtlSeconds)) {
    throw new Error("pluginConfig.trustWorkflows.confirmationTtlSeconds must be an integer");
  }
  if (
    rawTtlSeconds < MIN_CONFIRMATION_TTL_SECONDS ||
    rawTtlSeconds > MAX_CONFIRMATION_TTL_SECONDS
  ) {
    throw new Error(
      `pluginConfig.trustWorkflows.confirmationTtlSeconds must be between ${MIN_CONFIRMATION_TTL_SECONDS} and ${MAX_CONFIRMATION_TTL_SECONDS}`,
    );
  }
  return {
    confirmationTtlSeconds: rawTtlSeconds,
  };
}

export function readTrustWorkflowActionInput(event, ctx) {
  if (event && typeof event === "object" && event.trustnetTrustAction) {
    return event.trustnetTrustAction;
  }
  if (ctx && typeof ctx === "object" && ctx.trustnetTrustAction) {
    return ctx.trustnetTrustAction;
  }
  return undefined;
}

export function normalizeTrustWorkflowAction(actionRaw) {
  const action = ensureRecord(actionRaw, "trustnetTrustAction");
  const actionName = ensureNonEmptyString(action.action, "trustnetTrustAction.action").toLowerCase();
  if (!TRUST_WORKFLOW_ACTIONS.has(actionName)) {
    throw new Error(
      `trustnetTrustAction.action must be one of: ${Array.from(TRUST_WORKFLOW_ACTIONS.values()).join(", ")}`,
    );
  }

  if (actionName === TRUST_WORKFLOW_ACTION_TRUST) {
    return {
      action: TRUST_WORKFLOW_ACTION_TRUST,
      targetPrincipalId: canonicalizePrincipalId(
        action.targetPrincipalId,
        "trustnetTrustAction.targetPrincipalId",
      ),
      contextId: normalizeContextId(action.contextId, "trustnetTrustAction.contextId"),
      level:
        action.level === undefined || action.level === null
          ? 2
          : normalizeTrustLevel(action.level, "trustnetTrustAction.level"),
    };
  }

  if (actionName === TRUST_WORKFLOW_ACTION_BLOCK) {
    return {
      action: TRUST_WORKFLOW_ACTION_BLOCK,
      targetPrincipalId: canonicalizePrincipalId(
        action.targetPrincipalId,
        "trustnetTrustAction.targetPrincipalId",
      ),
      contextId: normalizeContextId(action.contextId, "trustnetTrustAction.contextId"),
    };
  }

  if (actionName === TRUST_WORKFLOW_ACTION_ENDORSE) {
    return {
      action: TRUST_WORKFLOW_ACTION_ENDORSE,
      endorserPrincipalId: canonicalizePrincipalId(
        action.endorserPrincipalId,
        "trustnetTrustAction.endorserPrincipalId",
      ),
      contextId: normalizeContextId(action.contextId, "trustnetTrustAction.contextId"),
      level:
        action.level === undefined || action.level === null
          ? 2
          : normalizeTrustLevel(action.level, "trustnetTrustAction.level"),
    };
  }

  if (actionName === TRUST_WORKFLOW_ACTION_STATUS) {
    return {
      action: TRUST_WORKFLOW_ACTION_STATUS,
      principalId: canonicalizePrincipalId(action.principalId, "trustnetTrustAction.principalId"),
      contextId:
        action.contextId === undefined || action.contextId === null
          ? undefined
          : normalizeContextId(action.contextId, "trustnetTrustAction.contextId"),
      includeCandidates: normalizeOptionalBoolean(
        action.includeCandidates,
        "trustnetTrustAction.includeCandidates",
        true,
      ),
      limit: normalizeStatusLimit(action.limit),
    };
  }

  if (actionName === TRUST_WORKFLOW_ACTION_CONFIRM) {
    return {
      action: TRUST_WORKFLOW_ACTION_CONFIRM,
      ticket: ensureNonEmptyString(action.ticket, "trustnetTrustAction.ticket"),
    };
  }

  return {
    action: TRUST_WORKFLOW_ACTION_CANCEL,
    ticket: ensureNonEmptyString(action.ticket, "trustnetTrustAction.ticket"),
  };
}

function buildMutation(action, decider) {
  if (action.action === TRUST_WORKFLOW_ACTION_TRUST) {
    return {
      kind: TRUST_WORKFLOW_ACTION_TRUST,
      rater: decider,
      target: action.targetPrincipalId,
      contextId: action.contextId,
      level: action.level,
      source: "workflow:trust",
    };
  }
  if (action.action === TRUST_WORKFLOW_ACTION_BLOCK) {
    return {
      kind: TRUST_WORKFLOW_ACTION_BLOCK,
      rater: decider,
      target: action.targetPrincipalId,
      contextId: action.contextId,
      level: -2,
      source: "workflow:block",
    };
  }
  return {
    kind: TRUST_WORKFLOW_ACTION_ENDORSE,
    rater: decider,
    target: action.endorserPrincipalId,
    contextId: action.contextId,
    level: action.level,
    source: "workflow:endorse",
  };
}

function issueMutationTicket({ trustStore, mutation, confirmationTtlSeconds, nowMs }) {
  const ticket = crypto.randomUUID();
  const expiresAt = nowMs + confirmationTtlSeconds * 1000;
  trustStore.insertWorkflowTicket({
    ticket,
    ticketType: WORKFLOW_TICKET_TYPE_MUTATION,
    payload: mutation,
    source: mutation.source,
    createdAt: nowMs,
    expiresAt,
  });
  return {
    ticket,
    expiresAt,
  };
}

function applyMutation({ trustStore, mutation, ticket, nowMs }) {
  trustStore.upsertEdgeLatest({
    rater: mutation.rater,
    target: mutation.target,
    contextId: mutation.contextId,
    level: mutation.level,
    updatedAt: nowMs,
    source: mutation.source,
    evidenceRef: JSON.stringify({
      type: "trustnet.trustWorkflow.v1",
      kind: mutation.kind,
      ticket,
      appliedAtU64: nowMs,
    }),
  });
}

function buildMutationPrompt(mutation, ticketInfo) {
  return {
    type: "trustnet.trustWorkflow.prompt.v1",
    ticket: ticketInfo.ticket,
    expiresAtU64: ticketInfo.expiresAt,
    mutation: {
      kind: mutation.kind,
      rater: mutation.rater,
      target: mutation.target,
      contextId: mutation.contextId,
      level: mutation.level,
    },
    actions: [TRUST_WORKFLOW_ACTION_CONFIRM, TRUST_WORKFLOW_ACTION_CANCEL],
  };
}

function buildStatusResult({ statusAction, trustStore, decider, trustCirclePolicy }) {
  if (!statusAction.contextId) {
    const edges = trustStore.listDirectEdges({
      rater: decider,
      target: statusAction.principalId,
      limit: statusAction.limit,
    });
    return {
      type: "trustnet.trustWorkflow.statusResult.v1",
      principalId: statusAction.principalId,
      contextId: null,
      trustCirclePreset: trustCirclePolicy.default,
      directEdges: edges,
    };
  }

  const directEdge = trustStore.getEdgeLatest({
    rater: decider,
    target: statusAction.principalId,
    contextId: statusAction.contextId,
  });
  const candidates = statusAction.includeCandidates
    ? filterCandidatesByTrustCircle(
        trustCirclePolicy,
        trustStore.listEndorserCandidates({
          decider,
          target: statusAction.principalId,
          contextId: statusAction.contextId,
        }),
      ).slice(0, statusAction.limit)
    : [];

  return {
    type: "trustnet.trustWorkflow.statusResult.v1",
    principalId: statusAction.principalId,
    contextId: statusAction.contextId,
    trustCirclePreset: trustCirclePolicy.default,
    directEdge: directEdge ?? null,
    candidateCount: candidates.length,
    candidates,
  };
}

export function handleTrustWorkflowAction({
  actionInput,
  trustStore,
  decider,
  trustWorkflowPolicy,
  trustCirclePolicy,
}) {
  if (actionInput === undefined) {
    return undefined;
  }
  trustStore.pruneExpiredWorkflowTickets({ nowMs: Date.now() });
  const action = normalizeTrustWorkflowAction(actionInput);
  const nowMs = Date.now();

  if (action.action === TRUST_WORKFLOW_ACTION_STATUS) {
    return {
      block: true,
      blockReason: "TrustNet STATUS workflow handled",
      trustnetTrustWorkflow: buildStatusResult({
        statusAction: action,
        trustStore,
        decider,
        trustCirclePolicy,
      }),
    };
  }

  if (
    action.action === TRUST_WORKFLOW_ACTION_TRUST ||
    action.action === TRUST_WORKFLOW_ACTION_BLOCK ||
    action.action === TRUST_WORKFLOW_ACTION_ENDORSE
  ) {
    const mutation = buildMutation(action, decider);
    const ticketInfo = issueMutationTicket({
      trustStore,
      mutation,
      confirmationTtlSeconds: trustWorkflowPolicy.confirmationTtlSeconds,
      nowMs,
    });
    return {
      block: true,
      blockReason: `TrustNet ${mutation.kind.toUpperCase()} confirmation required`,
      trustnetTrustWorkflow: buildMutationPrompt(mutation, ticketInfo),
    };
  }

  const ticketRecord = trustStore.consumeWorkflowTicket({
    ticket: action.ticket,
    nowMs,
  });
  if (!ticketRecord || ticketRecord.ticketType !== WORKFLOW_TICKET_TYPE_MUTATION) {
    throw new Error("invalid or expired TrustNet trust workflow ticket");
  }
  const mutation = ensureRecord(ticketRecord.payload, "workflow ticket payload");

  if (action.action === TRUST_WORKFLOW_ACTION_CANCEL) {
    return {
      block: true,
      blockReason: "TrustNet workflow canceled",
      trustnetTrustWorkflow: {
        type: "trustnet.trustWorkflow.result.v1",
        action: TRUST_WORKFLOW_ACTION_CANCEL,
        ticket: action.ticket,
        applied: false,
        mutation,
      },
    };
  }

  applyMutation({
    trustStore,
    mutation,
    ticket: action.ticket,
    nowMs,
  });
  return {
    block: true,
    blockReason: `TrustNet ${String(mutation.kind ?? "workflow").toUpperCase()} applied`,
    trustnetTrustWorkflow: {
      type: "trustnet.trustWorkflow.result.v1",
      action: TRUST_WORKFLOW_ACTION_CONFIRM,
      ticket: action.ticket,
      applied: true,
      mutation,
    },
  };
}
