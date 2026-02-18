import crypto from "node:crypto";

export const ASK_ACTION_ALLOW_ONCE = "allow_once";
export const ASK_ACTION_ALLOW_TTL = "allow_ttl";
export const ASK_ACTION_ALLOW_ALWAYS = "allow_always";
export const ASK_ACTION_BLOCK = "block";

const ASK_TICKET_TTL_MS = 15 * 60 * 1000;
const DEFAULT_ASK_TTL_SECONDS = 300;
const ASK_ACTIONS = new Set([
  ASK_ACTION_ALLOW_ONCE,
  ASK_ACTION_ALLOW_TTL,
  ASK_ACTION_ALLOW_ALWAYS,
  ASK_ACTION_BLOCK,
]);

function ensureRecord(value, fieldName) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value;
}

function ensureNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function normalizePositiveInteger(value, fieldName) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return value;
}

export function defaultAskTtlSecondsForMapping(mapping) {
  const ttlSeconds = mapping?.constraints?.ttlSeconds;
  if (Number.isInteger(ttlSeconds) && ttlSeconds > 0) {
    return ttlSeconds;
  }
  return DEFAULT_ASK_TTL_SECONDS;
}

export function buildAskPromptPayload({ ticket, mapping, targetPrincipalId }) {
  return {
    type: "trustnet.askPrompt.v1",
    ticket,
    target: targetPrincipalId,
    contextId: mapping.contextId,
    toolPattern: mapping.pattern,
    riskTier: mapping.riskTier ?? null,
    defaultTtlSeconds: defaultAskTtlSecondsForMapping(mapping),
    actions: Array.from(ASK_ACTIONS.values()),
  };
}

export function normalizeAskAction(input) {
  const actionInput = ensureRecord(input, "trustnetAskAction");
  const ticket = ensureNonEmptyString(actionInput.ticket, "trustnetAskAction.ticket");
  const action = ensureNonEmptyString(
    actionInput.action ?? actionInput.type,
    "trustnetAskAction.action",
  ).toLowerCase();
  if (!ASK_ACTIONS.has(action)) {
    throw new Error(
      `trustnetAskAction.action must be one of: ${Array.from(ASK_ACTIONS.values()).join(", ")}`,
    );
  }

  let ttlSeconds;
  if (action === ASK_ACTION_ALLOW_TTL) {
    if (actionInput.ttlSeconds === undefined || actionInput.ttlSeconds === null) {
      ttlSeconds = undefined;
    } else {
      ttlSeconds = normalizePositiveInteger(actionInput.ttlSeconds, "trustnetAskAction.ttlSeconds");
    }
  }

  return {
    ticket,
    action,
    ttlSeconds,
  };
}

export function issueAskTicket(map, payload) {
  const nowMs = Date.now();
  for (const [ticket, value] of map.entries()) {
    if (value.expiresAtMs <= nowMs) {
      map.delete(ticket);
    }
  }

  const ticket = crypto.randomUUID();
  map.set(ticket, {
    ...payload,
    createdAtMs: nowMs,
    expiresAtMs: nowMs + ASK_TICKET_TTL_MS,
  });
  return ticket;
}

export function consumeAskTicket(map, ticket) {
  const normalizedTicket = ensureNonEmptyString(ticket, "ticket");
  const payload = map.get(normalizedTicket);
  if (!payload) {
    return undefined;
  }
  map.delete(normalizedTicket);

  if (payload.expiresAtMs <= Date.now()) {
    return undefined;
  }
  return payload;
}

export function buildAskActionEvidenceRef({
  action,
  ttlSeconds,
  expiresAtMs,
  callKey,
  sessionKey,
  toolName,
}) {
  const payload = {
    type: "trustnet.askAction.v1",
    action,
    grantedAtU64: Date.now(),
    callKey,
    sessionKey: sessionKey ?? null,
    toolName,
  };
  if (ttlSeconds !== undefined) {
    payload.ttlSeconds = ttlSeconds;
  }
  if (expiresAtMs !== undefined) {
    payload.expiresAtU64 = expiresAtMs;
  }
  return JSON.stringify(payload);
}
