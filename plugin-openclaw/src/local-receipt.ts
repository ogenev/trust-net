import crypto from "node:crypto";

const DECISIONS = new Set(["allow", "ask", "deny"]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function ensureNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function normalizeDecision(value) {
  const decision = ensureNonEmptyString(value, "decision").toLowerCase();
  if (!DECISIONS.has(decision)) {
    throw new Error("decision must be one of: allow, ask, deny");
  }
  return decision;
}

function stableStringify(value) {
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${parts.join(",")}}`;
}

function hashValue(value) {
  return `0x${crypto.createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

function normalizeError(error) {
  if (error === undefined) {
    return null;
  }
  if (typeof error === "string") {
    return error;
  }
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack ?? null,
    };
  }
  return error ?? null;
}

function buildConstraints(mapping) {
  if (!isRecord(mapping?.constraints)) {
    return undefined;
  }
  const constraints = { ...mapping.constraints };
  return Object.keys(constraints).length > 0 ? constraints : undefined;
}

function deriveUserApproved(decision, askResolution) {
  if (askResolution && typeof askResolution.userApproved === "boolean") {
    return askResolution.userApproved;
  }
  return decision === "allow";
}

function toIntegerOrNull(value) {
  if (Number.isInteger(value)) {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  return null;
}

function buildWhySnapshot({ localDecision, decisionBundle }) {
  if (localDecision) {
    return {
      edgeDT: { level: localDecision.levelDt ?? 0 },
      edgeDE: {
        level: localDecision.levelDe ?? 0,
        endorser: localDecision.endorser ?? null,
      },
      edgeET: {
        level: localDecision.levelEt ?? 0,
        endorser: localDecision.endorser ?? null,
      },
      score: localDecision.score ?? null,
      thresholds: localDecision.thresholds ?? null,
    };
  }

  return {
    edgeDT: { level: null },
    edgeDE: { level: null, endorser: null },
    edgeET: { level: null, endorser: null },
    score: toIntegerOrNull(decisionBundle?.score),
    thresholds: isRecord(decisionBundle?.thresholds) ? decisionBundle.thresholds : null,
    path: decisionBundle?.why ?? null,
  };
}

function buildDecisionSnapshot({ localDecision, decisionBundle, root }) {
  return {
    score: localDecision?.score ?? toIntegerOrNull(decisionBundle?.score),
    thresholds: localDecision?.thresholds ?? decisionBundle?.thresholds ?? null,
    endorser: localDecision?.endorser ?? null,
    epoch: toIntegerOrNull(decisionBundle?.epoch),
    graphRoot: typeof root?.graphRoot === "string" ? root.graphRoot : null,
    manifestHash: typeof root?.manifestHash === "string" ? root.manifestHash : null,
  };
}

function buildAskActionSnapshot(askResolution) {
  if (!isRecord(askResolution)) {
    return undefined;
  }
  return {
    action: askResolution.action,
    ttlSeconds: askResolution.ttlSeconds ?? null,
    expiresAtU64: askResolution.expiresAtMs ?? null,
    persistedEdge: askResolution.persistedEdge ?? false,
    userApproved: askResolution.userApproved ?? false,
  };
}

function readOwnerSig(verifiableReceipt) {
  if (!isRecord(verifiableReceipt)) {
    return undefined;
  }
  if (typeof verifiableReceipt.ownerSig === "string" && verifiableReceipt.ownerSig.length > 0) {
    return verifiableReceipt.ownerSig;
  }
  if (
    typeof verifiableReceipt.signature === "string" &&
    verifiableReceipt.signature.length > 0
  ) {
    return verifiableReceipt.signature;
  }
  return undefined;
}

export function shouldPersistReceiptForMapping(mapping) {
  const riskTier = typeof mapping?.riskTier === "string" ? mapping.riskTier.trim().toLowerCase() : "";
  return riskTier === "high";
}

export function buildLocalInteractionReceipt({
  decision,
  mapping,
  targetPrincipalId,
  toolName,
  params,
  result,
  error,
  createdAtMs,
  localDecision,
  decisionBundle,
  root,
  askResolution,
  verifiableReceipt,
}) {
  const normalizedDecision = normalizeDecision(decision);
  const timestampMs = Number.isInteger(createdAtMs) && createdAtMs > 0 ? createdAtMs : Date.now();
  const receipt = {
    type: "trustnet.receipt.v1",
    receiptId: crypto.randomUUID(),
    createdAt: new Date(timestampMs).toISOString(),
    target: ensureNonEmptyString(targetPrincipalId, "targetPrincipalId"),
    contextId: ensureNonEmptyString(mapping?.contextId, "mapping.contextId").toLowerCase(),
    tool: ensureNonEmptyString(toolName, "toolName"),
    argsHash: hashValue(params ?? {}),
    resultHash: hashValue({
      result: result === undefined ? null : result,
      error: normalizeError(error),
    }),
    decision: normalizedDecision,
    userApproved: deriveUserApproved(normalizedDecision, askResolution),
    why: buildWhySnapshot({ localDecision, decisionBundle }),
    decisionSnapshot: buildDecisionSnapshot({ localDecision, decisionBundle, root }),
  };

  const constraints = buildConstraints(mapping);
  if (constraints) {
    receipt.constraints = constraints;
  }

  const askAction = buildAskActionSnapshot(askResolution);
  if (askAction) {
    receipt.askAction = askAction;
  }

  const ownerSig = readOwnerSig(verifiableReceipt);
  if (ownerSig) {
    receipt.ownerSig = ownerSig;
  }

  if (isRecord(verifiableReceipt)) {
    receipt.verifiable = verifiableReceipt;
  }

  return receipt;
}
