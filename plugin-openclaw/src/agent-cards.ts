import crypto from "node:crypto";

export const AGENT_CARD_TYPE_V1 = "openclaw.agentCard.v1";
export const AGENT_CARD_ACTION_IMPORT = "import";
export const AGENT_CARD_ACTION_STATUS = "status";
export const AGENT_CARD_STATUS_VERIFIED = "verified";
export const AGENT_CARD_STATUS_OWNER_UNKNOWN = "owner-unknown";

const AGENT_CARD_ACTIONS = new Set([AGENT_CARD_ACTION_IMPORT, AGENT_CARD_ACTION_STATUS]);
const AGENT_CARD_POLICY_KEYS = new Set(["trustedOwnerPubKeys"]);
const AGENT_CARD_KEYS = new Set([
  "type",
  "agentRef",
  "displayName",
  "endpoints",
  "capabilities",
  "policyManifestHash",
  "issuedAt",
  "agentPubKey",
  "ownerPubKey",
  "signatures",
]);
const SIGNATURE_KEYS = new Set(["agentSig", "ownerSig"]);
const HEX_BYTES32_RE = /^0x[a-fA-F0-9]{64}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MIN_STATUS_LIMIT = 1;
const MAX_STATUS_LIMIT = 100;
const DEFAULT_STATUS_LIMIT = 20;

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

function canonicalizePrincipalId(value) {
  const trimmed = ensureNonEmptyString(value, "principalId");
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return trimmed;
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
  const obj = ensureRecord(value, "value");
  const keys = Object.keys(obj).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`);
  return `{${parts.join(",")}}`;
}

function canonicalizeUnsignedPayloadBytes(unsignedPayload) {
  return Buffer.from(stableStringify(unsignedPayload), "utf8");
}

function normalizeStringArray(value, fieldName) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty array`);
  }
  const normalized = [];
  const seen = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const item = value[index];
    if (typeof item !== "string" || item.trim().length === 0) {
      throw new Error(`${fieldName}[${index}] must be a non-empty string`);
    }
    const trimmed = item.trim();
    if (seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    normalized.push(trimmed);
  }
  return normalized;
}

function parseRfc3339(value, fieldName) {
  const text = ensureNonEmptyString(value, fieldName);
  const timeMs = Date.parse(text);
  if (!Number.isFinite(timeMs)) {
    throw new Error(`${fieldName} must be an RFC3339 timestamp`);
  }
  return text;
}

function normalizeBase64(value, fieldName, expectedSize) {
  const text = ensureNonEmptyString(value, fieldName);
  const normalized = text.replace(/-/g, "+").replace(/_/g, "/");
  if (normalized.length % 4 === 1 || !BASE64_RE.test(normalized)) {
    throw new Error(`${fieldName} must be valid base64`);
  }
  const bytes = Buffer.from(normalized, "base64");
  const canonical = bytes.toString("base64");
  if (canonical.replace(/=+$/u, "") !== normalized.replace(/=+$/u, "")) {
    throw new Error(`${fieldName} must be valid base64`);
  }
  if (bytes.length !== expectedSize) {
    throw new Error(`${fieldName} must decode to ${expectedSize} bytes`);
  }
  return {
    bytes,
    canonical,
  };
}

function deriveAgentRef(agentPublicKeyBytes) {
  return `0x${crypto.createHash("sha256").update(agentPublicKeyBytes).digest("hex")}`;
}

function createEd25519PublicKey(rawBytes, fieldName) {
  if (!Buffer.isBuffer(rawBytes) || rawBytes.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`${fieldName} must decode to ${ED25519_PUBLIC_KEY_SIZE} bytes`);
  }
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawBytes]),
    type: "spki",
    format: "der",
  });
}

function verifyEd25519Signature({ payloadBytes, publicKeyBytes, signatureBytes, fieldName }) {
  const key = createEd25519PublicKey(publicKeyBytes, fieldName);
  if (!crypto.verify(null, payloadBytes, key, signatureBytes)) {
    throw new Error(`${fieldName} is invalid`);
  }
}

function normalizeCardShape(cardRaw) {
  const card = ensureRecord(cardRaw, "agentCard");
  ensureKnownKeys(card, AGENT_CARD_KEYS, "agentCard");

  const type = ensureNonEmptyString(card.type, "agentCard.type");
  if (type !== AGENT_CARD_TYPE_V1) {
    throw new Error(`agentCard.type must be ${AGENT_CARD_TYPE_V1}`);
  }

  const agentRef = ensureNonEmptyString(card.agentRef, "agentCard.agentRef");
  if (!HEX_BYTES32_RE.test(agentRef)) {
    throw new Error("agentCard.agentRef must be a 32-byte hex string");
  }

  let policyManifestHash;
  if (card.policyManifestHash !== undefined && card.policyManifestHash !== null) {
    policyManifestHash = ensureNonEmptyString(
      card.policyManifestHash,
      "agentCard.policyManifestHash",
    );
    if (!HEX_BYTES32_RE.test(policyManifestHash)) {
      throw new Error("agentCard.policyManifestHash must be a 32-byte hex string");
    }
    policyManifestHash = policyManifestHash.toLowerCase();
  }

  const signatures = ensureRecord(card.signatures, "agentCard.signatures");
  ensureKnownKeys(signatures, SIGNATURE_KEYS, "agentCard.signatures");

  const normalizedAgentPubKey = normalizeBase64(
    card.agentPubKey,
    "agentCard.agentPubKey",
    ED25519_PUBLIC_KEY_SIZE,
  );
  const normalizedOwnerPubKey = normalizeBase64(
    card.ownerPubKey,
    "agentCard.ownerPubKey",
    ED25519_PUBLIC_KEY_SIZE,
  );
  const normalizedAgentSig = normalizeBase64(
    signatures.agentSig,
    "agentCard.signatures.agentSig",
    ED25519_SIGNATURE_SIZE,
  );
  const normalizedOwnerSig = normalizeBase64(
    signatures.ownerSig,
    "agentCard.signatures.ownerSig",
    ED25519_SIGNATURE_SIZE,
  );

  const normalizedCard = {
    type: AGENT_CARD_TYPE_V1,
    agentRef: agentRef.toLowerCase(),
    displayName: ensureNonEmptyString(card.displayName, "agentCard.displayName"),
    endpoints: normalizeStringArray(card.endpoints, "agentCard.endpoints"),
    capabilities: normalizeStringArray(card.capabilities, "agentCard.capabilities"),
    issuedAt: parseRfc3339(card.issuedAt, "agentCard.issuedAt"),
    agentPubKey: normalizedAgentPubKey.canonical,
    ownerPubKey: normalizedOwnerPubKey.canonical,
    signatures: {
      agentSig: normalizedAgentSig.canonical,
      ownerSig: normalizedOwnerSig.canonical,
    },
  };
  if (policyManifestHash) {
    normalizedCard.policyManifestHash = policyManifestHash;
  }

  return {
    card: normalizedCard,
    agentPublicKeyBytes: normalizedAgentPubKey.bytes,
    ownerPublicKeyBytes: normalizedOwnerPubKey.bytes,
    agentSignatureBytes: normalizedAgentSig.bytes,
    ownerSignatureBytes: normalizedOwnerSig.bytes,
  };
}

function buildUnsignedCardPayload(card) {
  const unsigned = {
    type: card.type,
    agentRef: card.agentRef,
    displayName: card.displayName,
    endpoints: card.endpoints,
    capabilities: card.capabilities,
    issuedAt: card.issuedAt,
    agentPubKey: card.agentPubKey,
    ownerPubKey: card.ownerPubKey,
  };
  if (card.policyManifestHash) {
    unsigned.policyManifestHash = card.policyManifestHash;
  }
  return unsigned;
}

function normalizeTrustedOwnerKeys(value, fieldName) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array when set`);
  }
  const normalized = [];
  const seen = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const parsed = normalizeBase64(value[index], `${fieldName}[${index}]`, ED25519_PUBLIC_KEY_SIZE);
    if (seen.has(parsed.canonical)) {
      continue;
    }
    seen.add(parsed.canonical);
    normalized.push(parsed.canonical);
  }
  return normalized;
}

function normalizeStatusLimit(value) {
  if (value === undefined || value === null) {
    return DEFAULT_STATUS_LIMIT;
  }
  if (!Number.isInteger(value)) {
    throw new Error("trustnetAgentCardAction.limit must be an integer when set");
  }
  if (value < MIN_STATUS_LIMIT || value > MAX_STATUS_LIMIT) {
    throw new Error(
      `trustnetAgentCardAction.limit must be between ${MIN_STATUS_LIMIT} and ${MAX_STATUS_LIMIT}`,
    );
  }
  return value;
}

export function parseAgentCardPolicy(pluginConfigRaw) {
  const pluginConfig = ensureRecord(pluginConfigRaw ?? {}, "pluginConfig");
  const agentCardsRaw = pluginConfig.agentCards;
  if (agentCardsRaw === undefined || agentCardsRaw === null) {
    return { trustedOwnerPubKeys: [] };
  }
  const agentCards = ensureRecord(agentCardsRaw, "pluginConfig.agentCards");
  ensureKnownKeys(agentCards, AGENT_CARD_POLICY_KEYS, "pluginConfig.agentCards");

  return {
    trustedOwnerPubKeys: normalizeTrustedOwnerKeys(
      agentCards.trustedOwnerPubKeys,
      "pluginConfig.agentCards.trustedOwnerPubKeys",
    ),
  };
}

export function readAgentCardActionInput(event, ctx) {
  if (event && typeof event === "object" && event.trustnetAgentCardAction) {
    return event.trustnetAgentCardAction;
  }
  if (ctx && typeof ctx === "object" && ctx.trustnetAgentCardAction) {
    return ctx.trustnetAgentCardAction;
  }
  return undefined;
}

export function normalizeAgentCardAction(actionRaw) {
  const action = ensureRecord(actionRaw, "trustnetAgentCardAction");
  const normalizedAction = ensureNonEmptyString(action.action, "trustnetAgentCardAction.action");
  if (!AGENT_CARD_ACTIONS.has(normalizedAction)) {
    throw new Error(
      `trustnetAgentCardAction.action must be one of: ${Array.from(
        AGENT_CARD_ACTIONS.values(),
      ).join(", ")}`,
    );
  }

  if (normalizedAction === AGENT_CARD_ACTION_IMPORT) {
    let card = action.card ?? action.agentCard;
    if (typeof card === "string") {
      try {
        card = JSON.parse(card);
      } catch {
        throw new Error("trustnetAgentCardAction.card must be valid JSON when provided as string");
      }
    }
    return {
      action: AGENT_CARD_ACTION_IMPORT,
      source:
        action.source === undefined || action.source === null
          ? "runtime-action"
          : ensureNonEmptyString(action.source, "trustnetAgentCardAction.source"),
      card: ensureRecord(card, "trustnetAgentCardAction.card"),
    };
  }

  let includeCard = false;
  if (action.includeCard !== undefined && action.includeCard !== null) {
    if (typeof action.includeCard !== "boolean") {
      throw new Error("trustnetAgentCardAction.includeCard must be a boolean when set");
    }
    includeCard = action.includeCard;
  }

  return {
    action: AGENT_CARD_ACTION_STATUS,
    principalId:
      action.principalId === undefined || action.principalId === null
        ? undefined
        : canonicalizePrincipalId(action.principalId),
    includeCard,
    limit: normalizeStatusLimit(action.limit),
  };
}

export function verifyAgentCard(cardRaw, policy) {
  const normalized = normalizeCardShape(cardRaw);
  const unsignedPayload = buildUnsignedCardPayload(normalized.card);
  const payloadBytes = canonicalizeUnsignedPayloadBytes(unsignedPayload);

  const derivedRef = deriveAgentRef(normalized.agentPublicKeyBytes);
  if (derivedRef !== normalized.card.agentRef) {
    throw new Error("agentCard.agentRef does not match sha256(agentPubKey)");
  }

  verifyEd25519Signature({
    payloadBytes,
    publicKeyBytes: normalized.agentPublicKeyBytes,
    signatureBytes: normalized.agentSignatureBytes,
    fieldName: "agentCard.signatures.agentSig",
  });
  verifyEd25519Signature({
    payloadBytes,
    publicKeyBytes: normalized.ownerPublicKeyBytes,
    signatureBytes: normalized.ownerSignatureBytes,
    fieldName: "agentCard.signatures.ownerSig",
  });

  const trustedOwnerKeys = Array.isArray(policy?.trustedOwnerPubKeys)
    ? policy.trustedOwnerPubKeys
    : [];
  const ownerTrusted = new Set(trustedOwnerKeys).has(normalized.card.ownerPubKey);

  return {
    principalId: normalized.card.agentRef,
    card: normalized.card,
    status: ownerTrusted ? AGENT_CARD_STATUS_VERIFIED : AGENT_CARD_STATUS_OWNER_UNKNOWN,
    ownerTrusted,
    unsignedPayloadHash: `0x${crypto.createHash("sha256").update(payloadBytes).digest("hex")}`,
  };
}
