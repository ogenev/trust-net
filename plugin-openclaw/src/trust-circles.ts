export const TRUST_CIRCLE_ONLY_ME = "onlyMe";
export const TRUST_CIRCLE_MY_CONTACTS = "myContacts";
export const TRUST_CIRCLE_OPENCLAW_VERIFIED = "openclawVerified";
export const TRUST_CIRCLE_CUSTOM = "custom";

const TRUST_CIRCLE_PRESETS = new Set([
  TRUST_CIRCLE_ONLY_ME,
  TRUST_CIRCLE_MY_CONTACTS,
  TRUST_CIRCLE_OPENCLAW_VERIFIED,
  TRUST_CIRCLE_CUSTOM,
]);

const TRUST_CIRCLE_CONFIG_KEYS = new Set(["default", "endorsers"]);
const TRUST_CIRCLE_ENDORSER_KEYS = new Set([
  TRUST_CIRCLE_MY_CONTACTS,
  TRUST_CIRCLE_OPENCLAW_VERIFIED,
  TRUST_CIRCLE_CUSTOM,
]);

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

function canonicalizePrincipalId(value) {
  const trimmed = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return trimmed;
}

function normalizePrincipalList(value, fieldName) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array when set`);
  }
  const normalized = [];
  const seen = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const item = value[index];
    if (typeof item !== "string" || item.trim().length === 0) {
      throw new Error(`${fieldName}[${index}] must be a non-empty string`);
    }
    const canonical = canonicalizePrincipalId(item);
    if (seen.has(canonical)) {
      continue;
    }
    seen.add(canonical);
    normalized.push(canonical);
  }
  return normalized;
}

export function parseTrustCirclePolicy(pluginConfigRaw) {
  const pluginConfig = ensureRecord(pluginConfigRaw ?? {}, "pluginConfig");
  const trustCirclesRaw = pluginConfig.trustCircles;
  if (trustCirclesRaw === undefined || trustCirclesRaw === null) {
    return {
      default: TRUST_CIRCLE_ONLY_ME,
      endorsers: {
        [TRUST_CIRCLE_MY_CONTACTS]: [],
        [TRUST_CIRCLE_OPENCLAW_VERIFIED]: [],
        [TRUST_CIRCLE_CUSTOM]: [],
      },
    };
  }

  const trustCircles = ensureRecord(trustCirclesRaw, "pluginConfig.trustCircles");
  ensureKnownKeys(trustCircles, TRUST_CIRCLE_CONFIG_KEYS, "pluginConfig.trustCircles");

  const defaultPreset =
    trustCircles.default === undefined ? TRUST_CIRCLE_ONLY_ME : trustCircles.default;
  if (typeof defaultPreset !== "string" || !TRUST_CIRCLE_PRESETS.has(defaultPreset)) {
    throw new Error(
      `pluginConfig.trustCircles.default must be one of: ${Array.from(
        TRUST_CIRCLE_PRESETS.values(),
      ).join(", ")}`,
    );
  }

  const endorsersRaw =
    trustCircles.endorsers === undefined
      ? {}
      : ensureRecord(trustCircles.endorsers, "pluginConfig.trustCircles.endorsers");
  ensureKnownKeys(
    endorsersRaw,
    TRUST_CIRCLE_ENDORSER_KEYS,
    "pluginConfig.trustCircles.endorsers",
  );

  return {
    default: defaultPreset,
    endorsers: {
      [TRUST_CIRCLE_MY_CONTACTS]: normalizePrincipalList(
        endorsersRaw[TRUST_CIRCLE_MY_CONTACTS],
        `pluginConfig.trustCircles.endorsers.${TRUST_CIRCLE_MY_CONTACTS}`,
      ),
      [TRUST_CIRCLE_OPENCLAW_VERIFIED]: normalizePrincipalList(
        endorsersRaw[TRUST_CIRCLE_OPENCLAW_VERIFIED],
        `pluginConfig.trustCircles.endorsers.${TRUST_CIRCLE_OPENCLAW_VERIFIED}`,
      ),
      [TRUST_CIRCLE_CUSTOM]: normalizePrincipalList(
        endorsersRaw[TRUST_CIRCLE_CUSTOM],
        `pluginConfig.trustCircles.endorsers.${TRUST_CIRCLE_CUSTOM}`,
      ),
    },
  };
}

export function filterCandidatesByTrustCircle(policy, candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return [];
  }
  if (!policy || policy.default === TRUST_CIRCLE_ONLY_ME) {
    return [];
  }

  const allowed = policy.endorsers?.[policy.default];
  if (!Array.isArray(allowed) || allowed.length === 0) {
    return [];
  }
  const allowSet = new Set(allowed.map(canonicalizePrincipalId));

  return candidates.filter(
    (candidate) =>
      candidate &&
      typeof candidate === "object" &&
      typeof candidate.endorser === "string" &&
      candidate.endorser.trim().length > 0 &&
      allowSet.has(canonicalizePrincipalId(candidate.endorser)),
  );
}
