export const DEFAULT_THRESHOLDS = Object.freeze({
  allow: 2,
  ask: 1,
});

const MIN_LEVEL = -2;
const MAX_LEVEL = 2;

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

function normalizeLevel(value, fieldName) {
  if (!Number.isInteger(value) || value < MIN_LEVEL || value > MAX_LEVEL) {
    throw new Error(
      `${fieldName} must be an integer between ${MIN_LEVEL} and ${MAX_LEVEL}`,
    );
  }
  return value;
}

function normalizeBoolean(value, fieldName) {
  if (typeof value !== "boolean") {
    throw new Error(`${fieldName} must be a boolean`);
  }
  return value;
}

function maybeDecodeHexPrincipalId(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
    return undefined;
  }
  try {
    return Buffer.from(normalized.slice(2), "hex");
  } catch {
    return undefined;
  }
}

function compareEndorserIds(left, right) {
  const leftDecoded = maybeDecodeHexPrincipalId(left);
  const rightDecoded = maybeDecodeHexPrincipalId(right);
  if (leftDecoded && rightDecoded) {
    return Buffer.compare(leftDecoded, rightDecoded);
  }
  const leftText = String(left);
  const rightText = String(right);
  if (leftText === rightText) {
    return 0;
  }
  return leftText < rightText ? -1 : 1;
}

function normalizeThresholds(input) {
  const thresholds = ensureRecord(input ?? DEFAULT_THRESHOLDS, "thresholds");
  if (!Number.isInteger(thresholds.allow)) {
    throw new Error("thresholds.allow must be an integer");
  }
  if (!Number.isInteger(thresholds.ask)) {
    throw new Error("thresholds.ask must be an integer");
  }
  const allow = thresholds.allow;
  const ask = thresholds.ask;
  if (ask > allow) {
    throw new Error(`invalid thresholds: ask (${ask}) must be <= allow (${allow})`);
  }
  return { allow, ask };
}

function normalizeCandidate(input, index) {
  const candidate = ensureRecord(input, `candidates[${index}]`);
  return {
    endorser: ensureNonEmptyString(candidate.endorser, `candidates[${index}].endorser`),
    levelDe: normalizeLevel(candidate.levelDe, `candidates[${index}].levelDe`),
    levelEt: normalizeLevel(candidate.levelEt, `candidates[${index}].levelEt`),
  };
}

function normalizeEvidenceCandidate(input, index) {
  const normalized = normalizeCandidate(input, index);
  return {
    ...normalized,
    etHasEvidence: normalizeBoolean(
      input.etHasEvidence,
      `candidates[${index}].etHasEvidence`,
    ),
  };
}

function mapScoreToDecision(score, thresholds) {
  if (score >= thresholds.allow) {
    return "allow";
  }
  if (score >= thresholds.ask) {
    return "ask";
  }
  return "deny";
}

export function decideLocalTrust(input) {
  const payload = ensureRecord(input, "decision input");
  const thresholds = normalizeThresholds(payload.thresholds);
  const levelDt = normalizeLevel(payload.levelDt ?? 0, "levelDt");
  const candidates = Array.isArray(payload.candidates) ? payload.candidates : [];

  if (levelDt === -2) {
    return {
      decision: "deny",
      score: -2,
      endorser: null,
      levelDt,
      levelDe: 0,
      levelEt: 0,
      thresholds,
    };
  }

  let bestScore = 0;
  let bestCandidate;
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = normalizeCandidate(candidates[index], index);
    if (candidate.levelDe <= 0 || candidate.levelEt <= 0) {
      continue;
    }

    const propagated = Math.min(candidate.levelDe, candidate.levelEt);
    if (
      !bestCandidate ||
      propagated > bestScore ||
      (propagated === bestScore &&
        compareEndorserIds(candidate.endorser, bestCandidate.endorser) < 0)
    ) {
      bestScore = propagated;
      bestCandidate = candidate;
    }
  }

  const score = levelDt > 0 ? Math.max(bestScore, levelDt) : bestScore;
  return {
    decision: mapScoreToDecision(score, thresholds),
    score,
    endorser: bestCandidate?.endorser ?? null,
    levelDt,
    levelDe: bestCandidate?.levelDe ?? 0,
    levelEt: bestCandidate?.levelEt ?? 0,
    thresholds,
  };
}

export function decideLocalTrustWithEvidence(input) {
  const payload = ensureRecord(input, "decision input");
  const requirePositiveEtEvidence =
    payload.requirePositiveEtEvidence === undefined
      ? false
      : normalizeBoolean(payload.requirePositiveEtEvidence, "requirePositiveEtEvidence");
  const requirePositiveDtEvidence =
    payload.requirePositiveDtEvidence === undefined
      ? false
      : normalizeBoolean(payload.requirePositiveDtEvidence, "requirePositiveDtEvidence");
  const dtHasEvidence =
    payload.dtHasEvidence === undefined
      ? true
      : normalizeBoolean(payload.dtHasEvidence, "dtHasEvidence");
  const levelDt = normalizeLevel(payload.levelDt ?? 0, "levelDt");
  const candidates = Array.isArray(payload.candidates) ? payload.candidates : [];

  const gatedLevelDt =
    requirePositiveDtEvidence && levelDt > 0 && !dtHasEvidence ? 0 : levelDt;

  const gatedCandidates = candidates.map((candidateInput, index) => {
    const candidate = normalizeEvidenceCandidate(candidateInput, index);
    const levelEt =
      requirePositiveEtEvidence && candidate.levelEt > 0 && !candidate.etHasEvidence
        ? 0
        : candidate.levelEt;
    return {
      endorser: candidate.endorser,
      levelDe: candidate.levelDe,
      levelEt,
    };
  });

  return decideLocalTrust({
    thresholds: payload.thresholds,
    levelDt: gatedLevelDt,
    candidates: gatedCandidates,
  });
}
