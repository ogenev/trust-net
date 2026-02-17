import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

export const DECISION_ALLOW = "allow";
export const DECISION_ASK = "ask";
export const DECISION_DENY = "deny";
export const ASK_MODE_BLOCK = "block";
const ASK_MODE_ALLOW = "allow";

const DECISIONS = new Set([DECISION_ALLOW, DECISION_ASK, DECISION_DENY]);
const ASK_MODES = new Set([ASK_MODE_BLOCK, ASK_MODE_ALLOW]);

const HEX_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const HEX_BYTES32_RE = /^0x[a-fA-F0-9]{64}$/;

const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
const DEFAULT_VERIFY_TIMEOUT_MS = 15_000;
const DEFAULT_RECEIPT_TIMEOUT_MS = 15_000;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function ensureRecord(value, name) {
  if (!isRecord(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function readRequiredString(obj, key) {
  const value = obj[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`pluginConfig.${key} must be a non-empty string`);
  }
  return value.trim();
}

function readOptionalString(obj, key) {
  const value = obj[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error(`pluginConfig.${key} must be a string when set`);
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function readOptionalNumber(obj, key, fallback) {
  const value = obj[key];
  if (value === undefined || value === null) {
    return fallback;
  }
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error(`pluginConfig.${key} must be a positive number when set`);
  }
  return Math.floor(value);
}

function readOptionalBoolean(obj, key, fallback) {
  const value = obj[key];
  if (value === undefined || value === null) {
    return fallback;
  }
  if (typeof value !== "boolean") {
    throw new Error(`pluginConfig.${key} must be a boolean when set`);
  }
  return value;
}

function readOptionalEnum(obj, key, allowed, fallback) {
  const value = obj[key];
  if (value === undefined || value === null) {
    return fallback;
  }
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new Error(
      `pluginConfig.${key} must be one of: ${Array.from(allowed.values()).join(", ")}`,
    );
  }
  return value;
}

function resolvePath(api, rawPath) {
  if (typeof api.resolvePath === "function") {
    return api.resolvePath(rawPath);
  }
  if (path.isAbsolute(rawPath)) {
    return rawPath;
  }
  return path.resolve(process.cwd(), rawPath);
}

export function parseConfig(api) {
  const raw = ensureRecord(api.pluginConfig ?? {}, "pluginConfig");

  const apiBaseUrl = readRequiredString(raw, "apiBaseUrl");
  const decider = readRequiredString(raw, "decider");
  const toolMapPath = resolvePath(api, readRequiredString(raw, "toolMapPath"));
  const rpcUrl = readRequiredString(raw, "rpcUrl");
  const rootRegistry = readRequiredString(raw, "rootRegistry");
  const publisherAddress = readRequiredString(raw, "publisherAddress");

  if (!HEX_ADDRESS_RE.test(rootRegistry)) {
    throw new Error("pluginConfig.rootRegistry must be a 20-byte hex address");
  }
  if (!HEX_ADDRESS_RE.test(publisherAddress)) {
    throw new Error("pluginConfig.publisherAddress must be a 20-byte hex address");
  }

  const policyManifestHash = readOptionalString(raw, "policyManifestHash");
  if (policyManifestHash && !HEX_BYTES32_RE.test(policyManifestHash)) {
    throw new Error("pluginConfig.policyManifestHash must be a 32-byte hex string");
  }

  const receiptSignerKeyHex = readOptionalString(raw, "receiptSignerKeyHex");
  const trustnetBinary = readOptionalString(raw, "trustnetBinary") ?? "trustnet";
  const receiptOutDirRaw = readOptionalString(raw, "receiptOutDir");
  const receiptOutDir = receiptOutDirRaw ? resolvePath(api, receiptOutDirRaw) : undefined;

  const targetPrincipalId = readOptionalString(raw, "targetPrincipalId");
  const failOpen = readOptionalBoolean(raw, "failOpen", false);
  const askMode = readOptionalEnum(raw, "askMode", ASK_MODES, ASK_MODE_BLOCK);
  const unmappedDecision = readOptionalEnum(
    raw,
    "unmappedDecision",
    new Set([DECISION_DENY, DECISION_ASK]),
    DECISION_DENY,
  );

  return {
    apiBaseUrl,
    decider,
    toolMapPath,
    rpcUrl,
    rootRegistry,
    publisherAddress,
    targetPrincipalId,
    policyManifestHash,
    receiptSignerKeyHex,
    trustnetBinary,
    receiptOutDir,
    failOpen,
    askMode,
    unmappedDecision,
    requestTimeoutMs: readOptionalNumber(raw, "requestTimeoutMs", DEFAULT_REQUEST_TIMEOUT_MS),
    verifyTimeoutMs: readOptionalNumber(raw, "verifyTimeoutMs", DEFAULT_VERIFY_TIMEOUT_MS),
    receiptTimeoutMs: readOptionalNumber(raw, "receiptTimeoutMs", DEFAULT_RECEIPT_TIMEOUT_MS),
  };
}

export function loadToolMap(toolMapPath) {
  const rawText = fs.readFileSync(toolMapPath, "utf8");
  const parsed = JSON.parse(rawText);
  const obj = ensureRecord(parsed, "tool map");
  const entries = obj.entries;
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("tool map must contain a non-empty entries array");
  }

  return entries.map((entry, index) => {
    const item = ensureRecord(entry, `tool map entry at index ${index}`);
    const pattern = readRequiredString(item, "pattern");
    const contextId = readRequiredString(item, "contextId");
    if (!HEX_BYTES32_RE.test(contextId)) {
      throw new Error(`tool map entry ${index} has invalid contextId`);
    }

    let regex;
    try {
      regex = new RegExp(pattern);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`tool map entry ${index} has invalid pattern: ${message}`);
    }

    return {
      pattern,
      regex,
      context: readOptionalString(item, "context"),
      contextId: contextId.toLowerCase(),
      riskTier: readOptionalString(item, "riskTier"),
      constraints: isRecord(item.constraints) ? item.constraints : undefined,
    };
  });
}

export function findToolMapping(entries, toolName) {
  for (const entry of entries) {
    if (entry.regex.test(toolName)) {
      return entry;
    }
  }
  return undefined;
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

function hashPayload(payload) {
  return crypto.createHash("sha256").update(payload).digest("hex");
}

export function buildCallKey(sessionKey, toolName, params) {
  const fingerprint = hashPayload(stableStringify(params ?? {}));
  return `${sessionKey ?? "no-session"}:${toolName}:${fingerprint}`;
}

export function queuePush(map, key, value) {
  const existing = map.get(key);
  if (existing) {
    existing.push(value);
    return;
  }
  map.set(key, [value]);
}

export function queueShift(map, key) {
  const queue = map.get(key);
  if (!queue || queue.length === 0) {
    return undefined;
  }
  const value = queue.shift();
  if (queue.length === 0) {
    map.delete(key);
  }
  return value;
}

async function fetchJson(url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} for ${url}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchDecision(config, targetPrincipalId, contextId) {
  const url = new URL("/v1/decision", config.apiBaseUrl);
  url.searchParams.set("decider", config.decider);
  url.searchParams.set("target", targetPrincipalId);
  url.searchParams.set("contextId", contextId);
  return fetchJson(url.toString(), config.requestTimeoutMs);
}

export async function fetchRoot(config) {
  const url = new URL("/v1/root", config.apiBaseUrl);
  return fetchJson(url.toString(), config.requestTimeoutMs);
}

export function normalizeDecision(value) {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!DECISIONS.has(normalized)) {
    throw new Error(`unsupported TrustNet decision: ${String(value)}`);
  }
  return normalized;
}

export function ensureDecisionConsistency({ mapping, decisionBundle, root, decider, target }) {
  const bundle = ensureRecord(decisionBundle, "decision bundle");
  const rootObj = ensureRecord(root, "root response");

  if (String(bundle.contextId ?? "").toLowerCase() !== mapping.contextId) {
    throw new Error("decision bundle contextId does not match mapped contextId");
  }
  if (String(bundle.decider ?? "").toLowerCase() !== decider.toLowerCase()) {
    throw new Error("decision bundle decider does not match plugin config");
  }
  if (String(bundle.target ?? "").toLowerCase() !== target.toLowerCase()) {
    throw new Error("decision bundle target does not match resolved target principal");
  }
  if (String(bundle.graphRoot ?? "") !== String(rootObj.graphRoot ?? "")) {
    throw new Error("decision bundle graphRoot does not match root payload");
  }
  if (String(bundle.manifestHash ?? "") !== String(rootObj.manifestHash ?? "")) {
    throw new Error("decision bundle manifestHash does not match root payload");
  }
  if (Number(bundle.epoch) !== Number(rootObj.epoch)) {
    throw new Error("decision bundle epoch does not match root payload epoch");
  }
}

function withTempDir(prefix, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function runTrustnetCommand(config, args, timeoutMs) {
  const result = spawnSync(config.trustnetBinary, args, {
    encoding: "utf8",
    stdio: "pipe",
    timeout: timeoutMs,
  });

  if (result.error) {
    throw new Error(`failed to run '${config.trustnetBinary} ${args.join(" ")}': ${result.error}`);
  }

  if (result.status !== 0) {
    const stderr = result.stderr ? result.stderr.trim() : "";
    const stdout = result.stdout ? result.stdout.trim() : "";
    const details = stderr || stdout || `exit ${result.status}`;
    throw new Error(`'${config.trustnetBinary} ${args[0]}' failed: ${details}`);
  }
}

export function verifyDecisionBundleAnchored(config, root, decisionBundle) {
  withTempDir("trustnet-openclaw-verify-", (tmpDir) => {
    const rootPath = path.join(tmpDir, "root.json");
    const bundlePath = path.join(tmpDir, "decision.json");

    fs.writeFileSync(rootPath, JSON.stringify(root));
    fs.writeFileSync(bundlePath, JSON.stringify(decisionBundle));

    runTrustnetCommand(
      config,
      [
        "verify",
        "--root",
        rootPath,
        "--bundle",
        bundlePath,
        "--publisher",
        config.publisherAddress,
        "--rpc-url",
        config.rpcUrl,
        "--root-registry",
        config.rootRegistry,
      ],
      config.verifyTimeoutMs,
    );
  });
}

export function emitActionReceipt(config, payload) {
  return withTempDir("trustnet-openclaw-receipt-", (tmpDir) => {
    const rootPath = path.join(tmpDir, "root.json");
    const bundlePath = path.join(tmpDir, "decision.json");
    const argsPath = path.join(tmpDir, "args.json");
    const resultPath = path.join(tmpDir, "result.json");
    const receiptPath = path.join(tmpDir, "receipt.json");

    fs.writeFileSync(rootPath, JSON.stringify(payload.root));
    fs.writeFileSync(bundlePath, JSON.stringify(payload.decisionBundle));
    fs.writeFileSync(argsPath, JSON.stringify(payload.params ?? {}));

    const args = [
      "receipt",
      "--root",
      rootPath,
      "--bundle",
      bundlePath,
      "--tool",
      payload.toolName,
      "--args",
      argsPath,
      "--out",
      receiptPath,
    ];

    if (payload.error) {
      args.push("--error", payload.error);
    } else {
      fs.writeFileSync(resultPath, JSON.stringify(payload.result ?? null));
      args.push("--result", resultPath);
    }

    if (config.policyManifestHash) {
      args.push("--policy-manifest-hash", config.policyManifestHash);
    }
    if (config.receiptSignerKeyHex) {
      args.push("--signer-key", config.receiptSignerKeyHex);
    }

    runTrustnetCommand(config, args, config.receiptTimeoutMs);
    const receiptRaw = fs.readFileSync(receiptPath, "utf8");
    return JSON.parse(receiptRaw);
  });
}

function sanitizeFileToken(value) {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_");
}

export function persistReceipt(config, meta) {
  if (!config.receiptOutDir) {
    return undefined;
  }
  fs.mkdirSync(config.receiptOutDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const suffix = hashPayload(meta.callKey).slice(0, 12);
  const fileName = `${timestamp}_${sanitizeFileToken(meta.toolName)}_${suffix}.json`;
  const outputPath = path.join(config.receiptOutDir, fileName);
  fs.writeFileSync(outputPath, JSON.stringify(meta, null, 2));
  return outputPath;
}

export function resolveTargetPrincipalId(config, ctx) {
  if (config.targetPrincipalId) {
    return config.targetPrincipalId;
  }
  if (typeof ctx.agentId === "string" && ctx.agentId.trim().length > 0) {
    return ctx.agentId.trim();
  }
  throw new Error(
    "target principal is not available; set pluginConfig.targetPrincipalId or ensure ctx.agentId is present",
  );
}

export function buildDecisionBlockReason(decision, mapping) {
  const contextLabel = mapping.context ?? mapping.contextId;
  if (decision === DECISION_DENY) {
    return `TrustNet DENY for tool '${mapping.pattern}' (${contextLabel})`;
  }
  return `TrustNet ASK for tool '${mapping.pattern}' (${contextLabel}); operator approval required`;
}

export function addReceiptMetadataToMessage(message, receiptSummary) {
  if (!isRecord(message)) {
    return undefined;
  }
  const metadata = isRecord(message.metadata) ? { ...message.metadata } : {};
  metadata.trustnet = {
    decision: receiptSummary.decision,
    epoch: receiptSummary.epoch,
    contextId: receiptSummary.contextId,
    receiptPath: receiptSummary.receiptPath,
  };
  return { ...message, metadata };
}
