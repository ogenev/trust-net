import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export type DecisionString = "allow" | "ask" | "deny";
export type RiskTier = "high" | "medium" | "low";

export interface ThresholdsJson {
  allow: number;
  ask: number;
}

export interface DecisionBundleV1 {
  type: string;
  epoch: number;
  graphRoot: string;
  manifestHash: string;
  decider: string;
  target: string;
  contextId: string;
  decision: DecisionString;
  score: number;
  thresholds: ThresholdsJson;
  why: unknown;
  proofs: unknown;
  constraints?: Record<string, unknown>;
}

export interface RootResponseV1 {
  epoch: number;
  graphRoot: string;
  manifestHash: string;
  publisherSig: string;
  manifest?: unknown;
}

export interface ToolMappingEntry {
  pattern: string;
  context: string;
  contextId: string;
  riskTier: RiskTier;
  constraints?: Record<string, unknown>;
}

export interface ToolMap {
  version: number;
  entries: ToolMappingEntry[];
}

export interface PluginConfig {
  apiBaseUrl: string;
  decider: string;
  toolMapPath: string;
  policyManifestHash?: string;
  receiptSignerKeyHex?: string;
}

export interface ToolCallContext {
  toolName: string;
  targetPrincipalId: string;
  args: unknown;
}

export interface ToolCallResult {
  result?: unknown;
  error?: string;
}

export interface EnforcementContext {
  decision: DecisionString;
  decisionBundle: DecisionBundleV1;
  root: RootResponseV1;
  mapping: ToolMappingEntry;
}

function loadToolMap(toolMapPath: string): ToolMap {
  const raw = fs.readFileSync(toolMapPath, "utf8");
  return JSON.parse(raw) as ToolMap;
}

function resolveTool(toolName: string, toolMap: ToolMap): ToolMappingEntry | undefined {
  for (const entry of toolMap.entries) {
    const re = new RegExp(entry.pattern);
    if (re.test(toolName)) {
      return entry;
    }
  }
  return undefined;
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for ${url}`);
  }
  return (await res.json()) as T;
}

async function fetchDecision(
  apiBaseUrl: string,
  decider: string,
  target: string,
  contextId: string
): Promise<DecisionBundleV1> {
  const url = `${apiBaseUrl}/v1/decision?decider=${encodeURIComponent(decider)}` +
    `&target=${encodeURIComponent(target)}&contextId=${encodeURIComponent(contextId)}`;
  return fetchJson<DecisionBundleV1>(url);
}

async function fetchRoot(apiBaseUrl: string): Promise<RootResponseV1> {
  return fetchJson<RootResponseV1>(`${apiBaseUrl}/v1/root`);
}

function normalizeDecision(decision: string): DecisionString {
  if (decision === "allow" || decision === "ask" || decision === "deny") {
    return decision;
  }
  throw new Error(`Unknown decision: ${decision}`);
}

export async function beforeToolCall(
  ctx: ToolCallContext,
  config: PluginConfig
): Promise<EnforcementContext> {
  const toolMap = loadToolMap(config.toolMapPath);
  const mapping = resolveTool(ctx.toolName, toolMap);
  if (!mapping) {
    throw new Error(`No tool mapping for ${ctx.toolName}`);
  }

  const [root, bundle] = await Promise.all([
    fetchRoot(config.apiBaseUrl),
    fetchDecision(config.apiBaseUrl, config.decider, ctx.targetPrincipalId, mapping.contextId)
  ]);

  return {
    decision: normalizeDecision(bundle.decision),
    decisionBundle: bundle,
    root,
    mapping
  };
}

export async function afterToolCall(
  ctx: ToolCallContext,
  result: ToolCallResult,
  config: PluginConfig,
  enforcement: EnforcementContext
): Promise<unknown> {
  return emitActionReceipt({
    tool: ctx.toolName,
    args: ctx.args,
    result: result.result,
    error: result.error,
    root: enforcement.root,
    decisionBundle: enforcement.decisionBundle,
    policyManifestHash: config.policyManifestHash,
    signerKeyHex: config.receiptSignerKeyHex
  });
}

export interface EmitReceiptParams {
  tool: string;
  args: unknown;
  result?: unknown;
  error?: string;
  root: RootResponseV1;
  decisionBundle: DecisionBundleV1;
  policyManifestHash?: string;
  signerKeyHex?: string;
}

export function emitActionReceipt(params: EmitReceiptParams): unknown {
  if (!!params.result === !!params.error) {
    throw new Error("Provide exactly one of result or error");
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "trustnet-receipt-"));
  const rootPath = path.join(tmpDir, "root.json");
  const bundlePath = path.join(tmpDir, "decision.json");
  const argsPath = path.join(tmpDir, "args.json");
  const resultPath = path.join(tmpDir, "result.json");
  const receiptPath = path.join(tmpDir, "receipt.json");

  fs.writeFileSync(rootPath, JSON.stringify(params.root));
  fs.writeFileSync(bundlePath, JSON.stringify(params.decisionBundle));
  fs.writeFileSync(argsPath, JSON.stringify(params.args ?? {}));

  if (params.error) {
    fs.writeFileSync(resultPath, JSON.stringify({ error: params.error }));
  } else {
    fs.writeFileSync(resultPath, JSON.stringify(params.result ?? {}));
  }

  const args: string[] = [
    "receipt",
    "--root",
    rootPath,
    "--bundle",
    bundlePath,
    "--tool",
    params.tool,
    "--args",
    argsPath,
    "--out",
    receiptPath
  ];

  if (params.error) {
    args.push("--error", params.error);
  } else {
    args.push("--result", resultPath);
  }

  if (params.policyManifestHash) {
    args.push("--policy-manifest-hash", params.policyManifestHash);
  }

  if (params.signerKeyHex) {
    args.push("--signer-key", params.signerKeyHex);
  }

  execFileSync("trustnet", args, { stdio: "inherit" });

  const receiptJson = fs.readFileSync(receiptPath, "utf8");
  return JSON.parse(receiptJson);
}
