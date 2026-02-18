import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:http";

export const EXEC_CONTEXT_ID = "0x88329f80681e8980157f3ce652efd4fd18edf3c55202d5fb4f4da8a23e2d6971";
export const DECIDER_PRINCIPAL_ID = "0xdecider000000000000000000000000000000000001";
export const TARGET_PRINCIPAL_ID = "0xtarget000000000000000000000000000000000001";

export function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "trustnet-openclaw-test-"));
}

export function writeToolMap(filePath) {
  const toolMap = {
    version: 1,
    entries: [
      {
        pattern: "^exec$",
        context: "trustnet:ctx:agent-collab:code-exec:v1",
        contextId: EXEC_CONTEXT_ID,
        riskTier: "high",
      },
    ],
  };
  fs.writeFileSync(filePath, JSON.stringify(toolMap, null, 2));
}

export function writeMockTrustnetBinary(filePath, callsLogPath) {
  const script = `#!/usr/bin/env bash
set -euo pipefail
LOG_FILE=${JSON.stringify(callsLogPath)}
cmd="$1"
shift || true
echo "$cmd $*" >> "$LOG_FILE"
if [ "$cmd" = "verify" ]; then
  if [ "\${TRUSTNET_VERIFY_FAIL:-0}" = "1" ]; then
    echo "forced verify failure" >&2
    exit 42
  fi
  exit 0
fi
if [ "$cmd" = "receipt" ]; then
  out=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--out" ]; then
      out="$2"
      shift 2
      continue
    fi
    shift
  done
  if [ -z "$out" ]; then
    echo "missing --out" >&2
    exit 2
  fi
  printf '{"receiptId":"mock-1","signature":"0xdeadbeef"}' > "$out"
  exit 0
fi
echo "unknown command: $cmd" >&2
exit 3
`;

  fs.writeFileSync(filePath, script);
  fs.chmodSync(filePath, 0o755);
}

export function createMockApi({ pluginConfig, rootDir }) {
  const hooks = new Map();
  const logs = { info: [], warn: [], error: [] };

  const api = {
    id: "trustnet-openclaw",
    name: "TrustNet OpenClaw",
    source: "test",
    config: {},
    pluginConfig,
    logger: {
      info(message) {
        logs.info.push(message);
      },
      warn(message) {
        logs.warn.push(message);
      },
      error(message) {
        logs.error.push(message);
      },
    },
    resolvePath(input) {
      if (path.isAbsolute(input)) {
        return input;
      }
      return path.join(rootDir, input);
    },
    on(hookName, handler) {
      hooks.set(hookName, handler);
    },
  };

  return { api, hooks, logs };
}

export async function startTrustnetServer({ decision }) {
  const graphRoot = "0x" + "11".repeat(32);
  const manifestHash = "0x" + "22".repeat(32);
  const epoch = 7;

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    res.setHeader("content-type", "application/json");

    if (url.pathname === "/v1/root") {
      res.writeHead(200);
      res.end(
        JSON.stringify({
          epoch,
          graphRoot,
          manifestHash,
          publisherSig: "0xfeedface",
        }),
      );
      return;
    }

    if (url.pathname === "/v1/decision") {
      res.writeHead(200);
      res.end(
        JSON.stringify({
          type: "trustnet.decision.v1",
          epoch,
          graphRoot,
          manifestHash,
          decider: url.searchParams.get("decider"),
          target: url.searchParams.get("target"),
          contextId: url.searchParams.get("contextId"),
          decision,
          score: decision === "allow" ? 2 : 0,
          thresholds: { allow: 2, ask: 1 },
          why: { path: [] },
          proofs: {},
        }),
      );
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: "not found" }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("failed to resolve mock server address");
  }

  return {
    apiBaseUrl: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve(undefined);
        });
      });
    },
  };
}

export function basePluginConfig({
  apiBaseUrl,
  toolMapPath,
  trustnetBinary,
  receiptOutDir,
  trustStorePath,
  failOpen,
  askMode,
  unmappedDecision,
  mode,
  includeChainConfig,
  rpcUrl,
  rootRegistry,
  publisherAddress,
}) {
  const resolvedMode = mode ?? "local-lite";
  const resolvedIncludeChainConfig =
    includeChainConfig ?? resolvedMode === "local-verifiable";

  const config = {
    mode: resolvedMode,
    decider: DECIDER_PRINCIPAL_ID,
    targetPrincipalId: TARGET_PRINCIPAL_ID,
    toolMapPath,
    trustnetBinary,
    receiptOutDir,
    trustStorePath,
    failOpen,
    askMode,
    unmappedDecision,
  };
  if (typeof apiBaseUrl === "string" && apiBaseUrl.trim().length > 0) {
    config.apiBaseUrl = apiBaseUrl;
  }

  if (resolvedIncludeChainConfig) {
    config.rpcUrl = rpcUrl ?? "https://sepolia.example/rpc";
    config.rootRegistry = rootRegistry ?? "0x1111111111111111111111111111111111111111";
    config.publisherAddress = publisherAddress ?? "0x2222222222222222222222222222222222222222";
  }

  return config;
}
