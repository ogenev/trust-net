import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:http";

import registerTrustNetOpenClawPlugin from "../index.js";

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "trustnet-openclaw-test-"));
}

function writeToolMap(filePath) {
  const toolMap = {
    version: 1,
    entries: [
      {
        pattern: "^exec$",
        context: "trustnet:ctx:code-exec:v1",
        contextId: "0x5efe84ba1b51e4f09cf7666eca4d0685fcccf1ee1f5c051bfd1b40c537b4565b",
        riskTier: "high",
      },
    ],
  };
  fs.writeFileSync(filePath, JSON.stringify(toolMap, null, 2));
}

function writeMockTrustnetBinary(filePath, callsLogPath) {
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

function createMockApi({ pluginConfig, rootDir }) {
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

async function startTrustnetServer({ decision }) {
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

function basePluginConfig({
  apiBaseUrl,
  toolMapPath,
  trustnetBinary,
  receiptOutDir,
  failOpen,
  askMode,
  unmappedDecision,
}) {
  return {
    apiBaseUrl,
    decider: "0xdecider000000000000000000000000000000000001",
    targetPrincipalId: "0xtarget000000000000000000000000000000000001",
    toolMapPath,
    rpcUrl: "https://sepolia.example/rpc",
    rootRegistry: "0x1111111111111111111111111111111111111111",
    publisherAddress: "0x2222222222222222222222222222222222222222",
    trustnetBinary,
    receiptOutDir,
    failOpen,
    askMode,
    unmappedDecision,
  };
}

test("allow decision performs anchored verify, emits receipt, and annotates persisted tool result", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const callsLogPath = path.join(tmpDir, "trustnet-calls.log");
  const trustnetBinaryPath = path.join(tmpDir, "trustnet");
  const receiptOutDir = path.join(tmpDir, "receipts");
  writeToolMap(toolMapPath);
  writeMockTrustnetBinary(trustnetBinaryPath, callsLogPath);

  const server = await startTrustnetServer({ decision: "allow" });
  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      apiBaseUrl: server.apiBaseUrl,
      toolMapPath,
      trustnetBinary: trustnetBinaryPath,
      receiptOutDir,
    }),
  });

  registerTrustNetOpenClawPlugin(api);

  const beforeHook = hooks.get("before_tool_call");
  const afterHook = hooks.get("after_tool_call");
  const persistHook = hooks.get("tool_result_persist");

  assert.ok(beforeHook);
  assert.ok(afterHook);
  assert.ok(persistHook);

  const event = {
    toolName: "exec",
    params: { command: "echo hi" },
  };
  const ctx = {
    sessionKey: "session-1",
    agentId: "0xagent",
    toolName: "exec",
  };

  const beforeResult = await beforeHook(event, ctx);
  assert.equal(beforeResult, undefined);

  await afterHook(
    {
      toolName: "exec",
      params: { command: "echo hi" },
      result: { stdout: "hi" },
    },
    ctx,
  );

  const persistResult = persistHook(
    {
      toolName: "exec",
      message: { role: "tool", content: "hi" },
    },
    ctx,
  );

  assert.ok(persistResult);
  assert.ok(persistResult.message);
  assert.equal(persistResult.message.metadata.trustnet.decision, "allow");

  const calls = fs.readFileSync(callsLogPath, "utf8").trim().split("\n");
  assert.equal(calls.length, 2);
  assert.match(calls[0], /^verify /);
  assert.match(calls[0], /--rpc-url https:\/\/sepolia\.example\/rpc/);
  assert.match(calls[0], /--root-registry 0x1111111111111111111111111111111111111111/);
  assert.match(calls[1], /^receipt /);

  const receipts = fs.readdirSync(receiptOutDir);
  assert.equal(receipts.length, 1);

  await server.close();
});

test("deny decision blocks tool call", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const callsLogPath = path.join(tmpDir, "trustnet-calls.log");
  const trustnetBinaryPath = path.join(tmpDir, "trustnet");
  writeToolMap(toolMapPath);
  writeMockTrustnetBinary(trustnetBinaryPath, callsLogPath);

  const server = await startTrustnetServer({ decision: "deny" });
  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      apiBaseUrl: server.apiBaseUrl,
      toolMapPath,
      trustnetBinary: trustnetBinaryPath,
    }),
  });

  registerTrustNetOpenClawPlugin(api);

  const beforeResult = await hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "rm -rf /tmp/demo" } },
    { sessionKey: "session-2", agentId: "0xagent", toolName: "exec" },
  );

  assert.equal(beforeResult.block, true);
  assert.match(beforeResult.blockReason, /TrustNet DENY/);

  const calls = fs.readFileSync(callsLogPath, "utf8").trim().split("\n");
  assert.equal(calls.length, 1);
  assert.match(calls[0], /^verify /);

  await server.close();
});

test("verify failure blocks by default and can be configured to fail-open", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const callsLogPath = path.join(tmpDir, "trustnet-calls.log");
  const trustnetBinaryPath = path.join(tmpDir, "trustnet");
  writeToolMap(toolMapPath);
  writeMockTrustnetBinary(trustnetBinaryPath, callsLogPath);

  const server = await startTrustnetServer({ decision: "allow" });
  process.env.TRUSTNET_VERIFY_FAIL = "1";

  const strictApi = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      apiBaseUrl: server.apiBaseUrl,
      toolMapPath,
      trustnetBinary: trustnetBinaryPath,
      failOpen: false,
    }),
  });
  registerTrustNetOpenClawPlugin(strictApi.api);
  const blocked = await strictApi.hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "echo fail-closed" } },
    { sessionKey: "session-3", agentId: "0xagent", toolName: "exec" },
  );
  assert.equal(blocked.block, true);
  assert.match(blocked.blockReason, /enforcement error/i);

  const openApi = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      apiBaseUrl: server.apiBaseUrl,
      toolMapPath,
      trustnetBinary: trustnetBinaryPath,
      failOpen: true,
    }),
  });
  registerTrustNetOpenClawPlugin(openApi.api);
  const allowed = await openApi.hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "echo fail-open" } },
    { sessionKey: "session-4", agentId: "0xagent", toolName: "exec" },
  );
  assert.equal(allowed, undefined);

  delete process.env.TRUSTNET_VERIFY_FAIL;
  await server.close();
});

test("missing config keeps plugin inactive instead of throwing", () => {
  const tmpDir = makeTempDir();
  const { api, hooks, logs } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: {},
  });

  assert.doesNotThrow(() => {
    registerTrustNetOpenClawPlugin(api);
  });

  assert.equal(hooks.size, 0);
  assert.ok(logs.warn.some((message) => message.includes("plugin is inactive")));
});
