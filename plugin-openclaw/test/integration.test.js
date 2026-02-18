import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import registerTrustNetOpenClawPlugin from "../index.js";
import { openTrustStore } from "../src/store.js";
import {
  DECIDER_PRINCIPAL_ID,
  EXEC_CONTEXT_ID,
  TARGET_PRINCIPAL_ID,
  basePluginConfig,
  createMockApi,
  makeTempDir,
  startTrustnetServer,
  writeMockTrustnetBinary,
  writeToolMap,
} from "../testing/helpers.js";

function writeToolMapForRisk(filePath, riskTier) {
  fs.writeFileSync(
    filePath,
    JSON.stringify(
      {
        version: 1,
        entries: [
          {
            pattern: "^exec$",
            context: "trustnet:ctx:agent-collab:code-exec:v1",
            contextId: EXEC_CONTEXT_ID,
            riskTier,
          },
        ],
      },
      null,
      2,
    ),
  );
}

function seedDirectEdge(trustStorePath, level) {
  const seedStore = openTrustStore(trustStorePath);
  seedStore.upsertEdgeLatest({
    rater: DECIDER_PRINCIPAL_ID,
    target: TARGET_PRINCIPAL_ID,
    contextId: EXEC_CONTEXT_ID,
    level,
    updatedAt: Date.now(),
    source: "test-seed",
  });
  seedStore.close();
}

function seedEndorserPath(trustStorePath, { endorser, levelDe = 2, levelEt = 2 }) {
  const seedStore = openTrustStore(trustStorePath);
  const nowMs = Date.now();
  seedStore.upsertEdgeLatest({
    rater: DECIDER_PRINCIPAL_ID,
    target: endorser,
    contextId: EXEC_CONTEXT_ID,
    level: levelDe,
    updatedAt: nowMs,
    source: "test-seed",
  });
  seedStore.upsertEdgeLatest({
    rater: endorser,
    target: TARGET_PRINCIPAL_ID,
    contextId: EXEC_CONTEXT_ID,
    level: levelEt,
    updatedAt: nowMs + 1,
    source: "test-seed",
  });
  seedStore.close();
}

test("default mode is local-lite and computes decision without API or chain config", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const receiptOutDir = path.join(tmpDir, "receipts");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);
  seedDirectEdge(trustStorePath, 2);

  const pluginConfig = basePluginConfig({
    apiBaseUrl: "http://127.0.0.1:9",
    toolMapPath,
    receiptOutDir,
    trustStorePath,
    includeChainConfig: false,
  });
  delete pluginConfig.mode;

  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig,
  });

  registerTrustNetOpenClawPlugin(api);

  const beforeHook = hooks.get("before_tool_call");
  const afterHook = hooks.get("after_tool_call");
  const persistHook = hooks.get("tool_result_persist");
  assert.ok(beforeHook);
  assert.ok(afterHook);
  assert.ok(persistHook);

  const ctx = {
    sessionKey: "session-default-local-lite-1",
    agentId: "0xagent",
    toolName: "exec",
  };

  const beforeResult = await beforeHook(
    { toolName: "exec", params: { command: "echo default-mode" } },
    ctx,
  );
  assert.equal(beforeResult, undefined);

  await afterHook(
    {
      toolName: "exec",
      params: { command: "echo default-mode" },
      result: { stdout: "default-mode" },
    },
    ctx,
  );

  const persistResult = persistHook(
    {
      toolName: "exec",
      message: { role: "tool", content: "default-mode" },
    },
    ctx,
  );
  assert.ok(persistResult);
  assert.equal(persistResult.message.metadata.trustnet.decision, "allow");

  const receiptFiles = fs.readdirSync(receiptOutDir);
  assert.equal(receiptFiles.length, 1);

  const db = new DatabaseSync(trustStorePath);
  const row = db.prepare("SELECT decision, epoch FROM receipts LIMIT 1").get();
  assert.equal(row.decision, "allow");
  assert.equal(row.epoch, null);
  db.close();
});

test("local-lite mode computes from local store without TrustNet API", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const receiptOutDir = path.join(tmpDir, "receipts");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);
  seedDirectEdge(trustStorePath, 2);

  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      receiptOutDir,
      trustStorePath,
      mode: "local-lite",
      includeChainConfig: false,
    }),
  });

  registerTrustNetOpenClawPlugin(api);

  const ctx = {
    sessionKey: "session-lite-1",
    agentId: "0xagent",
    toolName: "exec",
  };
  const beforeResult = await hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "echo local-lite" } },
    ctx,
  );
  assert.equal(beforeResult, undefined);

  await hooks.get("after_tool_call")(
    {
      toolName: "exec",
      params: { command: "echo local-lite" },
      result: { stdout: "local-lite" },
    },
    ctx,
  );

  const persistResult = hooks.get("tool_result_persist")(
    {
      toolName: "exec",
      message: { role: "tool", content: "local-lite" },
    },
    ctx,
  );
  assert.ok(persistResult);
  assert.equal(persistResult.message.metadata.trustnet.decision, "allow");

  const receipts = fs.readdirSync(receiptOutDir);
  assert.equal(receipts.length, 1);
  const receiptMeta = JSON.parse(fs.readFileSync(path.join(receiptOutDir, receipts[0]), "utf8"));
  assert.equal(receiptMeta.decision, "allow");
  assert.equal(receiptMeta.epoch, null);
  assert.equal(receiptMeta.receipt.type, "trustnet.receipt.v1");
  assert.equal(receiptMeta.receipt.tool, "exec");
  assert.equal(receiptMeta.receipt.contextId, EXEC_CONTEXT_ID);
  assert.match(receiptMeta.receipt.argsHash, /^0x[0-9a-f]{64}$/);
  assert.match(receiptMeta.receipt.resultHash, /^0x[0-9a-f]{64}$/);
  assert.ok(receiptMeta.receipt.why);
  assert.ok(receiptMeta.receipt.decisionSnapshot);

  const db = new DatabaseSync(trustStorePath);
  const row = db.prepare("SELECT decision, epoch FROM receipts LIMIT 1").get();
  assert.equal(row.decision, "allow");
  assert.equal(row.epoch, null);
  db.close();
});

test("local-lite skips receipt persistence for non-high risk tools", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const receiptOutDir = path.join(tmpDir, "receipts");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMapForRisk(toolMapPath, "medium");
  seedDirectEdge(trustStorePath, 2);

  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      receiptOutDir,
      trustStorePath,
      mode: "local-lite",
      includeChainConfig: false,
    }),
  });
  registerTrustNetOpenClawPlugin(api);

  const ctx = {
    sessionKey: "session-lite-medium-1",
    agentId: "0xagent",
    toolName: "exec",
  };

  const beforeResult = await hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "echo medium" } },
    ctx,
  );
  assert.equal(beforeResult, undefined);

  await hooks.get("after_tool_call")(
    {
      toolName: "exec",
      params: { command: "echo medium" },
      result: { stdout: "medium" },
    },
    ctx,
  );

  const persistResult = hooks.get("tool_result_persist")(
    {
      toolName: "exec",
      message: { role: "tool", content: "medium" },
    },
    ctx,
  );
  assert.equal(persistResult, undefined);

  assert.equal(fs.existsSync(receiptOutDir), false);

  const db = new DatabaseSync(trustStorePath);
  const receiptCount = db.prepare("SELECT COUNT(*) AS c FROM receipts").get().c;
  assert.equal(receiptCount, 0);
  db.close();
});

test("local-lite hard veto blocks without TrustNet API", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);
  seedDirectEdge(trustStorePath, -2);

  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      trustStorePath,
      mode: "local-lite",
      includeChainConfig: false,
    }),
  });
  registerTrustNetOpenClawPlugin(api);

  const beforeResult = await hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "echo blocked" } },
    { sessionKey: "session-lite-2", agentId: "0xagent", toolName: "exec" },
  );
  assert.equal(beforeResult.block, true);
  assert.match(beforeResult.blockReason, /TrustNet DENY/);
});

test("local-lite default trust circle onlyMe ignores D->E->T endorsements", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  const contactEndorser = "0xendorser-contact-1";
  writeToolMap(toolMapPath);
  seedEndorserPath(trustStorePath, {
    endorser: contactEndorser,
    levelDe: 2,
    levelEt: 2,
  });

  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      trustStorePath,
      mode: "local-lite",
      includeChainConfig: false,
    }),
  });
  registerTrustNetOpenClawPlugin(api);

  const beforeResult = await hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "echo should-block" } },
    { sessionKey: "session-lite-circle-only-me", agentId: "0xagent", toolName: "exec" },
  );
  assert.equal(beforeResult.block, true);
  assert.match(beforeResult.blockReason, /TrustNet DENY/);
});

test("local-lite myContacts trust circle counts configured endorsers", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  const contactEndorser = "0xendorser-contact-2";
  writeToolMap(toolMapPath);
  seedEndorserPath(trustStorePath, {
    endorser: contactEndorser,
    levelDe: 2,
    levelEt: 2,
  });

  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      trustStorePath,
      mode: "local-lite",
      includeChainConfig: false,
      trustCircles: {
        default: "myContacts",
        endorsers: {
          myContacts: [contactEndorser],
        },
      },
    }),
  });
  registerTrustNetOpenClawPlugin(api);

  const beforeResult = await hooks.get("before_tool_call")(
    { toolName: "exec", params: { command: "echo should-allow" } },
    { sessionKey: "session-lite-circle-my-contacts", agentId: "0xagent", toolName: "exec" },
  );
  assert.equal(beforeResult, undefined);
});

test(
  "local-verifiable allow decision verifies bundle, emits receipt, and annotates persisted tool result",
  async () => {
    const tmpDir = makeTempDir();
    const toolMapPath = path.join(tmpDir, "tool-map.json");
    const callsLogPath = path.join(tmpDir, "trustnet-calls.log");
    const trustnetBinaryPath = path.join(tmpDir, "trustnet");
    const receiptOutDir = path.join(tmpDir, "receipts");
    const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
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
        trustStorePath,
        mode: "local-verifiable",
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

    const db = new DatabaseSync(trustStorePath);
    const tableNames = db
      .prepare(
        `
          SELECT name
          FROM sqlite_master
          WHERE type = 'table'
            AND name IN ('edges_latest', 'receipts', 'agents')
          ORDER BY name
        `,
      )
      .all()
      .map((row) => row.name);
    assert.deepEqual(tableNames, ["agents", "edges_latest", "receipts"]);

    const receiptRow = db
      .prepare("SELECT decider, target, context_id, decision, receipt_json FROM receipts LIMIT 1")
      .get();
    assert.equal(receiptRow.decider, DECIDER_PRINCIPAL_ID);
    assert.equal(receiptRow.target, TARGET_PRINCIPAL_ID);
    assert.equal(receiptRow.context_id, EXEC_CONTEXT_ID);
    assert.equal(receiptRow.decision, "allow");
    const receiptPayload = JSON.parse(receiptRow.receipt_json);
    assert.equal(receiptPayload.type, "trustnet.receipt.v1");
    assert.equal(receiptPayload.decision, "allow");
    assert.equal(receiptPayload.contextId, EXEC_CONTEXT_ID);
    assert.equal(receiptPayload.tool, "exec");
    assert.match(receiptPayload.argsHash, /^0x[0-9a-f]{64}$/);
    assert.match(receiptPayload.resultHash, /^0x[0-9a-f]{64}$/);
    assert.ok(receiptPayload.verifiable);
    assert.equal(receiptPayload.verifiable.receiptId, "mock-1");

    const agentCount = db.prepare("SELECT COUNT(*) AS c FROM agents").get().c;
    assert.equal(agentCount, 2);
    db.close();

    await server.close();
  },
);

test("local-verifiable deny decision blocks tool call", async () => {
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
      mode: "local-verifiable",
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
      mode: "local-verifiable",
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
      mode: "local-verifiable",
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

test("local-verifiable mode without chain config keeps plugin inactive", () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  writeToolMap(toolMapPath);
  const { api, hooks, logs } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      apiBaseUrl: "http://127.0.0.1:8088",
      toolMapPath,
      trustnetBinary: "trustnet",
      mode: "local-verifiable",
      includeChainConfig: false,
    }),
  });

  registerTrustNetOpenClawPlugin(api);

  assert.equal(hooks.size, 0);
  assert.ok(
    logs.warn.some((message) => message.includes("rpcUrl is required when mode=local-verifiable")),
  );
});

test("local-verifiable mode without apiBaseUrl keeps plugin inactive", () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  writeToolMap(toolMapPath);
  const { api, hooks, logs } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      trustnetBinary: "trustnet",
      mode: "local-verifiable",
      includeChainConfig: true,
    }),
  });

  delete api.pluginConfig.apiBaseUrl;
  registerTrustNetOpenClawPlugin(api);

  assert.equal(hooks.size, 0);
  assert.ok(
    logs.warn.some((message) =>
      message.includes("apiBaseUrl is required when mode=local-verifiable"),
    ),
  );
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
