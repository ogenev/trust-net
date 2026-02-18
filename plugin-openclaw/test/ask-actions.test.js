import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import registerTrustNetOpenClawPlugin from "../index.js";
import { DECIDER_PRINCIPAL_ID, EXEC_CONTEXT_ID, TARGET_PRINCIPAL_ID } from "../testing/helpers.js";
import { basePluginConfig, createMockApi, makeTempDir, writeToolMap } from "../testing/helpers.js";
import { openTrustStore } from "../src/store.js";

function askActionEvent(ticket, action, extra = {}) {
  return {
    trustnetAskAction: {
      ticket,
      action,
      ...extra,
    },
  };
}

function seedAskDecisionEdges(trustStorePath) {
  const store = openTrustStore(trustStorePath);
  store.upsertEdgeLatest({
    rater: DECIDER_PRINCIPAL_ID,
    target: "0xendorser0000000000000000000000000000000001",
    contextId: EXEC_CONTEXT_ID,
    level: 1,
    updatedAt: Date.now(),
    source: "test-seed",
  });
  store.upsertEdgeLatest({
    rater: "0xendorser0000000000000000000000000000000001",
    target: TARGET_PRINCIPAL_ID,
    contextId: EXEC_CONTEXT_ID,
    level: 1,
    updatedAt: Date.now(),
    source: "test-seed",
  });
  store.close();
}

test("ASK allow_once resumes a blocked call without writing edges", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  const receiptOutDir = path.join(tmpDir, "receipts");
  writeToolMap(toolMapPath);
  seedAskDecisionEdges(trustStorePath);

  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      trustStorePath,
      receiptOutDir,
      mode: "local-lite",
      includeChainConfig: false,
    }),
  });
  registerTrustNetOpenClawPlugin(api);

  const beforeHook = hooks.get("before_tool_call");
  const afterHook = hooks.get("after_tool_call");
  assert.ok(beforeHook);
  assert.ok(afterHook);

  const baseEvent = {
    toolName: "exec",
    params: { command: "echo ask-once" },
  };
  const ctx = {
    sessionKey: "session-ask-once",
    agentId: "0xagent",
    toolName: "exec",
  };

  const askResult = await beforeHook(baseEvent, ctx);
  assert.equal(askResult.block, true);
  assert.match(askResult.blockReason, /TrustNet ASK/);
  assert.ok(askResult.trustnetAsk);
  assert.equal(askResult.trustnetAsk.type, "trustnet.askPrompt.v1");
  assert.equal(askResult.trustnetAsk.target, TARGET_PRINCIPAL_ID);
  assert.deepEqual(askResult.trustnetAsk.actions, [
    "allow_once",
    "allow_ttl",
    "allow_always",
    "block",
  ]);

  const allowResult = await beforeHook(
    {
      ...baseEvent,
      ...askActionEvent(askResult.trustnetAsk.ticket, "allow_once"),
    },
    ctx,
  );
  assert.equal(allowResult, undefined);

  await afterHook(
    {
      toolName: "exec",
      params: baseEvent.params,
      result: { stdout: "ok" },
    },
    ctx,
  );

  const db = new DatabaseSync(trustStorePath);
  const edgeCount = db
    .prepare(
      `
        SELECT COUNT(*) AS c
        FROM edges_latest
        WHERE rater = ?
          AND target = ?
          AND context_id = ?
      `,
    )
    .get(DECIDER_PRINCIPAL_ID, TARGET_PRINCIPAL_ID, EXEC_CONTEXT_ID).c;
  assert.equal(edgeCount, 0);

  const receipt = db.prepare("SELECT decision, receipt_json FROM receipts LIMIT 1").get();
  assert.equal(receipt.decision, "ask");
  const receiptJson = JSON.parse(receipt.receipt_json);
  assert.equal(receiptJson.askAction.action, "allow_once");
  assert.equal(receiptJson.askAction.persistedEdge, false);
  assert.equal(receiptJson.askAction.userApproved, true);
  db.close();
});

test("ASK allow_always writes D->T=+2 and future calls allow without prompt", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);
  seedAskDecisionEdges(trustStorePath);

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

  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const event = {
    toolName: "exec",
    params: { command: "echo ask-always" },
  };
  const ctx = {
    sessionKey: "session-ask-always",
    agentId: "0xagent",
    toolName: "exec",
  };

  const askResult = await beforeHook(event, ctx);
  assert.equal(askResult.block, true);
  const resume = await beforeHook(
    {
      ...event,
      ...askActionEvent(askResult.trustnetAsk.ticket, "allow_always"),
    },
    ctx,
  );
  assert.equal(resume, undefined);

  const db = new DatabaseSync(trustStorePath);
  const edge = db
    .prepare(
      `
        SELECT level_i8, source, evidence_ref
        FROM edges_latest
        WHERE rater = ?
          AND target = ?
          AND context_id = ?
        LIMIT 1
      `,
    )
    .get(DECIDER_PRINCIPAL_ID, TARGET_PRINCIPAL_ID, EXEC_CONTEXT_ID);
  assert.equal(edge.level_i8, 2);
  assert.equal(edge.source, "ask-action:allow-always");
  const evidence = JSON.parse(edge.evidence_ref);
  assert.equal(evidence.action, "allow_always");
  db.close();

  const followUp = await beforeHook(event, {
    ...ctx,
    sessionKey: "session-ask-always-2",
  });
  assert.equal(followUp, undefined);
});

test("ASK block writes D->T=-2 and enforces DENY", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);
  seedAskDecisionEdges(trustStorePath);

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

  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const event = {
    toolName: "exec",
    params: { command: "echo ask-block" },
  };
  const ctx = {
    sessionKey: "session-ask-block",
    agentId: "0xagent",
    toolName: "exec",
  };

  const askResult = await beforeHook(event, ctx);
  assert.equal(askResult.block, true);

  const blockResult = await beforeHook(
    {
      ...event,
      ...askActionEvent(askResult.trustnetAsk.ticket, "block"),
    },
    ctx,
  );
  assert.equal(blockResult.block, true);
  assert.match(blockResult.blockReason, /TrustNet DENY/);

  const db = new DatabaseSync(trustStorePath);
  const edge = db
    .prepare(
      `
        SELECT level_i8, source
        FROM edges_latest
        WHERE rater = ?
          AND target = ?
          AND context_id = ?
        LIMIT 1
      `,
    )
    .get(DECIDER_PRINCIPAL_ID, TARGET_PRINCIPAL_ID, EXEC_CONTEXT_ID);
  assert.equal(edge.level_i8, -2);
  assert.equal(edge.source, "ask-action:block");
  db.close();

  const followUp = await beforeHook(event, {
    ...ctx,
    sessionKey: "session-ask-block-2",
  });
  assert.equal(followUp.block, true);
  assert.match(followUp.blockReason, /TrustNet DENY/);
});

test("ASK action ticket is required and cannot be replayed", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);
  seedAskDecisionEdges(trustStorePath);

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

  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const event = {
    toolName: "exec",
    params: { command: "echo ask-ticket" },
  };
  const ctx = {
    sessionKey: "session-ask-ticket",
    agentId: "0xagent",
    toolName: "exec",
  };

  const askResult = await beforeHook(event, ctx);
  assert.equal(askResult.block, true);

  const allowResult = await beforeHook(
    {
      ...event,
      ...askActionEvent(askResult.trustnetAsk.ticket, "allow_once"),
    },
    ctx,
  );
  assert.equal(allowResult, undefined);

  const replayResult = await beforeHook(
    {
      ...event,
      ...askActionEvent(askResult.trustnetAsk.ticket, "allow_once"),
    },
    { ...ctx, sessionKey: "session-ask-ticket-2" },
  );
  assert.equal(replayResult.block, true);
  assert.match(replayResult.blockReason, /enforcement error/i);
});
