import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import registerTrustNetOpenClawPlugin from "../index.js";
import {
  DECIDER_PRINCIPAL_ID,
  EXEC_CONTEXT_ID,
  TARGET_PRINCIPAL_ID,
  basePluginConfig,
  createMockApi,
  makeTempDir,
  writeToolMap,
} from "../testing/helpers.js";
import { openTrustStore } from "../src/store.js";

function trustActionEvent(payload) {
  return {
    toolName: "exec",
    params: {},
    trustnetTrustAction: payload,
  };
}

function createPlugin({ tmpDir, trustStorePath, trustCircles, trustWorkflows }) {
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  writeToolMap(toolMapPath);
  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      trustStorePath,
      mode: "local-lite",
      includeChainConfig: false,
      trustCircles,
      trustWorkflows,
    }),
  });
  registerTrustNetOpenClawPlugin(api);
  return hooks;
}

test("trust workflow trust action requires confirm and writes edge after confirmation", async () => {
  const tmpDir = makeTempDir();
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  const hooks = createPlugin({ tmpDir, trustStorePath });
  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const promptResult = await beforeHook(
    trustActionEvent({
      action: "trust",
      targetPrincipalId: TARGET_PRINCIPAL_ID,
      contextId: EXEC_CONTEXT_ID,
      level: 2,
    }),
    { sessionKey: "session-workflow-trust", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(promptResult.block, true);
  assert.equal(promptResult.trustnetTrustWorkflow.type, "trustnet.trustWorkflow.prompt.v1");

  const ticket = promptResult.trustnetTrustWorkflow.ticket;
  assert.equal(typeof ticket, "string");

  const db = new DatabaseSync(trustStorePath);
  const beforeEdge = db
    .prepare(
      `
        SELECT COUNT(*) AS c
        FROM edges_latest
        WHERE rater = ?
          AND target = ?
          AND context_id = ?
      `,
    )
    .get(DECIDER_PRINCIPAL_ID, TARGET_PRINCIPAL_ID, EXEC_CONTEXT_ID);
  assert.equal(beforeEdge.c, 0);

  const confirmResult = await beforeHook(
    trustActionEvent({
      action: "confirm",
      ticket,
    }),
    { sessionKey: "session-workflow-trust-confirm", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(confirmResult.block, true);
  assert.equal(confirmResult.trustnetTrustWorkflow.type, "trustnet.trustWorkflow.result.v1");
  assert.equal(confirmResult.trustnetTrustWorkflow.applied, true);

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
  assert.equal(edge.level_i8, 2);
  assert.equal(edge.source, "workflow:trust");

  const replayResult = await beforeHook(
    trustActionEvent({
      action: "confirm",
      ticket,
    }),
    { sessionKey: "session-workflow-trust-replay", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(replayResult.block, true);
  assert.match(replayResult.blockReason, /invalid or expired TrustNet trust workflow ticket/);
  db.close();
});

test("trust workflow block and endorse actions apply expected edges after confirmation", async () => {
  const tmpDir = makeTempDir();
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  const hooks = createPlugin({ tmpDir, trustStorePath });
  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const blockPrompt = await beforeHook(
    trustActionEvent({
      action: "block",
      targetPrincipalId: TARGET_PRINCIPAL_ID,
      contextId: EXEC_CONTEXT_ID,
    }),
    { sessionKey: "session-workflow-block", toolName: "exec", agentId: "0xagent" },
  );
  const blockTicket = blockPrompt.trustnetTrustWorkflow.ticket;
  const blockResult = await beforeHook(
    trustActionEvent({
      action: "confirm",
      ticket: blockTicket,
    }),
    { sessionKey: "session-workflow-block-confirm", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(blockResult.trustnetTrustWorkflow.applied, true);

  const endorserPrincipalId = "0xendorser-workflow-1";
  const endorsePrompt = await beforeHook(
    trustActionEvent({
      action: "endorse",
      endorserPrincipalId,
      contextId: EXEC_CONTEXT_ID,
      level: 2,
    }),
    { sessionKey: "session-workflow-endorse", toolName: "exec", agentId: "0xagent" },
  );
  const endorseTicket = endorsePrompt.trustnetTrustWorkflow.ticket;
  const endorseResult = await beforeHook(
    trustActionEvent({
      action: "confirm",
      ticket: endorseTicket,
    }),
    { sessionKey: "session-workflow-endorse-confirm", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(endorseResult.trustnetTrustWorkflow.applied, true);

  const db = new DatabaseSync(trustStorePath);
  const blockEdge = db
    .prepare(
      `
        SELECT level_i8, source
        FROM edges_latest
        WHERE rater = ?
          AND target = ?
          AND context_id = ?
      `,
    )
    .get(DECIDER_PRINCIPAL_ID, TARGET_PRINCIPAL_ID, EXEC_CONTEXT_ID);
  assert.equal(blockEdge.level_i8, -2);
  assert.equal(blockEdge.source, "workflow:block");

  const endorseEdge = db
    .prepare(
      `
        SELECT level_i8, source
        FROM edges_latest
        WHERE rater = ?
          AND target = ?
          AND context_id = ?
      `,
    )
    .get(DECIDER_PRINCIPAL_ID, endorserPrincipalId, EXEC_CONTEXT_ID);
  assert.equal(endorseEdge.level_i8, 2);
  assert.equal(endorseEdge.source, "workflow:endorse");
  db.close();
});

test("trust workflow status returns direct edges and trust-circle filtered candidates", async () => {
  const tmpDir = makeTempDir();
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  const trustedEndorser = "0xendorser-trusted";
  const nonTrustedEndorser = "0xendorser-other";

  const seedStore = openTrustStore(trustStorePath);
  const nowMs = Date.now();
  seedStore.upsertEdgeLatest({
    rater: DECIDER_PRINCIPAL_ID,
    target: TARGET_PRINCIPAL_ID,
    contextId: EXEC_CONTEXT_ID,
    level: 1,
    updatedAt: nowMs,
    source: "seed",
  });
  seedStore.upsertEdgeLatest({
    rater: DECIDER_PRINCIPAL_ID,
    target: trustedEndorser,
    contextId: EXEC_CONTEXT_ID,
    level: 2,
    updatedAt: nowMs + 1,
    source: "seed",
  });
  seedStore.upsertEdgeLatest({
    rater: trustedEndorser,
    target: TARGET_PRINCIPAL_ID,
    contextId: EXEC_CONTEXT_ID,
    level: 2,
    updatedAt: nowMs + 2,
    source: "seed",
  });
  seedStore.upsertEdgeLatest({
    rater: DECIDER_PRINCIPAL_ID,
    target: nonTrustedEndorser,
    contextId: EXEC_CONTEXT_ID,
    level: 2,
    updatedAt: nowMs + 3,
    source: "seed",
  });
  seedStore.upsertEdgeLatest({
    rater: nonTrustedEndorser,
    target: TARGET_PRINCIPAL_ID,
    contextId: EXEC_CONTEXT_ID,
    level: 2,
    updatedAt: nowMs + 4,
    source: "seed",
  });
  seedStore.close();

  const hooks = createPlugin({
    tmpDir,
    trustStorePath,
    trustCircles: {
      default: "myContacts",
      endorsers: {
        myContacts: [trustedEndorser],
      },
    },
  });
  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const scopedStatus = await beforeHook(
    trustActionEvent({
      action: "status",
      principalId: TARGET_PRINCIPAL_ID,
      contextId: EXEC_CONTEXT_ID,
      includeCandidates: true,
      limit: 10,
    }),
    { sessionKey: "session-workflow-status-scoped", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(scopedStatus.block, true);
  assert.equal(scopedStatus.trustnetTrustWorkflow.type, "trustnet.trustWorkflow.statusResult.v1");
  assert.equal(scopedStatus.trustnetTrustWorkflow.directEdge.level, 1);
  assert.equal(scopedStatus.trustnetTrustWorkflow.candidateCount, 1);
  assert.equal(scopedStatus.trustnetTrustWorkflow.candidates[0].endorser, trustedEndorser);

  const globalStatus = await beforeHook(
    trustActionEvent({
      action: "status",
      principalId: TARGET_PRINCIPAL_ID,
      limit: 10,
    }),
    { sessionKey: "session-workflow-status-global", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(globalStatus.block, true);
  assert.equal(globalStatus.trustnetTrustWorkflow.contextId, null);
  assert.equal(Array.isArray(globalStatus.trustnetTrustWorkflow.directEdges), true);
  assert.equal(globalStatus.trustnetTrustWorkflow.directEdges.length, 1);
  assert.equal(globalStatus.trustnetTrustWorkflow.directEdges[0].level, 1);
});

test("trust workflow cancel consumes ticket without applying changes", async () => {
  const tmpDir = makeTempDir();
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  const hooks = createPlugin({ tmpDir, trustStorePath });
  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const promptResult = await beforeHook(
    trustActionEvent({
      action: "trust",
      targetPrincipalId: TARGET_PRINCIPAL_ID,
      contextId: EXEC_CONTEXT_ID,
      level: 2,
    }),
    { sessionKey: "session-workflow-cancel", toolName: "exec", agentId: "0xagent" },
  );

  const cancelResult = await beforeHook(
    trustActionEvent({
      action: "cancel",
      ticket: promptResult.trustnetTrustWorkflow.ticket,
    }),
    { sessionKey: "session-workflow-cancel-confirm", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(cancelResult.block, true);
  assert.equal(cancelResult.trustnetTrustWorkflow.applied, false);

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
  db.close();
});
