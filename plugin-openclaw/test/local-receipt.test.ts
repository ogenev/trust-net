import test from "node:test";
import assert from "node:assert/strict";

import { buildLocalInteractionReceipt, shouldPersistReceiptForMapping } from "../src/local-receipt.js";

const EXEC_CONTEXT_ID = "0x88329f80681e8980157f3ce652efd4fd18edf3c55202d5fb4f4da8a23e2d6971";

test("shouldPersistReceiptForMapping only enables high risk contexts", () => {
  assert.equal(shouldPersistReceiptForMapping({ riskTier: "high" }), true);
  assert.equal(shouldPersistReceiptForMapping({ riskTier: "HIGH" }), true);
  assert.equal(shouldPersistReceiptForMapping({ riskTier: "medium" }), false);
  assert.equal(shouldPersistReceiptForMapping({ riskTier: "low" }), false);
  assert.equal(shouldPersistReceiptForMapping({}), false);
});

test("buildLocalInteractionReceipt emits v0.7 local receipt shape with snapshots", () => {
  const receipt = buildLocalInteractionReceipt({
    decision: "ask",
    mapping: {
      contextId: EXEC_CONTEXT_ID,
      constraints: { ttlSeconds: 60 },
    },
    targetPrincipalId: "0xtarget",
    toolName: "exec",
    params: { command: "echo hello" },
    result: { stdout: "hello" },
    createdAtMs: 1_739_836_800_000,
    localDecision: {
      score: 1,
      thresholds: { allow: 2, ask: 1 },
      endorser: "0xendorser",
      levelDt: 0,
      levelDe: 1,
      levelEt: 1,
    },
    askResolution: {
      action: "allow_ttl",
      ttlSeconds: 60,
      expiresAtMs: 1_739_836_860_000,
      persistedEdge: true,
      userApproved: true,
    },
  });

  assert.equal(receipt.type, "trustnet.receipt.v1");
  assert.match(receipt.receiptId, /^[0-9a-f-]{36}$/);
  assert.equal(receipt.createdAt, "2025-02-18T00:00:00.000Z");
  assert.equal(receipt.target, "0xtarget");
  assert.equal(receipt.contextId, EXEC_CONTEXT_ID);
  assert.equal(receipt.tool, "exec");
  assert.equal(receipt.decision, "ask");
  assert.equal(receipt.userApproved, true);
  assert.match(receipt.argsHash, /^0x[0-9a-f]{64}$/);
  assert.match(receipt.resultHash, /^0x[0-9a-f]{64}$/);
  assert.deepEqual(receipt.constraints, { ttlSeconds: 60 });
  assert.deepEqual(receipt.why.edgeDT, { level: 0 });
  assert.deepEqual(receipt.why.edgeDE, { level: 1, endorser: "0xendorser" });
  assert.deepEqual(receipt.why.edgeET, { level: 1, endorser: "0xendorser" });
  assert.deepEqual(receipt.decisionSnapshot, {
    score: 1,
    thresholds: { allow: 2, ask: 1 },
    endorser: "0xendorser",
    epoch: null,
    graphRoot: null,
    manifestHash: null,
  });
  assert.deepEqual(receipt.askAction, {
    action: "allow_ttl",
    ttlSeconds: 60,
    expiresAtU64: 1_739_836_860_000,
    persistedEdge: true,
    userApproved: true,
  });
});
