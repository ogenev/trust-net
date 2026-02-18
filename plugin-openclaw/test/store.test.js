import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { openTrustStore } from "../src/store.js";

function makeTempDbPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trustnet-openclaw-store-test-"));
  return path.join(dir, "trust-store.sqlite");
}

test("local trust store creates schema and enforces latest-wins edge updates", () => {
  const trustStorePath = makeTempDbPath();
  const store = openTrustStore(trustStorePath);

  store.upsertAgent({
    principalId: "0xdecider",
    displayName: "Decider",
    source: "seed",
    seenAt: 100,
  });
  store.upsertAgent({
    principalId: "0xtarget",
    source: "runtime",
    seenAt: 101,
  });

  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 1,
    updatedAt: 200,
    source: "manual",
  });
  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 2,
    updatedAt: 150,
    source: "manual-older",
  });
  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 2,
    updatedAt: 250,
    source: "manual-newer",
  });

  store.insertReceipt({
    receiptId: "receipt-1",
    callKey: "session:exec:fingerprint",
    sessionKey: "session",
    decider: "0xdecider",
    target: "0xtarget",
    toolName: "exec",
    contextId: "0xcontext",
    decision: "allow",
    epoch: 7,
    createdAt: 500,
    receipt: {
      receiptId: "receipt-1",
      signature: "0xdeadbeef",
    },
  });
  store.close();

  const db = new DatabaseSync(trustStorePath);
  const tables = db
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
  assert.deepEqual(tables, ["agents", "edges_latest", "receipts"]);

  const edge = db.prepare("SELECT level_i8, updated_at_u64, source FROM edges_latest").get();
  assert.equal(edge.level_i8, 2);
  assert.equal(edge.updated_at_u64, 250);
  assert.equal(edge.source, "manual-newer");

  const receipt = db.prepare("SELECT decision, epoch, receipt_id FROM receipts").get();
  assert.equal(receipt.decision, "allow");
  assert.equal(receipt.epoch, 7);
  assert.equal(receipt.receipt_id, "receipt-1");

  const agentCount = db.prepare("SELECT COUNT(*) AS c FROM agents").get().c;
  assert.equal(agentCount, 2);
  db.close();
});
