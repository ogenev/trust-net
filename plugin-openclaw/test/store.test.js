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
  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xendorser-a",
    contextId: "0xcontext",
    level: 2,
    updatedAt: 260,
    source: "manual-newer",
  });
  store.upsertEdgeLatest({
    rater: "0xendorser-a",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 1,
    updatedAt: 261,
    evidenceRef: "receipt:abc",
    source: "manual-newer",
  });
  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xendorser-b",
    contextId: "0xcontext",
    level: 1,
    updatedAt: 262,
    source: "manual-newer",
  });
  store.upsertEdgeLatest({
    rater: "0xendorser-b",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 2,
    updatedAt: 263,
    source: "manual-newer",
  });

  const direct = store.getEdgeLatest({
    rater: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
  });
  assert.ok(direct);
  assert.equal(direct.level, 2);
  assert.equal(direct.updatedAt, 250);
  assert.equal(direct.evidenceRef, null);

  const endorserCandidates = store.listEndorserCandidates({
    decider: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
  });
  assert.deepEqual(endorserCandidates, [
    {
      endorser: "0xendorser-a",
      levelDe: 2,
      levelEt: 1,
      etUpdatedAt: 261,
      etHasEvidence: true,
    },
    {
      endorser: "0xendorser-b",
      levelDe: 1,
      levelEt: 2,
      etUpdatedAt: 263,
      etHasEvidence: false,
    },
  ]);

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

test("local trust store ignores expired TTL edges in reads", () => {
  const trustStorePath = makeTempDbPath();
  const store = openTrustStore(trustStorePath);
  const nowMs = Date.now();

  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 2,
    updatedAt: nowMs,
    evidenceRef: JSON.stringify({
      type: "trustnet.askAction.v1",
      action: "allow_ttl",
      expiresAtU64: nowMs - 1,
    }),
    source: "ask-action:allow-ttl",
  });

  const expiredDirect = store.getEdgeLatest({
    rater: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
  });
  assert.equal(expiredDirect, undefined);

  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xendorser-expired",
    contextId: "0xcontext",
    level: 2,
    updatedAt: nowMs,
    evidenceRef: JSON.stringify({
      type: "trustnet.askAction.v1",
      action: "allow_ttl",
      expiresAtU64: nowMs - 1,
    }),
    source: "ask-action:allow-ttl",
  });
  store.upsertEdgeLatest({
    rater: "0xendorser-expired",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 2,
    updatedAt: nowMs,
    source: "manual",
  });

  store.upsertEdgeLatest({
    rater: "0xdecider",
    target: "0xendorser-active",
    contextId: "0xcontext",
    level: 2,
    updatedAt: nowMs,
    source: "manual",
  });
  store.upsertEdgeLatest({
    rater: "0xendorser-active",
    target: "0xtarget",
    contextId: "0xcontext",
    level: 2,
    updatedAt: nowMs,
    evidenceRef: JSON.stringify({
      type: "trustnet.askAction.v1",
      action: "allow_ttl",
      expiresAtU64: nowMs + 60_000,
    }),
    source: "ask-action:allow-ttl",
  });

  const endorserCandidates = store.listEndorserCandidates({
    decider: "0xdecider",
    target: "0xtarget",
    contextId: "0xcontext",
  });
  assert.deepEqual(endorserCandidates, [
    {
      endorser: "0xendorser-active",
      levelDe: 2,
      levelEt: 2,
      etUpdatedAt: nowMs,
      etHasEvidence: true,
    },
    {
      endorser: "0xendorser-expired",
      levelDe: 0,
      levelEt: 2,
      etUpdatedAt: nowMs,
      etHasEvidence: false,
    },
  ]);

  store.close();
});

test("local trust store returns imported agent cards via getAgent/listAgents", () => {
  const trustStorePath = makeTempDbPath();
  const store = openTrustStore(trustStorePath);

  store.upsertAgent({
    principalId: "0xagent-a",
    displayName: "Agent A",
    source: "agent-card:import",
    seenAt: 100,
    agentCard: {
      type: "openclaw.agentCard.v1",
      agentRef: "0xagent-a",
    },
    metadata: {
      agentCard: {
        verificationStatus: "verified",
      },
    },
  });
  store.upsertAgent({
    principalId: "0xagent-b",
    displayName: "Agent B",
    source: "agent-card:import",
    seenAt: 200,
    agentCard: {
      type: "openclaw.agentCard.v1",
      agentRef: "0xagent-b",
    },
    metadata: {
      agentCard: {
        verificationStatus: "owner-unknown",
      },
    },
  });

  const byPrincipal = store.getAgent({ principalId: "0xagent-a" });
  assert.ok(byPrincipal);
  assert.equal(byPrincipal.principalId, "0xagent-a");
  assert.equal(byPrincipal.displayName, "Agent A");
  assert.equal(byPrincipal.agentCard.type, "openclaw.agentCard.v1");
  assert.equal(byPrincipal.metadata.agentCard.verificationStatus, "verified");

  const listed = store.listAgents({ limit: 2 });
  assert.equal(listed.length, 2);
  assert.equal(listed[0].principalId, "0xagent-b");
  assert.equal(listed[1].principalId, "0xagent-a");

  store.close();
});
