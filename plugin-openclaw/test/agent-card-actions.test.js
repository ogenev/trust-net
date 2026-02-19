import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import registerTrustNetOpenClawPlugin from "../index.js";
import { basePluginConfig, createMockApi, makeTempDir, writeToolMap } from "../testing/helpers.js";

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
  const keys = Object.keys(value).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${parts.join(",")}}`;
}

function publicKeyRawBase64(publicKey) {
  const spki = publicKey.export({ type: "spki", format: "der" });
  return spki.subarray(spki.length - 32).toString("base64");
}

function deriveAgentRef(agentPubKeyBase64) {
  const raw = Buffer.from(agentPubKeyBase64, "base64");
  return `0x${crypto.createHash("sha256").update(raw).digest("hex")}`;
}

function buildUnsignedCard(card) {
  return {
    type: card.type,
    agentRef: card.agentRef,
    displayName: card.displayName,
    endpoints: card.endpoints,
    capabilities: card.capabilities,
    issuedAt: card.issuedAt,
    agentPubKey: card.agentPubKey,
    ownerPubKey: card.ownerPubKey,
  };
}

function makeSignedAgentCard() {
  const agentKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const agentPubKey = publicKeyRawBase64(agentKeys.publicKey);
  const ownerPubKey = publicKeyRawBase64(ownerKeys.publicKey);
  const card = {
    type: "openclaw.agentCard.v1",
    agentRef: deriveAgentRef(agentPubKey),
    displayName: "Imported Agent",
    endpoints: ["a2a://imported-agent"],
    capabilities: ["trustnet:ctx:agent-collab:messaging:v1"],
    issuedAt: "2026-02-19T00:00:00Z",
    agentPubKey,
    ownerPubKey,
  };
  const payload = Buffer.from(stableStringify(buildUnsignedCard(card)), "utf8");
  return {
    card: {
      ...card,
      signatures: {
        agentSig: crypto.sign(null, payload, agentKeys.privateKey).toString("base64"),
        ownerSig: crypto.sign(null, payload, ownerKeys.privateKey).toString("base64"),
      },
    },
    ownerPubKey,
  };
}

test("runtime Agent Card import verifies signatures and stores status=verified", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);

  const { card, ownerPubKey } = makeSignedAgentCard();
  const { api, hooks } = createMockApi({
    rootDir: tmpDir,
    pluginConfig: basePluginConfig({
      toolMapPath,
      trustStorePath,
      mode: "local-lite",
      includeChainConfig: false,
      agentCards: {
        trustedOwnerPubKeys: [ownerPubKey],
      },
    }),
  });
  registerTrustNetOpenClawPlugin(api);

  const beforeHook = hooks.get("before_tool_call");
  assert.ok(beforeHook);

  const importResult = await beforeHook(
    {
      toolName: "exec",
      params: {},
      trustnetAgentCardAction: {
        action: "import",
        source: "integration-test",
        card,
      },
    },
    { sessionKey: "session-agent-card-import", toolName: "exec", agentId: "0xagent" },
  );

  assert.equal(importResult.block, true);
  assert.equal(importResult.trustnetAgentCard.status, "verified");
  assert.equal(importResult.trustnetAgentCard.principalId, card.agentRef);

  const db = new DatabaseSync(trustStorePath);
  const row = db
    .prepare(
      `
        SELECT principal_id, display_name, agent_card_json, metadata_json
        FROM agents
        WHERE principal_id = ?
        LIMIT 1
      `,
    )
    .get(card.agentRef);
  assert.ok(row);
  assert.equal(row.display_name, card.displayName);
  const storedCard = JSON.parse(row.agent_card_json);
  const storedMetadata = JSON.parse(row.metadata_json);
  assert.equal(storedCard.agentRef, card.agentRef);
  assert.equal(storedMetadata.agentCard.verificationStatus, "verified");
  assert.equal(storedMetadata.agentCard.ownerTrusted, true);
  db.close();

  const statusResult = await beforeHook(
    {
      toolName: "exec",
      params: {},
      trustnetAgentCardAction: {
        action: "status",
        principalId: card.agentRef,
      },
    },
    { sessionKey: "session-agent-card-status", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(statusResult.block, true);
  assert.equal(statusResult.trustnetAgentCard.found, true);
  assert.equal(statusResult.trustnetAgentCard.agent.status, "verified");
  assert.equal(statusResult.trustnetAgentCard.agent.principalId, card.agentRef);
});

test("runtime Agent Card import marks unknown owners as owner-unknown", async () => {
  const tmpDir = makeTempDir();
  const toolMapPath = path.join(tmpDir, "tool-map.json");
  const trustStorePath = path.join(tmpDir, "trust-store.sqlite");
  writeToolMap(toolMapPath);

  const { card } = makeSignedAgentCard();
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

  const importResult = await beforeHook(
    {
      toolName: "exec",
      params: {},
      trustnetAgentCardAction: {
        action: "import",
        card,
      },
    },
    { sessionKey: "session-agent-card-owner-unknown", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(importResult.block, true);
  assert.equal(importResult.trustnetAgentCard.status, "owner-unknown");
  assert.equal(importResult.trustnetAgentCard.ownerTrusted, false);

  const listResult = await beforeHook(
    {
      toolName: "exec",
      params: {},
      trustnetAgentCardAction: {
        action: "status",
        limit: 10,
      },
    },
    { sessionKey: "session-agent-card-list", toolName: "exec", agentId: "0xagent" },
  );
  assert.equal(listResult.block, true);
  assert.equal(listResult.trustnetAgentCard.found, true);
  assert.equal(listResult.trustnetAgentCard.count, 1);
  assert.equal(listResult.trustnetAgentCard.agents[0].status, "owner-unknown");
});
