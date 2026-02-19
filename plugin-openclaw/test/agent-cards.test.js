import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  AGENT_CARD_ACTION_IMPORT,
  AGENT_CARD_ACTION_STATUS,
  AGENT_CARD_STATUS_OWNER_UNKNOWN,
  AGENT_CARD_STATUS_VERIFIED,
  normalizeAgentCardAction,
  parseAgentCardPolicy,
  verifyAgentCard,
} from "../src/agent-cards.js";

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
  const unsigned = {
    type: card.type,
    agentRef: card.agentRef,
    displayName: card.displayName,
    endpoints: card.endpoints,
    capabilities: card.capabilities,
    issuedAt: card.issuedAt,
    agentPubKey: card.agentPubKey,
    ownerPubKey: card.ownerPubKey,
  };
  if (card.policyManifestHash) {
    unsigned.policyManifestHash = card.policyManifestHash;
  }
  return unsigned;
}

function signCard(unsignedCard, agentPrivateKey, ownerPrivateKey) {
  const payload = Buffer.from(stableStringify(unsignedCard), "utf8");
  return {
    agentSig: crypto.sign(null, payload, agentPrivateKey).toString("base64"),
    ownerSig: crypto.sign(null, payload, ownerPrivateKey).toString("base64"),
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
    displayName: "Example Agent",
    endpoints: ["a2a://example-agent", "https://agent.example/api"],
    capabilities: [
      "trustnet:ctx:agent-collab:messaging:v1",
      "trustnet:ctx:agent-collab:code-exec:v1",
    ],
    issuedAt: "2026-02-19T00:00:00Z",
    policyManifestHash: `0x${"ab".repeat(32)}`,
    agentPubKey,
    ownerPubKey,
  };
  const signatures = signCard(buildUnsignedCard(card), agentKeys.privateKey, ownerKeys.privateKey);
  return {
    card: {
      ...card,
      signatures,
    },
    ownerPubKey,
  };
}

test("parseAgentCardPolicy defaults to empty trusted owner key list", () => {
  assert.deepEqual(parseAgentCardPolicy({}), {
    trustedOwnerPubKeys: [],
  });
});

test("parseAgentCardPolicy validates and deduplicates trusted owner keys", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerPubKey = publicKeyRawBase64(owner.publicKey);
  const policy = parseAgentCardPolicy({
    agentCards: {
      trustedOwnerPubKeys: [ownerPubKey, ownerPubKey],
    },
  });

  assert.deepEqual(policy, {
    trustedOwnerPubKeys: [ownerPubKey],
  });
});

test("verifyAgentCard returns owner-unknown when owner key is not trusted", () => {
  const { card } = makeSignedAgentCard();
  const result = verifyAgentCard(card, { trustedOwnerPubKeys: [] });
  assert.equal(result.principalId, card.agentRef);
  assert.equal(result.status, AGENT_CARD_STATUS_OWNER_UNKNOWN);
  assert.equal(result.ownerTrusted, false);
});

test("verifyAgentCard returns verified when owner key is trusted", () => {
  const { card, ownerPubKey } = makeSignedAgentCard();
  const result = verifyAgentCard(card, { trustedOwnerPubKeys: [ownerPubKey] });
  assert.equal(result.principalId, card.agentRef);
  assert.equal(result.status, AGENT_CARD_STATUS_VERIFIED);
  assert.equal(result.ownerTrusted, true);
});

test("verifyAgentCard rejects agentRef mismatch", () => {
  const { card, ownerPubKey } = makeSignedAgentCard();
  assert.throws(
    () =>
      verifyAgentCard(
        {
          ...card,
          agentRef: `0x${"11".repeat(32)}`,
        },
        { trustedOwnerPubKeys: [ownerPubKey] },
      ),
    /agentRef does not match/,
  );
});

test("normalizeAgentCardAction supports import cards as JSON strings", () => {
  const action = normalizeAgentCardAction({
    action: AGENT_CARD_ACTION_IMPORT,
    source: "qr-import",
    card: JSON.stringify({ type: "openclaw.agentCard.v1" }),
  });
  assert.equal(action.action, AGENT_CARD_ACTION_IMPORT);
  assert.equal(action.source, "qr-import");
  assert.deepEqual(action.card, { type: "openclaw.agentCard.v1" });
});

test("normalizeAgentCardAction normalizes status defaults", () => {
  const action = normalizeAgentCardAction({
    action: AGENT_CARD_ACTION_STATUS,
  });
  assert.equal(action.action, AGENT_CARD_ACTION_STATUS);
  assert.equal(action.includeCard, false);
  assert.equal(action.limit, 20);
  assert.equal(action.principalId, undefined);
});
