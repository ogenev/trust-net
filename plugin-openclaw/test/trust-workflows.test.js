import test from "node:test";
import assert from "node:assert/strict";

import {
  TRUST_WORKFLOW_ACTION_BLOCK,
  TRUST_WORKFLOW_ACTION_CANCEL,
  TRUST_WORKFLOW_ACTION_CONFIRM,
  TRUST_WORKFLOW_ACTION_ENDORSE,
  TRUST_WORKFLOW_ACTION_STATUS,
  TRUST_WORKFLOW_ACTION_TRUST,
  normalizeTrustWorkflowAction,
  parseTrustWorkflowPolicy,
} from "../src/trust-workflows.js";

const CONTEXT_ID = "0x88329f80681e8980157f3ce652efd4fd18edf3c55202d5fb4f4da8a23e2d6971";

test("parseTrustWorkflowPolicy defaults confirmation TTL", () => {
  assert.deepEqual(parseTrustWorkflowPolicy({}), {
    confirmationTtlSeconds: 300,
  });
});

test("parseTrustWorkflowPolicy validates TTL bounds", () => {
  assert.throws(
    () =>
      parseTrustWorkflowPolicy({
        trustWorkflows: {
          confirmationTtlSeconds: 10,
        },
      }),
    /confirmationTtlSeconds must be between/,
  );
});

test("normalizeTrustWorkflowAction supports trust action", () => {
  assert.deepEqual(
    normalizeTrustWorkflowAction({
      action: TRUST_WORKFLOW_ACTION_TRUST,
      targetPrincipalId: "0xA1B2C3",
      contextId: CONTEXT_ID,
      level: 1,
    }),
    {
      action: TRUST_WORKFLOW_ACTION_TRUST,
      targetPrincipalId: "0xa1b2c3",
      contextId: CONTEXT_ID,
      level: 1,
    },
  );
});

test("normalizeTrustWorkflowAction supports block action", () => {
  assert.deepEqual(
    normalizeTrustWorkflowAction({
      action: TRUST_WORKFLOW_ACTION_BLOCK,
      targetPrincipalId: "0xCDEF12",
      contextId: CONTEXT_ID,
    }),
    {
      action: TRUST_WORKFLOW_ACTION_BLOCK,
      targetPrincipalId: "0xcdef12",
      contextId: CONTEXT_ID,
    },
  );
});

test("normalizeTrustWorkflowAction supports endorse action", () => {
  assert.deepEqual(
    normalizeTrustWorkflowAction({
      action: TRUST_WORKFLOW_ACTION_ENDORSE,
      endorserPrincipalId: "0xABCDEF",
      contextId: CONTEXT_ID,
    }),
    {
      action: TRUST_WORKFLOW_ACTION_ENDORSE,
      endorserPrincipalId: "0xabcdef",
      contextId: CONTEXT_ID,
      level: 2,
    },
  );
});

test("normalizeTrustWorkflowAction supports status action defaults", () => {
  assert.deepEqual(
    normalizeTrustWorkflowAction({
      action: TRUST_WORKFLOW_ACTION_STATUS,
      principalId: "0xFfEe01",
    }),
    {
      action: TRUST_WORKFLOW_ACTION_STATUS,
      principalId: "0xffee01",
      contextId: undefined,
      includeCandidates: true,
      limit: 20,
    },
  );
});

test("normalizeTrustWorkflowAction supports confirm/cancel actions", () => {
  assert.deepEqual(
    normalizeTrustWorkflowAction({
      action: TRUST_WORKFLOW_ACTION_CONFIRM,
      ticket: "ticket-1",
    }),
    {
      action: TRUST_WORKFLOW_ACTION_CONFIRM,
      ticket: "ticket-1",
    },
  );
  assert.deepEqual(
    normalizeTrustWorkflowAction({
      action: TRUST_WORKFLOW_ACTION_CANCEL,
      ticket: "ticket-1",
    }),
    {
      action: TRUST_WORKFLOW_ACTION_CANCEL,
      ticket: "ticket-1",
    },
  );
});

test("normalizeTrustWorkflowAction rejects unsupported action", () => {
  assert.throws(
    () =>
      normalizeTrustWorkflowAction({
        action: "rate",
      }),
    /must be one of/,
  );
});
