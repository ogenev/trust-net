import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_THRESHOLDS,
  decideLocalTrust,
  decideLocalTrustWithEvidence,
} from "../src/decision-engine.js";

function pid(byteHex) {
  return `0x${byteHex.repeat(32)}`;
}

test("decideLocalTrust applies hard veto for direct -2 edge", () => {
  const result = decideLocalTrust({
    levelDt: -2,
    candidates: [
      {
        endorser: pid("01"),
        levelDe: 2,
        levelEt: 2,
      },
    ],
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.score, -2);
  assert.equal(result.endorser, null);
  assert.equal(result.levelDe, 0);
  assert.equal(result.levelEt, 0);
});

test("decideLocalTrust does not propagate negative endorsement edges", () => {
  const result = decideLocalTrust({
    thresholds: DEFAULT_THRESHOLDS,
    levelDt: 0,
    candidates: [
      {
        endorser: pid("01"),
        levelDe: -1,
        levelEt: 2,
      },
      {
        endorser: pid("02"),
        levelDe: 2,
        levelEt: -1,
      },
    ],
  });

  assert.equal(result.score, 0);
  assert.equal(result.decision, "deny");
  assert.equal(result.endorser, null);
});

test("decideLocalTrust uses deterministic tie-break on endorser id", () => {
  const result = decideLocalTrust({
    thresholds: DEFAULT_THRESHOLDS,
    levelDt: 0,
    candidates: [
      {
        endorser: pid("02"),
        levelDe: 2,
        levelEt: 1,
      },
      {
        endorser: pid("01"),
        levelDe: 1,
        levelEt: 2,
      },
    ],
  });

  assert.equal(result.score, 1);
  assert.equal(result.decision, "ask");
  assert.equal(result.endorser, pid("01"));
});

test("decideLocalTrust lets positive direct trust override base score", () => {
  const result = decideLocalTrust({
    thresholds: DEFAULT_THRESHOLDS,
    levelDt: 2,
    candidates: [
      {
        endorser: pid("03"),
        levelDe: 1,
        levelEt: 1,
      },
    ],
  });

  assert.equal(result.score, 2);
  assert.equal(result.decision, "allow");
  assert.equal(result.endorser, pid("03"));
});

test("decideLocalTrust validates threshold ordering", () => {
  assert.throws(
    () =>
      decideLocalTrust({
        thresholds: {
          allow: 1,
          ask: 2,
        },
        levelDt: 0,
        candidates: [],
      }),
    /ask \(2\) must be <= allow \(1\)/,
  );
});

test("decideLocalTrustWithEvidence gates positive ET edges without evidence", () => {
  const result = decideLocalTrustWithEvidence({
    thresholds: DEFAULT_THRESHOLDS,
    requirePositiveEtEvidence: true,
    requirePositiveDtEvidence: false,
    levelDt: 0,
    dtHasEvidence: true,
    candidates: [
      {
        endorser: pid("01"),
        levelDe: 1,
        levelEt: 1,
        etHasEvidence: false,
      },
    ],
  });

  assert.equal(result.score, 0);
  assert.equal(result.decision, "deny");
  assert.equal(result.endorser, null);
});

test("decideLocalTrustWithEvidence gates positive DT without evidence", () => {
  const withoutEvidence = decideLocalTrustWithEvidence({
    thresholds: DEFAULT_THRESHOLDS,
    requirePositiveEtEvidence: false,
    requirePositiveDtEvidence: true,
    levelDt: 1,
    dtHasEvidence: false,
    candidates: [],
  });
  assert.equal(withoutEvidence.score, 0);
  assert.equal(withoutEvidence.decision, "deny");

  const withEvidence = decideLocalTrustWithEvidence({
    thresholds: DEFAULT_THRESHOLDS,
    requirePositiveEtEvidence: false,
    requirePositiveDtEvidence: true,
    levelDt: 1,
    dtHasEvidence: true,
    candidates: [],
  });
  assert.equal(withEvidence.score, 1);
  assert.equal(withEvidence.decision, "ask");
});
