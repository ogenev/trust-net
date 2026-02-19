import test from "node:test";
import assert from "node:assert/strict";

import {
  TRUST_CIRCLE_CUSTOM,
  TRUST_CIRCLE_MY_CONTACTS,
  TRUST_CIRCLE_ONLY_ME,
  TRUST_CIRCLE_OPENCLAW_VERIFIED,
  filterCandidatesByTrustCircle,
  parseTrustCirclePolicy,
} from "../src/trust-circles.js";

const CANDIDATES = Object.freeze([
  { endorser: "0xcontact1", levelDe: 2, levelEt: 2 },
  { endorser: "0xverified1", levelDe: 2, levelEt: 1 },
  { endorser: "0xcustom1", levelDe: 1, levelEt: 1 },
]);

test("parseTrustCirclePolicy defaults to onlyMe with empty allowlists", () => {
  const policy = parseTrustCirclePolicy({});

  assert.equal(policy.default, TRUST_CIRCLE_ONLY_ME);
  assert.deepEqual(policy.endorsers[TRUST_CIRCLE_MY_CONTACTS], []);
  assert.deepEqual(policy.endorsers[TRUST_CIRCLE_OPENCLAW_VERIFIED], []);
  assert.deepEqual(policy.endorsers[TRUST_CIRCLE_CUSTOM], []);
});

test("parseTrustCirclePolicy validates trust circle preset", () => {
  assert.throws(
    () =>
      parseTrustCirclePolicy({
        trustCircles: {
          default: "invalid",
        },
      }),
    /trustCircles\.default must be one of/,
  );
});

test("filterCandidatesByTrustCircle enforces onlyMe", () => {
  const filtered = filterCandidatesByTrustCircle(
    parseTrustCirclePolicy({ trustCircles: { default: TRUST_CIRCLE_ONLY_ME } }),
    CANDIDATES,
  );
  assert.deepEqual(filtered, []);
});

test("filterCandidatesByTrustCircle enforces myContacts allowlist", () => {
  const filtered = filterCandidatesByTrustCircle(
    parseTrustCirclePolicy({
      trustCircles: {
        default: TRUST_CIRCLE_MY_CONTACTS,
        endorsers: {
          myContacts: ["0xcontact1", "0xcontact1"],
        },
      },
    }),
    CANDIDATES,
  );
  assert.deepEqual(filtered, [{ endorser: "0xcontact1", levelDe: 2, levelEt: 2 }]);
});

test("filterCandidatesByTrustCircle enforces openclawVerified allowlist", () => {
  const filtered = filterCandidatesByTrustCircle(
    parseTrustCirclePolicy({
      trustCircles: {
        default: TRUST_CIRCLE_OPENCLAW_VERIFIED,
        endorsers: {
          openclawVerified: ["0xverified1"],
        },
      },
    }),
    CANDIDATES,
  );
  assert.deepEqual(filtered, [{ endorser: "0xverified1", levelDe: 2, levelEt: 1 }]);
});

test("filterCandidatesByTrustCircle enforces custom allowlist", () => {
  const filtered = filterCandidatesByTrustCircle(
    parseTrustCirclePolicy({
      trustCircles: {
        default: TRUST_CIRCLE_CUSTOM,
        endorsers: {
          custom: ["0xcustom1"],
        },
      },
    }),
    CANDIDATES,
  );
  assert.deepEqual(filtered, [{ endorser: "0xcustom1", levelDe: 1, levelEt: 1 }]);
});
