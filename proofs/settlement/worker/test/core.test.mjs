import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  artifactPrefix,
  buildProofInput,
  classifyFailure,
  proofLeaseRecoveryStatus,
  retryDelaySeconds,
} from "../core.mjs";

const fixtureUrl = new URL("../../fixtures/layrs-v3-zen-15m-1785196800.json", import.meta.url);

test("production witness builder matches the committed real-market fixture", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const result = buildProofInput({
    marketId: fixture.marketId,
    opening: {
      protocol: "layrs-pyth-boundary-v1",
      feedId: 245,
      boundaryMs: fixture.opening.windowEndMicros / 1_000,
      manifestHash: `0x${Buffer.from(fixture.opening.evidenceCommitment).toString("hex")}`,
      medianPriceE8: String(fixture.opening.expectedMedianE8),
      observations: fixture.opening.observationsE8.map((normalizedPriceE8) => ({
        normalizedPriceE8: String(normalizedPriceE8),
        publishers: fixture.opening.minimumPublisherCount,
      })),
    },
    closing: {
      protocol: "layrs-pyth-boundary-v1",
      feedId: 245,
      boundaryMs: fixture.closing.windowEndMicros / 1_000,
      manifestHash: `0x${Buffer.from(fixture.closing.evidenceCommitment).toString("hex")}`,
      medianPriceE8: String(fixture.closing.expectedMedianE8),
      observations: fixture.closing.observationsE8.map((normalizedPriceE8) => ({
        normalizedPriceE8: String(normalizedPriceE8),
        publishers: fixture.closing.minimumPublisherCount,
      })),
    },
  });
  assert.deepEqual(result.input, fixture);
  assert.equal(result.witnessHash.length, 32);
});

test("invalid witnesses fail closed and retries are bounded", () => {
  assert.throws(() => buildProofInput({ marketId: "m", opening: {}, closing: {} }), /INVALID_OPENING/);
  assert.deepEqual(classifyFailure(new Error("INVALID_MEDIAN"), 1), {
    status: "MANUAL_REVIEW",
    code: "INVALID_MEDIAN",
  });
  assert.deepEqual(classifyFailure(new Error("NETWORK_TIMEOUT"), 8), {
    status: "FAILED",
    code: "NETWORK_TIMEOUT",
  });
  assert.equal(retryDelaySeconds(1), 16);
  assert.equal(retryDelaySeconds(100), 3_600);
});

test("artifact keys bind market, version, and settlement", () => {
  const first = artifactPrefix("market-a", `0x${"11".repeat(32)}`);
  const second = artifactPrefix("market-b", `0x${"11".repeat(32)}`);
  assert.notEqual(first, second);
  assert.match(first, /layrs\.zk\.settlement\.v1/);
});

test("expired proof leases recover without ambiguous resubmission", () => {
  assert.equal(proofLeaseRecoveryStatus("PROVING"), "PENDING");
  assert.equal(proofLeaseRecoveryStatus("ATTESTING"), "SUBMITTED");
  assert.equal(proofLeaseRecoveryStatus("SUBMITTING"), "MANUAL_REVIEW");
  assert.equal(proofLeaseRecoveryStatus("ATTESTED"), null);
});
