import { createHash } from "node:crypto";

export const PROOF_PROGRAM_VERSION = "layrs.zk.settlement.v1";
export const PROOF_INPUT_MAX_BYTES = 128 * 1024;
export const PROOF_LEASE_MILLIS = 2 * 60 * 60 * 1000;
export const PROOF_MAX_ATTEMPTS = 8;
export const PROOF_LEASE_RECOVERY = Object.freeze({
  PROVING: "PENDING",
  SUBMITTING: "MANUAL_REVIEW",
  ATTESTING: "SUBMITTED",
});
const OBSERVATION_DOMAIN = Buffer.from(
  "6c617972732e7a6b2e626f756e646172792d6f62736572766174696f6e732e763100",
  "hex",
);

export function sha256(value) {
  return createHash("sha256").update(value).digest();
}

export function hex32(value, label) {
  const normalized = String(value ?? "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`${label} must be a 32-byte hex value`);
  }
  return normalized;
}

export function buildProofInput(row) {
  const marketId = String(row.marketId ?? "");
  if (!marketId || marketId.length > 160) throw new Error("INVALID_MARKET_ID");
  const opening = buildBoundary(row.opening, "opening");
  const closing = buildBoundary(row.closing, "closing");
  if (opening.windowEndMicros >= closing.windowEndMicros) {
    throw new Error("INVALID_BOUNDARY_ORDER");
  }
  const input = {
    proofProgramVersion: PROOF_PROGRAM_VERSION,
    marketId,
    destinationChainId: 26_514,
    oracleFeedId: 245,
    opening,
    closing,
    payoutRoot: Array(32).fill(0),
    feeRoot: Array(32).fill(0),
    payoutCoverage: false,
    feeCoverage: false,
  };
  const encoded = Buffer.from(JSON.stringify(input));
  if (encoded.length > PROOF_INPUT_MAX_BYTES) throw new Error("PROOF_WITNESS_OVERSIZED");
  return { input, encoded, witnessHash: sha256(encoded) };
}

function buildBoundary(manifest, label) {
  if (
    manifest?.protocol !== "layrs-pyth-boundary-v1" ||
    manifest.feedId !== 245 ||
    !Number.isSafeInteger(manifest.boundaryMs) ||
    !Array.isArray(manifest.observations) ||
    manifest.observations.length !== 25
  ) {
    throw new Error(`INVALID_${label.toUpperCase()}_BOUNDARY`);
  }
  const observations = manifest.observations.map((observation) => {
    const value = String(observation?.normalizedPriceE8 ?? "");
    if (!/^[1-9][0-9]{0,17}$/.test(value)) throw new Error("INVALID_PYTH_OBSERVATION");
    const parsed = BigInt(value);
    if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("PYTH_OBSERVATION_OUT_OF_RANGE");
    return parsed;
  });
  const minimumPublisherCount = Math.min(
    ...manifest.observations.map((observation) => Number(observation?.publishers)),
  );
  if (!Number.isSafeInteger(minimumPublisherCount) || minimumPublisherCount < 3) {
    throw new Error("INVALID_PUBLISHER_POLICY");
  }
  const boundary = {
    windowStartMicros: (manifest.boundaryMs - 5_000) * 1_000,
    windowEndMicros: manifest.boundaryMs * 1_000,
    minimumPublisherCount,
    evidenceCommitment: [...Buffer.from(hex32(manifest.manifestHash, "manifestHash").slice(2), "hex")],
    observationsE8: observations.map(Number),
    observationsCommitment: Array(32).fill(0),
    expectedMedianE8: Number(BigInt(String(manifest.medianPriceE8))),
  };
  boundary.observationsCommitment = [...observationCommitment(boundary)];
  return boundary;
}

export function observationCommitment(boundary) {
  const hasher = createHash("sha256");
  hasher.update(OBSERVATION_DOMAIN);
  hasher.update(signedI64(boundary.windowStartMicros));
  hasher.update(signedI64(boundary.windowEndMicros));
  const publishers = Buffer.alloc(2);
  publishers.writeUInt16BE(boundary.minimumPublisherCount);
  hasher.update(publishers);
  for (const observation of boundary.observationsE8) hasher.update(signedI64(observation));
  return hasher.digest();
}

function signedI64(value) {
  const integer = BigInt(value);
  if (integer < -(1n << 63n) || integer > (1n << 63n) - 1n) {
    throw new Error("SIGNED_I64_OUT_OF_RANGE");
  }
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64BE(integer);
  return bytes;
}

export function retryDelaySeconds(attempt) {
  if (!Number.isSafeInteger(attempt) || attempt < 1) throw new Error("INVALID_ATTEMPT");
  return Math.min(3_600, 2 ** Math.min(attempt + 3, 12));
}

export function proofLeaseRecoveryStatus(status) {
  return PROOF_LEASE_RECOVERY[status] ?? null;
}

export function classifyFailure(error, attempt) {
  const code = error instanceof Error ? error.message : "UNKNOWN_FAILURE";
  const manual = [
    "INVALID_",
    "CORRUPT_",
    "CONFLICT",
    "MISMATCH",
    "OVERSIZED",
    "OUT_OF_RANGE",
    "UNSUPPORTED_",
  ].some((fragment) => code.includes(fragment));
  if (manual) return { status: "MANUAL_REVIEW", code };
  if (attempt >= PROOF_MAX_ATTEMPTS) return { status: "FAILED", code };
  return { status: "PENDING", code };
}

export function artifactPrefix(marketId, settlementManifestHash) {
  const marketHash = sha256(Buffer.from(marketId)).toString("hex");
  return `zk-settlement/${marketHash}/${PROOF_PROGRAM_VERSION}/${hex32(
    settlementManifestHash,
    "settlementManifestHash",
  ).slice(2)}`;
}
