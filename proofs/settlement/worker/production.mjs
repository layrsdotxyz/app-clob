import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  Contract,
  JsonRpcProvider,
  Wallet,
  getAddress,
  hexlify,
  sha256 as evmSha256,
  toUtf8Bytes,
} from "ethers";
import pg from "pg";
import {
  PROOF_LEASE_MILLIS,
  PROOF_PROGRAM_VERSION,
  artifactPrefix,
  buildProofInput,
  classifyFailure,
  hex32,
  retryDelaySeconds,
  sha256,
} from "./core.mjs";

const execFileAsync = promisify(execFile);
const ARTIFACT_FILES = [
  "witness.json",
  "proof.cbor",
  "public-inputs.bin",
  "output.json",
  "artifact.json",
];
const ABI = [
  "function imageId() view returns (bytes32)",
  "function attestation(bytes32 marketIdHash) view returns (bytes32 settlementCommitment,bytes32 journalHash,bytes32 zkVerifyLeaf,bytes32 proofArtifactHash,bytes32 zkVerifyTransactionHash,uint256 aggregationId,int64 openingMedianE8,int64 closingMedianE8,uint8 outcome,uint64 attestedAt)",
  "function attestSettlement(bytes publicJournal,uint256 aggregationId,bytes32[] merklePath,uint256 leafCount,uint256 index,bytes32 proofArtifactHash,bytes32 zkVerifyTransactionHash) returns (bytes32 marketIdHash)",
  "event SettlementAttested(bytes32 indexed marketIdHash,bytes32 indexed settlementCommitment,bytes32 indexed zkVerifyLeaf,uint256 aggregationId,bytes32 journalHash,bytes32 proofArtifactHash,bytes32 zkVerifyTransactionHash,int64 openingMedianE8,int64 closingMedianE8,uint8 outcome)",
];

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function positiveInteger(name, fallback) {
  const raw = process.env[name] ?? String(fallback);
  if (!/^[1-9][0-9]*$/.test(raw)) throw new Error(`${name} is invalid`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) throw new Error(`${name} is invalid`);
  return value;
}

function log(event, detail = {}) {
  process.stdout.write(`${JSON.stringify({
    level: "info",
    event,
    observedAt: new Date().toISOString(),
    ...detail,
  })}\n`);
}

function errorLog(event, detail = {}) {
  process.stderr.write(`${JSON.stringify({
    level: "error",
    event,
    observedAt: new Date().toISOString(),
    ...detail,
  })}\n`);
}

function databaseConfig() {
  return {
    host: required("LAYRSV2_DB_HOST"),
    port: positiveInteger("LAYRSV2_DB_PORT", 5432),
    database: required("LAYRSV2_DB_NAME"),
    user: required("LAYRSV2_DB_USER"),
    password: required("LAYRSV2_DB_PASSWORD"),
    application_name: "layrsv2-zk-settlement-proof-worker",
    max: 2,
    ssl: {
      rejectUnauthorized: true,
      ca: required("LAYRSV2_DB_CA_PEM").replaceAll("\\n", "\n"),
    },
  };
}

async function claim(database) {
  const owner = randomUUID();
  const result = await database.query(
    `WITH candidate AS (
       SELECT market_id,proof_program_version
         FROM layrsv2.zk_settlement_proof_jobs
        WHERE status IN ('PENDING','PROVED','SUBMITTED')
          AND next_attempt_at <= now()
          AND (lease_until IS NULL OR lease_until < now())
        ORDER BY CASE status
                   WHEN 'SUBMITTED' THEN 0
                   WHEN 'PROVED' THEN 1
                   ELSE 2
                 END,
                 next_attempt_at,created_at
        FOR UPDATE SKIP LOCKED
        LIMIT 1
     )
     UPDATE layrsv2.zk_settlement_proof_jobs job
        SET lease_owner=$1,
            lease_until=now()+($2*interval '1 millisecond'),
            attempts=attempts+1,
            status=CASE status
              WHEN 'PENDING' THEN 'PROVING'
              WHEN 'FAILED' THEN 'PROVING'
              WHEN 'PROVED' THEN 'SUBMITTING'
              WHEN 'SUBMITTED' THEN 'ATTESTING'
              ELSE status END,
            updated_at=now()
       FROM candidate
      WHERE job.market_id=candidate.market_id
        AND job.proof_program_version=candidate.proof_program_version
     RETURNING job.market_id,job.proof_program_version,
               encode(job.settlement_manifest_hash,'hex') AS settlement_manifest_hash,
               job.status,job.attempts::text,job.artifact_prefix`,
    [owner, PROOF_LEASE_MILLIS],
  );
  return result.rows[0] ? { ...result.rows[0], owner } : null;
}

async function heartbeat(database, job) {
  const result = await database.query(
    `UPDATE layrsv2.zk_settlement_proof_jobs
        SET lease_until=now()+($1*interval '1 millisecond'),updated_at=now()
      WHERE market_id=$2 AND proof_program_version=$3 AND lease_owner=$4`,
    [PROOF_LEASE_MILLIS, job.market_id, job.proof_program_version, job.owner],
  );
  if (result.rowCount !== 1) throw new Error("PROOF_JOB_LEASE_LOST");
}

async function loadWitnessRow(database, job) {
  const result = await database.query(
    `SELECT spec.market_id,
            encode(resolution.manifest_hash,'hex') AS manifest_hash,
            opening.manifest AS opening,
            closing.manifest AS closing
       FROM layrsv2.market_specs spec
       JOIN layrsv2.resolution_manifests resolution USING(market_id)
       JOIN layrsv2.pyth_boundary_markets opening_link
         ON opening_link.market_id=spec.market_id AND opening_link.boundary_role='OPENING'
       JOIN layrsv2.pyth_boundary_manifests opening
         ON opening.boundary_ms=opening_link.boundary_ms
       JOIN layrsv2.pyth_boundary_markets closing_link
         ON closing_link.market_id=spec.market_id AND closing_link.boundary_role='CLOSING'
       JOIN layrsv2.pyth_boundary_manifests closing
         ON closing.boundary_ms=closing_link.boundary_ms
      WHERE spec.market_id=$1
        AND resolution.resolution_source='PYTH_HISTORICAL_MEDIAN'`,
    [job.market_id],
  );
  const row = result.rows[0];
  if (!row) throw new Error("PROOF_WITNESS_NOT_FOUND");
  if (row.manifest_hash !== job.settlement_manifest_hash) {
    throw new Error("PROOF_SETTLEMENT_MANIFEST_CONFLICT");
  }
  return { marketId: row.market_id, opening: row.opening, closing: row.closing };
}

async function putImmutable(s3, bucket, key, bytes, contentType, visibility) {
  const digest = sha256(bytes);
  try {
    await s3.send(new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: bytes,
      ContentType: contentType,
      ChecksumSHA256: digest.toString("base64"),
      IfNoneMatch: "*",
      Metadata: {
        "content-sha256": digest.toString("hex"),
        "artifact-type": "zk-settlement",
        visibility,
      },
    }));
  } catch (error) {
    if (error?.$metadata?.httpStatusCode !== 412) throw error;
    const existing = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    if (existing.Metadata?.["content-sha256"] !== digest.toString("hex")) {
      throw new Error("PROOF_ARTIFACT_IMMUTABILITY_CONFLICT");
    }
  }
  return digest;
}

async function downloadArtifacts(s3, bucket, prefix, directory, files) {
  for (const file of files) {
    const object = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: `${prefix}/${file}` }));
    await writeFile(join(directory, file), Buffer.from(await object.Body.transformToByteArray()), { flag: "wx" });
  }
}

async function prove(database, s3, bucket, job, directory) {
  const row = await loadWitnessRow(database, job);
  const witness = buildProofInput(row);
  const prefix = artifactPrefix(job.market_id, `0x${job.settlement_manifest_hash}`);
  const witnessPath = join(directory, "witness.json");
  await writeFile(witnessPath, witness.encoded, { flag: "wx", mode: 0o600 });
  await heartbeat(database, job);
  const host = required("LAYRSV2_ZK_PROOF_HOST_PATH");
  const started = Date.now();
  await execFileAsync(host, [witnessPath, directory], {
    timeout: positiveInteger("LAYRSV2_ZK_PROOF_TIMEOUT_MS", 45 * 60 * 1000),
    maxBuffer: 1024 * 1024,
  });
  const elapsedMs = Date.now() - started;
  await heartbeat(database, job);
  const artifact = JSON.parse(await readFile(join(directory, "artifact.json"), "utf8"));
  const output = JSON.parse(await readFile(join(directory, "output.json"), "utf8"));
  if (artifact.proofVersion !== "2.2.0") throw new Error("PROOF_VERSION_MISMATCH");
  if (output.marketId !== job.market_id) throw new Error("PROOF_MARKET_MISMATCH");
  for (const file of ARTIFACT_FILES) {
    const bytes = await readFile(join(directory, file));
    await putImmutable(
      s3,
      bucket,
      `${prefix}/${file}`,
      bytes,
      file.endsWith(".json") ? "application/json" : "application/octet-stream",
      file === "witness.json" ? "private" : "public",
    );
  }
  const updated = await database.query(
    `UPDATE layrsv2.zk_settlement_proof_jobs
        SET status='PROVED',artifact_prefix=$1,witness_hash=$2,
            image_id=decode($3,'hex'),proof_hash=decode($4,'hex'),
            journal_hash=decode($5,'hex'),settlement_commitment=decode($6,'hex'),
            proved_at=now(),lease_until=now()+($7*interval '1 millisecond'),updated_at=now()
      WHERE market_id=$8 AND proof_program_version=$9 AND lease_owner=$10 AND status='PROVING'`,
    [
      prefix,
      witness.witnessHash,
      hex32(artifact.imageId, "imageId").slice(2),
      hex32(artifact.proofHash, "proofHash").slice(2),
      hex32(artifact.journalHash, "journalHash").slice(2),
      Buffer.from(output.settlementCommitment).toString("hex"),
      PROOF_LEASE_MILLIS,
      job.market_id,
      job.proof_program_version,
      job.owner,
    ],
  );
  if (updated.rowCount !== 1) throw new Error("PROOF_JOB_LEASE_LOST");
  log("zk_settlement_proof_generated", {
    marketId: job.market_id,
    attempt: Number(job.attempts),
    elapsedMs,
    proofHash: artifact.proofHash,
    artifactPrefix: prefix,
  });
  job.status = "SUBMITTING";
  job.artifact_prefix = prefix;
}

async function submit(database, s3, bucket, job, directory) {
  if (!job.artifact_prefix) throw new Error("PROOF_ARTIFACT_PREFIX_MISSING");
  if (!(await exists(join(directory, "proof.cbor")))) {
    await downloadArtifacts(s3, bucket, job.artifact_prefix, directory, ARTIFACT_FILES.slice(1));
  }
  await heartbeat(database, job);
  const script = required("LAYRSV2_ZKVERIFY_SUBMIT_SCRIPT");
  const started = Date.now();
  await execFileAsync(
    process.execPath,
    [
      script,
      "--proof", join(directory, "proof.cbor"),
      "--public-inputs", join(directory, "public-inputs.bin"),
      "--artifact", join(directory, "artifact.json"),
      "--output", directory,
    ],
    {
      timeout: positiveInteger("LAYRSV2_ZKVERIFY_TIMEOUT_MS", 60 * 60 * 1000),
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, ZKVERIFY_SEED: required("ZKVERIFY_SEED") },
    },
  );
  const elapsedMs = Date.now() - started;
  await heartbeat(database, job);
  const evidence = JSON.parse(await readFile(join(directory, "zkverify-attestation.json"), "utf8"));
  const transactionHash = hex32(evidence.transaction?.txHash, "zkVerify transactionHash");
  const aggregationId = Number(evidence.transaction?.aggregationId);
  if (!Number.isSafeInteger(aggregationId) || aggregationId < 0 || !evidence.merklePath?.leaf) {
    throw new Error("ZKVERIFY_ATTESTATION_INVALID");
  }
  for (const file of ["zkverify-submission.json", "zkverify-attestation.json"]) {
    const bytes = await readFile(join(directory, file));
    await putImmutable(s3, bucket, `${job.artifact_prefix}/${file}`, bytes, "application/json", "public");
  }
  const updated = await database.query(
    `UPDATE layrsv2.zk_settlement_proof_jobs
        SET status='SUBMITTED',zkverify_transaction_hash=decode($1,'hex'),
            zkverify_aggregation_id=$2,submitted_at=now(),
            lease_until=now()+($3*interval '1 millisecond'),updated_at=now()
      WHERE market_id=$4 AND proof_program_version=$5 AND lease_owner=$6
        AND status IN ('PROVED','SUBMITTING')`,
    [transactionHash.slice(2), aggregationId, PROOF_LEASE_MILLIS,
      job.market_id, job.proof_program_version, job.owner],
  );
  if (updated.rowCount !== 1) throw new Error("PROOF_JOB_LEASE_LOST");
  log("zk_settlement_proof_verified", {
    marketId: job.market_id,
    elapsedMs,
    transactionHash,
    aggregationId,
  });
  job.status = "ATTESTING";
}

async function attest(database, s3, bucket, job, directory, chain) {
  if (!job.artifact_prefix) throw new Error("PROOF_ARTIFACT_PREFIX_MISSING");
  if (!(await exists(join(directory, "zkverify-attestation.json")))) {
    await downloadArtifacts(s3, bucket, job.artifact_prefix, directory, [
      "proof.cbor",
      "public-inputs.bin",
      "output.json",
      "zkverify-attestation.json",
    ]);
  }
  await heartbeat(database, job);
  const evidence = JSON.parse(await readFile(join(directory, "zkverify-attestation.json"), "utf8"));
  const output = JSON.parse(await readFile(join(directory, "output.json"), "utf8"));
  const journal = await readFile(join(directory, "public-inputs.bin"));
  const proof = await readFile(join(directory, "proof.cbor"));
  if (journal.length !== 480 || output.marketId !== job.market_id) {
    throw new Error("HORIZEN_ATTESTATION_INPUT_MISMATCH");
  }
  const aggregationId = Number(evidence.transaction?.aggregationId);
  const merklePath = evidence.merklePath?.proof;
  const leafCount = Number(evidence.merklePath?.numberOfLeaves);
  const index = Number(evidence.merklePath?.leafIndex);
  if (
    !Number.isSafeInteger(aggregationId) ||
    !Number.isSafeInteger(leafCount) ||
    !Number.isSafeInteger(index) ||
    !Array.isArray(merklePath)
  ) {
    throw new Error("HORIZEN_ATTESTATION_INPUT_INVALID");
  }
  const marketIdHash = evmSha256(toUtf8Bytes(job.market_id));
  const existing = await chain.contract.attestation(marketIdHash);
  let transactionHash;
  let blockNumber;
  if (existing.attestedAt !== 0n) {
    if (
      existing.settlementCommitment.toLowerCase() !==
        `0x${Buffer.from(output.settlementCommitment).toString("hex")}` ||
      existing.zkVerifyTransactionHash.toLowerCase() !==
        String(evidence.transaction.txHash).toLowerCase()
    ) {
      throw new Error("HORIZEN_ATTESTATION_CONFLICT");
    }
    const latest = await chain.provider.getBlockNumber();
    const fromBlock = Math.max(chain.registryDeploymentBlock, latest - 1_000_000);
    const events = await chain.contract.queryFilter(
      chain.contract.filters.SettlementAttested(marketIdHash),
      fromBlock,
      latest,
    );
    const event = events.at(-1);
    if (!event) throw new Error("HORIZEN_ATTESTATION_EVENT_NOT_FOUND");
    transactionHash = event.transactionHash;
    blockNumber = event.blockNumber;
  } else {
    const transaction = await chain.contract.attestSettlement(
      hexlify(journal),
      aggregationId,
      merklePath.map((entry) => hex32(entry, "merklePath")),
      leafCount,
      index,
      evmSha256(proof),
      hex32(evidence.transaction.txHash, "zkVerifyTransactionHash"),
    );
    const receipt = await transaction.wait(2);
    if (!receipt || receipt.status !== 1) throw new Error("HORIZEN_ATTESTATION_REVERTED");
    transactionHash = transaction.hash;
    blockNumber = receipt.blockNumber;
  }
  const confirmed = await chain.contract.attestation(marketIdHash);
  if (confirmed.attestedAt === 0n) throw new Error("HORIZEN_ATTESTATION_READBACK_MISSING");
  const attestation = {
    marketId: job.market_id,
    marketIdHash,
    registry: chain.registry,
    transactionHash,
    blockNumber,
    aggregationId,
    settlementCommitment: confirmed.settlementCommitment,
    journalHash: confirmed.journalHash,
    zkVerifyLeaf: confirmed.zkVerifyLeaf,
    proofArtifactHash: confirmed.proofArtifactHash,
    zkVerifyTransactionHash: confirmed.zkVerifyTransactionHash,
    openingMedianE8: confirmed.openingMedianE8.toString(),
    closingMedianE8: confirmed.closingMedianE8.toString(),
    outcome: Number(confirmed.outcome),
    attestedAt: confirmed.attestedAt.toString(),
    confirmedAt: new Date().toISOString(),
  };
  const bytes = Buffer.from(JSON.stringify(attestation, null, 2));
  await putImmutable(
    s3,
    bucket,
    `${job.artifact_prefix}/horizen-attestation.json`,
    bytes,
    "application/json",
    "public",
  );
  const updated = await database.query(
    `UPDATE layrsv2.zk_settlement_proof_jobs
        SET status='ATTESTED',horizen_transaction_hash=decode($1,'hex'),
            horizen_block_number=$2,attested_at=now(),
            lease_owner=NULL,lease_until=NULL,last_error_code=NULL,updated_at=now()
      WHERE market_id=$3 AND proof_program_version=$4 AND lease_owner=$5
        AND status IN ('SUBMITTED','ATTESTING')`,
    [transactionHash.slice(2), blockNumber, job.market_id, job.proof_program_version, job.owner],
  );
  if (updated.rowCount !== 1) throw new Error("PROOF_JOB_LEASE_LOST");
  log("zk_settlement_attestation_confirmed", {
    marketId: job.market_id,
    transactionHash,
    blockNumber,
  });
}

async function fail(database, job, error) {
  const attempt = Number(job.attempts);
  const failure = classifyFailure(error, attempt);
  const retryStatus =
    failure.status === "PENDING" && job.status === "SUBMITTING"
      ? "PROVED"
      : failure.status === "PENDING" && job.status === "ATTESTING"
        ? "SUBMITTED"
        : failure.status;
  const updated = await database.query(
    `UPDATE layrsv2.zk_settlement_proof_jobs
        SET status=$1,next_attempt_at=CASE WHEN $1 IN ('PENDING','FAILED')
              OR $1 IN ('PROVED','SUBMITTED')
              THEN now()+($2*interval '1 second') ELSE next_attempt_at END,
            lease_owner=NULL,lease_until=NULL,last_error_code=$3,updated_at=now()
      WHERE market_id=$4 AND proof_program_version=$5 AND lease_owner=$6`,
    [
      retryStatus,
      retryDelaySeconds(Math.max(1, attempt)),
      failure.code.slice(0, 256),
      job.market_id,
      job.proof_program_version,
      job.owner,
    ],
  );
  if (updated.rowCount !== 1) throw new Error("PROOF_JOB_LEASE_LOST");
  const detail = {
    marketId: job.market_id,
    attempt,
    code: failure.code,
    nextStatus: retryStatus,
  };
  if (failure.status === "MANUAL_REVIEW") {
    errorLog("zk_settlement_proof_manual_review", detail);
  } else if (failure.status === "FAILED") {
    errorLog("zk_settlement_proof_failed", detail);
  } else {
    log("zk_settlement_proof_retry_scheduled", detail);
  }
}

async function exists(path) {
  try {
    await readFile(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function chainClient() {
  const rpc = required("LAYRSV2_HORIZEN_RPC_URL");
  const provider = new JsonRpcProvider(rpc, 26_514, { staticNetwork: true });
  const privateKey = required("LAYRSV2_ZK_ATTESTATION_PRIVATE_KEY");
  const signer = new Wallet(privateKey, provider);
  const expected = process.env.LAYRSV2_ZK_ATTESTATION_SIGNER_ADDRESS;
  if (expected && getAddress(expected) !== signer.address) {
    throw new Error("HORIZEN_ATTESTATION_SIGNER_MISMATCH");
  }
  const registry = getAddress(required("LAYRSV2_ZK_SETTLEMENT_REGISTRY"));
  return {
    provider,
    signer,
    registry,
    registryDeploymentBlock: positiveInteger("LAYRSV2_ZK_REGISTRY_DEPLOYMENT_BLOCK", 1),
    contract: new Contract(registry, ABI, signer),
  };
}

async function auditBacklog(database) {
  const result = await database.query(
    `SELECT count(*) FILTER (
              WHERE status IN ('PENDING','PROVING','PROVED','SUBMITTING','SUBMITTED','ATTESTING')
                AND created_at < now()-interval '2 hours'
            )::text AS stale,
            count(*) FILTER (WHERE status='MANUAL_REVIEW')::text AS manual_review,
            count(*) FILTER (WHERE status='FAILED')::text AS failed
       FROM layrsv2.zk_settlement_proof_jobs`,
  );
  const counts = result.rows[0] ?? { stale: "0", manual_review: "0", failed: "0" };
  for (const [name, value] of Object.entries(counts)) {
    if (Number(value) > 0) {
      errorLog(`zk_settlement_proof_${name}`, { count: Number(value) });
    }
  }
}

async function processJob(database, s3, bucket, chain, job) {
  const directory = await mkdtemp(join(tmpdir(), "layrs-zk-proof-"));
  try {
    if (job.status === "PROVING") await prove(database, s3, bucket, job, directory);
    if (job.status === "SUBMITTING") await submit(database, s3, bucket, job, directory);
    if (job.status === "ATTESTING") await attest(database, s3, bucket, job, directory, chain);
  } catch (error) {
    await fail(database, job, error);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function main() {
  const database = new pg.Pool(databaseConfig());
  const region = required("LAYRSV2_AWS_REGION");
  const bucket = required("LAYRSV2_IMMUTABLE_ARTIFACT_BUCKET");
  const s3 = new S3Client({ region });
  const chain = chainClient();
  const oneShot = process.env.LAYRSV2_ZK_ONESHOT === "true";
  if (Number((await chain.provider.getNetwork()).chainId) !== 26_514) {
    throw new Error("HORIZEN_CHAIN_ID_MISMATCH");
  }
  if ((await chain.provider.getCode(chain.registry)) === "0x") {
    throw new Error("ZK_SETTLEMENT_REGISTRY_NOT_DEPLOYED");
  }
  const host = required("LAYRSV2_ZK_PROOF_HOST_PATH");
  const { stdout: imageIdOutput } = await execFileAsync(host, ["--image-id"], {
    timeout: 30_000,
    maxBuffer: 1_024,
  });
  const hostImageId = hex32(imageIdOutput.trim(), "hostImageId");
  const registryImageId = hex32(await chain.contract.imageId(), "registryImageId");
  if (hostImageId !== registryImageId) {
    throw new Error("ZK_SETTLEMENT_REGISTRY_IMAGE_ID_MISMATCH");
  }
  let stopping = false;
  const stop = () => { stopping = true; };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  log("zk_settlement_proof_worker_ready", {
    proofProgramVersion: PROOF_PROGRAM_VERSION,
    registry: chain.registry,
    imageId: hostImageId,
    signer: chain.signer.address,
  });
  try {
    await auditBacklog(database);
    while (!stopping) {
      const job = await claim(database);
      if (job) {
        await processJob(database, s3, bucket, chain, job);
        if (oneShot) stopping = true;
      } else {
        if (oneShot) {
          stopping = true;
        } else {
          await new Promise((resolve) => setTimeout(resolve, 5_000));
        }
      }
    }
  } finally {
    await database.end();
  }
}

main().catch((error) => {
  errorLog("zk_settlement_proof_worker_fatal", {
    code: error instanceof Error ? error.message : "UNKNOWN_FAILURE",
  });
  process.exitCode = 1;
});
