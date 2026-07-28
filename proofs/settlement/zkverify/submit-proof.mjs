import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Risc0Version,
  ZkVerifyEvents,
  zkVerifySession,
} from "zkverifyjs";

const DOMAIN_ID = 3;
const DEFAULT_RECEIPT_TIMEOUT_MS = 45 * 60 * 1000;

function requireEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument near ${key ?? "<end>"}`);
    }
    values.set(key.slice(2), value);
  }
  for (const required of ["proof", "public-inputs", "artifact", "output"]) {
    if (!values.has(required)) {
      throw new Error(`--${required} is required`);
    }
  }
  return Object.fromEntries(values);
}

function hex(bytes) {
  return `0x${bytes.toString("hex")}`;
}

function json(value) {
  return JSON.stringify(
    value,
    (_key, item) => (typeof item === "bigint" ? item.toString() : item),
    2,
  );
}

const args = parseArgs(process.argv.slice(2));
const seed = requireEnv("ZKVERIFY_SEED");
const proof = hex(await readFile(resolve(args.proof)));
const publicSignals = hex(await readFile(resolve(args["public-inputs"])));
const artifact = JSON.parse(await readFile(resolve(args.artifact), "utf8"));
const outputDirectory = resolve(args.output);
const receiptTimeoutMs = Number(
  process.env.ZKVERIFY_RECEIPT_TIMEOUT_MS ?? DEFAULT_RECEIPT_TIMEOUT_MS,
);

if (!/^0x[0-9a-f]{64}$/i.test(artifact.imageId)) {
  throw new Error("artifact imageId must be a 32-byte hex value");
}
if (publicSignals.length !== 2 + 480 * 2) {
  throw new Error("settlement public journal must be exactly 480 bytes");
}
if (!Number.isSafeInteger(receiptTimeoutMs) || receiptTimeoutMs <= 0) {
  throw new Error("ZKVERIFY_RECEIPT_TIMEOUT_MS must be a positive integer");
}

await mkdir(outputDirectory, { recursive: true });
const session = await zkVerifySession.start().zkVerify().withAccount(seed);

try {
  const [account] = await session.getAccountInfo();
  if (!account) {
    throw new Error("zkVerify session did not expose the submitter account");
  }

  const eventLog = [];
  const { events, transactionResult } = await session
    .verify()
    .risc0({ version: Risc0Version.V2_2 })
    .execute({
      proofData: {
        proof,
        publicSignals,
        vk: artifact.imageId,
      },
      domainId: DOMAIN_ID,
    });

  for (const eventName of [
    ZkVerifyEvents.Broadcast,
    ZkVerifyEvents.IncludedInBlock,
    ZkVerifyEvents.ProofVerified,
    ZkVerifyEvents.Finalized,
    ZkVerifyEvents.CannotAggregate,
    ZkVerifyEvents.ErrorEvent,
  ]) {
    events.on(eventName, (data) => {
      eventLog.push({
        event: eventName,
        observedAt: new Date().toISOString(),
        data,
      });
    });
  }

  const transaction = await transactionResult;
  if (
    transaction.domainId !== DOMAIN_ID ||
    transaction.aggregationId === undefined ||
    !transaction.statement ||
    !transaction.txHash
  ) {
    throw new Error(`incomplete zkVerify result: ${json(transaction)}`);
  }

  const submitted = {
    submittedAt: new Date().toISOString(),
    submitter: account.address,
    balanceBefore: account.freeBalance,
    proofHash: artifact.proofHash,
    journalHash: artifact.journalHash,
    imageId: artifact.imageId,
    transaction,
    events: eventLog,
  };
  await writeFile(
    resolve(outputDirectory, "zkverify-submission.json"),
    `${json(submitted)}\n`,
  );
  process.stdout.write(`${json(submitted)}\n`);

  const receipt = await session.waitForAggregationReceipt(
    DOMAIN_ID,
    transaction.aggregationId,
    receiptTimeoutMs,
  );
  const merklePath = await session.getAggregateStatementPath(
    receipt.blockHash,
    DOMAIN_ID,
    transaction.aggregationId,
    transaction.statement,
  );
  const completed = {
    ...submitted,
    aggregationReceipt: receipt,
    merklePath,
    completedAt: new Date().toISOString(),
  };
  await writeFile(
    resolve(outputDirectory, "zkverify-attestation.json"),
    `${json(completed)}\n`,
  );
  process.stdout.write(`${json(completed)}\n`);
} finally {
  await session.close();
}
