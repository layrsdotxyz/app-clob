#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const stackName = 'layrs-production-direct-execution-dormant';
const bucket = 'layrs-production-082223548516-us-east-1-immutable';
const archivePrefix = 'direct-execution/layrs-opening-epoch-20260911-941107537728c98b';
const epochId = 'layrs-opening-epoch-20260911-941107537728c98b';
const epochStateSha256 = '84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590';
const evidenceManifestSha256 = '70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957';
const evidenceSha256 = 'f619b5be495668c08b098c535f9cf00802f20cb02ff76388356f0ac69eb711e6';
const startingSequence = 5;
const evidencePath = fileURLToPath(
  new URL('../evidence/P0_DIRECT_MARKET_REGISTRATIONS_SIGNED_20260914.json', import.meta.url),
);

const mode = process.argv[2] ?? '--validate';
if (!['--validate', '--preflight', '--execute'].includes(mode)) {
  throw new Error('usage: submit-direct-market-registrations.mjs [--validate|--preflight|--execute]');
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => JSON.stringify(value);
const stableCanonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableCanonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableCanonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};

function aws(args, { json = true } = {}) {
  const outputArguments = json ? ['--output', 'json'] : [];
  const output = execFileSync(
    'aws',
    ['--profile', 'predifi-root', '--region', 'us-east-1', ...outputArguments, ...args],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).trim();
  return json ? JSON.parse(output || 'null') : output;
}

function ssm(instanceId, commands) {
  const commandId = aws([
    'ssm',
    'send-command',
    '--instance-ids',
    instanceId,
    '--document-name',
    'AWS-RunShellScript',
    '--parameters',
    JSON.stringify({ commands }),
    '--query',
    'Command.CommandId',
    '--output',
    'text',
  ], { json: false });
  execFileSync(
    'aws',
    [
      '--profile',
      'predifi-root',
      '--region',
      'us-east-1',
      'ssm',
      'wait',
      'command-executed',
      '--command-id',
      commandId,
      '--instance-id',
      instanceId,
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );
  const invocation = aws([
    'ssm',
    'get-command-invocation',
    '--command-id',
    commandId,
    '--instance-id',
    instanceId,
  ]);
  if (invocation.Status !== 'Success' || invocation.ResponseCode !== 0) {
    throw new Error(`SSM command ${commandId} failed with status ${invocation.Status}`);
  }
  return { commandId, output: invocation.StandardOutputContent.trim() };
}

function httpViaSsm(instanceId, { method = 'GET', path, body }) {
  const commands = ['set -euo pipefail', 'umask 077'];
  if (body === undefined) {
    commands.push(
      'layrs_response_file=$(mktemp /run/layrs-market-response.XXXXXX)',
      "trap 'rm -f \"$layrs_response_file\"' EXIT",
      `layrs_http_code=$(curl --silent --show-error --max-time 20 --output "$layrs_response_file" --write-out '%{http_code}' 'http://127.0.0.1:8443${path}')`,
      'printf \'%s\\n\' "$layrs_http_code"',
      'base64 --wrap=0 "$layrs_response_file"',
      "printf '\\n'",
    );
  } else {
    const encoded = Buffer.from(canonical(body)).toString('base64');
    const bodySha256 = sha256(Buffer.from(canonical(body)));
    commands.push(
      'layrs_body_file=$(mktemp /run/layrs-market-body.XXXXXX)',
      'layrs_response_file=$(mktemp /run/layrs-market-response.XXXXXX)',
      "trap 'rm -f \"$layrs_body_file\" \"$layrs_response_file\"' EXIT",
      `printf '%s' '${encoded}' | base64 --decode > "$layrs_body_file"`,
      `test "$(sha256sum "$layrs_body_file" | awk '{print $1}')" = '${bodySha256}'`,
      `layrs_http_code=$(curl --silent --show-error --max-time 30 --request '${method}' --header 'content-type: application/json' --data-binary '@'"$layrs_body_file" --output "$layrs_response_file" --write-out '%{http_code}' 'http://127.0.0.1:8443${path}')`,
      'printf \'%s\\n\' "$layrs_http_code"',
      'base64 --wrap=0 "$layrs_response_file"',
      "printf '\\n'",
    );
  }
  const result = ssm(instanceId, commands);
  const [statusLine, encodedBody] = result.output.split('\n');
  const status = Number(statusLine);
  const decoded = Buffer.from(encodedBody ?? '', 'base64').toString('utf8');
  let response;
  try {
    response = JSON.parse(decoded);
  } catch {
    throw new Error(`HTTP ${status} returned a non-JSON bounded response (SSM ${result.commandId})`);
  }
  return { ...result, status, response };
}

function locateRuntime(expectedAmiId) {
  const resources = aws([
    'cloudformation',
    'list-stack-resources',
    '--stack-name',
    stackName,
  ]).StackResourceSummaries;
  const groups = resources.filter((item) => item.ResourceType === 'AWS::AutoScaling::AutoScalingGroup');
  if (groups.length !== 1) throw new Error('expected exactly one runtime Auto Scaling group');
  const group = aws([
    'autoscaling',
    'describe-auto-scaling-groups',
    '--auto-scaling-group-names',
    groups[0].PhysicalResourceId,
  ]).AutoScalingGroups[0];
  const instances = group.Instances.filter(
    (item) => item.LifecycleState === 'InService' && item.HealthStatus === 'Healthy',
  );
  if (group.DesiredCapacity !== 1 || instances.length !== 1) {
    throw new Error('expected exactly one healthy in-service runtime instance');
  }
  const instanceId = instances[0].InstanceId;
  const ec2 = aws(['ec2', 'describe-instances', '--instance-ids', instanceId])
    .Reservations[0].Instances[0];
  if (ec2.State.Name !== 'running' || ec2.ImageId !== expectedAmiId) {
    throw new Error(`runtime instance does not use expected AMI ${expectedAmiId}`);
  }
  const ssmInfo = aws([
    'ssm',
    'describe-instance-information',
    '--filters',
    `Key=InstanceIds,Values=${instanceId}`,
  ]).InstanceInformationList;
  if (ssmInfo.length !== 1 || ssmInfo[0].PingStatus !== 'Online') {
    throw new Error('runtime instance is not online in SSM');
  }
  return instanceId;
}

function archiveSnapshot() {
  const contents = aws([
    's3api',
    'list-objects-v2',
    '--bucket',
    bucket,
    '--prefix',
    `${archivePrefix}/`,
  ]).Contents ?? [];
  const keys = contents.map((item) => item.Key);
  const artifacts = keys.filter((key) => key.startsWith(`${archivePrefix}/artifacts/`));
  const heads = keys.filter((key) => key.startsWith(`${archivePrefix}/heads/`));
  if (artifacts.length !== heads.length) throw new Error('artifact/head cardinality mismatch');
  const artifactNames = artifacts.map((key) => key.split('/').at(-1)).sort();
  const headNames = heads.map((key) => key.split('/').at(-1)).sort();
  if (canonical(artifactNames) !== canonical(headNames)) throw new Error('artifact/head binding mismatch');
  const sequences = artifactNames.map((name) => Number(name.slice(0, 20)));
  if (sequences.some((sequence, index) => sequence !== index + 1)) {
    throw new Error('artifact lineage contains a sequence gap or duplicate');
  }
  return {
    sequence: sequences.at(-1) ?? 0,
    artifactNames,
  };
}

function validateResult(registration, result) {
  const expectedId = registration.unsignedRegistration.registrationId;
  if (
    result.effect !== 'MARKET_REGISTERED'
    || result.status !== 'APPLIED'
    || result.receipt?.effect !== 'MARKET_REGISTERED'
    || result.receipt?.status !== 'APPLIED'
    || result.receipt?.requestId !== expectedId
  ) {
    throw new Error(`invalid terminal registration result for ${registration.marketId}`);
  }
}

function validateMarketReadback(registration, response) {
  const expected = registration.unsignedRegistration.market;
  if (stableCanonical(response?.market?.market) !== stableCanonical(expected)) {
    throw new Error(`market readback mismatch for ${registration.marketId}`);
  }
}

const evidenceBytes = readFileSync(evidencePath);
if (sha256(evidenceBytes) !== evidenceSha256) throw new Error('signed evidence hash mismatch');
const evidence = JSON.parse(evidenceBytes);
if (
  evidence.protocol !== 'layrs.direct-market-registration-evidence.v1'
  || evidence.registrations.length !== 5
  || evidence.registrations.some((item) => (
    item.unsignedRegistration.epochId !== epochId
    || item.unsignedRegistration.runtime !== 'layrs.direct-execution.v1'
    || item.unsignedRegistration.signature !== ''
    || !item.httpBody?.registration?.signature
    || item.kmsSignatureVerifiedAtCreation !== true
    || item.localSignatureVerification !== true
  ))
) {
  throw new Error('signed evidence contract mismatch');
}
const nowUnix = Math.floor(Date.now() / 1000);
if (evidence.signing.expiresAtUnix <= nowUnix + 900) {
  throw new Error('market-registration authorization has expired or has less than 15 minutes remaining');
}

if (mode === '--validate') {
  process.stdout.write(`${JSON.stringify({
    status: 'VALIDATED_NOT_SUBMITTED',
    evidenceSha256,
    registrationCount: evidence.registrations.length,
    expectedSequence: `${startingSequence}->${startingSequence + evidence.registrations.length}`,
    expiresAt: evidence.signing.expiresAt,
  }, null, 2)}\n`);
  process.exit(0);
}

const expectedAmiId = process.env.LAYRS_EXPECTED_AMI_ID;
const expectedGrantCommitment = process.env.LAYRS_EXPECTED_WRITER_GRANT_COMMITMENT;
if (!expectedAmiId || !expectedGrantCommitment) {
  throw new Error('LAYRS_EXPECTED_AMI_ID and LAYRS_EXPECTED_WRITER_GRANT_COMMITMENT are required');
}
const instanceId = locateRuntime(expectedAmiId);
const statusResult = httpViaSsm(instanceId, { path: '/v1/runtime/status' });
if (
  statusResult.status !== 200
  || statusResult.response.transactionModel !== 'layrs.direct-execution.v1'
  || statusResult.response.epochStateSha256 !== epochStateSha256
  || statusResult.response.evidenceManifestSha256 !== evidenceManifestSha256
  || statusResult.response.writerEnabled !== true
  || statusResult.response.admissionEnabled !== true
  || statusResult.response.writerGrantCommitment !== expectedGrantCommitment
  || statusResult.response.writerGrantExpiresAtUnix <= nowUnix + 900
) {
  throw new Error('runtime status does not match the governed production candidate');
}

const initialArchive = archiveSnapshot();
const readbacks = evidence.registrations.map((registration) => ({
  registration,
  readback: httpViaSsm(instanceId, {
    path: `/v1/operator/markets/${registration.marketId}`,
  }),
}));
if (readbacks.some(({ readback }) => readback.status !== 200)) {
  throw new Error('market-status endpoint is unavailable on the expected candidate');
}
const present = readbacks.map(({ readback }) => readback.response.market !== null);
const presentCount = present.filter(Boolean).length;
if (present.some((value, index) => value !== (index < presentCount))) {
  throw new Error('registered markets are not the expected serial prefix');
}
for (let index = 0; index < presentCount; index += 1) {
  validateMarketReadback(evidence.registrations[index], readbacks[index].readback.response);
}
if (initialArchive.sequence !== startingSequence + presentCount) {
  throw new Error('archive sequence does not match the exact registered-market prefix');
}

if (mode === '--preflight') {
  process.stdout.write(`${JSON.stringify({
    status: 'PREFLIGHT_VERIFIED_NOT_SUBMITTED',
    instanceId,
    expectedAmiId,
    writerGrantCommitment: expectedGrantCommitment,
    currentSequence: initialArchive.sequence,
    registeredPrefixCount: presentCount,
    remainingCount: evidence.registrations.length - presentCount,
    statusCommandId: statusResult.commandId,
  }, null, 2)}\n`);
  process.exit(0);
}

const submit = (registration) => {
  const posted = httpViaSsm(instanceId, {
    method: 'POST',
    path: '/v1/operator/markets',
    body: registration.httpBody,
  });
  if (posted.status !== 200) {
    throw new Error(`registration returned HTTP ${posted.status} for ${registration.marketId}`);
  }
  validateResult(registration, posted.response);
  return posted;
};

// Replaying an already-present prefix first repairs a projection write whose
// response was lost after the immutable private-state commit. Exact replay is
// handled before candidate creation and must not create another artifact.
for (let index = 0; index < presentCount; index += 1) {
  const before = archiveSnapshot();
  submit(evidence.registrations[index]);
  const after = archiveSnapshot();
  if (canonical(before) !== canonical(after)) throw new Error('prefix replay created an artifact');
}

const submitted = [];
for (let index = presentCount; index < evidence.registrations.length; index += 1) {
  const registration = evidence.registrations[index];
  const before = archiveSnapshot();
  const posted = submit(registration);
  const after = archiveSnapshot();
  if (
    after.sequence !== before.sequence + 1
    || after.artifactNames.length !== before.artifactNames.length + 1
  ) {
    throw new Error(`registration did not create exactly one successor for ${registration.marketId}`);
  }
  const readback = httpViaSsm(instanceId, {
    path: `/v1/operator/markets/${registration.marketId}`,
  });
  if (readback.status !== 200) throw new Error(`market readback failed for ${registration.marketId}`);
  validateMarketReadback(registration, readback.response);
  submitted.push({
    marketId: registration.marketId,
    requestId: registration.unsignedRegistration.registrationId,
    sequence: after.sequence,
    artifact: after.artifactNames.at(-1),
    submitCommandId: posted.commandId,
    readbackCommandId: readback.commandId,
  });
}

const beforeReplay = archiveSnapshot();
const replayCommandIds = [];
for (const registration of evidence.registrations) {
  replayCommandIds.push(submit(registration).commandId);
}
const afterReplay = archiveSnapshot();
if (canonical(beforeReplay) !== canonical(afterReplay)) {
  throw new Error('exact replay changed the immutable archive');
}
if (afterReplay.sequence !== startingSequence + evidence.registrations.length) {
  throw new Error('final sequence is not 10');
}

process.stdout.write(`${JSON.stringify({
  status: 'SUBMITTED_AND_EXACT_REPLAY_VERIFIED',
  instanceId,
  expectedAmiId,
  evidenceSha256,
  startingSequence,
  finalSequence: afterReplay.sequence,
  submitted,
  replayCommandIds,
  finalArtifactCount: afterReplay.artifactNames.length,
  projectionProof: 'Each HTTP 200 is emitted only after direct_execution_receipts and direct_execution_accounting_events record_result succeeds; independently query the five request IDs before release.',
}, null, 2)}\n`);
