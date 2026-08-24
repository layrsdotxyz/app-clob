#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { canonicalJson } from './render-seq159300-recovery-parent-evidence.mjs';

const ACCOUNT_ID = '082223548516';
const REGION = 'us-east-1';
const PROTOCOL = 'layrs.seq159300.recovery-parent-post-build-cleanup-evidence.v1';
const ACCEPTED_CLEANUP_IMPLEMENTATION_COMMIT = '23f92bc64171862abc410af953321a991e5e1515';
const ACCEPTED_CLEANUP_TEMPLATE_SHA384 = '72c5872db412726d8e56c0c078067bae19c8cf316bba204f0849a6ae34bc504792b12601f023f76efdf81b750a6aa77c';
const ACCEPTED_POSTBUILD_PUBLISHER_SHA384 = '329c3ad67e05dec6efff89d7ede7553e652b18d7a6727c95fc88e7766584037f6d1345210120448cccba7f56397e9361';
const ACCEPTED_FINALIZER_TEMPLATE_SHA384 = '2eeca9da6a30bc6aef84126d8e53b70723b8b00554aa65c9da982e3fd47f82eb694c00b05a26c598eed3d5b8d110b2c9';
const ACCEPTED_BOOTSTRAP_TEMPLATE_SHA384 = 'caae4fa5902593a3648f6755669f87e4b6b59cb3bbb027ed82991b51ff8727f02cbcfe6883e8ea7644bd57477c9a8620';

const FIELDS = Object.freeze([
  'accountId', 'cleanupImplementationCommit', 'cleanupIntentObjectKey',
  'cleanupIntentObjectVersionId', 'cleanupIntentSha384', 'cleanupReceiptObjectKey',
  'cleanupReceiptObjectVersionId', 'cleanupReceiptSha384',
  'cleanupExecutionRoleInventoryObjectKey', 'cleanupExecutionRoleInventoryObjectVersionId',
  'cleanupExecutionRoleInventorySha384',
  'cleanupSubmitterRoleInventoryObjectKey', 'cleanupSubmitterRoleInventoryObjectVersionId',
  'cleanupSubmitterRoleInventorySha384',
  'cleanupTemplateEvidenceObjectKey', 'cleanupTemplateEvidenceObjectVersionId',
  'cleanupTemplateEvidenceSha384', 'cleanupApprovedAt', 'cleanupExpiresAt',
  'cleanupSubmitterExternalId', 'cleanupSubmitterIdentity', 'cleanupSubmitterSession',
  'environment', 'exactAbsenceInventory',
  'exactAbsenceInventorySha384', 'parentBuildEvidenceObjectKey',
  'parentBuildEvidenceObjectVersionId', 'parentBuildEvidenceSha384', 'phase4Authorized',
  'finalizerApprovedAt', 'finalizerExpiresAt', 'finalizerSession', 'finalizerRoleInventoryObjectKey',
  'finalizerRoleInventoryObjectVersionId', 'finalizerRoleInventorySha384',
  'finalizerTemplateEvidenceObjectKey', 'finalizerTemplateEvidenceObjectVersionId',
  'finalizerTemplateEvidenceSha384',
  'postBuildEvidencePublisherTemplateObjectKey',
  'postBuildEvidencePublisherTemplateObjectVersionId',
  'postBuildEvidencePublisherTemplateSha384',
  'postBuildPublisherApprovedAt', 'postBuildPublisherExpiresAt',
  'postBuildPublisherRoleInventoryObjectKey',
  'postBuildPublisherRoleInventoryObjectVersionId', 'postBuildPublisherRoleInventorySha384',
  'postBuildPublisherRoleInventoryReadbackRequestId',
  'postBuildPublisherRoleInventoryReadbackVerifiedAt',
  'postBuildPublisherRoleInventoryUploadRequestId',
  'postBuildPublisherRoleInventoryUploadedAt',
  'productionDeployerIdentity', 'productionDeployerSession',
  'productionDeployerRoleInventoryObjectKey',
  'productionDeployerRoleInventoryObjectVersionId',
  'productionDeployerRoleInventorySha384',
  'productionDeployerTemplateEvidenceObjectKey',
  'productionDeployerTemplateEvidenceObjectVersionId',
  'productionDeployerTemplateEvidenceSha384',
  'preDeletePhysicalInventoryObjectKey', 'preDeletePhysicalInventoryObjectVersionId',
  'preDeletePhysicalInventorySha384', 'protocol', 'region', 'retainedAmiInventory',
  'retainedEvidenceInventory', 'retainedFinalizerStackInventoryObjectKey',
  'retainedFinalizerStackInventoryObjectVersionId', 'retainedFinalizerStackInventorySha384',
  'retainedSnapshotInventory', 'verifiedAt',
  'runnerIdentity', 'trustedPrincipalInventorySha384', 'verifierIdentity', 'verifierRoleInventorySha384',
]);

const REQUIRED_ABSENT_IDENTITIES = Object.freeze([
  ['iam-instance-profile', 'layrs-production-recovery-seq159300-builder-instance'],
  ...[
    'invoker', 'invoker-window-guard',
    'template-publisher', 'template-publisher-window-guard', 'cloudformation-execution',
    'builder-instance', 'window-guard', 'packer-control', 'cleanup-window-guard',
    'cleanup-execution', 'cleanup-submitter', 'post-build-evidence-publisher',
    'post-build-publisher-window-guard', 'finalizer-window-guard',
  ].map(name => ['iam-role', `layrs-production-recovery-seq159300-${name}`]),
  ...[
    'packer-inventory', 'packer-launch', 'packer-artifacts', 'cfn-core-network',
    'cfn-endpoints', 'cfn-mutation',
  ].map(name => ['iam-managed-policy', `arn:aws:iam::${ACCOUNT_ID}:policy/layrs-production-recovery-seq159300-${name}`]),
  ...['invoker-window-guard', 'template-publisher-window-guard', 'window-guard', 'cleanup-window-guard',
    'post-build-publisher-window-guard', 'finalizer-window-guard']
    .map(name => ['lambda-function', `arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:layrs-production-recovery-seq159300-${name}`]),
]);

const ABSENCE_CODES = Object.freeze(new Map([
  ['cloudformation-stack', new Set(['ValidationError'])],
  ['cloudformation-change-set', new Set(['ChangeSetNotFoundException'])],
  ['iam-role', new Set(['NoSuchEntityException'])],
  ['iam-instance-profile', new Set(['NoSuchEntityException'])],
  ['iam-managed-policy', new Set(['NoSuchEntityException'])],
  ['lambda-function', new Set(['ResourceNotFoundException'])],
  ['ec2-vpc', new Set(['InvalidVpcID.NotFound'])],
  ['ec2-subnet', new Set(['InvalidSubnetID.NotFound'])],
  ['ec2-route-table', new Set(['InvalidRouteTableID.NotFound'])],
  ['ec2-security-group', new Set(['InvalidGroup.NotFound'])],
  ['ec2-vpc-endpoint', new Set(['InvalidVpcEndpointId.NotFound'])],
  ['ec2-network-interface', new Set(['InvalidNetworkInterfaceID.NotFound'])],
  ['packer-temporary-key-pair', new Set(['InvalidKeyPair.NotFound'])],
  ['packer-temporary-instance', new Set(['InvalidInstanceID.NotFound'])],
]));

const REQUIRED_STACK_NAMES = Object.freeze([
  'layrs-production-recovery-seq159300-invoker',
  'layrs-production-recovery-seq159300-builder',
  'layrs-production-recovery-seq159300-template-publisher',
  'layrs-production-recovery-seq159300-builder-cleanup',
  'layrs-production-recovery-seq159300-post-build-evidence-publisher',
]);
const REQUIRED_STATIC_ABSENCE_KEYS = new Set(
  REQUIRED_ABSENT_IDENTITIES.map(([type, id]) => `${type}\0${id}`),
);

function exactFields(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} is not an object`);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} field set is invalid`);
  }
}

function sha384(value) {
  return typeof value === 'string' && /^[0-9a-f]{96}$/u.test(value);
}

function immutableKey(value) {
  return typeof value === 'string' && /^evidence\/seq159300\/recovery-only\/[A-Za-z0-9][A-Za-z0-9._/-]{0,900}$/u.test(value)
    && !value.includes('..');
}

function versionId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{8,256}$/u.test(value);
}

function exactUtcSeconds(value) {
  if (typeof value !== 'string' || !/^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u.test(value)) {
    return Number.NaN;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value.replace('Z', '.000Z')
    ? parsed : Number.NaN;
}

function structuredRequestId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._:/-]{8,256}$/u.test(value);
}

function sortedUnique(values, identity, label) {
  const identities = values.map(identity);
  if (new Set(identities).size !== identities.length
      || canonicalJson(values) !== canonicalJson([...values].sort((left, right) => identity(left).localeCompare(identity(right))))) {
    throw new Error(`${label} must be sorted and unique`);
  }
}

function validateObjectRef(input, prefix, label) {
  const key = input[`${prefix}ObjectKey`];
  const version = input[`${prefix}ObjectVersionId`];
  const hash = input[`${prefix}Sha384`];
  if (!immutableKey(key) || !versionId(version) || !sha384(hash)) {
    throw new Error(`${label} immutable reference is malformed`);
  }
  return `${key}\0${version}`;
}

function validateRetainedAmiInventory(values) {
  if (!Array.isArray(values) || values.length !== 1) throw new Error('exactly one retained recovery AMI is required');
  for (const value of values) {
    exactFields(value, ['amiId', 'outputAmiInventorySha384'], 'retained AMI inventory entry');
    if (!/^ami-[0-9a-f]{8,17}$/u.test(value.amiId) || !sha384(value.outputAmiInventorySha384)) {
      throw new Error('retained AMI inventory entry is malformed');
    }
  }
}

function validateRetainedSnapshotInventory(values) {
  if (!Array.isArray(values) || values.length < 1) throw new Error('retained recovery snapshot inventory is empty');
  for (const value of values) {
    exactFields(value, ['snapshotId', 'snapshotInventorySha384'], 'retained snapshot inventory entry');
    if (!/^snap-[0-9a-f]{8,17}$/u.test(value.snapshotId) || !sha384(value.snapshotInventorySha384)) {
      throw new Error('retained snapshot inventory entry is malformed');
    }
  }
  sortedUnique(values, value => value.snapshotId, 'retained snapshot inventory');
}

function validateRetainedEvidenceInventory(values, requiredRefs) {
  if (!Array.isArray(values) || values.length < requiredRefs.size) {
    throw new Error('retained immutable evidence inventory is incomplete');
  }
  for (const value of values) {
    exactFields(value, ['objectKey', 'objectVersionId', 'sha384'], 'retained evidence inventory entry');
    if (!immutableKey(value.objectKey) || !versionId(value.objectVersionId) || !sha384(value.sha384)) {
      throw new Error('retained evidence inventory entry is malformed');
    }
  }
  sortedUnique(values, value => `${value.objectKey}\0${value.objectVersionId}`, 'retained evidence inventory');
  const actual = new Set(values.map(value => `${value.objectKey}\0${value.objectVersionId}\0${value.sha384}`));
  if ([...requiredRefs].some(value => !actual.has(value))) {
    throw new Error('retained evidence inventory omits a required cleanup binding');
  }
}

function validateAbsenceInventory(values, expectedSha384) {
  if (!Array.isArray(values) || values.length < REQUIRED_ABSENT_IDENTITIES.length) {
    throw new Error('exact absence inventory is incomplete');
  }
  for (const value of values) {
    exactFields(value, ['requestId', 'resourceId', 'resourceType', 'serviceErrorCode'], 'absence inventory record');
    const codes = ABSENCE_CODES.get(value.resourceType);
    if (!codes?.has(value.serviceErrorCode)
        || typeof value.resourceId !== 'string' || value.resourceId.length < 3 || value.resourceId.length > 512
        || typeof value.requestId !== 'string' || !/^[A-Za-z0-9._:/-]{8,256}$/u.test(value.requestId)) {
      throw new Error('absence inventory record is malformed or uses an unapproved not-found code');
    }
    const identityPatterns = {
      'cloudformation-stack': /^arn:aws:cloudformation:us-east-1:082223548516:stack\/layrs-production-recovery-seq159300-(?:invoker|builder|template-publisher|builder-cleanup|post-build-evidence-publisher)\/[0-9a-f-]{36}$/u,
      'cloudformation-change-set': /^arn:aws:cloudformation:us-east-1:082223548516:changeSet\/layrs-seq159300-builder-[0-9a-f]{12}\/[0-9a-f-]{36}$/u,
      'ec2-vpc': /^vpc-[0-9a-f]{8,17}$/u,
      'ec2-subnet': /^subnet-[0-9a-f]{8,17}$/u,
      'ec2-route-table': /^rtb-[0-9a-f]{8,17}$/u,
      'ec2-security-group': /^sg-[0-9a-f]{8,17}$/u,
      'ec2-vpc-endpoint': /^vpce-[0-9a-f]{8,17}$/u,
      'ec2-network-interface': /^eni-[0-9a-f]{8,17}$/u,
      'packer-temporary-key-pair': /^layrs-seq159300-recovery-[A-Za-z0-9._-]{8,128}$/u,
      'packer-temporary-instance': /^i-[0-9a-f]{8,17}$/u,
    };
    if (identityPatterns[value.resourceType] && !identityPatterns[value.resourceType].test(value.resourceId)) {
      throw new Error('absence inventory resource identity is malformed');
    }
    if (['iam-role', 'iam-instance-profile', 'iam-managed-policy', 'lambda-function'].includes(value.resourceType)
        && !REQUIRED_STATIC_ABSENCE_KEYS.has(`${value.resourceType}\0${value.resourceId}`)) {
      throw new Error('absence inventory contains an unreviewed authority identity');
    }
  }
  sortedUnique(values, value => `${value.resourceType}\0${value.resourceId}`, 'exact absence inventory');
  if (new Set(values.map(value => value.requestId)).size !== values.length) {
    throw new Error('exact absence inventory request IDs must be unique');
  }
  const identities = new Set(values.map(value => `${value.resourceType}\0${value.resourceId}`));
  if (REQUIRED_ABSENT_IDENTITIES.some(([type, id]) => !identities.has(`${type}\0${id}`))) {
    throw new Error('exact absence inventory omits a named recovery resource');
  }
  for (const stackName of REQUIRED_STACK_NAMES) {
    if (!values.some(value => value.resourceType === 'cloudformation-stack'
        && value.resourceId.startsWith(`arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/${stackName}/`))) {
      throw new Error(`exact absence inventory omits stack ID ${stackName}`);
    }
  }
  for (const type of [
    'cloudformation-change-set', 'ec2-vpc', 'ec2-subnet', 'ec2-route-table',
    'ec2-security-group', 'ec2-vpc-endpoint', 'ec2-network-interface',
    'packer-temporary-key-pair', 'packer-temporary-instance',
  ]) if (!values.some(value => value.resourceType === type)) {
    throw new Error(`exact absence inventory omits ${type}`);
  }
  const computed = createHash('sha384').update(canonicalJson(values)).digest('hex');
  if (computed !== expectedSha384) throw new Error('exact absence inventory aggregate SHA384 is invalid');
}

export function renderRecoveryParentPostBuildCleanupEvidence(input) {
  exactFields(input, FIELDS, 'post-build cleanup evidence');
  const finalizerApprovedAt = exactUtcSeconds(input.finalizerApprovedAt);
  const finalizerExpiresAt = exactUtcSeconds(input.finalizerExpiresAt);
  const cleanupApprovedAt = exactUtcSeconds(input.cleanupApprovedAt);
  const cleanupExpiresAt = exactUtcSeconds(input.cleanupExpiresAt);
  const postBuildPublisherApprovedAt = exactUtcSeconds(input.postBuildPublisherApprovedAt);
  const postBuildPublisherExpiresAt = exactUtcSeconds(input.postBuildPublisherExpiresAt);
  const postBuildPublisherInventoryUploadedAt = exactUtcSeconds(
    input.postBuildPublisherRoleInventoryUploadedAt,
  );
  const postBuildPublisherInventoryReadbackAt = exactUtcSeconds(
    input.postBuildPublisherRoleInventoryReadbackVerifiedAt,
  );
  const verifiedAt = exactUtcSeconds(input.verifiedAt);
  exactFields(input.cleanupSubmitterSession, ['durationSeconds', 'expiresAt', 'issuedAt'], 'cleanup submitter session');
  exactFields(input.finalizerSession, ['durationSeconds', 'expiresAt', 'issuedAt'], 'finalizer session');
  exactFields(input.productionDeployerSession, ['durationSeconds', 'expiresAt', 'issuedAt'], 'production deployer session');
  exactFields(input.cleanupSubmitterIdentity, ['accountId', 'arn', 'principalId'], 'cleanup submitter identity');
  exactFields(input.productionDeployerIdentity, ['accountId', 'arn', 'principalId'], 'production deployer identity');
  exactFields(input.runnerIdentity, ['accountId', 'arn', 'principalId'], 'runner identity');
  const cleanupSessionIssuedAt = exactUtcSeconds(input.cleanupSubmitterSession.issuedAt);
  const cleanupSessionExpiresAt = exactUtcSeconds(input.cleanupSubmitterSession.expiresAt);
  const finalizerSessionIssuedAt = exactUtcSeconds(input.finalizerSession.issuedAt);
  const finalizerSessionExpiresAt = exactUtcSeconds(input.finalizerSession.expiresAt);
  const deployerSessionIssuedAt = exactUtcSeconds(input.productionDeployerSession.issuedAt);
  const deployerSessionExpiresAt = exactUtcSeconds(input.productionDeployerSession.expiresAt);
  if (input.protocol !== PROTOCOL || input.accountId !== ACCOUNT_ID || input.region !== REGION
      || input.environment !== 'production' || input.phase4Authorized !== false
      || input.cleanupImplementationCommit !== ACCEPTED_CLEANUP_IMPLEMENTATION_COMMIT
      || !sha384(input.cleanupSubmitterExternalId)
      || input.cleanupSubmitterExternalId === input.cleanupIntentSha384
      || !sha384(input.cleanupExecutionRoleInventorySha384)
      || !sha384(input.cleanupSubmitterRoleInventorySha384)
      || !structuredRequestId(input.postBuildPublisherRoleInventoryUploadRequestId)
      || !structuredRequestId(input.postBuildPublisherRoleInventoryReadbackRequestId)
      || input.postBuildPublisherRoleInventoryUploadRequestId
        === input.postBuildPublisherRoleInventoryReadbackRequestId
      || !Number.isFinite(postBuildPublisherInventoryUploadedAt)
      || !Number.isFinite(postBuildPublisherInventoryReadbackAt)
      || postBuildPublisherInventoryUploadedAt < finalizerSessionIssuedAt
      || postBuildPublisherInventoryUploadedAt > postBuildPublisherInventoryReadbackAt
      || postBuildPublisherInventoryReadbackAt >= finalizerSessionExpiresAt
      || postBuildPublisherInventoryReadbackAt > verifiedAt
      || new Set([
        input.cleanupExecutionRoleInventorySha384, input.cleanupSubmitterRoleInventorySha384,
        input.finalizerRoleInventorySha384, input.productionDeployerRoleInventorySha384,
        input.postBuildPublisherRoleInventorySha384, input.trustedPrincipalInventorySha384,
      ]).size !== 6
      || !Number.isFinite(verifiedAt) || !sha384(input.verifierRoleInventorySha384)
      || !sha384(input.finalizerRoleInventorySha384)
      || !sha384(input.trustedPrincipalInventorySha384)
      || !sha384(input.productionDeployerRoleInventorySha384)
      || input.verifierRoleInventorySha384 !== input.finalizerRoleInventorySha384
      || input.finalizerRoleInventorySha384 === input.trustedPrincipalInventorySha384
      || input.productionDeployerRoleInventorySha384 === input.finalizerRoleInventorySha384
      || input.productionDeployerRoleInventorySha384 === input.trustedPrincipalInventorySha384
      || !Number.isFinite(finalizerApprovedAt) || !Number.isFinite(finalizerExpiresAt)
      || finalizerApprovedAt > verifiedAt || verifiedAt >= finalizerExpiresAt
      || finalizerExpiresAt - finalizerApprovedAt > 3_600_000
      || !Number.isFinite(cleanupApprovedAt) || !Number.isFinite(cleanupExpiresAt)
      || !Number.isFinite(cleanupSessionIssuedAt) || !Number.isFinite(cleanupSessionExpiresAt)
      || !Number.isFinite(finalizerSessionIssuedAt) || !Number.isFinite(finalizerSessionExpiresAt)
      || cleanupApprovedAt > cleanupSessionIssuedAt || cleanupSessionIssuedAt > verifiedAt
      || verifiedAt >= cleanupSessionExpiresAt || cleanupSessionExpiresAt > cleanupExpiresAt
      || !Number.isSafeInteger(input.cleanupSubmitterSession.durationSeconds)
      || input.cleanupSubmitterSession.durationSeconds < 900
      || input.cleanupSubmitterSession.durationSeconds > 3_600
      || cleanupSessionExpiresAt - cleanupSessionIssuedAt !== input.cleanupSubmitterSession.durationSeconds * 1000
      || cleanupExpiresAt - cleanupApprovedAt > 3_600_000
      || finalizerApprovedAt > finalizerSessionIssuedAt || finalizerSessionIssuedAt > verifiedAt
      || verifiedAt >= finalizerSessionExpiresAt || finalizerSessionExpiresAt > finalizerExpiresAt
      || !Number.isSafeInteger(input.finalizerSession.durationSeconds)
      || input.finalizerSession.durationSeconds < 900 || input.finalizerSession.durationSeconds > 3_600
      || finalizerSessionExpiresAt - finalizerSessionIssuedAt !== input.finalizerSession.durationSeconds * 1000
      || !Number.isFinite(postBuildPublisherApprovedAt) || !Number.isFinite(postBuildPublisherExpiresAt)
      || postBuildPublisherApprovedAt > verifiedAt
      || postBuildPublisherApprovedAt >= postBuildPublisherExpiresAt
      || postBuildPublisherExpiresAt - postBuildPublisherApprovedAt > 3_600_000
      || !Number.isFinite(deployerSessionIssuedAt) || !Number.isFinite(deployerSessionExpiresAt)
      || !Number.isSafeInteger(input.productionDeployerSession.durationSeconds)
      || input.productionDeployerSession.durationSeconds < 900
      || input.productionDeployerSession.durationSeconds > 3_600
      || deployerSessionExpiresAt - deployerSessionIssuedAt
        !== input.productionDeployerSession.durationSeconds * 1000
      || deployerSessionIssuedAt > cleanupSessionIssuedAt
      || deployerSessionIssuedAt > finalizerSessionIssuedAt
      || cleanupSessionExpiresAt > deployerSessionExpiresAt
      || finalizerSessionExpiresAt > deployerSessionExpiresAt) {
    throw new Error('post-build cleanup evidence identity or Phase4 boundary is invalid');
  }
  exactFields(input.verifierIdentity, ['accountId', 'arn', 'principalId'], 'cleanup verifier identity');
  const submitterArnMatch = /^arn:aws:sts::082223548516:assumed-role\/layrs-production-recovery-seq159300-cleanup-submitter\/([A-Za-z0-9+=,.@_-]{1,64})$/u
    .exec(input.cleanupSubmitterIdentity.arn ?? '');
  if (input.cleanupSubmitterIdentity.accountId !== ACCOUNT_ID
      || !submitterArnMatch
      || typeof input.cleanupSubmitterIdentity.principalId !== 'string'
      || !new RegExp(`^ARO[A-Z0-9]{16,}:${submitterArnMatch?.[1] ?? 'INVALID'}$`, 'u')
        .test(input.cleanupSubmitterIdentity.principalId)) {
    throw new Error('cleanup submitter identity is outside the exact recovery role');
  }
  const deployerArnMatch = /^arn:aws:sts::082223548516:assumed-role\/layrs-production-deployer\/([A-Za-z0-9+=,.@_-]{1,64})$/u
    .exec(input.productionDeployerIdentity.arn ?? '');
  if (input.productionDeployerIdentity.accountId !== ACCOUNT_ID
      || !deployerArnMatch || typeof input.productionDeployerIdentity.principalId !== 'string'
      || !new RegExp(`^ARO[A-Z0-9]{16,}:${deployerArnMatch?.[1] ?? 'INVALID'}$`, 'u')
        .test(input.productionDeployerIdentity.principalId)) {
    throw new Error('production deployer identity is outside the exact role');
  }
  const runnerArnMatch = /^arn:aws:sts::082223548516:assumed-role\/layrs-gitlab-runner-RunnerRole-1LXmWXGdTn9z\/([A-Za-z0-9+=,.@_-]{1,64})$/u
    .exec(input.runnerIdentity.arn ?? '');
  if (input.runnerIdentity.accountId !== ACCOUNT_ID
      || !runnerArnMatch || typeof input.runnerIdentity.principalId !== 'string'
      || !new RegExp(`^ARO[A-Z0-9]{16,}:${runnerArnMatch?.[1] ?? 'INVALID'}$`, 'u')
        .test(input.runnerIdentity.principalId)) {
    throw new Error('runner identity is outside the exact GitLab role');
  }
  const verifierArnMatch = /^arn:aws:sts::082223548516:assumed-role\/layrs-production-recovery-seq159300-finalizer\/([A-Za-z0-9+=,.@_-]{1,64})$/u
    .exec(input.verifierIdentity.arn ?? '');
  if (input.verifierIdentity.accountId !== ACCOUNT_ID
      || !verifierArnMatch
      || typeof input.verifierIdentity.principalId !== 'string'
      || !new RegExp(`^ARO[A-Z0-9]{16,}:${verifierArnMatch?.[1] ?? 'INVALID'}$`, 'u')
        .test(input.verifierIdentity.principalId)) {
    throw new Error('cleanup verifier identity is outside the exact recovery role');
  }

  const immutableRefs = new Set([
    validateObjectRef(input, 'parentBuildEvidence', 'parent build evidence'),
    validateObjectRef(input, 'cleanupTemplateEvidence', 'cleanup template evidence'),
    validateObjectRef(input, 'cleanupReceipt', 'cleanup receipt'),
    validateObjectRef(input, 'cleanupExecutionRoleInventory', 'cleanup execution role inventory'),
    validateObjectRef(input, 'cleanupSubmitterRoleInventory', 'cleanup submitter role inventory'),
    validateObjectRef(input, 'postBuildPublisherRoleInventory', 'post-build publisher role inventory'),
    validateObjectRef(input, 'preDeletePhysicalInventory', 'pre-delete physical inventory'),
    validateObjectRef(input, 'cleanupIntent', 'cleanup intent'),
    validateObjectRef(input, 'postBuildEvidencePublisherTemplate', 'post-build evidence publisher template'),
    validateObjectRef(input, 'finalizerTemplateEvidence', 'finalizer template evidence'),
    validateObjectRef(input, 'finalizerRoleInventory', 'finalizer role inventory'),
    validateObjectRef(input, 'productionDeployerTemplateEvidence', 'production deployer template evidence'),
    validateObjectRef(input, 'productionDeployerRoleInventory', 'production deployer role inventory'),
    validateObjectRef(input, 'retainedFinalizerStackInventory', 'retained finalizer stack inventory'),
  ]);
  if (immutableRefs.size !== 14
      || !input.parentBuildEvidenceObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/parent-build/')
      || input.cleanupTemplateEvidenceSha384 !== ACCEPTED_CLEANUP_TEMPLATE_SHA384
      || !input.cleanupTemplateEvidenceObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/builder/cleanup/templates/')
      || !input.cleanupReceiptObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/builder/cleanup/receipts/')
      || !input.preDeletePhysicalInventoryObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/builder/cleanup/inventory/')
      || !input.cleanupIntentObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/builder/cleanup/intents/')) {
    throw new Error('post-build cleanup immutable references are not exact and unique');
  }
  if (input.postBuildEvidencePublisherTemplateSha384 !== ACCEPTED_POSTBUILD_PUBLISHER_SHA384
      || input.postBuildEvidencePublisherTemplateObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/publisher/templates/layrs-seq159300-recovery-post-build-evidence-publisher-${input.postBuildEvidencePublisherTemplateSha384}.yml`) {
    throw new Error('post-build evidence publisher template binding is invalid');
  }
  if (input.postBuildPublisherRoleInventoryObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/post-build-evidence-publisher/inventory/${input.cleanupImplementationCommit}-${input.cleanupIntentSha384}.json`) {
    throw new Error('post-build publisher role inventory immutable binding is invalid');
  }
  if (input.cleanupExecutionRoleInventoryObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-execution/inventory/${input.cleanupImplementationCommit}-${input.cleanupIntentSha384}.json`
      || input.cleanupSubmitterRoleInventoryObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-submitter/inventory/${input.cleanupImplementationCommit}-${input.cleanupIntentSha384}.json`) {
    throw new Error('cleanup role inventory immutable bindings are invalid');
  }
  if (input.cleanupReceiptObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/receipts/${input.cleanupImplementationCommit}-${input.cleanupIntentSha384}.json`) {
    throw new Error('cleanup receipt stable immutable binding is invalid');
  }
  if (input.finalizerTemplateEvidenceSha384 !== ACCEPTED_FINALIZER_TEMPLATE_SHA384
      || input.finalizerTemplateEvidenceObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/templates/layrs-seq159300-recovery-finalizer-${input.finalizerTemplateEvidenceSha384}.yml`) {
    throw new Error('finalizer template immutable binding is invalid');
  }
  if (input.finalizerRoleInventoryObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/inventory/${input.cleanupImplementationCommit}-${input.cleanupIntentSha384}.json`) {
    throw new Error('finalizer role inventory immutable binding is invalid');
  }
  if (input.productionDeployerTemplateEvidenceSha384 !== ACCEPTED_BOOTSTRAP_TEMPLATE_SHA384
      || input.productionDeployerTemplateEvidenceObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/deployer/templates/layrs-predifi-root-bootstrap-${input.productionDeployerTemplateEvidenceSha384}.yml`) {
    throw new Error('production deployer template immutable binding is invalid');
  }
  if (input.productionDeployerRoleInventoryObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/deployer/inventory/${input.cleanupImplementationCommit}-${input.cleanupIntentSha384}.json`) {
    throw new Error('production deployer role inventory immutable binding is invalid');
  }
  if (input.retainedFinalizerStackInventoryObjectKey
      !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/stack-inventory/${input.cleanupImplementationCommit}-${input.cleanupIntentSha384}.json`) {
    throw new Error('retained finalizer stack inventory immutable binding is invalid');
  }

  validateRetainedAmiInventory(input.retainedAmiInventory);
  validateRetainedSnapshotInventory(input.retainedSnapshotInventory);
  validateRetainedEvidenceInventory(input.retainedEvidenceInventory, new Set([
    `${input.parentBuildEvidenceObjectKey}\0${input.parentBuildEvidenceObjectVersionId}\0${input.parentBuildEvidenceSha384}`,
    `${input.cleanupTemplateEvidenceObjectKey}\0${input.cleanupTemplateEvidenceObjectVersionId}\0${input.cleanupTemplateEvidenceSha384}`,
    `${input.cleanupReceiptObjectKey}\0${input.cleanupReceiptObjectVersionId}\0${input.cleanupReceiptSha384}`,
    `${input.preDeletePhysicalInventoryObjectKey}\0${input.preDeletePhysicalInventoryObjectVersionId}\0${input.preDeletePhysicalInventorySha384}`,
    `${input.cleanupIntentObjectKey}\0${input.cleanupIntentObjectVersionId}\0${input.cleanupIntentSha384}`,
    `${input.postBuildEvidencePublisherTemplateObjectKey}\0${input.postBuildEvidencePublisherTemplateObjectVersionId}\0${input.postBuildEvidencePublisherTemplateSha384}`,
    `${input.finalizerTemplateEvidenceObjectKey}\0${input.finalizerTemplateEvidenceObjectVersionId}\0${input.finalizerTemplateEvidenceSha384}`,
    `${input.finalizerRoleInventoryObjectKey}\0${input.finalizerRoleInventoryObjectVersionId}\0${input.finalizerRoleInventorySha384}`,
    `${input.productionDeployerTemplateEvidenceObjectKey}\0${input.productionDeployerTemplateEvidenceObjectVersionId}\0${input.productionDeployerTemplateEvidenceSha384}`,
    `${input.productionDeployerRoleInventoryObjectKey}\0${input.productionDeployerRoleInventoryObjectVersionId}\0${input.productionDeployerRoleInventorySha384}`,
    `${input.retainedFinalizerStackInventoryObjectKey}\0${input.retainedFinalizerStackInventoryObjectVersionId}\0${input.retainedFinalizerStackInventorySha384}`,
  ]));
  if (!sha384(input.exactAbsenceInventorySha384)) throw new Error('absence inventory SHA384 is malformed');
  validateAbsenceInventory(input.exactAbsenceInventory, input.exactAbsenceInventorySha384);
  const publicationAndAbsenceRequestIds = [
    input.postBuildPublisherRoleInventoryUploadRequestId,
    input.postBuildPublisherRoleInventoryReadbackRequestId,
    ...input.exactAbsenceInventory.map(value => value.requestId),
  ];
  if (new Set(publicationAndAbsenceRequestIds).size
      !== publicationAndAbsenceRequestIds.length) {
    throw new Error('publisher inventory publication request IDs are not unique across structured absence evidence');
  }
  return Buffer.from(canonicalJson(input));
}

function cliArguments() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--input' || args[2] !== '--output' || !args[1] || !args[3]) {
    throw new Error('use exactly --input <path> --output <path>');
  }
  return { input: args[1], output: args[3] };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const paths = cliArguments();
  const input = JSON.parse(readFileSync(paths.input, 'utf8'));
  writeFileSync(paths.output, renderRecoveryParentPostBuildCleanupEvidence(input), { flag: 'wx', mode: 0o600 });
}
