#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const ACCOUNT_ID = '082223548516';
const REGION = 'us-east-1';
const SOURCE_COMMIT = 'f282583cae7a5c873a26aa8d0c1bec10c490eb8e';
const REMEDIATION_COMMIT = '540fc566c83dee2c3226862cc71a95541bc69af7';
const REMEDIATION_INDEX_VERSION = 'oBGf0odkWa6tzYpml_UtGemDwXI6GdXy';
const PARENT_SHA384 = 'd9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1';
const EIF_SHA384 = '958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290';
const PCR0_SHA384 = '57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac';
const ACCEPTED_PHASE2_TEMPLATE_COMMIT = '23f92bc64171862abc410af953321a991e5e1515';
const ACCEPTED_BUILDER_TEMPLATE_SHA384 = '75e536d6d138b88aaf7ef29fece2f67f3e6ffbda02841092de73726795b4d55a6fe01af492d8d8d1f0d3dc7f8db105d7';
const ACCEPTED_INVOKER_TEMPLATE_SHA384 = 'd67e4f78be6bd679b4ab61e316215fce24035e89508baaefcf3b2df6209682fd94dc0fcd84bac1530664f02aaf7723e1';
const ACCEPTED_TEMPLATE_PUBLISHER_SHA384 = '6eefb0154b78e08949ffb677a5179782cd17ab3f9a2f3d68ddf65789ce085b73aa9f76ad13821aff06fe9d853153d529';
const ACCEPTED_CLEANUP_TEMPLATE_SHA384 = '72c5872db412726d8e56c0c078067bae19c8cf316bba204f0849a6ae34bc504792b12601f023f76efdf81b750a6aa77c';

const FIELDS = Object.freeze([
  'accountId', 'amiId', 'buildCompletedAt', 'builderEvidenceIndexObjectKey',
  'builderEvidenceIndexObjectVersionId', 'builderEvidenceIndexSha384',
  'builderTemplateEvidenceObjectKey', 'builderTemplateEvidenceObjectVersionId',
  'builderTemplateEvidenceSha384', 'builderTemplateSha384', 'buildControlPlaneRoleInventorySha384',
  'buildInstanceProfileInventorySha384', 'buildSecurityGroupInventorySha384',
  'buildSubnetInventorySha384', 'changeSetReceiptObjectKey',
  'changeSetReceiptObjectVersionId', 'changeSetReceiptSha384',
  'cleanupExecutionRoleInventoryObjectKey', 'cleanupExecutionRoleInventoryObjectVersionId',
  'cleanupExecutionRoleInventorySha384', 'cleanupSubmitterRoleInventoryObjectKey',
  'cleanupSubmitterRoleInventoryObjectVersionId', 'cleanupSubmitterRoleInventorySha384',
  'cleanupTemplateEvidenceObjectKey', 'cleanupTemplateEvidenceObjectVersionId',
  'cleanupTemplateEvidenceSha384', 'cleanupTemplateSha384',
  'cloudFormationExecutionRoleInventoryObjectKey',
  'cloudFormationExecutionRoleInventoryObjectVersionId',
  'cloudFormationExecutionRoleInventorySha384', 'eifSha384', 'environment', 'implementationCommit',
  'implementationEvidenceObjectKey', 'implementationEvidenceObjectVersionId',
  'implementationEvidenceObjectSha384', 'nitroCliNevra', 'nitroCliRpmObjectKey',
  'nitroCliRpmObjectVersionId', 'nitroCliRpmSha384', 'nitroPackageInventorySha384',
  'nitroPackageSetEvidenceObjectKey', 'nitroPackageSetEvidenceSha384',
  'nitroPackageSetEvidenceObjectVersionId', 'nitroPackageSetObjectKey',
  'nitroPackageSetSha384', 'nitroPackageSetObjectVersionId',
  'nitroPackageClosureSha384',
  'outputAmiInventorySha384', 'packerManifestSha384', 'packerTemplateSha384',
  'packerAmazonPluginSourceCommit', 'packerAmazonPluginVersion',
  'packerControlArtifactPolicySha384', 'packerControlInventoryPolicySha384',
  'packerControlLaunchPolicySha384', 'packerControlPlaneApprovedAt',
  'packerControlPlaneExpiresAt',
  'packerInvokerEvidenceObjectKey', 'packerInvokerEvidenceObjectVersionId',
  'packerInvokerEvidenceSha384', 'packerInvokerRoleInventorySha384',
  'packerInvokerTemplateSha384',
  'packerToolchainManifestSha256',
  'parentBinarySha384', 'parentBuildEvidenceRendererSha384', 'parentBuildWrapperSha384',
  'parentPackageCommit', 'parentPostBuildCleanupEvidenceRendererSha384',
  'parentPreflightSha384', 'parentRunbookSha384', 'pcr0Sha384', 'phase2EvidenceObjectKey',
  'phase2EvidenceObjectVersionId', 'phase2EvidenceObjectSha384', 'phase2TemplateCommit',
  'phase2TemplateSha384', 'protocol', 'region',
  'remediationEvidenceCommit', 'remediationIndexObjectVersionId', 'sourceCommit',
  'sourceAmiId', 'sourceAmiOwner', 'sourceAmiProvenanceSha384',
  'templatePublisherRoleInventoryObjectKey',
  'templatePublisherRoleInventoryObjectVersionId', 'templatePublisherRoleInventorySha384',
  'publisherTemplateEvidenceObjectKey',
  'publisherTemplateEvidenceObjectVersionId', 'publisherTemplateEvidenceSha384',
  'publisherTemplateSha384', 'templateUploadReceiptObjectKey',
  'templateUploadReceiptObjectVersionId', 'templateUploadReceiptSha384',
  'templatePublisherApprovedAt', 'templatePublisherExpiresAt',
  'trustedPrincipalInventorySha384', 'invokerApprovedAt', 'invokerExpiresAt',
]);

function exactUtcSeconds(value) {
  if (typeof value !== 'string' || !/^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u.test(value)) {
    return Number.NaN;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value.replace('Z', '.000Z')
    ? parsed : Number.NaN;
}

function immutableObjectKey(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/u.test(value)
    && !value.includes('..');
}

function immutableVersionId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{8,256}$/u.test(value);
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('canonical JSON numbers must be safe integers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error('unsupported canonical JSON value');
}

export function renderRecoveryParentBuildEvidence(input) {
  exactFields(input, FIELDS, 'recovery parent build evidence');
  const completedAt = exactUtcSeconds(input.buildCompletedAt);
  const authorityWindows = [
    [input.packerControlPlaneApprovedAt, input.packerControlPlaneExpiresAt],
    [input.invokerApprovedAt, input.invokerExpiresAt],
    [input.templatePublisherApprovedAt, input.templatePublisherExpiresAt],
  ].map(([approvedAt, expiresAt]) => [exactUtcSeconds(approvedAt), exactUtcSeconds(expiresAt)]);
  if (input.protocol !== 'layrs.seq159300.recovery-parent-build-evidence.v1'
      || input.accountId !== ACCOUNT_ID || input.region !== REGION
      || input.environment !== 'production' || input.sourceCommit !== SOURCE_COMMIT
      || !/^[0-9a-f]{40}$/u.test(input.parentPackageCommit)
      || input.parentPackageCommit === SOURCE_COMMIT
      || !/^[0-9a-f]{40}$/u.test(input.implementationCommit)
      || input.phase2TemplateCommit !== ACCEPTED_PHASE2_TEMPLATE_COMMIT
      || input.remediationEvidenceCommit !== REMEDIATION_COMMIT
      || input.remediationIndexObjectVersionId !== REMEDIATION_INDEX_VERSION
      || input.parentBinarySha384 !== PARENT_SHA384 || input.eifSha384 !== EIF_SHA384
      || input.pcr0Sha384 !== PCR0_SHA384 || !/^ami-[0-9a-f]{8,17}$/u.test(input.amiId)
      || input.sourceAmiId !== 'ami-0332d564d76dbd8d6'
      || input.sourceAmiOwner !== '137112412989'
      || input.packerAmazonPluginVersion !== '1.3.9'
      || input.packerAmazonPluginSourceCommit !== '2a769c39a05940e25143098f071490732fa24f4f'
      || input.packerToolchainManifestSha256 !== '6a6d597535481836605a4cc9762755038e56e524af621356e5f5f65519c6858e'
      || !/^[0-9a-f]{96}$/u.test(input.parentBuildWrapperSha384)
      || !/^[0-9a-f]{96}$/u.test(input.parentPreflightSha384)
      || !/^[0-9a-f]{96}$/u.test(input.parentBuildEvidenceRendererSha384)
      || !/^[0-9a-f]{96}$/u.test(input.parentPostBuildCleanupEvidenceRendererSha384)
      || !/^[0-9a-f]{96}$/u.test(input.parentRunbookSha384)
      || input.builderTemplateSha384 !== ACCEPTED_BUILDER_TEMPLATE_SHA384
      || input.builderTemplateEvidenceSha384 !== ACCEPTED_BUILDER_TEMPLATE_SHA384
      || input.packerInvokerTemplateSha384 !== ACCEPTED_INVOKER_TEMPLATE_SHA384
      || input.packerInvokerEvidenceSha384 !== ACCEPTED_INVOKER_TEMPLATE_SHA384
      || input.publisherTemplateSha384 !== ACCEPTED_TEMPLATE_PUBLISHER_SHA384
      || input.publisherTemplateEvidenceSha384 !== ACCEPTED_TEMPLATE_PUBLISHER_SHA384
      || input.cleanupTemplateSha384 !== ACCEPTED_CLEANUP_TEMPLATE_SHA384
      || input.cleanupTemplateEvidenceSha384 !== ACCEPTED_CLEANUP_TEMPLATE_SHA384
      || input.templatePublisherRoleInventorySha384
        === input.cloudFormationExecutionRoleInventorySha384
      || new Set([
        input.templatePublisherRoleInventorySha384,
        input.cloudFormationExecutionRoleInventorySha384,
        input.cleanupExecutionRoleInventorySha384, input.cleanupSubmitterRoleInventorySha384,
        input.trustedPrincipalInventorySha384,
      ]).size !== 5
      || !/^aws-nitro-enclaves-cli-[0-9]+:?[A-Za-z0-9._+~]+-[A-Za-z0-9._+~]+\.x86_64$/u.test(input.nitroCliNevra)
      || !immutableObjectKey(input.phase2EvidenceObjectKey)
      || !immutableObjectKey(input.implementationEvidenceObjectKey)
      || !immutableObjectKey(input.builderTemplateEvidenceObjectKey)
      || !immutableObjectKey(input.packerInvokerEvidenceObjectKey)
      || !immutableObjectKey(input.builderEvidenceIndexObjectKey)
      || !immutableObjectKey(input.publisherTemplateEvidenceObjectKey)
      || !immutableObjectKey(input.templateUploadReceiptObjectKey)
      || !immutableObjectKey(input.changeSetReceiptObjectKey)
      || !immutableObjectKey(input.cleanupTemplateEvidenceObjectKey)
      || !immutableObjectKey(input.cleanupExecutionRoleInventoryObjectKey)
      || !immutableObjectKey(input.cleanupSubmitterRoleInventoryObjectKey)
      || !immutableObjectKey(input.templatePublisherRoleInventoryObjectKey)
      || !immutableObjectKey(input.cloudFormationExecutionRoleInventoryObjectKey)
      || !immutableObjectKey(input.nitroCliRpmObjectKey)
      || !immutableObjectKey(input.nitroPackageSetObjectKey)
      || !immutableObjectKey(input.nitroPackageSetEvidenceObjectKey)
      || !input.nitroCliRpmObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/')
      || !input.nitroPackageSetObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/')
      || !input.nitroPackageSetEvidenceObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/')
      || !input.phase2EvidenceObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/')
      || !input.implementationEvidenceObjectKey.startsWith('evidence/seq159300/recovery-only/implementation/')
      || input.builderTemplateEvidenceObjectKey
        !== `evidence/seq159300/recovery-only/phase2/builder/templates/layrs-seq159300-recovery-builder-${input.builderTemplateSha384}.yml`
      || !input.packerInvokerEvidenceObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/invoker/')
      || !input.builderEvidenceIndexObjectKey.startsWith('evidence/seq159300/recovery-only/phase2/builder/')
      || !input.publisherTemplateEvidenceObjectKey
        .startsWith('evidence/seq159300/recovery-only/phase2/builder/publisher/')
      || !input.templateUploadReceiptObjectKey
        .startsWith('evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/')
      || !input.changeSetReceiptObjectKey
        .startsWith('evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/')
      || input.cleanupTemplateEvidenceObjectKey
        !== `evidence/seq159300/recovery-only/phase2/builder/cleanup/templates/layrs-seq159300-recovery-builder-cleanup-${input.cleanupTemplateSha384}.yml`
      || !/^evidence\/seq159300\/recovery-only\/phase2\/builder\/cleanup\/roles\/cleanup-execution\/inventory\/[0-9a-f]{40}-[0-9a-f]{96}\.json$/u
        .test(input.cleanupExecutionRoleInventoryObjectKey)
      || !/^evidence\/seq159300\/recovery-only\/phase2\/builder\/cleanup\/roles\/cleanup-submitter\/inventory\/[0-9a-f]{40}-[0-9a-f]{96}\.json$/u
        .test(input.cleanupSubmitterRoleInventoryObjectKey)
      || input.cleanupExecutionRoleInventoryObjectKey.split('/').at(-1)
        !== input.cleanupSubmitterRoleInventoryObjectKey.split('/').at(-1)
      || !/^evidence\/seq159300\/recovery-only\/phase2\/builder\/publisher\/roles\/template-publisher\/inventory\/[0-9a-f]{40}-[0-9a-f]{96}\.json$/u
        .test(input.templatePublisherRoleInventoryObjectKey)
      || !/^evidence\/seq159300\/recovery-only\/phase2\/builder\/publisher\/roles\/cloudformation-execution\/inventory\/[0-9a-f]{40}-[0-9a-f]{96}\.json$/u
        .test(input.cloudFormationExecutionRoleInventoryObjectKey)
      || input.templatePublisherRoleInventoryObjectKey.split('/').at(-1)
        !== input.cloudFormationExecutionRoleInventoryObjectKey.split('/').at(-1)
      || input.cleanupExecutionRoleInventoryObjectKey.split('/').at(-1)
        !== input.templatePublisherRoleInventoryObjectKey.split('/').at(-1)
      || input.publisherTemplateEvidenceObjectKey
        !== `evidence/seq159300/recovery-only/phase2/builder/publisher/layrs-seq159300-recovery-template-publisher-${input.publisherTemplateSha384}.yml`
      || !immutableVersionId(input.phase2EvidenceObjectVersionId)
      || !immutableVersionId(input.implementationEvidenceObjectVersionId)
      || !immutableVersionId(input.builderTemplateEvidenceObjectVersionId)
      || !immutableVersionId(input.packerInvokerEvidenceObjectVersionId)
      || !immutableVersionId(input.builderEvidenceIndexObjectVersionId)
      || !immutableVersionId(input.publisherTemplateEvidenceObjectVersionId)
      || !immutableVersionId(input.templateUploadReceiptObjectVersionId)
      || !immutableVersionId(input.changeSetReceiptObjectVersionId)
      || !immutableVersionId(input.cleanupTemplateEvidenceObjectVersionId)
      || !immutableVersionId(input.cleanupExecutionRoleInventoryObjectVersionId)
      || !immutableVersionId(input.cleanupSubmitterRoleInventoryObjectVersionId)
      || !immutableVersionId(input.templatePublisherRoleInventoryObjectVersionId)
      || !immutableVersionId(input.cloudFormationExecutionRoleInventoryObjectVersionId)
      || !immutableVersionId(input.nitroCliRpmObjectVersionId)
      || !immutableVersionId(input.nitroPackageSetObjectVersionId)
      || !immutableVersionId(input.nitroPackageSetEvidenceObjectVersionId)
      || [
        input.builderEvidenceIndexSha384, input.builderTemplateEvidenceSha384,
        input.builderTemplateSha384,
        input.buildControlPlaneRoleInventorySha384,
        input.buildInstanceProfileInventorySha384, input.buildSecurityGroupInventorySha384,
        input.buildSubnetInventorySha384, input.changeSetReceiptSha384,
        input.cleanupExecutionRoleInventorySha384, input.cleanupSubmitterRoleInventorySha384,
        input.cleanupTemplateEvidenceSha384, input.cleanupTemplateSha384,
        input.cloudFormationExecutionRoleInventorySha384,
        input.implementationEvidenceObjectSha384,
        input.nitroCliRpmSha384, input.nitroPackageInventorySha384, input.outputAmiInventorySha384,
        input.nitroPackageClosureSha384, input.nitroPackageSetSha384,
        input.nitroPackageSetEvidenceSha384,
        input.packerInvokerEvidenceSha384, input.packerInvokerRoleInventorySha384,
        input.packerInvokerTemplateSha384, input.packerManifestSha384,
        input.packerControlArtifactPolicySha384, input.packerControlInventoryPolicySha384,
        input.packerControlLaunchPolicySha384,
        input.packerTemplateSha384, input.phase2EvidenceObjectSha384,
        input.phase2TemplateSha384, input.templatePublisherRoleInventorySha384,
        input.publisherTemplateEvidenceSha384, input.publisherTemplateSha384,
        input.sourceAmiProvenanceSha384, input.templateUploadReceiptSha384,
        input.trustedPrincipalInventorySha384,
      ].some(value => !/^[0-9a-f]{96}$/u.test(value))
      || new Set([
        [input.builderEvidenceIndexObjectKey, input.builderEvidenceIndexObjectVersionId],
        [input.builderTemplateEvidenceObjectKey, input.builderTemplateEvidenceObjectVersionId],
        [input.packerInvokerEvidenceObjectKey, input.packerInvokerEvidenceObjectVersionId],
        [input.publisherTemplateEvidenceObjectKey, input.publisherTemplateEvidenceObjectVersionId],
        [input.templateUploadReceiptObjectKey, input.templateUploadReceiptObjectVersionId],
        [input.changeSetReceiptObjectKey, input.changeSetReceiptObjectVersionId],
        [input.cleanupTemplateEvidenceObjectKey, input.cleanupTemplateEvidenceObjectVersionId],
        [input.cleanupExecutionRoleInventoryObjectKey, input.cleanupExecutionRoleInventoryObjectVersionId],
        [input.cleanupSubmitterRoleInventoryObjectKey, input.cleanupSubmitterRoleInventoryObjectVersionId],
        [input.templatePublisherRoleInventoryObjectKey, input.templatePublisherRoleInventoryObjectVersionId],
        [input.cloudFormationExecutionRoleInventoryObjectKey, input.cloudFormationExecutionRoleInventoryObjectVersionId],
        [input.phase2EvidenceObjectKey, input.phase2EvidenceObjectVersionId],
        [input.implementationEvidenceObjectKey, input.implementationEvidenceObjectVersionId],
        [input.nitroCliRpmObjectKey, input.nitroCliRpmObjectVersionId],
        [input.nitroPackageSetObjectKey, input.nitroPackageSetObjectVersionId],
        [input.nitroPackageSetEvidenceObjectKey, input.nitroPackageSetEvidenceObjectVersionId],
      ].map(([key, version]) => `${key}\0${version}`)).size !== 16
      || !Number.isFinite(completedAt)
      || authorityWindows.some(([approvedAt, expiresAt]) => !Number.isFinite(approvedAt)
        || !Number.isFinite(expiresAt) || approvedAt >= expiresAt
        || expiresAt - approvedAt > 3_600_000 || approvedAt > completedAt)) {
    throw new Error('recovery parent build evidence binding is invalid');
  }
  return Buffer.from(canonicalJson(input));
}

function exactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} is not an object`);
  const actual = Object.keys(value).sort();
  const fields = [...expected].sort();
  if (actual.length !== fields.length || actual.some((field, index) => field !== fields[index])) {
    throw new Error(`${label} field set is invalid`);
  }
}

function cliArguments() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--input' || args[2] !== '--output'
      || !args[1] || !args[3]) {
    throw new Error('use exactly --input <path> --output <path>');
  }
  return { input: args[1], output: args[3] };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const paths = cliArguments();
  const input = JSON.parse(readFileSync(paths.input, 'utf8'));
  writeFileSync(paths.output, renderRecoveryParentBuildEvidence(input), { flag: 'wx', mode: 0o600 });
}
