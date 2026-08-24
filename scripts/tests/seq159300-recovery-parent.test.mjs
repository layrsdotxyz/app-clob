import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  renderRecoveryParentBuildEvidence,
} from '../render-seq159300-recovery-parent-evidence.mjs';
import {
  renderRecoveryParentPostBuildCleanupEvidence,
} from '../render-seq159300-recovery-parent-post-build-cleanup-evidence.mjs';
import { validatePreflight } from '../lib/seq159300-recovery-parent-preflight.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const packer = readFileSync(
  resolve(ROOT, 'enclave/packer/layrs-seq159300-recovery-parent.pkr.hcl'),
  'utf8',
);
const enclaveUnit = readFileSync(resolve(ROOT, 'enclave/systemd/layrsv2-enclave.service'), 'utf8');
const parentUnit = readFileSync(
  resolve(ROOT, 'enclave/systemd/layrsv2-enclave-parent.service'),
  'utf8',
);
const wrapper = readFileSync(resolve(ROOT, 'scripts/build-seq159300-recovery-parent-ami.sh'), 'utf8');
const toolchainManifestBytes = readFileSync(
  resolve(ROOT, 'enclave/packer/layrs-seq159300-packer-toolchain-provenance.v1.json'),
  'utf8',
);
const toolchainManifest = JSON.parse(toolchainManifestBytes);
const runbook = readFileSync(
  resolve(ROOT, 'docs/runbooks/LAYRS_SEQ159300_RECOVERY_PARENT_AMI.md'),
  'utf8',
);

const SOURCE_COMMIT = 'f282583cae7a5c873a26aa8d0c1bec10c490eb8e';
const IMPLEMENTATION_COMMIT = '9e21c925d121822019524ec3d9b4973b1a32f38a';
const PARENT_PACKAGE_COMMIT = '24405e0da728e237dc851915bcdb60c6ee1db5bb';
const PHASE2_TEMPLATE_COMMIT = '37f9ce648efcf4f3e048cab7edf2748cda4ce2c3';
const PHASE2_TEMPLATE_SHA384 = '74a007bfaae07601afb056d9d0e4c2b198a4b508951bfacaf8552cd2573736fbd4a86232e55f4a1a1e5146fb866efcae';
const CLEANUP_IMPLEMENTATION_COMMIT = '23f92bc64171862abc410af953321a991e5e1515';
const BUILDER_TEMPLATE_SHA384 = '75e536d6d138b88aaf7ef29fece2f67f3e6ffbda02841092de73726795b4d55a6fe01af492d8d8d1f0d3dc7f8db105d7';
const INVOKER_TEMPLATE_SHA384 = 'd67e4f78be6bd679b4ab61e316215fce24035e89508baaefcf3b2df6209682fd94dc0fcd84bac1530664f02aaf7723e1';
const TEMPLATE_PUBLISHER_SHA384 = '6eefb0154b78e08949ffb677a5179782cd17ab3f9a2f3d68ddf65789ce085b73aa9f76ad13821aff06fe9d853153d529';
const CLEANUP_TEMPLATE_SHA384 = '72c5872db412726d8e56c0c078067bae19c8cf316bba204f0849a6ae34bc504792b12601f023f76efdf81b750a6aa77c';
const POSTBUILD_PUBLISHER_SHA384 = '329c3ad67e05dec6efff89d7ede7553e652b18d7a6727c95fc88e7766584037f6d1345210120448cccba7f56397e9361';
const FINALIZER_TEMPLATE_SHA384 = '2eeca9da6a30bc6aef84126d8e53b70723b8b00554aa65c9da982e3fd47f82eb694c00b05a26c598eed3d5b8d110b2c9';
const BOOTSTRAP_TEMPLATE_SHA384 = 'a1842b42708550d46233b7abbd7296b70a413ad02cd4e907debe36944a8e9a036fcd6a56bb8cf6cf2c6d74530b9691f2';
const SHA384 = '3'.repeat(96);
const PARENT_SHA384 = 'd9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1';
const EIF_SHA384 = '958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290';
const REJECTED_BUILD_A_EIF = '110c31235f36fa85e4a50d61fb89ab3a08e5b18587a35dfe4818c3615eed5a79513082df101e5c655fce8c7640d66ad8';
const PCR0_SHA384 = '57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac';
const AMAZON_KEY_FINGERPRINT = 'B21C50FA44A99720EAA72F7FE951904AD832C631';
const AMAZON_KEY_SHA256 = '664b632018bd84f9b249be7bd26937c560edb2f2bfc0cbc01ec5a7b4e06aad56';

function validEvidence(overrides = {}) {
  return {
    protocol: 'layrs.seq159300.recovery-parent-build-evidence.v1',
    accountId: '082223548516',
    region: 'us-east-1',
    environment: 'production',
    implementationCommit: IMPLEMENTATION_COMMIT,
    implementationEvidenceObjectKey: 'evidence/seq159300/recovery-only/implementation/backend.json',
    implementationEvidenceObjectVersionId: 'implementation.version.1',
    implementationEvidenceObjectSha384: SHA384,
    parentPackageCommit: PARENT_PACKAGE_COMMIT,
    parentBuildWrapperSha384: '1'.repeat(96),
    parentPreflightSha384: '2'.repeat(96),
    parentBuildEvidenceRendererSha384: '3'.repeat(96),
    parentPostBuildCleanupEvidenceRendererSha384: '4'.repeat(96),
    parentRunbookSha384: '5'.repeat(96),
    builderEvidenceIndexObjectKey: 'evidence/seq159300/recovery-only/phase2/builder/evidence-index.json',
    builderEvidenceIndexObjectVersionId: 'builder.index.version.1',
    builderEvidenceIndexSha384: SHA384,
    builderTemplateSha384: BUILDER_TEMPLATE_SHA384,
    builderTemplateEvidenceObjectKey: `evidence/seq159300/recovery-only/phase2/builder/templates/layrs-seq159300-recovery-builder-${BUILDER_TEMPLATE_SHA384}.yml`,
    builderTemplateEvidenceObjectVersionId: 'builder.template.version.1',
    builderTemplateEvidenceSha384: BUILDER_TEMPLATE_SHA384,
    publisherTemplateSha384: TEMPLATE_PUBLISHER_SHA384,
    publisherTemplateEvidenceObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/publisher/layrs-seq159300-recovery-template-publisher-${TEMPLATE_PUBLISHER_SHA384}.yml`,
    publisherTemplateEvidenceObjectVersionId: 'publisher.template.version.1',
    publisherTemplateEvidenceSha384: TEMPLATE_PUBLISHER_SHA384,
    templatePublisherRoleInventoryObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/publisher/roles/template-publisher/inventory/${'6'.repeat(40)}-${'5'.repeat(96)}.json`,
    templatePublisherRoleInventoryObjectVersionId: 'template.publisher.inventory.version.1',
    templatePublisherRoleInventorySha384: '5'.repeat(96),
    cloudFormationExecutionRoleInventoryObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/publisher/roles/cloudformation-execution/inventory/${'6'.repeat(40)}-${'5'.repeat(96)}.json`,
    cloudFormationExecutionRoleInventoryObjectVersionId: 'cloudformation.execution.inventory.version.1',
    cloudFormationExecutionRoleInventorySha384: '6'.repeat(96),
    templateUploadReceiptObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/template-upload.json',
    templateUploadReceiptObjectVersionId: 'template.upload.receipt.version.1',
    templateUploadReceiptSha384: '7'.repeat(96),
    changeSetReceiptObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/change-set.json',
    changeSetReceiptObjectVersionId: 'change.set.receipt.version.1',
    changeSetReceiptSha384: '8'.repeat(96),
    cleanupTemplateSha384: CLEANUP_TEMPLATE_SHA384,
    cleanupTemplateEvidenceObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/cleanup/templates/layrs-seq159300-recovery-builder-cleanup-${CLEANUP_TEMPLATE_SHA384}.yml`,
    cleanupTemplateEvidenceObjectVersionId: 'cleanup.template.version.1',
    cleanupTemplateEvidenceSha384: CLEANUP_TEMPLATE_SHA384,
    cleanupExecutionRoleInventoryObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-execution/inventory/${'6'.repeat(40)}-${'5'.repeat(96)}.json`,
    cleanupExecutionRoleInventoryObjectVersionId: 'cleanup.execution.inventory.version.1',
    cleanupExecutionRoleInventorySha384: 'd'.repeat(96),
    cleanupSubmitterRoleInventoryObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-submitter/inventory/${'6'.repeat(40)}-${'5'.repeat(96)}.json`,
    cleanupSubmitterRoleInventoryObjectVersionId: 'cleanup.submitter.inventory.version.1',
    cleanupSubmitterRoleInventorySha384: 'e'.repeat(96),
    trustedPrincipalInventorySha384: 'f'.repeat(96),
    buildControlPlaneRoleInventorySha384: SHA384,
    buildInstanceProfileInventorySha384: SHA384,
    buildSecurityGroupInventorySha384: SHA384,
    buildSubnetInventorySha384: SHA384,
    nitroCliNevra: 'aws-nitro-enclaves-cli-0:1.4.2-1.amzn2023.x86_64',
    nitroCliRpmObjectKey: 'evidence/seq159300/recovery-only/phase2/packages/aws-nitro-enclaves-cli.rpm',
    nitroCliRpmObjectVersionId: 'nitro.rpm.version.1',
    nitroCliRpmSha384: SHA384,
    nitroPackageInventorySha384: SHA384,
    nitroPackageSetObjectKey: 'evidence/seq159300/recovery-only/phase2/packages/nitro-packages.tar',
    nitroPackageSetObjectVersionId: 'package.set.version.1',
    nitroPackageSetSha384: SHA384,
    nitroPackageClosureSha384: SHA384,
    nitroPackageSetEvidenceObjectKey: 'evidence/seq159300/recovery-only/phase2/packages/nitro-package-set-evidence.json',
    nitroPackageSetEvidenceObjectVersionId: 'package.evidence.version.1',
    nitroPackageSetEvidenceSha384: SHA384,
    outputAmiInventorySha384: SHA384,
    packerManifestSha384: SHA384,
    packerInvokerRoleInventorySha384: SHA384,
    packerInvokerTemplateSha384: INVOKER_TEMPLATE_SHA384,
    packerInvokerEvidenceObjectKey: 'evidence/seq159300/recovery-only/phase2/invoker/template.yml',
    packerInvokerEvidenceObjectVersionId: 'invoker.template.version.1',
    packerInvokerEvidenceSha384: INVOKER_TEMPLATE_SHA384,
    packerControlInventoryPolicySha384: 'a'.repeat(96),
    packerControlLaunchPolicySha384: 'b'.repeat(96),
    packerControlArtifactPolicySha384: 'c'.repeat(96),
    packerControlPlaneApprovedAt: '2026-08-24T03:00:00Z',
    packerControlPlaneExpiresAt: '2026-08-24T04:00:00Z',
    invokerApprovedAt: '2026-08-24T02:55:00Z',
    invokerExpiresAt: '2026-08-24T03:55:00Z',
    templatePublisherApprovedAt: '2026-08-24T02:50:00Z',
    templatePublisherExpiresAt: '2026-08-24T03:50:00Z',
    packerTemplateSha384: SHA384,
    packerAmazonPluginVersion: '1.3.9',
    packerAmazonPluginSourceCommit: '2a769c39a05940e25143098f071490732fa24f4f',
    packerToolchainManifestSha256: '6a6d597535481836605a4cc9762755038e56e524af621356e5f5f65519c6858e',
    phase2EvidenceObjectKey: 'evidence/seq159300/recovery-only/phase2/rendered-phase2.json',
    phase2EvidenceObjectVersionId: 'phase2.version.1',
    phase2EvidenceObjectSha384: SHA384,
    phase2TemplateCommit: PHASE2_TEMPLATE_COMMIT,
    phase2TemplateSha384: PHASE2_TEMPLATE_SHA384,
    remediationEvidenceCommit: '540fc566c83dee2c3226862cc71a95541bc69af7',
    remediationIndexObjectVersionId: 'oBGf0odkWa6tzYpml_UtGemDwXI6GdXy',
    sourceCommit: SOURCE_COMMIT,
    sourceAmiId: 'ami-0332d564d76dbd8d6',
    sourceAmiOwner: '137112412989',
    sourceAmiProvenanceSha384: SHA384,
    amiId: 'ami-0123456789abcdef0',
    parentBinarySha384: PARENT_SHA384,
    eifSha384: EIF_SHA384,
    pcr0Sha384: PCR0_SHA384,
    buildCompletedAt: '2026-08-24T03:30:00Z',
    ...overrides,
  };
}

function validPostBuildCleanupEvidence(overrides = {}) {
  const record = (resourceType, resourceId, serviceErrorCode, index) => ({
    requestId: `request-seq159300-${String(index).padStart(3, '0')}`,
    resourceId,
    resourceType,
    serviceErrorCode,
  });
  const records = [
    record('cloudformation-stack',
      'arn:aws:cloudformation:us-east-1:082223548516:stack/layrs-production-recovery-seq159300-invoker/00000000-0000-0000-0000-000000000007',
      'ValidationError', 7),
    record('cloudformation-stack',
      'arn:aws:cloudformation:us-east-1:082223548516:stack/layrs-production-recovery-seq159300-builder/00000000-0000-0000-0000-000000000001',
      'ValidationError', 1),
    record('cloudformation-stack',
      'arn:aws:cloudformation:us-east-1:082223548516:stack/layrs-production-recovery-seq159300-template-publisher/00000000-0000-0000-0000-000000000002',
      'ValidationError', 2),
    record('cloudformation-stack',
      'arn:aws:cloudformation:us-east-1:082223548516:stack/layrs-production-recovery-seq159300-builder-cleanup/00000000-0000-0000-0000-000000000003',
      'ValidationError', 3),
    record('cloudformation-stack',
      'arn:aws:cloudformation:us-east-1:082223548516:stack/layrs-production-recovery-seq159300-post-build-evidence-publisher/00000000-0000-0000-0000-000000000005',
      'ValidationError', 5),
    record('cloudformation-change-set',
      'arn:aws:cloudformation:us-east-1:082223548516:changeSet/layrs-seq159300-builder-123456789abc/00000000-0000-0000-0000-000000000004',
      'ChangeSetNotFoundException', 4),
    record('iam-instance-profile', 'layrs-production-recovery-seq159300-builder-instance', 'NoSuchEntityException', 6),
    ...[
      'invoker', 'invoker-window-guard',
      'template-publisher', 'template-publisher-window-guard', 'cloudformation-execution',
      'builder-instance', 'window-guard', 'packer-control', 'cleanup-window-guard',
      'cleanup-execution', 'cleanup-submitter', 'post-build-evidence-publisher',
      'post-build-publisher-window-guard', 'finalizer-window-guard',
    ].map((name, index) => record('iam-role', `layrs-production-recovery-seq159300-${name}`,
      'NoSuchEntityException', 10 + index)),
    ...[
      'packer-inventory', 'packer-launch', 'packer-artifacts', 'cfn-core-network',
      'cfn-endpoints', 'cfn-mutation',
    ].map((name, index) => record('iam-managed-policy',
      `arn:aws:iam::082223548516:policy/layrs-production-recovery-seq159300-${name}`,
      'NoSuchEntityException', 30 + index)),
    ...['invoker-window-guard', 'template-publisher-window-guard', 'window-guard', 'cleanup-window-guard',
      'post-build-publisher-window-guard', 'finalizer-window-guard']
      .map((name, index) => record('lambda-function',
        `arn:aws:lambda:us-east-1:082223548516:function:layrs-production-recovery-seq159300-${name}`,
        'ResourceNotFoundException', 40 + index)),
    record('ec2-vpc', 'vpc-0123456789abcdef0', 'InvalidVpcID.NotFound', 50),
    record('ec2-subnet', 'subnet-0123456789abcdef0', 'InvalidSubnetID.NotFound', 51),
    record('ec2-route-table', 'rtb-0123456789abcdef0', 'InvalidRouteTableID.NotFound', 52),
    record('ec2-security-group', 'sg-0123456789abcdef0', 'InvalidGroup.NotFound', 53),
    record('ec2-vpc-endpoint', 'vpce-0123456789abcdef0', 'InvalidVpcEndpointId.NotFound', 54),
    record('ec2-network-interface', 'eni-0123456789abcdef0', 'InvalidNetworkInterfaceID.NotFound', 55),
    record('packer-temporary-key-pair', 'layrs-seq159300-recovery-key-12345678', 'InvalidKeyPair.NotFound', 56),
    record('packer-temporary-instance', 'i-0123456789abcdef0', 'InvalidInstanceID.NotFound', 57),
  ].sort((left, right) => `${left.resourceType}\0${left.resourceId}`.localeCompare(`${right.resourceType}\0${right.resourceId}`));
  const evidenceRefs = [
    ['evidence/seq159300/recovery-only/phase2/parent-build/build.json', 'parent.build.version.1', '1'.repeat(96)],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/templates/layrs-seq159300-recovery-builder-cleanup-${CLEANUP_TEMPLATE_SHA384}.yml`, 'cleanup.template.version.1', CLEANUP_TEMPLATE_SHA384],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/receipts/${CLEANUP_IMPLEMENTATION_COMMIT}-${'5'.repeat(96)}.json`, 'cleanup.receipt.version.1', '3'.repeat(96)],
    ['evidence/seq159300/recovery-only/phase2/builder/cleanup/inventory/pre-delete.json', 'predelete.inventory.version.1', '4'.repeat(96)],
    ['evidence/seq159300/recovery-only/phase2/builder/cleanup/intents/cleanup.json', 'cleanup.intent.version.1', '5'.repeat(96)],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/publisher/templates/layrs-seq159300-recovery-post-build-evidence-publisher-${POSTBUILD_PUBLISHER_SHA384}.yml`, 'postbuild.publisher.template.version.1', POSTBUILD_PUBLISHER_SHA384],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/templates/layrs-seq159300-recovery-finalizer-${FINALIZER_TEMPLATE_SHA384}.yml`, 'finalizer.template.version.1', FINALIZER_TEMPLATE_SHA384],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/inventory/${CLEANUP_IMPLEMENTATION_COMMIT}-${'5'.repeat(96)}.json`, 'finalizer.role.inventory.version.1', '9'.repeat(96)],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/deployer/templates/layrs-predifi-root-bootstrap-${BOOTSTRAP_TEMPLATE_SHA384}.yml`, 'production.deployer.template.version.1', BOOTSTRAP_TEMPLATE_SHA384],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/deployer/inventory/${CLEANUP_IMPLEMENTATION_COMMIT}-${'5'.repeat(96)}.json`, 'production.deployer.inventory.version.1', 'f'.repeat(96)],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/stack-inventory/${CLEANUP_IMPLEMENTATION_COMMIT}-${'5'.repeat(96)}.json`, 'finalizer.stack.inventory.version.1', 'c'.repeat(96)],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-execution/inventory/${CLEANUP_IMPLEMENTATION_COMMIT}-${'5'.repeat(96)}.json`, 'cleanup.execution.inventory.version.1', 'd'.repeat(96)],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-submitter/inventory/${CLEANUP_IMPLEMENTATION_COMMIT}-${'5'.repeat(96)}.json`, 'cleanup.submitter.inventory.version.1', 'e'.repeat(96)],
    [`evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/post-build-evidence-publisher/inventory/${CLEANUP_IMPLEMENTATION_COMMIT}-${'5'.repeat(96)}.json`, 'postbuild.publisher.inventory.version.1', '0'.repeat(96)],
  ];
  return {
    protocol: 'layrs.seq159300.recovery-parent-post-build-cleanup-evidence.v1',
    accountId: '082223548516', region: 'us-east-1', environment: 'production',
    cleanupImplementationCommit: CLEANUP_IMPLEMENTATION_COMMIT,
    verifiedAt: '2026-08-24T08:00:00Z',
    finalizerApprovedAt: '2026-08-24T07:59:00Z',
    finalizerExpiresAt: '2026-08-24T08:59:00Z',
    cleanupApprovedAt: '2026-08-24T07:56:00Z',
    cleanupExpiresAt: '2026-08-24T08:56:00Z',
    cleanupSubmitterExternalId: '0'.repeat(96),
    cleanupSubmitterIdentity: {
      accountId: '082223548516',
      arn: 'arn:aws:sts::082223548516:assumed-role/layrs-production-recovery-seq159300-cleanup-submitter/cleanup1',
      principalId: 'AROABCDEFGHIJKLMNOP:cleanup1',
    },
    cleanupSubmitterSession: {
      durationSeconds: 3450, issuedAt: '2026-08-24T07:56:00Z', expiresAt: '2026-08-24T08:53:30Z',
    },
    finalizerSession: {
      durationSeconds: 3270, issuedAt: '2026-08-24T07:59:00Z', expiresAt: '2026-08-24T08:53:30Z',
    },
    runnerIdentity: {
      accountId: '082223548516',
      arn: 'arn:aws:sts::082223548516:assumed-role/layrs-gitlab-runner-RunnerRole-1LXmWXGdTn9z/runner1',
      principalId: 'AROABCDEFGHIJKLMNOP:runner1',
    },
    productionDeployerIdentity: {
      accountId: '082223548516',
      arn: 'arn:aws:sts::082223548516:assumed-role/layrs-production-deployer/deployer1',
      principalId: 'AROABCDEFGHIJKLMNOP:deployer1',
    },
    productionDeployerSession: {
      durationSeconds: 3600, issuedAt: '2026-08-24T07:54:00Z', expiresAt: '2026-08-24T08:54:00Z',
    },
    postBuildPublisherApprovedAt: '2026-08-24T07:50:00Z',
    postBuildPublisherExpiresAt: '2026-08-24T08:50:00Z',
    phase4Authorized: false,
    parentBuildEvidenceObjectKey: evidenceRefs[0][0], parentBuildEvidenceObjectVersionId: evidenceRefs[0][1],
    parentBuildEvidenceSha384: evidenceRefs[0][2],
    cleanupTemplateEvidenceObjectKey: evidenceRefs[1][0], cleanupTemplateEvidenceObjectVersionId: evidenceRefs[1][1],
    cleanupTemplateEvidenceSha384: evidenceRefs[1][2],
    cleanupReceiptObjectKey: evidenceRefs[2][0], cleanupReceiptObjectVersionId: evidenceRefs[2][1],
    cleanupReceiptSha384: evidenceRefs[2][2],
    cleanupExecutionRoleInventoryObjectKey: evidenceRefs[11][0],
    cleanupExecutionRoleInventoryObjectVersionId: evidenceRefs[11][1],
    cleanupExecutionRoleInventorySha384: evidenceRefs[11][2],
    cleanupSubmitterRoleInventoryObjectKey: evidenceRefs[12][0],
    cleanupSubmitterRoleInventoryObjectVersionId: evidenceRefs[12][1],
    cleanupSubmitterRoleInventorySha384: evidenceRefs[12][2],
    postBuildPublisherRoleInventoryObjectKey: evidenceRefs[13][0],
    postBuildPublisherRoleInventoryObjectVersionId: evidenceRefs[13][1],
    postBuildPublisherRoleInventorySha384: evidenceRefs[13][2],
    postBuildPublisherRoleInventoryUploadRequestId: 'req-publisher-inventory-upload-001',
    postBuildPublisherRoleInventoryUploadedAt: '2026-08-24T07:59:20Z',
    postBuildPublisherRoleInventoryReadbackRequestId: 'req-publisher-inventory-readback-001',
    postBuildPublisherRoleInventoryReadbackVerifiedAt: '2026-08-24T07:59:21Z',
    preDeletePhysicalInventoryObjectKey: evidenceRefs[3][0],
    preDeletePhysicalInventoryObjectVersionId: evidenceRefs[3][1], preDeletePhysicalInventorySha384: evidenceRefs[3][2],
    cleanupIntentObjectKey: evidenceRefs[4][0], cleanupIntentObjectVersionId: evidenceRefs[4][1],
    cleanupIntentSha384: evidenceRefs[4][2],
    postBuildEvidencePublisherTemplateObjectKey: evidenceRefs[5][0],
    postBuildEvidencePublisherTemplateObjectVersionId: evidenceRefs[5][1],
    postBuildEvidencePublisherTemplateSha384: evidenceRefs[5][2],
    finalizerTemplateEvidenceObjectKey: evidenceRefs[6][0],
    finalizerTemplateEvidenceObjectVersionId: evidenceRefs[6][1],
    finalizerTemplateEvidenceSha384: evidenceRefs[6][2],
    finalizerRoleInventoryObjectKey: evidenceRefs[7][0],
    finalizerRoleInventoryObjectVersionId: evidenceRefs[7][1],
    productionDeployerTemplateEvidenceObjectKey: evidenceRefs[8][0],
    productionDeployerTemplateEvidenceObjectVersionId: evidenceRefs[8][1],
    productionDeployerTemplateEvidenceSha384: evidenceRefs[8][2],
    productionDeployerRoleInventoryObjectKey: evidenceRefs[9][0],
    productionDeployerRoleInventoryObjectVersionId: evidenceRefs[9][1],
    productionDeployerRoleInventorySha384: evidenceRefs[9][2],
    retainedFinalizerStackInventoryObjectKey: evidenceRefs[10][0],
    retainedFinalizerStackInventoryObjectVersionId: evidenceRefs[10][1],
    retainedFinalizerStackInventorySha384: evidenceRefs[10][2],
    retainedAmiInventory: [{ amiId: 'ami-0123456789abcdef0', outputAmiInventorySha384: '7'.repeat(96) }],
    retainedSnapshotInventory: [{ snapshotId: 'snap-0123456789abcdef0', snapshotInventorySha384: '8'.repeat(96) }],
    retainedEvidenceInventory: evidenceRefs.map(([objectKey, objectVersionId, sha384]) => ({
      objectKey, objectVersionId, sha384,
    })).sort((left, right) => `${left.objectKey}\0${left.objectVersionId}`.localeCompare(`${right.objectKey}\0${right.objectVersionId}`)),
    exactAbsenceInventory: records,
    exactAbsenceInventorySha384: createHash('sha384').update(canonicalJson(records)).digest('hex'),
    verifierIdentity: {
      accountId: '082223548516',
      arn: 'arn:aws:sts::082223548516:assumed-role/layrs-production-recovery-seq159300-finalizer/session1',
      principalId: 'AROABCDEFGHIJKLMNOP:session1',
    },
    verifierRoleInventorySha384: '9'.repeat(96),
    finalizerRoleInventorySha384: '9'.repeat(96),
    trustedPrincipalInventorySha384: 'b'.repeat(96),
    ...overrides,
  };
}

test('Packer source is pinned, private and recovery-only', () => {
  assert.match(packer, /version\s*=\s*"= 1\.3\.9"/u);
  assert.match(packer, /image-id\s*=\s*var\.source_ami_id/u);
  assert.match(packer, /owners\s*=\s*\[var\.source_ami_owner\]/u);
  assert.match(packer, /most_recent\s*=\s*false/u);
  assert.match(packer, /associate_public_ip_address\s*=\s*false/u);
  assert.match(packer, /allowed_account_ids\s*=\s*\["082223548516"\]/u);
  assert.match(packer, /ssh_interface\s*=\s*"session_manager"/u);
  assert.match(packer, /temporary_key_pair_name\s*=\s*"layrs-seq159300-recovery-/u);
  assert.match(packer, /launch_block_device_mappings\s*\{[\s\S]*encrypted\s*=\s*true/u);
  assert.doesNotMatch(packer, /\bencrypt_boot\b|\bena_support\b|\bkms_key_id\b/u);
  assert.match(packer, /snapshot_tags\s*=\s*\{/u);
  for (const tag of [
    'RecoveryBuilderTemplateSha384', 'RecoveryPackageSetSha384', 'RecoveryEvidenceIndexSha384',
    'Phase2TemplateSha384',
  ]) {
    assert.ok((packer.match(new RegExp(tag, 'gu')) ?? []).length >= 4);
  }
  assert.match(packer, /layrs-seq159300-recovery/u);
  assert.match(packer, /variable "parent_package_commit"/u);
  assert.match(packer, /RecoveryParentPackageCommit\s+=\s+var\.parent_package_commit/u);
  assert.match(packer, /parentPackageCommit\s+=\s+var\.parent_package_commit/u);
  assert.doesNotMatch(packer, /builder_source_commit|builderSourceCommit|RecoveryBuilderSourceCommit/u);
  assert.match(packer, /ProductionRouteAttached\s*=\s*"false"/u);
  assert.match(packer, new RegExp(PARENT_SHA384, 'u'));
  assert.match(
    packer,
    /condition\s*=\s*can\(regex\("\^\[0-9a-f\]\{40\}\$", var\.implementation_commit\)\)/u,
  );
  assert.match(packer, /source_ami_owner == "137112412989"/u);
  assert.match(packer, /aws_region == "us-east-1"/u);
  assert.doesNotMatch(packer, /temporary_security_group_source_public_ip/u);
  assert.doesNotMatch(packer, /\bami_users\b|\bami_groups\b|user_data/u);
  assert.doesNotMatch(packer, /target.?group|cloudflare|route53/iu);
});

test('Packer copies only the accepted existing runtime artifacts and existing services', () => {
  assert.match(packer, /source\s*=\s*"build\/layrs-enclave-parent"/u);
  assert.match(packer, /source\s*=\s*"build\/layrsv2-clob\.eif"/u);
  assert.match(packer, new RegExp(`printf '[^']+' '[^']*${PARENT_SHA384}`, 'u'));
  assert.match(packer, new RegExp(`printf '[^']+' '[^']*${EIF_SHA384}`, 'u'));
  assert.ok((packer.match(/sha384sum -c -/gu) ?? []).length >= 4);
  assert.doesNotMatch(packer, /cargo build|nitro-cli build-enclave|docker build/iu);
  assert.doesNotMatch(packer, /aws-nitro-enclaves-cli-devel/u);
  assert.match(packer, /source\s*=\s*"build\/seq159300-nitro-packages"/u);
  assert.match(packer, /rpmkeys --checksig --verbose/u);
  assert.match(packer, /dnf install -y --disablerepo='\*'/u);
  const enableLines = packer.match(/sudo systemctl enable[^"\n]+/gu) ?? [];
  assert.deepEqual(enableLines, [
    'sudo systemctl enable nitro-enclaves-allocator.service layrsv2-enclave.service layrsv2-enclave-parent.service layrsv2-enclave-watchdog.timer',
  ]);
});

test('wrapper cross-checks immutable package versions and a dedicated Packer role', () => {
  assert.match(wrapper, /s3api get-object[\s\S]*--version-id/u);
  assert.match(wrapper, /cmp -s/u);
  assert.match(wrapper, /rpmkeys --checksig --verbose/u);
  assert.match(wrapper, /layrs-production-recovery-seq159300-packer-control/u);
  assert.match(wrapper, /LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384/u);
  assert.match(wrapper, /LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384/u);
  assert.match(wrapper, /LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_FILE/u);
  assert.match(wrapper, /LAYRS_RECOVERY_BUILDER_TEMPLATE_FILE/u);
  assert.match(wrapper, /LAYRS_RECOVERY_INVOKER_APPROVED_AT/u);
  assert.match(wrapper, /LAYRS_RECOVERY_INVOKER_EXPIRES_AT/u);
  assert.match(wrapper, /LAYRS_RECOVERY_TEMPLATE_PUBLISHER_APPROVED_AT/u);
  assert.match(wrapper, /LAYRS_RECOVERY_TEMPLATE_PUBLISHER_EXPIRES_AT/u);
  assert.match(wrapper, /LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384/u);
  assert.match(wrapper, /LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_SHA384/u);
  assert.match(wrapper, /LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_VERSION_ID/u);
  assert.match(wrapper, /LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384/u);
  assert.match(wrapper, /B21C50FA44A99720EAA72F7FE951904AD832C631/u);
  assert.match(wrapper, /664b632018bd84f9b249be7bd26937c560edb2f2bfc0cbc01ec5a7b4e06aad56/u);
  assert.match(wrapper, /assumed-role/u);
  assert.match(wrapper, /LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID/u);
  assert.equal((wrapper.match(/s3api get-object/gu) ?? []).length, 11);
  assert.match(wrapper, /for prefix in EXECUTION SUBMITTER/u);
  assert.match(wrapper, /for prefix in TEMPLATE_PUBLISHER CLOUDFORMATION_EXECUTION/u);
  assert.match(wrapper, /cleanup .* role inventory is noncanonical or self-referential/u);
  assert.match(wrapper, /\.Key == "RoleInventorySha384"/u);
  assert.match(wrapper, /role inventory embeds its own SHA384/u);
  assert.match(wrapper, /remote builder evidence index SHA384/u);
  assert.match(wrapper, /reviewed builder template differs from its exact immutable object version/u);
  assert.match(wrapper, /reviewed Packer invoker template differs from its exact immutable object version/u);
  assert.match(wrapper, /immutable template-upload receipt is malformed/u);
  assert.match(wrapper, /immutable change-set receipt is malformed/u);
  assert.match(wrapper, /immutable JSON evidence is not exact canonical JSON plus one newline/u);
  assert.doesNotMatch(wrapper, /dnf download|reposync|curl|wget/iu);
});

test('wrapper verifies under the exact invoker then gives Packer only exact short-lived control credentials', () => {
  assert.match(wrapper, /preflight invoker role[\s\S]*LAYRS_RECOVERY_PACKER_INVOKER_ROLE_ARN/u);
  assert.match(wrapper, /sts assume-role[\s\S]*--role-arn[\s\S]*PACKER_CONTROL_ROLE_NAME/u);
  assert.match(wrapper, /--external-id "\$\{LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384\}"/u);
  assert.match(wrapper, /duration_seconds >= 900 && duration_seconds <= 3600/u);
  assert.match(wrapper, /export AWS_ACCESS_KEY_ID=/u);
  assert.match(wrapper, /export AWS_SECRET_ACCESS_KEY=/u);
  assert.match(wrapper, /export AWS_SESSION_TOKEN=/u);
  assert.match(wrapper, /assumed-role\/layrs-production-recovery-seq159300-packer-control\/layrs-seq159300-packer/u);
  assert.match(wrapper,
    /verify_immutable_package_objects\s*\n\s*verify_builder_contract_objects\s*\n\s*verify_cleanup_contract_object\s*\n\s*verify_publication_evidence_objects\s*\n\s*assume_packer_control_role/u);
  assert.match(wrapper, /run_aws_preflight\s*\n\s*\[\[ -n "\$\{PACKER_BINARY\}"/u);
  assert.doesNotMatch(wrapper, /LAYRS_RECOVERY_PACKER_CALLER_ROLE_ARN/u);
});

test('wrapper uses only the exact offline-reviewed Packer CLI and Amazon plugin bytes', () => {
  for (const binding of [
    'PACKER_CLI_VERSION="1.16.0"',
    '5edcd14ab59b535040c512dbecd6ec9ef976a000b073c19d93e4c431c948581e',
    '1c327cd37ce76790c9c10ebda1af3981554cc4eceaed1d6fdfdb59d5ccfe25d5',
    'acdd742a9f7a9e32715e81e72c8d0622ac1a700779e2b1480d89544bec89761655fa07a1fc75edaf35d337fcd318d126',
    'packer-plugin-amazon_v1.3.9_x5.0_linux_amd64',
    'a46e0d719dfc34e51ecaf50b9b575087a8007e3df2d856ed19fb91714539b87b',
    '72d1f95616192ce9b5f7f4011b43e2fee43c48c464fd03b99b5d1bd23b49940a9b41a2151a2240a670d063b9aa53e973',
    '6d8797b95727c3ce85afae0dfedbbf27f6ff8a8cd780467b9fa74d2c20414083',
    'e103534fafb5f4702f08123e0a5e190fef193e3db2c9ae26f4f80a35c12f9e3a',
    'C874011F0AB405110D02105534365D9472D7468F',
    '374EC75B485913604A831CC7C820C6D5CD27AB87',
    '9f116d64eba294c61582335d74a4812b287d9a9c601787ea7454cb030ebebb33',
  ]) assert.match(wrapper, new RegExp(binding, 'u'));
  assert.match(wrapper, /export PACKER_PLUGIN_PATH=/u);
  assert.match(wrapper, /CHECKPOINT_DISABLE=1/u);
  assert.match(wrapper, /isolated installed Packer plugin/u);
  assert.match(wrapper, /gpg --batch --status-fd 1[\s\S]*--verify/u);
  assert.ok((wrapper.match(/install -m 0500/gu) ?? []).length >= 2);
  assert.ok((wrapper.match(/assert_isolated_packer_toolchain\s*\n/gu) ?? []).length >= 3);
  assert.match(wrapper, /unreviewed Packer, HCP or checkpoint environment overrides remain set/u);
  assert.doesNotMatch(wrapper, /\bpacker init\b|plugins\s+install(?:\s|$)/u);
});

test('Packer and f282 units expose one exact runtime layout contract for Phase2 IaC', () => {
  const parentPath = '/opt/layrsv2/layrs-enclave-parent';
  const eifPath = '/opt/layrsv2/layrsv2-clob.eif';
  assert.match(packer, new RegExp(parentPath, 'u'));
  assert.match(packer, new RegExp(eifPath.replace('.', '\\.'), 'u'));
  assert.match(parentUnit, new RegExp(`ExecStart=${parentPath}`, 'u'));
  assert.match(enclaveUnit, new RegExp(eifPath.replace('.', '\\.'), 'u'));
  assert.match(parentUnit, /Requires=layrsv2-enclave\.service/u);
  assert.match(packer, /layrsv2-enclave\.service layrsv2-enclave-parent\.service/u);
  for (const source of [packer, enclaveUnit, parentUnit]) {
    assert.doesNotMatch(source, /\/opt\/layrs\/recovery|layrs-seq159300-recovery-parent\.service/u);
  }
});

test('wrapper selects exact bytes and explicitly rejects the build-a EIF', () => {
  for (const binding of [SOURCE_COMMIT, PARENT_SHA384, EIF_SHA384, PCR0_SHA384]) {
    assert.match(wrapper, new RegExp(binding, 'u'));
  }
  assert.match(wrapper, new RegExp(REJECTED_BUILD_A_EIF, 'u'));
  assert.match(wrapper, /rejected build-a EIF supplied/u);
  assert.match(wrapper, /sha384_file "\$\{EIF_BINARY\}"/u);
  assert.match(wrapper, /canonical_pcr0 "\$\{EIF_MEASUREMENTS\}"/u);
  assert.doesNotMatch(wrapper, /find .*layrsv2-clob|sort.*mtime|newest|most_recent/iu);
});

test('wrapper requires clean f282 ancestry and permits only recovery-path source changes', () => {
  assert.match(wrapper, /merge-base --is-ancestor/u);
  assert.match(wrapper, /LAYRS_RECOVERY_PARENT_PACKAGE_COMMIT/u);
  assert.doesNotMatch(wrapper, /LAYRS_RECOVERY_BUILDER_COMMIT/u);
  assert.match(wrapper, /active AWS account/u);
  assert.match(wrapper, /sts get-caller-identity/u);
  assert.match(wrapper, /status --porcelain=v1 --untracked-files=all/u);
  assert.match(wrapper, /PARENT_BUILD_WRAPPER_SHA384="\$\(sha384_file "\$\{BASH_SOURCE\[0\]\}"\)"/u);
  assert.match(wrapper, /PARENT_PREFLIGHT_SHA384="\$\(sha384_file "\$\{PREFLIGHT_VALIDATOR\}"\)"/u);
  assert.match(wrapper, /PARENT_BUILD_EVIDENCE_RENDERER_SHA384="\$\(sha384_file "\$\{EVIDENCE_RENDERER\}"\)"/u);
  assert.match(wrapper, /PARENT_POST_BUILD_CLEANUP_EVIDENCE_RENDERER_SHA384="\$\(sha384_file "\$\{POST_BUILD_EVIDENCE_RENDERER\}"\)"/u);
  assert.match(wrapper, /PARENT_RUNBOOK_SHA384="\$\(sha384_file "\$\{RECOVERY_RUNBOOK\}"\)"/u);
  assert.match(wrapper, /parentPackageCommit:\$parentPackageCommit/u);
  assert.match(wrapper, /build_completed_at=.*%Y-%m-%dT%H:%M:%SZ/u);
  assert.doesNotMatch(wrapper, /build_completed_at=.*\.000Z/u);
  assert.match(wrapper, /non-recovery source differs from f282/u);
  assert.match(wrapper, /LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384/u);
  assert.match(wrapper, /reviewed Phase2 template SHA384/u);
  assert.match(wrapper, /LAYRS_RECOVERY_SOURCE_AMI_ID/u);
  assert.match(wrapper, /137112412989/u);
  assert.match(wrapper, /LAYRS_RECOVERY_IMPLEMENTATION_COMMIT.*\^\[0-9a-f\]\{40\}\$/u);
  assert.doesNotMatch(wrapper, /\baws\s+(ec2|cloudformation|iam|s3|kms)\b/u);
  assert.match(wrapper, /cd -- "\$\{REPO_ROOT\}"/u);
});

test('wrapper keeps validation and separately authorized build modes explicit', () => {
  assert.match(wrapper, /--validate-only/u);
  assert.match(wrapper, /--build/u);
  assert.match(wrapper, /"\$\{PACKER_BINARY\}" build -color=false -force=false/u);
  assert.doesNotMatch(wrapper, /command -v packer|packer init/u);
  assert.doesNotMatch(wrapper, /-force=true/u);
});

test('runbook makes Phase2 no-production-route controls mandatory', () => {
  assert.match(runbook, /must never be\s+launched with a production route/u);
  assert.match(runbook, /denies fixed-parent\s+egress/u);
  assert.match(runbook, /does not grant Phase4 authorization/u);
  assert.match(runbook, new RegExp(REJECTED_BUILD_A_EIF, 'u'));
  assert.match(runbook, /parent binary: `\/opt\/layrsv2\/layrs-enclave-parent`/u);
  assert.match(runbook, /fixed-egress parent unit: `layrsv2-enclave-parent\.service`/u);
});

test('renderer emits exact canonical Phase2 build evidence bytes', () => {
  const evidence = validEvidence();
  const rendered = renderRecoveryParentBuildEvidence(evidence);
  assert.equal(rendered.toString('utf8'), canonicalJson(evidence));
  assert.equal(rendered.at(-1), '}'.charCodeAt(0));
  assert.deepEqual(Object.keys(JSON.parse(rendered)).sort(), Object.keys(evidence).sort());
});

test('renderer rejects swapped artifacts and recovery bindings', () => {
  for (const invalid of [
    { parentBinarySha384: '0'.repeat(96) },
    { eifSha384: REJECTED_BUILD_A_EIF },
    { pcr0Sha384: '1'.repeat(96) },
    { sourceCommit: '2'.repeat(40) },
    { parentPackageCommit: SOURCE_COMMIT },
    { parentPackageCommit: 'not-a-commit' },
    { parentBuildWrapperSha384: '0'.repeat(95) },
    { parentPreflightSha384: '0'.repeat(95) },
    { parentBuildEvidenceRendererSha384: '0'.repeat(95) },
    { parentPostBuildCleanupEvidenceRendererSha384: '0'.repeat(95) },
    { parentRunbookSha384: '0'.repeat(95) },
    { packerTemplateSha384: '0'.repeat(95) },
    { implementationCommit: 'not-a-commit' },
    { phase2TemplateCommit: '0'.repeat(40) },
    { phase2TemplateSha384: '0'.repeat(96) },
    { nitroCliRpmSha384: '0'.repeat(95) },
    { phase2EvidenceObjectKey: '../mutable.json' },
    { remediationIndexObjectVersionId: 'different' },
    { packerAmazonPluginSourceCommit: '0'.repeat(40) },
    { builderTemplateEvidenceSha384: '0'.repeat(96) },
    { builderTemplateSha384: '0'.repeat(96) },
    { packerInvokerTemplateSha384: '0'.repeat(96) },
    { packerInvokerEvidenceSha384: '0'.repeat(96) },
    { publisherTemplateSha384: '0'.repeat(96) },
    { publisherTemplateEvidenceSha384: '0'.repeat(96) },
    { cleanupTemplateSha384: '0'.repeat(96) },
    { cleanupTemplateEvidenceSha384: '0'.repeat(96) },
    { cleanupExecutionRoleInventorySha384: 'e'.repeat(96) },
    { cleanupExecutionRoleInventoryObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-execution/inventory/${'6'.repeat(40)}-${'4'.repeat(96)}.json` },
    { cleanupSubmitterRoleInventoryObjectVersionId: 'short' },
    { trustedPrincipalInventorySha384: 'd'.repeat(96) },
    { cleanupTemplateEvidenceObjectVersionId: 'short' },
    { templatePublisherRoleInventorySha384: '0'.repeat(95) },
    { templatePublisherRoleInventoryObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/publisher/roles/template-publisher/inventory/mutable.json' },
    { cloudFormationExecutionRoleInventoryObjectVersionId: 'short' },
    { cloudFormationExecutionRoleInventorySha384: '5'.repeat(96) },
    { cloudFormationExecutionRoleInventorySha384: '0'.repeat(95) },
    { templateUploadReceiptObjectKey: '../mutable-upload.json' },
    { changeSetReceiptObjectVersionId: 'short' },
    { packerControlPlaneExpiresAt: '2026-08-24T04:00:01Z' },
    { invokerApprovedAt: '2026-08-24T03:31:00Z' },
    { templatePublisherApprovedAt: '2026-08-24T02:50:00.000Z' },
    { buildCompletedAt: '2026-08-24T03:30:00.000Z' },
    {
      changeSetReceiptObjectKey:
        'evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/template-upload.json',
      changeSetReceiptObjectVersionId: 'template.upload.receipt.version.1',
    },
    { accountId: '111111111111' },
    { region: 'eu-west-1' },
  ]) {
    assert.throws(
      () => renderRecoveryParentBuildEvidence(validEvidence(invalid)),
      /binding is invalid/u,
    );
  }
});

test('renderer requires and faithfully emits the final external implementation commit', () => {
  const alternateFinalCommit = '4'.repeat(40);
  const rendered = JSON.parse(renderRecoveryParentBuildEvidence(validEvidence({
    implementationCommit: alternateFinalCommit,
  })));
  assert.equal(rendered.implementationCommit, alternateFinalCommit);
  const sameRepositoryCommit = JSON.parse(renderRecoveryParentBuildEvidence(validEvidence({
    implementationCommit: PHASE2_TEMPLATE_COMMIT,
  })));
  assert.equal(sameRepositoryCommit.implementationCommit, PHASE2_TEMPLATE_COMMIT);

  const omitted = validEvidence();
  delete omitted.implementationCommit;
  assert.throws(() => renderRecoveryParentBuildEvidence(omitted), /field set is invalid/u);

  assert.throws(
    () => renderRecoveryParentBuildEvidence(validEvidence({
      implementationCommit: SOURCE_COMMIT,
      sourceCommit: IMPLEMENTATION_COMMIT,
    })),
    /binding is invalid/u,
  );
});

test('renderer rejects extra fields and noncanonical timestamps', () => {
  assert.throws(
    () => renderRecoveryParentBuildEvidence(validEvidence({ secret: 'must-not-appear' })),
    /field set is invalid/u,
  );
  assert.throws(
    () => renderRecoveryParentBuildEvidence(validEvidence({ buildCompletedAt: '2026-08-24T03:30:00.000Z' })),
    /binding is invalid/u,
  );
});

test('post-build cleanup renderer binds retained artifacts and exact structured absence', () => {
  const evidence = validPostBuildCleanupEvidence();
  const rendered = renderRecoveryParentPostBuildCleanupEvidence(evidence);
  assert.equal(rendered.toString('utf8'), canonicalJson(evidence));
  assert.equal(rendered.at(-1), '}'.charCodeAt(0));
  assert.equal(JSON.parse(rendered).phase4Authorized, false);
  assert.match(runbook, /ListAttachedRolePolicies/u);
  assert.match(runbook, /ListInstanceProfilesForRole/u);
  assert.match(runbook, /zero attached instance profiles/u);
  assert.match(runbook, /\$metadata\.requestId/u);
  assert.match(runbook, /Parsing `aws --debug` stderr/u);
  assert.match(runbook, /`\$metadata\.httpStatusCode` values of 400 and 404/u);
  assert.match(runbook, /ordered per-resource deletion/u);
  assert.match(runbook, /cleanup\s+authority deletion last/u);
  assert.match(runbook, /not counts or booleans/u);
  assert.match(runbook, /layrs\.seq159300\.recovery-builder-cleanup-execution-receipt\.v2/u);
  assert.match(runbook, /The only order is builder, invoker, template-publisher/u);
  assert.match(runbook, /`cleanup-authority` is not an accepted alias/u);
  assert.match(runbook, /`completedAt` equals the final builder-cleanup/u);
  assert.match(runbook, /`physicalInventorySha384` must equal/u);
  assert.match(runbook, /`deleteCallCount` \(`1`\)/u);
  assert.match(runbook, /must\s+equal the final evidence's exact assumed-finalizer identity/u);
  assert.match(runbook, /cleanup\/receipts\/<cleanupImplementationCommit>-<cleanupIntentSha384>\.json/u);
  assert.match(runbook, /Finalizer creation must not require or read/u);
  assert.match(runbook, /inside one process that deployer then role-chains/u);
  assert.match(runbook, /runner cannot directly assume/u);
  assert.match(runbook, /never\s+serializes\s+their credentials/u);
  assert.match(runbook, /that same finalizer\s+session render[\s\S]*create-only upload/u);
  assert.match(runbook, /reuse the same finalizer SDK absence calls/u);
  assert.match(runbook, /map one-for-one/u);
  assert.match(runbook, /A fresh or differing absence ID is\s+rejected/u);
  assert.match(runbook, /three stable output keys/u);
  assert.match(runbook, /must not alias\s+any structured absence request ID/u);
  assert.match(runbook, /alternates two exact temporary principals through the bound/u);
  assert.match(runbook, /absenceVerifiedAt` is less than or equal/u);
  assert.match(runbook, /Single ambient-role execution/u);
  assert.match(runbook, /post-hoc finalizer reread/u);
  assert.match(runbook, /durationSeconds/u);
  assert.match(runbook, /min\(roleExpiresAt, deployerSessionExpiresAt\) - preCallNow/u);
  assert.match(runbook, /does not recompute that request/u);
  assert.match(runbook, /Fewer than 900 safe/u);
  assert.match(runbook, /maximum expiry across every parent-bound temporary/u);
  assert.match(runbook, /never proves already issued STS credentials revoked/u);
  assert.match(runbook, /runnerIdentity/u);
  assert.match(runbook, /productionDeployerIdentity/u);
  assert.match(runbook, /AssumeExactSeq159300CleanupSubmitter/u);
  assert.match(runbook, /AssumeExactSeq159300Finalizer/u);
  assert.match(runbook, /cleanupSubmitterExternalId/u);
  assert.match(runbook, /finalizer ExternalId is exactly `cleanupIntentSha384`/u);
  assert.match(runbook, /Both temporary session expirations must be no/u);
  assert.doesNotMatch(runbook, /finalizer has sole trust in that runner/u);
});

test('post-build cleanup renderer fails closed on replay, drift and Phase4 substitution', () => {
  const base = validPostBuildCleanupEvidence();
  const missingNamedResource = base.exactAbsenceInventory.filter(value =>
    value.resourceId !== 'layrs-production-recovery-seq159300-packer-control');
  const missingFinalizerGuard = base.exactAbsenceInventory.filter(value =>
    !value.resourceId.endsWith('layrs-production-recovery-seq159300-finalizer-window-guard'));
  const unreviewedAuthority = [...base.exactAbsenceInventory, {
    requestId: 'request-seq159300-unreviewed-role',
    resourceId: 'layrs-production-recovery-seq159300-unreviewed-role',
    resourceType: 'iam-role', serviceErrorCode: 'NoSuchEntityException',
  }].sort((left, right) => `${left.resourceType}\0${left.resourceId}`.localeCompare(`${right.resourceType}\0${right.resourceId}`));
  const duplicateRequestId = base.exactAbsenceInventory.map((value, index) => index === 1
    ? { ...value, requestId: base.exactAbsenceInventory[0].requestId } : value);
  const publicationRequestIdAlias = base.exactAbsenceInventory.map((value, index) => index === 0
    ? { ...value, requestId: base.postBuildPublisherRoleInventoryUploadRequestId } : value);
  let replacedIamCode = false;
  const cliIamCode = base.exactAbsenceInventory.map(value => {
    if (!replacedIamCode && value.resourceType === 'iam-role') {
      replacedIamCode = true;
      return { ...value, serviceErrorCode: 'NoSuchEntity' };
    }
    return value;
  });
  const stackCodeForChangeSet = base.exactAbsenceInventory.map(value =>
    value.resourceType === 'cloudformation-change-set'
      ? { ...value, serviceErrorCode: 'ValidationError' } : value);
  for (const invalid of [
    { phase4Authorized: true },
    { cleanupImplementationCommit: 'not-a-commit' },
    { cleanupImplementationCommit: '0'.repeat(40) },
    { cleanupTemplateEvidenceSha384: '0'.repeat(96) },
    { postBuildEvidencePublisherTemplateSha384: '0'.repeat(96) },
    { finalizerTemplateEvidenceSha384: '0'.repeat(96) },
    { productionDeployerTemplateEvidenceSha384: '0'.repeat(96) },
    { cleanupReceiptObjectVersionId: base.cleanupIntentObjectVersionId,
      cleanupReceiptObjectKey: base.cleanupIntentObjectKey },
    { cleanupReceiptObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/receipts/cleanup.json' },
    { postBuildEvidencePublisherTemplateObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/publisher/templates/mutable.yml' },
    { finalizerTemplateEvidenceObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/templates/mutable.yml' },
    { finalizerRoleInventoryObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/inventory/mutable.json' },
    { finalizerRoleInventoryObjectVersionId: base.finalizerTemplateEvidenceObjectVersionId },
    { productionDeployerTemplateEvidenceObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/deployer/templates/mutable.yml' },
    { productionDeployerRoleInventoryObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/deployer/inventory/mutable.json' },
    { retainedFinalizerStackInventoryObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/finalizer/stack-inventory/mutable.json' },
    { finalizerExpiresAt: '2026-08-24T09:00:00Z' },
    { finalizerApprovedAt: '2026-08-24T08:01:00Z' },
    { cleanupExpiresAt: '2026-08-24T08:57:00Z' },
    { cleanupSubmitterSession: { ...base.cleanupSubmitterSession,
      expiresAt: '2026-08-24T08:55:00Z' } },
    { cleanupSubmitterSession: { ...base.cleanupSubmitterSession,
      durationSeconds: 899, expiresAt: '2026-08-24T08:10:59Z' } },
    { cleanupSubmitterExternalId: base.cleanupIntentSha384 },
    { cleanupSubmitterExternalId: 'A'.repeat(96) },
    { cleanupExecutionRoleInventoryObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-execution/inventory/mutable.json' },
    { cleanupSubmitterRoleInventorySha384: base.cleanupExecutionRoleInventorySha384 },
    { cleanupExecutionRoleInventorySha384: base.finalizerRoleInventorySha384 },
    { postBuildPublisherRoleInventoryObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/post-build-evidence-publisher/inventory/mutable.json' },
    { postBuildPublisherRoleInventorySha384: base.finalizerRoleInventorySha384 },
    { postBuildPublisherRoleInventoryUploadRequestId:
      base.postBuildPublisherRoleInventoryReadbackRequestId },
    { postBuildPublisherRoleInventoryUploadedAt: '2026-08-24T07:58:59Z' },
    { postBuildPublisherRoleInventoryReadbackVerifiedAt: '2026-08-24T08:00:01Z' },
    { postBuildPublisherRoleInventoryUploadedAt: '2026-08-24T07:59:20.000Z' },
    { verifiedAt: '2026-08-24T08:00:00.000Z' },
    { finalizerSession: { ...base.finalizerSession,
      issuedAt: '2026-08-24T08:01:00Z' } },
    { postBuildPublisherExpiresAt: '2026-08-24T08:51:00Z' },
    { verifierRoleInventorySha384: 'c'.repeat(96) },
    { trustedPrincipalInventorySha384: base.finalizerRoleInventorySha384 },
    { productionDeployerRoleInventorySha384: base.finalizerRoleInventorySha384 },
    { productionDeployerRoleInventorySha384: base.trustedPrincipalInventorySha384 },
    { retainedSnapshotInventory: [] },
    { retainedEvidenceInventory: base.retainedEvidenceInventory.slice(1) },
    { exactAbsenceInventory: missingNamedResource,
      exactAbsenceInventorySha384: createHash('sha384').update(canonicalJson(missingNamedResource)).digest('hex') },
    { exactAbsenceInventory: missingFinalizerGuard,
      exactAbsenceInventorySha384: createHash('sha384').update(canonicalJson(missingFinalizerGuard)).digest('hex') },
    { exactAbsenceInventory: unreviewedAuthority,
      exactAbsenceInventorySha384: createHash('sha384').update(canonicalJson(unreviewedAuthority)).digest('hex') },
    { exactAbsenceInventory: duplicateRequestId,
      exactAbsenceInventorySha384: createHash('sha384').update(canonicalJson(duplicateRequestId)).digest('hex') },
    { exactAbsenceInventory: publicationRequestIdAlias,
      exactAbsenceInventorySha384:
        createHash('sha384').update(canonicalJson(publicationRequestIdAlias)).digest('hex') },
    { exactAbsenceInventory: cliIamCode,
      exactAbsenceInventorySha384: createHash('sha384').update(canonicalJson(cliIamCode)).digest('hex') },
    { exactAbsenceInventory: stackCodeForChangeSet,
      exactAbsenceInventorySha384: createHash('sha384').update(canonicalJson(stackCodeForChangeSet)).digest('hex') },
    { exactAbsenceInventorySha384: '0'.repeat(96) },
    { verifierIdentity: { ...base.verifierIdentity,
      arn: 'arn:aws:sts::082223548516:assumed-role/Admin/session1' } },
    { verifierIdentity: { ...base.verifierIdentity,
      principalId: 'AROABCDEFGHIJKLMNOP:different-session' } },
    { cleanupSubmitterIdentity: { ...base.cleanupSubmitterIdentity,
      arn: 'arn:aws:sts::082223548516:assumed-role/Admin/cleanup1' } },
    { runnerIdentity: { ...base.runnerIdentity,
      arn: 'arn:aws:sts::082223548516:assumed-role/Admin/runner1' } },
    { productionDeployerIdentity: { ...base.productionDeployerIdentity,
      arn: 'arn:aws:sts::082223548516:assumed-role/Admin/deployer1' } },
    { productionDeployerSession: { ...base.productionDeployerSession,
      durationSeconds: 899, expiresAt: '2026-08-24T08:08:59Z' } },
    { productionDeployerSession: { ...base.productionDeployerSession,
      expiresAt: '2026-08-24T08:53:00Z' } },
  ]) assert.throws(
    () => renderRecoveryParentPostBuildCleanupEvidence(validPostBuildCleanupEvidence(invalid)),
    /invalid|malformed|incomplete|omits|empty|outside|unique|unreviewed/u,
  );
});

test('Packer toolchain provenance is canonical, strict and cryptographically complete', () => {
  assert.equal(toolchainManifestBytes, `${canonicalJson(toolchainManifest)}\n`);
  assert.equal(
    createHash('sha256').update(toolchainManifestBytes).digest('hex'),
    '6a6d597535481836605a4cc9762755038e56e524af621356e5f5f65519c6858e',
  );
  assert.deepEqual(
    validatePreflight({ kind: 'packer-toolchain', payload: toolchainManifest }),
    toolchainManifest,
  );
  const tampered = structuredClone(toolchainManifest);
  tampered.cli.archiveSha256 = '0'.repeat(64);
  assert.throws(
    () => validatePreflight({ kind: 'packer-toolchain', payload: tampered }),
    /exact reviewed manifest/u,
  );
  assert.throws(
    () => validatePreflight({ kind: 'packer-toolchain', payload: { ...toolchainManifest, extra: true } }),
    /exact reviewed manifest/u,
  );
});

function validSourceAmiEnvelope() {
  return {
    kind: 'source-ami',
    payload: {
      expectedImageId: 'ami-0332d564d76dbd8d6',
      expectedOwnerId: '137112412989',
      response: { Images: [{
        Architecture: 'x86_64', BlockDeviceMappings: [{
          DeviceName: '/dev/xvda', Ebs: {
            DeleteOnTermination: true, Encrypted: false, SnapshotId: 'snap-0bc9cf3f9e4893b60',
            VolumeSize: 8, VolumeType: 'gp3',
          },
        }], BootMode: 'uefi-preferred', CreationDate: '2026-08-12T23:50:59.000Z',
        EnaSupport: true, ImageId: 'ami-0332d564d76dbd8d6',
        ImageLocation: 'amazon/al2023-ami-2023.12.20260817.0-kernel-6.18-x86_64',
        ImdsSupport: 'v2.0', Name: 'al2023-ami-2023.12.20260817.0-kernel-6.18-x86_64',
        OwnerId: '137112412989', PlatformDetails: 'Linux/UNIX', Public: true,
        RootDeviceName: '/dev/xvda', RootDeviceType: 'ebs', State: 'available',
        UsageOperation: 'RunInstances', VirtualizationType: 'hvm',
      }] },
      snapshotResponse: { Snapshots: [{
        Encrypted: false, OwnerId: '137112412989', SnapshotId: 'snap-0bc9cf3f9e4893b60',
        State: 'completed', StorageTier: 'standard', VolumeSize: 8,
      }] },
    },
  };
}

function validNetworkEnvelope() {
  return {
    kind: 'build-network',
    payload: {
      expectedSubnetId: 'subnet-0123456789abcdef0',
      expectedSecurityGroupId: 'sg-0123456789abcdef0',
      subnetsResponse: { Subnets: [{
        AssignIpv6AddressOnCreation: false, AvailabilityZone: 'us-east-1a', EnableDns64: false,
        Ipv6CidrBlockAssociationSet: [], Ipv6Native: false, MapPublicIpOnLaunch: false,
        State: 'available', SubnetId: 'subnet-0123456789abcdef0', VpcId: 'vpc-0123456789abcdef0',
      }] },
      vpcsResponse: { Vpcs: [{
        CidrBlock: '10.0.0.0/16', Ipv6CidrBlockAssociationSet: [], State: 'available',
        Tags: [{ Key: 'Purpose', Value: 'seq159300-recovery-build' }],
        VpcId: 'vpc-0123456789abcdef0',
      }] },
      routeTablesResponse: { RouteTables: [{
        Associations: [{ SubnetId: 'subnet-0123456789abcdef0' }],
        RouteTableId: 'rtb-0123456789abcdef0', VpcId: 'vpc-0123456789abcdef0',
        Routes: [
          { DestinationCidrBlock: '10.0.0.0/16', GatewayId: 'local', State: 'active' },
        ],
      }] },
      vpcEndpointsResponse: { VpcEndpoints: ['ec2messages', 'ssm', 'ssmmessages'].map((service, index) => ({
        Groups: [{ GroupId: 'sg-0fedcba9876543210' }],
        NetworkInterfaceIds: [`eni-0123456789abcde${index}`], PrivateDnsEnabled: true,
        DnsOptions: { DnsRecordIpType: 'ipv4' }, IpAddressType: 'ipv4',
        ServiceName: `com.amazonaws.us-east-1.${service}`, State: 'available',
        SubnetIds: ['subnet-0123456789abcdef0'],
        VpcEndpointId: `vpce-0123456789abcde${index}`, VpcEndpointType: 'Interface',
        VpcId: 'vpc-0123456789abcdef0',
      })) },
      networkInterfacesResponse: { NetworkInterfaces: [0, 1, 2].map(index => ({
        AvailabilityZone: 'us-east-1a', Groups: [{ GroupId: 'sg-0fedcba9876543210' }],
        InterfaceType: 'vpc_endpoint', NetworkInterfaceId: `eni-0123456789abcde${index}`,
        Ipv6Addresses: [], RequesterManaged: true, SubnetId: 'subnet-0123456789abcdef0',
        VpcId: 'vpc-0123456789abcdef0',
      })) },
      securityGroupsResponse: { SecurityGroups: [
        {
          GroupId: 'sg-0123456789abcdef0', GroupName: 'layrs-production-recovery-seq159300-builder',
          IpPermissions: [], IpPermissionsEgress: [{
            IpProtocol: '-1', IpRanges: [{ CidrIp: '127.0.0.1/32' }], Ipv6Ranges: [],
            PrefixListIds: [], UserIdGroupPairs: [],
          }, {
            FromPort: 443, IpProtocol: 'tcp', IpRanges: [], Ipv6Ranges: [], PrefixListIds: [],
            ToPort: 443, UserIdGroupPairs: [{ GroupId: 'sg-0fedcba9876543210' }],
          }], Tags: [{ Key: 'Purpose', Value: 'seq159300-recovery-build' }],
          VpcId: 'vpc-0123456789abcdef0',
        },
        {
          GroupId: 'sg-0fedcba9876543210', GroupName: 'layrs-seq159300-recovery-endpoints',
          IpPermissions: [{
            FromPort: 443, IpProtocol: 'tcp', IpRanges: [], Ipv6Ranges: [], PrefixListIds: [],
            ToPort: 443, UserIdGroupPairs: [{ GroupId: 'sg-0123456789abcdef0' }],
          }], IpPermissionsEgress: [],
          Tags: [{ Key: 'Purpose', Value: 'seq159300-recovery-endpoints' }],
          VpcId: 'vpc-0123456789abcdef0',
        },
      ] },
    },
  };
}

function validProfileEnvelope() {
  return {
    kind: 'instance-profile',
    payload: {
      expectedInstanceProfileName: 'layrs-production-recovery-seq159300-builder-instance',
      response: { InstanceProfile: {
        Arn: 'arn:aws:iam::082223548516:instance-profile/layrs-production-recovery-seq159300-builder-instance',
        InstanceProfileName: 'layrs-production-recovery-seq159300-builder-instance',
        Roles: [{
          Arn: 'arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-builder-instance',
          AssumeRolePolicyDocument: { Statement: [{
            Action: 'sts:AssumeRole', Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' },
          }], Version: '2012-10-17' },
          RoleName: 'layrs-production-recovery-seq159300-builder-instance',
        }],
      } },
      policies: [{
        document: { Statement: [{
          Action: [
            'ssm:DescribeAssociation', 'ssm:ListInstanceAssociations',
            'ssm:UpdateInstanceAssociationStatus', 'ssm:UpdateInstanceInformation',
            'ssmmessages:CreateControlChannel', 'ssmmessages:CreateDataChannel',
            'ssmmessages:OpenControlChannel', 'ssmmessages:OpenDataChannel',
            'ec2messages:AcknowledgeMessage', 'ec2messages:DeleteMessage',
            'ec2messages:FailMessage', 'ec2messages:GetEndpoint',
            'ec2messages:GetMessages', 'ec2messages:SendReply',
          ],
          Effect: 'Allow', Resource: '*',
        }], Version: '2012-10-17' },
        name: 'recovery-ssm', source: 'inline:layrs-production-recovery-seq159300-builder-instance:recovery-ssm',
      }],
    },
  };
}

function validPackerControlRoleEnvelope() {
  const approvedAt = '2026-08-24T03:00:00Z';
  const expiresAt = '2026-08-24T04:00:00Z';
  const invokerArn = 'arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-reviewer';
  const roleName = 'layrs-production-recovery-seq159300-packer-control';
  const inventoryDocument = {
    Version: '2012-10-17', Statement: [{
      Sid: 'DescribeExactRecoveryBuildBoundary', Effect: 'Allow',
      Action: [
        'ec2:DescribeAccountAttributes', 'ec2:DescribeAvailabilityZones', 'ec2:DescribeImages',
        'ec2:DescribeImageAttribute', 'ec2:DescribeInstances', 'ec2:DescribeInstanceStatus',
        'ec2:DescribeInstanceTypeOfferings', 'ec2:DescribeKeyPairs', 'ec2:DescribeNetworkInterfaces',
        'ec2:DescribeRegions', 'ec2:DescribeRouteTables', 'ec2:DescribeSecurityGroups',
        'ec2:DescribeSnapshots', 'ec2:DescribeSubnets', 'ec2:DescribeTags',
        'ec2:DescribeVolumes', 'ec2:DescribeVolumeStatus', 'ec2:DescribeVpcEndpoints',
        'ec2:DescribeVpcs', 'ssm:DescribeInstanceInformation',
      ], Resource: '*', Condition: { DateLessThan: { 'aws:CurrentTime': expiresAt } },
    }],
  };
  const launchDocument = { Version: '2012-10-17', Statement: [{
    Sid: 'RunExactRecoveryInstance', Effect: 'Allow', Action: 'ec2:RunInstances',
    Resource: 'arn:aws:ec2:us-east-1:082223548516:instance/*',
    Condition: { DateLessThan: { 'aws:CurrentTime': expiresAt } },
  }] };
  const artifactDocument = { Version: '2012-10-17', Statement: [{
    Sid: 'BuildPrivateRecoveryImage', Effect: 'Allow', Action: 'ec2:CreateImage',
    Resource: 'arn:aws:ec2:us-east-1:082223548516:instance/*',
    Condition: { DateLessThan: { 'aws:CurrentTime': expiresAt } },
  }] };
  const managedPolicy = (suffix, document) => ({
    arn: `arn:aws:iam::082223548516:policy/layrs-production-recovery-seq159300-packer-${suffix}`,
    defaultVersionId: 'v1', document,
    name: `layrs-production-recovery-seq159300-packer-${suffix}`,
    sha384: createHash('sha384').update(canonicalJson(document)).digest('hex'),
  });
  const attachedPolicies = [
    managedPolicy('artifacts', artifactDocument), managedPolicy('inventory', inventoryDocument),
    managedPolicy('launch', launchDocument),
  ];
  const artifactPolicySha384 = attachedPolicies[0].sha384;
  const inventoryPolicySha384 = attachedPolicies[1].sha384;
  const launchPolicySha384 = attachedPolicies[2].sha384;
  const tags = [
    ['Name', roleName], ['Application', 'layrs'], ['Environment', 'production'],
    ['Purpose', 'seq159300-recovery-ami-build-control'], ['RecoverySourceCommit', SOURCE_COMMIT],
    ['BuilderTemplateSha384', SHA384], ['OfflinePackageSetSha384', SHA384],
    ['OfflinePackageClosureSha384', SHA384], ['EvidenceIndexSha384', SHA384],
    ['InvokerRoleInventorySha384', SHA384], ['InvokerTemplateSha384', SHA384],
    ['InvokerEvidenceSha384', SHA384], ['PackerAmazonPluginVersion', '1.3.9'],
    ['PackerAmazonPluginCommit', '2a769c39a05940e25143098f071490732fa24f4f'],
    ['Phase2RecoveryTemplateSha384', SHA384],
    ['PackerInventoryPolicySha384', inventoryPolicySha384],
    ['PackerLaunchPolicySha384', launchPolicySha384],
    ['PackerArtifactPolicySha384', artifactPolicySha384],
  ].map(([Key, Value]) => ({ Key, Value }));
  const trust = {
    Version: '2012-10-17', Statement: [{
      Effect: 'Allow', Principal: { AWS: invokerArn }, Action: 'sts:AssumeRole',
      Condition: {
        ArnEquals: { 'aws:PrincipalArn': invokerArn },
        StringEquals: { 'aws:PrincipalAccount': '082223548516', 'sts:ExternalId': SHA384 },
        DateGreaterThanEquals: { 'aws:CurrentTime': approvedAt },
        DateLessThan: { 'aws:CurrentTime': expiresAt },
      },
    }],
  };
  const document = {
    Version: '2012-10-17', Statement: [{
      Sid: 'DenyBeforeExactApproval', Effect: 'Deny', Action: '*', Resource: '*',
      Condition: { DateLessThan: { 'aws:CurrentTime': approvedAt } },
    }, {
      Sid: 'DenyAfterExactExpiry', Effect: 'Deny', Action: '*', Resource: '*',
      Condition: { DateGreaterThanEquals: { 'aws:CurrentTime': expiresAt } },
    }],
  };
  const outputs = {
    BuilderEvidenceIndexSha384: SHA384, BuilderTemplateSha384: SHA384,
    OfflinePackageClosureSha384: SHA384, OfflinePackageSetSha384: SHA384,
    PackerControlPlaneApprovedAt: approvedAt, PackerControlPlaneExpiresAt: expiresAt,
    PackerControlPlaneMaxLifetimeSeconds: '3600',
    PackerControlPlaneRoleArn: `arn:aws:iam::082223548516:role/${roleName}`,
    PackerInvokerRoleArn: invokerArn, PackerInvokerRoleInventorySha384: SHA384,
    PackerInvokerTemplateSha384: SHA384, PackerInvokerEvidenceSha384: SHA384,
    PackerAmazonPluginVersion: '1.3.9',
    PackerAmazonPluginSourceCommit: '2a769c39a05940e25143098f071490732fa24f4f',
    PackerControlInventoryPolicyArn: attachedPolicies[1].arn,
    PackerControlInventoryPolicySha384: inventoryPolicySha384,
    PackerControlLaunchPolicyArn: attachedPolicies[2].arn,
    PackerControlLaunchPolicySha384: launchPolicySha384,
    PackerControlArtifactPolicyArn: attachedPolicies[0].arn,
    PackerControlArtifactPolicySha384: artifactPolicySha384,
    Phase2RecoveryTemplateSha384: SHA384,
  };
  return { kind: 'packer-control-role', payload: {
    approvedAt, attachedPolicies, builderEvidenceIndexSha384: SHA384,
    builderTemplateSha384: SHA384, evaluatedAt: '2026-08-24T03:30:00Z',
    expectedInvokerRoleArn: invokerArn, expiresAt, inlinePolicies: [{ name: roleName, document }],
    invokerRoleInventorySha384: SHA384, offlinePackageClosureSha384: SHA384,
    offlinePackageSetSha384: SHA384, packerInvokerTemplateSha384: SHA384,
    packerInvokerEvidenceSha384: SHA384, packerAmazonPluginVersion: '1.3.9',
    packerAmazonPluginSourceCommit: '2a769c39a05940e25143098f071490732fa24f4f',
    packerControlInventoryPolicySha384: inventoryPolicySha384,
    packerControlLaunchPolicySha384: launchPolicySha384,
    packerControlArtifactPolicySha384: artifactPolicySha384,
    phase2TemplateSha384: SHA384,
    publisherTemplateObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/publisher/layrs-seq159300-recovery-template-publisher-${'4'.repeat(96)}.yml`,
    publisherTemplateObjectVersionId: 'publisher.template.version.1',
    publisherTemplateSha384: '4'.repeat(96),
    templateUploadReceiptObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/template-upload.json',
    templateUploadReceiptObjectVersionId: 'template.upload.receipt.version.1',
    templateUploadReceiptSha384: '7'.repeat(96),
    changeSetReceiptObjectKey:
      'evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/change-set.json',
    changeSetReceiptObjectVersionId: 'change.set.receipt.version.1',
    changeSetReceiptSha384: '8'.repeat(96),
    roleResponse: { Role: {
      Arn: `arn:aws:iam::082223548516:role/${roleName}`, AssumeRolePolicyDocument: trust,
      MaxSessionDuration: 3600, Path: '/', RoleName: roleName, Tags: tags,
    } },
    stackResponse: { Stacks: [{
      StackName: 'layrs-production-recovery-seq159300-builder', StackStatus: 'CREATE_COMPLETE',
      Outputs: Object.entries(outputs)
      .map(([OutputKey, OutputValue]) => ({ OutputKey, OutputValue })) }] },
  } };
}

function validPackageSetEnvelope() {
  const packages = [
    {
      filename: 'aws-nitro-enclaves-cli-1.4.2.rpm',
      name: 'aws-nitro-enclaves-cli',
      nevra: 'aws-nitro-enclaves-cli-0:1.4.2-1.amzn2023.x86_64',
      objectKey: 'evidence/seq159300/recovery-only/phase2/packages/aws-nitro-enclaves-cli-1.4.2.rpm',
      objectVersionId: 'package.cli.version.1', sha384: SHA384,
    },
    {
      filename: 'libnsm-1.4.2.rpm', name: 'libnsm',
      nevra: 'libnsm-0:1.4.2-1.amzn2023.x86_64',
      objectKey: 'evidence/seq159300/recovery-only/phase2/packages/libnsm-1.4.2.rpm',
      objectVersionId: 'package.libnsm.version.1', sha384: '4'.repeat(96),
    },
  ];
  const packageClosureSha384 = createHash('sha384').update(canonicalJson(
    packages.map(({ name, nevra }) => ({ name, nevra })),
  )).digest('hex');
  return { kind: 'nitro-package-set', payload: {
    expectedPackageClosureSha384: packageClosureSha384,
    manifest: {
      protocol: 'layrs.seq159300.nitro-offline-package-set.v2', accountId: '082223548516',
      region: 'us-east-1', environment: 'production', packageClosureSha384,
      signingKeyFingerprint: AMAZON_KEY_FINGERPRINT, signingKeySha256: AMAZON_KEY_SHA256,
      packages,
    },
  } };
}

function validPublicationEvidenceEnvelope() {
  const builderKey = `evidence/seq159300/recovery-only/phase2/builder/templates/layrs-seq159300-recovery-builder-${SHA384}.yml`;
  const builderVersion = 'builder.template.version.1';
  const bucket = 'layrs-production-082223548516-us-east-1-immutable';
  const policyHash = document => createHash('sha384').update(canonicalJson(document)).digest('hex');
  const inlineDocument = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'ec2:DescribeVpcs', Resource: '*' }] };
  const managed = [
    'layrs-production-recovery-seq159300-cfn-core-network',
    'layrs-production-recovery-seq159300-cfn-endpoints',
    'layrs-production-recovery-seq159300-cfn-mutation',
  ].map((name, index) => {
    const document = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: `ec2:Test${index}`, Resource: '*' }] };
    return { arn: `arn:aws:iam::082223548516:policy/${name}`, defaultVersionId: 'v1', document,
      name, sha384: policyHash(document) };
  });
  const executionPolicies = { inline: { document: inlineDocument,
    name: 'layrs-seq159300-exact-builder-stack-base', sha384: policyHash(inlineDocument) }, managed };
  const executionPolicySha384 = policyHash(executionPolicies);
  return { kind: 'publication-evidence', payload: {
    builderTemplateObjectKey: builderKey,
    builderTemplateObjectVersionId: builderVersion,
    builderTemplateSha384: SHA384,
    publisherTemplateObjectKey:
      `evidence/seq159300/recovery-only/phase2/builder/publisher/layrs-seq159300-recovery-template-publisher-${'4'.repeat(96)}.yml`,
    publisherTemplateObjectVersionId: 'publisher.template.version.1',
    publisherTemplateSha384: '4'.repeat(96),
    publisherRoleInventorySha384: '5'.repeat(96),
    cloudFormationExecutionRoleInventorySha384: '6'.repeat(96),
    templateUploadReceipt: {
      protocol: 'layrs.seq159300.recovery-builder-template-upload-receipt.v1',
      accountId: '082223548516', region: 'us-east-1', bucket,
      objectKey: builderKey, objectVersionId: builderVersion, objectSha384: SHA384,
      bucketControlsSha384: 'e'.repeat(96), bucketKeyEnabled: false, createOnly: true,
      kmsKeyArn: 'arn:aws:kms:us-east-1:082223548516:key/11111111-2222-3333-4444-555555555555',
      retainUntil: '2026-09-24T00:00:00Z',
      publisherPolicySha384: '7'.repeat(96), publisherRoleInventorySha384: '5'.repeat(96),
      bucketPolicySha384: 'c'.repeat(96), kmsKeyPolicySha384: 'd'.repeat(96),
      publisherTemplateObject: {
        bucket,
        key: `evidence/seq159300/recovery-only/phase2/builder/publisher/layrs-seq159300-recovery-template-publisher-${'4'.repeat(96)}.yml`,
        versionId: 'publisher.template.version.1', sha384: '4'.repeat(96),
      },
    },
    changeSetReceipt: {
      protocol: 'layrs.seq159300.recovery-builder-change-set-receipt.v1',
      accountId: '082223548516', region: 'us-east-1',
      templateObject: { bucket, key: builderKey, versionId: builderVersion, sha384: SHA384 },
      kms: { keyArn: 'arn:aws:kms:us-east-1:082223548516:key/11111111-2222-3333-4444-555555555555', bucketKeyEnabled: false },
      templateUrl: `https://${bucket}.s3.us-east-1.amazonaws.com/${builderKey}?versionId=${builderVersion}`,
      publisherRoleArn: 'arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-template-publisher',
      executionRoleArn: 'arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-cloudformation-execution',
      publisherPolicySha384: '7'.repeat(96),
      cloudFormationExecutionPolicies: executionPolicies,
      cloudFormationExecutionPolicySha384: executionPolicySha384,
      publisherRoleInventorySha384: '5'.repeat(96),
      cloudFormationExecutionRoleInventorySha384: '6'.repeat(96),
      bucketControlsSha384: 'e'.repeat(96), bucketPolicySha384: 'c'.repeat(96),
      kmsKeyPolicySha384: 'd'.repeat(96),
      publisherTemplateObject: {
        bucket,
        key: `evidence/seq159300/recovery-only/phase2/builder/publisher/layrs-seq159300-recovery-template-publisher-${'4'.repeat(96)}.yml`,
        versionId: 'publisher.template.version.1', sha384: '4'.repeat(96),
      },
      parameters: {
        BuilderTemplateEvidenceObjectKey: builderKey,
        BuilderTemplateEvidenceObjectVersionId: builderVersion,
        BuilderTemplateEvidenceSha384: SHA384,
        BuilderTemplateSha384: SHA384,
      },
      parametersSha384: '61c87e4c37006002a03addb662390ef6036c18a0d1acef6de4b16a4287fd726ae6ff7f9a4a6668b29faadbe2e50f10ea',
      validationSha384: 'a'.repeat(96),
      changeSetId: `arn:aws:cloudformation:us-east-1:082223548516:changeSet/layrs-seq159300-builder-${SHA384.slice(0, 12)}/11111111-2222-3333-4444-555555555555`,
      changeSetName: `layrs-seq159300-builder-${SHA384.slice(0, 12)}`,
      changeSetStatus: 'CREATE_COMPLETE', executionStatus: 'AVAILABLE', stable: true,
      changesSha384: 'b'.repeat(96), executed: false,
    },
  } };
}

test('publication evidence binds exact immutable template and unexecuted receipts', () => {
  const output = validatePreflight(validPublicationEvidenceEnvelope());
  assert.equal(output.changeSetReceipt.executed, false);
  for (const mutate of [
    envelope => { envelope.payload.templateUploadReceipt.objectVersionId = 'substituted.version'; },
    envelope => { envelope.payload.changeSetReceipt.executed = true; },
    envelope => { envelope.payload.changeSetReceipt.changeSetStatus = 'CREATE_IN_PROGRESS'; },
    envelope => { envelope.payload.changeSetReceipt.executionStatus = 'UNAVAILABLE'; },
    envelope => { envelope.payload.changeSetReceipt.changeSetName = 'layrs-seq159300-builder-000000000000'; },
    envelope => { envelope.payload.changeSetReceipt.parametersSha384 = '0'.repeat(96); },
    envelope => { envelope.payload.changeSetReceipt.parameters.BuilderTemplateSha384 = '0'.repeat(96); },
    envelope => { envelope.payload.changeSetReceipt.bucketControlsSha384 = '0'.repeat(96); },
    envelope => { envelope.payload.changeSetReceipt.cloudFormationExecutionPolicies.managed[0].document.Statement[0].Action = '*'; },
    envelope => { envelope.payload.changeSetReceipt.publisherRoleArn
      = 'arn:aws:iam::082223548516:role/other'; },
    envelope => { envelope.payload.changeSetReceipt.templateObject.sha384 = '0'.repeat(96); },
    envelope => { envelope.payload.publisherRoleInventorySha384 = '0'.repeat(95); },
    envelope => { envelope.payload.cloudFormationExecutionRoleInventorySha384
      = envelope.payload.publisherRoleInventorySha384; },
    envelope => { envelope.payload.changeSetReceipt.secret = 'forbidden'; },
  ]) {
    const envelope = validPublicationEvidenceEnvelope();
    mutate(envelope);
    assert.throws(() => validatePreflight(envelope));
  }
});

test('offline Nitro manifest binds the exact signed dependency closure', () => {
  const output = validatePreflight(validPackageSetEnvelope());
  assert.equal(output.packages.length, 2);
  for (const mutate of [
    envelope => { envelope.payload.manifest.packages[0].objectVersionId = 'short'; },
    envelope => { envelope.payload.manifest.packages[0].filename = '../escape.rpm'; },
    envelope => { envelope.payload.manifest.packages[1].nevra = 'aws-nitro-enclaves-cli-devel-0:1-1.x86_64'; },
    envelope => { envelope.payload.manifest.packages.splice(1, 1); },
    envelope => { envelope.payload.manifest.packages.reverse(); },
    envelope => { envelope.payload.manifest.signingKeyFingerprint = '0'.repeat(40); },
    envelope => { envelope.payload.manifest.signingKeySha256 = '0'.repeat(64); },
    envelope => { envelope.payload.expectedPackageClosureSha384 = '0'.repeat(96); },
  ]) {
    const envelope = validPackageSetEnvelope();
    mutate(envelope);
    assert.throws(() => validatePreflight(envelope));
  }
});

test('Packer control-role preflight binds exact trust, policy, tags, boundary and expiry', () => {
  const output = validatePreflight(validPackerControlRoleEnvelope());
  assert.equal(output.roleName, 'layrs-production-recovery-seq159300-packer-control');
  assert.equal(output.permissionsBoundaryArn, '');
  assert.equal(Object.hasOwn(output, 'evaluatedAt'), false);
  for (const mutate of [
    envelope => { envelope.payload.roleResponse.Role.RoleName = 'layrs-production-recovery-seq159300-other'; },
    envelope => { envelope.payload.roleResponse.Role.PermissionsBoundary = { PermissionsBoundaryArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }; },
    envelope => { envelope.payload.roleResponse.Role.AssumeRolePolicyDocument.Statement[0]
      .Condition.DateGreaterThanEquals['aws:CurrentTime'] = '2026-08-24T02:59:59Z'; },
    envelope => { envelope.payload.inlinePolicies[0].document.Statement[0]
      .Condition.DateLessThan['aws:CurrentTime'] = '2026-08-24T05:00:00Z'; },
    envelope => { envelope.payload.attachedPolicies[1].document.Statement[0].Action
      = envelope.payload.attachedPolicies[1].document.Statement[0].Action
        .filter(action => action !== 'ec2:DescribeVpcEndpoints'); },
    envelope => { envelope.payload.inlinePolicies[0].document.Statement
      .find(statement => statement.Sid === 'DenyBeforeExactApproval')
      .Condition.DateLessThan['aws:CurrentTime'] = '2026-08-24T02:59:59Z'; },
    envelope => envelope.payload.attachedPolicies.push({ PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }),
    envelope => { envelope.payload.roleResponse.Role.Tags[0].Value = 'different'; },
    envelope => { envelope.payload.stackResponse.Stacks[0].Outputs
      .find(outputItem => outputItem.OutputKey === 'OfflinePackageClosureSha384').OutputValue = '4'.repeat(96); },
    envelope => { envelope.payload.stackResponse.Stacks[0].Outputs
      .find(outputItem => outputItem.OutputKey === 'Phase2RecoveryTemplateSha384').OutputValue = '4'.repeat(96); },
    envelope => { envelope.payload.stackResponse.Stacks[0].Outputs
      .find(outputItem => outputItem.OutputKey === 'PackerControlInventoryPolicySha384').OutputValue = '0'.repeat(96); },
    envelope => { envelope.payload.roleResponse.Role.Tags
      .find(tag => tag.Key === 'PackerArtifactPolicySha384').Value = '0'.repeat(96); },
    envelope => { envelope.payload.changeSetReceiptObjectVersionId = 'short'; },
    envelope => { envelope.payload.stackResponse.Stacks[0].StackStatus = 'UPDATE_ROLLBACK_IN_PROGRESS'; },
    envelope => envelope.payload.stackResponse.Stacks[0].Outputs.push({
      OutputKey: 'BuilderTemplateSha384', OutputValue: SHA384,
    }),
    envelope => { envelope.payload.evaluatedAt = envelope.payload.expiresAt; },
  ]) {
    const envelope = validPackerControlRoleEnvelope();
    mutate(envelope);
    assert.throws(() => validatePreflight(envelope));
  }
});

test('read-only preflight canonicalizes exact source, private network and minimal profile', () => {
  const source = validatePreflight(validSourceAmiEnvelope());
  const network = validatePreflight(validNetworkEnvelope());
  const profile = validatePreflight(validProfileEnvelope());
  assert.equal(source.ownerId, '137112412989');
  assert.equal(network.subnet.mapPublicIpOnLaunch, false);
  assert.deepEqual(network.routes.map(route => route.target.field), ['GatewayId']);
  assert.equal(profile.roleName, 'layrs-production-recovery-seq159300-builder-instance');
});

test('source AMI rejects every provenance and root-snapshot substitution', () => {
  for (const mutate of [
    envelope => { envelope.payload.response.Images[0].ImageId = 'ami-0aaaaaaaaaaaaaaaa'; },
    envelope => { envelope.payload.response.Images[0].Name = 'al2023-latest'; },
    envelope => { envelope.payload.response.Images[0].ImageLocation = 'other/location'; },
    envelope => { envelope.payload.response.Images[0].CreationDate = '2026-08-13T00:00:00.000Z'; },
    envelope => { envelope.payload.response.Images[0].ImdsSupport = 'v1.0'; },
    envelope => { envelope.payload.response.Images[0].BootMode = 'legacy-bios'; },
    envelope => { envelope.payload.response.Images[0].BlockDeviceMappings[0].Ebs.SnapshotId = 'snap-0aaaaaaaaaaaaaaaa'; },
    envelope => { envelope.payload.response.Images[0].BlockDeviceMappings[0].Ebs.VolumeSize = 30; },
    envelope => { envelope.payload.snapshotResponse.Snapshots[0].OwnerId = '082223548516'; },
    envelope => { envelope.payload.snapshotResponse.Snapshots[0].Encrypted = true; },
  ]) {
    const envelope = validSourceAmiEnvelope();
    mutate(envelope);
    assert.throws(() => validatePreflight(envelope), /mechanically pinned/u);
  }
});

test('read-only preflight rejects public/NAT routes and public security-group egress', () => {
  for (const mutate of [
    envelope => envelope.payload.routeTablesResponse.RouteTables[0].Routes.push({
      DestinationCidrBlock: '0.0.0.0/0', NatGatewayId: 'nat-0123456789abcdef0', State: 'active',
    }),
    envelope => envelope.payload.securityGroupsResponse.SecurityGroups[0].IpPermissionsEgress[0]
      .IpRanges.push({ CidrIp: '0.0.0.0/0' }),
    envelope => { envelope.payload.subnetsResponse.Subnets[0].MapPublicIpOnLaunch = true; },
    envelope => { envelope.payload.vpcEndpointsResponse.VpcEndpoints[0].ServiceName = 'com.amazonaws.us-east-1.kms'; },
    envelope => { envelope.payload.networkInterfacesResponse.NetworkInterfaces[0].InterfaceType = 'interface'; },
    envelope => { envelope.payload.networkInterfacesResponse.NetworkInterfaces[0].AvailabilityZone = 'us-east-1b'; },
    envelope => { envelope.payload.networkInterfacesResponse.NetworkInterfaces[0].Ipv6Addresses = [{ Ipv6Address: '2001:db8::1' }]; },
    envelope => { envelope.payload.vpcEndpointsResponse.VpcEndpoints[0].SubnetIds = ['subnet-0aaaaaaaaaaaaaaaa']; },
    envelope => { envelope.payload.vpcEndpointsResponse.VpcEndpoints[0].IpAddressType = 'dualstack'; },
    envelope => { envelope.payload.subnetsResponse.Subnets[0].AssignIpv6AddressOnCreation = true; },
    envelope => envelope.payload.subnetsResponse.Subnets[0].Ipv6CidrBlockAssociationSet.push({
      AssociationId: 'subnet-cidr-assoc-1', Ipv6CidrBlock: '2001:db8::/64',
    }),
    envelope => envelope.payload.vpcsResponse.Vpcs[0].Ipv6CidrBlockAssociationSet.push({
      AssociationId: 'vpc-cidr-assoc-1', Ipv6CidrBlock: '2001:db8::/56',
    }),
    envelope => envelope.payload.routeTablesResponse.RouteTables[0].Routes.push({
      DestinationIpv6CidrBlock: '::/0', EgressOnlyInternetGatewayId: 'eigw-0123456789abcdef0', State: 'active',
    }),
    envelope => { envelope.payload.vpcEndpointsResponse.VpcEndpoints.pop(); },
    envelope => envelope.payload.routeTablesResponse.RouteTables[0].Routes.push({
      DestinationPrefixListId: 'pl-0123456789abcdef0', VpcEndpointId: 'vpce-0123456789abcde0', State: 'active',
    }),
  ]) {
    const envelope = validNetworkEnvelope();
    mutate(envelope);
    assert.throws(
      () => validatePreflight(envelope),
      /public|IPv6|endpoint-SG-only|private available|private control-plane endpoint|attached outside|three exact SSM|forbidden target/u,
    );
  }
});

test('read-only preflight rejects secret, KMS, data and production-route authority', () => {
  for (const action of [
    'kms:Decrypt', 'secretsmanager:GetSecretValue', 's3:GetObject', 'ssm:GetParameter',
    'rds-data:ExecuteStatement', 'dynamodb:GetItem', 'ec2:CreateRoute',
    'elasticloadbalancing:RegisterTargets', 'iam:PassRole', 'sts:AssumeRole',
  ]) {
    const envelope = validProfileEnvelope();
    envelope.payload.policies[0].document.Statement[0].Action = action;
    assert.throws(() => validatePreflight(envelope), /forbidden action/u);
  }
  const notAction = validProfileEnvelope();
  delete notAction.payload.policies[0].document.Statement[0].Action;
  notAction.payload.policies[0].document.Statement[0].NotAction = 'kms:Decrypt';
  assert.throws(() => validatePreflight(notAction), /NotAction/u);
  const unrelated = validProfileEnvelope();
  unrelated.payload.policies[0].document.Statement[0].Action = 'ec2:TerminateInstances';
  assert.throws(() => validatePreflight(unrelated), /minimal recovery allowlist/u);
});

test('output AMI readback rejects public, unencrypted or provenance-swapped images', () => {
  const expected = {
    buildControlPlaneRoleInventorySha384: SHA384, builderTemplateSha384: SHA384,
    buildInstanceProfileInventorySha384: SHA384, buildSecurityGroupInventorySha384: SHA384,
    buildSubnetInventorySha384: SHA384, parentPackageCommit: PARENT_PACKAGE_COMMIT,
    eifSha384: EIF_SHA384,
    imageId: 'ami-0123456789abcdef0', implementationCommit: IMPLEMENTATION_COMMIT,
    parentSha384: PARENT_SHA384, pcr0Sha384: PCR0_SHA384,
    nitroCliRpmSha384: SHA384, nitroPackageInventorySha384: SHA384,
    nitroPackageSetSha384: SHA384, nitroPackageClosureSha384: SHA384,
    packerInvokerRoleInventorySha384: SHA384,
    packerTemplateSha384: SHA384,
    phase2TemplateCommit: PHASE2_TEMPLATE_COMMIT,
    phase2TemplateSha384: PHASE2_TEMPLATE_SHA384,
    recoveryEvidenceIndexSha384: SHA384,
    sourceAmiId: 'ami-0332d564d76dbd8d6', sourceAmiProvenanceSha384: SHA384,
    sourceCommit: SOURCE_COMMIT,
  };
  const tags = [
    ['BuildControlPlaneRoleSha384', SHA384],
    ['BuildInstanceProfileSha384', SHA384], ['BuildSecurityGroupSha384', SHA384],
    ['BuildSubnetInventorySha384', SHA384],
    ['GateImplementationCommit', IMPLEMENTATION_COMMIT],
    ['Phase2TemplateCommit', PHASE2_TEMPLATE_COMMIT],
    ['Phase2TemplateSha384', PHASE2_TEMPLATE_SHA384],
    ['PackerTemplateSha384', SHA384],
    ['RecoveryParentPackageCommit', PARENT_PACKAGE_COMMIT],
    ['RecoveryEifSha384', EIF_SHA384], ['RecoveryParentSha384', PARENT_SHA384],
    ['RecoveryPcr0Sha384', PCR0_SHA384], ['RecoverySourceCommit', SOURCE_COMMIT],
    ['SourceAmiProvenanceSha384', SHA384], ['NitroCliRpmSha384', SHA384],
    ['NitroPackageInventorySha384', SHA384],
    ['NitroPackageSetSha384', SHA384],
    ['NitroPackageClosureSha384', SHA384],
    ['PackerInvokerRoleSha384', SHA384],
    ['RecoveryBuilderTemplateSha384', SHA384],
    ['RecoveryEvidenceIndexSha384', SHA384], ['RecoveryPackageSetSha384', SHA384],
    ['Visibility', 'private'],
  ].map(([Key, Value]) => ({ Key, Value }));
  const valid = { kind: 'output-ami', payload: { expected, response: { Images: [{
    Architecture: 'x86_64', BlockDeviceMappings: [{
      DeviceName: '/dev/xvda', Ebs: { Encrypted: true, SnapshotId: 'snap-0123456789abcdef0', VolumeSize: 8, VolumeType: 'gp3' },
    }], ImageId: expected.imageId, OwnerId: '082223548516', Public: false,
    RootDeviceName: '/dev/xvda', RootDeviceType: 'ebs', SourceImageId: expected.sourceAmiId,
    SourceImageRegion: 'us-east-1', State: 'available', Tags: tags,
  }] } } };
  assert.equal(validatePreflight(valid).public, false);
  for (const mutate of [
    envelope => { envelope.payload.response.Images[0].Public = true; },
    envelope => { envelope.payload.response.Images[0].BlockDeviceMappings[0].Ebs.Encrypted = false; },
    envelope => { envelope.payload.response.Images[0].SourceImageId = 'ami-0aaaaaaaaaaaaaaaa'; },
  ]) {
    const envelope = structuredClone(valid);
    mutate(envelope);
    assert.throws(() => validatePreflight(envelope), /readback does not match/u);
  }
});
