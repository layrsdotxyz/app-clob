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

const FIELDS = Object.freeze([
  'accountId', 'amiId', 'buildCompletedAt', 'builderSourceCommit',
  'buildInstanceProfileInventorySha384', 'buildSecurityGroupInventorySha384',
  'buildSubnetInventorySha384', 'eifSha384', 'environment', 'implementationCommit',
  'implementationEvidenceObjectKey', 'implementationEvidenceObjectVersionId',
  'implementationEvidenceSha384', 'nitroCliNevra', 'nitroCliRpmObjectKey',
  'nitroCliRpmObjectVersionId', 'nitroCliRpmSha384', 'nitroPackageInventorySha384',
  'outputAmiInventorySha384', 'packerManifestSha384', 'packerTemplateSha384',
  'parentBinarySha384', 'pcr0Sha384', 'phase2EvidenceObjectKey',
  'phase2EvidenceObjectVersionId', 'phase2EvidenceSha384', 'phase2TemplateCommit',
  'phase2TemplateSha384', 'protocol', 'region',
  'remediationEvidenceCommit', 'remediationIndexObjectVersionId', 'sourceCommit',
  'sourceAmiId', 'sourceAmiOwner', 'sourceAmiProvenanceSha384',
]);

function immutableObjectKey(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/u.test(value)
    && !value.includes('..');
}

function immutableVersionId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{1,1024}$/u.test(value);
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
  const completedAt = new Date(input.buildCompletedAt);
  if (input.protocol !== 'layrs.seq159300.recovery-parent-build-evidence.v1'
      || input.accountId !== ACCOUNT_ID || input.region !== REGION
      || input.environment !== 'production' || input.sourceCommit !== SOURCE_COMMIT
      || !/^[0-9a-f]{40}$/u.test(input.builderSourceCommit)
      || input.builderSourceCommit === SOURCE_COMMIT
      || !/^[0-9a-f]{40}$/u.test(input.implementationCommit)
      || !/^[0-9a-f]{40}$/u.test(input.phase2TemplateCommit)
      || input.remediationEvidenceCommit !== REMEDIATION_COMMIT
      || input.remediationIndexObjectVersionId !== REMEDIATION_INDEX_VERSION
      || input.parentBinarySha384 !== PARENT_SHA384 || input.eifSha384 !== EIF_SHA384
      || input.pcr0Sha384 !== PCR0_SHA384 || !/^ami-[0-9a-f]{8,17}$/u.test(input.amiId)
      || !/^ami-[0-9a-f]{8,17}$/u.test(input.sourceAmiId)
      || input.sourceAmiOwner !== '137112412989'
      || !/^aws-nitro-enclaves-cli-[0-9]+:?[A-Za-z0-9._+~]+-[A-Za-z0-9._+~]+\.x86_64$/u.test(input.nitroCliNevra)
      || !immutableObjectKey(input.phase2EvidenceObjectKey)
      || !immutableObjectKey(input.implementationEvidenceObjectKey)
      || !immutableObjectKey(input.nitroCliRpmObjectKey)
      || !immutableVersionId(input.phase2EvidenceObjectVersionId)
      || !immutableVersionId(input.implementationEvidenceObjectVersionId)
      || !immutableVersionId(input.nitroCliRpmObjectVersionId)
      || [
        input.buildInstanceProfileInventorySha384, input.buildSecurityGroupInventorySha384,
        input.buildSubnetInventorySha384, input.implementationEvidenceSha384,
        input.nitroCliRpmSha384, input.nitroPackageInventorySha384, input.outputAmiInventorySha384,
        input.packerManifestSha384, input.packerTemplateSha384, input.phase2EvidenceSha384,
        input.phase2TemplateSha384, input.sourceAmiProvenanceSha384,
      ].some(value => !/^[0-9a-f]{96}$/u.test(value))
      || !Number.isFinite(completedAt.getTime())
      || completedAt.toISOString() !== input.buildCompletedAt) {
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
