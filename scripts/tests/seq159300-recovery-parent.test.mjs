import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  renderRecoveryParentBuildEvidence,
} from '../render-seq159300-recovery-parent-evidence.mjs';

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
const runbook = readFileSync(
  resolve(ROOT, 'docs/runbooks/LAYRS_SEQ159300_RECOVERY_PARENT_AMI.md'),
  'utf8',
);

const SOURCE_COMMIT = 'f282583cae7a5c873a26aa8d0c1bec10c490eb8e';
const IMPLEMENTATION_COMMIT = '9e21c925d121822019524ec3d9b4973b1a32f38a';
const PARENT_SHA384 = 'd9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1';
const EIF_SHA384 = '958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290';
const REJECTED_BUILD_A_EIF = '110c31235f36fa85e4a50d61fb89ab3a08e5b18587a35dfe4818c3615eed5a79513082df101e5c655fce8c7640d66ad8';
const PCR0_SHA384 = '57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac';

function validEvidence(overrides = {}) {
  return {
    protocol: 'layrs.seq159300.recovery-parent-build-evidence.v1',
    accountId: '082223548516',
    region: 'us-east-1',
    environment: 'production',
    implementationCommit: IMPLEMENTATION_COMMIT,
    remediationEvidenceCommit: '540fc566c83dee2c3226862cc71a95541bc69af7',
    remediationIndexObjectVersionId: 'oBGf0odkWa6tzYpml_UtGemDwXI6GdXy',
    sourceCommit: SOURCE_COMMIT,
    amiId: 'ami-0123456789abcdef0',
    parentBinarySha384: PARENT_SHA384,
    eifSha384: EIF_SHA384,
    pcr0Sha384: PCR0_SHA384,
    buildCompletedAt: '2026-08-24T03:30:00.000Z',
    ...overrides,
  };
}

test('Packer source is pinned, private and recovery-only', () => {
  assert.match(packer, /version\s*=\s*"= 1\.3\.9"/u);
  assert.match(packer, /image-id\s*=\s*var\.source_ami_id/u);
  assert.match(packer, /owners\s*=\s*\[var\.source_ami_owner\]/u);
  assert.match(packer, /most_recent\s*=\s*false/u);
  assert.match(packer, /associate_public_ip_address\s*=\s*false/u);
  assert.match(packer, /ssh_interface\s*=\s*"session_manager"/u);
  assert.match(packer, /layrs-seq159300-recovery/u);
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
  assert.doesNotMatch(packer, /layrs-production|target.?group|cloudflare|route53/iu);
});

test('Packer copies only the accepted existing runtime artifacts and existing services', () => {
  assert.match(packer, /source\s*=\s*"build\/layrs-enclave-parent"/u);
  assert.match(packer, /source\s*=\s*"build\/layrsv2-clob\.eif"/u);
  assert.match(packer, new RegExp(`printf '[^']+' '[^']*${PARENT_SHA384}`, 'u'));
  assert.match(packer, new RegExp(`printf '[^']+' '[^']*${EIF_SHA384}`, 'u'));
  assert.equal((packer.match(/sha384sum -c -/gu) ?? []).length, 2);
  assert.doesNotMatch(packer, /cargo build|nitro-cli build-enclave|docker build/iu);
  const enableLines = packer.match(/sudo systemctl enable[^"\n]+/gu) ?? [];
  assert.deepEqual(enableLines, [
    'sudo systemctl enable nitro-enclaves-allocator.service layrsv2-enclave.service layrsv2-enclave-parent.service layrsv2-enclave-watchdog.timer',
  ]);
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
  assert.match(wrapper, /status --porcelain=v1 --untracked-files=all/u);
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
  assert.match(wrapper, /packer_bin.*command -v packer/u);
  assert.match(wrapper, /"\$\{packer_bin\}" build -color=false -force=false/u);
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
    { implementationCommit: 'not-a-commit' },
    { remediationIndexObjectVersionId: 'different' },
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
    () => renderRecoveryParentBuildEvidence(validEvidence({ buildCompletedAt: '2026-08-24T03:30:00Z' })),
    /binding is invalid/u,
  );
});
