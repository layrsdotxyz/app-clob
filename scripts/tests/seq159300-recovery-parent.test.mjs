import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  renderRecoveryParentBuildEvidence,
} from '../render-seq159300-recovery-parent-evidence.mjs';
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
const runbook = readFileSync(
  resolve(ROOT, 'docs/runbooks/LAYRS_SEQ159300_RECOVERY_PARENT_AMI.md'),
  'utf8',
);

const SOURCE_COMMIT = 'f282583cae7a5c873a26aa8d0c1bec10c490eb8e';
const IMPLEMENTATION_COMMIT = '9e21c925d121822019524ec3d9b4973b1a32f38a';
const BUILDER_SOURCE_COMMIT = '24405e0da728e237dc851915bcdb60c6ee1db5bb';
const PHASE2_TEMPLATE_COMMIT = 'e93b3658f034f07fb9d0b867d448a07813fb1fce';
const SHA384 = '3'.repeat(96);
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
    implementationEvidenceObjectKey: 'evidence/seq159300/recovery-only/implementation/backend.json',
    implementationEvidenceObjectVersionId: 'implementation.version.1',
    implementationEvidenceObjectSha384: SHA384,
    builderSourceCommit: BUILDER_SOURCE_COMMIT,
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
    nitroPackageSetEvidenceObjectKey: 'evidence/seq159300/recovery-only/phase2/packages/nitro-package-set-evidence.json',
    nitroPackageSetEvidenceObjectVersionId: 'package.evidence.version.1',
    nitroPackageSetEvidenceSha384: SHA384,
    outputAmiInventorySha384: SHA384,
    packerManifestSha384: SHA384,
    packerTemplateSha384: SHA384,
    phase2EvidenceObjectKey: 'evidence/seq159300/recovery-only/phase2/rendered-phase2.json',
    phase2EvidenceObjectVersionId: 'phase2.version.1',
    phase2EvidenceObjectSha384: SHA384,
    phase2TemplateCommit: PHASE2_TEMPLATE_COMMIT,
    phase2TemplateSha384: SHA384,
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
  assert.match(packer, /allowed_account_ids\s*=\s*\["082223548516"\]/u);
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
  assert.match(wrapper, /layrs-production-recovery-seq159300-packer-/u);
  assert.match(wrapper, /assumed-role/u);
  assert.match(wrapper, /LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID/u);
  assert.doesNotMatch(wrapper, /dnf download|reposync|curl|wget/iu);
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
  assert.match(wrapper, /LAYRS_RECOVERY_BUILDER_COMMIT/u);
  assert.match(wrapper, /active AWS account/u);
  assert.match(wrapper, /sts get-caller-identity/u);
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
    { builderSourceCommit: SOURCE_COMMIT },
    { implementationCommit: 'not-a-commit' },
    { nitroCliRpmSha384: '0'.repeat(95) },
    { phase2EvidenceObjectKey: '../mutable.json' },
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
        AvailabilityZone: 'us-east-1a', MapPublicIpOnLaunch: false,
        State: 'available', SubnetId: 'subnet-0123456789abcdef0', VpcId: 'vpc-0123456789abcdef0',
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
        ServiceName: `com.amazonaws.us-east-1.${service}`, State: 'available',
        SubnetIds: ['subnet-0123456789abcdef0'],
        VpcEndpointId: `vpce-0123456789abcde${index}`, VpcEndpointType: 'Interface',
        VpcId: 'vpc-0123456789abcdef0',
      })) },
      networkInterfacesResponse: { NetworkInterfaces: [0, 1, 2].map(index => ({
        AvailabilityZone: 'us-east-1a', Groups: [{ GroupId: 'sg-0fedcba9876543210' }],
        InterfaceType: 'vpc_endpoint', NetworkInterfaceId: `eni-0123456789abcde${index}`,
        RequesterManaged: true, SubnetId: 'subnet-0123456789abcdef0',
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

function validPackageSetEnvelope() {
  const packages = [
    {
      filename: 'aws-nitro-enclaves-cli-1.4.2.rpm',
      nevra: 'aws-nitro-enclaves-cli-0:1.4.2-1.amzn2023.x86_64',
      objectKey: 'evidence/seq159300/recovery-only/phase2/packages/aws-nitro-enclaves-cli-1.4.2.rpm',
      objectVersionId: 'package.cli.version.1', sha384: SHA384, signatureKeyId: 'D832C631',
    },
    {
      filename: 'libnsm-1.4.2.rpm', nevra: 'libnsm-0:1.4.2-1.amzn2023.x86_64',
      objectKey: 'evidence/seq159300/recovery-only/phase2/packages/libnsm-1.4.2.rpm',
      objectVersionId: 'package.libnsm.version.1', sha384: '4'.repeat(96), signatureKeyId: 'D832C631',
    },
  ];
  return { kind: 'nitro-package-set', payload: { manifest: {
    protocol: 'layrs.seq159300.nitro-offline-package-set.v1', accountId: '082223548516',
    region: 'us-east-1', environment: 'production', packages,
  } } };
}

test('offline Nitro manifest binds the exact signed dependency closure', () => {
  const output = validatePreflight(validPackageSetEnvelope());
  assert.equal(output.packages.length, 2);
  for (const mutate of [
    envelope => { envelope.payload.manifest.packages[0].objectVersionId = 'short'; },
    envelope => { envelope.payload.manifest.packages[0].filename = '../escape.rpm'; },
    envelope => { envelope.payload.manifest.packages[1].nevra = 'aws-nitro-enclaves-cli-devel-0:1-1.x86_64'; },
    envelope => { envelope.payload.manifest.packages.splice(1, 1); },
    envelope => { envelope.payload.manifest.packages.reverse(); },
  ]) {
    const envelope = validPackageSetEnvelope();
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
    envelope => { envelope.payload.vpcEndpointsResponse.VpcEndpoints[0].SubnetIds = ['subnet-0aaaaaaaaaaaaaaaa']; },
    envelope => { envelope.payload.vpcEndpointsResponse.VpcEndpoints.pop(); },
    envelope => envelope.payload.routeTablesResponse.RouteTables[0].Routes.push({
      DestinationPrefixListId: 'pl-0123456789abcdef0', VpcEndpointId: 'vpce-0123456789abcde0', State: 'active',
    }),
  ]) {
    const envelope = validNetworkEnvelope();
    mutate(envelope);
    assert.throws(
      () => validatePreflight(envelope),
      /public|endpoint-SG-only|private available|private control-plane endpoint|attached outside|three exact SSM|forbidden target/u,
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
    buildInstanceProfileInventorySha384: SHA384, buildSecurityGroupInventorySha384: SHA384,
    buildSubnetInventorySha384: SHA384, builderSourceCommit: BUILDER_SOURCE_COMMIT,
    eifSha384: EIF_SHA384,
    imageId: 'ami-0123456789abcdef0', implementationCommit: IMPLEMENTATION_COMMIT,
    parentSha384: PARENT_SHA384, pcr0Sha384: PCR0_SHA384,
    nitroCliRpmSha384: SHA384, nitroPackageInventorySha384: SHA384,
    nitroPackageSetSha384: SHA384,
    packerTemplateSha384: SHA384,
    phase2TemplateCommit: PHASE2_TEMPLATE_COMMIT, phase2TemplateSha384: SHA384,
    sourceAmiId: 'ami-0332d564d76dbd8d6', sourceAmiProvenanceSha384: SHA384,
    sourceCommit: SOURCE_COMMIT,
  };
  const tags = [
    ['BuildInstanceProfileSha384', SHA384], ['BuildSecurityGroupSha384', SHA384],
    ['BuildSubnetInventorySha384', SHA384],
    ['GateImplementationCommit', IMPLEMENTATION_COMMIT],
    ['Phase2TemplateCommit', PHASE2_TEMPLATE_COMMIT],
    ['Phase2TemplateSha384', SHA384],
    ['PackerTemplateSha384', SHA384],
    ['RecoveryBuilderSourceCommit', BUILDER_SOURCE_COMMIT],
    ['RecoveryEifSha384', EIF_SHA384], ['RecoveryParentSha384', PARENT_SHA384],
    ['RecoveryPcr0Sha384', PCR0_SHA384], ['RecoverySourceCommit', SOURCE_COMMIT],
    ['SourceAmiProvenanceSha384', SHA384], ['NitroCliRpmSha384', SHA384],
    ['NitroPackageInventorySha384', SHA384],
    ['NitroPackageSetSha384', SHA384],
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
