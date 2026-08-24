#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const ACCOUNT_ID = '082223548516';
const REGION = 'us-east-1';
const SOURCE_AMI = Object.freeze({
  architecture: 'x86_64',
  bootMode: 'uefi-preferred',
  creationDate: '2026-08-12T23:50:59.000Z',
  imageId: 'ami-0332d564d76dbd8d6',
  imageLocation: 'amazon/al2023-ami-2023.12.20260817.0-kernel-6.18-x86_64',
  imdsSupport: 'v2.0',
  name: 'al2023-ami-2023.12.20260817.0-kernel-6.18-x86_64',
  ownerId: '137112412989',
  platformDetails: 'Linux/UNIX',
  rootDeviceName: '/dev/xvda',
  rootSnapshotId: 'snap-0bc9cf3f9e4893b60',
  usageOperation: 'RunInstances',
  virtualizationType: 'hvm',
});
const REQUIRED_SSM_SERVICES = Object.freeze([
  `com.amazonaws.${REGION}.ec2messages`,
  `com.amazonaws.${REGION}.ssm`,
  `com.amazonaws.${REGION}.ssmmessages`,
]);
const FORBIDDEN_ACTIONS = [
  /^\*$/iu,
  /^kms:/iu,
  /^secretsmanager:/iu,
  /^s3:/iu,
  /^ssm:getparameter/iu,
  /^rds(?:-data)?:/iu,
  /^dynamodb:/iu,
  /^iam:passrole$/iu,
  /^sts:assumerole$/iu,
  /^ec2:(?:create|replace|delete|associate|disassociate).*route/iu,
  /^ec2:modifysubnetattribute$/u,
  /^elasticloadbalancing:/iu,
  /^route53:/iu,
  /^ecs:(?:run|start)task$/iu,
];
const ALLOWED_BUILD_ROLE_ACTIONS = new Set([
  'ec2messages:acknowledgemessage', 'ec2messages:deletemessage',
  'ec2messages:failmessage', 'ec2messages:getendpoint', 'ec2messages:getmessages',
  'ec2messages:sendreply', 'ssm:describeassociation', 'ssm:listinstanceassociations',
  'ssm:updateinstanceassociationstatus', 'ssm:updateinstanceinformation',
  'ssmmessages:createcontrolchannel', 'ssmmessages:createdatachannel',
  'ssmmessages:opencontrolchannel', 'ssmmessages:opendatachannel',
]);

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('canonical JSON numbers must be safe integers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error('unsupported canonical JSON value');
}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireExactFields(value, fields, label) {
  requireObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} field set is invalid`);
  }
}

function one(values, label) {
  if (!Array.isArray(values) || values.length !== 1) throw new Error(`${label} must contain exactly one item`);
  return requireObject(values[0], `${label}[0]`);
}

function normalizedTags(tags) {
  if (!Array.isArray(tags)) return [];
  return tags.map(tag => ({ key: String(tag.Key ?? ''), value: String(tag.Value ?? '') }))
    .sort((left, right) => left.key.localeCompare(right.key) || left.value.localeCompare(right.value));
}

function normalizedPermission(permission) {
  return {
    fromPort: Number.isInteger(permission.FromPort) ? permission.FromPort : null,
    ipProtocol: String(permission.IpProtocol ?? ''),
    ipv4Ranges: (permission.IpRanges ?? []).map(range => String(range.CidrIp ?? '')).sort(),
    ipv6Ranges: (permission.Ipv6Ranges ?? []).map(range => String(range.CidrIpv6 ?? '')).sort(),
    prefixListIds: (permission.PrefixListIds ?? []).map(value => String(value.PrefixListId ?? '')).sort(),
    referencedGroupIds: (permission.UserIdGroupPairs ?? []).map(value => String(value.GroupId ?? '')).sort(),
    toPort: Number.isInteger(permission.ToPort) ? permission.ToPort : null,
  };
}

function validateSourceAmi(input) {
  requireExactFields(input, ['expectedImageId', 'expectedOwnerId', 'response', 'snapshotResponse'], 'source AMI preflight');
  const image = one(requireObject(input.response, 'source AMI response').Images, 'source AMI response.Images');
  const snapshot = one(requireObject(input.snapshotResponse, 'source snapshot response').Snapshots,
    'source snapshot response.Snapshots');
  if (input.expectedImageId !== SOURCE_AMI.imageId || input.expectedOwnerId !== SOURCE_AMI.ownerId
      || image.ImageId !== SOURCE_AMI.imageId || image.OwnerId !== SOURCE_AMI.ownerId
      || image.State !== 'available' || image.Architecture !== 'x86_64'
      || image.RootDeviceType !== 'ebs' || image.VirtualizationType !== 'hvm'
      || image.EnaSupport !== true || image.Name !== SOURCE_AMI.name
      || image.ImageLocation !== SOURCE_AMI.imageLocation
      || image.CreationDate !== SOURCE_AMI.creationDate
      || image.PlatformDetails !== SOURCE_AMI.platformDetails
      || image.UsageOperation !== SOURCE_AMI.usageOperation
      || image.ImdsSupport !== SOURCE_AMI.imdsSupport
      || image.BootMode !== SOURCE_AMI.bootMode
      || image.RootDeviceName !== SOURCE_AMI.rootDeviceName
      || image.Public !== true || !Array.isArray(image.BlockDeviceMappings)
      || image.BlockDeviceMappings.length !== 1
      || image.BlockDeviceMappings[0]?.DeviceName !== SOURCE_AMI.rootDeviceName
      || image.BlockDeviceMappings[0]?.Ebs?.SnapshotId !== SOURCE_AMI.rootSnapshotId
      || image.BlockDeviceMappings[0]?.Ebs?.DeleteOnTermination !== true
      || image.BlockDeviceMappings[0]?.Ebs?.Encrypted !== false
      || image.BlockDeviceMappings[0]?.Ebs?.VolumeSize !== 8
      || image.BlockDeviceMappings[0]?.Ebs?.VolumeType !== 'gp3'
      || snapshot.SnapshotId !== SOURCE_AMI.rootSnapshotId
      || snapshot.OwnerId !== SOURCE_AMI.ownerId || snapshot.State !== 'completed'
      || snapshot.Encrypted !== false || snapshot.VolumeSize !== 8
      || snapshot.StorageTier !== 'standard') {
    throw new Error('source AMI does not match the mechanically pinned AL2023 provenance');
  }
  return {
    architecture: image.Architecture,
    blockDeviceMappings: image.BlockDeviceMappings.map(mapping => ({
      deviceName: String(mapping.DeviceName ?? ''),
      ebs: mapping.Ebs ? {
        deleteOnTermination: Boolean(mapping.Ebs.DeleteOnTermination),
        encrypted: Boolean(mapping.Ebs.Encrypted),
        snapshotId: String(mapping.Ebs.SnapshotId ?? ''),
        volumeSize: Number(mapping.Ebs.VolumeSize ?? 0),
        volumeType: String(mapping.Ebs.VolumeType ?? ''),
      } : null,
    })).sort((left, right) => left.deviceName.localeCompare(right.deviceName)),
    bootMode: String(image.BootMode ?? ''),
    enaSupport: image.EnaSupport,
    imageId: image.ImageId,
    imageLocation: image.ImageLocation,
    creationDate: image.CreationDate,
    imdsSupport: image.ImdsSupport,
    name: image.Name,
    ownerId: image.OwnerId,
    platformDetails: image.PlatformDetails,
    public: Boolean(image.Public),
    rootDeviceName: image.RootDeviceName,
    rootDeviceType: image.RootDeviceType,
    state: image.State,
    rootSnapshot: {
      encrypted: snapshot.Encrypted,
      ownerId: snapshot.OwnerId,
      snapshotId: snapshot.SnapshotId,
      state: snapshot.State,
      storageTier: snapshot.StorageTier,
      volumeSize: snapshot.VolumeSize,
    },
    usageOperation: image.UsageOperation,
    virtualizationType: image.VirtualizationType,
  };
}

function routeTarget(route) {
  const targets = [
    'CarrierGatewayId', 'CoreNetworkArn', 'EgressOnlyInternetGatewayId', 'GatewayId',
    'InstanceId', 'LocalGatewayId', 'NatGatewayId', 'NetworkInterfaceId',
    'TransitGatewayId', 'VpcPeeringConnectionId', 'VpcEndpointId',
  ].filter(field => route[field]);
  if (targets.length !== 1) throw new Error('each build route must have one exact target');
  const field = targets[0];
  const value = String(route[field]);
  if (!(field === 'GatewayId' && value === 'local')) {
    throw new Error(`build route has forbidden target ${field}`);
  }
  return { field, value };
}

function validateBuildNetwork(input) {
  requireExactFields(
    input,
    ['expectedSecurityGroupId', 'expectedSubnetId', 'networkInterfacesResponse',
      'routeTablesResponse', 'securityGroupsResponse', 'subnetsResponse', 'vpcEndpointsResponse'],
    'build network preflight',
  );
  const subnet = one(requireObject(input.subnetsResponse, 'subnets response').Subnets, 'subnets response.Subnets');
  if (subnet.SubnetId !== input.expectedSubnetId || subnet.State !== 'available'
      || subnet.MapPublicIpOnLaunch !== false || !/^vpc-[0-9a-f]{8,17}$/u.test(String(subnet.VpcId ?? ''))) {
    throw new Error('build subnet is not the exact private available subnet');
  }

  const routeTables = requireObject(input.routeTablesResponse, 'route tables response').RouteTables;
  if (!Array.isArray(routeTables) || routeTables.length < 1) throw new Error('no applicable build route table was found');
  const routes = [];
  for (const table of routeTables) {
    if (table.VpcId !== subnet.VpcId || !Array.isArray(table.Routes)) {
      throw new Error('build route table belongs to a different VPC or is malformed');
    }
    const applies = (table.Associations ?? []).some(association => (
      association.SubnetId === subnet.SubnetId || association.Main === true
    ));
    if (!applies) throw new Error('route table is not associated with the build subnet or its VPC main route');
    for (const route of table.Routes) {
      if (route.State && route.State !== 'active') throw new Error('build route is not active');
      if (route.DestinationCidrBlock === '0.0.0.0/0' || route.DestinationIpv6CidrBlock === '::/0') {
        throw new Error('build route permits public default egress');
      }
      const target = routeTarget(route);
      routes.push({
        destination: String(route.DestinationCidrBlock ?? route.DestinationIpv6CidrBlock
          ?? route.DestinationPrefixListId ?? ''),
        routeTableId: String(table.RouteTableId ?? ''),
        state: String(route.State ?? 'active'),
        target,
      });
    }
  }

  const securityGroups = requireObject(input.securityGroupsResponse, 'security groups response').SecurityGroups;
  if (!Array.isArray(securityGroups)) throw new Error('security groups response is malformed');
  const buildGroup = securityGroups.find(group => group.GroupId === input.expectedSecurityGroupId);
  if (!buildGroup || buildGroup.VpcId !== subnet.VpcId
      || !String(buildGroup.GroupName ?? '').startsWith('layrs-production-recovery-seq159300-')
      || (buildGroup.IpPermissions ?? []).length !== 0
      || !Array.isArray(buildGroup.IpPermissionsEgress) || buildGroup.IpPermissionsEgress.length < 1) {
    throw new Error('build security group is not the exact ingress-free recovery group');
  }
  const referencedIds = new Set();
  let sentinelCount = 0;
  for (const permission of buildGroup.IpPermissionsEgress) {
    const sentinel = String(permission.IpProtocol) === '-1'
      && (permission.IpRanges ?? []).length === 1
      && permission.IpRanges[0]?.CidrIp === '127.0.0.1/32'
      && !(permission.Ipv6Ranges ?? []).length && !(permission.PrefixListIds ?? []).length
      && !(permission.UserIdGroupPairs ?? []).length;
    if (sentinel) {
      sentinelCount += 1;
      continue;
    }
    if (!['tcp', '6'].includes(String(permission.IpProtocol))
        || permission.FromPort !== 443 || permission.ToPort !== 443
        || (permission.IpRanges ?? []).length || (permission.Ipv6Ranges ?? []).length
        || (permission.PrefixListIds ?? []).length || !(permission.UserIdGroupPairs ?? []).length) {
      throw new Error('build security-group egress is not endpoint-SG-only TCP/443');
    }
    for (const pair of permission.UserIdGroupPairs) referencedIds.add(String(pair.GroupId ?? ''));
  }
  if (sentinelCount !== 1 || referencedIds.size < 1) {
    throw new Error('build security group requires one loopback sentinel and exact endpoint egress');
  }
  for (const referencedId of referencedIds) {
    const group = securityGroups.find(candidate => candidate.GroupId === referencedId);
    const tags = normalizedTags(group?.Tags);
    const recoveryNamed = /seq159300.*recovery|recovery.*seq159300/iu.test(String(group?.GroupName ?? ''));
    const recoveryTagged = tags.some(tag => tag.key === 'Purpose'
      && /seq159300.*recovery|recovery.*seq159300/iu.test(tag.value));
    if (!group || group.VpcId !== subnet.VpcId || !(recoveryNamed || recoveryTagged)) {
      throw new Error('build security-group egress references a non-recovery group');
    }
    for (const permission of group.IpPermissions ?? []) {
      if (!['tcp', '6'].includes(String(permission.IpProtocol))
          || permission.FromPort !== 443 || permission.ToPort !== 443
          || (permission.IpRanges ?? []).length || (permission.Ipv6Ranges ?? []).length
          || (permission.PrefixListIds ?? []).length
          || !(permission.UserIdGroupPairs ?? []).length
          || (permission.UserIdGroupPairs ?? []).some(pair => pair.GroupId !== buildGroup.GroupId)) {
        throw new Error('recovery endpoint security-group ingress is not builder-SG-only TCP/443');
      }
    }
    if (!(group.IpPermissions ?? []).length) {
      throw new Error('recovery endpoint security group has no exact builder ingress');
    }
  }

  const allowedServices = new Set(REQUIRED_SSM_SERVICES);
  const endpoints = requireObject(input.vpcEndpointsResponse, 'VPC endpoints response').VpcEndpoints;
  const interfaces = requireObject(input.networkInterfacesResponse, 'network interfaces response').NetworkInterfaces;
  if (!Array.isArray(endpoints) || !Array.isArray(interfaces)) throw new Error('endpoint inventory is malformed');
  const endpointInterfaceIds = new Set();
  const observedServices = new Set();
  for (const referencedId of referencedIds) {
    const matches = endpoints.filter(endpoint => (endpoint.Groups ?? []).some(group => group.GroupId === referencedId));
    if (matches.length < 1) throw new Error('recovery endpoint security group must bind private VPC endpoints');
    for (const endpoint of matches) {
      if (endpoint.VpcId !== subnet.VpcId || endpoint.VpcEndpointType !== 'Interface'
          || endpoint.State !== 'available' || endpoint.PrivateDnsEnabled !== true
          || !allowedServices.has(endpoint.ServiceName)
          || !Array.isArray(endpoint.SubnetIds) || endpoint.SubnetIds.length !== 1
          || endpoint.SubnetIds[0] !== subnet.SubnetId
          || !Array.isArray(endpoint.NetworkInterfaceIds)
          || endpoint.NetworkInterfaceIds.length !== 1) {
        throw new Error('build security-group destination is not an allowed private control-plane endpoint');
      }
      observedServices.add(endpoint.ServiceName);
      for (const interfaceId of endpoint.NetworkInterfaceIds ?? []) endpointInterfaceIds.add(interfaceId);
    }
  }
  for (const networkInterface of interfaces) {
    if (networkInterface.VpcId !== subnet.VpcId || networkInterface.InterfaceType !== 'vpc_endpoint'
        || networkInterface.RequesterManaged !== true
        || networkInterface.SubnetId !== subnet.SubnetId
        || networkInterface.AvailabilityZone !== subnet.AvailabilityZone
        || !endpointInterfaceIds.has(networkInterface.NetworkInterfaceId)) {
      throw new Error('recovery endpoint security group is attached outside reviewed VPC endpoints');
    }
  }
  if (interfaces.length !== endpointInterfaceIds.size
      || interfaces.some(networkInterface => !(networkInterface.Groups ?? [])
        .some(group => referencedIds.has(group.GroupId)))) {
    throw new Error('VPC endpoint network-interface inventory is incomplete');
  }
  if (observedServices.size !== REQUIRED_SSM_SERVICES.length
      || REQUIRED_SSM_SERVICES.some(service => !observedServices.has(service))
      || endpoints.filter(endpoint => (endpoint.Groups ?? [])
        .some(group => referencedIds.has(group.GroupId))).length !== REQUIRED_SSM_SERVICES.length) {
    throw new Error('all three exact SSM interface endpoints are required in the build subnet and AZ');
  }
  return {
    endpoints: endpoints.filter(endpoint => (endpoint.Groups ?? [])
      .some(group => referencedIds.has(group.GroupId))).map(endpoint => ({
      networkInterfaceIds: [...(endpoint.NetworkInterfaceIds ?? [])].sort(),
      privateDnsEnabled: endpoint.PrivateDnsEnabled,
      serviceName: endpoint.ServiceName,
      state: endpoint.State,
      subnetIds: [...endpoint.SubnetIds].sort(),
      vpcEndpointId: endpoint.VpcEndpointId,
      vpcEndpointType: endpoint.VpcEndpointType,
      vpcId: endpoint.VpcId,
    })).sort((left, right) => left.vpcEndpointId.localeCompare(right.vpcEndpointId)),
    routeTables: routeTables.map(table => String(table.RouteTableId ?? '')).sort(),
    routes: routes.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))),
    securityGroups: securityGroups.map(group => ({
      egress: (group.IpPermissionsEgress ?? []).map(normalizedPermission)
        .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))),
      groupId: String(group.GroupId ?? ''),
      groupName: String(group.GroupName ?? ''),
      ingress: (group.IpPermissions ?? []).map(normalizedPermission)
        .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))),
      tags: normalizedTags(group.Tags),
      vpcId: String(group.VpcId ?? ''),
    })).sort((left, right) => left.groupId.localeCompare(right.groupId)),
    subnet: {
      availabilityZone: String(subnet.AvailabilityZone ?? ''),
      mapPublicIpOnLaunch: subnet.MapPublicIpOnLaunch,
      subnetId: subnet.SubnetId,
      vpcId: subnet.VpcId,
    },
  };
}

function validatePackageSet(input) {
  requireExactFields(input, ['manifest'], 'Nitro package-set preflight');
  const manifest = requireObject(input.manifest, 'Nitro package-set manifest');
  requireExactFields(manifest, [
    'accountId', 'environment', 'packages', 'protocol', 'region',
  ], 'Nitro package-set manifest');
  if (manifest.protocol !== 'layrs.seq159300.nitro-offline-package-set.v1'
      || manifest.accountId !== ACCOUNT_ID || manifest.region !== REGION
      || manifest.environment !== 'production'
      || !Array.isArray(manifest.packages) || manifest.packages.length < 2) {
    throw new Error('Nitro package-set manifest binding is invalid');
  }
  const seenFiles = new Set();
  const seenNevras = new Set();
  let hasCli = false;
  const packages = manifest.packages.map((entry, index) => {
    requireExactFields(entry, [
      'filename', 'nevra', 'objectKey', 'objectVersionId', 'sha384', 'signatureKeyId',
    ], `Nitro package-set packages[${index}]`);
    if (!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,180}\.rpm$/u.test(entry.filename)
        || !/^[A-Za-z0-9][A-Za-z0-9+_.:-]{0,220}\.(?:x86_64|noarch)$/u.test(entry.nevra)
        || !immutableKey(entry.objectKey) || !immutableVersion(entry.objectVersionId)
        || !entry.objectKey.startsWith('evidence/seq159300/recovery-only/phase2/')
        || !sha384(entry.sha384) || !/^[0-9A-F]{8,16}$/u.test(entry.signatureKeyId)
        || seenFiles.has(entry.filename) || seenNevras.has(entry.nevra)) {
      throw new Error('Nitro package-set package entry is invalid or duplicated');
    }
    seenFiles.add(entry.filename);
    seenNevras.add(entry.nevra);
    if (entry.nevra.startsWith('aws-nitro-enclaves-cli-')) hasCli = true;
    if (entry.nevra.startsWith('aws-nitro-enclaves-cli-devel-')) {
      throw new Error('Nitro development package is forbidden');
    }
    return { ...entry };
  }).sort((left, right) => left.nevra.localeCompare(right.nevra));
  if (!hasCli) throw new Error('Nitro package set must contain the exact CLI package');
  if (canonicalJson(packages) !== canonicalJson(manifest.packages)) {
    throw new Error('Nitro package-set packages must be canonical NEVRA order');
  }
  return { ...manifest, packages };
}

function immutableKey(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/u.test(value)
    && !value.includes('..');
}

function immutableVersion(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{8,256}$/u.test(value);
}

function sha384(value) {
  return typeof value === 'string' && /^[0-9a-f]{96}$/u.test(value);
}

function actions(statement) {
  if (Object.hasOwn(statement, 'NotAction')) throw new Error('build role Allow/NotAction is forbidden');
  const value = statement.Action;
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && value.every(action => typeof action === 'string')) return value;
  throw new Error('build role policy Action is malformed');
}

function validateInstanceProfile(input) {
  requireExactFields(input, ['expectedInstanceProfileName', 'policies', 'response'], 'instance-profile preflight');
  const profile = requireObject(requireObject(input.response, 'instance-profile response').InstanceProfile, 'instance profile');
  if (profile.InstanceProfileName !== input.expectedInstanceProfileName
      || !profile.InstanceProfileName.startsWith('layrs-production-recovery-seq159300-')
      || !String(profile.Arn ?? '').startsWith(`arn:aws:iam::${ACCOUNT_ID}:instance-profile/`)
      || !Array.isArray(profile.Roles) || profile.Roles.length !== 1) {
    throw new Error('build instance profile is not exact or does not contain one role');
  }
  const role = requireObject(profile.Roles[0], 'build role');
  if (!String(role.Arn ?? '').startsWith(`arn:aws:iam::${ACCOUNT_ID}:role/`)) {
    throw new Error('build role belongs to the wrong account');
  }
  const trustStatements = requireObject(role.AssumeRolePolicyDocument, 'build role trust').Statement;
  if (!Array.isArray(trustStatements) || trustStatements.length !== 1) throw new Error('build role trust must have one statement');
  const trust = requireObject(trustStatements[0], 'build role trust statement');
  const trustActions = typeof trust.Action === 'string' ? [trust.Action] : trust.Action;
  if (Object.hasOwn(trust, 'NotAction') || Object.hasOwn(trust, 'NotPrincipal')
      || Object.hasOwn(trust, 'NotResource') || trust.Effect !== 'Allow'
      || canonicalJson(trust.Principal) !== canonicalJson({ Service: 'ec2.amazonaws.com' })
      || !Array.isArray(trustActions) || trustActions.length !== 1 || trustActions[0] !== 'sts:AssumeRole') {
    throw new Error('build role trust is not EC2-only');
  }
  if (!Array.isArray(input.policies)) throw new Error('build role policies must be an array');
  const observedAllowedActions = new Set();
  for (const policy of input.policies) {
    requireExactFields(policy, ['document', 'name', 'source'], 'build role policy');
    const statements = requireObject(policy.document, `policy ${policy.name}`).Statement;
    const list = Array.isArray(statements) ? statements : [statements];
    for (const statement of list) {
      if (statement?.Effect !== 'Allow') continue;
      for (const action of actions(statement)) {
        if (FORBIDDEN_ACTIONS.some(pattern => pattern.test(action))) {
          throw new Error(`build role has forbidden action ${action}`);
        }
        if (!ALLOWED_BUILD_ROLE_ACTIONS.has(action.toLowerCase())) {
          throw new Error(`build role action is outside the minimal recovery allowlist: ${action}`);
        }
        observedAllowedActions.add(action.toLowerCase());
      }
    }
  }
  if (observedAllowedActions.size !== ALLOWED_BUILD_ROLE_ACTIONS.size
      || [...ALLOWED_BUILD_ROLE_ACTIONS].some(action => !observedAllowedActions.has(action))) {
    throw new Error('build role does not contain the exact complete SSM agent action set');
  }
  return {
    instanceProfileArn: profile.Arn,
    instanceProfileName: profile.InstanceProfileName,
    policies: input.policies.map(policy => ({
      document: policy.document,
      name: policy.name,
      source: policy.source,
    })).sort((left, right) => left.source.localeCompare(right.source) || left.name.localeCompare(right.name)),
    roleArn: role.Arn,
    roleName: role.RoleName,
    permissionsBoundaryArn: String(role.PermissionsBoundary?.PermissionsBoundaryArn ?? ''),
    trust: role.AssumeRolePolicyDocument,
  };
}

function validateOutputAmi(input) {
  requireExactFields(input, ['expected', 'response'], 'output AMI readback');
  const expected = requireObject(input.expected, 'output AMI expected values');
  const image = one(requireObject(input.response, 'output AMI response').Images, 'output AMI response.Images');
  const tags = new Map(normalizedTags(image.Tags).map(tag => [tag.key, tag.value]));
  const requiredTags = {
    BuildInstanceProfileSha384: expected.buildInstanceProfileInventorySha384,
    BuildSecurityGroupSha384: expected.buildSecurityGroupInventorySha384,
    BuildSubnetInventorySha384: expected.buildSubnetInventorySha384,
    GateImplementationCommit: expected.implementationCommit,
    Phase2TemplateCommit: expected.phase2TemplateCommit,
    Phase2TemplateSha384: expected.phase2TemplateSha384,
    PackerTemplateSha384: expected.packerTemplateSha384,
    RecoveryBuilderSourceCommit: expected.builderSourceCommit,
    RecoveryEifSha384: expected.eifSha384,
    RecoveryParentSha384: expected.parentSha384,
    RecoveryPcr0Sha384: expected.pcr0Sha384,
    RecoverySourceCommit: expected.sourceCommit,
    SourceAmiProvenanceSha384: expected.sourceAmiProvenanceSha384,
    NitroCliRpmSha384: expected.nitroCliRpmSha384,
    NitroPackageInventorySha384: expected.nitroPackageInventorySha384,
    NitroPackageSetSha384: expected.nitroPackageSetSha384,
    Visibility: 'private',
  };
  if (image.ImageId !== expected.imageId || image.OwnerId !== ACCOUNT_ID || image.Public !== false
      || image.State !== 'available' || image.Architecture !== 'x86_64'
      || image.RootDeviceType !== 'ebs' || image.SourceImageId !== expected.sourceAmiId
      || image.SourceImageRegion !== REGION
      || Object.entries(requiredTags).some(([key, value]) => tags.get(key) !== value)
      || !Array.isArray(image.BlockDeviceMappings)
      || image.BlockDeviceMappings.some(mapping => mapping.Ebs && mapping.Ebs.Encrypted !== true)) {
    throw new Error('output AMI readback does not match exact private recovery bindings');
  }
  return {
    architecture: image.Architecture,
    blockDeviceMappings: image.BlockDeviceMappings.map(mapping => ({
      deviceName: String(mapping.DeviceName ?? ''),
      encrypted: mapping.Ebs ? Boolean(mapping.Ebs.Encrypted) : null,
      snapshotId: String(mapping.Ebs?.SnapshotId ?? ''),
      volumeSize: Number(mapping.Ebs?.VolumeSize ?? 0),
      volumeType: String(mapping.Ebs?.VolumeType ?? ''),
    })).sort((left, right) => left.deviceName.localeCompare(right.deviceName)),
    imageId: image.ImageId,
    ownerId: image.OwnerId,
    public: image.Public,
    rootDeviceName: String(image.RootDeviceName ?? ''),
    rootDeviceType: image.RootDeviceType,
    sourceImageId: image.SourceImageId,
    sourceImageRegion: image.SourceImageRegion,
    state: image.State,
    tags: normalizedTags(image.Tags),
  };
}

export function validatePreflight(input) {
  requireObject(input, 'preflight envelope');
  switch (input.kind) {
    case 'source-ami': return validateSourceAmi(input.payload);
    case 'build-network': return validateBuildNetwork(input.payload);
    case 'instance-profile': return validateInstanceProfile(input.payload);
    case 'output-ami': return validateOutputAmi(input.payload);
    case 'nitro-package-set': return validatePackageSet(input.payload);
    default: throw new Error('unsupported recovery-parent preflight kind');
  }
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
  const result = validatePreflight(JSON.parse(readFileSync(paths.input, 'utf8')));
  writeFileSync(paths.output, Buffer.from(canonicalJson(result)), { flag: 'wx', mode: 0o600 });
}
