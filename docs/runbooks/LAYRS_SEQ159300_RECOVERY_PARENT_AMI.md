# Sequence 159300 recovery parent AMI

This path produces a private, recovery-only parent AMI from the already-built
and independently accepted f282 parent and EIF bytes. It does not rebuild or
modify either runtime artifact.

The wrapper fails closed unless all of these inputs are exact:

- source commit `f282583cae7a5c873a26aa8d0c1bec10c490eb8e`;
- `LAYRS_RECOVERY_BUILDER_COMMIT`, which must equal the clean app-clob
  checkout's exact HEAD and must differ from f282. This commit is evidence,
  not authorization, and is bound by the later signed gate;
- the exact lowercase 40-hex final integrated gate implementation commit,
  supplied only after the gate, harness and Phase2 IaC are integrated, plus
  the immutable object key, VersionId and SHA384 of its reviewed evidence;
- parent SHA384
  `d9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1`;
- accepted build-b EIF SHA384
  `958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290`;
- PCR0
  `57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac`;
- exact AL2023 AMI `ami-0332d564d76dbd8d6`, name and image location
  `al2023-ami-2023.12.20260817.0-kernel-6.18-x86_64` (the image location is
  `amazon/` plus that name), owner `137112412989`, creation time
  `2026-08-12T23:50:59.000Z`, Linux/UNIX platform, `RunInstances` operation,
  IMDS `v2.0`, `uefi-preferred` boot, `/dev/xvda` EBS root, and exact unencrypted
  8-GiB gp3 source snapshot `snap-0bc9cf3f9e4893b60`; and
- the app-backend/IaC commit and SHA384 of the separately reviewed Phase2 isolation template,
  plus the immutable object key, VersionId and SHA384 of its evidence;
- the separate SHA384 of the accepted recovery-builder CloudFormation template;
- the SHA384 calculated directly from this Packer template; and
- one canonical immutable Nitro package-set manifest at
  `build/seq159300-nitro-package-set.json` and its complete regular-file RPM
  closure at `build/seq159300-nitro-packages/`. Every entry binds filename,
  package name, NEVRA, immutable object key, VersionId and SHA384. The complete
  canonical name-plus-NEVRA closure is independently SHA384-bound. The manifest
  must bind the pinned Amazon Linux 2023 signing fingerprint
  `B21C50FA44A99720EAA72F7FE951904AD832C631` and exact public-key SHA256
  `664b632018bd84f9b249be7bd26937c560edb2f2bfc0cbc01ec5a7b4e06aad56`; a
  signer asserted only by a package entry or manifest is insufficient. The build
  caller retrieves the exact-version package archive and canonical manifest,
  rehashes and byte-compares them locally, verifies archive membership/order and
  every member hash, then verifies each local RPM signature, header and exact
  equality to its archived bytes. Individual RPM S3 reads are intentionally
  redundant and forbidden by the five-object invoker contract. Packer repeats
  signature/header/hash checks,
  installs the entire closure with `dnf --disablerepo='*'`, validates each
  installed NEVRA, and exports a canonical NEVRA-plus-package-file-hash
  inventory. Development packages and live repositories are forbidden; and
- exact offline Packer toolchain bytes: Packer CLI `1.16.0` and Amazon plugin
  `1.3.9` (`x5.0`, linux/amd64). The wrapper mechanically verifies their pinned
  archives, signed checksum lists, detached signatures, HashiCorp signing-key
  fingerprints, binary SHA256/SHA384 values and the exact reviewed provenance
  record. The strict canonical manifest rejects extra fields and binds the CLI
  platform plus the plugin protocol and source-tag revision; it makes no claim
  about a Packer CLI source revision. Both verified binaries are copied into a
  private one-link toolchain directory, owner/mode/hash checked immediately
  before validate and build, and the plugin is exposed only through its exact
  isolated `PACKER_PLUGIN_PATH` and checksum file. Packer/HCP/checkpoint
  overrides are cleared or rejected and `PATH` is reset. `packer init`, remote
  plugin resolution and arbitrary `packer` from `PATH` are forbidden.

The plugin checksum list and signature are the official
`hashicorp/packer-plugin-amazon` GitHub release assets named with the `v1.3.9`
prefix. The similarly named `releases.hashicorp.com` checksum list and detached
signature did not verify together during review and are therefore not accepted,
even though both distribution paths expose the same reviewed Linux archive
hash. The CLI remains bound to the signed `releases.hashicorp.com` Packer
`1.16.0` assets.

The wrapper accepts these bytes only through the dedicated
`LAYRS_RECOVERY_PACKER_BINARY`, `LAYRS_RECOVERY_PACKER_CLI_ARCHIVE`,
`LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS`,
`LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS_SIGNATURE`,
`LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_BINARY`,
`LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_ARCHIVE`,
`LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS`,
`LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS_SIGNATURE`,
`LAYRS_RECOVERY_HASHICORP_SIGNING_KEY` and
`LAYRS_RECOVERY_PACKER_TOOLCHAIN_EVIDENCE_FILE` paths. Their exact reviewed
basenames, single-link ownership and modes are part of the gate; the signing
key must be materialized as `hashicorp-pgp-key.txt`.

The known build-a EIF SHA384
`110c31235f36fa85e4a50d61fb89ab3a08e5b18587a35dfe4818c3615eed5a79513082df101e5c655fce8c7640d66ad8`
is explicitly rejected. Filenames, timestamps and recency never select an
artifact.

## Mandatory Phase2 isolation

The AMI contains the existing fixed parent binary unchanged. It must never be
launched with a production route, production security group, DNS record, load
balancer target group, Cloudflare route, NAT gateway or public IP. Before an
AMI build, the wrapper requires the hash of the reviewed Phase2 template that
defines the isolated recovery VPC/subnet/security group and denies fixed-parent
egress except for the exact recovery harness and explicitly reviewed AWS
service endpoints. The AMI build does not create or authorize those runtime
controls; their separately signed Phase2 evidence remains mandatory.

The build instance also uses a caller-supplied recovery-only subnet, security
group and instance profile. The Packer source uses SSM Session Manager, requests
no public address or user data, produces a private AMI and adds no credentials,
services, DNS or target-group registrations.

`--build` first performs read-only AWS and immutable-object preflight in account
`082223548516` and region `us-east-1` using the exact reviewed invoker role;
arbitrary account credentials, admin sessions and root are rejected. Only after
all exact-version S3/KMS-backed package bytes, IAM/CloudFormation state and
infrastructure inventories pass does the wrapper call `sts:AssumeRole` for
`layrs-production-recovery-seq159300-packer-control`, using the evidence-index
SHA384 as external ID and a session bounded by the accepted expiry. It then
read-backs the exact assumed-role/session identity. Packer and its AWS calls run
only with those short-lived control credentials and use the already verified
local package bytes; the control role has no S3 or KMS authority. Packer also
uses `allowed_account_ids` for the same account. The preflight fails closed unless:

- the source AMI has the exact ID and AWS AL2023 owner, is available, x86_64,
  HVM/EBS and has a valid root mapping;
- the build VPC and subnet have no IPv6 CIDR associations, the subnet disables
  IPv6 auto-assignment, DNS64 and automatic public IPs, every endpoint is
  IPv4-only, every endpoint ENI has no IPv6 address, and every active route is
  VPC-local. Endpoint, internet-gateway, NAT, transit, peering,
  network-interface and public-default routes fail; interface endpoints do not
  require route entries, so any purported endpoint route is rejected rather
  than accepted without correlation;
- the build security group has no ingress and its only egress is TCP/443 to
  recovery-labelled endpoint security groups in the same VPC; and
- all three SSM interface endpoints (`ssm`, `ssmmessages`, `ec2messages`) are
  available, private-DNS enabled and attached to that exact subnet and AZ, and
  all endpoint ENIs are completely inventoried there; and
- the build instance profile belongs to the recovery account, uses the exact
  `layrs-production-recovery-seq159300-*` naming contract, has one
  EC2-only role and contains only the minimal SSM message-channel and recovery
  log actions. Secret, KMS, S3, parameter read, database/data, route mutation,
  target registration, PassRole and AssumeRole authority fail closed; and
- the exact Packer control role has the accepted invoker, approval and expiry
  trust, one exact inline policy, no managed policy or permissions boundary,
  exact evidence tags and exact builder-stack outputs. A canonical hash of its
  trust, policy, tags, boundary state and window must equal the separately
  reviewed `buildControlPlaneRoleInventorySha384` before Packer is invoked.

The exact Amazon plugin uses `run_tags` for temporary-key creation and
CreateImage image/snapshot TagSpecifications. Therefore AMI `tags`, `run_tags`,
`run_volume_tags` and `snapshot_tags` cross-bind Purpose, Environment,
recovery-builder template SHA384, package-set SHA384, evidence-index SHA384 and
Phase2-template SHA384. This also makes the post-create snapshot retag satisfy
the same boundary; HCL `tags` alone are not treated as CreateImage authorization
evidence.

The canonical preflight inventories are reduced to stable, non-secret fields
and SHA384-bound in the final evidence as `sourceAmiProvenanceSha384`,
`buildSubnetInventorySha384`, `buildSecurityGroupInventorySha384` and
`buildInstanceProfileInventorySha384`, plus the separate
`buildControlPlaneRoleInventorySha384`.

## Runtime layout contract

Phase2 IaC must use the existing f282 runtime layout embedded in this AMI. It
must not invent recovery-specific paths or unit names:

- parent binary: `/opt/layrsv2/layrs-enclave-parent`;
- EIF: `/opt/layrsv2/layrsv2-clob.eif`;
- enclave unit: `layrsv2-enclave.service`; and
- fixed-egress parent unit: `layrsv2-enclave-parent.service`.

The enclave unit verifies the EIF path and starts CID 16. The parent unit starts
the exact parent path and requires the enclave unit. Phase2 UserData must hash
these two exact paths and start the two exact units. There is no
`/opt/layrs/recovery` layout and no
`layrs-seq159300-recovery-parent.service` in this AMI.

## Operation boundary

`--validate-only` performs local source, hash, PCR0 and Phase2-template checks.
`--build` is a separately authorized operation and emits canonical Phase2 AMI
build evidence. The evidence includes the exact builder/source commits,
Phase2 IaC commit/hash and immutable reference, final integrated backend
implementation commit and its independent immutable reference, builder
template, invoker-template and builder-evidence-index immutable references,
source AMI provenance, network/profile inventory hashes,
Packer template and manifest hashes, installed Nitro CLI NEVRA/package hash,
exact package closure and pinned signing-key identity, explicit Amazon-plugin
version/full source commit, canonical Packer-toolchain manifest SHA256,
and post-build private/encrypted AMI readback hash. The two cross-repository
commit fields are intentionally independent and must never be forced equal.
Both are only recorded here; a later signed gate must independently require
equality to their respective reviewed immutable evidence.

No self-hash is used: the clean builder HEAD and Packer template are hashed
before the build, while the completed Packer manifest is hashed only after it
is closed. This implementation does not grant Phase4 authorization and must not
be interpreted as approval to invoke the enclave or touch funds.
