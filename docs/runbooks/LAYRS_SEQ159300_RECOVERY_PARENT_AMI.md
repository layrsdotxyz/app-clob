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
- accepted app-backend recovery implementation/Phase2 commit
  `23f92bc64171862abc410af953321a991e5e1515`, with these exact independently
  reviewed CloudFormation template SHA384 identities:
  - recovery builder `75e536d6d138b88aaf7ef29fece2f67f3e6ffbda02841092de73726795b4d55a6fe01af492d8d8d1f0d3dc7f8db105d7`;
  - Packer invoker `d67e4f78be6bd679b4ab61e316215fce24035e89508baaefcf3b2df6209682fd94dc0fcd84bac1530664f02aaf7723e1`;
  - template publisher `6eefb0154b78e08949ffb677a5179782cd17ab3f9a2f3d68ddf65789ce085b73aa9f76ad13821aff06fe9d853153d529`;
  - builder cleanup `72c5872db412726d8e56c0c078067bae19c8cf316bba204f0849a6ae34bc504792b12601f023f76efdf81b750a6aa77c`;
  - post-build evidence publisher `329c3ad67e05dec6efff89d7ede7553e652b18d7a6727c95fc88e7766584037f6d1345210120448cccba7f56397e9361`;
  - retained finalizer `2eeca9da6a30bc6aef84126d8e53b70723b8b00554aa65c9da982e3fd47f82eb694c00b05a26c598eed3d5b8d110b2c9`;
  - production deployer bootstrap `caae4fa5902593a3648f6755669f87e4b6b59cb3bbb027ed82991b51ff8727f02cbcfe6883e8ea7644bd57477c9a8620`.
  These source identities are necessary but not authorization: the later gate
  must still exact-read immutable VersionIds, validate signed evidence and keep
  Phase4 closed;
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
  redundant and forbidden by the exact-object invoker contract. Packer repeats
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
  trust, one exact inline deny policy, exactly three hash-bound managed policies
  (`packer-inventory`, `packer-launch` and `packer-artifacts`), and no
  permissions boundary,
  exact evidence tags and exact builder-stack outputs. Before role assumption,
  the wrapper exact-VersionId reads and rehashes all nine immutable invoker,
  builder, package, index, publisher, receipt and cleanup-template objects; the
  reviewed invoker, builder, publisher and cleanup templates are also
  byte-compared locally. A canonical hash of the role trust, all four policy
  documents, attachments, tags, boundary state and window must equal the separately
  reviewed `buildControlPlaneRoleInventorySha384` before Packer is invoked.
  Its read-only action set must include the exact route-table, VPC-endpoint and
  endpoint-ENI inventory calls used after role assumption; and
- the independently reviewed publisher template is byte-equal to its immutable
  object version. The exact template-upload and unexecuted change-set receipts
  are fetched by VersionId, rehashed, schema-checked and cross-bound to the same
  builder-template object version. The change set must be stable
  `CREATE_COMPLETE/AVAILABLE`, with `executed=false`; pending, unavailable,
  failed or post-teardown absence receipts are different evidence and fail this
  gate. The receipts also equality-bind the canonical immutable-bucket controls
  and the exact inline-plus-three-managed-policy CloudFormation execution set;
  every policy document and aggregate hash is recomputed. Their immutable references, the publisher
  and CloudFormation execution role inventory immutable triplets, and the publisher
  template hash/reference are all distinct evidence fields. None authorizes
  change-set execution. The role inventories use the exact stable
  `.../builder/publisher/roles/{template-publisher|cloudformation-execution}/inventory/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`
  keys and the same full role shape as the cleanup-role inventories, including
  RoleId, empty instance profiles and no self-inventory-hash tag; and
- the default-inert cleanup template is byte-equal to its exact immutable
  object version. Its template SHA384/reference and the independently reviewed
  cleanup submitter/execution role inventory object keys, VersionIds and
  SHA384s are bound into the parent build evidence. Their exact stable keys are
  `.../cleanup/roles/cleanup-execution/inventory/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`
  and the corresponding `.../cleanup-submitter/inventory/...` key. Each
  canonical inventory has exactly `attachedPolicies`, `inlinePolicies`,
  `instanceProfiles`, `maxSessionDuration`, `path`, `permissionsBoundaryArn`,
  `roleArn`, `roleId`, `roleName`, `tags` and `trust`; it binds zero attached
  policies, zero instance profiles, no boundary and exactly one reviewed inline
  policy. The source role must not contain a `RoleInventorySha384` tag or any
  other self-inventory-hash reference; the exact expected SHA384 must not occur
  anywhere in its canonical inventory bytes. Inventory capture and live readback run
  only through the exact runner to production-deployer chain with the reviewed
  role-read authority; an ambient runner session cannot and must not perform
  those IAM reads. The parent wrapper only exact-VersionId reads and rehashes
  the resulting immutable artifacts through its reviewed invoker. A cleanup
  receipt is deliberately not a build-evidence field:
  it cannot exist until after the AMI and its evidence are durable and the
  isolated builder has been removed.

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
publisher-template immutable reference, exact template-upload and unexecuted
change-set receipt references, `templatePublisherRoleInventoryObjectKey/VersionId/Sha384`
and `cloudFormationExecutionRoleInventoryObjectKey/VersionId/Sha384`,
cleanup-template immutable reference and cleanup submitter/execution-role
inventory hashes, plus the exact trusted GitLab-runner principal inventory hash,
the exact `packerControlPlaneApprovedAt/ExpiresAt`,
`invokerApprovedAt/ExpiresAt` and `templatePublisherApprovedAt/ExpiresAt`
one-hour-or-less authority windows,
source AMI provenance, network/profile inventory hashes,
Packer template and manifest hashes, installed Nitro CLI NEVRA/package hash,
exact package closure and pinned signing-key identity, explicit Amazon-plugin
full source commit in the builder outputs, tags and final evidence, canonical
Packer-toolchain manifest SHA256,
and post-build private/encrypted AMI readback hash. The two cross-repository
commit fields are intentionally independent and must never be forced equal.
Both are only recorded here; a later signed gate must independently require
equality to their respective reviewed immutable evidence.

After the retained AMI, snapshots and parent-build evidence are durable, cleanup
uses a separate canonical
`layrs.seq159300.recovery-parent-post-build-cleanup-evidence.v1` object. Its
renderer requires unique immutable references for the parent-build evidence,
cleanup template, cleanup intent, pre-delete physical inventory and exact
cleanup receipt, both cleanup role inventories, plus the exact immutable post-build evidence-publisher
template and `postBuildPublisherRoleInventoryObjectKey/VersionId/Sha384`. The
role inventory uses stable key
`.../cleanup/roles/post-build-evidence-publisher/inventory/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`
and the same full, non-self-referential role shape. This triplet is deliberately
not a parent-build or preexisting publisher input: the same exact finalizer
session used for structured absence captures the live publisher role, uploads
canonical bytes create-only to that stable key, exact-VersionId reads and
rehashes them, and records the returned VersionId/SHA384 immediately before
ordinal 4 deletes the publisher. The cleanup receipt and final evidence bind
the returned triplet byte-for-byte together with
`postBuildPublisherRoleInventoryUploadRequestId`,
`postBuildPublisherRoleInventoryUploadedAt`,
`postBuildPublisherRoleInventoryReadbackRequestId` and
`postBuildPublisherRoleInventoryReadbackVerifiedAt`. The two request IDs must
be distinct, upload must occur inside the same finalizer session, exact-version
readback must follow upload and finish before both final evidence verification
and ordinal 4's `deleteRequestedAt`; each publication request ID must not alias
any structured absence request ID. The finalizer policy grants create-only
publication and runtime exact-version readback over only the three stable output keys:
this post-build publisher inventory, the cleanup receipt and the final cleanup
evidence. Their VersionIds and hashes are runtime results, never prebound future
inputs; all other immutable inputs remain exact-VersionId reads. It retains one AMI inventory, one or more snapshot inventories
that bind owner/encryption/KMS/size, and a sorted immutable-evidence inventory.
The exact absence inventory is a sorted set of
`resourceType/resourceId/serviceErrorCode/requestId` records with a canonical
aggregate SHA384 and a distinct request ID for every resource read. It must include the exact builder, publisher and cleanup
StackIds plus the temporary invoker StackId; every recovery role, instance profile, managed policy and window-guard
Lambda; every captured VPC, subnet, route table, security group, endpoint and
ENI; and the temporary Packer key pair and instance. Only the service-specific
reviewed not-found codes are accepted. The cleanup implementation commit,
finalizer approval and expiry, exact finalizer-template immutable reference,
exact assumed finalizer identity, and an immutable finalizer role-inventory
object key, VersionId and SHA384 are also bound. That canonical object records
the exact role ARN and creation RoleId, trust, path, tags, maximum session
duration, inline policy names and documents, zero attached managed policies,
zero attached instance profiles, no permissions boundary, finalizer-template hash, approval/expiry window and
the post-expiry explicit deny. Its object SHA384 must equal
`finalizerRoleInventorySha384`. The ARN session name must equal the principal-ID suffix and
`verifierRoleInventorySha384` must equal `finalizerRoleInventorySha384`. The
parent-build evidence separately binds the exact GitLab runner inventory as
`trustedPrincipalInventorySha384`; the production-deployer has sole trust in
that runner, while both temporary roles have sole trust in the exact
production-deployer. The runner, production deployer and finalizer inventories
must be pairwise distinct.
The final cleanup evidence additionally binds
`postBuildPublisherApprovedAt/ExpiresAt`, `cleanupApprovedAt/ExpiresAt`, the
exact assumed `cleanupSubmitterIdentity`, and
`cleanupSubmitterSession`/`finalizerSession` objects. Each session has exactly
`durationSeconds`, `issuedAt` and `expiresAt`; duration is an integer from 900
through 3600 seconds, equals the exact timestamp delta, and its returned STS
expiration cannot exceed the corresponding role expiry. It is deterministically
computed as
`min(3600, floor((min(roleExpiresAt, deployerSessionExpiresAt) - preCallNow)/1000) - 30)`, preserving
an exact 30-second safety margin in the bound pre-call builder source. The
evidence validator does not recompute that request from returned/derived
`issuedAt`, because service/network latency across a second boundary can differ
by one; it validates the actual returned duration/delta and role bounds. Fewer than 900 safe
remaining seconds fails closed. The submitter ARN session name must equal its
principal-ID suffix; the finalizer session belongs to `verifierIdentity`.
The chain is fully explicit through `runnerIdentity`,
`productionDeployerIdentity` and `productionDeployerSession`. Every identity
has exactly `accountId`, `arn` and `principalId`; every session has the same
three-field duration/time shape. The runner is the exact GitLab runner role and
the deployer is exactly `layrs-production-deployer`, with ARN session-name to
principal-ID suffix binding. Both temporary session expirations must be no
later than the chained production-deployer session expiration. Receipt and
final evidence bind all identities and sessions byte-for-byte.
The inventory object key is derived without a hash fixed point as
`.../finalizer/inventory/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`;
its create-only VersionId and SHA384 bind the resulting canonical bytes. The
final evidence uses the corresponding stable
`.../finalizer/final/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`
key and is likewise accepted only by exact VersionId and content hash. Neither
object is an invoker pre-read input.

The final evidence also binds the production-deployer trust chain through two
unique immutable triplets. The deployer template is fixed at
`.../finalizer/deployer/templates/layrs-predifi-root-bootstrap-<templateSha384>.yml`;
the canonical live role inventory is fixed at
`.../finalizer/deployer/inventory/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`.
The latter binds the deployer's sole runner trust and its complete existing
policy inventory plus only the exact finalizer self/readback actions. Before
any finalizer inventory read, the later gate exact-VersionId reads both objects,
rehashes them and requires a byte-equivalent live deployer role inventory.

The retained finalizer stack is separately bound by
`retainedFinalizerStackInventoryObjectKey/VersionId/Sha384` at the stable key
`.../finalizer/stack-inventory/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`.
The finalizer template may move only from `EXACT_CREATE_REVIEWED` to
`EXACT_FINALIZE_REVIEWED`: this removes the temporary finalizer window-guard
role, Lambda and custom resource while leaving the finalizer role policy
byte-identical. Any policy-changing finalize/readback update fails closed. The
canonical post-finalize inventory binds StackId, status, template hash,
parameters and an exact `ListStackResources` result containing only
`RecoveryFinalizerRole`. The structured absence inventory must independently
prove the finalizer window-guard role and Lambda are absent. After expiry, the
gate exact-VersionId reads and rehashes the retained-stack inventory and
live-compares the stack before accepting the inert finalizer.

Sequencing is non-recursive: the temporary post-build publisher may publish
only the reviewed preliminary cleanup artifacts and immutable role/stack
inventories, but never the cleanup receipt or final evidence. Then its stack, role and window-guard
role/function must be deleted. The existing runner initiates the final
structured absence readback through its bound production-deployer and finalizer
sessions only afterward, so the final evidence's absence
inventory includes that publisher StackId and all three publisher authorities.
The runner cannot directly assume either temporary role. It first assumes the
exact production-deployer; inside one process that deployer then role-chains
into the separately accepted cleanup-submitter and finalizer sessions before
the ordered sequence, with each chained session at most one hour, and never
serializes their credentials. The cleanup submitter supplies the structured SDK
delete-success request IDs; the same finalizer session supplies each
interleaved structured absence request ID.
The deployer policy must contain two separate statements named exactly
`AssumeExactSeq159300CleanupSubmitter` and
`AssumeExactSeq159300Finalizer`. Each allows only `sts:AssumeRole` on its one
exact role ARN, uses its own approval/expiry window, and requires its own exact
ExternalId. The cleanup submitter ExternalId is the 96-lowercase-hex
`cleanupSubmitterExternalId`; the finalizer ExternalId is exactly `cleanupIntentSha384`,
and those values must differ. Each temporary role trust names only the exact
production-deployer principal, exact-equals `aws:PrincipalArn`, and repeats the
matching ExternalId and time-window conditions. The deployer and both role
inventories must byte-bind these statements; a combined statement, wildcard
resource/action, shared ExternalId, or mismatched window fails closed.
Only after ordinal 5 proves the cleanup stack absent does that same finalizer
session render the v2 receipt at
`.../cleanup/receipts/<cleanupImplementationCommit>-<cleanupIntentSha384>.json`,
create-only upload it, capture its VersionId/SHA384, and then render,
create-only upload and exact-VersionId read back the final parent post-build
evidence referencing that receipt. Finalizer creation must not require or read
a future cleanup-receipt VersionId or SHA384. The finalizer does not introduce a signer; the existing gate
governance and two distinct reviewer envelopes later bind the exact object
version. The finalizer is retained and excluded from the temporary-resource
absence set. Completion remains fail-closed until its at-most-one-hour window
has expired and a separate live readback proves the retained role is inert
under an explicit deny and byte-equivalent to the immutable finalizer role
inventory. The later gate performs that readback only through the exact GitLab
runner to production-deployer chain, using `GetRole`, `ListRolePolicies`,
`GetRolePolicy`, `ListAttachedRolePolicies` and `ListInstanceProfilesForRole`
for this role. It re-canonicalizes role ARN/RoleId, trust,
inline policy, tags, path and maximum session duration; rejects any attached
managed policy, instance profile or permissions boundary; and equality-binds the live hash in
the gate receipt and reviewer signatures. No second mutable readback artifact
is accepted.

Cleanup ownership and order are exact: the cleanup path must bind and delete
the invoker and post-build-publisher StackIds and their owned roles/functions,
then verify them absent before the cleanup stack/submitter/execution authority
is removed last. A cleanup implementation that authorizes only the builder,
template publisher and cleanup stacks is incomplete and must be rejected.
The immutable `cleanupReceiptObjectKey/VersionId/Sha384` must resolve to
canonical exact receipt bytes containing the ordered per-resource deletion
proof, not counts or booleans. Those bytes equality-bind the pre-delete
inventory and the exact invoker, builder, template-publisher,
post-build-publisher and cleanup-authority StackIds, and record the cleanup
authority deletion last. The later gate must exact-VersionId read, rehash and
strict-schema validate this receipt before accepting the reference in final
evidence; this local renderer alone does not make unmaterialized cross-repo
receipt bytes trustworthy.

The cleanup receipt protocol is exactly
`layrs.seq159300.recovery-builder-cleanup-execution-receipt.v2`. Its strict
top-level fields are `accountId`, `region`, `mode` (`POST_BUILD`),
`phase4Authorized` (`false`), `cleanupImplementationCommit`,
`cleanupIntentSha384`, `physicalInventorySha384`,
`cleanupExecutionRoleInventorySha384`,
`cleanupExecutionRoleInventoryObjectKey`,
`cleanupExecutionRoleInventoryObjectVersionId`,
`cleanupSubmitterRoleInventorySha384`,
`cleanupSubmitterRoleInventoryObjectKey`,
`cleanupSubmitterRoleInventoryObjectVersionId`, `cleanupSubmitterExternalId`,
`cleanupApprovedAt`, `cleanupExpiresAt`,
`postBuildPublisherApprovedAt`, `postBuildPublisherExpiresAt`,
`postBuildPublisherRoleInventoryObjectKey`,
`postBuildPublisherRoleInventoryObjectVersionId`,
`postBuildPublisherRoleInventorySha384`,
`postBuildPublisherRoleInventoryUploadRequestId`,
`postBuildPublisherRoleInventoryUploadedAt`,
`postBuildPublisherRoleInventoryReadbackRequestId`,
`postBuildPublisherRoleInventoryReadbackVerifiedAt`,
`finalizerApprovedAt`, `finalizerExpiresAt`,
`runnerIdentity`, `productionDeployerIdentity`, `productionDeployerSession`,
`cleanupSubmitterIdentity`, `cleanupSubmitterSession`, `finalizerSession`,
`clientRequestToken`,
`verifierIdentity`, `changeSetDeletion`, `stackDeletionSequence`, `allExactStacksAbsent` (`true`),
`cleanupAuthorityDeletedLast` (`true`) and `completedAt`.
`physicalInventorySha384` must equal the final evidence's
`preDeletePhysicalInventorySha384`; the commits, intent and role inventories
must also equality-bind their final-evidence/build-evidence values.
`verifierIdentity` has exactly `accountId`, `arn` and `principalId` and must
equal the final evidence's exact assumed-finalizer identity, including the ARN
session-name/principal-ID suffix binding.

`changeSetDeletion` has exactly `changeSetId`, `deleteCallCount` (`1`),
`deleteRequestId`, `deleteRequestedAt`, `absenceErrorCode`
(`ChangeSetNotFoundException`), `absenceRequestId` and `absenceVerifiedAt`.
Every ordered stack record has exactly `ordinal`, `stackRole`, `stackName`,
`stackId`, `deleteCallCount` (`1`), `deleteRequestId`, `deleteRequestedAt`,
`absenceErrorCode` (`ValidationError`), `absenceRequestId` and
`absenceVerifiedAt`. The only order is builder, invoker, template-publisher,
post-build-evidence-publisher, builder-cleanup. Ordinal 5 `stackRole` is exactly
`builder-cleanup`; `cleanup-authority` is not an accepted alias. All timestamps are monotonic;
`completedAt` equals the final builder-cleanup `absenceVerifiedAt` and the final
cleanup evidence `verifiedAt`. `clientRequestToken` binds overall cleanup
idempotency; it does not assert that `DeleteChangeSet` accepts such a parameter.
Execution alternates two exact temporary principals through the bound
production-deployer: it uses `cleanup-submitter` only for each delete mutation and the finalizer only for
the immediately following structured absence read. For every ordinal, delete
precedes its finalizer absence; that `absenceVerifiedAt` is less than or equal
to the next ordinal's `deleteRequestedAt`. The cleanup stack is still last.
Single ambient-role execution, a deleted cleanup-submitter attempting ordinal
5 verification, or a post-hoc finalizer reread that overwrites the original
request IDs/timestamps is rejected.
All parent-build, receipt and final-evidence authority, session, publication,
deletion and verification timestamps use one canonical UTC-seconds representation
`YYYY-MM-DDTHH:MM:SSZ`; `.000Z` is rejected as an alternate encoding. Raw STS
expirations are normalized to UTC seconds before evidence serialization and
then checked against their exact duration and role-window bounds.
The v2 receipt and final evidence reuse the same finalizer SDK absence calls.
The receipt change-set record and all five stack records must map one-for-one to
the final `exactAbsenceInventory` entries with identical `serviceErrorCode`,
`requestId`, resource type and resource ID. A fresh or differing absence ID is
rejected; new readback IDs are allowed only in the separate post-expiry
finalizer/guard/deployer gate.

Every structured absence record must come directly from an AWS SDK exception's
`error.name` and `$metadata.requestId`. Parsing `aws --debug` stderr, scraping
human-formatted CLI output or synthesizing either field is prohibited and must
fail static review before this contract can be frozen. IAM absence therefore
uses the SDK-v3 name `NoSuchEntityException`; the CLI/API text
`NoSuchEntity` is not an accepted alias. CloudFormation stack absence uses
`ValidationError`, while `DescribeChangeSet` absence uses the live SDK name
`ChangeSetNotFoundException`; the source check must also require their live
`$metadata.httpStatusCode` values of 400 and 404 respectively. Those codes are
not interchangeable. An S3
`HeadObject` miss for a nonexistent VersionId is ambiguous and is never
accepted as an absence record.

This post-build object remains separate from the parent-build object to avoid a
future dependency. Both exact immutable object versions must be bound by the
independent reviewer signatures before the later gate may accept the recovery
package. The post-build schema always fixes `phase4Authorized` to `false`.

The later gate computes the maximum expiry across every parent-bound temporary
authority: Packer control, invoker, template publisher, post-build publisher,
cleanup and finalizer role windows, plus both returned STS session expirations.
It may claim authority inert only when current time is at or after that maximum
and the required live readbacks pass. A deleted IAM role is physical-resource
absence only; it never proves already issued STS credentials revoked, and the
contract must not label that authority absent before the maximum expiry and
explicit deny-after-expiry boundary.

The current GitLab runner/deployer permissions are not sufficient to perform
the final immutable upload/readback and later reviewer binding or every required structured absence
read. Therefore the final evidence sequence is held fail-closed pending an
independently accepted finalizer template and immutable version. That
least-authority role must be default-inert and time-expired, trust only the
exact runner inventory, write/read only the exact stable cleanup-receipt and
final-evidence object versions, and expose only the required absence APIs. It is retained and
inventory-bound, never falsely listed as absent. Until that contract is
implemented and independently accepted, this renderer is evidence schema only,
not an executable completion or Phase4 path.

No self-hash is used: the clean builder HEAD and Packer template are hashed
before the build, while the completed Packer manifest is hashed only after it
is closed. This implementation does not grant Phase4 authorization and must not
be interpreted as approval to invoke the enclave or touch funds.
