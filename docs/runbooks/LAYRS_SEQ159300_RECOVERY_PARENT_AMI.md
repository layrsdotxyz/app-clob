# Sequence 159300 recovery parent AMI

This path produces a private, recovery-only parent AMI from the already-built
and independently accepted f282 parent and EIF bytes. It does not rebuild or
modify either runtime artifact.

The wrapper fails closed unless all of these inputs are exact:

- source commit `f282583cae7a5c873a26aa8d0c1bec10c490eb8e`;
- the exact lowercase 40-hex final integrated gate implementation commit,
  supplied only after the gate, harness and Phase2 IaC are integrated;
- parent SHA384
  `d9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1`;
- accepted build-b EIF SHA384
  `958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290`;
- PCR0
  `57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac`;
- a pinned AL2023 AMI ID owned by AWS account `137112412989`; and
- the SHA384 of the separately reviewed Phase2 isolation template.

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
build evidence. This implementation does not grant Phase4 authorization and
must not be interpreted as approval to invoke the enclave or touch funds.
