# Final direct-runtime candidate — dormant deployment evidence

The governed dormant runtime stack
`layrs-production-direct-execution-dormant` was updated through the reviewed
CloudFormation change set `direct-final-365f299-dormant-20260912`.

The accepted change set modified only the direct-runtime launch template and
its one-instance dormant Auto Scaling Group.  It set the image to
`ami-0a1dc1839d623e326` and retained `WriterEnabled=false`.  It made no
change to custody, balances, databases, archive contents, writer authority,
or the legacy runtime.

The replacement verifier instance is `i-09c3cf4240a781ddc`.  Read-only SSM
verification established all of the following:

- `nitro-enclaves-allocator`, `layrs-opening-enclave`, and
  `layrs-opening-parent` are active;
- the parent reports `layrs.direct-execution.nitro.v1`, transaction model
  `layrs.direct-execution.v1`, opening-epoch hash
  `84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590`,
  evidence-manifest hash
  `70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957`,
  genesis ordinal `0`, and `writerEnabled=false`;
- the installed EIF SHA-256 is
  `c622e2ad1b3a8b6dade00b957a9ff14f44467425578b0a617361a0e15e45ab2b`;
- the installed parent SHA-256 is
  `0b69d4de65c597cafbb2fe2b10c0c375b800d8a1e45f1b8f4a961737dd99a3dd`;
- the installed epoch and evidence files match their sealed hashes; and
- Nitro reported PCR0
  `069cf300806081754ffe8e346054540efdcf1c128e4aa4912f676f0f56f2e4cd9f8738d95f38ca6339bb3258cffbbc48`,
  PCR1
  `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`,
  and PCR2
  `46cf055fe9df4c08096b1f3b659f6f23908446cde95f79d9fb7fdfd53a537d6c6f352eb6f6a19650756ff872ce9344c9`.

The parent health endpoint and nonce-bound attestation endpoint responded.
The environment contains no WriterGrant, and the enclave attestation binding
reports `writerEnabled=false`.  The deployment is deliberately dormant:
there is no funded canary, custody submission, customer-balance change, or
production financial writer enablement in this operation.

The activation-critical `layrs-production-direct-runtime-health-missing`
alarm was then rebound to the replacement instance.  It retains its existing
production SNS action and breaching treatment for missing telemetry; it was
not silenced, disabled, or state-forced.
