# Funded canary preflight blocker — 2026-09-12

`FUNDED_CANARY_STATUS = BLOCKED_BEFORE_FINANCIAL_MUTATION`

The authorized canary reached the last safe pre-broadcast boundary. MM-20 was
created through the normal Gmail/Privy modal flow and now has one embedded EVM
wallet and one embedded Solana wallet. It has not been admitted into the direct
runtime, credited, funded, traded, or projected.

MM-02 retains its certified private balance of 9.404611 USDC, but its embedded
Base wallet currently has zero USDC and zero native gas. MM-20's new Base wallet
also has zero USDC and zero native gas. Consequently, the intended funding chain
must begin with a governed direct withdrawal from MM-02 to its own bound wallet,
then the exact 5 USDC transfer into MM-20's normal deposit route.

## Exact blocker

The final candidate cannot be safely switched from dormant to writable mode.
The parent can load the exact signed WriterGrant, but Nitro does not propagate
the parent's systemd environment into the EIF. The enclave currently reads the
execution mode, WriterGrant, approved measurement binding, receipt key, private
state key, and durability-ACK key only from its EIF-local environment. The
measured EIF contains only the sealed opening-state paths, so it boots dormant.

Enabling only the parent cannot create enclave writer authority. Baking the
grant into a replacement EIF would change the PCRs and invalidate the existing
candidate-bound grant. Sending private state keys from the parent without an
attested key-release protocol would weaken the TEE boundary and is rejected.
Default/zero keys, the legacy writer, and Durable Commands are also rejected.

The required correction is a narrowly scoped attested startup grant/key-release
path, completed before immutable-artifact recovery. Any resulting runtime change
requires a new EIF/AMI/PCR tuple, attestation, WriterGrant, restart/replay proof,
and repeated canary preflight.

No deposit request, withdrawal intent, custody signature, transaction, archive
successor, private-ledger mutation, projection mutation, or trade was created.
No funds moved and all legacy writers remain fenced.
