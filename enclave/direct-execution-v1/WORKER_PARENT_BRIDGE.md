# Worker brief: v70 parent/enclave safety bridge

Base contract: `FULL_STATE_JOURNAL_V71_CONTRACT.md`.

## Exact deliverable

Implement only the format-compatible bridge needed to keep v70 restorable while
the journal redesign is developed:

1. use one shared direct-execution frame-limit constant on parent and enclave;
2. raise it from 256 MiB to 512 MiB;
3. make only the checkpoint seal performed at the end of a successful restore
   non-fatal, with a finite structured diagnostic;
4. make asynchronous checkpoint refresh classify an oversized checkpoint as a
   skipped refresh and return to idle instead of immediately retrying forever;
5. add focused tests for the frame boundary, successful restore despite a
   failed post-restore checkpoint refresh, and bounded background behavior.

Do not change the v70 artifact/checkpoint wire format. Do not weaken artifact,
receipt, lineage, or head validation. Do not alter financial command handling.
Do not address journal v71, compaction, matching, custody, deployment, AWS, S3,
database schema, EIFs, grants, services, market publishing, or unrelated code.

## Files

Expected production-code scope:

- `src/bin/enclave.rs`
- `src/bin/parent.rs`
- at most one small shared constants module if required

Tests may be added in those files or a directly associated test module. Avoid
formatting unrelated lines.

## Required result

- Run `cargo fmt --check` and focused tests.
- Run the complete crate tests if time permits.
- Commit the change to the worker branch.
- Report commit SHA, changed files, tests, assumptions, and any blocker.
- Do not merge, deploy, access production, or perform any network/AWS action.

If a requirement cannot be implemented without broad refactoring, stop and
report the exact dependency. Do not create a mini-project.
