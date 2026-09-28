# Worker brief: direct-execution persistence verification baseline

Base contract: `FULL_STATE_JOURNAL_V71_CONTRACT.md`.

## Exact deliverable

Add narrowly scoped local tests/fixtures that characterize the v70 persistence
invariants needed before compaction and v71 journal work:

1. exact replay returns the original terminal result without a successor;
2. conflicting request-id reuse fails closed;
3. committed sequence and request-map cardinality are coupled in v70;
4. artifact restore preserves the terminal result and financial state hash;
5. checkpoint validation detects a missing, duplicated, reordered, or modified
   receipt record;
6. a local synthetic-size test or ignored measurement helper reports serialized
   total state bytes and the incremental bytes attributable to request history,
   without reading production artifacts or secrets.

Prefer tests and `#[cfg(test)]` helpers. Production behavior must not change.
Do not implement the bridge, compaction, journal, parent persistence, writer
fencing, deployment, AWS, S3, database work, matching, custody, or unrelated
cleanup.

## Files

Expected scope:

- `src/lib.rs` test module and test-only helpers
- optionally one local example/benchmark file under this crate

Do not edit `src/bin/parent.rs` or `src/bin/enclave.rs`.

## Required result

- Run `cargo fmt --check` and focused tests.
- Run the complete library tests if time permits.
- Commit the change to the worker branch.
- Report commit SHA, changed files, tests, measurements, assumptions, and any
  blocker.
- Do not merge, deploy, access production, or perform any network/AWS action.

If useful coverage requires changing financial semantics, stop and report the
gap. Do not widen scope.
