# Enclave snapshot migration approvals

This directory is intentionally empty unless a release changes the private CLOB
state, journal, ledger, session, or runtime snapshot surface.

Why this exists: a replay-only Nitro hotfix once accidentally included a private
engine field change. The new EIF built successfully, but production provisioning
failed when existing snapshots could not be replayed. CI and the signed-EIF
workflow now block that class of release.

For a genuine snapshot/schema migration, add a dated markdown file in this
directory and include these exact markers:

```text
SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: <exact deployed app-clob commit sha>
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
```

The document should also describe:

- the state/schema fields being changed;
- how old snapshots are transformed or replayed;
- how production replay is tested before cutover;
- the rollback path if provisioning fails;
- the owner who approved the release.

Do not add a permanent bypass file. The guard only accepts a migration document
that changes in the candidate release diff.
