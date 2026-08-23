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

An incident-only, read-only terminal recovery may use
`--allow-stateless-terminal-recovery` only when its changed document contains:

```text
STATE_SCHEMA_UNCHANGED: true
STATE_ROOT_MATERIAL_UNCHANGED: true
TERMINAL_RECOVERY_ONLY: true
BASE_RELEASE_COMMIT: <exact deployed app-clob commit sha>
EXACT_SNAPSHOT_TEST: exact_terminal_snapshot_reissues_withdrawal_proof_without_state_change
```

That mode permits changes only in `engine.rs`, `journal.rs`, `mod.rs` and
`session.rs`; it still requires a branch from the exact deployed release and a
test proving recovery leaves the restored sequence, root and journal head
unchanged. It is not permission to deploy a state migration.
