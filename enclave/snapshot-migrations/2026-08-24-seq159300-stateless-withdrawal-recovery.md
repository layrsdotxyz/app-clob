# Sequence 159300 stateless withdrawal recovery

STATE_SCHEMA_UNCHANGED: true
STATE_ROOT_MATERIAL_UNCHANGED: true
TERMINAL_RECOVERY_ONLY: true
BASE_RELEASE_COMMIT: 97614f37c05089708f93bf50ac8831adde98ab2f
EXACT_SNAPSHOT_TEST: exact_terminal_snapshot_reissues_withdrawal_proof_without_state_change

This incident-only EIF is based directly on the exact release embedded in the
currently running production parent AMI. It restores an isolated copy of the
immutable sequence-159300 snapshot and decrypts only the journal record whose
sequence, record hash and state root equal that restored checkpoint's current
head.

The patch adds no field to `CoreStateSnapshot`, no ledger/session/market/order
state, no state-root input and no mutation path. Optional receipt and
authorization proof fields exist only in the freshly returned recovery output;
their absent/default representation leaves every pre-existing receipt wire
encoding unchanged. The session change is a read-only owner accessor. The
journal change authenticates/decrypts the already-anchored current record and
cannot append it.

The exact-snapshot test commits a withdrawal, restores its exact terminal
snapshot, produces a proof, and asserts that sequence, state root, journal head
and withdrawal hold remain unchanged. It rejects altered ciphertext, wrong
withdrawal ID and wrong session.

Production replay plan: none. The EIF is for a separately isolated recovery
parent only. It must never replace or receive traffic from the live enclave.

Rollback plan: before public persistence, discard the isolated recovery
environment and its proof. No production TEE or ledger state changes. After an
approved public projection is created, use only the normal withdrawal lifecycle
and idempotency controls; never delete the proof or edit a balance.
