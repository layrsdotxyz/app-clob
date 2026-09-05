# Direct-withdrawal reservation binding for custody signing

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: e27b96e9cdae05018d606afbcb4f6e7b0eabb5a5
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

This declaration records an intentional validation change in the private engine
for the GREEN direct-withdrawal candidate. It does not authorize a production
deployment, PCR-policy update, public route, custody key, fund movement, or
market-maker change. The operator authorized only full CI and deployment to the
isolated GREEN environment for hermetic sign, broadcast, restart, and replay
certification.

The cumulative-state marker acknowledges that this engine must preserve and
restore the complete state surface inherited from the base release; it does not
claim that this patch introduces a new serialized field or encoding.

## Persisted-state delta

There is no serialized state or snapshot-schema change. No field, enum variant,
journal record, ledger bucket, replay key, or encoding is added or removed.
Existing encrypted snapshots therefore decode without transformation and must
restore to their exact prior sequence, state root, journal head, balances,
withdrawal holds, direct results, and terminal markers.

The validation rule now recognizes an existing direct `RESERVE_WITHDRAWAL`
result as signing authority only when all of the following are already present
and mutually consistent in restored private state:

- the stored result is `APPLIED` for the exact reserve operation;
- session, withdrawal ID, chain, asset, amount, and destination match the
  immutable signing intent;
- the direct reserve marker exists;
- neither a finalize nor release marker exists; and
- the identity-bound withdrawal-hold balance still covers the exact amount.

The existing legacy withdrawal-reservation marker path remains unchanged.
Mismatched, malformed, missing, finalized, or released direct reservations fail
closed as `unknown withdrawal reservation`.

## Production replay plan

No production activation is permitted by this candidate. Before any separately
approved production release, restore the exact then-current encrypted production
snapshot in a passive attested candidate with no writer lease, worker, RPC
broadcaster, queue consumer, custody authority, or public traffic. Require exact
equality of sequence, root, journal head, balances, withdrawal holds, direct
results, legacy markers, and terminal markers.

Using only synthetic state in the isolated candidate, prove that an exact
existing direct reservation validates before and after snapshot restore, that a
changed destination and every other immutable-field mismatch reject, and that
the same authorization rejects after finalize or release. Then run a separately
authorized funded canary before any production traffic. Production custody and
the quest market maker remain outside this GREEN certification.

## Rollback plan

Because the patch changes no persisted representation and creates no new state,
the GREEN enclave may be rolled back to the retained base EIF/AMI before traffic
or custody authority is attached. Preserve the exact encrypted snapshot,
journal, receipts, sequence, root, and PCR evidence; never edit or delete a
reservation, hold, direct result, or terminal marker to manufacture rollback.

If any signing attempt has been accepted, stop new attempts and reconcile that
exact withdrawal and receipt before rollback. A completed finalize or release
must remain terminal. Any restore mismatch, duplicate signature, altered intent,
or projection discrepancy is a hard stop rather than a reason to weaken the
binding checks.
