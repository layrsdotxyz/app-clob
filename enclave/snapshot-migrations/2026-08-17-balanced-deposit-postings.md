# Balanced confirmed-deposit postings

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: ecae35c0bde5be479d5f21dbf5a4da0c0bbae671
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
FUNDED_CANARY_REQUIRED: true

Release owner: Layrs financial-core owner. This approval covers the intentional
change from a single user-liability mutation to one atomic, normal-side pair:
debit canonical custody `PoolCash`, credit opaque `UserAvailable` liability.
It does not approve deployment before the historical opening-balance migration
and custody reconciliation stories are complete.

## Compatibility

No field is added to `LedgerWire` or the encrypted snapshot. Existing snapshots
therefore restore byte-for-byte under the current decoder. Historical
`EXTERNAL_FLOW` records retain their original meaning. New finalized deposits
use a distinct `CONFIRMED_DEPOSIT` journal command and include an explicit
two-leg `postings` projection in the applied result.

The state transition intentionally changes for new `CreditDeposit` commands:
both pool cash and the private user balance enter the state root. Existing
snapshot liabilities do not acquire a synthetic pool-cash opening balance.
The governed historical migration must post an independently reconciled opening
balance before the chart becomes production-effective.

## Required release evidence

Before activation:

1. restore the latest production snapshot and verify the identical pre-upgrade
   state root and journal head;
2. reconcile every historical deposit liability to finalized canonical pool
   cash and post the governed opening balance without changing user balances;
3. demonstrate direct, routed and late finalized deposits for USDC and ZEN;
4. demonstrate below-minimum, refunded and non-final routes create no enclave
   posting;
5. retry every receipt and prove neither leg can be duplicated;
6. reconcile pool cash, user liabilities, holds, collateral, fees and reserves;
7. build and attest the candidate EIF; and
8. complete capped funded deposit, trade, resolution and withdrawal canaries.

## Rollback

Before the candidate accepts a command, restore the prior parent AMI, EIF,
manifest and PCR policy. After the first new deposit command, freeze financial
mutations and retain the candidate snapshot/journal. Roll back only after the
new pool-cash leg and user liability reconcile to chain custody; never remove a
posting or rewrite an encrypted record to regain the prior root.

