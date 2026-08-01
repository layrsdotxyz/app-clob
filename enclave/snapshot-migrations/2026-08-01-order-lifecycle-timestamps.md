# 2026-08-01 — private order lifecycle timestamps

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: ed540cb920f7e5b5c7cce57f1eccf59c3283722d
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who requested accurate active and
historical order timing before the controlled alpha release.

## Change

`BookOrder` adds enclave-observed `created_at_millis` and
`updated_at_millis` fields. New orders record both fields at acceptance. The
update time advances deterministically for maker and taker fills, authenticated
owner cancellation, and market-wide cancellation during close or resolution.

The fields are private portfolio metadata. They are returned only through the
existing authenticated owner-scoped portfolio command and are not added to
public depth, audit batches, receipt roots, MatchSettlement calldata, or any
other public surface.

## State compatibility

Both fields use Serde defaults, so a snapshot written by the current production
release remains decodable and restores each legacy timestamp as zero. Zero
values are omitted when reserialized, preserving the exact legacy order-book
bytes and state root until a legacy order changes state.

Once a restored legacy order fills or is cancelled, only its update time is
recorded; its unknown creation time remains zero. The browser therefore falls
back to deterministic sequence display for that historical order instead of
inventing a timestamp. New orders record truthful enclave time from creation.

This change does not alter order crossing, NORMAL/MINT/MERGE selection,
price-time priority, complete-set accounting, collateral holds, ledger
transfers, maker/taker fees, withdrawal authorization, resolution, rewards,
signed receipt commitments, or public audit payloads.

## Production replay plan

1. Freeze new private commands and retain the immutable running snapshot,
   journal head, sequence and state root.
2. Restore that snapshot in the candidate EIF. Require the restored sequence,
   journal head and state root to equal the running release before accepting a
   command.
3. Replay all later encrypted journal entries and require identical command
   results, fills, balances, positions and final state root.
4. Run owner-isolated order canaries covering resting, partial fill, complete
   fill, owner cancellation and market-wide cancellation. Verify monotonic
   creation/update times without publishing owner or timing metadata on-chain.
5. Re-run NORMAL, MINT and MERGE conservation/replay tests, then rotate PCR0,
   the signed release manifest and KMS attestation policy as one release.

The release suite includes an exact legacy-book serialization vector, actual
production-lineage snapshot restore tests, deterministic maker/taker timestamp
tests, all-target Rust tests, strict clippy, and the complete-set conservation
and replay suite.

## Rollback plan

Before the candidate accepts any command, rollback restores release
`ed540cb920f7e5b5c7cce57f1eccf59c3283722d` and its approved PCR allowlist.

After the candidate accepts commands, freeze trading and retain its snapshot
and journal. Roll back only after reconciling all post-cutover orders, holds,
positions, fees and custody movements. Older binaries ignore the new timestamp
fields, but a rollback must not invent or backfill timestamps and must never
truncate the encrypted journal silently.

## Approval

This is an intentional additive private-order history release. It must use the
normal measured EIF build, signed manifest, PCR rotation, exact snapshot replay,
owner-isolated canaries and capped activation process.
