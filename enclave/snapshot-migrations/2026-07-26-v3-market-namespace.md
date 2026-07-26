# 2026-07-26 — v3 rolling market namespace

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: b4d573495447c2fca17e244a4ec6f1160e7a575e
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

The private core market validator now accepts `layrs:v3:*` market identifiers in
addition to the existing `layrs:v1:*` and `layrs:v2:*` namespaces.

## Reason

Some already registered `layrs:v2` rolling ZEN markets were created with stale
alpha minimum-order limits. Because registered market releases are immutable and
may already be visible on-chain, the safe repair is to roll forward to a fresh
namespace instead of mutating historical release payloads.

## State compatibility

This does not change the encrypted journal format, snapshot schema, ledger
accounts, order-book representation, settlement math, fee math, withdrawal
authorization schema, replay cache format, or resolution state.

Existing v1/v2 markets remain readable and valid. New v3 markets are independent
market IDs and therefore create independent order books/ledger position buckets.

## Release rule

Deploy a measured enclave that accepts v3 before deploying a control scheduler
that emits v3 market releases.

## Production replay plan

Restore the latest immutable snapshot/journal exactly as with the previous
release. v3 market IDs are new buckets, so replay does not reinterpret any
existing v1/v2 market, order, position, withdrawal, fee, settlement or
resolution record.

## Rollback plan

If the new enclave fails provisioning or v3 registration, freeze the v3 control
scheduler, roll the launch template back to the previous approved AMI/PCR, and
continue serving existing v1/v2 markets. No v1/v2 state needs migration.
