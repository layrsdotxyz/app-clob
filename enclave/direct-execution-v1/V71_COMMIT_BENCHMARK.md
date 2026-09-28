# v71 production-sized commit benchmark

Date: 2026-09-28

Scope: local synthetic benchmark only. No production artifact, secret, AWS,
database, S3, EIF, grant, or deployment operation was used.

The fixture creates 35,000 genuine terminal v70 results while keeping the
financial state constant, seals and authenticates the migration bundle, then
proves that the migrated v71 runtime has no full request map. The timed loop
includes sparse-proof generation, candidate execution, signed journal-record
encoding, request-index insertion and candidate adoption. Migration setup is
reported separately and is not included in commit percentiles.

## Command

```text
LAYRS_V71_BENCH_HISTORY=35000 LAYRS_V71_BENCH_SAMPLES=250 \
  /usr/bin/time -v cargo test --release \
  --manifest-path enclave/direct-execution-v1/Cargo.toml --lib \
  v71::tests::v71_production_sized_commit_latency_benchmark \
  -- --ignored --nocapture
```

A second run invoked the already-built release test binary directly so its
RSS measurement excludes the compiler.

## Results

| Run | Setup | Max record | p50 | p95 | p99 | Max RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Conservative cargo run | 137.610 s | 36,081 B | 8.348 ms | 15.362 ms | 19.528 ms | compiler included |
| Direct release binary | 152.050 s | 36,081 B | 4.907 ms | 7.430 ms | 8.505 ms | 345,304 KiB |

The second setup was slower because another isolated worktree was compiling at
the same time; the timed commit percentiles still remained far below one
second. Both runs asserted a 35,000-sequence migration, an empty v71 full
request map, exact final sequence, and a journal record below 64 KiB.

## Interpretation and remaining gate

This demonstrates that historical v70 request-result state is removed from the
v71 commit path and that local cryptographic/state work has substantial margin
inside the p50 250 ms, p95 750 ms and p99 one-second targets.

It does **not** measure VSOCK, KMS-backed S3 Object Lock PUT, exact readback,
fence listing, host scheduling, or network tails. End-to-end production-sized
measurement of that unchanged durability path is still a mandatory rollout
gate; local results must not be reported as production latency.
