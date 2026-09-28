# v70 bridge memory benchmark

Date: 2026-09-28

Scope: local synthetic benchmark only. No production artifact, secret, AWS,
database, S3, EIF, grant, or deployment operation was used.

The bridge raises the shared parent/enclave frame ceiling to 768 MiB and raises
the finite v70 lineage-record guard from 100,000 to 250,000. The frame remains
the tighter bound for normal-sized records.

## Near-limit state benchmark

Command:

```text
LAYRS_BRIDGE_BENCH_RECORDS=200000 /usr/bin/time -v <lib-test-binary> \
  --ignored --exact \
  tests::v70_bridge_commit_checkpoint_and_restore_memory_benchmark --nocapture
```

Results:

| Stage | Elapsed | Encoded bytes | Process high-water RSS |
| --- | ---: | ---: | ---: |
| Fixture construction | 30.755 s | n/a | 1,002,500 KiB |
| Full-state commit candidate | 100.844 s | 428,796,104 | 2,659,528 KiB |
| Checkpoint seal and encoding | 115.680 s | 688,466,676 | 3,510,024 KiB |
| Full checkpoint restore | 156.635 s | 688,466,676 input | 3,510,024 KiB |

The exact release candidate `9f93fb0`, rebuilt with `Cargo.lock` enforced after
integrating the production parent-health change, produced the same encoded
sizes with these optimized-stage results:

| Stage | Elapsed | Encoded bytes | Process high-water RSS |
| --- | ---: | ---: | ---: |
| Fixture construction | 2.848 s | n/a | 998,932 KiB |
| Full-state commit candidate | 4.568 s | 428,796,104 | 2,655,960 KiB |
| Checkpoint seal and encoding | 9.819 s | 688,466,676 | 3,506,420 KiB |
| Full checkpoint restore | 9.077 s | 688,466,676 input | 3,506,420 KiB |

The candidate process peak was 3,506,420 KiB and the complete ignored test
finished in 34.19 seconds.

Restore reproduced the exact sequence and canonical full-state hash. The peak
was about 3.35 GiB, below the 8 GiB enclave allocation. The test deliberately
keeps the source runtime and checkpoint alive during restore, making the memory
overlap conservative.

## Exact frame-boundary benchmark

The 768 MiB round-trip test accepted exactly `MAX_FRAME_BYTES` and rejected one
byte more on both read and write. `/usr/bin/time -v` reported 1,580,672 KiB
maximum RSS.

## Interpretation

This validates emergency recovery headroom; it does not make v70 fast. The
first conservative run took about 101 seconds for the full-state candidate;
the exact optimized release candidate took 4.568 seconds locally. Neither
measurement includes production VSOCK, multipart S3 upload, exact readback,
fence listing, or host/network tails. The v71 bounded journal remains required
to remove full-state serialization, upload, readback, and verification from
each commit.
