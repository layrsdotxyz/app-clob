# Phase-1 prover benchmark

Measured on 2026-07-28 using the production Linux container and the canonical
real-market fixture `layrs:v3:ZEN:15m:1785196800.json`.

## Runtime envelope

- RISC Zero: `2.2.0`
- guest image ID:
  `0x563cc7ea1bdf5583d07234d48a198b41e348ac51bd4c8ae028652974284746dc`
- container image ID:
  `sha256:3d2d514b21d579650606481e17dcb03ed5367837dcafeb881ff972100b4895bd`
- container image size: `2,361,516,883` bytes
- container user: unprivileged UID `1001`
- measured wall-clock latency: `91` seconds
- observed peak container memory: `2.275 GiB`
- observed peak CPU: approximately `739%` across available cores

The production scheduled Fargate task is provisioned with 4 vCPU, 16 GiB RAM
and 50 GiB ephemeral storage. Proving is asynchronous and never blocks matching
or settlement.

## Deterministic public output

- public journal SHA-256:
  `9a7ab21b3b41f1bb8a29d3d41d92f256c98f013986b6cc082ebf0a0fbf2bc3b6`
- public output JSON SHA-256:
  `e3cd4db4c81a68ed75a903a55c20e659b5fa5f7a3670ea75651b63b1b631aa67`
- public journal size: `480` bytes
- proof size in this run: `315,319` bytes

RISC Zero proof bytes are not treated as a deterministic build artifact.
Reproducibility is anchored to the guest image ID, verified public journal and
settlement commitment.

## Reproduction

```bash
docker build -f Dockerfile.zk-proof-worker \
  -t layrs-zk-proof-worker:local .

docker run --rm \
  --entrypoint /app/bin/layrs-settlement-proof-host \
  -v "$PWD/proofs/settlement/fixtures:/input:ro" \
  -v "$PWD/proof-output:/out" \
  layrs-zk-proof-worker:local \
  /input/layrs-v3-zen-15m-1785196800.json /out
```

The input directory must be readable by UID `1001`, and the output directory
must be writable by UID `1001`.
