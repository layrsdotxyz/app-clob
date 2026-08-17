# Deterministic replay vectors

`tests/vectors/e10_replay_input_v1.json` is a public, test-only semantic journal input. The
integration test executes it twice in fresh private cores and compares the canonical compact JSON
bytes of every resulting fill ID, maker/taker order ID, price, quantity, match type, fee, command
state root, final state root, and final conserved balance. It then compares those bytes with the
checked-in `e10_replay_expected_v1.json` golden output.

Run the certification with:

```sh
cargo test --locked --test deterministic_replay_vectors
```

All keys, commitments, sessions, IDs, balances, and markets in these fixtures are synthetic test
values. They must never be used in a live environment.

## Determinism boundary

The vector certifies replay of the decrypted, authenticated semantic journal input used by the
matching and financial core. Encrypted journal ciphertext, AEAD nonces, receipt signatures, and
their hashes are deliberately absent: fresh randomized encryption is a security property, and
those envelope bytes are not matching state. Their exclusion cannot hide matching drift because
the vector pins the resulting fill data, deterministic IDs, applied fees, ledger roots, and final
balances.

Any intentional financial or state-transition change must publish a new versioned input/output
pair. Editing the existing expected fixture without a reviewed protocol change defeats the replay
gate.
