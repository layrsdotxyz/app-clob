# Authenticated checkpoint / immutable successor recovery

Authorized by the user on 17 September 2026. This specifically supersedes the
previous exclusion of checkpoint startup work. It does not broaden P1 routes,
enable admission, change wallet authority, or permit financial-history edits.

## Recovery contract

Production starts from the latest content-addressed checkpoint under the
existing private epoch archive `checkpoints/` namespace. It checks the exact
artifact/head prefix, authenticates and decrypts one full-state snapshot inside
the enclave, then appends only its immutable successors. Adoption still requires
the exact final sequence and state hash. A checkpoint at 4827 starts at 4827 and
verifies 4828 onward; a newer checkpoint must not be rolled back to 4827.

The snapshot retains balances, identities, wallet links, orders, books,
positions, custody deduplication and **every original request/result**. Active
Bus holds reconstruct from the existing signed receipts, preserving the old
encrypted state schema. Compact receipt metadata and the original artifact
object hashes are retained for projection ordering and historical payout
reconciliation; startup does not reread all historical encrypted snapshots.

Existing production history requires both a checkpoint and a governance-signed
`committedRestoreFrontier` in the next writer grant. That frontier pins a minimum
sequence, state hash and original artifact hash. Missing/corrupt checkpoints,
wrong keys/epochs, archive gaps/forks, a checkpoint below the signed frontier,
and failed final-head verification stop startup. There is **no silent genesis
fallback**. Isolated tests retain the original full-restore path.

## Authentication and one-time predecessor upgrade

Ordinary checkpoints have an enclave-issued HMAC over a protocol-separated CBOR
envelope containing the encrypted artifact, opening root, complete compact
receipt lineage and original archive hashes. Only an already-adopted matching
head can be sealed; original signed receipts must match the encrypted state's
request map exactly. The parent never receives receipt/state keys or plaintext
private state. The encrypted financial artifact format is unchanged.

The live predecessor has no checkpoint endpoint. Its first checkpoint uses a
one-time, domain-separated ECDSA bootstrap certificate verified against the
**existing compiled governance public key**. It binds the epoch/opening root,
sequence/state root, full encrypted artifact hash, receipt-metadata hash and
archive-hashes hash. The new enclave independently checks AEAD, receipt HMACs,
the original-request map, signed cutover frontier and immutable archive prefix.
Successful adoption emits an ordinary enclave-authenticated checkpoint.

Bootstrap procedure (not a database checkpoint or bypass):

1. Prove the predecessor's full restore, exact current governed successor,
   all balances, no duplicate external payment, key continuity and genuine
   nonce-bound Nitro attestation.
2. Prepare the checkpoint from the exact immutable artifact/head prefix using
   `examples/checkpoint-bootstrap.rs prepare ANCHOR OUTPUT`. The anchor contains
   the verified sequence/root and measured source/grant commitment. Every
   artifact/head pair is read completely, byte-compared and content-address
   checked; downloads are bounded to sixteen pairs. Preparation does not sign,
   write remotely or decrypt private state.
3. Recheck the protected preparation bytes/proofs, then use `certify INPUT
   OUTPUT`. This signs the exact certificate using the existing governance KMS
   key and verifies its signature against the compiled public key. The
   operator's certificate explicitly vouches for the already-verified
   predecessor prefix; unverified anchors must never be certified.
4. Stage the certified opaque checkpoint with conditional create, existing
   archive KMS encryption and COMPLIANCE retention at least as long as the source
   head. Verify exact readback. This adds a recovery artifact; it neither edits
   financial history nor activates the checkpoint-capable runtime.
5. Build/measure compatible parent **and enclave**, roll forward the latest
   sealed root-key lineage, sign the exact next grant/frontier, and include them
   in the unified release. Do not reuse a parent-only AMI or an old PCR approval.
6. Prove a genuine non-debug cold restart logs `VERIFIED_ARCHIVE_RESTORE_START
   <checkpoint>/<tip>`, applies only the suffix, preserves balances/identities,
   resumes original IDs as no-ops and reconciles the current head. Keep customer
   admission closed until the remaining funded P1 gates pass.

## Persistence, reply loss and rollback

The original financial artifact/head durability callback and ACK are unchanged.
Checkpoint refresh occurs **after** adoption, in a coalesced background task.
An optional refresh failure cannot change the committed response or authorize
another submission. A crash/lost refresh resumes the previous authenticated
checkpoint plus every committed successor. Startup seeds/readbacks a fresh
checkpoint before serving the restored writer. There is no mutable `latest`
pointer and no financial effect in checkpoint recovery.

Older runtime code ignores the additive checkpoint namespace. Original grants
serialize unchanged when the optional frontier is absent; a newly signed grant
containing the frontier requires a checkpoint-aware verifier. An older fallback
therefore needs its own freshly governed compatible grant, not the new grant.
Checkpoint support does not authorize restoring an old
writer grant, key artifact or balances. Any fallback rolls forward the current
key/history and still obeys existing Bus-hold drain restrictions.

## Local acceptance / remaining release gates

134 tests pass: 58 library, 20 enclave, 53 parent and three bootstrap-helper tests.
They cover exact-tip adoption, reconnect, invalid MAC/ciphertext/keys/epochs,
missing receipts, substituted identities/archive hashes, suffix gaps, signed
frontier rollback/forks, active-hold preservation and original-ID no-op recovery.
Independently persisted original PostgreSQL receipts must also occur exactly in
the authenticated recovered lineage: even a balance-free successor cannot be
hidden by presenting an older archive tip. The database can fence incomplete
recovery but never supplies/adopts private state.
The 4827→4828 fixture has genuine signed request results and a genuine encrypted
final snapshot but **synthetic intermediate archive metadata**; it is a bounded
protocol-size/counter test, not funded or production cold-start evidence.

Release gates still pending: exact versioned measured parent/enclave artifact,
current-root-key-compatible cutover grant with the frontier, unified deployment,
and actual cold-restart/no-op proof. Local tests and checkpoint staging must not
be reported as deployment, cold-start certification or funded P1 certification.
