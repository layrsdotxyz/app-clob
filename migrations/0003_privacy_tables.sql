-- Phase 3: Privacy-preserving state tables
-- private_notes, private_nullifiers, private_transitions, prover_jobs, commitment_roots
-- These mirror the Redis-based PrivacyStateService and ProverPipeline for long-term
-- durability and auditability.  Redis remains the primary fast store; Postgres acts as
-- a write-behind audit log flushed asynchronously.

-- Private commitment notes (created on deposit, spent on withdrawal)
CREATE TABLE IF NOT EXISTS private_notes (
    note_id         VARCHAR(64) PRIMARY KEY,
    commitment      VARCHAR(130) UNIQUE NOT NULL,
    amount_commitment VARCHAR(130) NOT NULL,
    asset           VARCHAR(130) NOT NULL,
    owner_key_hash  VARCHAR(130) NOT NULL,
    epoch_id        BIGINT NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'unspent',   -- unspent | locked | spent
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_private_notes_commitment  ON private_notes(commitment);
CREATE INDEX IF NOT EXISTS idx_private_notes_status      ON private_notes(status);
CREATE INDEX IF NOT EXISTS idx_private_notes_owner       ON private_notes(owner_key_hash);

-- Nullifier registry (prevents double-spend; insert is idempotent via UNIQUE)
CREATE TABLE IF NOT EXISTS private_nullifiers (
    nullifier        VARCHAR(130) PRIMARY KEY,
    note_commitment  VARCHAR(130) NOT NULL REFERENCES private_notes(commitment),
    tx_ref           VARCHAR(200) NOT NULL,         -- e.g. "wd-intent:0xabc"
    created_at       TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_private_nullifiers_commitment ON private_nullifiers(note_commitment);

-- Private state transitions (one per proof job; tracks Pending→Attested→Finalized)
CREATE TABLE IF NOT EXISTS private_transitions (
    transition_id    VARCHAR(64) PRIMARY KEY,
    epoch_id         BIGINT NOT NULL,
    old_root         VARCHAR(130) NOT NULL,
    new_root         VARCHAR(130) NOT NULL,
    nullifiers       JSONB NOT NULL DEFAULT '[]',
    new_commitments  JSONB NOT NULL DEFAULT '[]',
    proof_job_id     VARCHAR(64),
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending | attested | finalized | failed
    chain_tx_hash    VARCHAR(130),                            -- set after root published on chain
    created_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_private_transitions_job    ON private_transitions(proof_job_id);
CREATE INDEX IF NOT EXISTS idx_private_transitions_status ON private_transitions(status);
CREATE INDEX IF NOT EXISTS idx_private_transitions_epoch  ON private_transitions(epoch_id);

-- Prover jobs queue (mirrors Redis ProverPipeline; Postgres copy for durability)
CREATE TABLE IF NOT EXISTS prover_jobs (
    job_id        VARCHAR(64) PRIMARY KEY,
    job_type      VARCHAR(40) NOT NULL,    -- private_deposit | private_withdraw | ...
    circuit_name  VARCHAR(100) NOT NULL,
    input_key     VARCHAR(200) NOT NULL,   -- Redis key of the snarkjs input
    status        VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts      SMALLINT NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_prover_jobs_status ON prover_jobs(status);
CREATE INDEX IF NOT EXISTS idx_prover_jobs_type   ON prover_jobs(job_type);

-- Commitment root log (immutable audit; one row per finalized Merkle root)
CREATE TABLE IF NOT EXISTS commitment_roots (
    id               BIGSERIAL PRIMARY KEY,
    root_hex         VARCHAR(130) NOT NULL,
    epoch_id         BIGINT,
    transition_id    VARCHAR(64) REFERENCES private_transitions(transition_id),
    chain_tx_hash    VARCHAR(130),
    published_at     TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_commitment_roots_chain_tx ON commitment_roots(chain_tx_hash);
CREATE INDEX IF NOT EXISTS idx_commitment_roots_epoch       ON commitment_roots(epoch_id);
