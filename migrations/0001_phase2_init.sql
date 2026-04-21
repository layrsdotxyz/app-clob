CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    starknet_address VARCHAR(66) UNIQUE,
    proxy_address VARCHAR(66),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS balances (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    token_address VARCHAR(66),
    balance NUMERIC(78, 0),
    commitment CHAR(64),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS processed_deposits (
    id BIGSERIAL PRIMARY KEY,
    chain_id BIGINT NOT NULL,
    tx_hash VARCHAR(130) NOT NULL,
    user_wallet VARCHAR(66) NOT NULL,
    token VARCHAR(66) NOT NULL,
    amount VARCHAR(80) NOT NULL,
    block_number BIGINT NOT NULL,
    processed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(chain_id, tx_hash)
);

CREATE TABLE IF NOT EXISTS deposit_checkpoints (
    chain_id BIGINT PRIMARY KEY,
    last_block BIGINT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_nonces (
    wallet VARCHAR(66) PRIMARY KEY,
    nonce BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS withdrawals (
    id BIGSERIAL PRIMARY KEY,
    withdrawal_id VARCHAR(80) UNIQUE,
    user_id UUID REFERENCES users(user_id),
    transaction_hash VARCHAR(130),
    token_address VARCHAR(66),
    amount VARCHAR(80),
    destination_address VARCHAR(66),
    proof_data JSONB,
    status VARCHAR(20),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
