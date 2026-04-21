CREATE TABLE IF NOT EXISTS deposits (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    transaction_hash VARCHAR(130) UNIQUE,
    token_address VARCHAR(66),
    amount NUMERIC(78, 0),
    block_number BIGINT,
    status VARCHAR(20),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    order_id VARCHAR(64) UNIQUE,
    market_id VARCHAR(64),
    side VARCHAR(8),
    price NUMERIC(28, 18),
    amount NUMERIC(28, 18),
    status VARCHAR(20),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS positions (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    market_id VARCHAR(64),
    side VARCHAR(8),
    size NUMERIC(28, 18),
    average_price NUMERIC(28, 18),
    realized_pnl NUMERIC(28, 18),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS markets (
    id BIGSERIAL PRIMARY KEY,
    market_id VARCHAR(64) UNIQUE,
    description TEXT,
    expiry TIMESTAMP,
    oracle_address VARCHAR(66),
    resolution_price NUMERIC(28, 18),
    status VARCHAR(20),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deposits_user_id ON deposits(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_user_id ON withdrawals(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_market_id ON orders(market_id);
CREATE INDEX IF NOT EXISTS idx_positions_user_market ON positions(user_id, market_id);
CREATE INDEX IF NOT EXISTS idx_markets_status ON markets(status);
