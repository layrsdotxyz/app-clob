# Layrs CLOB Service

Production-grade Central Limit Order Book (CLOB) matching engine built in Rust.

## Features

- **High-Performance Matching Engine**: Sub-millisecond order matching with price-time priority
- **Redis-Backed Order Book**: Persistent order book with sorted sets for efficient depth queries
- **REST API**: Comprehensive REST API for order management, order book snapshots, and trade history
- **WebSocket Server**: Real-time broadcasts for order book updates, trade executions, and user-specific order status
- **Settlement Engine**: Balance verification, position limits, and fee calculation
- **Prometheus Metrics**: Full observability with order latency, match rate, book depth, and WebSocket metrics
- **ECS Ready**: Docker multi-stage build with health checks and graceful shutdown

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ HTTP/WS
       │
┌──────▼──────────────────────────────────────┐
│          Axum REST API + WebSocket          │
├─────────────────────────────────────────────┤
│           Matching Engine (Core)            │
│  ┌──────────────────────────────────────┐  │
│  │  Order Validation & Risk Checks      │  │
│  │  Price-Time Priority Matching        │  │
│  │  Partial Fills & IOC/FOK/GTC         │  │
│  │  Atomic Trade Execution              │  │
│  └──────────────────────────────────────┘  │
├─────────────────────────────────────────────┤
│         Order Book Manager (Redis)          │
│  ┌──────────────────────────────────────┐  │
│  │  Sorted Sets (Bids/Asks)             │  │
│  │  Price-Level Aggregation             │  │
│  │  Efficient Depth Queries             │  │
│  └──────────────────────────────────────┘  │
├─────────────────────────────────────────────┤
│            Settlement Engine                │
│  ┌──────────────────────────────────────┐  │
│  │  Balance Verification                │  │
│  │  Fee Calculation                     │  │
│  │  Trade Finalization                  │  │
│  └──────────────────────────────────────┘  │
└──────────────┬──────────────────────────────┘
               │
        ┌──────▼──────┐
        │    Redis    │
        └─────────────┘
```

## API Endpoints

### Orders
- `POST /v1/orders` - Submit new order
- `DELETE /v1/orders/:id` - Cancel order
- `GET /v1/orders/:id` - Get order details
- `GET /v1/orders/user/:user_id` - Get user's orders

### Order Book
- `GET /v1/orderbook/:market_id` - Get order book snapshot
- `GET /v1/orderbook/:market_id/depth` - Get depth chart data

### Trades
- `GET /v1/trades/:market_id` - Get recent trades
- `GET /v1/trades/:market_id/history` - Get historical trades with pagination
- `GET /v1/trades/user/:user_id` - Get user's trades

### Markets
- `GET /v1/markets` - List active markets
- `GET /v1/markets/:market_id/stats` - Get market statistics

### WebSocket
- `GET /v1/ws` - WebSocket connection for real-time updates

### Observability
- `GET /health` - Health check
- `GET /ready` - Readiness check
- `GET /metrics` - Prometheus metrics

## WebSocket Channels

Subscribe to channels by sending:
```json
{
  "type": "subscribe",
  "channel": "orderbook",
  "market_id": "ETH-USD"
}
```

Available channels:
- `orderbook:{market_id}` - Order book updates
- `trades:{market_id}` - Trade executions
- User-specific channel (authenticated) - Order status updates

## Development

### Prerequisites
- Rust 1.82+
- Redis 6.0+

### Build
```bash
cargo build --release
```

### Run Locally
```bash
# Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# Set environment variables
cp .env.example .env
source .env

# Run service
cargo run --release
```

### Test
```bash
# Unit tests
cargo test

# Integration tests
cargo test --test '*'

# Benchmarks
cargo bench
```

## Deployment

### AWS deployment
```bash
# Build from this repository. Production infrastructure is delivered separately.
docker build -t layrs-clob-service:local .
```

Every new AWS resource and secret must use the `layrsv2` prefix. The legacy
Layrs AWS estate is not a deployment target.

### Configuration

Environment variables:
- `HOST` - Server host (default: `0.0.0.0`)
- `PORT` - Server port (default: `8080`)
- `REDIS_URL` - Redis connection URL (required)
- `MAX_ORDERS_PER_USER` - Maximum open orders per user (default: `100`)
- `MAX_ORDER_SIZE` - Maximum order size (default: `1000000`)
- `MIN_ORDER_SIZE` - Minimum order size (default: `1`)
- `MAKER_FEE_BPS` - Maker fee in basis points (default: `10` = 0.10%)
- `TAKER_FEE_BPS` - Taker fee in basis points (default: `20` = 0.20%)
- `RUST_LOG` - Logging level (default: `clob_service=info`)

## Performance

Target latencies:
- Order submission: < 1ms p50, < 5ms p99
- Order matching: < 100μs p50, < 500μs p99
- WebSocket broadcast: < 10ms p99
- Order book query: < 1ms p99

## Redis Schema

### Order Book (Sorted Sets)
- `ob:bid:{market_id}` - Bid orders (score: -price for descending order)
- `ob:ask:{market_id}` - Ask orders (score: price for ascending order)
- Members: `{order_id}:{size}:{timestamp_nanos}`

### Orders (Hashes)
- `order:{order_id}` - Order details (JSON)

### User Orders (Sets)
- `user:orders:{user_id}` - Set of order IDs

### Trades (Sorted Sets)
- `market:trades:{market_id}` - Trade IDs (score: timestamp)
- `user:trades:{user_id}` - Trade IDs (score: timestamp)
- `trade:{trade_id}` - Trade details (JSON)

### Market Stats (Hashes)
- `market:stats:{market_id}` - last_price, volume_24h, high_24h, low_24h

## License

Proprietary - Layrs
