# Predifi CLOB Service

Production-grade Central Limit Order Book (CLOB) microservice for the Predifi prediction market platform.

## Overview

The CLOB service is a standalone microservice that provides:
- **Order Book Management**: Redis-backed in-memory order books with price-time priority
- **Matching Engine**: High-performance order matching with atomic execution
- **REST API**: Order submission, cancellation, order book snapshots, trade history
- **WebSocket Server**: Real-time broadcasts for order book updates, trades, and order status
- **Settlement Integration**: Hooks for balance verification and position settlement
- **Monitoring**: Prometheus metrics for latency, throughput, and system health

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLOB Service                             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  REST API    │    │  WebSocket   │    │   Metrics    │  │
│  │  (Fastify)   │    │  (Socket.io) │    │ (Prometheus) │  │
│  └──────┬───────┘    └──────┬───────┘    └──────────────┘  │
│         │                   │                                │
│  ┌──────▼───────────────────▼──────────────────────────┐   │
│  │           Matching Engine (Core Logic)              │   │
│  │  • Order validation & matching                      │   │
│  │  • Price-time priority algorithm                    │   │
│  │  • Partial fills & order types (GTC/IOC/FOK)       │   │
│  │  • Event emission (fills, cancels, updates)        │   │
│  └──────┬──────────────────────────────────────────────┘   │
│         │                                                    │
│  ┌──────▼───────────────────────────────────────────────┐  │
│  │         Order Book Manager (Redis)                   │  │
│  │  • Sorted sets for bids/asks (price-time)           │  │
│  │  • Fast lookups: O(log n) insert, O(1) best price   │  │
│  │  • Atomic operations with Lua scripts               │  │
│  └──────┬──────────────────────────────────────────────┘  │
│         │                                                    │
└─────────┼────────────────────────────────────────────────────┘
          │
    ┌─────▼─────┐       ┌──────────────┐
    │   Redis   │       │  PostgreSQL  │
    │  (Orders) │       │  (Trades)    │
    └───────────┘       └──────────────┘
```

## Tech Stack

- **Runtime**: Node.js 20+ with TypeScript
- **Web Framework**: Fastify 5 (REST API)
- **WebSocket**: Socket.io 4 (real-time broadcasts)
- **Order Book Storage**: Redis 7 (sorted sets, pub/sub)
- **Trade Persistence**: PostgreSQL 15 (historical trades, order ledger)
- **Metrics**: prom-client (Prometheus)
- **Deployment**: AWS ECS (Fargate) on cluster `layrs`
- **Testing**: Vitest with integration test suite

## Order Types

- **GTC (Good Till Cancel)**: Remains in book until filled or explicitly cancelled
- **IOC (Immediate or Cancel)**: Fill immediately or cancel unfilled portion
- **FOK (Fill or Kill)**: Fill entire order immediately or cancel completely
- **POST_ONLY**: Only add liquidity, reject if would match existing orders

## API Endpoints

### REST API

```
POST   /v1/orders              - Submit new order
DELETE /v1/orders/:id          - Cancel order
GET    /v1/orders/:id          - Get order status
GET    /v1/orders              - List user orders (authenticated)
GET    /v1/orderbook/:marketId - Get order book snapshot
GET    /v1/trades/:marketId    - Get recent trades
GET    /v1/trades/:marketId/history - Get historical trades (paginated)
GET    /health                 - Health check
GET    /metrics                - Prometheus metrics
```

### WebSocket Events

```javascript
// Subscribe to market
socket.emit('subscribe', { channel: 'orderbook', marketId: 'market-123' })
socket.emit('subscribe', { channel: 'trades', marketId: 'market-123' })
socket.emit('subscribe', { channel: 'orders', userId: 'user-456' }) // authenticated

// Orderbook updates
socket.on('orderbook:update', { marketId, bids: [...], asks: [...], timestamp })

// Trade executions
socket.on('trade:executed', { marketId, price, size, side, timestamp, takerOrderId, makerOrderId })

// User order updates (private channel)
socket.on('order:status', { orderId, status, filledSize, remainingSize })
```

## Deployment

```bash
# Run from layrs-backend/ — builds image, pushes to ECR, deploys to ECS
AWS_PROFILE=layrs bash deploy-clob.sh

# Service URL
https://clob.layrs.xyz
```

## Environment Variables

See `.env.example` for complete configuration. Key variables:

```bash
NODE_ENV=production
PORT=8080

# Redis (order book)
REDIS_HOST=redis-12345.c1.us-east1-1.gce.redns.redis-cloud.com
REDIS_PORT=12345
REDIS_PASSWORD=secret

# PostgreSQL (trades)
DATABASE_URL=postgresql://user:pass@host:5432/clob

# Security
JWT_SECRET=your-jwt-secret
CORS_ORIGINS=https://predifi.com,https://app.predifi.com

# Performance
MAX_ORDERS_PER_USER=100
MAX_ORDER_BOOK_DEPTH=1000
MATCHING_ENGINE_TICK_MS=10
```

## Monitoring

Prometheus metrics exposed at `/metrics`:

- `clob_orders_total{status}` - Total orders submitted
- `clob_orders_matched_total` - Total orders matched
- `clob_order_latency_seconds` - Order processing latency histogram
- `clob_matching_duration_seconds` - Matching engine cycle duration
- `clob_orderbook_depth{side}` - Current order book depth
- `clob_websocket_connections` - Active WebSocket connections
- `clob_redis_operations_total{operation}` - Redis operation counter

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Run integration tests
npm run test:integration

# Build for production
npm run build

# Start production server
npm start
```

## Performance Targets

- Order submission latency: < 10ms (p99)
- Matching cycle duration: < 5ms (p99)
- WebSocket broadcast latency: < 50ms (p99)
- Order book snapshot generation: < 20ms
- Throughput: > 1,000 orders/sec per market

## License

Proprietary - Predifi © 2025
