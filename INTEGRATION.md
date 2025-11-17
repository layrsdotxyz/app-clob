# CLOB Service Integration Guide

## Quick Start

### 1. Test Compilation

```bash
cd clob-service
cargo check
```

### 2. Run Locally

```bash
# Start Redis
docker run -d --name redis-clob -p 6379:6379 redis:7-alpine

# Create .env file
cat > .env << EOF
HOST=0.0.0.0
PORT=8080
REDIS_URL=redis://localhost:6379
RUST_LOG=clob_service=debug,tower_http=debug
EOF

# Build and run
cargo run --release
```

### 3. Test API

```bash
# Health check
curl http://localhost:8080/health

# Create order
curl -X POST http://localhost:8080/v1/orders \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "market_id": "ETH-USD-2025",
    "side": "buy",
    "order_type": "LIMIT",
    "time_in_force": "GTC",
    "price": "100.50",
    "size": "10.0"
  }'

# Get order book
curl http://localhost:8080/v1/orderbook/ETH-USD-2025?depth=20

# Get recent trades
curl http://localhost:8080/v1/trades/ETH-USD-2025?limit=50
```

### 4. Test WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8080/v1/ws');

ws.onopen = () => {
  // Subscribe to order book updates
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'orderbook',
    market_id: 'ETH-USD-2025'
  }));
  
  // Subscribe to trades
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'trades',
    market_id: 'ETH-USD-2025'
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  console.log('Received:', msg);
};
```

## Integration with Backend

### 1. Add Predifi Venue Adapter

In `backend/src/venues/adapters/`, create `predifi.adapter.ts`:

```typescript
import type { VenueAdapter } from '../adapter.js';
import type { Market, MarketWithQuotes } from '../../types/market.js';

export class PredifiAdapter implements VenueAdapter {
  private baseUrl: string;
  
  constructor(config: { baseUrl: string }) {
    this.baseUrl = config.baseUrl;
  }
  
  async listActiveMarkets(): Promise<Market[]> {
    const response = await fetch(`${this.baseUrl}/v1/markets`);
    const { markets } = await response.json();
    
    return markets.map((marketId: string) => ({
      venue: 'predifi',
      venueMarketId: marketId,
      // ... map to Market type
    }));
  }
  
  async getOrderBook(marketId: string, depth = 20) {
    const response = await fetch(
      `${this.baseUrl}/v1/orderbook/${marketId}?depth=${depth}`
    );
    return response.json();
  }
  
  async submitOrder(order: any) {
    const response = await fetch(`${this.baseUrl}/v1/orders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(order),
    });
    return response.json();
  }
}
```

### 2. Add WebSocket Consumer

In `backend/src/websockets/`, create `clob-consumer.ts`:

```typescript
import WebSocket from 'ws';

export class ClobWebSocketConsumer {
  private ws: WebSocket;
  private subscribers = new Map<string, Set<Function>>();
  
  constructor(url: string) {
    this.ws = new WebSocket(url);
    this.setupHandlers();
  }
  
  private setupHandlers() {
    this.ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      
      if (msg.type === 'orderbook_update') {
        this.notify('orderbook', msg);
      } else if (msg.type === 'trade') {
        this.notify('trade', msg);
      }
    });
  }
  
  subscribe(channel: string, marketId: string, callback: Function) {
    const key = `${channel}:${marketId}`;
    if (!this.subscribers.has(key)) {
      this.subscribers.set(key, new Set());
      
      // Subscribe to CLOB channel
      this.ws.send(JSON.stringify({
        type: 'subscribe',
        channel,
        market_id: marketId,
      }));
    }
    
    this.subscribers.get(key)!.add(callback);
  }
  
  private notify(channel: string, data: any) {
    const marketId = data.market_id;
    const key = `${channel}:${marketId}`;
    
    this.subscribers.get(key)?.forEach(cb => cb(data));
  }
}
```

### 3. Update Backend Configuration

In `backend/src/config/index.ts`:

```typescript
export const config = {
  // ... existing config
  venues: {
    // ... existing venues
    predifi: {
      enabled: env.bool('PREDIFI_ENABLED', true),
      apiUrl: env.str('PREDIFI_CLOB_URL', 'http://localhost:8080'),
      wsUrl: env.str('PREDIFI_CLOB_WS_URL', 'ws://localhost:8080/v1/ws'),
    },
  },
};
```

## Cloud Run Deployment

### 1. Setup Redis Cloud

```bash
# Use Redis Cloud or Memorystore
# Get connection URL: redis://user:password@host:port
```

### 2. Create Secret

```bash
gcloud secrets create REDIS_URL \
  --data-file=- \
  --project=zoopx-0xperps \
  <<< "redis://your-redis-url"
```

### 3. Deploy CLOB Service

```bash
cd clob-service
./deploy-cloudrun.sh us-east1 predifi-clob
```

### 4. Update Backend Environment

```bash
# In backend/.env
PREDIFI_ENABLED=true
PREDIFI_CLOB_URL=https://predifi-clob-xxxxx-ue.a.run.app
PREDIFI_CLOB_WS_URL=wss://predifi-clob-xxxxx-ue.a.run.app/v1/ws
```

## Monitoring

### Prometheus Metrics

```bash
# Scrape metrics
curl http://localhost:8080/metrics

# Key metrics:
# - clob_orders_submitted_total{market_id, side}
# - clob_order_latency_seconds_bucket{status}
# - clob_matches_total{market_id}
# - clob_orderbook_depth_bids{market_id}
# - clob_trades_total{market_id}
# - clob_ws_connections{type}
```

### Grafana Dashboard

Import dashboard template from `ops/grafana/clob-dashboard.json` (to be created).

## Next Steps

1. **Fix Compilation Issues**: Run `cargo check` and fix any Rust compilation errors
2. **Add Tests**: Create integration tests in `tests/` directory
3. **Benchmark**: Run `cargo bench` to verify performance targets
4. **Security**: Add JWT authentication for order submission
5. **Balance Integration**: Connect settlement engine to on-chain wallets or balance service
6. **Market Registry**: Integrate with backend market registry to validate market_id
7. **Rate Limiting**: Add per-user rate limiting with Tower middleware
8. **Circuit Breaker**: Add circuit breaker for Redis connection
9. **Monitoring**: Set up Grafana dashboard and alerting
10. **Load Testing**: Use `k6` or `wrk` to test under load

## Troubleshooting

### Redis Connection Errors
```bash
# Check Redis is running
redis-cli ping

# Test connection
redis-cli -u redis://localhost:6379 ping
```

### Compilation Errors
```bash
# Update dependencies
cargo update

# Clean build
cargo clean && cargo build
```

### Port Already in Use
```bash
# Find process using port 8080
lsof -i :8080

# Kill process
kill -9 <PID>
```
