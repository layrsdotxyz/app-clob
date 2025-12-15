# CLOB Service Integration Issue

## Problem
The live market simulation encounters DATABASE_ERROR when orders match in the CLOB service.

## Root Cause
- Non-matching orders work perfectly (verified)  
- Matching orders fail during `settle_trade()` execution
- Error occurs in Redis operations when saving trades:
  - `save_trade()` in `redis_store.rs` line 224-243
  - `update_market_stats()` in `redis_store.rs` line 269-305

## Evidence
```
# Working: Non-matching order
curl -X POST http://localhost:8080/v1/orders \
  -d '{"user_id":"buyer1","market_id":"TEST","side":"BUY","price":0.5,"size":0.1}'
→ SUCCESS (order added to book)

# Failing: Matching order
curl -X POST http://localhost:8080/v1/orders \
  -d '{"user_id":"seller1","market_id":"TEST","side":"SELL","price":0.5,"size":0.05}'
→ {"error":{"code":"DATABASE_ERROR","message":"Database error"}}
```

## Logs Show
```
Retrieved counter orders: counter_orders_count=1
→ Match found, executing trade
→ 500 Internal Server Error (DATABASE_ERROR)
```

## Next Steps to Fix
1. Add detailed error logging in `settlement.rs` `settle_trade()` method
2. Check Redis type annotations (warnings about never type fallback)
3. Verify Redis connection handling during concurrent operations
4. Test with Redis MONITOR to see exact failing command

## Workaround
For simulation testing, the test harness with mock orderbook (`pnpm sim:test`) works perfectly and tests all logic without CLOB service dependency.

## Files to Fix
- `clob-service/src/redis_store.rs` (lines 224-243, 269-305)
- `clob-service/src/settlement.rs` (lines 58-81)
- `clob-service/src/matching.rs` (line 284 - improve error handling)
