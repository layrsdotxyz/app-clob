#!/bin/bash
# CLOB Service Stress Test
# Tests with hundreds of concurrent orders

set -e

BASE_URL="http://localhost:8081"
MARKET_ID="STRESS-TEST-$(date +%s)"
TOTAL_ORDERS=500
CONCURRENT_JOBS=50

echo "=== CLOB Service Stress Test ==="
echo "Market: $MARKET_ID"
echo "Total Orders: $TOTAL_ORDERS"
echo "Concurrent Jobs: $CONCURRENT_JOBS"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check service health
echo "Checking service health..."
if ! curl -sf "$BASE_URL/health" > /dev/null; then
    echo -e "${RED}❌ Service not healthy${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Service healthy${NC}"
echo ""

# Function to submit an order
submit_order() {
    local user_id=$1
    local side=$2
    local price=$3
    local size=$4
    
    curl -sf -X POST "$BASE_URL/v1/orders" \
        -H "Content-Type: application/json" \
        -d "{
            \"user_id\": \"$user_id\",
            \"market_id\": \"$MARKET_ID\",
            \"side\": \"$side\",
            \"order_type\": \"LIMIT\",
            \"time_in_force\": \"GTC\",
            \"price\": \"$price\",
            \"size\": \"$size\"
        }" > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo 1
    else
        echo 0
    fi
}

export -f submit_order
export BASE_URL
export MARKET_ID

echo "Phase 1: Submitting BUY orders (building the book)..."
start_time=$(date +%s)
success_count=0

# Submit BUY orders at various price levels
for i in $(seq 1 250); do
    user_id="buyer_$i"
    # Prices from 0.40 to 0.49 (below mid)
    price=$(echo "scale=2; 0.40 + ($i % 10) * 0.01" | bc)
    size=$((10 + RANDOM % 90))
    
    if [ $((i % CONCURRENT_JOBS)) -eq 0 ]; then
        wait
    fi
    
    submit_order "$user_id" "BUY" "$price" "$size" &
done

wait
buy_time=$(($(date +%s) - start_time))
echo -e "${GREEN}✅ Phase 1 Complete${NC} - Time: ${buy_time}s"
echo ""

echo "Phase 2: Submitting SELL orders (some will match)..."
start_time=$(date +%s)

# Submit SELL orders at various price levels
for i in $(seq 1 250); do
    user_id="seller_$i"
    # Prices from 0.45 to 0.54 (some overlap with buys)
    price=$(echo "scale=2; 0.45 + ($i % 10) * 0.01" | bc)
    size=$((10 + RANDOM % 90))
    
    if [ $((i % CONCURRENT_JOBS)) -eq 0 ]; then
        wait
    fi
    
    submit_order "$user_id" "SELL" "$price" "$size" &
done

wait
sell_time=$(($(date +%s) - start_time))
echo -e "${GREEN}✅ Phase 2 Complete${NC} - Time: ${sell_time}s"
echo ""

# Wait for all orders to be processed
sleep 3

echo "Collecting results..."

# Get orderbook
echo "Checking orderbook depth..."
orderbook=$(curl -sf "$BASE_URL/v1/orderbook/$MARKET_ID?depth=100")
bid_count=$(echo "$orderbook" | jq '.bids | length')
ask_count=$(echo "$orderbook" | jq '.asks | length')

echo "  Bid levels: $bid_count"
echo "  Ask levels: $ask_count"

# Get trades
echo "Checking trades..."
trades=$(curl -sf "$BASE_URL/v1/trades/$MARKET_ID")
trade_count=$(echo "$trades" | jq 'length')
echo "  Total trades: $trade_count"

# Get metrics
echo "Checking metrics..."
metrics=$(curl -sf "$BASE_URL/metrics")
orders_submitted=$(echo "$metrics" | grep 'clob_orders_submitted_total' | grep -v '#' | awk '{sum+=$2} END {print sum}')
matches=$(echo "$metrics" | grep 'clob_matches_total' | grep -v '#' | awk '{sum+=$2} END {print sum}')

echo "  Orders submitted: $orders_submitted"
echo "  Matches: $matches"
echo ""

# Test order cancellation
echo "Phase 3: Testing order cancellation..."
# Get a random open order
sample_order=$(curl -sf "$BASE_URL/v1/orders/user/buyer_1" | jq -r '.[0].id // empty')

if [ -n "$sample_order" ]; then
    cancel_result=$(curl -sf -X DELETE "$BASE_URL/v1/orders/$sample_order?user_id=buyer_1")
    if echo "$cancel_result" | jq -e '.status == "CANCELLED"' > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Order cancellation working${NC}"
    else
        echo -e "${YELLOW}⚠️  Order cancellation returned: $(echo $cancel_result | jq -r '.status // "unknown"')${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  No orders found for cancellation test${NC}"
fi
echo ""

# Summary
echo "=== STRESS TEST SUMMARY ==="
echo "Total Time: $((buy_time + sell_time))s"
echo "BUY Orders: 250 in ${buy_time}s ($(echo "scale=2; 250/$buy_time" | bc) orders/sec)"
echo "SELL Orders: 250 in ${sell_time}s ($(echo "scale=2; 250/$sell_time" | bc) orders/sec)"
echo "Order Book: $bid_count bid levels, $ask_count ask levels"
echo "Trades Executed: $trade_count"
echo ""

# Performance check
if [ "$trade_count" -gt 0 ]; then
    echo -e "${GREEN}✅ Matching engine working under load${NC}"
fi

if [ "$bid_count" -gt 0 ] && [ "$ask_count" -gt 0 ]; then
    echo -e "${GREEN}✅ Order book maintained correctly${NC}"
fi

if [ $((buy_time + sell_time)) -lt 120 ]; then
    echo -e "${GREEN}✅ Performance acceptable (<2min for 500 orders)${NC}"
else
    echo -e "${YELLOW}⚠️  Performance slower than expected${NC}"
fi

echo ""
echo "=== TEST COMPLETE ==="
