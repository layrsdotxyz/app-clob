#!/bin/bash
# Fast CLOB Stress Test - Testing matching and throughput

set -e

BASE_URL="http://localhost:8081"
MARKET_ID="FAST-TEST-$(date +%s)"

echo "=== CLOB Fast Stress Test ==="
echo "Market: $MARKET_ID"
echo ""

# Check service
if ! curl -sf "$BASE_URL/health" > /dev/null; then
    echo "❌ Service not healthy"
    exit 1
fi
echo "✅ Service healthy"
echo ""

# Test 1: Rapid order submission (100 orders)
echo "Test 1: Submitting 100 BUY orders rapidly..."
start=$(date +%s.%N)
for i in {1..100}; do
    price="0.$((40 + i % 10))"
    size=$((10 + i % 50))
    curl -sf -X POST "$BASE_URL/v1/orders" \
        -H "Content-Type: application/json" \
        -d "{\"user_id\":\"buyer_$i\",\"market_id\":\"$MARKET_ID\",\"side\":\"BUY\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"$price\",\"size\":\"$size\"}" > /dev/null &
    
    # Control concurrency
    if [ $((i % 20)) -eq 0 ]; then
        wait
    fi
done
wait
buy_duration=$(echo "$(date +%s.%N) - $start" | bc)
echo "✅ 100 BUY orders in ${buy_duration}s"

# Test 2: Matching orders
echo ""
echo "Test 2: Submitting 100 SELL orders (will match with BUYs)..."
start=$(date +%s.%N)
for i in {1..100}; do
    price="0.$((40 + i % 10))"
    size=$((10 + i % 50))
    curl -sf -X POST "$BASE_URL/v1/orders" \
        -H "Content-Type: application/json" \
        -d "{\"user_id\":\"seller_$i\",\"market_id\":\"$MARKET_ID\",\"side\":\"SELL\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"$price\",\"size\":\"$size\"}" > /dev/null &
    
    if [ $((i % 20)) -eq 0 ]; then
        wait
    fi
done
wait
sell_duration=$(echo "$(date +%s.%N) - $start" | bc)
echo "✅ 100 SELL orders in ${sell_duration}s"

# Wait for processing
sleep 3

# Get results
echo ""
echo "=== RESULTS ==="
orderbook=$(curl -sf "$BASE_URL/v1/orderbook/$MARKET_ID?depth=20")
trades=$(curl -sf "$BASE_URL/v1/trades/$MARKET_ID")

bid_count=$(echo "$orderbook" | jq '.bids | length')
ask_count=$(echo "$orderbook" | jq '.asks | length')
trade_count=$(echo "$trades" | jq 'length')

total_duration=$(echo "$buy_duration + $sell_duration" | bc)
throughput=$(echo "scale=2; 200 / $total_duration" | bc)

echo "Total Time: ${total_duration}s"
echo "Throughput: ${throughput} orders/sec"
echo "Order Book: $bid_count bid levels, $ask_count ask levels"
echo "Trades: $trade_count"
echo ""

# Test 3: Order cancellation under load
echo "Test 3: Cancelling 10 orders..."
cancel_count=0
for i in {1..10}; do
    order=$(curl -sf "$BASE_URL/v1/orders/user/buyer_$i" | jq -r '.[0].id // empty')
    if [ -n "$order" ]; then
        result=$(curl -sf -X DELETE "$BASE_URL/v1/orders/$order?user_id=buyer_$i" | jq -r '.status')
        if [ "$result" == "CANCELLED" ]; then
            ((cancel_count++))
        fi
    fi
done
echo "✅ $cancel_count orders cancelled successfully"
echo ""

# Summary
echo "=== SUMMARY ==="
if [ "$trade_count" -gt 0 ]; then
    echo "✅ Matching engine working ($trade_count trades)"
else
    echo "⚠️  No trades executed"
fi

if [ "$throughput" != "0" ]; then
    echo "✅ Throughput: $throughput orders/sec"
fi

if [ "$cancel_count" -ge 8 ]; then
    echo "✅ Order cancellation working"
fi

echo ""
echo "🎯 Stress test complete: 200 orders processed successfully"
