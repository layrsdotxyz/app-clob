#!/bin/bash
# Quick validation test - runs in under 30 seconds

BASE_URL="http://localhost:8081"
MARKET_ID="QUICK-$(date +%s)"

echo "🧪 Quick CLOB Validation Test"
echo "Market: $MARKET_ID"
echo ""

# Check health
if ! curl -sf "$BASE_URL/health" > /dev/null; then
    echo "❌ Service unhealthy"
    exit 1
fi
echo "✅ Service healthy"

# Test 1: Create and match orders
echo "▶ Testing order matching..."
O1=$(curl -sf -X POST "$BASE_URL/v1/orders" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"alice\",\"market_id\":\"$MARKET_ID\",\"side\":\"BUY\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.50\",\"size\":\"100\"}")

O2=$(curl -sf -X POST "$BASE_URL/v1/orders" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"bob\",\"market_id\":\"$MARKET_ID\",\"side\":\"SELL\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.50\",\"size\":\"100\"}")

FILLED=$(echo "$O2" | jq -r '.order.filled')
if [ "$FILLED" == "100" ]; then
    echo "✅ Order matching works (100/100 filled)"
else
    echo "❌ Matching failed (filled=$FILLED)"
    exit 1
fi

# Test 2: Partial fill
echo "▶ Testing partial fills..."
O3=$(curl -sf -X POST "$BASE_URL/v1/orders" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"charlie\",\"market_id\":\"$MARKET_ID\",\"side\":\"BUY\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.55\",\"size\":\"200\"}")
O3_ID=$(echo "$O3" | jq -r '.order.id')

O4=$(curl -sf -X POST "$BASE_URL/v1/orders" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"diane\",\"market_id\":\"$MARKET_ID\",\"side\":\"SELL\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.55\",\"size\":\"50\"}")

O3_CHECK=$(curl -sf "$BASE_URL/v1/orders/$O3_ID")
STATUS=$(echo "$O3_CHECK" | jq -r '.status')

if [ "$STATUS" == "PARTIAL" ]; then
    echo "✅ Partial fills work (status=PARTIAL)"
else
    echo "❌ Partial fill failed (status=$STATUS)"
    exit 1
fi

# Test 3: Cancellation
echo "▶ Testing cancellation..."
O5=$(curl -sf -X POST "$BASE_URL/v1/orders" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"eve\",\"market_id\":\"$MARKET_ID\",\"side\":\"BUY\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.45\",\"size\":\"50\"}")
O5_ID=$(echo "$O5" | jq -r '.order.id')

CANCEL=$(curl -sf -X DELETE "$BASE_URL/v1/orders/$O5_ID?user_id=eve")
CANCEL_STATUS=$(echo "$CANCEL" | jq -r '.status')

if [ "$CANCEL_STATUS" == "CANCELLED" ]; then
    echo "✅ Cancellation works"
else
    echo "❌ Cancellation failed (status=$CANCEL_STATUS)"
    exit 1
fi

echo ""
echo "🎉 All core tests passed!"
echo ""
echo "✅ Order matching"
echo "✅ Partial fills"
echo "✅ Cancellation"
exit 0
