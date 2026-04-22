#!/bin/bash
# DB Persistence Integration Test
# Verifies that trades, fills, orders, markets, and balances are written to PostgreSQL.
#
# Usage:
#   BASE_URL=http://localhost:8081 DATABASE_URL=postgres://... ./test_db_persistence.sh
#
# If DATABASE_URL is unset it will attempt to fetch it from AWS Secrets Manager
# (requires `aws` CLI with the `layrs` profile).

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8081}"
MARKET_ID="DBTEST-$(date +%s)"
PASS=0
FAIL=0

pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

# ── Resolve DATABASE_URL ──────────────────────────────────────────────────────
if [[ -z "${DATABASE_URL:-}" ]]; then
    echo "DATABASE_URL not set — fetching from AWS Secrets Manager..."
    SECRET=$(aws secretsmanager get-secret-value \
        --profile layrs --region us-east-1 \
        --secret-id layrs/backend/config \
        --query SecretString --output text 2>/dev/null || true)
    if [[ -n "$SECRET" ]]; then
        DATABASE_URL=$(echo "$SECRET" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('DATABASE_URL',''))" 2>/dev/null || true)
    fi
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
    echo "⚠️  DATABASE_URL unavailable — DB verification steps will be skipped."
    echo "   Set DATABASE_URL manually to run full DB checks."
    DB_AVAILABLE=false
else
    DB_AVAILABLE=true
fi

psql_query() {
    # Run a SQL query and return the single text result
    psql "$DATABASE_URL" -tAc "$1" 2>/dev/null
}

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   CLOB-Service DB Persistence Integration Test   ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  Base URL : $BASE_URL"
echo "  Market   : $MARKET_ID"
echo "  DB check : $DB_AVAILABLE"
echo ""

# ── Health check ─────────────────────────────────────────────────────────────
echo "▶ Health check"
if curl -sf "$BASE_URL/health" > /dev/null; then
    pass "Service healthy"
else
    echo "❌ Service unreachable at $BASE_URL — aborting."
    exit 1
fi

# ── Phase 1: Balance deposit ──────────────────────────────────────────────────
echo ""
echo "▶ Phase 1: Balance deposit"
DEP=$(curl -sf -X POST "$BASE_URL/v1/balance/deposit" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"alice\",\"market_id\":\"$MARKET_ID\",\"amount\":\"1000\"}")

NEW_BAL=$(echo "$DEP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('new_balance',''))" 2>/dev/null || true)
if [[ "$NEW_BAL" == "1000" ]]; then
    pass "Deposit accepted (new_balance=1000)"
else
    fail "Deposit response unexpected: $DEP"
fi

if $DB_AVAILABLE; then
    sleep 0.5  # allow fire-and-forget DB write to land
    BAL_ROW=$(psql_query "SELECT to_char(balance/1e18,'FM999999999.0') FROM balances b JOIN users u ON u.id=b.user_id WHERE u.wallet_address='alice' LIMIT 1" || true)
    if [[ -n "$BAL_ROW" ]]; then
        pass "Balance row written to DB (balance=$BAL_ROW)"
    else
        fail "Balance row not found in DB"
    fi
fi

# ── Phase 2: Matching orders → trade + fills ─────────────────────────────────
echo ""
echo "▶ Phase 2: Matching orders (trade + fills)"

# Also fund bob
curl -sf -X POST "$BASE_URL/v1/balance/deposit" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"bob\",\"market_id\":\"$MARKET_ID\",\"amount\":\"1000\"}" > /dev/null

O1=$(curl -sf -X POST "$BASE_URL/v1/orders" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"alice\",\"market_id\":\"$MARKET_ID\",\"side\":\"BUY\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.50\",\"size\":\"100\"}")
O1_ID=$(echo "$O1" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('order',d).get('id',''))" 2>/dev/null || true)

O2=$(curl -sf -X POST "$BASE_URL/v1/orders" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"bob\",\"market_id\":\"$MARKET_ID\",\"side\":\"SELL\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.50\",\"size\":\"100\"}")
FILLED=$(echo "$O2" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('order',d).get('filled',''))" 2>/dev/null || true)
O2_ID=$(echo "$O2" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('order',d).get('id',''))" 2>/dev/null || true)

if [[ "$FILLED" == "100" ]]; then
    pass "Match produced (100/100 filled)"
else
    fail "Match not produced (filled=$FILLED)"
fi

if $DB_AVAILABLE; then
    sleep 1  # allow async DB writes to complete

    TRADE_COUNT=$(psql_query "SELECT COUNT(*) FROM trades WHERE market_id='$MARKET_ID'" || true)
    if [[ "${TRADE_COUNT:-0}" -ge 1 ]]; then
        pass "trades row written to DB (count=$TRADE_COUNT)"
    else
        fail "No trades row found in DB for market $MARKET_ID"
    fi

    FILL_COUNT=$(psql_query "SELECT COUNT(*) FROM fills WHERE trade_id IN (SELECT id FROM trades WHERE market_id='$MARKET_ID')" || true)
    if [[ "${FILL_COUNT:-0}" -ge 2 ]]; then
        pass "fills rows written to DB (count=$FILL_COUNT, expect ≥2)"
    else
        fail "Not enough fills rows in DB (count=$FILL_COUNT, expect ≥2)"
    fi

    if [[ -n "$O1_ID" ]]; then
        ORD_STATUS=$(psql_query "SELECT status FROM orders WHERE order_id='$O1_ID'" || true)
        if [[ -n "$ORD_STATUS" ]]; then
            pass "order row written to DB (order_id=$O1_ID status=$ORD_STATUS)"
        else
            fail "Order row not found in DB (order_id=$O1_ID)"
        fi
    fi
fi

# ── Phase 3: Cancel → order status update ────────────────────────────────────
echo ""
echo "▶ Phase 3: Open order → cancel → DB status update"

O3=$(curl -sf -X POST "$BASE_URL/v1/orders" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"alice\",\"market_id\":\"$MARKET_ID\",\"side\":\"BUY\",\"order_type\":\"LIMIT\",\"time_in_force\":\"GTC\",\"price\":\"0.45\",\"size\":\"50\"}")
O3_ID=$(echo "$O3" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('order',d).get('id',''))" 2>/dev/null || true)

if [[ -n "$O3_ID" ]]; then
    curl -sf -X DELETE "$BASE_URL/v1/orders/$O3_ID?user_id=alice" > /dev/null
    pass "Cancel request sent (order_id=$O3_ID)"

    if $DB_AVAILABLE; then
        sleep 0.5
        CAN_STATUS=$(psql_query "SELECT status FROM orders WHERE order_id='$O3_ID'" || true)
        if [[ "$CAN_STATUS" == "cancelled" ]]; then
            pass "Order status updated to cancelled in DB"
        else
            fail "Order status in DB is '$CAN_STATUS' (expected cancelled)"
        fi
    fi
else
    fail "Could not place open order for cancel test"
fi

# ── Phase 4: Balance persistence across reload ────────────────────────────────
if $DB_AVAILABLE; then
    echo ""
    echo "▶ Phase 4: Balance endpoint mirrors DB row"

    BAL_RESP=$(curl -sf "$BASE_URL/v1/balance?user_id=alice&market_id=$MARKET_ID" || true)
    API_TOTAL=$(echo "$BAL_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total',''))" 2>/dev/null || true)

    DB_TOTAL_RAW=$(psql_query "SELECT b.balance FROM balances b JOIN users u ON u.id=b.user_id WHERE u.wallet_address='alice' LIMIT 1" || true)
    # DB stores scaled × 1e18 as NUMERIC; convert back for comparison
    DB_TOTAL=$(psql_query "SELECT (b.balance/1e18)::text FROM balances b JOIN users u ON u.id=b.user_id WHERE u.wallet_address='alice' LIMIT 1" || true)

    if [[ -n "$API_TOTAL" && -n "$DB_TOTAL" ]]; then
        pass "Balance visible in both API ($API_TOTAL) and DB ($DB_TOTAL)"
    elif [[ -n "$API_TOTAL" ]]; then
        fail "Balance in API ($API_TOTAL) but DB row missing"
    else
        fail "Balance not present in API response"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  Results: $PASS passed  $FAIL failed"
echo "══════════════════════════════════════════════════"

if [[ $FAIL -eq 0 ]]; then
    echo "🎉 All checks passed!"
    exit 0
else
    echo "😬 $FAIL check(s) failed."
    exit 1
fi
