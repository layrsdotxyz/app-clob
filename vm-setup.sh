#!/bin/bash
set -e

echo "Installing Docker..."
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

echo "Configuring Docker authentication for GCR..."
gcloud auth configure-docker gcr.io --quiet

echo "Pulling CLOB service image..."
sudo docker pull gcr.io/zoopx-0xperps/predifi-clob-app:latest

echo "Creating environment file..."
cat > /tmp/clob.env << 'EOF'
HOST=0.0.0.0
PORT=8080
REDIS_URL=redis://default:wFktm8qKcph43BqdWuqdchfDYnJFpYb5@redis-19021.c294.ap-northeast-1-2.ec2.redns.redis-cloud.com:19021
MAX_ORDERS_PER_USER=100
MAX_ORDER_SIZE=1000000
MIN_ORDER_SIZE=1
MAKER_FEE_BPS=0
TAKER_FEE_BPS=0
RUST_LOG=clob_service=debug,tower_http=debug
ENABLE_SETTLEMENT=true
RPC_URL=https://sepolia.optimism.io
SETTLEMENT_CONTRACT=0xB42EE1571E2a4C151aA09ea8C001059D867aD96C
SETTLEMENT_PRIVATE_KEY=0x7ed2d34e0c6833a7128e14cd8bd87758b34f9113ee32dfa7efe7bc667992aa04
CHAIN_ID=11155420
SETTLEMENT_BATCH_SIZE=10
SETTLEMENT_RETRY_ATTEMPTS=3
EOF

echo "Starting CLOB service container..."
sudo docker run -d \
  --name clob-service \
  --restart=always \
  --env-file /tmp/clob.env \
  -p 8080:8080 \
  gcr.io/zoopx-0xperps/predifi-clob-app:latest

echo "Waiting for service to start..."
sleep 5

echo "Checking container status..."
sudo docker ps

echo "Tailing logs (Ctrl+C to stop)..."
sudo docker logs -f clob-service
