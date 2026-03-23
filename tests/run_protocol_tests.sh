#!/usr/bin/env bash
# APISentinel Protocol Test Suite — tests all supported protocols
# Run from repo root: ./tests/run_protocol_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SENSOR_NAME="sentinel-sensor-$$"

# Auto-select free ports to avoid conflicts with other services on the host
find_free_port() {
    python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()"
}
METRICS_PORT=$(find_free_port)
VALIDATOR_EXT_PORT=$(find_free_port)

SENSOR_URL="http://localhost:${METRICS_PORT}"
VALIDATOR_URL="http://localhost:${VALIDATOR_EXT_PORT}"

# Colors
CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
header()  { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    header "Cleanup"
    docker kill "$SENSOR_NAME" 2>/dev/null || true
    docker rm -f "$SENSOR_NAME" 2>/dev/null || true
    cd "$SCRIPT_DIR" && docker compose down 2>/dev/null || true
    docker network rm tests_default 2>/dev/null || true
    echo "  Done."
}
trap cleanup EXIT

echo ""
echo -e "${YELLOW}======================================${NC}"
echo "  APISentinel Protocol Test Suite"
echo -e "${YELLOW}======================================${NC}"
echo "  Metrics port: ${METRICS_PORT}"
echo "  Validator port: ${VALIDATOR_EXT_PORT}"

# --- Step 0: Cleanup leftovers ---
header "Cleaning up previous runs"
docker ps -a --filter "name=sentinel-sensor" -q | xargs -r docker rm -f 2>/dev/null || true
cd "$SCRIPT_DIR" && docker compose down 2>/dev/null || true
docker network rm tests_default 2>/dev/null || true
cd "$REPO_ROOT"
sleep 1

# --- Step 1: Start test infrastructure ---
# Override validator port in compose
header "Starting test infrastructure"
cd "$SCRIPT_DIR"
VALIDATOR_PORT_MAP="${VALIDATOR_EXT_PORT}:9999" \
  docker compose up -d --build 2>&1 | grep -E "Created|Started|Error" || true
cd "$REPO_ROOT"

# Wait for services to be healthy
echo "Waiting for test services..."
for i in $(seq 1 40); do
    if curl -sk https://localhost:18444/health >/dev/null 2>&1 && \
       curl -s "http://localhost:${VALIDATOR_EXT_PORT}/counts" >/dev/null 2>&1; then
        echo "  Services healthy after ${i}s"
        break
    fi
    if [ "$i" -eq 40 ]; then
        echo "  WARNING: Services not fully healthy after 40s"
    fi
    sleep 1
done

# --- Step 2: Start sensor ---
header "Starting sensor"
docker run -d --name "$SENSOR_NAME" --privileged --pid=host \
  --network tests_default --init \
  -p "${METRICS_PORT}:${METRICS_PORT}" -e RUST_LOG=info \
  api-sentinel-sensor:v0.2.0 \
  --config /dev/null \
  --bpf /opt/sensor/http_trace.bpf.o \
  --ingest http://ingest-validator:9999/ingest \
  --api-key "test-key" \
  --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3 \
  --go-tls \
  --discover-libs \
  --metrics-port "${METRICS_PORT}" >/dev/null

# Wait for sensor to reach "polling ring buffer" state
echo "Waiting for sensor readiness..."
for i in $(seq 1 90); do
    if docker logs "$SENSOR_NAME" 2>&1 | grep -q "probes attached, polling ring buffer"; then
        echo -e "  ${GREEN}Sensor ready after ${i}s${NC}"
        break
    fi
    if [ "$i" -eq 90 ]; then
        echo -e "  ${RED}WARNING: Sensor not ready after 90s${NC}"
        docker logs "$SENSOR_NAME" 2>&1 | tail -3
    fi
    sleep 1
done

# Wait for static TLS probes to attach to test containers
echo "Waiting for static TLS probe attachment..."
for i in $(seq 1 120); do
    if docker logs "$SENSOR_NAME" 2>&1 | grep -q "static TLS: probe attachment complete"; then
        echo -e "  ${GREEN}Static TLS probes attached after ${i}s${NC}"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "  WARNING: Static TLS scan still running after 120s, proceeding..."
    fi
    sleep 1
done

# Reset validator
curl -s "http://localhost:${VALIDATOR_EXT_PORT}/reset" >/dev/null 2>&1 || true
echo "Validator reset."

# --- Step 3: Generate traffic ---

header "HTTP/1.1 over TLS (Node.js)"
curl -sk https://localhost:18444/health >/dev/null || true
curl -sk https://localhost:18444/api/echo >/dev/null || true
echo "  Sent 2 HTTPS requests to Node.js"

header "HTTP/2 over TLS (Go server)"
docker run --rm --network tests_default curlimages/curl:latest \
  -sk --http2 https://go-api:8443/health https://go-api:8443/api/users https://go-api:8443/api/echo 2>/dev/null || true
echo "  Sent 3 HTTP/2 requests to Go server"

header "WebSocket over TLS"
docker run --rm --network tests_default -v "$SCRIPT_DIR:/tests" python:3.11-slim \
  bash -c "pip install -q websockets 2>/dev/null && python3 /tests/ws_client.py ws-server" 2>&1 || true
echo "  Sent 2 WebSocket messages"

header "MCP/SSE over TLS (JSON-RPC)"
curl -sk -X POST https://localhost:17778 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' >/dev/null || true
curl -sk -X POST https://localhost:17778 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' >/dev/null || true
curl -sk -X POST https://localhost:17778 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}' >/dev/null || true
# SSE endpoint — text/event-stream detection
curl -sk --max-time 3 https://localhost:17778/events >/dev/null 2>&1 || true
echo "  Sent 4 MCP requests over HTTPS (3 JSON-RPC + 1 SSE)"

header "gRPC over TLS"
docker run --rm --network tests_default -v "$SCRIPT_DIR:/tests" python:3.11-slim \
  bash -c "pip install -q grpcio grpcio-reflection grpcio-health-checking 2>/dev/null && python3 /tests/grpc_client.py grpc-server" 2>&1 || true
echo "  Sent gRPC health + reflection requests"

header "GnuTLS over TLS"
# Pre-built gnutls-client image avoids apt-get on every run.
# gnutls-cli uses libgnutls (NOT OpenSSL), exercising gnutls_record_send/recv uprobes.
docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm gnutls-client 2>/dev/null || true
# Send a second request with a different path
docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm gnutls-client \
  sh -c "echo -e 'GET /api/test HTTP/1.1\r\nHost: gnutls-server\r\nConnection: close\r\n\r\n' | gnutls-cli --insecure -p 8446 gnutls-server 2>/dev/null" 2>/dev/null || true
echo "  Sent 2 HTTPS requests via GnuTLS (gnutls-cli -> gnutls-serv)"

header "HTTP/3 over QUIC"
# Run http3-client INSIDE the quic-server container so it uses the SAME
# libquiche.so file (same inode) — the sensor's QUIC uprobes are inode-based,
# so they only fire for processes using the exact same library file.
docker exec tests-quic-server-1 http3-client 127.0.0.1 8447 2>/dev/null || true
docker exec tests-quic-server-1 http3-client 127.0.0.1 8447 2>/dev/null || true
echo "  Sent 2 HTTP/3 requests to QUIC server (loopback via quiche client)"

# --- Step 4: Wait for batch flush ---
echo ""
echo "Waiting 10s for batch flush..."
sleep 10

# --- Step 5: Results ---
header "SENSOR METRICS"
metrics=$(curl -s "$SENSOR_URL/metrics" || echo "")
captured=$(echo "$metrics" | grep -oP 'apisec_events_captured_total \K\d+' || echo "0")
sent=$(echo "$metrics" | grep -oP 'apisec_events_sent_total \K\d+' || echo "0")
echo "  Events captured: $captured"
echo "  Events sent: $sent"
echo ""
echo "$metrics" | grep "apisec_protocol_events_total" || true

header "INGEST VALIDATOR"
counts=$(curl -s "http://localhost:${VALIDATOR_EXT_PORT}/counts" || echo "{}")
echo "  Protocol counts: $counts"

header "SENSOR LOGS (key events)"
docker logs "$SENSOR_NAME" 2>&1 | grep -E "global TLS|static TLS|Go TLS|GnuTLS|gnutls|QUIC|quic|bootstrap|probes attached|polling ring|batch|discovery|uprobe attached" | head -30 || true

echo ""
echo -e "${YELLOW}======================================${NC}"
if [ "${captured:-0}" -gt 0 ]; then
    echo -e "  ${GREEN}RESULT: PASS — $captured events captured${NC}"
else
    echo -e "  ${RED}RESULT: ZERO EVENTS — check sensor logs${NC}"
fi
echo -e "${YELLOW}======================================${NC}"
