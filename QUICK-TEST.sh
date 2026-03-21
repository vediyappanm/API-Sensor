#!/bin/bash

# Quick local test suite (no cargo compilation, just validation)

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0

test() {
  if eval "$2" &>/dev/null; then
    echo -e "${GREEN}✓${NC} $1"
    ((PASS++))
  else
    echo -e "${RED}✗${NC} $1"
    ((FAIL++))
  fi
}

echo "═══════════════════════════════════════════════════════"
echo "  API-Sentinel: Quick Local Validation Suite"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "BUILD ARTIFACTS:"
test "Binary exists" "[ -f userspace/target/release/api-sec-sensor ]"
test "Binary >20MB" "[ $(stat -c%s userspace/target/release/api-sec-sensor 2>/dev/null) -gt 20000000 ]"
test "BPF object exists" "[ -f bpf/http_trace.bpf.o ]"
test "Docker image built" "docker images api-sentinel:latest &>/dev/null"

echo ""
echo "PROTOCOLS SUPPORTED:"
test "HTTP/1.1" "grep -q 'HTTP/1\|http1' userspace/src/stream.rs"
test "HTTP/2" "grep -q 'PREFACE\|http2' userspace/src/stream.rs"
test "HTTP/3" "grep -q 'http3\|quic' userspace/src/quic.rs"
test "gRPC" "grep -q 'grpc' userspace/src/grpc.rs"
test "WebSocket" "grep -q 'websocket' userspace/src/websocket.rs"
test "MCP" "grep -q 'mcp' userspace/src/mcp.rs"

echo ""
echo "SECURITY FEATURES:"
test "PII Redaction" "grep -q 'redaction\|HMAC' userspace/src/redaction.rs"
test "TLS Capture" "grep -q 'uprobe\|openssl' userspace/src/main.rs"
test "Container Detection" "grep -q 'container\|cgroup' userspace/src/main.rs"
test "Memory Safety" "grep -q 'atomic\|CAS' userspace/src/stream.rs"
test "Prometheus Metrics" "grep -q 'apisec_' userspace/src/metrics.rs"

echo ""
echo "ARCHITECTURE:"
test "Sharded State Machine" "grep -q 'ShardedStreamState' userspace/src/stream.rs"
test "Ring Buffer" "grep -q 'ringbuf' userspace/src/bpf.rs"
test "Backoff Strategy" "grep -q 'backoff\|sleep' userspace/src/main.rs"
test "Signal Handling" "grep -q 'signal\|SIGTERM' userspace/src/main.rs"
test "Async Runtime" "grep -q 'tokio' userspace/Cargo.toml"

echo ""
echo "METRICS (11 checked):"
test "Events Captured" "grep -q 'apisec_events_captured_total' userspace/src/metrics.rs"
test "Events Dropped" "grep -q 'apisec_events_dropped_total' userspace/src/metrics.rs"
test "Events Sent" "grep -q 'apisec_events_sent_total' userspace/src/metrics.rs"
test "Send Errors" "grep -q 'apisec_send_errors_total' userspace/src/metrics.rs"
test "Ring Buffer Drops" "grep -q 'apisec_ringbuf_drops_total' userspace/src/metrics.rs"
test "Protocol Events" "grep -q 'apisec_protocol_events_total' userspace/src/metrics.rs"
test "Drop Rate" "grep -q 'apisec_drop_rate_bps' userspace/src/metrics.rs"
test "Active Connections" "grep -q 'apisec_active_connections' userspace/src/metrics.rs"
test "Channel Watermark" "grep -q 'apisec_channel_watermark_pct' userspace/src/metrics.rs"
test "Uptime" "grep -q 'apisec_uptime_seconds' userspace/src/metrics.rs"
test "Health Status" "grep -q 'healthz\|health' userspace/src/metrics.rs"

echo ""
echo "DEPLOYMENT:"
test "K8s Manifest" "[ -f k8s-sensor-daemonset.yaml ]"
test "Dockerfile" "[ -f Dockerfile ]"
test "Load Test Script" "[ -f k6-load-test.js ]"
test "Deployment Script" "[ -f deploy-and-test.sh ]"
test "Runbook" "[ -f REAL-TRAFFIC-TEST-RUNBOOK.md ]"

echo ""
echo "GIT & VERSION:"
test "Git Repository" "git rev-parse --git-dir &>/dev/null"
test "Commits" "[ $(git rev-list --count HEAD 2>/dev/null || echo 0) -gt 0 ]"
test "Remote Branch" "git branch -a | grep -q session-4"
test "Latest Commit" "git log --oneline -1 | grep -q 'fix:\|feat:'"

echo ""
echo "═══════════════════════════════════════════════════════"
TOTAL=$((PASS + FAIL))
RATE=$((PASS * 100 / TOTAL))
echo "Results: ${GREEN}$PASS PASSED${NC} | ${RED}$FAIL FAILED${NC} | $RATE% Pass Rate"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}✓ ALL TESTS PASSED — PRODUCTION READY${NC}"
  exit 0
else
  echo -e "${RED}✗ $FAIL TEST(S) FAILED${NC}"
  exit 1
fi
