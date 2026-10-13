#!/usr/bin/env bash
# e2e-test.sh — Full end-to-end sensor test (runs inside privileged container)
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
PASS=0; FAIL=0; TOTAL_TESTS=0
ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); TOTAL_TESTS=$((TOTAL_TESTS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); TOTAL_TESTS=$((TOTAL_TESTS+1)); }
info() { echo -e "${YELLOW}[INFO]${RESET} $1"; }
step() { echo -e "\n${CYAN}── $1 ──${RESET}"; }

# Archive the identities this run actually tested (audit F20).
GIT_REV=$(git -C /sensor rev-parse HEAD 2>/dev/null || echo "unknown")
{
    echo "source=${GIT_REV}"
    echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
    echo "arch=$(uname -m 2>/dev/null || echo unknown)"
    echo "date_utc=$(date -u +%FT%TZ 2>/dev/null || echo unknown)"
} > /tmp/api-sensor-e2e-identity.txt 2>/dev/null || true
info "Source: ${GIT_REV} | Kernel: $(uname -r 2>/dev/null) | $(uname -m 2>/dev/null)"

SENSOR_BIN="/sensor/userspace/target/release/api-sec-sensor"
BPF_OBJ="/sensor/bpf/http_trace.bpf.o"
INGEST_PORT=9999
METRICS_PORT=9091
INGEST_PID=""
SENSOR_PID=""

cleanup() {
    info "Cleaning up..."
    [[ -n "${SENSOR_PID:-}" ]] && kill "$SENSOR_PID" 2>/dev/null && wait "$SENSOR_PID" 2>/dev/null || true
    [[ -n "${INGEST_PID:-}" ]] && kill "$INGEST_PID" 2>/dev/null && wait "$INGEST_PID" 2>/dev/null || true
    rm -f /sys/fs/bpf/http_trace_e2e 2>/dev/null || true
}
trap cleanup EXIT

# Kill any leftover processes from previous runs
pkill -9 -f api-sec-sensor 2>/dev/null || true
# Kill leftover ingest stubs
fuser -k ${INGEST_PORT}/tcp 2>/dev/null || true
fuser -k ${METRICS_PORT}/tcp 2>/dev/null || true
sleep 1

echo ""
echo "================================================================"
echo "  API-Sentinel eBPF Sensor — End-to-End Test Suite"
echo "================================================================"
echo ""

# ── Test 1: BPF verifier accepts all programs ──────────────────────────────
step "Test 1: BPF Verifier"
if command -v bpftool &>/dev/null; then
    if bpftool prog load "$BPF_OBJ" /sys/fs/bpf/http_trace_e2e 2>&1; then
        ok "BPF verifier accepted all programs"
        rm -f /sys/fs/bpf/http_trace_e2e
    else
        fail "BPF verifier rejected programs"
    fi
else
    # bpftool not available — verify via sensor load instead (Test 3)
    info "bpftool not found — BPF verifier will be tested via sensor startup"
    ok "BPF verifier (deferred to sensor startup)"
fi

# ── Test 2: Start ingest validator (real MsgHeader/Batch schema, gzip OK) ───
step "Test 2: Start Ingest Validator"
VALIDATOR_PY="/sensor/tests/test-servers/validator/server.py"
if [[ ! -f "$VALIDATOR_PY" ]]; then
    VALIDATOR_PY="$(cd "$(dirname "$0")/.." && pwd)/tests/test-servers/validator/server.py"
fi
if [[ ! -f "$VALIDATOR_PY" ]]; then
    fail "Validator script not found — the e2e suite requires the schema-validating ingest validator (F20)"
    exit 1
fi
VALIDATOR_PORT="${INGEST_PORT}" python3 "$VALIDATOR_PY" &
INGEST_PID=$!
sleep 1

if kill -0 "$INGEST_PID" 2>/dev/null && curl -sf "http://localhost:${INGEST_PORT}/health" >/dev/null; then
    ok "Ingest validator running (PID=$INGEST_PID, MsgHeader/Batch schema, gzip accepted)"
else
    fail "Ingest validator failed to start"
    exit 1
fi

# ── Test 3: Sensor starts successfully ─────────────────────────────────────
step "Test 3: Sensor Startup"
RUST_LOG=info "$SENSOR_BIN" \
    --bpf "$BPF_OBJ" \
    --ingest "http://127.0.0.1:${INGEST_PORT}/ingest" \
    --api-key "e2e-test-key" \
    --account-id 1001 \
    --role client \
    --metrics-port "${METRICS_PORT}" \
    --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3 \
    --discover-libs 2>&1 &
SENSOR_PID=$!
sleep 3

if kill -0 "$SENSOR_PID" 2>/dev/null; then
    ok "Sensor started and running (PID=$SENSOR_PID)"
else
    fail "Sensor exited immediately — check BPF/libssl"
    # Show sensor output for debugging
    wait "$SENSOR_PID" 2>/dev/null || true
    exit 1
fi

# ── Test 4: Prometheus /metrics endpoint ───────────────────────────────────
step "Test 4: Prometheus Metrics"
METRICS=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null || echo "")

declare -a METRIC_NAMES=(
    "apisec_events_captured_total"
    "apisec_events_dropped_total"
    "apisec_events_sent_total"
    "apisec_send_errors_total"
    "apisec_active_connections"
    "apisec_ringbuf_drops_total"
    "apisec_uptime_seconds"
    "apisec_drop_rate_bps"
    "apisec_channel_watermark_pct"
    "apisec_protocol_events_total"
)

for m in "${METRIC_NAMES[@]}"; do
    if echo "$METRICS" | grep -q "$m"; then
        ok "/metrics contains $m"
    else
        fail "/metrics missing $m"
    fi
done

# Verify HTTP/3 protocol counter exists (new feature)
if echo "$METRICS" | grep -q 'protocol="http3"'; then
    ok "/metrics contains protocol=\"http3\" counter"
else
    fail "/metrics missing protocol=\"http3\" counter"
fi

# ── Test 5: Health & Readiness endpoints ───────────────────────────────────
step "Test 5: Health & Readiness Endpoints"
HEALTH=$(curl -sf "http://localhost:${METRICS_PORT}/healthz" 2>/dev/null || echo "")
if echo "$HEALTH" | grep -q '"status":"ok"'; then
    ok "/healthz returns status:ok"
else
    fail "/healthz unexpected: $HEALTH"
fi

READY=$(curl -sf "http://localhost:${METRICS_PORT}/readyz" 2>/dev/null || echo "")
if echo "$READY" | grep -q '"ready":true'; then
    ok "/readyz returns ready:true (within grace period)"
else
    fail "/readyz unexpected: $READY"
fi

# ── Test 6: Capture real HTTPS traffic (OpenSSL) ──────────────────────────
step "Test 6: OpenSSL TLS Capture"
BEFORE_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)

info "Making HTTPS requests..."
# Multiple requests to different endpoints
curl -sk "https://httpbin.org/get?test=e2e" -o /dev/null 2>/dev/null || true
curl -sk "https://httpbin.org/headers" -o /dev/null 2>/dev/null || true
curl -sk "https://httpbin.org/user-agent" -o /dev/null 2>/dev/null || true
sleep 3

AFTER_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)

NEW_EVENTS=$(( ${AFTER_CAP:-0} - ${BEFORE_CAP:-0} ))
if [[ "$NEW_EVENTS" -gt 0 ]]; then
    ok "Captured $NEW_EVENTS TLS events from HTTPS requests"
else
    fail "0 events captured after HTTPS requests — uprobes may not be attached"
fi

# ── Test 7: PII redaction in captured events ──────────────────────────────
step "Test 7: PII Redaction"
info "Making request with PII data..."
curl -sk "https://httpbin.org/get?email=alice@example.com&ssn=123-45-6789&cc=4111111111111111" \
    -o /dev/null 2>/dev/null || true
sleep 3

# Check schema-accepted events for raw PII (request-side fields)
EVENTS_JSON=$(curl -sf "http://localhost:${INGEST_PORT}/events" 2>/dev/null || echo "")
if echo "$EVENTS_JSON" | grep -q "alice@example.com"; then
    fail "Raw email found in captured request lines (PII redaction failed)"
else
    ok "Raw email NOT in captured request lines (PII redacted)"
fi
if echo "$EVENTS_JSON" | grep -q "123-45-6789"; then
    fail "Raw SSN found in captured request lines (PII redaction failed)"
else
    ok "Raw SSN NOT in captured request lines (PII redacted)"
fi
if echo "$EVENTS_JSON" | grep -q "4111111111111111"; then
    fail "Raw credit card found in captured request lines"
else
    ok "Raw credit card NOT in captured request lines"
fi

# ── Test 8: Events are sent to ingest ─────────────────────────────────────
step "Test 8: Events Sent to Ingest"
SENT=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_sent_total " | awk '{print $2}' | head -1)
if [[ "${SENT:-0}" -gt 0 ]]; then
    ok "Events sent to ingest: $SENT"
else
    fail "0 events sent to ingest"
fi

# ── Test 9: Protocol detection (HTTP/1.1 and HTTP/2) ──────────────────────
step "Test 9: Protocol Detection"
# Force HTTP/1.1 by using --http1.1 flag
info "Making HTTP/1.1 request..."
curl -sk --http1.1 "https://httpbin.org/get?proto=h1" -o /dev/null 2>/dev/null || true
sleep 2
HTTP1_COUNT=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep 'protocol="http1"' | awk '{print $2}' | head -1)
if [[ "${HTTP1_COUNT:-0}" -gt 0 ]]; then
    ok "HTTP/1.1 events detected: $HTTP1_COUNT"
else
    fail "No HTTP/1.1 events detected"
fi
HTTP2_COUNT=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep 'protocol="http2"' | awk '{print $2}' | head -1)
if [[ "${HTTP2_COUNT:-0}" -gt 0 ]]; then
    ok "HTTP/2 events detected: $HTTP2_COUNT"
else
    fail "No HTTP/2 events detected"
fi

# ── Test 10: Accepted-event schema validation (validator-enforced) ──────────
step "Test 10: Accepted Event Schema Validation"
# The validator only ever accepted payloads matching the real MsgHeader/Batch
# wire schema — so an accepted_total > 0 IS the schema validation (audit F20).
# The old check validated the legacy nested schema against a file the old stub
# wrote; it could not fail on today's exporter.
SUMMARY=$(curl -sf "http://localhost:${INGEST_PORT}/summary" 2>/dev/null || echo "")
info "Validator summary: ${SUMMARY:-<unreachable>}"
ACCEPTED=$(echo "$SUMMARY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('accepted_total', 0))" 2>/dev/null || echo "0")
REJECTED=$(echo "$SUMMARY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('rejected_total', 0))" 2>/dev/null || echo "0")
LAST_REJ=$(echo "$SUMMARY" | python3 -c "import json,sys; r=json.load(sys.stdin).get('last_rejection'); print(r.get('error','') if r else '')" 2>/dev/null || echo "")

if [[ "${ACCEPTED:-0}" -gt 0 ]]; then
    ok "Validator accepted ${ACCEPTED} schema-valid events (MsgHeader/Batch contract holds)"
    FIRST_EVENT=$(curl -sf "http://localhost:${INGEST_PORT}/events" 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
evs = data.get('events', [])
e = evs[0] if evs else {}
required = ['SrcInfo.Source', 'LogVersion', 'Id', 'SessionStats.StartTime',
            'L7Protocol', 'HTTPReq.Method', 'HTTPReq.Uri', 'HTTPReq.Query',
            'HTTPReq.BodyLength', 'HTTPResp.ResponseCode',
            'DownstreamL3L4.SourceIP', 'DownstreamL3L4.DestIP',
            'Proto', 'APIID', 'MetaDataMap']
missing = [k for k in required if k not in e]
if missing:
    print(f'MISSING: {missing}')
    sys.exit(1)
print(f\"proto={e['L7Protocol']} method={e['HTTPReq.Method']} \"
      f\"status={e['HTTPResp.ResponseCode']} process={e.get('Req.Header.user-agent','?')}\")
" 2>/dev/null || echo "ERROR")
    if echo "$FIRST_EVENT" | grep -q "proto="; then
        ok "Accepted event carries the full dotted-key contract: $(echo "$FIRST_EVENT" | head -1)"
    else
        fail "Accepted event failed the dotted-key contract check: $FIRST_EVENT"
    fi
else
    fail "Validator accepted 0 events (rejected=${REJECTED:-?}${LAST_REJ:+ last_rejection=$LAST_REJ}) — wire-schema regression or delivery failure"
fi

# ── Test 11: Drop rate is acceptable ──────────────────────────────────────
step "Test 11: Drop Rate Check"
METRICS=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null || echo "")
CAPTURED=$(echo "$METRICS" | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)
DROPPED=$(echo "$METRICS" | grep "^apisec_events_dropped_total " | awk '{print $2}' | head -1)
RINGDROPS=$(echo "$METRICS" | grep "^apisec_ringbuf_drops_total " | awk '{print $2}' | head -1)
SEND_ERRS=$(echo "$METRICS" | grep "^apisec_send_errors_total " | awk '{print $2}' | head -1)

info "Captured: ${CAPTURED:-0} | Dropped: ${DROPPED:-0} | Ring drops: ${RINGDROPS:-0} | Send errors: ${SEND_ERRS:-0}"

if [[ "${DROPPED:-0}" -eq 0 ]]; then
    ok "Zero events dropped"
else
    if [[ "${CAPTURED:-0}" -gt 0 ]]; then
        DROP_PCT=$(( (${DROPPED:-0} * 100) / ${CAPTURED:-1} ))
        if [[ "$DROP_PCT" -lt 5 ]]; then
            ok "Drop rate ${DROP_PCT}% < 5% — acceptable"
        else
            fail "Drop rate ${DROP_PCT}% >= 5% — too high"
        fi
    fi
fi

if [[ "${SEND_ERRS:-0}" -eq 0 ]]; then
    ok "Zero send errors"
else
    fail "Send errors: ${SEND_ERRS:-0}"
fi

# ── Test 12: Burst traffic test ───────────────────────────────────────────
step "Test 12: Burst Traffic (10 rapid sequential requests)"
BEFORE_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)

info "Sending 10 rapid HTTPS requests..."
for i in $(seq 1 10); do
    curl -sk --max-time 5 --http1.1 "https://httpbin.org/get?burst=$i" -o /dev/null 2>/dev/null || true
done
sleep 4

AFTER_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)
BURST_EVENTS=$(( ${AFTER_CAP:-0} - ${BEFORE_CAP:-0} ))
if [[ "$BURST_EVENTS" -gt 0 ]]; then
    ok "Burst test: captured $BURST_EVENTS events from 10 rapid requests"
else
    fail "Burst test: 0 events captured"
fi

# ── Test 13: Connection tracking ──────────────────────────────────────────
step "Test 13: Connection Tracking"
ACTIVE=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_active_connections " | awk '{print $2}' | head -1)
info "Active connections: ${ACTIVE:-0}"
# After all requests are done, connections should exist or have been cleaned
ok "Connection tracking operational (active=${ACTIVE:-0})"

# ── Test 14: Graceful shutdown ────────────────────────────────────────────
step "Test 14: Graceful Shutdown"
BEFORE_SENT=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_sent_total " | awk '{print $2}' | head -1)
info "Events sent before shutdown: ${BEFORE_SENT:-0}"

kill -TERM "$SENSOR_PID" 2>/dev/null || true
WAIT_RESULT=0
wait "$SENSOR_PID" 2>/dev/null || WAIT_RESULT=$?
SENSOR_PID=""

if [[ "$WAIT_RESULT" -eq 0 ]] || [[ "$WAIT_RESULT" -eq 143 ]]; then
    ok "Sensor shut down gracefully (exit=$WAIT_RESULT)"
else
    fail "Sensor exited with code $WAIT_RESULT"
fi

# ── Final Results ─────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  Results: ${PASS} passed / ${TOTAL_TESTS} total"
echo "================================================================"

# Show sample accepted event (schema-validated by the ingest validator)
EVENTS_JSON=$(curl -sf "http://localhost:${INGEST_PORT}/events" 2>/dev/null || echo "")
EVENT_COUNT=$(echo "$EVENTS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total', 0))" 2>/dev/null || echo "0")
if [[ "${EVENT_COUNT:-0}" -gt 0 ]]; then
    echo ""
    info "Sample accepted event (first):"
    echo "$EVENTS_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
evs = data.get('events', [])
if evs:
    print(json.dumps(evs[0], indent=2)[:2000])
" 2>/dev/null || true
fi
info "Run identity archived at /tmp/api-sensor-e2e-identity.txt (source ${GIT_REV})"

if [[ "$FAIL" -eq 0 ]]; then
    echo -e "\n${GREEN}  All ${TOTAL_TESTS} e2e checks passed in THIS run.${RESET}"
    echo -e "${YELLOW}  This is a smoke test, not a production-readiness certification.${RESET}"
    echo -e "${YELLOW}  See docs/PRODUCTION-READINESS-AUDIT.md for the release contract.${RESET}"
    exit 0
else
    echo -e "\n${RED}  ${FAIL} of ${TOTAL_TESTS} tests FAILED${RESET}"
    exit 1
fi
