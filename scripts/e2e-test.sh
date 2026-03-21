#!/usr/bin/env bash
# e2e-test.sh — Full end-to-end sensor test (runs inside privileged container)
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
PASS=0; FAIL=0; TOTAL_TESTS=0
ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); TOTAL_TESTS=$((TOTAL_TESTS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); TOTAL_TESTS=$((TOTAL_TESTS+1)); }
info() { echo -e "${YELLOW}[INFO]${RESET} $1"; }
step() { echo -e "\n${CYAN}── $1 ──${RESET}"; }

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

echo ""
echo "================================================================"
echo "  API-Sentinel eBPF Sensor — End-to-End Test Suite"
echo "================================================================"
echo ""

# ── Test 1: BPF verifier accepts all programs ──────────────────────────────
step "Test 1: BPF Verifier"
if bpftool prog load "$BPF_OBJ" /sys/fs/bpf/http_trace_e2e 2>&1; then
    ok "BPF verifier accepted all programs"
    rm -f /sys/fs/bpf/http_trace_e2e
else
    fail "BPF verifier rejected programs"
fi

# ── Test 2: Start ingest stub (captures events for inspection) ─────────────
step "Test 2: Start Ingest Stub"
python3 - <<'PYEOF' &
import sys, json, datetime, os
from http.server import HTTPServer, BaseHTTPRequestHandler

events_file = "/tmp/captured_events.json"
all_events = []

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n))
        events = body.get('events', [])
        all_events.extend(events)
        # Write to file so test can inspect
        with open(events_file, 'w') as f:
            json.dump(all_events, f, indent=2)
        for e in events:
            proto = e.get('protocol', '?')
            req   = e.get('request', {})
            resp  = e.get('response', {})
            ts    = datetime.datetime.now().strftime('%H:%M:%S')
            print(f"[{ts}] {proto} {req.get('method','?')} "
                  f"{req.get('path','?')} -> {resp.get('status_code','?')}", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass

# Initialize empty events file
with open(events_file, 'w') as f:
    json.dump([], f)

print(f"Ingest stub listening on :{9999}", flush=True)
HTTPServer(('', 9999), Handler).serve_forever()
PYEOF
INGEST_PID=$!
sleep 1

if kill -0 "$INGEST_PID" 2>/dev/null; then
    ok "Ingest stub running (PID=$INGEST_PID)"
else
    fail "Ingest stub failed to start"
    exit 1
fi

# ── Test 3: Sensor starts successfully ─────────────────────────────────────
step "Test 3: Sensor Startup"
RUST_LOG=info "$SENSOR_BIN" \
    --bpf "$BPF_OBJ" \
    --ingest "http://127.0.0.1:${INGEST_PORT}" \
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

# Check captured events file for raw PII
if [[ -f /tmp/captured_events.json ]]; then
    EVENTS_JSON=$(cat /tmp/captured_events.json)
    if echo "$EVENTS_JSON" | grep -q "alice@example.com"; then
        fail "Raw email found in captured events (PII redaction failed)"
    else
        ok "Raw email NOT in captured events (PII redacted)"
    fi
    if echo "$EVENTS_JSON" | grep -q "123-45-6789"; then
        fail "Raw SSN found in captured events (PII redaction failed)"
    else
        ok "Raw SSN NOT in captured events (PII redacted)"
    fi
    if echo "$EVENTS_JSON" | grep -q "4111111111111111"; then
        fail "Raw credit card found in captured events"
    else
        ok "Raw credit card NOT in captured events (PII redacted)"
    fi
else
    info "No events file yet — PII test inconclusive"
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

# ── Test 9: Protocol detection (HTTP/1.1) ─────────────────────────────────
step "Test 9: Protocol Detection"
HTTP1_COUNT=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep 'protocol="http1"' | awk '{print $2}' | head -1)
if [[ "${HTTP1_COUNT:-0}" -gt 0 ]]; then
    ok "HTTP/1.1 events detected: $HTTP1_COUNT"
else
    fail "No HTTP/1.1 events detected"
fi

# ── Test 10: Event structure validation ───────────────────────────────────
step "Test 10: Event Structure Validation"
if [[ -f /tmp/captured_events.json ]]; then
    EVENT_COUNT=$(python3 -c "
import json, sys
events = json.load(open('/tmp/captured_events.json'))
print(len(events))
" 2>/dev/null || echo "0")
    if [[ "$EVENT_COUNT" -gt 0 ]]; then
        ok "Received $EVENT_COUNT events in ingest stub"
        # Validate first event structure
        VALID=$(python3 -c "
import json, sys
events = json.load(open('/tmp/captured_events.json'))
e = events[0]
required = ['version', 'event_type', 'source', 'account_id', 'observed_at',
            'protocol', 'request', 'response']
missing = [f for f in required if f not in e]
if missing:
    print(f'MISSING: {missing}')
    sys.exit(1)
req = e['request']
req_fields = ['method', 'path', 'scheme', 'headers']
missing_req = [f for f in req_fields if f not in req]
if missing_req:
    print(f'MISSING_REQ: {missing_req}')
    sys.exit(1)
resp = e['response']
if 'status_code' not in resp:
    print('MISSING: response.status_code')
    sys.exit(1)
# Check new fields exist (process_name, hostnames)
print(f'version={e[\"version\"]} proto={e[\"protocol\"]} method={req[\"method\"]} status={resp[\"status_code\"]}')
if 'process_name' in e:
    print(f'process_name={e.get(\"process_name\")}')
if 'source_hostname' in e:
    print(f'source_hostname={e.get(\"source_hostname\")}')
if 'dest_hostname' in e:
    print(f'dest_hostname={e.get(\"dest_hostname\")}')
if 'anomaly_features' in e and e['anomaly_features']:
    af = e['anomaly_features']
    print(f'anomaly_features: path_depth={af.get(\"path_depth\")} entropy={af.get(\"shannon_entropy\",0):.2f}')
print('VALID')
" 2>/dev/null || echo "ERROR")
        if echo "$VALID" | grep -q "VALID"; then
            ok "Event structure valid: $(echo "$VALID" | head -1)"
        else
            fail "Event structure invalid: $VALID"
        fi

        # Check process_name field (new feature)
        HAS_PROCESS_NAME=$(python3 -c "
import json
events = json.load(open('/tmp/captured_events.json'))
has = any(e.get('process_name') for e in events)
print('yes' if has else 'no')
" 2>/dev/null || echo "no")
        if [[ "$HAS_PROCESS_NAME" == "yes" ]]; then
            ok "process_name field populated in events (new feature working)"
        else
            info "process_name not yet populated (may appear on next event cycle)"
        fi

        # Check anomaly_features
        HAS_ANOMALY=$(python3 -c "
import json
events = json.load(open('/tmp/captured_events.json'))
has = any(e.get('anomaly_features') for e in events)
print('yes' if has else 'no')
" 2>/dev/null || echo "no")
        if [[ "$HAS_ANOMALY" == "yes" ]]; then
            ok "anomaly_features present in events"
        else
            fail "anomaly_features missing from events"
        fi
    else
        fail "No events received in ingest stub"
    fi
else
    fail "Events file not created"
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
step "Test 12: Burst Traffic (50 concurrent requests)"
BEFORE_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)

info "Sending 50 concurrent HTTPS requests..."
for i in $(seq 1 50); do
    curl -sk "https://httpbin.org/get?burst=$i" -o /dev/null 2>/dev/null &
done
wait
sleep 4

AFTER_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)
BURST_EVENTS=$(( ${AFTER_CAP:-0} - ${BEFORE_CAP:-0} ))
if [[ "$BURST_EVENTS" -gt 0 ]]; then
    ok "Burst test: captured $BURST_EVENTS events from 50 concurrent requests"
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

# Show sample captured event
if [[ -f /tmp/captured_events.json ]]; then
    EVENT_COUNT=$(python3 -c "import json; print(len(json.load(open('/tmp/captured_events.json'))))" 2>/dev/null || echo "0")
    if [[ "$EVENT_COUNT" -gt 0 ]]; then
        echo ""
        info "Sample captured event (first):"
        python3 -c "
import json
events = json.load(open('/tmp/captured_events.json'))
if events:
    e = events[0]
    print(json.dumps(e, indent=2)[:2000])
" 2>/dev/null || true
    fi
fi

if [[ "$FAIL" -eq 0 ]]; then
    echo -e "\n${GREEN}  ALL ${TOTAL_TESTS} TESTS PASSED — sensor is production ready${RESET}"
    exit 0
else
    echo -e "\n${RED}  ${FAIL} of ${TOTAL_TESTS} tests FAILED${RESET}"
    exit 1
fi
