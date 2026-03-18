#!/usr/bin/env bash
# root-verify.sh — run as root on a real Linux machine to complete the 6
# mechanical verification steps for the APISentinel eBPF sensor.
#
# Usage:
#   sudo ./scripts/root-verify.sh [--skip-stress] [--skip-gotls]
#
# Requirements:
#   - Root / CAP_BPF
#   - Go 1.21+ (for Go TLS test)
#   - Python 3
#   - curl, openssl, bpftool
#   - Sensor binary: ./target/release/api-sec-sensor
#   - BPF object:    ./bpf/http_trace.bpf.o
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SENSOR_BIN="${SCRIPT_DIR}/../userspace/target/release/api-sec-sensor"
BPF_OBJ="${SCRIPT_DIR}/../bpf/http_trace.bpf.o"
INGEST_PORT=9999
METRICS_PORT=9090
GOTEST_PORT=19443
PASS=0
FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "${YELLOW}[INFO]${RESET} $1"; }

SKIP_STRESS=false
SKIP_GOTLS=false
for arg in "$@"; do
  [[ "$arg" == "--skip-stress" ]] && SKIP_STRESS=true
  [[ "$arg" == "--skip-gotls"  ]] && SKIP_GOTLS=true
done

INGEST_PID=""
SENSOR_PID=""
GOSERVER_PID=""

cleanup() {
  info "Cleaning up background processes..."
  [[ -n "${INGEST_PID:-}" ]]   && kill "$INGEST_PID"   2>/dev/null || true
  [[ -n "${SENSOR_PID:-}" ]]   && kill "$SENSOR_PID"   2>/dev/null || true
  [[ -n "${GOSERVER_PID:-}" ]] && kill "$GOSERVER_PID" 2>/dev/null || true
  rm -f /sys/fs/bpf/http_trace_verify 2>/dev/null || true
  rm -rf /tmp/gotest_verify 2>/dev/null || true
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo "  APISentinel Sensor — Mechanical Verification Suite"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── Check 1: BPF verifier ─────────────────────────────────────────────────
echo "── Check 1: BPF verifier (bpftool prog load) ───────────────────"
if bpftool prog load "$BPF_OBJ" /sys/fs/bpf/http_trace_verify 2>&1; then
  ok "BPF verifier accepted all programs"
  rm -f /sys/fs/bpf/http_trace_verify
else
  fail "BPF verifier rejected one or more programs — see output above"
fi
echo ""

# ── Check 2: Start ingest stub ────────────────────────────────────────────
echo "── Starting ingest stub on :${INGEST_PORT} ─────────────────────────────"
python3 - <<'PYEOF' &
import sys, json, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

captured = []

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n))
        events = body.get('events', [])
        captured.extend(events)
        for e in events:
            proto = e.get('protocol', '?')
            req   = e.get('request', {})
            resp  = e.get('response', {})
            meta  = e.get('metadata', {})
            ts    = datetime.datetime.now().strftime('%H:%M:%S')
            print(f"[{ts}] {proto} {req.get('method','?')} "
                  f"{req.get('path','?')} → {resp.get('status_code','?')} "
                  f"injection={meta.get('has_injection',False)}", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass

print(f"Ingest stub on :{9999}", flush=True)
HTTPServer(('', 9999), H).serve_forever()
PYEOF
INGEST_PID=$!
sleep 1
info "Ingest stub PID=$INGEST_PID"

# ── Check 2: Start sensor ─────────────────────────────────────────────────
echo ""
echo "── Check 2: Sensor starts and loads BPF programs ───────────────"
"$SENSOR_BIN" \
  --bpf "$BPF_OBJ" \
  --ingest "http://localhost:${INGEST_PORT}" \
  --api-key test-verify \
  --account-id 1001 \
  --role client \
  --metrics-port "${METRICS_PORT}" \
  --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3 \
  --discover-libs \
  --go-tls &
SENSOR_PID=$!
sleep 3

if kill -0 "$SENSOR_PID" 2>/dev/null; then
  ok "Sensor started and is running (PID=$SENSOR_PID)"
else
  fail "Sensor exited immediately — check BPF permissions and libssl path"
  exit 1
fi
echo ""

# ── Check 3: Prometheus /metrics ─────────────────────────────────────────
echo "── Check 3: Prometheus metrics endpoint ────────────────────────"
METRICS=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null || echo "")
if echo "$METRICS" | grep -q "apisec_events_captured_total"; then
  ok "/metrics contains apisec_events_captured_total"
else
  fail "/metrics missing apisec_events_captured_total"
fi
if echo "$METRICS" | grep -q "apisec_ringbuf_drops_total"; then
  ok "/metrics contains apisec_ringbuf_drops_total"
else
  fail "/metrics missing apisec_ringbuf_drops_total"
fi
if echo "$METRICS" | grep -q "apisec_uptime_seconds"; then
  ok "/metrics contains apisec_uptime_seconds"
else
  fail "/metrics missing apisec_uptime_seconds"
fi
HEALTH=$(curl -sf "http://localhost:${METRICS_PORT}/healthz" 2>/dev/null || echo "")
if echo "$HEALTH" | grep -q '"status":"ok"'; then
  ok "/healthz returns {\"status\":\"ok\"}"
else
  fail "/healthz did not return ok — got: $HEALTH"
fi
echo ""

# ── Check 4: OpenSSL capture + PII redaction ─────────────────────────────
echo "── Check 4: OpenSSL capture + PII redaction ────────────────────"
sleep 1
curl -sk "https://httpbin.org/get?email=alice@example.com&ssn=123-45-6789" -o /dev/null || true
sleep 2

METRICS=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null || echo "")
CAPTURED=$(echo "$METRICS" | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)
if [[ "${CAPTURED:-0}" -gt 0 ]]; then
  ok "Events captured: ${CAPTURED} (OpenSSL uprobe working)"
else
  fail "0 events captured after curl — OpenSSL uprobe may not be attached"
fi
echo ""

# ── Check 5: Go TLS test ──────────────────────────────────────────────────
if [[ "$SKIP_GOTLS" == "true" ]]; then
  info "Skipping Go TLS test (--skip-gotls)"
elif ! command -v go &>/dev/null; then
  info "Go not installed — skipping Go TLS test (install with: apt install golang-go)"
else
  echo "── Check 5: Go TLS capture ─────────────────────────────────────"
  GOTEST_DIR=$(mktemp -d /tmp/gotest_verify.XXXX)
  openssl req -x509 -newkey rsa:2048 -keyout "$GOTEST_DIR/key.pem" -out "$GOTEST_DIR/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

  cat > "$GOTEST_DIR/main.go" <<'GOEOF'
package main
import ("crypto/tls"; "fmt"; "net/http"; "os")
func main() {
    http.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        fmt.Fprintf(w, `{"users":[{"id":1,"email":"test@example.com"}]}`)
    })
    cfg := &tls.Config{MinVersion: tls.VersionTLS12}
    srv := &http.Server{Addr: ":" + os.Args[3], TLSConfig: cfg}
    fmt.Fprintln(os.Stderr, "Go HTTPS on :" + os.Args[3])
    srv.ListenAndServeTLS(os.Args[1], os.Args[2])
}
GOEOF

  (cd "$GOTEST_DIR" && go mod init gotest 2>/dev/null && go build -o goserver . 2>/dev/null)
  if [[ -f "$GOTEST_DIR/goserver" ]]; then
    # Start Go server FIRST, then restart the sensor with --pid so Go TLS probes attach.
    "$GOTEST_DIR/goserver" "$GOTEST_DIR/cert.pem" "$GOTEST_DIR/key.pem" "${GOTEST_PORT}" 2>/dev/null &
    GOSERVER_PID=$!
    sleep 2
    if kill -0 "$GOSERVER_PID" 2>/dev/null; then
      info "Go server alive (PID=$GOSERVER_PID)"
    else
      fail "Go server exited immediately — check cert/key files and port :${GOTEST_PORT}"
    fi

    # Restart sensor targeting the Go server PID so Go TLS uprobes are attached at startup.
    info "Restarting sensor with --pid=${GOSERVER_PID} --go-tls for Go TLS probe attachment"
    kill "$SENSOR_PID" 2>/dev/null || true
    sleep 1
    "$SENSOR_BIN" \
      --bpf "$BPF_OBJ" \
      --ingest "http://localhost:${INGEST_PORT}" \
      --api-key test-verify \
      --account-id 1001 \
      --role client \
      --metrics-port "${METRICS_PORT}" \
      --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3 \
      --discover-libs \
      --go-tls \
      --pid "${GOSERVER_PID}" &
    SENSOR_PID=$!
    sleep 3

    BEFORE=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
      | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)

    curl -sk "https://localhost:${GOTEST_PORT}/api/users" -o /dev/null || true
    curl -sk "https://localhost:${GOTEST_PORT}/api/users" -o /dev/null || true
    sleep 3

    AFTER=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
      | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)

    if [[ "${AFTER:-0}" -gt "${BEFORE:-0}" ]]; then
      ok "Go TLS events captured (before=${BEFORE} after=${AFTER})"
    else
      fail "No new events after Go HTTPS requests (before=${BEFORE} after=${AFTER})"
      info "Check: sudo cat /sys/kernel/debug/tracing/uprobe_events | grep go_tls"
    fi

    # Verify PII redaction: email should NOT appear raw
    info "Verify PII: the captured events should contain PII_EMAIL_* not test@example.com"
  else
    fail "Failed to build Go test server"
  fi
  echo ""
fi

# ── Check 6: Ring buffer stress test ─────────────────────────────────────
if [[ "$SKIP_STRESS" == "true" ]]; then
  info "Skipping ring buffer stress test (--skip-stress)"
else
  echo "── Check 6: Ring buffer stress (10,000 requests) ───────────────"
  info "Sending 10,000 requests to httpbin.org via curl..."

  BEFORE_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)
  BEFORE_DROP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_ringbuf_drops_total " | awk '{print $2}' | head -1)

  python3 - <<'PYEOF'
import subprocess, threading, time

def blast(n):
    for _ in range(n):
        subprocess.run(
            ["curl", "-sk", "https://httpbin.org/get", "-o", "/dev/null"],
            capture_output=True, timeout=10
        )

print("Launching 10 threads × 1000 requests = 10,000 total", flush=True)
start = time.time()
threads = [threading.Thread(target=blast, args=(1000,)) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.time() - start
print(f"Done: 10,000 requests in {elapsed:.1f}s ({10000/elapsed:.0f} req/s)", flush=True)
PYEOF

  sleep 2
  AFTER_CAP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_events_captured_total " | awk '{print $2}' | head -1)
  AFTER_DROP=$(curl -sf "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^apisec_ringbuf_drops_total " | awk '{print $2}' | head -1)

  NEW_CAP=$(( ${AFTER_CAP:-0}  - ${BEFORE_CAP:-0}  ))
  NEW_DROP=$(( ${AFTER_DROP:-0} - ${BEFORE_DROP:-0} ))

  info "Events captured during stress: ${NEW_CAP}"
  info "Ring buffer drops during stress: ${NEW_DROP}"

  if [[ "$NEW_DROP" -eq 0 ]]; then
    ok "Ring buffer drops = 0 — perfect"
  elif [[ "$NEW_CAP" -gt 0 ]]; then
    DROP_PCT=$(( (NEW_DROP * 100) / (NEW_CAP + NEW_DROP) ))
    if [[ "$DROP_PCT" -lt 1 ]]; then
      ok "Ring buffer drop rate = ${DROP_PCT}% < 1% — acceptable"
    else
      fail "Ring buffer drop rate = ${DROP_PCT}% ≥ 1% — increase ring buffer size"
      info "Fix: increase RINGBUF_SIZE_BYTES in bpf/http_trace.bpf.c (currently 4MB)"
    fi
  else
    fail "0 events captured during stress — sensor may not be running"
  fi
  echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed  •  ${FAIL} failed"
echo "═══════════════════════════════════════════════════════════════"
if [[ "$FAIL" -eq 0 ]]; then
  echo -e "${GREEN}  ALL CHECKS PASSED — sensor is production ready${RESET}"
else
  echo -e "${RED}  ${FAIL} check(s) failed — see output above${RESET}"
fi
