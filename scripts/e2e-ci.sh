#!/usr/bin/env bash
# e2e-ci.sh — Hermetic end-to-end capture test for CI.
#
# Unlike scripts/e2e-test.sh (which hits httpbin.org), this test has NO external
# network dependency: it stands up a local self-signed HTTPS server and a local
# ingest stub, runs the sensor against the host's libssl, drives real HTTPS
# traffic with curl, and asserts the whole capture path works end to end:
#
#   BPF load + verifier  ->  uprobe capture (SSL_read/SSL_write)
#     ->  parse/protocol detect  ->  PII redaction  ->  ingest delivery
#
# Requires root (CAP_BPF/CAP_PERFMON) and a kernel >= 5.8 with BTF. Intended to
# run on a GitHub Actions ubuntu-latest runner (real kernel + BTF + sudo) and
# locally. Exit code is non-zero on any failed assertion so CI fails loudly when
# capture regresses.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SENSOR_BIN="${SENSOR_BIN:-$REPO_ROOT/userspace/target/release/api-sec-sensor}"
BPF_OBJ="${BPF_OBJ:-$REPO_ROOT/bpf/http_trace.bpf.o}"
LIBSSL="${LIBSSL:-}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
PASS=0; FAIL=0
ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}[INFO]${RESET} $1"; }
step() { echo -e "\n${CYAN}── $1 ──${RESET}"; }

WORKDIR="$(mktemp -d)"
EVENTS_FILE="$WORKDIR/captured_events.json"
SENSOR_LOG="$WORKDIR/sensor.log"
SENSOR_PID=""; INGEST_PID=""; HTTPS_PID=""

cleanup() {
    [[ -n "$SENSOR_PID" ]] && kill "$SENSOR_PID" 2>/dev/null; wait "$SENSOR_PID" 2>/dev/null || true
    [[ -n "$INGEST_PID" ]] && kill "$INGEST_PID" 2>/dev/null || true
    [[ -n "$HTTPS_PID"  ]] && kill "$HTTPS_PID"  2>/dev/null || true
    rm -rf "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT

free_port() { python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"; }

# --- Preconditions -----------------------------------------------------------
step "Preconditions"
if [[ "$(id -u)" -ne 0 ]]; then fail "must run as root (need CAP_BPF/CAP_PERFMON)"; exit 1; fi
[[ -x "$SENSOR_BIN" ]] && ok "sensor binary present" || { fail "sensor binary missing: $SENSOR_BIN"; exit 1; }
[[ -f "$BPF_OBJ"   ]] && ok "BPF object present"   || { fail "BPF object missing: $BPF_OBJ"; exit 1; }
if [[ -z "$LIBSSL" ]]; then
    for c in /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/aarch64-linux-gnu/libssl.so.3 /lib/x86_64-linux-gnu/libssl.so.3; do
        [[ -f "$c" ]] && LIBSSL="$c" && break
    done
fi
[[ -n "$LIBSSL" && -f "$LIBSSL" ]] && ok "libssl found: $LIBSSL" || { fail "libssl.so.3 not found"; exit 1; }

INGEST_PORT=$(free_port); METRICS_PORT=$(free_port); HTTPS_PORT=$(free_port)

# --- Ingest stub: records delivered event batches to EVENTS_FILE -------------
step "Start ingest stub"
EVENTS_FILE="$EVENTS_FILE" python3 - "$INGEST_PORT" <<'PYEOF' &
import sys, json, os, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
port = int(sys.argv[1]); path = os.environ["EVENTS_FILE"]; lock = threading.Lock(); seen = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            n = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(n)
            if self.headers.get('Content-Encoding') == 'gzip':
                import gzip; raw = gzip.decompress(raw)
            for e in json.loads(raw).get('events', []):
                with lock:
                    seen.append(e)
                    json.dump(seen, open(path, 'w'))
        except Exception:
            pass
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
class S(ThreadingMixIn, HTTPServer): allow_reuse_address = True; daemon_threads = True
json.dump([], open(path, 'w'))
S(('127.0.0.1', port), H).serve_forever()
PYEOF
INGEST_PID=$!
sleep 1
kill -0 "$INGEST_PID" 2>/dev/null && ok "ingest stub on :$INGEST_PORT" || { fail "ingest stub failed"; exit 1; }

# --- Local self-signed HTTPS server (uses libssl -> gets captured) -----------
step "Start local HTTPS server"
openssl req -x509 -newkey rsa:2048 -keyout "$WORKDIR/k.pem" -out "$WORKDIR/c.pem" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1
python3 - "$HTTPS_PORT" "$WORKDIR/c.pem" "$WORKDIR/k.pem" <<'PYEOF' &
import sys, ssl, json
from http.server import HTTPServer, BaseHTTPRequestHandler
port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
httpd = HTTPServer(('127.0.0.1', port), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PYEOF
HTTPS_PID=$!
sleep 1
kill -0 "$HTTPS_PID" 2>/dev/null && ok "HTTPS server on :$HTTPS_PORT" || { fail "HTTPS server failed"; exit 1; }

# --- Start the sensor --------------------------------------------------------
step "Start sensor"
RUST_LOG=info "$SENSOR_BIN" \
    --bpf "$BPF_OBJ" \
    --ingest "http://127.0.0.1:${INGEST_PORT}" \
    --api-key "ci-e2e-key" --account-id 1001 --role client \
    --metrics-port "${METRICS_PORT}" \
    --tls-libs "$LIBSSL" --discover-libs >"$SENSOR_LOG" 2>&1 &
SENSOR_PID=$!
sleep 4
if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    fail "sensor exited on startup"; echo "---- sensor log ----"; cat "$SENSOR_LOG"; exit 1
fi
ok "sensor running (pid $SENSOR_PID)"

# --- Health endpoints --------------------------------------------------------
step "Health endpoints"
curl -sf "http://127.0.0.1:${METRICS_PORT}/healthz" | grep -q '"status":"ok"' \
    && ok "/healthz ok" || fail "/healthz not ok"
curl -sf "http://127.0.0.1:${METRICS_PORT}/metrics" | grep -q 'apisec_events_captured_total' \
    && ok "/metrics exposes capture counters" || fail "/metrics missing counters"

metric() { curl -sf "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep "^$1 " | awk '{print $2}' | head -1; }

# --- Drive real HTTPS traffic (with PII) and assert capture ------------------
step "Capture real HTTPS traffic"
BEFORE=$(metric apisec_events_captured_total); BEFORE=${BEFORE:-0}
for i in 1 2 3 4 5; do
    curl -sk "https://127.0.0.1:${HTTPS_PORT}/get?email=alice@example.com&ssn=123-45-6789&cc=4111111111111111" -o /dev/null 2>/dev/null || true
done
# Allow ring-buffer drain + 1s batch flush interval + retry headroom
sleep 5
AFTER=$(metric apisec_events_captured_total); AFTER=${AFTER:-0}
NEW=$(( ${AFTER%.*} - ${BEFORE%.*} ))
if [[ "$NEW" -gt 0 ]]; then ok "captured $NEW TLS events from HTTPS traffic"
else fail "0 events captured — uprobes not firing"; echo "---- sensor log ----"; tail -30 "$SENSOR_LOG"; fi

SENT=$(metric apisec_events_sent_total); SENT=${SENT%.*}
[[ "${SENT:-0}" -gt 0 ]] && ok "events delivered to ingest: $SENT" || fail "0 events delivered to ingest"

# --- Ingest stub received well-formed events ---------------------------------
step "Delivered event structure"
RECV=$(python3 -c "import json;print(len(json.load(open('$EVENTS_FILE'))))" 2>/dev/null || echo 0)
if [[ "${RECV:-0}" -gt 0 ]]; then
    ok "ingest stub received $RECV events"
    python3 - "$EVENTS_FILE" <<'PYEOF' && ok "event has required fields" || fail "event structure invalid"
import json, sys
e = json.load(open(sys.argv[1]))[0]
req = ['version','protocol','request','response']
assert all(k in e for k in req), [k for k in req if k not in e]
assert 'method' in e['request'] and 'path' in e['request'], e['request']
assert 'status_code' in e['response'], e['response']
PYEOF
else
    fail "ingest stub received 0 events"
fi

# --- PII redaction on the egress path ----------------------------------------
step "PII redaction"
BLOB=$(cat "$EVENTS_FILE" 2>/dev/null || echo "")
echo "$BLOB" | grep -q "alice@example.com"  && fail "raw email leaked"        || ok "email redacted"
echo "$BLOB" | grep -q "123-45-6789"         && fail "raw SSN leaked"          || ok "SSN redacted"
echo "$BLOB" | grep -q "4111111111111111"    && fail "raw credit card leaked"  || ok "credit card redacted"

# --- Summary -----------------------------------------------------------------
echo ""
echo "============================================================"
echo -e "  E2E capture: ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}"
echo "============================================================"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
