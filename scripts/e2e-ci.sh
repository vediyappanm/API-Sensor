#!/usr/bin/env bash
# e2e-ci.sh — Hermetic, multi-protocol end-to-end capture test for CI.
#
# No external network: stands up local servers (TLS via OpenSSL, HTTP/2 via
# nginx, plaintext HTTP, GnuTLS via gnutls-serv, Go crypto/tls), runs ONE sensor
# with all capture modes on, drives real traffic for each, and asserts the live
# capture path works end to end for each:
#
#   BPF load + verifier -> uprobe/tracepoint capture -> parse/protocol detect
#     -> PII redaction -> ingest delivery
#
# Core path (OpenSSL + HTTP/1.1 + ingest + PII redaction) is always asserted.
# The per-protocol matrix (HTTP/2, plaintext, GnuTLS, Go) asserts capture when
# the driving tool is installed, and SKIPs (not fails) when it is not — so CI,
# which installs all of them, gets full coverage, while a bare box degrades
# gracefully. A tool that IS present but captures nothing is a hard failure.
#
# Requires root (CAP_BPF/CAP_PERFMON) and kernel >= 5.8 with BTF.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SENSOR_BIN="${SENSOR_BIN:-$REPO_ROOT/userspace/target/release/api-sec-sensor}"
BPF_OBJ="${BPF_OBJ:-$REPO_ROOT/bpf/http_trace.bpf.o}"
LIBSSL="${LIBSSL:-}"; LIBGNUTLS="${LIBGNUTLS:-}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
PASS=0; FAIL=0; SKIP=0
ok()   { echo -e "${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}[SKIP]${RESET} $1"; SKIP=$((SKIP+1)); }
info() { echo -e "${YELLOW}[INFO]${RESET} $1"; }
step() { echo -e "\n${CYAN}-- $1 --${RESET}"; }

WORKDIR="$(mktemp -d)"
EVENTS_FILE="$WORKDIR/events.json"
SENSOR_LOG="$WORKDIR/sensor.log"
declare -a BG_PIDS=()
NGINX_STARTED=0; GNUTLS_STARTED=0

cleanup() {
    for p in "${BG_PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    [[ "$NGINX_STARTED" -eq 1 ]] && nginx -c "$WORKDIR/nginx.conf" -p "$WORKDIR" -s stop 2>/dev/null || true
    rm -rf "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT

free_port() { python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"; }
have() { command -v "$1" >/dev/null 2>&1; }
metric() { curl -sf "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | grep "$1" | awk '{print $NF}' | head -1; }
captured() { curl -sf "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | grep '^apisec_events_captured_total ' | awk '{print $2}' | head -1; }

# Assert that running $2 (a traffic generator) increases the captured counter.
# $1 = label.  Captures the delta over a fixed settle window.
assert_capture() {
    local label="$1"; shift
    local before after
    before=$(captured); before=${before:-0}
    "$@"
    sleep 4
    after=$(captured); after=${after:-0}
    local delta=$(( ${after%.*} - ${before%.*} ))
    if [[ "$delta" -gt 0 ]]; then ok "$label: captured $delta events"
    else fail "$label: 0 events captured (tool present but nothing captured)"; tail -20 "$SENSOR_LOG"; fi
}

# --- Preconditions -----------------------------------------------------------
step "Preconditions"
[[ "$(id -u)" -eq 0 ]] || { fail "must run as root"; exit 1; }
[[ -x "$SENSOR_BIN" ]] && ok "sensor binary present" || { fail "sensor binary missing: $SENSOR_BIN"; exit 1; }
[[ -f "$BPF_OBJ" ]] && ok "BPF object present" || { fail "BPF object missing: $BPF_OBJ"; exit 1; }
if [[ -z "$LIBSSL" ]]; then
    for c in /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/aarch64-linux-gnu/libssl.so.3 /lib/x86_64-linux-gnu/libssl.so.3; do
        [[ -f "$c" ]] && LIBSSL="$c" && break
    done
fi
[[ -n "$LIBSSL" && -f "$LIBSSL" ]] && ok "libssl: $LIBSSL" || { fail "libssl.so.3 not found"; exit 1; }
if [[ -z "$LIBGNUTLS" ]]; then
    for c in /usr/lib/x86_64-linux-gnu/libgnutls.so.30 /usr/lib/aarch64-linux-gnu/libgnutls.so.30; do
        [[ -f "$c" ]] && LIBGNUTLS="$c" && break
    done
fi

INGEST_PORT=$(free_port); METRICS_PORT=$(free_port)
TLS_PORT=$(free_port); PLAIN_PORT=$(free_port); H2_PORT=$(free_port); GTLS_PORT=$(free_port); GO_PORT=$(free_port)

openssl req -x509 -newkey rsa:2048 -keyout "$WORKDIR/k.pem" -out "$WORKDIR/c.pem" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

# --- Ingest stub -------------------------------------------------------------
step "Start ingest stub"
EVENTS_FILE="$EVENTS_FILE" python3 - "$INGEST_PORT" <<'PY' &
import sys, json, os, threading, gzip
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
port=int(sys.argv[1]); path=os.environ["EVENTS_FILE"]; lk=threading.Lock(); seen=[]
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            n=int(self.headers.get('Content-Length',0)); raw=self.rfile.read(n)
            if self.headers.get('Content-Encoding')=='gzip': raw=gzip.decompress(raw)
            for e in json.loads(raw).get('events',[]):
                with lk: seen.append(e); json.dump(seen, open(path,'w'))
        except Exception: pass
        self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
    def log_message(self,*a): pass
class S(ThreadingMixIn,HTTPServer): allow_reuse_address=True; daemon_threads=True
json.dump([], open(path,'w')); S(('127.0.0.1',port),H).serve_forever()
PY
BG_PIDS+=($!); sleep 1
kill -0 "${BG_PIDS[-1]}" 2>/dev/null && ok "ingest stub on :$INGEST_PORT" || { fail "ingest stub failed"; exit 1; }

# --- Servers: TLS (OpenSSL, core), plaintext, HTTP/2, GnuTLS, Go --------------
step "Start traffic servers"
# OpenSSL TLS server (python) — core path
python3 - "$TLS_PORT" "$WORKDIR/c.pem" "$WORKDIR/k.pem" <<'PY' &
import sys, ssl, json
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b=json.dumps({"ok":True}).encode()
        self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
h=HTTPServer(('127.0.0.1',int(sys.argv[1])),H); h.socket=ctx.wrap_socket(h.socket,server_side=True); h.serve_forever()
PY
BG_PIDS+=($!); ok "OpenSSL TLS server on :$TLS_PORT"

# Plaintext HTTP server
python3 -m http.server "$PLAIN_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
BG_PIDS+=($!); ok "plaintext HTTP server on :$PLAIN_PORT"

# HTTP/2 over TLS (nginx)
if have nginx; then
    cat > "$WORKDIR/nginx.conf" <<EOF
worker_processes 1; pid $WORKDIR/nginx.pid; error_log $WORKDIR/nginx.err;
events {}
http { access_log off;
  server { listen 127.0.0.1:$H2_PORT ssl http2;
    ssl_certificate $WORKDIR/c.pem; ssl_certificate_key $WORKDIR/k.pem;
    location / { return 200 "ok\n"; } } }
EOF
    if nginx -c "$WORKDIR/nginx.conf" -p "$WORKDIR" 2>>"$WORKDIR/nginx.err"; then
        NGINX_STARTED=1; ok "nginx HTTP/2 server on :$H2_PORT"
    else info "nginx failed to start — HTTP/2 will be skipped"; fi
fi

# GnuTLS server
if have gnutls-serv && [[ -n "$LIBGNUTLS" ]]; then
    gnutls-serv --http -p "$GTLS_PORT" --x509certfile "$WORKDIR/c.pem" --x509keyfile "$WORKDIR/k.pem" >/dev/null 2>&1 &
    BG_PIDS+=($!); GNUTLS_STARTED=1; ok "gnutls-serv on :$GTLS_PORT"
fi

# Go crypto/tls workload (must be running before sensor so the startup scan finds it)
GO_BIN=""
if have go; then
    export GOCACHE="$WORKDIR/gocache" GOPROXY=off GOFLAGS=-mod=mod
    if go build -C "$REPO_ROOT/tests/e2e" -o "$WORKDIR/gotls" . 2>"$WORKDIR/gobuild.log"; then
        "$WORKDIR/gotls" "$GO_PORT" "$WORKDIR/c.pem" "$WORKDIR/k.pem" >/dev/null 2>&1 &
        BG_PIDS+=($!); GO_BIN="$WORKDIR/gotls"; sleep 1
        kill -0 "${BG_PIDS[-1]}" 2>/dev/null && ok "Go crypto/tls workload on :$GO_PORT" || info "Go workload failed to start"
    else info "go build failed — Go TLS will be skipped"; cat "$WORKDIR/gobuild.log"; fi
fi

# --- Start sensor (all capture modes) ----------------------------------------
step "Start sensor"
TLS_LIBS="$LIBSSL"; [[ -n "$LIBGNUTLS" ]] && TLS_LIBS="$LIBSSL,$LIBGNUTLS"
RUST_LOG=info "$SENSOR_BIN" --bpf "$BPF_OBJ" --ingest "http://127.0.0.1:${INGEST_PORT}" \
    --api-key ci-e2e --account-id 1001 --role server --metrics-port "${METRICS_PORT}" \
    --tls-libs "$TLS_LIBS" --discover-libs --capture-plaintext --go-tls >"$SENSOR_LOG" 2>&1 &
BG_PIDS+=($!)
# Go attach needs the startup /proc scan + symbol/offset resolution; give it time.
sleep 8
kill -0 "${BG_PIDS[-1]}" 2>/dev/null || { fail "sensor exited on startup"; cat "$SENSOR_LOG"; exit 1; }
ok "sensor running"

# --- Health ------------------------------------------------------------------
step "Health endpoints"
curl -sf "http://127.0.0.1:${METRICS_PORT}/healthz" | grep -q '"status":"ok"' && ok "/healthz ok" || fail "/healthz not ok"
curl -sf "http://127.0.0.1:${METRICS_PORT}/metrics" | grep -q apisec_events_captured_total && ok "/metrics live" || fail "/metrics missing"

# --- CORE: OpenSSL + HTTP/1.1 capture (always) -------------------------------
step "Core: OpenSSL / HTTP/1.1"
gen_openssl() { for i in 1 2 3 4 5; do
    curl -sk --http1.1 "https://127.0.0.1:${TLS_PORT}/get?email=alice@example.com&ssn=123-45-6789&cc=4111111111111111" -o /dev/null 2>/dev/null || true
done; }
assert_capture "OpenSSL HTTP/1.1" gen_openssl
SENT=$(metric '^apisec_events_sent_total'); SENT=${SENT%.*}
[[ "${SENT:-0}" -gt 0 ]] && ok "events delivered to ingest: $SENT" || fail "0 events delivered to ingest"

# --- Protocol matrix ---------------------------------------------------------
step "HTTP/2 (over TLS)"
if [[ "$NGINX_STARTED" -eq 1 ]]; then
    B2=$(metric 'protocol="http2"'); B2=${B2:-0}
    gen_h2() { for i in 1 2 3 4; do curl -sk --http2 "https://127.0.0.1:${H2_PORT}/get?q=$i" -o /dev/null 2>/dev/null || true; done; }
    assert_capture "HTTP/2" gen_h2
    A2=$(metric 'protocol="http2"'); A2=${A2:-0}
    [[ $(( ${A2%.*} - ${B2%.*} )) -gt 0 ]] && ok "HTTP/2 protocol detected (counter +$(( ${A2%.*} - ${B2%.*} )))" || fail "HTTP/2 traffic not classified as http2"
else skip "HTTP/2 (nginx unavailable)"; fi

step "Plaintext HTTP"
gen_plain() { for i in 1 2 3 4; do curl -s "http://127.0.0.1:${PLAIN_PORT}/?q=$i&token=secret" -o /dev/null 2>/dev/null || true; done; }
assert_capture "plaintext HTTP" gen_plain

step "GnuTLS"
if have gnutls-cli && [[ "$GNUTLS_STARTED" -eq 1 ]]; then
    gen_gnutls() { for i in 1 2 3 4; do printf 'GET /?ssn=123-45-6789 HTTP/1.0\r\n\r\n' | gnutls-cli --insecure -p "$GTLS_PORT" 127.0.0.1 >/dev/null 2>&1 || true; done; }
    assert_capture "GnuTLS" gen_gnutls
else skip "GnuTLS (gnutls-cli/libgnutls unavailable)"; fi

step "Go crypto/tls"
if [[ -n "$GO_BIN" ]]; then
    # The Go workload self-drives every 300ms; just sample the delta over a window.
    GB=$(captured); GB=${GB:-0}; sleep 5; GA=$(captured); GA=${GA:-0}
    GD=$(( ${GA%.*} - ${GB%.*} ))
    if grep -qiE 'attaching Go TLS probes' "$SENSOR_LOG"; then ok "Go TLS probes attached"; else info "no explicit Go-attach log line"; fi
    [[ "$GD" -gt 0 ]] && ok "Go crypto/tls: captured $GD events" || fail "Go TLS: 0 events captured"
else skip "Go crypto/tls (go toolchain unavailable)"; fi

# --- PII redaction on egress -------------------------------------------------
step "PII redaction (delivered events)"
BLOB=$(cat "$EVENTS_FILE" 2>/dev/null || echo "")
echo "$BLOB" | grep -q "alice@example.com" && fail "raw email leaked" || ok "email redacted"
echo "$BLOB" | grep -q "123-45-6789" && fail "raw SSN leaked" || ok "SSN redacted"
echo "$BLOB" | grep -q "4111111111111111" && fail "raw credit card leaked" || ok "credit card redacted"

# --- Delivered event structure -----------------------------------------------
step "Delivered event structure"
RECV=$(python3 -c "import json;print(len(json.load(open('$EVENTS_FILE'))))" 2>/dev/null || echo 0)
if [[ "${RECV:-0}" -gt 0 ]]; then
    ok "ingest received $RECV events"
    python3 - "$EVENTS_FILE" <<'PY' && ok "event schema valid" || fail "event schema invalid"
import json,sys
e=json.load(open(sys.argv[1]))[0]
for k in ('version','protocol','request','response'): assert k in e, k
assert 'method' in e['request'] and 'path' in e['request']
assert 'status_code' in e['response']
PY
else fail "ingest received 0 events"; fi

# --- Summary -----------------------------------------------------------------
echo ""
echo "============================================================"
echo -e "  E2E capture: ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}, ${YELLOW}${SKIP} skipped${RESET}"
echo "============================================================"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
