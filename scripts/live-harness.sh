#!/usr/bin/env bash
# Live capture harness: real BPF load, real OpenSSL traffic in both directions, real ingest.
#
# Runs as root on a Linux host (or a privileged container) with openssl and curl. Each phase is
# a separate command so an outer script can stop/start the ingest backend between phases.
# Needs python3 for the inbound server.
#
#
#   live-harness.sh start                 load the sensor, start TLS servers
#   live-harness.sh traffic <tag> <n>     n requests: curl (outbound) -> python ssl server (inbound);
#                                         TARGET_PORT=8443 targets `openssl s_server -WWW` instead
#   live-harness.sh burst <tag> <n> <par> n requests with par concurrent clients (overload)
#   live-harness.sh pending <tag>         a request whose server never answers
#   live-harness.sh verify <tag> <n>      per-request event counts as stored by the ingest validator
#   live-harness.sh metrics               sensor counters and resident memory
#   live-harness.sh sigterm               SIGTERM; report drain time and the shutdown log
#   live-harness.sh kill                  SIGKILL (crash); the next `start` must load cleanly
#   live-harness.sh stop                  stop everything
#   live-harness.sh paths                 print SENSOR_BIN and BPF_OBJ as the sensor will see them
#
# Required env: SENSOR_BIN, BPF_OBJ, VALIDATOR (base URL of tests/test-servers/validator, e.g.
# http://validator:9999). Optional: WORK (default /tmp/live), PII_HASH_KEY, SENSOR_ARGS.
# SENSOR_BIN and BPF_OBJ may be relative to the caller's directory; paths inside SENSOR_ARGS must
# be absolute because the sensor runs from $WORK.
set -euo pipefail

# Resolve before changing into $WORK, or a relative path would point inside it.
abspath() { (cd "$(dirname "$1")" 2>/dev/null && echo "$(pwd -P)/$(basename "$1")"); }
for var in SENSOR_BIN BPF_OBJ; do
    if [ -n "${!var:-}" ]; then
        resolved=$(abspath "${!var}" || true)
        if [ -z "$resolved" ] || [ ! -f "$resolved" ]; then
            echo "$var not found: ${!var}" >&2
            exit 2
        fi
        printf -v "$var" '%s' "$resolved"
    fi
done

WORK=${WORK:-/tmp/live}
METRICS=http://127.0.0.1:${METRICS_PORT:-9090}
mkdir -p "$WORK/www"
cd "$WORK"

sensor_pid() { cat "$WORK/sensor.pid" 2>/dev/null || true; }

# A zombie still answers kill -0; containers whose PID 1 never reaps (sleep infinity) keep them.
running() { [ -r "/proc/$1/stat" ] && [ "$(awk '{print $3}' "/proc/$1/stat")" != Z ]; }

metric() { curl -s "$METRICS/metrics" | awk -v m="$1" '$1==m {print $2}'; }

start() {
    : "${SENSOR_BIN:?}" "${BPF_OBJ:?}" "${VALIDATOR:?}"
    if [ ! -f cert.pem ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 \
            -subj /CN=localhost >/dev/null 2>&1
        echo '{"ok":true}' > www/index.html
    fi
    if ! pgrep -f 'openssl s_server -accept 8443' >/dev/null; then
        (cd www && nohup openssl s_server -accept 8443 -WWW -cert ../cert.pem -key ../key.pem -quiet \
            >/dev/null 2>&1 &)
        # stdin EOF makes s_server close the connection, so keep stdin open.
        (sleep 100000 | openssl s_server -accept 8444 -cert cert.pem -key key.pem -quiet) >/dev/null 2>&1 &
        sleep 1
    fi
    # Inbound target: CPython's ssl module calls SSL_read_ex/SSL_write_ex like typical servers.
    # (`s_server -WWW` on 8443 reads through BIO_f_ssl, which bypasses the public symbols.)
    if ! pgrep -f 'live-https-server' >/dev/null; then
        cat > https_server.py <<'EOF'
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer.request_queue_size = 512
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8445), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
        nohup python3 https_server.py live-https-server >/dev/null 2>&1 &
        sleep 1
    fi
    : > sensor.log
    # SENSOR_ARGS is a space-separated flag list; word splitting is intended.
    # shellcheck disable=SC2086
    API_KEY=live-test PII_HASH_KEY=${PII_HASH_KEY:-$(openssl rand -hex 32)} \
    APISEC_ALLOW_HTTP=true APISEC_ALLOW_CAPTURE_ALL=true RUST_LOG=${RUST_LOG:-info} \
        nohup "$SENSOR_BIN" --bpf="$BPF_OBJ" --ingest="$VALIDATOR/ingest" --discover-libs \
        --tls-libs=/usr/lib/x86_64-linux-gnu/libssl.so.3 --batch-size=50 ${SENSOR_ARGS:-} \
        >> sensor.log 2>&1 &
    echo $! > sensor.pid
    local t0=$SECONDS
    until grep -q 'BPF object loaded' sensor.log; do
        if ! running "$(sensor_pid)"; then
            echo "SENSOR EXITED DURING LOAD"; tail -40 sensor.log; exit 1
        fi
        [ $((SECONDS - t0)) -gt 60 ] && { echo "LOAD TIMEOUT"; tail -40 sensor.log; exit 1; }
        sleep 0.5
    done
    sleep 3
    echo "== load =="
    grep -E 'BPF object loaded|attached|probe|WARN|ERROR' sensor.log | sed 's/\x1b\[[0-9;]*m//g' | head -40
}

TARGET_PORT=${TARGET_PORT:-8445}

traffic() {
    local tag=$1 n=$2 i
    for i in $(seq 1 "$n"); do
        curl -sk -o /dev/null "https://127.0.0.1:$TARGET_PORT/index.html?rid=$tag-$i" || true
    done
}

burst() {
    local tag=$1 n=$2 par=$3
    seq 1 "$n" | xargs -P "$par" -I{} curl -sk -o /dev/null --max-time 10 -w '%{http_code}\n' \
        "https://127.0.0.1:$TARGET_PORT/index.html?rid=$tag-{}" > "burst-$tag.codes" || true
    echo "  client results (http_code count; 000 = request never completed):"
    sort "burst-$tag.codes" | uniq -c | sed 's/^/    /'
}

pending() {
    local tag=$1
    # s_server on 8444 is not an HTTP server: the request is read and never answered.
    ( { printf 'GET /never?rid=%s HTTP/1.1\r\nHost: localhost\r\n\r\n' "$tag"; sleep 600; } |
        openssl s_client -connect 127.0.0.1:8444 -quiet ) >/dev/null 2>&1 < /dev/null &
    sleep 2
}

verify() {
    local tag=$1 n=$2
    sleep "${SETTLE:-4}"
    curl -s "$VALIDATOR/events?rid=$tag-" > "events-$tag.json"
    # Count events per rid without jq: one rid per event in HTTPReq.Query.
    grep -o "rid=$tag-[0-9]*" "events-$tag.json" | sort | uniq -c | awk '{print $1}' | sort -n | uniq -c |
        awk '{printf "  %s requests seen %s time(s)\n", $1, $2}'
    local distinct
    distinct=$(grep -o "rid=$tag-[0-9]*" "events-$tag.json" | sort -u | wc -l)
    echo "  distinct requests with >=1 event: $distinct / $n"
    echo "  events by capturing process:"
    grep -oE '"process_name": ?"[^"]*"' "events-$tag.json" | sort | uniq -c | sed 's/^/    /'
    echo "  validator summary: $(curl -s "$VALIDATOR/summary")"
}

metrics() {
    local pid
    pid=$(sensor_pid)
    for m in apisec_events_captured_total apisec_events_dropped_total apisec_events_sent_total \
             apisec_events_lost_send_total apisec_send_errors_total apisec_consecutive_send_failures \
             apisec_export_queue_bytes apisec_export_queue_byte_drops_total apisec_buffer_bytes \
             apisec_capture_gaps_total apisec_role_ambiguous_total apisec_abi_mismatch_total \
             apisec_probe_attach_failures_total apisec_transactions_incomplete_total \
             apisec_bpf_reserve_fail_total apisec_ringbuf_drops_total apisec_unpaired_responses_total; do
        printf '  %-42s %s\n' "$m" "$(metric "$m")"
    done
    printf '  %-42s %s\n' "readyz" "$(curl -s -o /dev/null -w '%{http_code}' "$METRICS/readyz")"
    [ -n "$pid" ] && grep -E 'VmRSS|VmHWM' "/proc/$pid/status" | sed 's/^/  /'
}

sigterm() {
    local pid t0
    pid=$(sensor_pid)
    t0=$(date +%s%N)
    kill -TERM "$pid"
    while running "$pid"; do sleep 0.1; done
    echo "  exited after $(( ($(date +%s%N) - t0) / 1000000 )) ms"
    grep -E 'shutdown|drain|deadline' sensor.log | sed 's/\x1b\[[0-9;]*m//g' | tail -5 | sed 's/^/  /'
}

kill9() {
    kill -KILL "$(sensor_pid)" 2>/dev/null || true
    sleep 1
}

stop() {
    kill -TERM "$(sensor_pid)" 2>/dev/null || true
    pkill -f 'openssl s_client -connect 127.0.0.1:8444' 2>/dev/null || true
    pkill -f 'openssl s_server' 2>/dev/null || true
    pkill -f 'sleep 100000' 2>/dev/null || true
    pkill -f 'live-https-server' 2>/dev/null || true
}

cmd=${1:?usage: $0 start|traffic|burst|pending|verify|metrics|sigterm|kill|stop|paths}
shift
case $cmd in
    start) start ;;
    traffic) traffic "$@" ;;
    burst) burst "$@" ;;
    pending) pending "$@" ;;
    verify) verify "$@" ;;
    metrics) metrics ;;
    sigterm) sigterm ;;
    kill) kill9 ;;
    stop) stop ;;
    paths) echo "SENSOR_BIN=${SENSOR_BIN:-}"; echo "BPF_OBJ=${BPF_OBJ:-}" ;;
    *) echo "unknown phase $cmd"; exit 2 ;;
esac
