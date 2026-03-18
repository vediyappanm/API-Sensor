#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Required values ──────────────────────────────────────────────────────────
if [[ -z "$NGROK_URL" ]]; then
    read -rp "Paste your ngrok URL (https://xxxx.ngrok-free.app): " NGROK_URL
fi

if [[ -z "$SENSOR_KEY" ]]; then
    read -rsp "Paste your sensor_key: " SENSOR_KEY
    echo
fi

NGROK_URL="${NGROK_URL%/}"   # strip trailing slash

# ── Sanity checks ────────────────────────────────────────────────────────────
BINARY="./userspace/target/release/api-sec-sensor"
BPF_OBJ="./bpf/http_trace.bpf.o"
TLS_LIB="/usr/lib/x86_64-linux-gnu/libssl.so.3"

if [[ ! -f "$BINARY" ]]; then
    echo "[ERROR] Binary not found: $BINARY"
    echo "        Run: cd userspace && cargo build --release"
    exit 1
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    echo "[ERROR] BPF object not found: $BPF_OBJ"
    echo "        Run: make"
    exit 1
fi

if [[ ! -f "$TLS_LIB" ]]; then
    echo "[ERROR] libssl not found: $TLS_LIB"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Must run as root. Use: sudo NGROK_URL=... SENSOR_KEY=... $0"
    exit 1
fi

INGEST_URL="${NGROK_URL}/api/stream/ingest/ebpf"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  API-Sentinel eBPF Sensor"
echo "═══════════════════════════════════════════════════════"
echo "  Ingest : $INGEST_URL"
echo "  BPF    : $BPF_OBJ"
echo "  TLS    : $TLS_LIB"
echo "  Metrics: http://localhost:9090/metrics"
echo "  Health : http://localhost:9090/healthz"
echo "═══════════════════════════════════════════════════════"
echo ""

exec "$BINARY" \
    --bpf       "$BPF_OBJ" \
    --ingest    "$INGEST_URL" \
    --api-key   "$SENSOR_KEY" \
    --account-id 1000000 \
    --role      server \
    --tls-libs  "$TLS_LIB" \
    --discover-libs
