#!/usr/bin/env bash
# Behavioural checks for live-harness.sh that need no BPF, root or network.
set -euo pipefail

HARNESS=$(cd "$(dirname "$0")" && pwd -P)/live-harness.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/caller/target/release" "$TMP/caller/bpf"
touch "$TMP/caller/target/release/api-sec-sensor" "$TMP/caller/bpf/http_trace.bpf.o"
CALLER=$(cd "$TMP/caller" && pwd -P)

PASS=0
FAIL=0
check() {
    local name=$1; shift
    if "$@"; then echo "PASS: $name"; PASS=$((PASS + 1)); else echo "FAIL: $name"; FAIL=$((FAIL + 1)); fi
}

out=$(cd "$CALLER" && WORK="$TMP/work" SENSOR_BIN=./target/release/api-sec-sensor \
    BPF_OBJ=bpf/http_trace.bpf.o bash "$HARNESS" paths)
check "relative SENSOR_BIN resolves against the caller's directory, not \$WORK" \
    grep -qx "SENSOR_BIN=$CALLER/target/release/api-sec-sensor" <<<"$out"
check "relative BPF_OBJ resolves against the caller's directory" \
    grep -qx "BPF_OBJ=$CALLER/bpf/http_trace.bpf.o" <<<"$out"

out=$(WORK="$TMP/work" SENSOR_BIN="$CALLER/target/release/api-sec-sensor" BPF_OBJ="$CALLER/bpf/http_trace.bpf.o" \
    bash "$HARNESS" paths)
check "absolute paths are kept" grep -qx "SENSOR_BIN=$CALLER/target/release/api-sec-sensor" <<<"$out"

set +e
err=$(cd "$CALLER" && WORK="$TMP/work" SENSOR_BIN=./missing BPF_OBJ=bpf/http_trace.bpf.o \
    bash "$HARNESS" paths 2>&1)
status=$?
set -e
check "a missing binary fails with status 2" test "$status" -eq 2
check "the failure names the variable" grep -q "SENSOR_BIN not found: ./missing" <<<"$err"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
