#!/usr/bin/env bash
# Rendered-output assertions for the api-sentinel-sensor Helm chart.
# Each check renders the chart with `helm template` and asserts on the YAML
# the cluster would actually receive — not on the template source.
set -uo pipefail

CHART_DIR="$(cd "$(dirname "$0")/api-sentinel-sensor" && pwd)"
PASS=0
FAIL=0

check() {
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

OUT="$(helm template test-release "$CHART_DIR")" || {
    echo "FAIL: helm template renders without error"
    exit 1
}

check "helm lint passes" helm lint --quiet "$CHART_DIR"

# --- PII_HASH_KEY: mandatory at startup (main.rs bails without it) ---------
check "PII_HASH_KEY env is defined" \
    grep -q 'name: PII_HASH_KEY' <<<"$OUT"
check "PII_HASH_KEY comes from a secretKeyRef" \
    bash -c 'grep -A3 "name: PII_HASH_KEY" <<<"$1" | grep -q secretKeyRef' _ "$OUT"
check "PII_HASH_KEY secret key is pii-hash-key" \
    bash -c 'grep -A4 "name: PII_HASH_KEY" <<<"$1" | grep -q "key: pii-hash-key"' _ "$OUT"

# --- CRI socket: container enrichment needs the containerd socket ----------
check "CRI socket hostPath volume exists" \
    grep -q 'path: /run/containerd/containerd.sock' <<<"$OUT"
check "CRI socket is mounted in the container" \
    grep -q 'mountPath: /run/containerd/containerd.sock' <<<"$OUT"
# CRI_SOCKET reaches the container as env via envFrom: configMapRef.
check "CRI_SOCKET env points at the mounted socket" \
    grep -q 'CRI_SOCKET: "/run/containerd/containerd.sock"' <<<"$OUT"

# --- Tenant identity: MsgHeader must not ship TenantId "default" -----------
check "TENANT_ID present in ConfigMap" \
    grep -q 'TENANT_ID:' <<<"$OUT"
check "POLICY_VERSION present in ConfigMap" \
    grep -q 'POLICY_VERSION:' <<<"$OUT"
check "--tenant-id arg wired to env" \
    grep -q -- '--tenant-id=$(TENANT_ID)' <<<"$OUT"
check "--policy-version arg wired to env" \
    grep -q -- '--policy-version=$(POLICY_VERSION)' <<<"$OUT"

# --- Overrides flow through ------------------------------------------------
OUT2="$(helm template test-release "$CHART_DIR" \
    --set sensor.tenantId=acme --set sensor.criSocket=/run/k3s/containerd/containerd.sock)"
check "sensor.tenantId override reaches the ConfigMap" \
    grep -q 'TENANT_ID: "acme"' <<<"$OUT2"
check "sensor.criSocket override moves volume and mount" \
    bash -c 'grep -q "path: /run/k3s/containerd/containerd.sock" <<<"$1" && grep -q "mountPath: /run/k3s/containerd/containerd.sock" <<<"$1"' _ "$OUT2"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
