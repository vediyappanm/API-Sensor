#!/usr/bin/env bash
# docker-entrypoint.sh — sets up BPF environment inside the privileged container
# then runs root-verify.sh
set -euo pipefail

echo "=== Setting up BPF environment ==="

# Mount bpffs if not already mounted
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    echo "[INFO] Mounting bpffs at /sys/fs/bpf"
    mount -t bpf bpf /sys/fs/bpf
else
    echo "[INFO] bpffs already mounted"
fi

# Mount debugfs if not already mounted (needed for uprobe events)
if ! mountpoint -q /sys/kernel/debug 2>/dev/null; then
    echo "[INFO] Mounting debugfs at /sys/kernel/debug"
    mount -t debugfs debugfs /sys/kernel/debug || echo "[WARN] debugfs mount failed (non-fatal)"
fi

echo "[INFO] bpftool version: $(bpftool version 2>/dev/null | head -1 || echo 'not found')"
echo "[INFO] Kernel: $(uname -r)"
echo "[INFO] libssl: $(ls /usr/lib/x86_64-linux-gnu/libssl.so* 2>/dev/null | head -1 || echo 'not found')"

echo ""
echo "=== Running root-verify.sh ==="
exec bash /sensor/ebpf/scripts/root-verify.sh "$@"
