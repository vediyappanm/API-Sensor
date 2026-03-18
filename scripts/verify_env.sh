#!/usr/bin/env bash
set -euo pipefail

echo "== eBPF TLS Sensor Environment Check =="

KERNEL="$(uname -r || true)"
echo "Kernel: ${KERNEL}"

if [ -f /etc/os-release ]; then
  echo "OS:"
  cat /etc/os-release | grep -E "^(NAME|VERSION)=" || true
fi

if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "BTF: present (/sys/kernel/btf/vmlinux)"
else
  echo "BTF: missing. CO-RE may fail. Install kernel with BTF or provide vmlinux."
fi

if command -v bpftool >/dev/null 2>&1; then
  echo "bpftool: found"
  echo "bpftool feature probe (kernel):"
  bpftool feature probe kernel 2>/dev/null | grep -E "(Tracing|BTF|Uprobe)" || true
else
  echo "bpftool: missing (recommended for vmlinux.h generation)"
fi

if command -v clang >/dev/null 2>&1; then
  echo "clang: found"
else
  echo "clang: missing (required for BPF compilation)"
fi

if [ -f /sys/kernel/debug/tracing/uprobe_events ]; then
  echo "uprobes: available (/sys/kernel/debug/tracing/uprobe_events)"
else
  echo "uprobes: not available (mount debugfs or enable CONFIG_UPROBE_EVENTS)"
fi

if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
  echo "unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
fi

if [ -f /proc/sys/kernel/kptr_restrict ]; then
  echo "kptr_restrict: $(cat /proc/sys/kernel/kptr_restrict)"
fi

CONFIG_SOURCE=""
if [ -f "/boot/config-${KERNEL}" ]; then
  CONFIG_SOURCE="/boot/config-${KERNEL}"
elif [ -f /proc/config.gz ]; then
  CONFIG_SOURCE="/proc/config.gz"
fi
if [ -n "${CONFIG_SOURCE}" ]; then
  echo "Kernel config: ${CONFIG_SOURCE}"
  if [ "${CONFIG_SOURCE}" = "/proc/config.gz" ]; then
    zcat /proc/config.gz | grep -E "CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|UPROBE_EVENTS)=y" || true
  else
    grep -E "CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|UPROBE_EVENTS)=y" "${CONFIG_SOURCE}" || true
  fi
else
  echo "Kernel config: not found (unable to verify CONFIG_BPF/UPROBE)"
fi

LIBSSL=${1:-/usr/lib/x86_64-linux-gnu/libssl.so.3}
if [ -f "$LIBSSL" ]; then
  echo "libssl: ${LIBSSL}"
  if command -v nm >/dev/null 2>&1; then
    echo "Checking TLS symbols in libssl..."
    nm -D "$LIBSSL" | grep -E "SSL_(read|write)(_ex)?" || true
  else
    echo "nm: missing (unable to verify SSL_read/SSL_write symbols)"
  fi
else
  echo "libssl: not found at ${LIBSSL}"
fi

GNUTLS_LIB=${2:-/usr/lib/x86_64-linux-gnu/libgnutls.so.30}
if [ -f "$GNUTLS_LIB" ]; then
  echo "libgnutls: ${GNUTLS_LIB}"
  if command -v nm >/dev/null 2>&1; then
    echo "Checking GnuTLS symbols in libgnutls..."
    nm -D "$GNUTLS_LIB" | grep -E "gnutls_record_(send|recv)" || true
  else
    echo "nm: missing (unable to verify gnutls_record_* symbols)"
  fi
else
  echo "libgnutls: not found at ${GNUTLS_LIB}"
fi

echo "== Done =="
