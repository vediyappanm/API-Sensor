# Cross-Kernel Portability

How this sensor runs across different Linux kernels — the model, the guarantees,
and the path for older/locked-down kernels. The design follows the same approach
as Falco's `modern_bpf` driver and Cilium: **one CO-RE BPF object that relocates
against the target kernel's BTF at load time.**

## Why it's portable at all

The BPF program (`bpf/http_trace.bpf.c`) is compiled **once** with CO-RE
(Compile Once – Run Everywhere) relocations. Every kernel-struct field access
(e.g. `struct sock`, `struct task_struct`) is recorded as a relocation, not a
hard-coded offset. At load time, libbpf reads the **running** kernel's BTF
(`/sys/kernel/btf/vmlinux`) and rewrites those offsets to match. So the kernel
that produced the `vmlinux.h` used at build time does **not** constrain which
kernels the object runs on — only the target kernel's BTF matters.

The sensor's primary capture mechanism is **uprobes** on userspace TLS libraries
(`SSL_read`/`SSL_write`, GnuTLS, Go `crypto/tls`). Uprobes attach to userspace
ELF symbols and read userspace memory — they carry **no CO-RE relocations and
need no kernel BTF**, so TLS capture itself is portable down to very old kernels.
The only kernel-coupled surfaces are the optional connection-tracking kprobes and
the ring buffer.

## Support tiers

### Tier 1 — Modern fleet (supported & verified)

**Requirement: kernel ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`).**

The 5.8 floor comes from the BPF **ring buffer** (`BPF_MAP_TYPE_RINGBUF`,
introduced in 5.8) plus the CO-RE helper set. This is the same baseline as Falco
`modern_bpf` and Cilium, and covers essentially the entire modern fleet:

| Distro / platform | Kernel | BTF | Status |
|---|---|---|---|
| Ubuntu 20.04+ | 5.4 HWE 5.8+, 5.15, 6.x | yes | ✅ supported |
| RHEL / Rocky / Alma 9 | 5.14 | yes | ✅ supported |
| Debian 11+ | 5.10+ | yes | ✅ supported |
| Amazon Linux 2022/2023 | 5.15+ | yes | ✅ supported |
| EKS / GKE / AKS node images | 5.10+ | yes | ✅ supported |
| Container-Optimized OS | 5.10+ | yes | ✅ supported |

On these kernels the sensor runs with `CAP_BPF` + `CAP_PERFMON` (+ `CAP_SYS_PTRACE`
for `/proc/<pid>/maps` discovery) rather than full `--privileged`.

The startup **preflight** (`userspace/src/compat.rs`) detects the kernel version,
architecture, and BTF presence and fails fast with an actionable message if the
kernel is below the floor or lacks BTF — instead of a cryptic libbpf load error.

### Tier 2 — Legacy / BTF-less kernels (extension point)

Kernels built **without** BTF — RHEL 7, RHEL 8 early (4.18), Ubuntu 18.04,
custom kernels with `CONFIG_DEBUG_INFO_BTF=n`, anything < 5.2 — cannot self-supply
the BTF that CO-RE needs at load time. The industry-standard fix (Tracee,
Inspektor Gadget, BTFHub) is to **ship a tailored BTF with the binary** and feed
it to libbpf via `btf_custom_path`.

The sensor already **detects** this case and prints the remediation. Supplying a
custom BTF is wired through the `BTF_CUSTOM_PATH` environment variable:

```bash
# Generate a minimal, program-tailored BTF for the target kernel (≈1 KB):
bpftool gen min_core_btf /sys/kernel/btf/vmlinux tailored.btf bpf/http_trace.bpf.o
# …or download the full kernel BTF from BTFHub:
#   https://github.com/aquasecurity/btfhub-archive/<distro>/<ver>/<arch>/

BTF_CUSTOM_PATH=/path/to/tailored.btf ./api-sec-sensor --bpf … --ingest …
```

**Status:** detection + clear remediation + the `BTF_CUSTOM_PATH` hook are in
place. Full turnkey support — embedding btfgen-minimized BTFs for a matrix of
kernels and auto-selecting by `os-release` + `uname` + arch, plus a
perf-buffer fallback for the < 5.8 ring-buffer gap — is the next increment and
**must be certified on a multi-kernel test rig** before being relied on in
production. It is intentionally not bundled yet: shipping megabytes of
unverifiable BTF blobs into a production image is worse than a clear error.

## Graceful degradation

The connection-tracking kprobes (`tcp_connect`, `inet_csk_accept`, `tcp_close`)
are **best-effort**. They hook stable, arch-agnostic kernel functions and read
`struct sock` via CO-RE, but they are non-essential — they only enrich events
with the kernel-resolved source/dest IP 4-tuple. If any fails to attach (missing
symbol, lockdown, exotic kernel), the sensor **logs and continues uprobe-only**:
TLS capture stays fully intact, only IP enrichment is reduced. A failed kprobe
never aborts startup. See `attach_kernel_probes` in `userspace/src/bpf.rs`.

## Architecture (x86_64 / arm64)

The BPF program has arch guards for the few arch-specific reads (Go TLS goroutine
register: x86 `fsbase` vs arm64 `tp_value`; Go register-based args). The build
selects the arch via `-D__TARGET_ARCH_x86` / `-D__TARGET_ARCH_arm64`:

- **Makefile** auto-detects via `uname -m` and uses live BTF when present, else
  the committed `bpf/vmlinux.$(uname -m).h`.
- **Dockerfile** uses `buildx`'s `TARGETARCH` and the committed
  `bpf/vmlinux.<arch>.h`, so `docker build` is reproducible from a clean clone.

`bpf/vmlinux.x86_64.h` is committed. To enable arm64 image builds, generate and
commit `bpf/vmlinux.aarch64.h` on an arm64 node:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.aarch64.h
```

## What is verified vs. what needs a multi-kernel rig

- **Verified on kernel 6.8 (this build):** CO-RE load, ring buffer, all uprobes,
  kprobe attach + graceful degradation, preflight gating, reproducible Docker
  build, end-to-end HTTPS capture + PII redaction (see `scripts/e2e-test.sh`).
- **Needs a multi-kernel CI matrix to certify:** behavior on RHEL 9 (5.14),
  Amazon Linux (5.15), and the Tier-2 BTF-less path on RHEL 7 / Ubuntu 18.04.
  Recommended: a CI job that boots VM images (or BTFHub-sourced BTFs) across the
  support matrix and runs `scripts/e2e-test.sh` on each.
