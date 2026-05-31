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
`modern_bpf` and Cilium, and **by design** covers essentially the entire modern
fleet. Be precise about what "supported" means per row:

- **✅ verified** — actually run and asserted (full e2e capture) by this project.
- **🟡 expected** — meets the architectural requirements (kernel ≥ 5.8 + BTF +
  x86_64) and *should* work, but is **not yet exercised in CI**. Don't read 🟡 as
  a guarantee; it's a design expectation pending the multi-kernel rig below.

| Distro / platform | Kernel | BTF | Arch | Status |
|---|---|---|---|---|
| Ubuntu (this build) | 6.8 | yes | x86_64 | ✅ verified |
| Ubuntu 20.04+ | 5.4 HWE 5.8+, 5.15, 6.x | yes | x86_64 | 🟡 expected |
| RHEL / Rocky / Alma 9 | 5.14 | yes | x86_64 | 🟡 expected |
| Debian 11+ | 5.10+ | yes | x86_64 | 🟡 expected |
| Amazon Linux 2022/2023 | 5.15+ | yes | x86_64 | 🟡 expected |
| EKS / GKE / AKS node images | 5.10+ | yes | x86_64 | 🟡 expected |
| Container-Optimized OS | 5.10+ | yes | x86_64 | 🟡 expected |
| any arm64 node | ≥ 5.8 | yes | arm64 | ⚠️ not built (see Architecture) |

On these kernels the sensor runs with `CAP_BPF` + `CAP_PERFMON` (+ `CAP_SYS_PTRACE`
for `/proc/<pid>/maps` discovery) rather than full `--privileged`.

> **Honest scope:** only the 6.8/x86_64 row is verified end-to-end. Every 🟡 row
> is an *expectation* from the CO-RE design, not a tested claim, until the
> multi-kernel CI matrix lands. arm64 does not build from a clean clone yet
> (the committed `vmlinux.aarch64.h` is missing).

The startup **preflight** (`userspace/src/compat.rs`) detects the kernel version,
architecture, and BTF presence and fails fast with an actionable message if the
kernel is below the floor or lacks BTF — instead of a cryptic libbpf load error.

### Tier 2 — Legacy / BTF-less kernels (extension point)

Kernels built **without** BTF — RHEL 7, RHEL 8 early (4.18), Ubuntu 18.04,
custom kernels with `CONFIG_DEBUG_INFO_BTF=n`, anything < 5.2 — cannot self-supply
the BTF that CO-RE needs at load time. The industry-standard fix (Tracee,
Inspektor Gadget, BTFHub) is to **ship a tailored BTF with the binary** and feed
it to libbpf via `btf_custom_path`.

The sensor **detects** this case, prints the remediation, and — when you supply
a BTF via `BTF_CUSTOM_PATH` — **feeds it to libbpf at load time** so CO-RE
relocates against it:

```bash
# Generate a minimal, program-tailored BTF for the target kernel (≈1 KB):
bpftool gen min_core_btf /sys/kernel/btf/vmlinux tailored.btf bpf/http_trace.bpf.o
# …or download the full kernel BTF from BTFHub:
#   https://github.com/aquasecurity/btfhub-archive/<distro>/<ver>/<arch>/

BTF_CUSTOM_PATH=/path/to/tailored.btf ./api-sec-sensor --bpf … --ingest …
```

`BTF_CUSTOM_PATH` is applied in `open_and_load_bpf` (`userspace/src/main.rs`):
because libbpf-rs 0.23 exposes no setter for `btf_custom_path`, the sensor opens
the object via raw `libbpf_sys::bpf_object__open_mem` with the option set, then
wraps it with `OpenObject::from_ptr`. This is **verified on kernel 6.8** by
loading the program with a `bpftool gen min_core_btf` BTF (and a negative
control: a malformed BTF makes the load fail, proving the supplied BTF is
actually consumed rather than ignored).

**Status:** detection + remediation + a **functioning** `BTF_CUSTOM_PATH` load
path are in place and unit/loader-verified on 6.8. What is **not** yet done:
(1) bundling btfgen-minimized BTFs for a matrix of kernels and auto-selecting by
`os-release` + `uname` + arch, and (2) a **perf-buffer fallback for the < 5.8
ring-buffer gap** — below 5.8 the sensor still hard-stops at preflight (there is
no perf-buffer path in the BPF program today; it uses `BPF_MAP_TYPE_RINGBUF`
exclusively). The BTF-less path also **must be certified on a multi-kernel test
rig** (RHEL 7 / Ubuntu 18.04) before being relied on in production. BTF blobs
are intentionally not bundled yet: shipping megabytes of unverifiable BTF into a
production image is worse than a clear error.

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
  build, end-to-end HTTPS capture + PII redaction (32/32 in `scripts/e2e-test.sh`),
  the `BTF_CUSTOM_PATH` custom-BTF load path (positive + negative control), and
  metrics-port rebind across TIME_WAIT (`SO_REUSEADDR`).
- **Needs a multi-kernel CI matrix to certify:** behavior on RHEL 9 (5.14),
  Amazon Linux (5.15), and the Tier-2 BTF-less path on RHEL 7 / Ubuntu 18.04.
  A starter matrix workflow lives at `.github/workflows/kernel-matrix.yml`
  (BTFHub-sourced BTFs); it checks **CO-RE relocatability** (`bpftool gen
  min_core_btf`), which is **necessary but not sufficient** — it proves the
  struct fields the program reads exist on the target kernel, but NOT that
  runtime features it *uses* exist. In particular it does **not** verify
  `BPF_MAP_TYPE_RINGBUF` (mainline 5.8): a backported 4.18 kernel (RHEL 8 /
  CentOS 8) can pass relocatability and still fail to load for lack of a ring
  buffer. The real runtime floor stays **5.8 mainline / RHEL 9+** (enforced by
  the preflight). arm64 needs `bpf/vmlinux.aarch64.h` committed from an arm64
  node plus an arm64 runner.
- **Ring-buffer saturation / dropped-event coverage is NOT done.** The userspace
  hot path sustains ~265k events/sec (`tests/load_test.rs`), but that does not
  exercise the scarier failure: under a traffic burst the kernel ring buffer can
  fill, `bpf_ringbuf_reserve` fails, and events are **dropped** — a detection
  gap. The drop is *counted* (BPF `ringbuf_drop_counter` →
  `apisec_ringbuf_drops_total`, asserted < 5% in `scripts/e2e-test.sh`), and the
  ingest side has a circuit breaker, but there is **no burst/soak test that
  deliberately saturates the ring buffer** and asserts drops are bounded and
  observable. This is the cheapest remaining gap (pure software, no hardware) and
  should land before relying on the sensor under heavy load.
