# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An eBPF-based TLS traffic capture sensor for the API Sentinel platform. It attaches uprobes to TLS library functions (OpenSSL/BoringSSL `SSL_read`/`SSL_write`, Go `crypto/tls`, GnuTLS, QUIC) to intercept decrypted HTTP traffic at the kernel level — no application changes required — then parses, redacts PII, and ships events to a cloud ingest endpoint. The kernel side is C/BPF; userspace is async Rust (Tokio).

## Build

The two halves build separately. `make` builds both; the Rust half can build standalone without a kernel.

```bash
make                      # builds bpf/http_trace.bpf.o AND userspace release binary
make clean                # removes BPF object, vmlinux.h, runs cargo clean
cd userspace && cargo build --release   # userspace only (no BPF toolchain needed)
```

Building the BPF object requires `clang`, `llvm`, `libbpf-dev`, and `bpftool` (for generating `bpf/vmlinux.h` from `/sys/kernel/btf/vmlinux`). `vmlinux.h` is generated on the fly by the Makefile and is gitignored — it depends on the host kernel's BTF. Compiling the Rust userspace requires `protobuf-compiler` (build.rs runs `tonic-build` against `userspace/proto/runtime/v1/api.proto`).

The binary is named `api-sec-sensor` (crate `api-sec-sensor`, lib `api_sec_sensor`). It lives at `userspace/target/release/api-sec-sensor`.

## Test, lint, format

All cargo commands run from `userspace/`. CI (`.github/workflows/ci.yml`) gates on fmt + clippy-as-errors + tests, so match it locally:

```bash
cd userspace
cargo fmt --check                       # CI fails on any diff
cargo clippy --release -- -D warnings   # warnings are errors in CI
cargo test --release                    # unit tests (inline #[cfg(test)] mods) + integration_test
cargo test --release --test adversarial # malformed-input / parser-hardening suite
cargo test --release test_grpc_protobuf_decode   # run a single test by name
```

Unit tests live in `#[cfg(test)] mod tests` blocks inside each `src/*.rs` module. `tests/adversarial.rs` exercises parsers against malformed/oversized input (it imports from the `api_sec_sensor` lib, so any function it tests must be `pub` and re-exported in `lib.rs`). Fuzz targets are under `userspace/fuzz/fuzz_targets/` (run with `cargo +nightly fuzz run <target>`).

The `userspace/tests/integration_test.rs` suite is gated behind env vars and does nothing without them: `SENSOR_INTEGRATION=1` runs service-level checks against the docker-compose test stack; adding `SENSOR_RUNNING=1` (plus a root-run sensor) enables full TLS-capture assertions. See the doc comment at the top of that file for the exact invocation.

Protocol end-to-end tests run via Docker against real test servers (Go, Node, Python, WebSocket, MCP, gRPC, QUIC, GnuTLS): `./tests/run_protocol_tests.sh` (or `.ps1` on Windows). These build the sensor image and spin up `tests/docker-compose.yml`.

## Running locally

Requires root (or `CAP_BPF`/`CAP_PERFMON`). `run-sensor.sh` is a convenience wrapper; the raw form:

```bash
sudo ./userspace/target/release/api-sec-sensor \
  --bpf ./bpf/http_trace.bpf.o \
  --ingest https://api.example.com/v1/events \
  --api-key <token> --account-id 1000000 --role server \
  --discover-libs
```

Config can also come from a TOML file (`--config`, default `/etc/api-sentinel/config.toml`); CLI flags override file values, and `API_KEY` env overrides both (see `config/config.example.toml`). `--go-tls --pid <pid>` enables Go TLS interception for one process.

## Architecture

### Data flow (kernel → cloud)

```
BPF uprobes/kprobes → ring buffer → RingBuffer callback (main.rs)
  → ShardedStreamState::handle_event → per-protocol parse + PII redaction
  → mpsc channel (cap 10000) → batch task → gzip → POST to ingest
```

1. **`bpf/http_trace.bpf.c`** — the only kernel file. Defines `struct tls_event` (the ring-buffer wire format: pid/tid, ssl_ptr, direction, IPs/ports, cgroup_id, comm, and up to 32KB of decrypted `data`). Attaches uprobes to TLS read/write functions and kprobes to `connect`/`accept` for connection tuple tracking. **`struct tls_event` here must stay byte-compatible with the Rust `RawEventHeader`/parsing in `bpf.rs` + `types.rs`** — changing one without the other corrupts every event.

2. **`main.rs`** (~760 lines, the orchestrator) — parses args/config, attaches all probe families (`attach_tls_uprobes`, `attach_kernel_probes`, `attach_quic_uprobes`, `attach_boring_ssl_static`, `attach_go_tls_probes`), spins up the metrics server, the container-metadata resolver task, the reverse-DNS task, and the batch/flush task, then drives the libbpf `RingBuffer` poll loop. A background task watches for new PIDs to dynamically attach probes to processes that start after the sensor.

3. **`stream.rs`** (~970 lines, the core) — `ShardedStreamState` shards per-connection `StreamState` across N mutexes keyed by `hash(pid, ssl_ptr)` to avoid lock contention. Reassembles read/write byte streams per connection, detects the protocol, dispatches to the right parser, pairs requests with responses (including HTTP/2 stream multiplexing), enriches with container/DNS metadata, and emits `ApiTrafficEvent`s. Enforces per-connection (`max_buffer_bytes`) and global (`max_total_buffer_bytes`) memory ceilings.

### Protocol parsers (one module each, all `pub` via `lib.rs`)

`http.rs` (HTTP/1.1), `http2.rs` (HTTP/2 frames + built-in HPACK decoder), `grpc.rs` (protobuf field decode over HTTP/2), `websocket.rs` (frame/opcode parsing), `mcp.rs` (MCP/SSE JSON-RPC, tool-call extraction), `quic.rs` (QUIC/HTTP3). Protocol detection lives in `stream.rs` (e.g. HTTP/2 client-preface sniff, `content-type` checks).

### Cross-cutting modules

- **`redaction.rs`** — regex-based PII detection + redaction (email, SSN, Luhn-validated credit cards, phone, JWT, bearer tokens, private keys, AWS/GCP keys, Indian PAN/Aadhaar). Applied to query params, headers, and body before events leave the process. Also computes injection flags (SQLi/XSS/path-traversal) and the `anomaly_features` ML feature vector.
- **`types.rs`** — `ApiTrafficEvent`, `EventBatch`, `TrafficRole`, the raw BPF event header, and `NUM_SHARDS`. The serialized shape here is the ingest API contract.
- **`ingest.rs`** — batching, gzip (only when payload >4KB), retry with a circuit breaker (opens after consecutive failures, tracked in atomics).
- **`bpf.rs`** — libbpf-rs probe attachment helpers and raw-event decoding.
- **`go_tls.rs` / `boringssl.rs`** — locate TLS functions in stripped/static binaries by scanning ELF symbols and (for Go return probes) disassembling with Capstone to find every `RET` offset. This is the trickiest code in the repo; the README "Go TLS" section documents the 6-step address-resolution dance.
- **`container.rs`** — resolves cgroup_id/netns → Kubernetes container metadata via the CRI socket. **`dns.rs`** — async reverse DNS with an LRU cache. **`metrics.rs`** — Prometheus counters/gauges (global statics) + the axum `/metrics`, `/healthz`, `/readyz` server. **`config.rs`** — TOML + CLI + env merge.

## Conventions and gotchas

- **lib vs. bin duality:** `main.rs` declares modules with `mod` for the binary; `lib.rs` re-exports a subset with `pub mod` for external tests/fuzzers. If you add a parser and want it tested from `tests/adversarial.rs` or fuzzed, export it in `lib.rs` and keep the tested functions `pub`.
- **Metrics are global statics** (`metrics.rs`) incremented from anywhere via `crate::metrics::*` — no need to thread a handle through.
- **The BPF struct is a hard contract.** Treat `struct tls_event` in the C file and its Rust counterpart as a single unit; `MAX_DATA` (32768) is the per-event payload cap.
- **CI's `build-bpf` job is `continue-on-error: true`** — BPF compilation is best-effort on GitHub runners (kernel BTF may be absent). The Docker build (`Dockerfile`) is the authoritative BPF build check.
- New protocol/library support follows existing patterns by design — see `docs/superpowers/plans/2026-03-22-protocol-expansion.md` for the NSS/rustls/plaintext-TCP expansion plan and which existing module each new one mirrors.

## Deployment

Production runs as a Kubernetes DaemonSet (one pod per node) via the Helm chart in `deploy/helm/api-sentinel-sensor/`. It uses `hostPID: true` and granular capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`) rather than `privileged: true`, and mounts `/sys/kernel/debug`, `/sys/fs/bpf`, `/sys/fs/cgroup`. The multi-stage `Dockerfile` compiles BPF → Rust → minimal runtime; `Dockerfile.verify` is the build+verification image and `Dockerfile.fast` is a quicker iteration variant. Full deploy steps are in the README.
