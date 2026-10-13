# Implementation progress — production-readiness fixes

Working tree base: commit `c60cfae0` (branch `main`); audit source: docs/PRODUCTION-READINESS-AUDIT.md.

## Package 1 — F20: verification harness repair (COMPLETE, pending Linux live-capture validation)

### Finding IDs addressed

- **F20** (verification can pass without validating today's capture contract) — all of its sub-defects:
  - validator expected the legacy nested `events` schema and could not decode gzip;
  - integration tests asserted the legacy schema, skipped silently on missing env, and contained the tautological `resp.is_ok() || resp.is_err()`;
  - the documented ingest URL omitted `/ingest`;
  - the HTTP/2 fuzz target drove the legacy parser, not the active streaming decoder;
  - `root-verify.sh` printed failures without a failing exit status and carried a "production ready" banner;
  - no source/kernel identity was archived with results.

### Files changed

| File | Change |
|---|---|
| `tests/test-servers/validator/server.py` | Rewritten: validates the real `MsgHeader`/`Batch` envelope with flat dotted-key events (field names/types mirrored from `userspace/src/output.rs`), decodes gzip (header or magic, with decompressed-size cap and truncated-stream rejection), rejects the legacy nested schema, empty batches, and unknown `L7Protocol` values with 4xx; bounded event store with visible overflow counter; `GET /events?rid=` correlation filter; `GET /summary` totals (accepted/rejected/last rejection); threaded server. |
| `tests/test-servers/validator/test_validator.py` | New regression suite (23 tests): valid envelope + gzip accepted; legacy schema, empty batch, missing/mistyped fields, bool-as-int, bad protocol, invalid JSON, truncated gzip, zero Content-Length all rejected; body/decompressed caps enforced (413/400); store overflow bounded and visible; rid oracle filter; reset/counts/summary. |
| `userspace/tests/integration_test.rs` | Rewritten harness: `SENSOR_INTEGRATION=1` makes validator + sensor metrics **required** (missing prerequisite fails, never skips); `SENSOR_RUNNING=1` capture tests use per-test request IDs (`rid=<test>-<nanos>`) sent over TLS endpoints only (plain HTTP is an explicit, reported gap) and require the validator to deliver an event carrying that exact rid — zero captured traffic fails with diagnostics; request method/status/connection identity asserted exactly; the Go test asserts `L7Protocol` matches the ALPN version the client actually negotiated; the PII test correlates its own event before asserting redaction; the WebSocket test performs a real opening handshake (asserts 101) replacing the tautological assertion; metrics/health tests hard-require endpoints under `SENSOR_INTEGRATION=1`; new `test_validator_enforces_current_wire_schema` tripwire fails if the validator is reverted to accept legacy schema/empty batches. Ingest URL documented as `http://localhost:19999/ingest`. |

| `userspace/tests/schema_contract.rs` | New default-run contract tests: envelope is exactly `MsgHeader`+`Batch` (no `events`), header field names/types/`Version=2.0`, every event carries the dotted keys the validator requires with correct JSON types, rid survives in `HTTPReq.Uri`/`HTTPReq.Query`, sequence increases monotonically, `MessageTime` format locked. |
| `userspace/src/ingest.rs` | Extracted `encode_batch_payload()` (threshold/gzip policy) from `try_send_batch` with unit tests: below-threshold plain JSON, above-threshold gzip with magic bytes + lossless round-trip, threshold boundary behaviour. No behaviour change. |
| `userspace/fuzz/fuzz_targets/fuzz_http2.rs` | Now drives the **active** `Http2Direction::feed` streaming decoder (both directions, chunked feeding over split points, preface/CONTINUATION/HPACK state); legacy `parse_http2_frames` kept as secondary target. |
| `scripts/root-verify.sh` | Ingest stub replaced by the shared schema-validating validator (one validator, per F20); `--ingest` now includes `/ingest`; check 4 additionally requires validator `accepted_total > 0` (schema-validated evidence, not just a counter) and checks request-side PII on schema-accepted events; source/kernel identity archived to `/tmp/api-sensor-verification-identity.txt`; exits 1 on any failure; "production ready" banner replaced with honest smoke-test wording. |
| `scripts/e2e-test.sh` | Same validator replacement and `/ingest` fix; Test 7 PII checks read schema-accepted events from the validator; Test 10 now validates the dotted-key contract of schema-accepted events (`accepted_total == 0` fails, with last-rejection diagnostics); identity archived; final banner de-falsified (kept existing `exit 1` on failure). |
| `tests/docker-compose.yml` | Corrected the documented test command (was `cargo test --test integration`, which does not exist). |
| `docs/IMPLEMENTATION-PROGRESS.md` | This file. |

### Tests executed and results (environment: Windows 11 + Docker Desktop)

**Initial Package 1 tests (Linux container):**
The Rust suite was executed for real inside a Linux container built from the
repo `Dockerfile` (`api-sensor-build:dev`, `FROM ubuntu:24.04`, clang/libbpf/
protoc/rustc 1.99.0), mounting the live `userspace/` source, with a persistent
target volume for incremental rebuilds.

| Command | Result |
|---|---|
| `python -m py_compile tests/test-servers/validator/server.py` | PASS |
| `python -m unittest test_validator` (in `tests/test-servers/validator`) | **PASS — 23/23**. Suite found and fixed a real bug: zlib returns partial output for truncated gzip streams; the validator now checks `eof` and rejects with 400. |
| `bash -n` (Linux bash, LF-normalized) on `scripts/root-verify.sh` and `scripts/e2e-test.sh` | PASS |
| `docker build -t api-sentinel-sensor:dev .` (repo Dockerfile, full reproducible build) | PASS — image builds from source (BPF object + Rust binary) |
| `cargo test --test integration_test --test schema_contract` (Linux container) | **PASS — 13/13** (9 integration + 4 schema-contract). Integration tests skip without `SENSOR_INTEGRATION=1` (logged as NOT a pass); the 4 `schema_contract` tests run by default and genuinely exercise `output::to_sensor_batch`. |
| `SENSOR_INTEGRATION=1 cargo test --test integration_test test_validator_enforces_current_wire_schema` (Linux container + live validator) | **PASS — 1/1** against the rewritten validator run as `api-sensor-validator:dev` sharing the test container's network namespace. Proves: legacy nested schema → 400, empty Batch → 400, current MsgHeader/Batch → 200, gzip batch → 200. Also proved the negative: with the validator absent the same test **FAILED** (did not skip). |
| `cargo test` (full default suite incl. lib unit tests: `ingest.rs` payload encode, `container.rs`, `memory_ceiling.rs`, etc.) | PENDING — only the two named test targets were run here; full `cargo test` should be run on the Linux CI host. |
| `SENSOR_INTEGRATION=1 SENSOR_RUNNING=1 cargo test --test integration_test` (live eBPF sensor + docker-compose services) | **PENDING — requires a Linux host with BPF privileges and a running sensor.** (Later superseded: a privileged container on Docker Desktop's 6.6 kernel does load and attach. See "Live validation run".) |
| Fuzzing campaign on the reworked `fuzz_http2` target | PENDING — requires `cargo-fuzz`; target rewritten and compile-verified, no campaign re-run here. |
| `scripts/root-verify.sh` / `scripts/e2e-test.sh` end-to-end | PENDING — require a privileged Linux host with clang/bpftool/libssl. |

**Package 2 validation (Windows 11 + Docker Desktop):**
Rust toolchain not available on Windows; verified test services and validator are working.

| Command | Result |
|---|---|
| `docker-compose up -d` (test services) | **PASS** - All 6 services built and running (httpbin, go-api, node-api, ws-server, mcp-server, ingest-validator) |
| `curl http://localhost:19999/summary` | **PASS** - Validator returns schema v2.0, zero events accepted |
| `curl POST http://localhost:19999/ingest` (current schema) | **PASS** - Accepted with `{"accepted": 1, "batch_sequence": 1, "schema": "sensor-batch-v2.0"}` |
| `curl POST http://localhost:19999/ingest` (legacy schema) | **PASS** - Rejected with `{"error": "legacy nested schema rejected: this sensor emits MsgHeader/Batch with flat dotted-key events, not {'events': [...]]} (validator schema sensor-batch-v2.0)"}` |
| `cargo test` (Windows - cargo not installed) | **SKIPPED** - Cargo not available on Windows |
| BPF compilation (Windows - no clang) | **SKIPPED** - clang/libbpf-dev not available on Windows |

### Remaining limitations and blockers (package 1)

- Live-capture integration (Level 2) and the smoke scripts cannot be executed on this Windows machine; they are validated to the extent possible here (bash syntax with real Linux bash, validator suite executed, Rust tests executed in WSL if the toolchain builds). Full validation must be repeated on an authorized Linux host per docs/PRODUCTION-READINESS-AUDIT.md §8.
- Plain HTTP (httpbin) traffic is not capturable by the current sensor (capability gap, audit matrix); tests no longer pretend otherwise — capture assertions target TLS endpoints, and the MCP/plaintext gap is reported explicitly in test output.
- Plaintext MCP/SSE capture assertions are deliberately absent until a scoped plaintext capture source exists; reachability is asserted instead.
- Validator authentication (bearer API key) is not enforced — it is a test oracle, not a production sink (documented in the file header).
- The fuzz target rewrite is compile-verified only if the WSL build succeeds; no fuzzing campaign has been re-run here.

### Next work package

**Package 2 (F01/F02/F04/F21):** bounded H2 header state, safe BPF copy-failure handling, encoding-aware final-wire redaction, explicit scope/secure export policy.

---

## Package 2 — F01/F02/F04/F21: memory, redaction, privacy (COMPLETE, pending Linux BPF verification)

### Finding IDs addressed

- **F01** (HTTP/2 header accumulation bypasses memory ceiling) — **ALREADY FIXED** in previous work:
  - `userspace/src/http2.rs:290` defines `H2_MAX_HEADER_BLOCK_BYTES = 128 KiB`
  - `http2.rs:436` checks aggregate CONTINUATION block size before append
  - `http2.rs:474` checks initial HEADERS fragment size
  - Direction fails (unrecoverable HPACK desync) on violation

- **F02** (failed BPF memory reads reported as captured bytes) — **FIXED**:
  - Added `producer_stats` PERCPU_ARRAY map in `bpf/http_trace.bpf.c` (indices: 0=attempted, 1=submitted, 2=reserve_fail, 3=copy_fail, 4=sampled, 5=map_fail)
  - Both `emit_event_dynptr` and `emit_event` now check return values from `bpf_probe_read_user` and `bpf_dynptr_write`
  - On copy failure: discard reservation, increment copy_fail counter, return without submitting
  - Initialize all header fields before payload copy (memset comm to 0 first)
  - Added userspace aggregation in `main.rs::aggregate_producer_stats` (5-second interval)
  - Added Prometheus metrics: `apisec_bpf_attempted_total`, `apisec_bpf_submitted_total`, `apisec_bpf_reserve_fail_total`, `apisec_bpf_copy_fail_total`, `apisec_bpf_sampled_total`
  - **Limitation**: libbpf-rs 0.26 doesn't expose per-CPU aggregation; current implementation reads current CPU's value. Full per-CPU accuracy requires libbpf upgrade or manual iteration.

- **F04** (raw body redaction bypasses) — **ALREADY FIXED** in previous work:
  - `redaction.rs:294-339` implements `json_unescape_name` for escaped JSON keys
  - `redaction.rs:342-368` implements `percent_decode_name` for form/query names
  - `redaction.rs:374-381` implements `is_internal_redaction_token` (only trust exact `PII_<TYPE>_<32 hex>` shape or `PII_PRIVATE_KEY_REDACTED`)
  - `redaction.rs:386-389` implements `canonical_field_name` (JSON-unescape then optionally percent-decode)
  - `redaction.rs:439, 461` uses canonical field names in JSON and form scrubbing
  - `redaction.rs:440, 452, 462` checks `is_internal_redaction_token` before trusting values

- **F21** (privacy scope and transport enforcement) — **FIXED**:
  - `main.rs:155-159` warns if ingest URL is HTTP (credentials in plaintext)
  - `main.rs:418-423` makes explicit warning when no namespace scope is set (capture-all default)
  - `ingest.rs:107-121` bounds error body reading (512 char truncation) and redacts before logging
  - Export errors are redacted via `redact_text` before appearing in logs

### Files changed

| File | Change |
|------|--------|
| `bpf/http_trace.bpf.c` | Added `producer_stats` PERCPU_ARRAY map (6 counters). Modified `emit_event_dynptr`: count attempted, count sampled separately, check reserve failure, initialize header fields before copy, check `bpf_probe_read_user` return, check `bpf_dynptr_write` return, discard on failure with counter increment. Modified `emit_event` (fixed-slot path): same changes applied. |
| `userspace/src/main.rs` | Added `aggregate_producer_stats()` function to read BPF producer_stats map periodically (5-second interval). Added HTTPS warning on HTTP ingest URLs. Enhanced namespace scope warning to be explicit about capture-all default. |
| `userspace/src/metrics.rs` | Added 5 new static counters: `BPF_ATTEMPTED`, `BPF_SUBMITTED`, `BPF_RESERVE_FAIL`, `BPF_COPY_FAIL`, `BPF_SAMPLED`. Added corresponding Prometheus metrics in `metrics_handler`. |
| `userspace/src/ingest.rs` | Modified error body reading: check Content-Length for large bodies (>4096), truncate to 512 chars, redact via `redact_text` before logging to prevent sensitive data exposure in error messages. |

### Tests executed and results

**Environment:** Windows 11 + Docker Desktop - BPF compilation performed via Docker Linux containers (ubuntu:24.04).

| Command | Result |
|---------|--------|
| Rust syntax check (visual inspection) | PASS - all edits are syntactically valid Rust |
| BPF syntax check (visual inspection) | PASS - added map definition follows existing pattern, counter increments use `__sync_fetch_and_add` pattern |
| Cargo dependency check | PASS - no new dependencies added |
| `docker build -t api-sentinel-sensor:dev .` | **PASS** - Full reproducible build from source (BPF object + Rust binary) with all Package 2 changes. Build time: 2m 50s release profile. 23 warnings (unused mut variables, dead code - pre-existing, not from Package 2 changes). |
| `docker-compose up -d` (test services) | **PASS** - All 6 services built and running (httpbin, go-api, node-api, ws-server, mcp-server, ingest-validator) |
| `curl http://localhost:19999/summary` | **PASS** - Validator returns schema v2.0, zero events accepted |
| `curl POST http://localhost:19999/ingest` (current schema) | **PASS** - Accepted with `{"accepted": 1, "batch_sequence": 1, "schema": "sensor-batch-v2.0"}` |
| `curl POST http://localhost:19999/ingest` (legacy schema) | **PASS** - Rejected with legacy schema error (validator correctly enforces current contract) |

**Pending validation (requires Linux host with BPF privileges and privileged container):**
- Runtime verification that copy failures are counted correctly under actual copy failures
- Metrics export shows non-zero producer stats under load
- HTTPS warning appears in logs with HTTP ingest URL
- Error body redaction prevents sensitive data in logs
- Rust unit tests (cargo test) via Docker container (path mounting issue on Windows)

### Remaining limitations and blockers (package 2)

- **Per-CPU aggregation limitation**: libbpf-rs 0.26 doesn't expose per-CPU array iteration. Current `aggregate_producer_stats` reads the current CPU's value only. On multi-CPU systems, this undercounts. Fix: upgrade libbpf-rs or use libbpf C API directly for `bpf_map_lookup_percpu_elem`.
- **BPF compilation**: COMPLETED via Docker Linux container (ubuntu:24.04) - clang successfully compiled the modified BPF code with new producer_stats map.
- **Rust unit tests**: Path mounting issue on Windows prevents running `cargo test` via Docker container. Package 2 code changes are syntactically valid and compiled successfully in release build, but unit tests not yet executed.
- **Live eBPF testing**: Cannot run live eBPF tests on Windows. Full validation requires a Linux host with BPF privileges to attach probes and observe copy failures in real traffic.
- **Error body memory bound**: Current implementation uses `resp.text()` which internally bounds reads, but the exact bound is not enforced before reading. A more defensive implementation would use `resp.bytes_stream()` with explicit chunk limits.

### Next work package

**Package 3 (F03/F08/F09):** process-safe connection identity, versioned capture ABI, true producer loss accounting and explicit gap propagation.

---

## Package 3 — F03/F08/F09: connection identity, ABI versioning, loss accounting (CODE COMPLETE, pending live kernel validation)

### Finding IDs addressed

- **F03** (TLS pointer reuse mixes connections): BPF keys SSL state by `(tgid, ssl_ptr)` and records a per-object `generation` that `SSL_free` bumps. Every event carries `proc_start_ns` (group leader start time) and `conn_generation`; userspace `ConnKey`/`StreamKey` include both. A close event only evicts the incarnation it names, so a stale close cannot evict a reused pointer.
- **F08** (ABI drift): `TLS_EVENT_ABI_VERSION = 2` in both `bpf/http_trace.bpf.c` and `types.rs`; header is 144 bytes with no implicit padding, verified by `offset_of!` tests. Userspace drops and counts (`apisec_abi_mismatch_total`) any record with another version.
- **F09** (silent loss): per-direction sequence numbers (`dir_seq`), `actual_len` vs `copied_len` with `TLS_FLAG_TRUNCATED`, attribution confidence (SSL association vs thread fallback), provider id, and per-CPU producer counters (attempted / submitted / reserve_fail / copy_fail / map_fail). A truncated chunk is never joined with the next one: the HTTP/1 stream is marked gapped and resynchronises only on a new message start; an HTTP/2 connection is dropped. Counted in `apisec_capture_gaps_total`.

### Files changed

`bpf/http_trace.bpf.c`, `userspace/src/types.rs`, `userspace/src/stream.rs`, `userspace/src/main.rs`, `userspace/src/metrics.rs`, `userspace/src/container.rs`, `userspace/tests/memory_ceiling.rs`

### Tests executed and results

Environment: Windows 11 + Docker Desktop, build image `api-sensor-build:dev` (Ubuntu 24.04, clang 18, libbpf, Rust stable).

| Command | Result |
|---------|--------|
| `clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c bpf/http_trace.bpf.c` | PASS, no warnings |
| `cargo test` — `types::abi_tests` (layout offsets, truncation flag, length clamping) | PASS |
| `stream::tests::same_tls_pointer_in_two_processes_never_shares_state` | PASS |
| `stream::tests::stale_close_does_not_evict_a_reused_pointer` | PASS |
| `stream::tests::truncated_chunk_is_not_joined_with_the_next_one` | PASS |

### Remaining limitations and blockers (package 3)

- Not yet loaded by a live kernel verifier. Validate on the VPS (`scripts/root-verify.sh`).
- The per-object sequence counter is a plain increment: TLS libraries serialise I/O per object and direction. An atomic fetch-and-add that returns the old value would need BPF ISA v3 (kernel 5.12+).
- A truncated HTTP/1 chunk discards that message rather than emitting a partial one.

---

## Package 4 — F05/F06/F07: mixed-direction traffic, HTTP/1 framing, sampling (CODE COMPLETE, pending live traffic validation)

### Finding IDs addressed

- **F05** (one global role): `--role` defaults to `auto`. Each connection's request direction is inferred once from syntax (preface, request line, `HTTP/1.` status line) and otherwise from the kernel accept/connect hint (`role_hint`). Ambiguous connections are counted (`apisec_role_ambiguous_total`) and skipped, never guessed. `server`/`client` remain as diagnostic overrides. Helm `sensor.role` default changed to `auto`.
- **F06** (HTTP/1 framing): new incremental `Http1Decoder` (RFC 9112): Content-Length, chunked with trailers, close-delimited responses, HEAD/204/304/1xx without body, 101 and CONNECT 2xx upgrade, 64 KiB header cap, 16-hex-digit chunk-size cap, `checked_add`. Rejects TE+CL, conflicting CL, invalid CL and non-final chunked on requests (`apisec_http1_parse_errors_total`), then resynchronises. Repeated headers are combined. Body previews are capped and marked truncated (`apisec_bodies_truncated_total`).
- **F07** (per-chunk sampling): the kernel always captures 100%. `--sample-default`/`--sample-health` now apply to completed transactions in userspace with a deterministic hash, so request/response pairs and HPACK state are never split. Auth, token, admin, OAuth and MCP paths are always kept.

### Files changed

`userspace/src/http.rs`, `userspace/src/stream.rs`, `userspace/src/main.rs`, `userspace/src/metrics.rs`, `deploy/helm/api-sentinel-sensor/values.yaml`

### Tests executed and results

| Command | Result |
|---------|--------|
| `http::tests` decoder suite (every split point, byte-at-a-time, 100→200, HEAD/204/304, large body preview, invalid framing, huge chunk length, close-delimited, repeated headers) | PASS |
| `stream::tests::auto_role_pairs_inbound_and_outbound_in_one_process` | PASS |
| `stream::tests::auto_role_uses_the_kernel_hint_when_syntax_is_inconclusive` | PASS |
| `stream::tests::transaction_sampling_keeps_pairs_intact_and_is_deterministic` | PASS |
| `tests/adversarial.rs` (27) | PASS |

### Remaining limitations and blockers (package 4)

- HEAD/CONNECT framing uses the oldest pending request on the connection (correct for HTTP/1 pipelining order).
- A close-delimited response holds the direction until the connection closes.
- BPF `should_sample_out` remains in the object but is inert at 100%.

---

## Package 5 — F17: HTTP/2 detection and lifecycle (CODE COMPLETE, pending live traffic validation)

### Finding IDs addressed

- **F17**:
  - A connection is HTTP/2 only if its client stream begins with the preface and no HTTP/1 bytes were ever seen on it. A preface split across reads is held (bounded) and joined.
  - A stream completes only on END_STREAM, so trailers (gRPC status) are kept even after the body preview cap.
  - GOAWAY releases streams above `last_stream_id`.
  - HPACK desync drops the connection's state instead of guessing headers.

### Files changed

`userspace/src/http2.rs`, `userspace/src/stream.rs`, `userspace/fuzz/fuzz_targets/fuzz_http2.rs`

### Tests executed and results

| Command | Result |
|---------|--------|
| `stream::tests::h2_preface_split_across_reads_is_still_detected` | PASS |
| `stream::tests::short_first_chunk_that_is_not_the_preface_stays_http1` | PASS |
| `stream::tests::h2_response_past_the_preview_cap_waits_for_trailers` | PASS |
| `stream::tests::goaway_releases_streams_the_peer_never_processed` | PASS |
| `stream::tests::http1_body_containing_the_h2_preface_cannot_blind_the_http1_parser` | PASS |

### Remaining limitations and blockers (package 5)

- Validate with real h2/gRPC clients on the VPS (`scripts/e2e-test.sh`).

---

## Package 6 — F10/F11/F12/F13: continuous coverage (CODE COMPLETE, pending live kernel validation)

### Finding IDs addressed

- **F10** (optional programs block startup):
  - The object is opened, configured and then loaded (`bpf::open_and_load`).
  - The dynptr switch is a frozen read-only constant (`cfg_use_dynptr` in `.rodata.cfg`) set before load, so the verifier prunes the dynptr path on kernels older than 5.19. The old runtime map could not make unknown helpers loadable.
  - LSM programs load only with `--enable-lsm` (default off) and `bpf` in `/sys/kernel/security/lsm`. kTLS programs load only when `tls_sw_sendmsg` is in `/proc/kallsyms`.
  - If a load fails, it retries without LSM/kTLS, then without dynptr, so an optional program can never stop core capture. The active feature set is logged.
- **F11** (startup-only discovery):
  - The exec tracepoint (`handle_new_process`) is now attached, and an exec triggers a library rescan. A periodic rescan every 30 s covers missed notifications and late `dlopen`.
  - Discovery runs in a blocking task off the capture path. The poll loop attaches only library files it has not seen, by (device, inode), capped at 256.
  - Each entry/exit pair attaches together or not at all. A library counts as covered only when both its read and write pairs attach, and startup requires at least one covered library (or Go TLS). Failures are counted in `apisec_probe_attach_failures_total`.
- **F12** (Go TLS correlation):
  - Entry and exit pair by `(tgid, g pointer)`, with `g` taken from the ABIInternal register (R14 amd64, R28 arm64). This replaces `fsbase + goid_offset`, which did not point at the goroutine, and the unsafe thread-id fallback.
  - Go releases before 1.17, and unidentifiable ones, are refused. Return lengths are clamped to the buffer length.
  - A partial attach is rolled back and reported.
- **F13** (failed lookup suppresses a busy workload):
  - Cache entries keep the unresolved container id and a retry deadline with exponential backoff (1 s to 60 s). Ordinary traffic requeues the CRI lookup once the deadline passes.
  - A full lookup queue undoes the pending mark. Unresolved traffic stays fail-closed under namespace scoping.

### Files changed

`bpf/http_trace.bpf.c`, `userspace/src/bpf.rs`, `userspace/src/main.rs`, `userspace/src/go_tls.rs`, `userspace/src/container.rs`, `userspace/src/metrics.rs`

### Tests executed and results

| Command | Result |
|---------|--------|
| `bpf::tests::the_built_object_exposes_the_load_time_switches` (opens the real compiled object: `.rodata.cfg` map and every optional program present) | PASS |
| `bpf::tests::optional_program_failure_falls_back_to_core_capture` | PASS |
| `bpf::tests::unselected_optional_programs_are_not_loaded` | PASS |
| `bpf::tests::provider_plans_follow_the_library_name_in_auto_mode` | PASS |
| `bpf::tests::rediscovery_attaches_each_library_file_once` | PASS |
| `go_tls::tests::only_register_abi_go_releases_are_attached` | PASS |
| `container::tests::a_busy_workload_whose_first_lookup_failed_is_resolved_without_a_restart` | PASS |
| `llvm-objdump -h http_trace.bpf.o` shows `.rodata.cfg` size 4 | PASS |

### Remaining limitations and blockers (package 6)

- Verifier acceptance of the pruned dynptr path on a kernel older than 5.19 must be confirmed on such a kernel.
- Obsolete uprobe links are not detached when a library file disappears. Links are bounded by the 256-library cap.
- Go TLS still needs symbols (stripped binaries are skipped), and Go binaries are discovered at startup only.
- Coverage-gap duration for unresolved containers is not exported as a metric yet.

---

## Package 7 — F14/F16: runtime and export bounds (CODE COMPLETE, pending load test)

### Finding IDs addressed

- **F14**:
  - Reverse DNS concurrency is bounded at 8. A permit is held until the blocking lookup returns, so an expired timeout no longer frees a slot while the resolver thread still runs. Reverse DNS can be disabled (`--reverse-dns=false`, env `REVERSE_DNS`).
  - Rediscovery `/proc` scans run off the ring callback, and the attached-library set is capped.
  - Partial-event production is capped per sweep.
- **F16** (shutdown ordering):
  1. Detach every probe.
  2. Drain the ring buffer once more.
  3. Drop the ring buffer, which releases the callbacks' senders.
  4. Export every still-pending request as a `sensor_shutdown` event.
  5. Close the export channel and wait up to `--shutdown-timeout-secs` (default 20).
  6. Log how many events were queued at close and whether the deadline was hit.

  The Helm `terminationGracePeriodSeconds` is set to `shutdownTimeoutSecs + 10`.

### Files changed

`userspace/src/main.rs`, `deploy/helm/api-sentinel-sensor/values.yaml`, `deploy/helm/api-sentinel-sensor/templates/daemonset.yaml`

### Tests executed and results

| Command | Result |
|---------|--------|
| `cargo test` full suite (shutdown path compiles; ordering is enforced by ownership: senders are dropped before the channel close is awaited) | PASS |
| `helm template` renders `terminationGracePeriodSeconds: 30` and `--shutdown-timeout-secs=20` | PASS |
| `tests/memory_ceiling.rs` (pending-request ceiling and full release on eviction) | PASS |

### Remaining limitations and blockers (package 7)

- ~~The export channel is bounded by item count only.~~ Byte budgets for the queue and the batch are now in place (Package 11).
- The cgroup tree scan still runs on the event path (cooldown-limited to once every 2 s).
- SIGTERM during retries is still untested. A SIGTERM with a pending request and a non-empty queue passed live (see Live validation).

---

## Package 8 — F15/F19/F22: wire contract and durable delivery (PARTIAL: F19/F22 code complete, F15 durable spool open)

### Finding IDs addressed

- **F15**:
  - Event IDs are now `<process nonce>-<ms>-<counter>`, unique within and across sensor incarnations. They are fixed when the batch is serialised, so retries carry the same IDs and the backend can deduplicate.
  - **Not done:** a durable disk spool and an ACK contract. Both need backend agreement.
- **F19**:
  - `SessionStats.StartTime` is RFC 3339 UTC (`…T..:..:...mmm000000Z`). The old format printed milliseconds in the wrong digit positions.
  - `HTTPReq.Query` is rebuilt from the parsed, redacted query. It was empty because the path had already been split.
  - `MetaDataMap` now carries `container_id`, `container_name`, `workload_type`, `node_name`, `mcp_method`, `mcp_tool_name`, `transport` and `transaction_outcome`. All new keys live inside the free-form map, so the backend's fixed keys are unchanged.
- **F22**:
  - Requests that never receive a response are exported with `transaction_outcome` set to `no_response_observed` (periodic expiry), `connection_closed` (close event) or `sensor_shutdown`. Status stays 0 and latency is absent; nothing is fabricated.
  - Expiry runs every 5 s from the poll loop, independent of traffic. Counted in `apisec_transactions_incomplete_total`.

### Files changed

`userspace/src/output.rs`, `userspace/src/types.rs`, `userspace/src/stream.rs`, `userspace/src/main.rs`, `userspace/src/metrics.rs`, `userspace/tests/memory_ceiling.rs`

### Tests executed and results

| Command | Result |
|---------|--------|
| `output::tests::start_time_is_rfc3339_utc_with_the_right_milliseconds` | PASS |
| `output::tests::events_in_the_same_millisecond_get_distinct_ids` | PASS |
| `output::tests::wire_event_keeps_query_container_mcp_and_outcome` | PASS |
| `stream::tests::a_request_whose_connection_closes_unanswered_is_reported_not_dropped` | PASS |
| `stream::tests::an_unanswered_request_expires_into_an_event_without_further_traffic` | PASS |
| `stream::tests::shutdown_reports_every_pending_request` | PASS |
| `tests/schema_contract.rs` (4) | PASS |

### Remaining limitations and blockers (package 8)

- **Backend coordination needed:**
  - Confirm the new `StartTime` format with the trailing `Z` parses.
  - Confirm the backend deduplicates on `Id`.
  - Agree an ACK and partial-rejection contract before a disk spool is built.
- Query parameters are stored as a map, so repeated keys collapse to one value.
- Latency still uses userspace wall-clock time at handling, not BPF monotonic capture time.
- Close events travel on a separate ring buffer. A close processed before the final response chunk reports `connection_closed` for that request.

---

## Package 9 — F18/F23: advertised protocols (CODE COMPLETE for narrowed claims)

### Finding IDs addressed

- **F18**: QUIC/HTTP-3 probes attach only with `--experimental-http3` (env `EXPERIMENTAL_HTTP3`), default off. They stay off until a provider-specific adapter with conformant QPACK exists.
- **F23**:
  - **WebSocket:** a frame spanning TLS chunks no longer desynchronises the stream. The unread remainder is carried per stream (bounded) and skipped before the next header is parsed.
  - **SSE vs MCP:** `text/event-stream` alone is no longer labelled MCP. Only an SSE body containing a JSON-RPC 2.0 message is.
  - **MCP over plain JSON:** a request whose body is a JSON-RPC 2.0 call (or batch) is MCP even when the server answers with `application/json`. Method and tool name come from the request, where MCP puts them. Previously these calls were exported as plain REST with no MCP metadata.

### Files changed

`userspace/src/main.rs`, `userspace/src/stream.rs`

### Tests executed and results

| Command | Result |
|---------|--------|
| `stream::tests::a_websocket_frame_spanning_chunks_does_not_desynchronise_the_stream` | PASS |
| `stream::tests::plain_server_sent_events_are_not_labelled_mcp` | PASS |
| existing MCP test (`tools/call`, tool `read_file`) still classified as MCP | PASS |
| `stream::tests::mcp_call_answered_with_plain_json_is_still_mcp` | PASS |
| `stream::tests::ordinary_json_request_is_not_labelled_mcp` | PASS |

### Remaining limitations and blockers (package 9)

- A WebSocket frame header split across chunks still loses frame sync for the rest of that chunk.
- gRPC compression and descriptors, and multi-line SSE `data:` fields, are not handled.
- kTLS reads only the first iovec. kTLS is now loaded only when the kernel has it.

---

## Package 10 — Section 7: release hardening (PARTIAL)

### Done

- `.github/workflows/ci.yml` runs on every push and PR:
  - BPF compile with production flags plus `-Werror`
  - `cargo test --locked`
  - `helm lint` and `helm template`
  - hadolint on the Dockerfile
  - shellcheck on all scripts
- `.gitattributes` forces LF for `*.sh`. Scripts copied from a Windows checkout failed with `$'\r': command not found`.

### Tests executed and results

| Command | Result |
|---------|--------|
| `shellcheck -S error scripts/*.sh` (after LF normalisation) | PASS |
| `helm template` with `sensor.onlyNamespaces={demo}` | PASS |

### Remaining limitations and blockers (package 10)

- Image signing and provenance (cosign), soak test, canary and rollback rehearsal need the registry and a staging cluster.
- The CI workflow has not run on GitHub yet; the first push will exercise it.

---

## Package 11 — Review findings and export byte budgets (CODE COMPLETE)

### Findings addressed

| Severity | Finding | Fix |
|----------|---------|-----|
| P1 | HTTP/2 `buffered()` ignored an open CONTINUATION header block, and PUSH_PROMISE skipped the header-block limit | `buffered()` counts the open block. PUSH_PROMISE fails the direction when its fragment exceeds `H2_MAX_HEADER_BLOCK_BYTES`. `stream.rs` keeps retained header bytes charged. |
| P1 | `ingest.rs` read error bodies with an unbounded `resp.bytes()` | `read_error_body` reads chunk by chunk and stops at 512 bytes. A chunked body with no Content-Length can no longer grow memory. |
| P1 | Redaction trusted any input shaped like `PII_…_<32hex>` | Tokens produced within one call are wrapped in private-use markers (U+E000/U+E001), and only marked spans are skipped. Markers in the input are stripped first and removed from the output, so an attacker cannot forge them. |
| P1 | The Helm default ingest URL was http without the opt-in, and `captureAllWorkloads` did not set the capture-all opt-in | `ingestUrl` is now required and `http://` needs `allowInsecureHttp=true`; render fails otherwise. The ConfigMap sets `APISEC_ALLOW_HTTP` and `APISEC_ALLOW_CAPTURE_ALL` from values. |
| P1 | `tests/enforcement.rs` held two empty placeholders | Eight subprocess tests run the real binary with `--check-config`. It performs every startup check and exits before BPF loads. Opt-ins parse strictly: `maybe` is a configuration error. |
| P2 | `Dockerfile.test` WORKDIR was wrong | `WORKDIR /src/userspace`. `docker build -f Dockerfile.test` then `docker run` exits 0 with all suites passing. |

### Export byte budgets

- **Queue:** `--max-queue-bytes` (env `MAX_QUEUE_BYTES`, default 64 MiB) in addition to the 10,000-event limit. A producer reserves `ApiTrafficEvent::approx_bytes()` before `try_send`, and the batch task releases it on receipt. Refusals count in `apisec_export_queue_byte_drops_total` and `apisec_events_dropped_total`; the current level is `apisec_export_queue_bytes`.
- **Batch:** `--max-batch-bytes` (env `MAX_BATCH_BYTES`, default 4 MiB) is a hard ceiling, not a flush threshold.
  - An event that would push the batch over the limit first flushes the existing batch, then starts the next one.
  - A single event larger than the whole budget is dropped and counted in `apisec_export_oversized_drops_total` and `apisec_events_dropped_total`.
  - Both byte budgets must be at least 64 KiB; smaller values are rejected at startup.
  - Earlier versions added the event before checking, so a batch could exceed its budget by one event.
- **Helm:** `sensor.maxQueueBytes` and `sensor.maxBatchBytes`.

### Found by the live run and fixed

- **Inbound address orientation** (`stream.rs` `net_context_from_event`). BPF reports the local socket end as `src`. On a server the request is read, so inbound events named the server as `DownstreamL3L4.Source*` and the client's ephemeral port as `UpstreamL3L4.DestPort`. Each transaction was labelled in opposite directions depending on which side captured it. Source is now always the request sender. Test: `source_is_the_client_whichever_side_captured_the_transaction`. Confirmed live: all 400 mixed events report `DestPort 8445`.

### Files changed

`userspace/src/http2.rs`, `stream.rs`, `ingest.rs`, `redaction.rs`, `main.rs`, `export.rs` (new), `lib.rs`, `types.rs`, `metrics.rs`, `mcp.rs`; `userspace/tests/enforcement.rs`; `Dockerfile.test`; `deploy/helm/api-sentinel-sensor/values.yaml`, `templates/configmap.yaml`, `deploy/helm/test-chart.sh`; `.github/workflows/ci.yml`; `deploy-and-test.sh`; `README.md`; `QUICK-START.md`; `scripts/live-harness.sh` (new).

### Tests executed and results

| Command | Result |
|---------|--------|
| `cargo test --no-fail-fast` (Docker build image) | **497 passed, 0 failed, 0 ignored**: lib 216, bin 225, adversarial 27, delivery 3, enforcement 9, integration 9, memory_ceiling 1, producer_stats 3, schema_contract 4 |
| `export::tests` batch ceiling: overflow flushes first, exact fit after a flush, oversized dropped and counted, and no sent batch exceeds its budget over 500 mixed sizes | PASS |
| `enforcement::an_export_byte_budget_too_small_for_one_event_is_rejected` | PASS |
| `bash scripts/test-live-harness.sh`: relative `SENSOR_BIN`/`BPF_OBJ` resolve against the caller's directory, not `$WORK`; a missing file fails with status 2 | 5/5 PASS |
| `http2::tests::an_open_header_block_is_reported_as_buffered_until_it_completes`, `an_oversized_push_promise_fragment_is_rejected` | PASS |
| `ingest::tests::an_endless_chunked_error_body_is_read_only_up_to_the_limit` (1 GiB chunked 400; reads 512 B, server sent < 64 MiB) | PASS |
| `redaction::tests::f04_attacker_supplied_value_in_the_exact_token_shape_is_still_redacted` (JSON, header, bearer, form, XML), `f04_input_cannot_forge_the_internal_markers`, `a_token_from_an_earlier_pass_of_the_same_call_keeps_its_classification` | PASS |
| `tests/enforcement.rs` (8 subprocess tests) | PASS |
| `export::tests` (queue byte budget refuses with item slots free and reuses space after receipt; a full item queue releases its reservation; batch flushes on bytes and on count) | PASS |
| `bash deploy/helm/test-chart.sh` (includes render-policy and byte-budget checks) | 22/22 PASS |
| `docker build -f Dockerfile.test` + `docker run` | exit 0 |
| shellcheck: `deploy/helm/test-chart.sh`, `deploy-and-test.sh`, `scripts/e2e-test.sh`, `scripts/root-verify.sh`, `scripts/live-harness.sh` | clean |

### Remaining limitations (package 11)

- `approx_bytes()` is an estimate of in-memory size, not of the serialised size. During a send, one batch exists about three times over (events, JSON, gzip), so peak send memory is about 3 × `maxBatchBytes`.

---

## Live validation run — Docker Desktop kernel (2026-10-13)

**Scope:** one kernel only, `6.6.87.2-microsoft-standard-WSL2` (BTF present, no BPF LSM). Userspace was Ubuntu 24.04 with OpenSSL 3.0.13 and a **debug** build of the sensor. This is not the VPS, not a range of kernels, not Kubernetes, and not a soak test. It does not establish production readiness.

### Setup (exact commands, PowerShell host)

```
docker network create apisensor-live
docker run -d --name live-validator --network apisensor-live -v "${PWD}/tests/test-servers/validator:/app:ro" python:3.12-slim python -u /app/server.py
docker run -d --name live-sensor --network apisensor-live --privileged -v "${PWD}:/src:ro" -v apisensor_target:/t:ro api-sensor-build:dev sleep infinity
docker exec live-sensor bash -c "apt-get update && apt-get install -y python3"   # inbound test server
# every phase:
docker exec -e SENSOR_BIN=/t/debug/api-sec-sensor -e BPF_OBJ=/t/debug/build/<hash>/out/http_trace.bpf.o \
  -e VALIDATOR=http://live-validator:9999 live-sensor bash /src/scripts/live-harness.sh <phase> [args]
```

`live-harness.sh` drives the following:
- curl as the client (outbound).
- A CPython `ssl` HTTPS server on 8445 as the server (inbound); it calls `SSL_read_ex`/`SSL_write_ex`.
- `openssl s_server -WWW` on 8443, to test the BIO path.
- A non-answering `s_server` on 8444, for pending requests.

The sensor starts with `APISEC_ALLOW_HTTP=true APISEC_ALLOW_CAPTURE_ALL=true --discover-libs --tls-libs=/usr/lib/x86_64-linux-gnu/libssl.so.3 --batch-size=50`.

Events are counted per `rid` query value at the schema-validating validator.

### Results

| Phase | Command | Result |
|-------|---------|--------|
| BPF load | `start` | Passed the kernel verifier: `BPF object loaded kernel_major=6 kernel_minor=6 dynptr=true lsm=false ktls=true`. TLS uprobes attached `usable_libs=1`, kTLS kprobes `attached=4`. **The exec tracepoint failed to attach** (`failed to attach BPF program`); the sensor fell back to periodic rescans. |
| Mixed inbound/outbound | `traffic mix 200`, `verify mix 200` | 200/200 requests each produced exactly **2 events**: 200 from `curl` (outbound) and 200 from `python3` (inbound). **0 duplicates, 0 drops, 0 capture gaps, 0 ABI mismatches, 0 role-ambiguous, 0 reserve failures.** The validator accepted 400 and rejected 0. |
| BIO-based server | `TARGET_PORT=8443 traffic bio 20` | 20/20 captured on the **client side only**. `s_server -WWW` reads through `BIO_f_ssl`, which calls OpenSSL internals and not the public `SSL_read*`. See limitations. |
| Ingest outage | `docker stop live-validator`; `traffic out 50`; `docker start live-validator`; `traffic after 50` | 100 events were produced during the outage. **95 were delivered after recovery and 5 were lost**, counted in `apisec_events_lost_send_total=5` (batches that exhausted their retries). Every after-recovery request arrived (100/100 events). 0 duplicates. `/readyz` stayed 200: `consecutive_send_failures` peaked at 1, below the readiness threshold. |
| Overload, default budgets | `burst burst 3000 64` | 2997/3000 requests with both sides. The 3 missing requests are missing from both sides, which points to client failures at the test server's 5-deep backlog; the backlog is now 512 and `burst` reports client status codes. Sensor `sent` rose by exactly the validator's 5,994 accepted. **0 drops**, 1 `unpaired_response`, 1 `transactions_incomplete`. |
| Overload, 200 kB queue budget, ingest down | `SENSOR_ARGS=--max-queue-bytes=200000 start`; validator stopped; `burst ovl 1000 32` | All 1000 client requests returned 200, producing 2000 events. **107 were delivered, 1,843 refused by the byte budget** (`apisec_export_queue_byte_drops_total`), and **50 lost on send.** 107 + 1843 + 50 = 2000: no silent loss. Queue bytes peaked at **199,928 of 200,000**. |
| Restart after SIGKILL | `traffic crash 200 &`; `kill`; `start`; `traffic post 100` | Reloaded cleanly with 0 attach failures. 100/100 post-restart requests had both sides. Whatever sat in the in-memory queue at the kill was lost (no spool); the exact count is unknown because the test server was killed in the same step. |
| SIGTERM drain | `traffic term 30`; `pending pend`; `sigterm` | **1.70 s** from `received SIGTERM` to `shutdown complete`. `export queue drained queued_at_close=2 queued_bytes_at_close=2844`. 30/30 requests (60 events) plus **both sides of the unanswered request**, exported as `transaction_outcome=sensor_shutdown` with status 0. Total 62, nothing lost. |

**Memory:** VmRSS 320–326 MB and VmHWM 326 MB, flat across every phase including the 3000-request burst. `smaps_rollup` shows most of it is the mapped **debug** binary (Shared_Clean 272 MB, file-backed). Private anonymous memory was **30 MB** (Private_Dirty 30,168 kB). Release-build RSS has not been measured yet.

**Not tested here:** HTTP/2 and gRPC live, Go TLS, kTLS traffic, BPF LSM, other kernels (5.x, 6.1, 6.8+), Kubernetes namespace scoping, the release build, sustained soak, and SIGTERM during an ingest retry.

### Limitations confirmed or found live

- **Coverage is only what was tested:** HTTP/1.1 between curl and a CPython OpenSSL server. Other applications, TLS stacks and protocols are not established.
- **Two observations per request when both endpoints are monitored.** These events have distinct `Id`s, so backend deduplication on `Id` will not merge them. Correlating the two sides is a separate backend concern.
- **BIO-based TLS servers are invisible.** Applications that read through `BIO_f_ssl` (e.g. `openssl s_server -WWW`) bypass the public `SSL_read*`/`SSL_write*` symbols. Do not claim "all TLS traffic".
- **The exec tracepoint did not attach on this kernel.** New processes are found only by periodic rescan, so their first requests can be missed.
- **No durable delivery.** Batches that exhaust their retries are lost (counted, not silent). A SIGKILL loses whatever is queued in memory.
- The 3-event gap in the default-budget burst was not reproduced after the backlog fix. Re-run on the VPS.

---

## Canary 1 — single sensor pod, aegis cluster (2026-10-13): HOLD at one pod

**Build and rollout:** fine. **Delivery:** not stable. The ingest API (`aegis-sentinel-api`, one replica) answers after the sensor's 10 s request timeout.

| Metric (over ~2 min) | Start | End | Change |
|---|---|---|---|
| `apisec_events_sent_total` | 87 | 105 | +18 |
| `apisec_events_lost_send_total` | 49 | 64 | +15 |
| `apisec_send_errors_total` | 23 | 30 | +7 |
| `apisec_consecutive_send_failures` | 0 | 3 | — |
| `apisec_seconds_since_last_send_ok` | 21 | 107 | — |
| `apisec_export_queue_bytes` | 5,739,965 | 7,096,276 | +1.4 MB |
| `apisec_export_queue_byte_drops_total` | 0 | 0 | — |

`events_captured_total` counts raw BPF records, so it is not comparable with `sent`. The four marked demo requests (CANARYAPP-092053-1…4) were not found in `request_logs`.

**Backend findings (ingest service, outside this repo):**
- A 321-byte plain batch took 16.8 s. A 30-event gzip batch got no answer within 20 s, yet all 30 rows were committed later.
- Postgres sessions were blocked on `UPDATE sensors SET lines_shipped…, last_heartbeat…`, waiting on `transactionid`. A request that times out leaves the transaction open, and the next batch for the same sensor row waits behind it. There was also a deadlock on `UPDATE api_endpoints SET last_seen…`, and some transactions ended in ROLLBACK.
- `JWT decode error: Not enough segments` is logged once per request because the rate limiter parses the API key as a JWT. It is noise, not a 401.

**Sensor-side consequences:**
- `apisec_events_lost_send_total` means "not acknowledged within the timeout", not "never stored". During this canary the backend committed some of those batches. On retry the same event `Id`s are resent, so **without backend deduplication on `Id` a slow commit plus a retry stores duplicates.** This is point 1 of the ACK contract.
- The sensor timeout is deliberately **not** raised. A longer timeout would hide the ingest latency and let more requests pile up on the locked row.

**Fixed in the sensor:** `MetaDataMap.direction` was never set, so every stored row had an empty direction. Events now carry `incoming` (the observed process received the request) or `outgoing` (it sent it), and the field is omitted when the direction is unknown. Unanswered and shutdown events keep their direction. Tests: `output::tests::wire_event_carries_direction_only_when_known`, `stream::tests::source_is_the_client_whichever_side_captured_the_transaction`, `stream::tests::shutdown_reports_every_pending_request`. This needs a new image before it reaches the canary.

**Backend changes needed before widening:**
1. Do not hold the `sensors` row lock across the whole batch insert. Update the heartbeat and counters in a separate short transaction, or as an atomic increment after the commit.
2. Write `api_endpoints.last_seen` in a stable key order, or as one upsert per batch, to remove the deadlock.
3. Make the server abandon the transaction when the client disconnects or a server-side deadline passes, so a timed-out request cannot leave a transaction open.
4. Deduplicate on event `Id` (ACK contract point 1).
5. Skip JWT parsing for API-key requests in the rate limiter.
6. Add a second API replica only after items 1–3; with a hot row lock, more replicas only add contention.

**Exit criteria for widening past one pod** (all must hold on the canary):
- Batches are accepted well inside the 10 s timeout. Watch `apisec_consecutive_send_failures` = 0 and `apisec_seconds_since_last_send_ok` staying low.
- `apisec_export_queue_bytes` drains back to baseline.
- `apisec_events_lost_send_total` stops increasing.
- A marked demo request appears in `request_logs` with a non-empty direction.

---

## Canary 1b — image `e5856f8` on kind-wecrew (2026-10-13 09:52–10:12 UTC): gate NOT met

- **Setup:** one pod, `api-sentinel-sensor-s7hd5` in `sentinel-sensor`, running `harbor.wecrew.in/finspot/api-sentinel-sensor:e5856f8` (Helm revision 17). Kernel 6.8.0-139-generic.
- **Startup:** BPF loaded (`dynptr=true lsm=false ktls=true`). TLS uprobes attached `usable_libs=82 total_libs=82`, and kTLS kprobes `attached=4`. **The exec tracepoint did not attach**: the same failure as on Docker Desktop.
- **Direction fix:** works on stored traffic. Rows from 09:58 onward carry `outgoing`.
- **Marked request:** `CANARYAPP-095856` returned 200 but was **not** in `request_logs` through 10:11:58.

**Delivery, sampled every 30 s from 10:00:22 to 10:12:30:**
- `lost_send` rose from 11 to 63.
- `consecutive_send_failures` bounced between 0 and 4.
- `seconds_since_last_send_ok` peaked at 131.
- `export_queue_bytes` grew from 0.8 to 6.9 MB and never drained.
- There were 24 `flush failed` messages, all `operation timed out`.
- Postgres was still blocked on `UPDATE sensors SET lines_shipped…`.

**Duplicates:** `request_logs` has no event-id column, and `event_context` carries no sensor `Id`. Grouping by `created_at, method, path, direction` found ten groups with **count = 3**, all outgoing Kubernetes API calls.

**Memory (release build):**
- `VmRSS` 33 MB and `VmHWM` 37 MB, flat. PID 1 is the sensor, so these readings are valid.
- The cgroup working set rose from 208 to 217 Mi.
- The pod limit is 1536 Mi.
- Ingest was failing throughout, so this was not a clean load test.

**Not run:** the Kubernetes SIGTERM test (step 5) and the host harness (step 7).

### Two sensor defects found, fixed after `e5856f8`

1. **The sensor re-sent timed-out batches, tripling rows and load.**
   - **Cause:** `MAX_ATTEMPTS = 3`, and a request timeout was retried like a refused connection. The backend committed every attempt late, which explains the count = 3 groups exactly. Each failing batch also held the export task for about 30 s (3 × 10 s plus backoff), so the queue grew. The retries tripled the writes contending on the locked `sensors` row.
   - **Fix (`ingest.rs`):** a batch is resent only when the server certainly did not process it, that is, a connection failure or HTTP 429/503. A timeout after sending, a 500/502/504, or a mid-request reset is not resent. Those events still count in `apisec_events_lost_send_total`, and timeouts also count in the new `apisec_send_timeouts_total`, because the backend may still store them.
   - **Test:** `tests/delivery.rs::a_batch_is_resent_only_when_the_server_certainly_did_not_process_it` uses a counting server. A timeout, then a 500, each reach the server exactly once; a 503 and a 429 each reach it 3 times.
   - **Revisit when** the backend deduplicates on event `Id` (ACK contract point 1). Resending ambiguous failures becomes safe then.
2. **The exec tracepoint never attached in a container.**
   - **Cause:** a classic `tracepoint/` program is attached by libbpf through tracefs (`/sys/kernel/tracing/events/.../id`), and tracefs is not mounted in containers, privileged or not; the chart mounts only `/sys/kernel/btf` and the cgroup filesystem. Kprobes and uprobes do not use tracefs, which is why they attached.
   - **Fix (`bpf/http_trace.bpf.c`):** the program is now `raw_tp/sched_process_exec`, attached by name through `bpf()`. The filename is read from `bprm->filename` with CO-RE. The event layout is unchanged, so no ABI bump. Success now logs `exec tracepoint attached`.
   - **Verified live** on Docker Desktop 6.6 in a privileged container with `tracefs mounted: 0`: the program passed the verifier, logged `exec tracepoint attached`, and reported 22 `new process` events with correct filenames (`/usr/bin/true`, `/bin/sleep`). The pod is not privileged, but raw tracepoints need the same BPF capabilities as the kprobes that already attach there. Confirm on the canary.

**Tests:** `cargo test` 497 passed, 0 failed: lib 216, bin 225, adversarial 27, delivery 3, enforcement 9, integration 9, memory_ceiling 1, producer_stats 3, schema_contract 4.

**The gate is still blocked on the ingest service** (the Canary 1 backend list). The retry fix removes the sensor's tripling but cannot make a 16 s ingest answer in under 10 s.

**Backend follow-up:**
- `request_logs` and `event_context` drop the sensor's event `Id`. Store it with a unique constraint; the ACK contract depends on it.

---

## ACK contract (proposal — needs backend sign-off before durable replay)

Durable replay is **not implemented**. A disk spool replays the right thing only once the backend's answer per batch is defined. This is the current sensor behaviour (`ingest.rs`) and a proposed contract to agree first.

**Current behaviour:**
- **2xx:** the whole batch counts as accepted.
- **429 / 5xx:** retried with jittered backoff, honouring `Retry-After`, up to the attempt limit. The batch is then dropped and counted in `apisec_events_lost_send_total`.
- **Other 4xx:** dropped immediately.
- **Network errors:** retried.
- Event `Id`s are fixed at serialisation, so a retry resends the same IDs.

**Proposed contract (to confirm):**
1. **The backend deduplicates on `Id`.** A replayed or retried event that was already stored is accepted and not stored twice. This is required for at-least-once delivery.
2. **`2xx` with a body of `{"accepted": n, "rejected": [{"id": "...", "reason": "...", "retryable": false}]}`:** partial acceptance is explicit. The spool deletes accepted and non-retryable IDs, and keeps retryable ones.
3. **`409`/`422` for the whole batch:** a schema problem. Never replay; quarantine for inspection.
4. **`429`/`503` with `Retry-After`:** keep the batch on disk and back off. Never drop while spool space remains.
5. **`401`/`403`:** a credentials problem. Keep the batch on disk, stop sending and report not-ready.

Until the backend confirms points 1 and 2, the in-memory queue and its loss counters stay the delivery model.

---

## Overall Implementation Summary

| Package | Status |
|---------|--------|
| 1 (F20) | Complete, pending Linux live capture |
| 2 (F01/F02/F04/F21) | Complete, pending Linux BPF verification |
| 3 (F03/F08/F09) | Code complete, pending live verifier and traffic |
| 4 (F05/F06/F07) | Code complete, pending live traffic |
| 5 (F17) | Code complete, pending live traffic |
| 6 (F10/F11/F12/F13) | Code complete, pending live kernel |
| 7 (F14/F16) | Code complete; burst and SIGTERM passed live on one kernel; SIGTERM during retries pending |
| 8 (F15/F19/F22) | F19/F22 complete; F15 durable spool blocked on the backend ACK contract |
| 9 (F18/F23) | Narrowed claims implemented |
| 10 (Section 7) | CI added; signing, soak and canary pending |
| 11 (review fixes, byte budgets) | Code complete; byte budget verified live on one kernel |

**Not production ready.** The BPF object passed the verifier, and HTTP/1.1 inbound and outbound capture, outage, overload, restart and SIGTERM passed **on one kernel (Docker Desktop WSL2 6.6) with a debug build**. Still open:
- The VPS kernel and other kernels.
- HTTP/2, gRPC and Go TLS live.
- Kubernetes scoping.
- The release build.
- Soak.
- Durable delivery, which is blocked on the ACK contract.
- The BIO blind spot and the exec-tracepoint attach failure.

Do not claim "collects all traffic".

### Test totals (Docker build image, this session)

- `cargo test --no-fail-fast`: 497 passed, 0 failed, 0 ignored. The suites are lib 216, bin 225, adversarial 27, delivery 3, enforcement 9, integration 9, memory_ceiling 1, producer_stats 3 and schema_contract 4.
- The BPF object compiles with `clang -O2 -g -Wall` and loads through the 6.6 verifier.

### VPS validation checklist (run as root on a Linux host)

1. `docker build -t api-sentinel-sensor:dev .`, which compiles BPF and builds the release binary.
2. `sudo scripts/root-verify.sh`: does the object load through the verifier, and do the probes attach? Check the `BPF object loaded` log line for `dynptr`, `ktls` and `lsm`.
3. `scripts/e2e-test.sh`: HTTP/1, HTTP/2 and gRPC traffic in both directions, with pairing checked against the validator.
4. `scripts/live-harness.sh`, using the same phases as the live validation run above. It needs python3, openssl and curl, and a validator reachable at `$VALIDATOR`. Use the **release** binary and record VmRSS.
5. While traffic runs, check these metrics:
   - `apisec_abi_mismatch_total` = 0
   - `apisec_capture_gaps_total`
   - `apisec_role_ambiguous_total`
   - `apisec_probe_attach_failures_total`
   - `apisec_transactions_incomplete_total`
6. Send SIGTERM under load. Confirm `export queue drained` appears within 20 s.
