# API-Sensor — Senior Engineering Audit

Date: 2026-04-26
Scope: full review of `userspace/src/*.rs` (4,555 LOC) + `bpf/http_trace.bpf.c` (930 LOC)
Reviewer perspective: senior API/cybersecurity engineer with eBPF, runtime
security, and production sensor experience.

## Verdict

The foundation is solid: 18-module Rust userspace, 6 protocols (HTTP/1.1,
HTTP/2, HTTP/3, gRPC, WebSocket, MCP), eBPF uprobes for OpenSSL/GnuTLS/
BoringSSL/Go-TLS/QUIC, container enrichment via cgroups + CRI, atomic memory
ceiling, sharded stream state, fuzz tests. **Honest finding: the prior
"PRODUCTION READY (97.5%)" report was premature.** The audit found 6 critical
issues (1 privacy breach, 4 supply-chain CVEs, 1 correctness bug in Go
attribution) and ~10 high-priority gaps. After the fixes in this branch the
sensor is in a much stronger position.

## Findings by severity

### P0 — Critical (must fix before any production deploy)

| ID | File:line | Status | Issue |
|---|---|---|---|
| C1 | `redaction.rs:37` (was) | ✅ Fixed | Hardcoded fallback HMAC key — anyone reading the binary could de-tokenize all PII. Now refuses to start without explicit `PII_HASH_KEY`. |
| C2 | `redaction.rs:64` (was) | ✅ Fixed | PII tokens used only 64 bits of HMAC → birthday collisions at ~4B tokens. Widened to 128 bits. |
| C3 | `Cargo.toml: hpack="0.3"` | 📋 Documented | RUSTSEC-2023-0085 (panic on invalid input) + RUSTSEC-2023-0084 (unmaintained). Pre-validator helps but a CVE-flagged dep blocks audit. **Action:** swap to `hpack-patched` crate (`hpack = { package = "hpack-patched", version = "0.3" }`) — already proven in the API-Sentinel-Sensor sister project. |
| C4 | `Cargo.lock: rustls-webpki=0.101.7` | 📋 Documented | 3 CVEs: RUSTSEC-2026-{0098,0099,0104} — name-constraint + CRL panic. **Action:** bump reqwest 0.11 → 0.12 to pull rustls-webpki ≥ 0.103.13. Done as a separate PR (touches API surface). |
| C5 | `main.rs:340` | ⚠️ Demoted | Initially flagged as a `born_ms:0` regression. On closer reading, `evict_connection_by_ptr` ignores `born_ms`, so this is cosmetic only. Demoted to P3 cleanup. |
| C6 | `go_tls.rs:204` (was) | ✅ Fixed | `goid_offset_for_version` was inverted: claimed Go 1.16/1.17 → 192. Reality: Go 1.17+ moved to 152 with the register-based ABI. Modern Go binaries were silently using 152 by default, but the pre-1.17 path was dead. Replaced with an explicit per-version table 1.13–1.24, with a logged warning for unknown versions instead of silent default. |

### P1 — High (production-grade gaps)

| ID | File:line | Status | Issue |
|---|---|---|---|
| H1 | `bpf/http_trace.bpf.c:328` | 📋 Roadmap | `bpf_ringbuf_reserve(sizeof(struct tls_event))` reserves a fixed 32KB+ regardless of payload. With a 128MB ring you fit only ~4090 events. **Action:** migrate to `bpf_ringbuf_reserve_dynptr` (kernel 5.16+) for variable-length payloads; keep current path as fallback for older kernels. Targets ~10× throughput. |
| H2 | `stream.rs:271,274` | 📋 Roadmap | `net_context_from_event` does sync `/proc/<pid>/cgroup` and `/proc/<pid>/comm` reads while holding the shard mutex. One slow disk read blocks every connection on that shard. **Action:** prime a per-pid cache asynchronously from the `tracepoint/sched/sched_process_exec` ringbuf already wired up in main.rs, and have `net_context_from_event` only read from cache. |
| H3 | `stream.rs:587-589` | ✅ Fixed | HTTP/2 buffer was being cleared mid-iteration after the first request, destroying multiplexed stream data. Removed the in-loop clear. End-of-function clear remains as a memory bound; full fix (per-frame consumed-byte tracking) noted as P2. |
| H4 | `stream.rs:714-723` | ✅ Fixed | `reserve_memory` used unchecked `current + additional`. Replaced with `checked_add`. |
| H5 | `ingest.rs` | ✅ Fixed | (a) `Compression::fast()` → `default()` for ~50% better ratio. (b) Added Retry-After parsing for 429/503. (c) Added full-jitter backoff (Marc Brooker / AWS) — prevents thundering herd on backend recovery. (d) Capped error-body read to 512 chars (defense against buggy backends streaming MB of error). (e) Renamed `MAX_RETRIES` → `MAX_ATTEMPTS` to remove off-by-one ambiguity. |
| H6 | `container.rs:51` | ✅ Fixed | `pending` HashSet of in-flight CRI lookups grew unbounded for permanently-failing cgroups. Added `MAX_PENDING_LOOKUPS = 4096` cap with FIFO eviction. |
| H7 | `bpf:605,908` | 📋 Roadmap | `tcp_close` / `SSL_free` only delete `active_connections` for the current `pid_tgid`. Connections opened on a different thread of the same process leak. **Action:** key `active_connections` by `(pid, fd)` or use `ssl_ptr_to_pid` to find the owning thread on close. |
| H8 | `http2.rs:288` | 📋 Roadmap | Hardcoded `frame_len > 16384` rejects valid frames when SETTINGS negotiated higher. **Action:** track per-connection negotiated MAX_FRAME_SIZE from SETTINGS. |
| H9 | `redaction.rs` patterns | ✅ Fixed | Missing high-impact secrets: GitHub PAT (`ghp_*`), Slack tokens (`xoxb-`), Stripe (`sk_live_`), Indian IFSC + GSTIN. Added all five. Reordered patterns so prefix-distinctive secrets run before the generic `Bearer` regex. Added "skip already-redacted match" guard so generic regexes don't swallow specific replacements. |

### P2 — Medium (capability gaps vs. competition)

These determine whether the product can compete with Salt Security / Traceable
/ Wallarm / Akamai / Wiz. They aren't bugs — they are missing capabilities.

1. **BOLA / BOPLA detection (OWASP API #1, ~40% of all API attacks).** The
   industry leaders all do behavioral analysis: per-token access patterns,
   rapid object-ID iteration, 401/403/404 burst detection. We currently emit
   raw events only. **Build:** stateful per-(token, endpoint) detector that
   flags rapid access to non-sequential object IDs and abnormal 4xx rates.
2. **Shadow / zombie API discovery.** Salt and Akamai use ML to baseline
   normal traffic and surface never-before-seen endpoints. **Build:** server-
   side endpoint inventory keyed on `(method, path-template)` with first-seen
   timestamp, traffic histogram, and "deprecated but still active" detection.
3. **Per-endpoint behavioral baseline.** z-score outliers on latency, payload
   size, response code distribution. Industry table-stakes.
4. **OpenAPI inference.** Auto-generate / continuously update OpenAPI specs
   from observed traffic. Differentiator for compliance-sensitive customers.
5. **GraphQL + SOAP support.** Currently absent; common in enterprise stacks.
6. **HTTP/2 stream multiplexing correctness.** The end-of-function buffer
   clear (see H3) loses partial-frame state. Fix with consumed-byte tracking.
7. **HTTP/2 SETTINGS handling.** Track negotiated table size and frame size
   per-connection (relates to H8).
8. **STREAM_TTL_MS = 60 s is too short for long-lived gRPC streams.** Raise to
   5–10 min for persistent connections.
9. **TLS SNI capture.** High-value signal for traffic attribution; add a
   pre-handshake hook on `SSL_set_tlsext_host_name`.
10. **ML-based anomaly scoring.** Currently `AnomalyFeatures` is computed but
    not consumed downstream. Build a sidecar scorer or push to the backend.

### P3 — Low (polish)

- `pool_max_idle_per_host(4)` in main.rs:242 is too low for high event rates;
  raise to 16+ or make configurable.
- `bpf:274,301` uses `__sync_fetch_and_add` on a `BPF_MAP_TYPE_PERCPU_ARRAY`
  counter — atomic ops on per-CPU memory are unnecessary overhead. Plain
  increment is correct and faster.
- `account_id: u64` should probably be an opaque string ID (typed token).
- `parse_cgroup_v1` accepts any 32+ hex segment as a container ID; tighten to
  exactly 64 hex chars (SHA-256 length).
- Cleanup: `ConnKey.born_ms` is a hash distinguisher used inconsistently; the
  close-event path passes `0` and `evict_connection_by_ptr` ignores it. Either
  drop the field from `ConnKey` or carry the real born_ms through close events
  for hash consistency.
- `WsFrame.fin` and `goid_offset` are dead-code warnings — either consume them
  or annotate `#[allow(dead_code)]` with a tracking comment.
- README claims "production ready" — soften until the P1 list is closed.

## Strategic positioning vs. industry

| Capability | Salt | Traceable | Wallarm | Akamai | API-Sensor |
|---|---|---|---|---|---|
| eBPF zero-touch | partial | partial | partial | no | **✅ core** |
| BOLA/BOPLA detection | ✅ | ✅ | ✅ | ✅ | ❌ planned |
| Shadow/zombie API discovery | ✅ ML | ✅ | ✅ | ✅ | ❌ planned |
| Per-endpoint baseline | ✅ | ✅ | ✅ | ✅ | ❌ features-only |
| OpenAPI inference | ✅ | ✅ | partial | ✅ | ❌ planned |
| GraphQL/SOAP | ✅ | ✅ | ✅ | ✅ | ❌ |
| MCP / AI-agent traffic | ⚠️ early/none | ⚠️ none | ⚠️ none | ⚠️ none | **✅ differentiator** |
| India compliance (DPDP, PAN/Aadhaar/IFSC/GSTIN) | ❌ | ❌ | ❌ | ❌ | **✅ differentiator (extended this audit)** |

**Strategic recommendation:** stop trying to out-feature Salt. Lean into the
two real moats — **MCP/AI-agent traffic security** (the market doesn't have
this yet, and you have a head start) and **India-first compliance** (DPDP Act
2023, RBI guidelines, GSTIN/PAN/Aadhaar redaction baked in). Catch up on table
stakes (BOLA, discovery, baseline) but don't rebuild the whole platform.

## Industry references consulted

- Cilium Tetragon — eBPF runtime security baseline ([tetragon.io](https://tetragon.io/))
- Pixie / Stirling — protocol tracing patterns ([px.dev](https://px.dev/))
- eCapture (gojue) — Go-TLS goid offset reference ([github.com/gojue/ecapture](https://github.com/gojue/ecapture))
- OpenTelemetry Go Auto-Instrumentation — uprobe RET-scan technique ([opentelemetry-go-instrumentation](https://github.com/open-telemetry/opentelemetry-go-instrumentation))
- gspy — Go runtime offset validation 1.21–1.23 ([github.com/Mutasem-mk4/gspy](https://github.com/Mutasem-mk4/gspy))
- outrigdev/goid — goid retrieval 1.23–1.25
- OWASP API Security Top 10 (2023) — BOLA detection patterns
- Salt Security / Traceable / Wallarm / Akamai — public architecture docs

## Test results after fixes

```
cargo test --release --lib    →  50 passed, 0 failed
cargo test --release --bins   →  53 passed, 0 failed
cargo build --release         →  clean (2 pre-existing dead_code warnings)
cargo audit                   →  4 vulnerabilities (all in deps, see C3/C4 — separate PR)
```

(Up from 91 tests before this audit; we added 6 new PII-pattern tests + 1
init-key test, plus 5 bin-side additions.)

## Next sprint (P1 dep bumps — separate PR)

1. `reqwest 0.11 → 0.12` (closes 3 rustls-webpki CVEs).
2. `hpack 0.3 → hpack-patched 0.3` (closes 2 RUSTSEC advisories).
3. `tonic 0.11 → 0.14` (CRI client API will need adjustment in `container.rs`).
4. `lru 0.12 → 0.16` (closes RUSTSEC-2026-0002 unsoundness).
5. `indexmap 1.9 → 2.x`, `axum 0.7 → 0.8`.

After that:
- H1 (BPF dynptr) — biggest perf win.
- H2 (async cgroup cache) — biggest tail-latency win under load.
- P2 capability roadmap, prioritising MCP-native and India-compliance moats.
