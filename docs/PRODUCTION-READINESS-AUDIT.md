# API Sensor: production-readiness audit and implementation plan

Date: 13 October 2026  
Reviewed commit: `c60cfae0b7393b8931fc0c15e836f1c6777abbd1`  
Status: **Not ready to promise complete, reliable incoming and outgoing API audit coverage.**

## 1. Decision and scope

Keep the Rust/eBPF architecture. Fix capture identity, framing, resource bounds, privacy, delivery, and verification before expanding the protocol list. A rewrite is unnecessary. Several defects are small changes; reliable HTTP framing, durable delivery, and runtime discovery require explicit state and cannot safely be reduced to one-line patches.

This is a source-based engineering audit and implementation specification, not a production certification. It covers the BPF producer, Rust runtime and protocol modules, enrichment, redaction, wire serializer, exporter, tests/fuzz targets, container build, Helm manifests, verification scripts, and existing reports. Source references below identify the reviewed revision; line numbers will move as fixes land. Generated `vmlinux.h`, the generated dependency graph, third-party implementations, and the external ingestion backend were not exhaustively audited. No dependency vulnerability clearance is claimed.

Environment checks: `cargo` and `rustc` were not available on PATH; Docker CLI was available but its Linux engine pipe was absent; WSL enumeration returned `WSL/E_ACCESSDENIED`; Helm was not available on PATH. Consequently no Rust tests, BPF verifier runs, image builds, Kubernetes tests, live capture, or performance benchmarks were executed. Existing checked-in reports are historical evidence only. Git was clean before these documents were added. Runtime code was not changed by this audit.

Evidence labels:

- **Confirmed:** directly visible control flow or data-model defect; runtime impact still needs its regression test.
- **Compatibility risk:** source conflicts with a runtime/kernel/API assumption; needs a target-platform experiment.
- **Capability gap:** functionality required by the stated objective is absent or deliberately limited.

The repository already has valuable improvements: explicit HMAC-key initialization, header/name-aware redaction, per-direction HTTP/2 decoders and stream-ID pairing, pending-request accounting, namespace scope enforcement in userspace, container-namespace library discovery, retry-loss counters, capture-loop liveness, and a source-built image. Preserve these. Older audit items about missing HTTP/2 pairing, a hardcoded redaction key, the old HPACK dependency, or a 60-second TTL are no longer accurate descriptions of this revision.

## 2. Define what “end to end, all data” means

Separate three promises:

1. **Coverage:** observe every supported, explicitly scoped workload and both request/response directions, including a server making outbound calls.
2. **Audit completeness:** emit an outcome for each observed transaction or stream, including failures, resets, timeouts, capture gaps and truncated payloads.
3. **Payload completeness:** retain every application byte. This is not currently implemented and conflicts with finite buffers and unrestricted traffic volume. Make full-body collection an explicit, bounded policy for selected endpoints; default to metadata plus redacted body previews.

A passive sensor cannot recover bytes before attachment, bytes dropped by the kernel, unsupported encrypted-runtime plaintext, or the internals of an external service. Guaranteed business audit records require application/gateway instrumentation and a durable sink alongside the sensor. Cross-service causal tracing requires propagated trace context; matching IPs and timestamps is insufficient under concurrency.

Recommended release contract: supported TLS/runtime combinations, workload scope, attach gap, offered-load envelope, captured-body limit, streaming behavior, exporter outage budget, and every loss reason are documented and measurable. “100% sampling” must not be described as “100% delivery.”

### Current capability matrix

| Area | Current source behavior | Required production behavior |
|---|---|---|
| Ingress plus egress | One process-wide `server` or `client` role | Per-connection role; capture both in one process |
| HTTP/1.1 | Parses headers and complete bodies in one buffer; fragmented bodies break association | Incremental framing across arbitrary chunk boundaries |
| HTTP/2 | Stateful direction decoders, pairing, DATA/trailers, partial-frame support | Bound all header state; detect fragmented preface; preserve lifecycle after body cap |
| gRPC | HTTP/2 plus first-message, schema-free protobuf inspection | Message framing, compression policy, trailers, streaming summaries |
| WebSocket | Upgrade event; later frames counted and discarded | Explicit opt-in message/summary events, bounded reassembly |
| SSE/MCP | SSE content type classified as MCP; one-buffer JSON-RPC inspection | Generic SSE parser plus separately verified MCP semantics |
| HTTP/3 | Heuristic/static QPACK parser; no exported QUIC stream ID | Experimental until provider ABI, stream identity, QPACK and reassembly are correct |
| OpenSSL/GnuTLS | Startup library discovery, entry/exit hooks | Paired attachment checks, lifecycle rediscovery and coverage diagnostics |
| Go TLS | Opt-in; up to eight discovered binaries, symbol-dependent | Version/architecture-safe correlation and discovery; explicit stripped-binary coverage |
| Plain HTTP | No ordinary plaintext read/write capture pipeline | Add scoped plaintext source or gateway/OTel integration |
| Delivery | Three in-memory attempts, then counted loss | Durable redacted queue and idempotent acknowledgement where required |
| Bodies | BPF capture at most 32,767 bytes per call; output preview generally 8,192 bytes | Original/captured byte counts and truncation/gap status |
| Failures | Unpaired/expired/reset state is mostly dropped | Separate partial/failure audit outcomes without invented HTTP success |

## 3. Prioritized findings

P0 = release blocker for privacy, integrity, or bounded operation. P1 = required for the requested production coverage/reliability contract. P2 = hardening or subsequent capability work. Priority is relative to that contract, not a CVSS score.

### F01 — P0 — HTTP/2 header accumulation bypasses the memory ceiling [Confirmed]

**Evidence:** `userspace/src/http2.rs:327` (`buffered`) counts only `buf`; `on_frame` around line 414 appends CONTINUATION payloads into `HeaderBlock.bytes`. `userspace/src/stream.rs:993` releases consumed input accounting using `buffered()`. There is no total continuation-block cap. Repeated valid-size CONTINUATION frames without END_HEADERS can grow memory while the accounting reports those bytes released. Decoded header lists and HPACK dynamic state need independent bounds too.

**Fix:** account every retained allocation, cap aggregate encoded and decoded header bytes and field count, constrain HPACK table size, and fail the affected direction with a reason on violation. Check before allocation. Do not rely on a per-frame cap to bound a multi-frame block.

**Acceptance:** many CONTINUATION frames across many connections cannot exceed the configured header budget; accounting and allocator/RSS evidence agree within documented overhead; eviction returns all charges. Fuzz the active `Http2Direction::feed` path.

### F02 — P1 — failed BPF memory reads are reported as captured bytes [Confirmed]

**Evidence:** `bpf/http_trace.bpf.c`, `emit_event_dynptr` around lines 448–459, ignores `bpf_probe_read_user` and `bpf_dynptr_write` results. The fixed-slot path also ignores the payload-read return code. A failed read is submitted with a successful-looking data length, corrupting reconstruction without a copy-error signal. The [Linux helper implementation](https://github.com/torvalds/linux/blob/master/kernel/trace/bpf_trace.c) clears the destination on a failed user read; this audit therefore does not claim that this read-failure path leaks stale scratch bytes.

**Fix:** discard the reservation on any copy failure; count the error and mark the connection gap. Initialize all header fields/padding and publish only bytes successfully copied. Never ship raw diagnostic payloads on this failure path.

**Acceptance:** deliberately unreadable/cross-page pointers produce no payload event, increment a dedicated counter, and never reproduce a previous event's bytes.

### F03 — P0 — connection attribution is not process/socket safe [Confirmed]

**Evidence:** BPF `ssl_ptr_to_pid` and `ssl_ptr_to_conn` use a bare virtual address as a node-wide key (`bpf/http_trace.bpf.c:124`, `179`). Different processes can reuse the same address. Both emit paths prefer `active_connections[pid_tgid]` over the SSL mapping. An event-loop thread with multiple connections can therefore attach another connection's tuple to a payload. The tuple copied by `fill_conn_info` is local/remote, while the output labels imply client/server.

**Fix:** key TLS state by process incarnation plus TLS pointer; associate it with a stable socket identity and generation. Prefer the exact association. Treat thread context only as an explicitly low-confidence fallback, or omit the tuple. Carry local/remote separately from client/server. Test `SSL_set_fd`, separate read/write BIOs, close/reuse, and thread migration. Close records must include generation so an old close cannot evict a reused pointer.

**Acceptance:** same TLS address in two processes, many sockets on one thread, same pointer reused after close, and cross-thread I/O never exchange identities or tuples. Unknown attribution stays unknown.

### F04 — P0 — raw body redaction has bypasses [Confirmed]

**Evidence:** `redaction.rs:338` passes escaped JSON field names directly to `is_sensitive_name`; `:356` does not percent-decode form/query names. `:345` and `:407` trust attacker-controlled `PII_` prefixes. Examples to turn into tests: `{"pass\u0077ord":"opaque-secret"}`, `pass%77ord=opaque-secret`, and a sensitive header value starting with `PII_`. Regex matching is not a complete content-type parser. `stream.rs:1319` redacts `user_id` by shape, but exports role and JWT `jti` without equivalent policy; these are unverified, attacker-controlled claims.

**Fix:** canonicalize field names with bounded decoding; use structured redaction for complete supported content types, with a conservative fallback for truncated/unsupported bodies. Do not trust incoming token prefixes; use a typed/internal redacted representation or one final export redaction boundary. Apply policy to identity, authority, metadata, decoded protocol bodies and error logs too. Mark JWT identity as unverified; do not use observed claims as authorization evidence. Keep raw bodies out of any future spool.

**Acceptance:** escaped keys, percent encodings, arrays, multipart/XML, truncated and compressed data, token-looking input, and protocol-decoded payloads are scanned in the final serialized batch. Unsupported bodies become metadata-only under the safe default.

### F05 — P1 — one global role loses half of mixed-direction API activity [Confirmed]

**Evidence:** `stream.rs:729` interprets read as request for `Server` and write as request for `Client`. Later HTTP/1 and HTTP/2 processing rejects the other direction. A normal service accepts inbound requests and calls dependencies; either global setting misses one class.

**Fix:** add `Auto` as the normal mode and maintain per-connection role, informed by accept/connect and validated HTTP request syntax/preface. Keep explicit role only as a diagnostic override. Freeze a role once established; report ambiguous/midstream traffic rather than guessing. Add ingress/egress and capture-location fields to the wire model.

**Acceptance:** one process receives A→B and initiates B→C simultaneously; both transactions have correct request/response pairing and direction, with no duplicate synthetic requests.

### F06 — P1 — HTTP/1 framing loses bodies and can shift request/response pairing [Confirmed]

**Evidence:** `http.rs:68` returns a message once headers are present. `split_body` at line 124 returns empty body plus trailing partial bytes when incomplete. `stream.rs:874` replaces the buffer with that remainder, losing framing context. `100 Continue` consumes a pending request; chunked trailers are not fully consumed; duplicate headers overwrite; HEAD and close-delimited bodies lack request-aware handling. `decode_chunked_body:61` uses unchecked length addition before slicing.

**Fix:** incremental states for headers, fixed body, chunk size/data/trailers, close-delimited body and upgraded stream. Return `NeedMore`, `Complete { consumed, message }`, or `Invalid { reason }`. Retain context after headers. Capture only the body preview while continuing to count/consume the entire body. Treat informational responses as intermediate; handle HEAD/204/304/CONNECT correctly; use checked arithmetic; reject ambiguous framing with a parse-gap outcome. Preserve repeated headers deliberately.

**Acceptance:** split each fixture at every byte boundary; coalesce multiple pipelined requests/responses; test 100→200, HEAD, 204/304, chunk extensions/trailers, enormous chunk lengths, conflicting lengths, close-delimited responses and bodies larger than the preview/buffer cap. These rules are grounded in [RFC 9112 §6–7](https://www.rfc-editor.org/rfc/rfc9112.html#section-6).

### F07 — P1 — sampling individual TLS chunks corrupts stream reconstruction [Confirmed]

**Evidence:** `should_sample_out` in BPF applies a counter decision independently to request, response and body fragments. Default health sampling is 5%, even when general sampling is 100%. A dropped request can leave its response to pair with the next retained FIFO request. Dropped HTTP/2 header bytes also invalidate HPACK state.

**Fix:** for the first reliable release, capture scoped stream bytes and sample completed transactions after parsing. For lower producer overhead later, use a stable whole-connection sampling decision; HTTP/2 transaction sampling must still consume header compression state. Count intentional sampling separately from capture loss. Namespace filtering and self-exclusion should precede copying payloads where feasible.

**Acceptance:** 0/5/50/100% policies preserve valid pairings and deterministic decisions; loss never silently reassigns responses. Sampling denominators are explicitly transactions or connections, not mixed units.

### F08 — P1 — truncation and gaps are invisible in the event contract [Confirmed]

**Evidence:** `emit_event` caps a call at `MAX_DATA - 1`; `TlsEventHeader` lacks original byte count, sequence/gap indicator and flags. HTTP/1 overflow drains the beginning of the buffer (`stream.rs:863`). Body previews are capped to 8 KiB without exported completeness state. QUIC return hooks use `len &= 32767`, so a 32,768-byte return becomes zero (`bpf:1031`, `1062`).

**Fix:** version the BPF/Rust ABI together; include actual-returned length, copied length, provider, connection generation, per-direction sequence and truncation/copy-error flags. Replace QUIC bit masking with checked bounded length handling. Either copy a supported call in bounded chunks with offsets or mark the missing tail and stop parsing that stream as contiguous. Body preview truncation is distinct from capture-byte loss.

**Acceptance:** 32,767/32,768/32,769/65,536-byte calls, ring drops, and buffer pressure produce accurate byte counts and explicit partial outcomes without false complete events.

### F09 — P1 — kernel losses are not measured [Confirmed]

**Evidence:** both BPF ring reservation failures return without a loss counter. `main.rs` increments `RINGBUF_DROPS` for userspace polling errors only. The exported name describes kernel losses, which it cannot currently measure. `scripts/root-verify.sh` accepts zero drops before requiring nonzero captured traffic.

**Fix:** per-CPU producer counters for attempted records, submitted records, reserve failures, copy failures, intentional sampling and map failures; periodically aggregate them into separate userspace metrics. Add connection sequence evidence to identify damaged streams. Keep TLS-record, transaction and export counts separate.

**Acceptance:** a deliberately tiny/full ring produces nonzero producer losses even when polling succeeds. A zero-capture load run fails verification. The kernel documents reservation failure behavior in [BPF ring buffer documentation](https://kernel.org/doc/html/latest/bpf/ringbuf.html).

### F10 — P1 — unsupported optional programs can prevent startup [Compatibility risk]

**Evidence:** `main.rs:150` loads the entire object before feature selection. The dynptr switch is written after load. The object includes LSM programs and kTLS CO-RE access to a field identified as kernel ≥6.0. Catching attach failure cannot recover from an earlier load/verifier/relocation failure. A mutable map switch cannot make unknown helper calls loadable on an older kernel.

**Fix:** feature-probe before load; disable unsupported optional programs with the open-object autoload API; use separate legacy/dynptr object variants or verifier-prunable load-time configuration. Disable LSM enforcement by default and separate its lifecycle from observation. Publish only kernel/architecture combinations actually tested. See [libbpf-rs open-program loading controls](https://docs.rs/libbpf-rs/latest/libbpf_rs/type.OpenProgramMut.html); verify exact API usage against the locked 0.26 version.

**Acceptance:** real supported kernels with/without BPF LSM and kTLS load the supported subset and report every unavailable provider. An unsupported optional feature does not kill core capture.

### F11 — P1 — probe discovery is startup-only and attachment success is too weak [Confirmed]

**Evidence:** `main.rs` discovers libraries/binaries once; its process-event callback only logs. `attach_kernel_probes` does not attach the process-exec tracepoint. `bpf.rs:24` counts individual entry/exit links; one successful link can pass startup without a usable pair. The Go guard checks all links, including kernel links. Static providers are gated behind `--go-tls` and a positive PID. Automatic shared-library discovery includes only libssl/libgnutls.

**Fix:** bounded discovery reconciliation off the capture loop; attach exec/exit notifications and retain periodic scans for missed notifications and delayed library loading. Track inode/build identity, provider/version, pair health, errors and process lifecycle. Detach obsolete links. Readiness needs usable provider coverage for intended targets, not merely any link. Explicitly exclude sensor/exporter processes and optionally the ingestion destination to prevent feedback.

**Acceptance:** new/restarted pods, delayed `dlopen`, upgrades, disappearing `/proc` paths and one failed return probe are detected and reported. Coverage inventory explains eligible, attached, unsupported and failed targets.

### F12 — P1 — Go TLS correlation is not production-safe [Confirmed + compatibility risk]

**Evidence:** `go_tls.rs:354` discards attachment errors and does not install `offsets.goid_offset`. `go_goid_offset` is an array whose existing zero value defeats the pointer-null default in `get_goroutine_id`. BPF reads `fsbase + offset`, not the ABI's current-goroutine pointer; its fallback is thread identity, which is unsafe across goroutine migration. Goroutine-only keys can also collide across Go processes. Stripped binaries are explicitly skipped. The chart never passes `--go-tls`.

**Fix:** first constrain support to tested ABI/architecture versions. Resolve the current goroutine using the validated ABI, key state by process incarnation plus goroutine identity, and verify entry/return buffer bounds. Prefer stable `g` pointer identity where appropriate instead of an unnecessary runtime-field offset. Keep version-specific data per target, not one global setting. Surface failures. Add explicit Helm provider configuration. Stripped-binary discovery via verified runtime metadata is a separate feature.

**Acceptance:** concurrent goroutines with forced scheduling/blocking, multiple Go versions/processes, PIE/static/stripped binaries, and both architectures if advertised. Go's [ABIInternal reference](https://go.dev/src/cmd/compile/abi-internal) specifies the current-goroutine register, including R14 on amd64; do not guess private runtime layouts.

### F13 — P1 — container lookup failure can permanently suppress a busy workload [Confirmed]

**Evidence:** `container.rs:158` returns cached unresolved context and refreshes `last_seen`. `mark_lookup_failed:250` only clears pending state, so subsequent cache hits never requeue the lookup. Queue submission failure is ignored after inserting into `pending`. With namespace filtering, unresolved context means every event is dropped. Continued traffic keeps that unresolved entry fresh indefinitely.

**Fix:** separate metadata freshness, activity and retry deadlines. Track `Unknown/Pending/Resolved/RetryAt`; undo pending state on send failure; retry with bounded backoff independently of traffic. Keep unresolved traffic fail-closed. Seed metadata before enabling capture where possible, and expose coverage-gap duration.

**Acceptance:** first CRI request fails or lookup channel is full; after recovery the same continuously busy workload becomes resolved without restarting the sensor. Unrelated namespaces remain excluded.

### F14 — P1 — the memory ceiling is only a partial budget [Confirmed]

**Evidence:** the 10,000-event export channel and batch/JSON/base64/gzip copies are outside `TOTAL_BUFFER_BYTES`; so are map/set overhead, parser capacities and enrichment. DNS and container cache eviction retains fresh entries and then inserts, so `MAX_ENTRIES` is not a hard cap. DNS processing spawns work per IP; timeout around `spawn_blocking` does not stop the underlying blocking resolver. Cgroup scanning can visit 200,000 directories inside the capture call path.

**Fix:** byte-bound the export queue and batch in addition to item count; hard-bound connection counts, caches, header state and pending tasks. Use bounded DNS concurrency with permits held until blocking work actually finishes, and make reverse DNS optional. Move cgroup scans, `/proc` and ELF reads off the ring callback. Reserve headroom for allocator capacity, transient serialization and kernel maps/rings; test actual cgroup/RSS usage.

**Acceptance:** adversarial cardinality, slow DNS/CRI and a dead ingest endpoint stay within the deployed memory limit. Example sizing warning: 10,000 events with two 8-KiB bodies already retain about 156 MiB of body bytes alone, before headers and expansion. A 100-MiB stream ceiling is not a 100-MiB process limit.

### F15 — P1 — delivery is lossy and identifiers cannot safely deduplicate retries [Confirmed]

**Evidence:** `ingest.rs` drops a batch after three attempts; the batch loop blocks receipt while awaiting retries. There is no durable spool. A backend commit followed by a lost response can duplicate a batch. `output.rs:341` builds event IDs only from millisecond timestamp and source port, so multiple events on one connection in a millisecond collide. Batch sequence resets per process. Any HTTP 2xx is considered full acceptance without a documented acknowledgement contract.

**Fix:** first add unique stable event/batch IDs and bounded batch bytes. For audit-grade delivery add a bounded, access-controlled, redacted-only disk queue with checksum/version, crash recovery, acknowledgement checkpoint and retention/full-disk policy. Backend must implement idempotent event or batch acceptance, including partial rejection semantics. Preserve IDs across retry/replay. Document the durability boundary and fsync policy; claim at-least-once delivery plus deduplication, not magical exactly-once capture.

**Acceptance:** connection drops after server commit, 429/503, restart, torn final record, disk full, partial acknowledgement and invalid schema are deterministic; acknowledged logical events appear once. Outage survival is measured against spool capacity. Buffer bytes required are approximately `event rate × mean serialized size × outage seconds`, plus overhead.

### F16 — P1 — shutdown does not actually close the export channel [Confirmed]

**Evidence:** `main.rs` clones `tx` into the ring callback; the ring buffer remains alive when `drop(tx)` executes. The batch task cannot observe channel closure. It may flush on its timer, but the five-second timeout can end the runtime with queued or retrying work. Pending transactions and remaining ring records are not finalized.

**Fix:** stop/detach producers in a controlled order, drain accepted ring records, finalize partial transactions, drop the ring buffer/callback senders, then close/drain or persist export work. Report timeout and unfinished counts. Align Kubernetes termination grace with the explicit drain deadline. Do not merely increase the timeout.

**Acceptance:** SIGTERM with idle, busy, backpressured and retrying export paths has a verified outcome for every accepted event; shutdown exits cleanly within grace and no sender keeps the receiver alive accidentally.

### F17 — P1 — HTTP/2 detection and lifecycle still miss valid traffic [Confirmed]

**Evidence:** `stream.rs:741` requires a single payload to start with the full 13-byte `HTTP2_PREFACE` marker; if its first chunk is shorter, the connection enters the HTTP/1 buffer and is never promoted. The inner HTTP/2 parser's split-preface support does not fix this outer dispatch. `stream.rs:1049` completes a response when its preview fills, before END_STREAM/trailers. Later gRPC status and duration are lost. Request trailers are ignored; GOAWAY handling is absent in the active parser.

**Fix:** bounded protocol-detection prefix state; preserve an existing HTTP/1 classification. Stop collecting body bytes at the cap but retain cheap stream state through END_STREAM/reset/timeout. Record terminal status and trailers, or emit correlated progress/final events for long streams. A desynchronized HPACK decoder must not silently reset and resume as though complete.

**Acceptance:** all preface splits, h2c if claimed, server-first SETTINGS, >8-KiB response plus final gRPC error trailer, GOAWAY, RST and long-lived streams. Midstream attachments explicitly report partial coverage.

### F18 — P1 — HTTP/3 support is experimental, not complete [Confirmed]

**Evidence:** QUIC hooks store `stream_id` but omit it from emitted records; userspace pairs HTTP/3 by connection FIFO. All providers share the quiche-shaped argument decoder despite different APIs. `quic.rs:187` is static-table-only; `:317` interprets Huffman bytes as lossy text. QPACK literal/dynamic/encoder-stream semantics and partial stream reassembly are incomplete. Payload heuristics lack a provider tag.

**Fix:** disable advertised production HTTP/3 decoding until a provider-specific, version-tested adapter carries connection/stream IDs, direction and FIN/reset. Use a conformant bounded QPACK implementation; reject unsupported representations rather than manufacture headers. Support one provider first. [RFC 9204](https://www.ietf.org/ietf-ftp/rfc/rfc9204.pdf) defines the required compression state and Huffman handling.

**Acceptance:** multiplexed streams completing out of order, Huffman and dynamic-table headers, fragmented frames and stream cancellation compare exactly with application ground truth.

### F19 — P1 — output conversion drops useful evidence and misstates time [Confirmed]

**Evidence:** `build_event` splits redacted path/query (`stream.rs:1265`), but `output.rs:149` splits the already query-free path again and never uses `request.query`. MCP metadata is not exported from `ev.metadata`; several container identifiers and collection/network context fields are also omitted. Transport is hardcoded TCP. `format_iso8601:286` prints milliseconds as six digits then adds three zeros: 123 ms becomes `.000123000`, not `.123000000`, and has no timezone marker. Latency uses wall-clock handling time rather than BPF monotonic event timestamps.

**Fix:** define one versioned schema with golden fixtures and an explicit map of every internal field to its external destination. Preserve query multiplicity using ordered pairs or a redacted raw query. Include source/provider, direction, complete workload identity, protocol metadata and completeness reasons. Emit RFC3339 UTC times; compute durations from monotonic capture time and export queue delay separately. Keep original-body length distinct from redacted-preview length.

**Acceptance:** final wire fixtures preserve query, MCP method/tool, namespace/pod/container/node, trace context, transport and exact timestamps; multiple events in one millisecond remain distinct. Confirm compatibility with the actual backend before rollout.

### F20 — P1 — verification can pass without validating today's capture contract [Confirmed]

**Evidence:** `tests/test-servers/validator/server.py:23` expects `events` with nested fields and cannot decode gzip; production sends `MsgHeader`/`Batch` with dotted keys. It can return 200 with zero accepted events for the uncompressed production envelope. Integration tests expect the old nested schema, skip by returning successfully when environment flags are absent, and contain `resp.is_ok() || resp.is_err()` at line 144. The documented ingest URL omits `/ingest`. Plain HTTP test traffic is unsupported by the current capture source. The HTTP/2 fuzz target calls the legacy parser instead of the active streaming decoder. There is no tracked CI workflow in this checkout. `root-verify.sh` ends by printing failures without an explicit failing exit status.

**Fix:** update one validator to enforce actual schema, gzip and accepted counts; correlate generated request IDs with received events; fail required integration jobs when prerequisites are absent. Remove tautological checks. Exercise the production parser/reassembly path in fuzzing. Make scripts return nonzero on any failure. Archive image/source/kernel/test-fixture identities with results. Remove generic “production ready” banners from smoke tests.

**Acceptance:** deliberately break exporter schema, disable capture, remove return probes or suppress all events; the suite must fail each time. Successful requests must have exact expected audit results, not just increasing counters.

### F21 — P1 — privacy scope and transport need explicit enforcement [Confirmed]

**Evidence:** namespace exclusion occurs in userspace after decrypted bytes have already entered the BPF ring. Helm is explicit about scope, but standalone CLI defaults to all workloads. HTTP ingest is accepted and the chart defaults to it. Export errors read the entire response with `resp.text()` before truncating to 512 characters; memory is not bounded by that truncation, and reflected bodies may expose sensitive values in logs.

**Fix:** for strict isolation, resolve eligible cgroups proactively and enforce an allowlist before payload copy; document enrollment gaps. Make standalone capture-all explicit. Require authenticated HTTPS in production, with an explicit development override and optional mTLS/custom CA. Read error bodies as a capped byte stream, sanitize before logging, and avoid URLs containing credentials. Scope and key rotation changes need a documented rollout procedure.

**Acceptance:** excluded workloads never place payload bytes in the ring under strict mode; bad certificates/production HTTP endpoints fail safely; a large or reflected error response is bounded and redacted.

### F22 — P1 — failed transactions disappear from the audit trail [Capability gap]

**Evidence:** `PendingQueue::expire`, `PendingStreams::expire`, connection eviction and reset remove requests; unpaired responses increment a counter. No event represents a request that never receives a response, TCP failure, capture gap or process exit. Stream expiry happens when further events drive eviction, not on an independent timer.

**Fix:** add explicit transaction outcomes: completed, reset, timed_out, process_exit, capture_gap and unknown_request. Do not fabricate GET `/` or status 200. Use periodic expiry; retain enough bounded context to emit a partial result. Distinguish “application timed out” from “sensor stopped observing.” Add connect failure/close lifecycle metadata for supported sockets.

**Acceptance:** crashes, half-closes, network failures, idle streams and missing responses yield one appropriate outcome, with no false attribution and no indefinite stale state.

### F23 — P2 — streaming protocols and optional providers require narrower claims [Confirmed / capability gap]

`stream.rs:832` deliberately discards WebSocket content; `websocket.rs:13` can return a consumed length larger than available input and has no connection-level fragmentation state. `mcp.rs:56` classifies every SSE response as MCP; its line parser accepts only `data: ` in one buffer. `grpc.rs:29` ignores compression and only interprets the first message without descriptors. The kTLS reader uses only the first iovec and passes the full return count to capture, potentially reading beyond that segment (`bpf:1187–1260`).

Build bounded WebSocket/SSE/gRPC state machines with message ordinals, partial flags, negotiated compression and explicit budgets. Keep protocol decoding separate from regex threat heuristics. Treat gRPC schema-free fields as partial evidence; use supplied descriptors for names. kTLS needs iterator-kind/offset-aware bounded gathering and deduplication against TLS uprobes. Test or disable optional adapters rather than claiming support from symbol attachment alone.

## 4. Implementation order and ownership

Do not implement all findings in one pull request. Each row is a reviewable work package; subdivide where BPF ABI and backend contracts require it. All findings remain open until the relevant gates run.

| Order | Work package / owner | Findings | Exit evidence |
|---|---|---|---|
| 1 | Repair evidence harness / QA + Rust | F20 | Actual batch accepted; deliberately broken capture fails |
| 2 | Protect memory and redaction / Rust + BPF | F01, F02, F04, F21 | Adversarial allocation and final-wire privacy tests |
| 3 | Version capture identity and loss contract / BPF + Rust | F03, F08, F09 | ABI layout checks, tuple truth, forced loss accounting |
| 4 | Correct direction, HTTP/1 and sampling / Rust | F05, F06, F07 | Mixed-role and all-boundary split tests |
| 5 | Repair HTTP/2 lifecycle / Rust | F17 | Split detection, cap without early completion, final trailers |
| 6 | Make coverage continuous / BPF + platform | F10, F11, F12, F13 | Supported kernel/runtime matrix and pod churn |
| 7 | Bound runtime and export / Rust | F14, F16 | RSS, queue-byte bounds and SIGTERM evidence |
| 8 | Stabilize wire contract and durable delivery / Rust + backend | F15, F19, F22 | Golden schema, partial outcomes, deduplicated replay |
| 9 | Expand advertised protocols / protocol owners | F18, F23 | Provider-specific real-traffic corpus and lifecycle tests |
| 10 | Release hardening / platform | Section 7 | Reproducible release, canary and rollback evidence |

A constrained pilot may disable unsupported optional providers, force 100% byte capture within scope, use metadata-only bodies, and document best-effort export. That is a narrower pilot contract, not completion of the requested audit-grade product.

## 5. Minimal target architecture and event contract

Keep the current modules and improve their boundaries:

```text
bounded provider discovery + cgroup policy
                 |
validated BPF adapters -> versioned records + producer loss counters
                 |
short ring callback -> bounded per-connection ordered parser work
                 |
protocol state -> transaction/stream lifecycle -> redaction policy
                 |
versioned audit event -> byte-bounded queue/spool -> idempotent ingest
```

The ring callback should do validation, copying and bounded enqueue work. First remove synchronous enrichment; only add parser workers if profiling justifies them. If workers are added, assign every connection to exactly one worker and preserve its order. Sixteen mutex shards called from one poller do not by themselves provide parallel parsing.

Minimum additional fields (names to be agreed with the existing backend):

| Group | Required information |
|---|---|
| Identity | schema version, stable event ID, sensor instance/boot ID, node, process incarnation, connection generation, stream/message ID |
| Attribution | local/remote tuples, client/server role, ingress/egress, provider, capture location, attribution confidence |
| Timing | capture wall time, monotonic duration, emitted time, ingestion delay |
| Workload | cluster, namespace, pod UID/name, container ID/name, service, cgroup/network namespace |
| HTTP | method, authority, scheme, redacted target/query, repeat-preserving headers/trailers, status |
| Integrity | observed/captured body bytes, preview limit, complete/partial/unsupported, gap/truncation/error reason, sampling decision |
| Lifecycle | completion/reset/timeout/exit, streaming message sequence, final protocol status |
| Policy | collection scope, redaction policy/key version, verified/unverified identity provenance |
| Correlation | traceparent/tracestate/request ID when present; link confidence and source |

Unknown values must be null/explicitly unknown. Do not represent missing network context as trustworthy `0.0.0.0`, missing duration as a measured zero, or failed parsing as a successful transaction. Keep immutable IDs through every conversion and retry.

## 6. Features worth adding after correctness

1. **Coverage inventory and diagnostics:** attached/failed/unsupported provider per workload, first/last seen, attach delay, active policy, partial-capture reasons. This should precede ML features because it reveals invisible services.
2. **Plaintext API coverage:** scoped socket plaintext hooks or gateway/OTel ingestion, including sidecar-to-app hops. Deduplicate multiple observation points explicitly.
3. **Cross-service request graph:** preserve trace IDs and workload identity. Correlate in the backend; show uncorrelated edges honestly. Support outbound third-party APIs as observed client-side activity.
4. **Audit durability and replay:** encrypted-at-rest redacted spool if required by deployment policy, bounded retention, deduplication, replay lag and dead-letter diagnostics.
5. **Streaming audit:** gRPC message counts/final status, SSE event sequence, WebSocket messages and MCP JSON-RPC calls/results with safe bounded body policy.
6. **Policy controls:** endpoint/content-type body allowlists, per-workload budgets, exclusion rules, key rotation and configuration validation with last-known-good rollback.
7. **Backend API inventory:** host/service-aware route templates, schema drift, shadow endpoints, error/latency baselines and OpenAPI inference. The current method+literal-path hash is not a global API identity or normalized route catalog.
8. **Backend security analytics:** authorization anomalies, object-access patterns and rate anomalies using trustworthy identity provenance. Regex injection flags are heuristic signals, not proof of an attack. Keep model inference and long-lived behavioral state out of the capture hot path.

## 7. Release and performance gates

The following are proposed initial acceptance targets, not measured results. Agree hardware, workload, supported protocols and traffic envelope before enforcing numeric performance targets.

### Correctness and privacy

- Deterministic supported-protocol fixtures: 100% expected transaction IDs and outcomes, zero cross-pairings, zero fabricated successes. Include both directions within the same process.
- Final exported data and spool/log fixtures contain none of the seeded secret values, including encoded/truncated cases.
- Every intentional sample, producer loss, parse failure, orphan, queue rejection and export rejection is classified. Reconcile counts within their own units; a TLS read is not a transaction.
- New workload detection and recovery from a failed CRI lookup meet an agreed deadline, initially target ≤10 seconds after required metadata/symbols become available. Report enrollment loss.
- Kernel loading and live plaintext capture pass for every advertised kernel, CPU architecture, TLS provider and application build mode. Scope unknown combinations as unsupported.

### Performance and resource stability

- Measure sensor disabled/enabled on identical repeated workloads; report throughput, application p50/p95/p99 latency, CPU per 1,000 transactions, allocations, RSS, kernel map/ring memory, queue bytes, and export bandwidth.
- Candidate target: ≤3% application p99 latency overhead and ≤5% throughput reduction inside the agreed envelope. These are goals to validate, not guarantees or reasons to hide capture loss.
- Nominal deterministic workload: no unexplained loss. At overload: bounded memory, visible losses and no application interference; do not increase buffers until evidence identifies the bottleneck.
- Run a 24-hour soak with connection churn and long-lived streams. Require stable post-warmup memory and no unbounded cache/continuation/task growth. Include backend outage and DNS/CRI degradation.
- Spool outage target must fit disk budget. For example, 5,000 events/s × 2,048 bytes × 900 seconds is about 8.6 GiB before overhead; a small pod filesystem cannot promise 15 minutes at that rate.
- Benchmark gzip fast/default with representative redacted batches. Tune compression, copies and worker count from profiles. Avoid guessing multipliers such as “10× faster.”

### Build, CI and deployment

- Add CI jobs for Rust checks, active-path regression/fuzz corpus, schema contract, Helm rendering, image build and isolated privileged Linux capture. Required integration cannot silently skip.
- Make the BPF release build mandatory; `build.rs` currently only warns on compile failure. Compile/package one authoritative object, validate BPF/Rust layout and version, and use locked dependencies in all release entry points.
- Pin release image digests and toolchain; verify downloads, publish SBOM/provenance and run current dependency/image advisories. Existing audit CVE claims are not a current scan. Ubuntu tags and unpinned apt packages alone are not bit-reproducible builds.
- Docker explicitly compiles x86 BPF while Makefile/build.rs have architecture selection. Produce and test separate architecture artifacts; do not advertise arm64 from source branches alone.
- Add Helm values schema, explicit provider configuration, digest support, Linux/architecture scheduling, startup probe and matching termination grace. Namespace resource names/selectors should include the release identity; current hardcoded names collide for multiple releases in one namespace.
- Keep the existing no-service-account-token setting. Evaluate each capability on target kernels; restrict CRI access and metrics network access. A read-only mount flag alone does not make a Unix socket API read-only. Add a read-only root filesystem once spool/temp paths are explicit.
- Keep liveness about a functioning capture loop; readiness should include valid policy, usable probe coverage, exporter health/queue budget and worker health. Idle traffic is healthy; zero attached usable providers is not. Supervise the metrics task rather than discarding its failure.
- Canary on one isolated node, compare IDs and overhead, expand gradually. Roll back image and configuration together. Record redaction/spool/schema compatibility across rollback. No production deployment is performed by this document.

## 8. Verification runbook for implementation

Run on a disposable, authorized Linux test host/CI runner with clang, libbpf/libelf headers, protoc, Rust, Docker, Helm and kernel permissions. These commands are not evidence until their outputs are saved. Build/test scripts must first be corrected under F20.

```bash
# Repository root: build exactly the reviewed implementation.
git rev-parse HEAD
make
cargo fmt --manifest-path userspace/Cargo.toml --all -- --check
cargo clippy --manifest-path userspace/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path userspace/Cargo.toml --locked
bash deploy/helm/test-chart.sh
docker build -t api-sentinel-sensor:audit-candidate .
```

The default Cargo test command currently does not prove live capture. After validator repair, start the test services and a test-configured sensor explicitly, with generated test-only API/HMAC keys and a scope restricted to those workloads. Use the validator `/ingest` route. Run `SENSOR_INTEGRATION=1 SENSOR_RUNNING=1 cargo test --manifest-path userspace/Cargo.toml --test integration_test --locked -- --test-threads=1`; the single-thread setting avoids shared validator reset races until the harness uses isolated run IDs. This command is expected to expose current gaps, not necessarily pass on the audited revision.

Required test families:

| Family | Cases |
|---|---|
| Parser properties | All split points, byte-at-a-time, coalescing, invalid sizes, repeated fields, gap injection, exact consumed length |
| Identity | Shared thread/many sockets, same pointer/different processes, reuse, migration, IPv4/IPv6, accepted versus connected sockets |
| Protocol lifecycle | HTTP interim/HEAD/chunked/close; H2 continuation/dynamic tables/reset; large response plus trailers; streaming timeout |
| Runtime coverage | Process churn, delayed libraries, stripped Go, optional feature unavailable, real provider versions |
| Export faults | DNS/TLS failures, timeout after commit, 429, 503, 401/403, 413, partial ACK, malicious error body, disk full and restart |
| Scope/privacy | Unknown metadata, failed lookup then recovery, excluded workloads, encoded secret keys, identity fields and final wire |
| Operational | Idle readiness, metrics bind failure, capture stall, SIGTERM during backlog, SIGKILL/crash recovery |

Evidence for every gate must include source SHA, image digest, kernel/config, architecture, provider/app versions, configuration without secrets, offered load, expected IDs, received IDs, loss reasons, benchmark comparison and raw test result files. Keep failures and skipped capabilities visible.

## 9. Engineering rules: minimal code, high confidence

1. Start with an observable invariant and a failing regression that reaches the production path. Do not write a test that reproduces a helper's implementation without proving behavior.
2. Change the narrowest responsible layer. BPF extracts bounded bytes and identity; parsers own framing; redaction owns privacy; output owns schema; exporter owns persistence/ACKs. Avoid parallel implementations of the same rule.
3. Separate correctness from optimization. First preserve ordering, lengths, identity and outcome; then profile. Do not replace state machines with heuristics to reduce line count.
4. Bound bytes, entries, tasks, time and retries before accepting untrusted input. Validate arithmetic and lengths before allocation/copy. Every allocation owner defines release on success, error, timeout, close and shutdown.
5. No filesystem, DNS, CRI, ELF scanning or blocking export work inside the ring callback. Avoid cloning entire buffers/batches; return consumed offsets and reuse bounded allocations where profiles justify it.
6. Never join bytes across an unknown gap. Never fabricate protocol/identity fields to make a dashboard look populated. Emit explicit partial/unsupported outcomes.
7. Use monotonic capture time for durations and wall time only for presentation. IDs must remain unique across processes/restarts and stable through replay.
8. Redact before disk/export and cover derived fields. Treat source strings as untrusted even when they resemble internal redaction tokens. Logging is an export path too.
9. An attachment is healthy only when its necessary entry/return/cleanup hooks are usable. Supported means demonstrated with real traffic on a declared version matrix.
10. Preserve wire compatibility deliberately. Add schema versions and golden fixtures; coordinate backend deduplication/acknowledgements before changing delivery guarantees.
11. Use one focused PR per invariant; include trigger, root cause, changed behavior, regression result, performance implication, limitations and rollback. Do not mix cosmetic rewrites with parser or BPF fixes.
12. Completion means tests and release gates passed on the target environment. “Code written,” “no panic,” “HTTP 200,” and “zero reported drops” are insufficient evidence of complete audit coverage.

See [IMPLEMENTATION-INSTRUCTIONS.md](IMPLEMENTATION-INSTRUCTIONS.md) for a copyable engineering execution brief.
