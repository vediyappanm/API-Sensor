# Engineering execution brief

Use with [PRODUCTION-READINESS-AUDIT.md](PRODUCTION-READINESS-AUDIT.md). The audit is based on commit `c60cfae0b7393b8931fc0c15e836f1c6777abbd1`; re-check findings against the current tree before editing.

## Copyable instruction for an engineer or coding agent

> Improve this sensor into a bounded, observable production API audit collector for both inbound and outbound traffic. Preserve the current Rust/eBPF architecture. Follow the findings and work-package order in docs/PRODUCTION-READINESS-AUDIT.md. Implement one coherent work package at a time; do not claim all findings are fixed until their acceptance evidence exists.
>
> Begin by inspecting repository instructions, current changes, source SHA and available Linux test environment. Preserve unrelated edits. Repair the real-wire integration harness first so it rejects empty acceptance, wrong schemas, skipped capture and missing return probes. Independently address the P0 memory, attribution and privacy defects, together with copy-failure integrity, as early changes.
>
> For each finding, trace the production caller, create a minimal failing regression, patch the narrowest responsible layer, then run the affected checks. Use incremental protocol state and checked lengths. Preserve per-connection ordering. Bound retained bytes, headers, entries, tasks, retries and deadlines. Keep slow discovery/enrichment away from the ring callback. Do not add concurrency until a profile justifies it.
>
> Build the mixed-direction contract around per-connection roles and stable process/socket generations. Add explicit capture gaps, truncation, partial outcomes and unsupported-provider status. Redact all export fields and any durable spool. Do not use unknown/fabricated values to hide missing coverage. Keep experimental providers disabled until real provider-specific tests pass.
>
> Version and test the BPF/Rust event ABI together. Coordinate wire-schema changes and idempotent acknowledgements with the backend. Introduce durable delivery only with bounded disk use, replay IDs, crash recovery and a documented full-disk policy. A passive sensor remains best effort before its durability boundary; do not promise universal lossless payload collection.
>
> For every work package, report findings addressed, exact changed files, regressions run and results, resource/performance evidence where relevant, remaining limitations and rollback. If required tooling is unavailable, preserve the work and clearly mark validation pending. Never turn historical logs or an unrun command into a passing result. Do not deploy to production or claim production readiness based on unit tests alone.

## Work-package checklist

- [ ] 1. F20: current-schema/gzip validator, exact request-ID oracle, mandatory integration execution, failing smoke-script exits, active streaming fuzz paths.
- [ ] 2. F01/F02/F04/F21: bounded H2 header state, safe BPF copy failures, encoding-aware final-wire redaction, explicit scope/secure export policy.
- [ ] 3. F03/F08/F09: process-safe connection identity, versioned capture ABI, true producer loss counters and explicit gap propagation.
- [ ] 4. F05/F06/F07: per-connection roles, incremental HTTP/1 framing, transaction-safe sampling.
- [ ] 5. F17: fragmented H2 detection, retained lifecycle after preview cap, trailers and terminal state.
- [ ] 6. F10/F11/F12/F13: pre-load capability selection, discovery reconciliation, validated Go ABI, recoverable metadata lookup.
- [ ] 7. F14/F16: complete resource budgets, bounded resolver tasks, ordered shutdown/drain.
- [ ] 8. F15/F19/F22: stable IDs and times, complete wire mappings, durable replay/ACKs, failure and partial audit events.
- [ ] 9. F18/F23: opt-in supported QUIC/streaming/kTLS adapters with real traffic ground truth.
- [ ] 10. CI, release/image provenance, Helm schema and security, workload benchmarks, soak, canary and rollback rehearsal.

## Pull-request acceptance record

```text
Finding IDs:
Source SHA / image digest:
Observable failure before change:
Root cause and affected production path:
Smallest responsible change:
Compatibility / schema / ABI effects:
Regression fixture and exact expected result:
Commands executed and actual results:
Target Linux/kernel/provider versions tested:
Performance/resource comparison (or why not applicable):
Unvalidated behavior and remaining risk:
Rollback procedure:
```

## Done means

All scoped transactions on the declared test matrix have correct identity and direction, valid protocol framing, policy-compliant payload handling and an honest terminal/partial outcome. Loss is observable, resources remain bounded, accepted events survive the promised outage/restart envelope, and backend replay is deduplicated. Performance targets are demonstrated on agreed hardware. Unsupported runtimes and incomplete payloads are visible. Every open finding is either fixed with evidence or explicitly excluded from the released support contract.
