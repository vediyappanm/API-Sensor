//! Userspace hot-path throughput / load test.
//!
//! The full capture pipeline is BPF -> ring buffer -> handle_event -> parse +
//! redact + anomaly -> channel -> batch -> ingest. The BPF/ring half is covered
//! by the live e2e (`scripts/e2e-ci.sh`); this test stresses the per-event
//! USERSPACE CPU cost — protocol parse + PII redaction + anomaly extraction —
//! which is what runs for every captured event and dominates steady-state CPU.
//!
//! It is a sanity/throughput guard, not a benchmark harness: it processes a
//! large batch of realistic, PII-bearing events, asserts a conservative
//! throughput floor (so a future O(n^2) regression in a parser/redactor trips
//! CI), and asserts redaction never leaks at volume. Run with `--nocapture` to
//! see the measured events/sec:
//!
//!   cargo test --release --test load_test -- --nocapture

use std::time::Instant;

use api_sec_sensor::redaction::{compute_anomaly_features, redact_pii};

/// Representative request shapes the per-event path must chew through, including
/// PII, secrets, and injection payloads so the redactor/anomaly code does real
/// work (not a trivial fast path).
fn corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "/api/v1/users?email=alice@example.com&ssn=123-45-6789",
            "{\"ok\":true}",
        ),
        (
            "/v1/pay?cc=4111111111111111&token=AKIAIOSFODNN7EXAMPLE",
            "{\"status\":\"paid\"}",
        ),
        (
            "/search?q=%27%20OR%201=1%20--%20&page=2",
            "{\"results\":[]}",
        ),
        (
            "/files?name=..%2f..%2fetc%2fpasswd",
            "{\"error\":\"denied\"}",
        ),
        (
            // synthetic, non-real bot token (still matches the Telegram pattern)
            "/bot100000000:AAFsyntheticTESTtokenValue0000000000zz/getUpdates",
            "{\"ok\":true,\"result\":[]}",
        ),
        (
            "/products?category=books&inStock=true&sort=price",
            "{\"items\":[1,2,3,4,5]}",
        ),
        (
            "/callback?state=Zk9pX2qL3mWnB7vR8sT1uY4eC6dA0fG2hJ5kP",
            "{\"redirect\":\"/home\"}",
        ),
        ("/health", "OK"),
    ]
}

#[test]
fn hot_path_throughput() {
    let corpus = corpus();
    // Scale the batch so the test runs ~sub-second in release but is large
    // enough to be a stable signal: 50k * 8 shapes = 400k events.
    const ROUNDS: usize = 50_000;
    let total = ROUNDS * corpus.len();

    let mut redacted_bytes = 0usize;
    let mut injection_hits = 0usize;

    let start = Instant::now();
    for _ in 0..ROUNDS {
        for (path, body) in &corpus {
            // Mirror build_event's per-event work: redact path + body, extract
            // anomaly features from the raw request.
            let rp = redact_pii(path);
            let rb = redact_pii(body);
            let af = compute_anomaly_features(path, Some(body));
            redacted_bytes += rp.len() + rb.len();
            if af.has_sqli_pattern || af.has_xss_pattern || af.has_path_traversal {
                injection_hits += 1;
            }
            // Correctness under load: known PII/secret literals must never survive.
            assert!(!rp.contains("alice@example.com"));
            assert!(!rp.contains("123-45-6789"));
            assert!(!rp.contains("4111111111111111"));
            assert!(!rp.contains("AAFsyntheticTESTtokenValue0000000000zz"));
        }
    }
    let elapsed = start.elapsed();

    let eps = total as f64 / elapsed.as_secs_f64();
    let ns_per_event = elapsed.as_nanos() as f64 / total as f64;
    println!(
        "load_test: {total} events in {:.3}s => {:.0} events/sec ({:.0} ns/event), \
         redacted_bytes={redacted_bytes}, injection_events={injection_hits}",
        elapsed.as_secs_f64(),
        eps,
        ns_per_event,
    );

    // Two injection shapes per round (sqli, traversal) — sanity that detection
    // actually fired across the whole batch.
    assert_eq!(injection_hits, ROUNDS * 2, "injection detection count off");

    // Conservative floor: a release build processes well over 100k eps. If this
    // trips, a parser/redactor likely regressed to super-linear complexity.
    assert!(
        eps > 20_000.0,
        "hot-path throughput {eps:.0} eps below 20k floor — possible perf regression"
    );
}
