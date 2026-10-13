/// APISentinel Sensor — Integration Tests (real-wire harness, audit F20)
///
/// Levels (env-gated; a required CI job MUST set these — absence of env is a
/// skip, not a pass):
///
/// Level 1 — SENSOR_INTEGRATION=1 (services up, no root needed):
///   cd tests && docker-compose up -d
///   SENSOR_INTEGRATION=1 cargo test --manifest-path userspace/Cargo.toml \
///     --test integration_test --locked -- --test-threads=1
///   Prerequisites (validator, sensor metrics) are REQUIRED: a missing
///   prerequisite FAILS the test instead of silently passing. The validator
///   must reject legacy/wrong schemas (it validates the real MsgHeader/Batch
///   wire contract and gzip payloads).
///
/// Level 2 — additionally SENSOR_RUNNING=1 (live eBPF sensor, requires root):
///   sudo ./userspace/target/release/api-sec-sensor --bpf ./bpf/http_trace.bpf.o \
///     --ingest http://localhost:19999/ingest --api-key test --account-id 1 \
///     --role server --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3 \
///     --discover-libs --go-tls
///   Every capture test generates a unique request id (`rid=<test>-<nanos>`)
///   on a TLS endpoint (the sensor captures TLS plaintext only — plain HTTP
///   is NOT capturable, see audit capability matrix), then requires the
///   validator to deliver an event carrying that exact rid. Zero captured
///   traffic FAILS with a diagnostic dump of the validator summary.
///
/// Tests use isolated run IDs instead of /reset, so they are race-free under
/// `--test-threads=1` (still the recommended setting: the validator store is
/// shared and bounded).

use std::time::Duration;

const VALIDATOR_URL: &str = "http://localhost:19999";
const MCP_URL: &str = "http://localhost:17777";
const GO_API_URL: &str = "https://localhost:18443";
const NODE_API_URL: &str = "https://localhost:18444";
const WS_URL: &str = "https://localhost:18445";
const METRICS_URL: &str = "http://localhost:9090";

/// How long a capture test waits for its rid event before failing.
const CAPTURE_WAIT: Duration = Duration::from_secs(15);

fn integration_enabled() -> bool {
    matches!(std::env::var("SENSOR_INTEGRATION").as_deref(), Ok("1") | Ok("true"))
}

fn sensor_running() -> bool {
    integration_enabled()
        && matches!(std::env::var("SENSOR_RUNNING").as_deref(), Ok("1") | Ok("true"))
}

/// Skip (with an explicit note) only when integration was not requested at all.
/// When SENSOR_INTEGRATION=1, missing prerequisites must NOT skip — tests call
/// `require_*` helpers that fail with a diagnostic instead.
fn skip_unless_integration(test: &str) -> bool {
    if integration_enabled() {
        return false;
    }
    eprintln!(
        "SKIPPED {test}: set SENSOR_INTEGRATION=1 (and start tests/docker-compose.yml) \
         to run integration tests — this skip is NOT a pass"
    );
    true
}

fn skip_unless_sensor_running(test: &str) -> bool {
    if sensor_running() {
        return false;
    }
    eprintln!(
        "SKIPPED {test}: set SENSOR_INTEGRATION=1 SENSOR_RUNNING=1 (live sensor attached) \
         to run capture tests — this skip is NOT a pass"
    );
    true
}

async fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // self-signed test certs
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

async fn validator_get(path: &str) -> reqwest::Result<reqwest::Response> {
    let client = http_client().await;
    client.get(format!("{VALIDATOR_URL}{path}")).send().await
}

/// GET /summary from the validator; fails the test with a diagnostic when the
/// validator is unreachable (a required integration job must not proceed
/// without its oracle).
async fn require_validator_summary(context: &str) -> serde_json::Value {
    match validator_get("/summary").await {
        Ok(resp) if resp.status().is_success() => resp
            .json::<serde_json::Value>()
            .await
            .unwrap_or_else(|e| panic!("validator /summary returned non-JSON ({e}) [{context}]")),
        Ok(resp) => panic!(
            "validator /summary returned HTTP {} [{context}] — the validator must be the \
             F20 MsgHeader/Batch version (tests/test-servers/validator/server.py)",
            resp.status()
        ),
        Err(e) => panic!(
            "validator unreachable at {VALIDATOR_URL} [{context}]: {e} — \
             start it with `cd tests && docker-compose up -d` — a required \
             integration job must FAIL when its oracle is missing, not skip"
        ),
    }
}

/// Poll the validator for events carrying `rid` until CAPTURE_WAIT elapses.
async fn wait_for_rid(rid: &str) -> Vec<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + CAPTURE_WAIT;
    loop {
        let found = match validator_get(&format!("/events?rid={rid}")).await {
            Ok(resp) => resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v["events"].as_array().cloned())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        if !found.is_empty() || tokio::time::Instant::now() >= deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn unique_rid(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("itest-{test}-{nanos}")
}

/// The wire event must carry the request line, response code, and connection
/// identity — the exact audit of one transaction.
fn assert_captured_transaction(events: &[serde_json::Value], rid: &str, method: &str) {
    assert!(
        !events.is_empty(),
        "zero captured traffic for rid={rid}: the sensor must emit an audit event \
         for every observed transaction (audit F20 — a capture miss must fail, not \
         pass). Check: sensor attached to the right TLS libs/pids, --ingest points \
         at http://localhost:19999/ingest, and the validator accepted the batch \
         (GET {VALIDATOR_URL}/summary)."
    );
    let raw = serde_json::to_string(events).unwrap();
    assert!(raw.contains(rid), "event must carry the rid for correlation: {raw}");
    let ev = &events[0];
    assert_eq!(
        ev["HTTPReq.Method"].as_str(),
        Some(method),
        "request method must match exactly: {ev}"
    );
    assert!(
        ev["HTTPResp.ResponseCode"].as_i64().unwrap_or(0) > 0,
        "response code must be captured (request AND response audited): {ev}"
    );
    assert!(
        ev["SrcInfo.Source"].as_i64().is_some(),
        "connection identity (SrcInfo.Source) must be present: {ev}"
    );
}

// ─── Level 1: validator contract (schema + gzip + counts) ───────────────────

/// A minimal event carrying every dotted key the production exporter emits.
fn probe_envelope(sequence: u64) -> serde_json::Value {
    serde_json::json!({
        "MsgHeader": {"Version": "2.0", "MessageTime": "2026-01-01 00:00:00.000",
                      "TenantId": "itest", "Sequence": sequence, "InternalOPCID": "0",
                      "PolicyVersion": "1"},
        "Batch": [{
            "SrcInfo.Source": 1, "LogVersion": "v4", "Id": "itest-probe",
            "SessionStats.StartTime": "2026-01-01 00:00:00.000",
            "L7Protocol": "HTTP11",
            "HTTPReq.Method": "GET", "HTTPReq.Uri": "/__probe__",
            "HTTPReq.Query": "", "HTTPReq.BodyLength": 0,
            "HTTPResp.ResponseCode": 200,
            "DownstreamL3L4.SourceIP": "127.0.0.1", "DownstreamL3L4.DestIP": "127.0.0.1",
            "DownstreamL3L4.SourcePort": 1, "DownstreamL3L4.DestPort": 1,
            "Proto": "rest", "APIID": 1, "MetaDataMap": {}
        }]
    })
}

#[tokio::test]
async fn test_validator_enforces_current_wire_schema() {
    // The validator itself is a test prerequisite: if it accepts the legacy
    // nested `events` schema or zero-event batches, every capture assertion
    // below could silently pass against a broken oracle. Prove the rejections
    // here — this is the "break the exporter schema → suite fails" tripwire.
    let test = "validator-enforces-schema";
    if skip_unless_integration(test) {
        return;
    }
    require_validator_summary(test).await;
    let client = http_client().await;
    let ingest = format!("{VALIDATOR_URL}/ingest");

    // 1. the legacy nested schema must be rejected
    let legacy = serde_json::json!({
        "version": "1.0",
        "events": [{"protocol": "HTTP/1.1", "request": {"method": "GET"},
                    "response": {"status_code": 200}}]
    });
    let resp = client.post(&ingest).json(&legacy).send().await.unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "the validator MUST reject the legacy nested schema (F20): if this \
         passes, the validator has been reverted and every capture test is void"
    );

    // 2. a zero-event batch must be rejected
    let mut empty = probe_envelope(1);
    empty["Batch"] = serde_json::json!([]);
    let resp = client.post(&ingest).json(&empty).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST,
               "an empty Batch must be rejected, not silently accepted");

    // 3. the current MsgHeader/Batch schema must be accepted
    let resp = client.post(&ingest).json(&probe_envelope(2)).send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, reqwest::StatusCode::OK,
               "the current MsgHeader/Batch schema must be accepted: {body}");

    // 4. gzip payloads must be accepted (the sensor gzips batches > 4 KiB)
    let mut big = probe_envelope(3);
    big["Batch"][0]["HTTPReq.Uri"] =
        serde_json::Value::String(format!("/__probe__?pad={}", "A".repeat(8192)));
    let resp = client
        .post(&ingest)
        .header("Content-Encoding", "gzip")
        .body(gzip_json(&big))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, reqwest::StatusCode::OK,
               "gzip-compressed batches must be accepted: {body}");
}

fn gzip_json(value: &serde_json::Value) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    enc.finish().unwrap()
}

// ─── Level 2: live capture with the rid oracle ──────────────────────────────

#[tokio::test]
async fn test_http1_tls_capture_has_exact_audit_event() {
    // HTTP/1.1 over TLS against the Node (OpenSSL) test server. Plain HTTP is
    // deliberately NOT used: the current capture source only sees TLS
    // plaintext (audit capability matrix), so a plain-HTTP assertion could
    // never pass honestly.
    let test = "http1-tls-capture";
    if skip_unless_sensor_running(test) {
        return;
    }
    require_validator_summary(test).await;

    let rid = unique_rid(test);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = client
        .get(format!("{NODE_API_URL}/api/echo?rid={rid}"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("node-api test server unreachable: {e}"));
    assert!(resp.status().is_success(), "node-api should answer the probe");

    let events = wait_for_rid(&rid).await;
    assert_captured_transaction(&events, &rid, "GET");
    assert_eq!(
        events[0]["L7Protocol"].as_str(),
        Some("HTTP11"),
        "HTTP/1.1 must be reported as HTTP11 on the wire: {}",
        events[0]
    );
}

#[tokio::test]
async fn test_go_tls_capture_pairs_request_and_response() {
    // Go crypto/tls server: request and response must land in ONE event with
    // the negotiated protocol — never a request without its response.
    let test = "go-tls-capture";
    if skip_unless_sensor_running(test) {
        return;
    }
    require_validator_summary(test).await;

    let rid = unique_rid(test);
    let client = http_client().await;
    let resp = client
        .get(format!("{GO_API_URL}/api/users?rid={rid}"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("go-api test server unreachable: {e}"));
    assert!(resp.status().is_success(), "go-api should answer the probe");
    let negotiated_h2 = resp.version() == reqwest::Version::HTTP_2;

    let events = wait_for_rid(&rid).await;
    assert_captured_transaction(&events, &rid, "GET");
    let reported = events[0]["L7Protocol"].as_str().unwrap_or("?");
    let expected = if negotiated_h2 { "HTTP2" } else { "HTTP11" };
    assert_eq!(
        reported, expected,
        "the reported L7Protocol must match what the client actually negotiated \
         (ALPN): {events:?}"
    );
}

#[tokio::test]
async fn test_pii_is_redacted_in_captured_event() {
    let test = "pii-redaction";
    if skip_unless_sensor_running(test) {
        return;
    }
    require_validator_summary(test).await;

    let rid = unique_rid(test);
    let client = http_client().await;
    let resp = client
        .get(format!(
            "{GO_API_URL}/api/echo?rid={rid}&email=test@example.com&ssn=123-45-6789"
        ))
        .send()
        .await
        .unwrap_or_else(|e| panic!("go-api test server unreachable: {e}"));
    assert!(resp.status().is_success());

    let events = wait_for_rid(&rid).await;
    assert_captured_transaction(&events, &rid, "GET");
    let raw = serde_json::to_string(&events).unwrap();
    assert!(!raw.contains("test@example.com"), "raw email leaked into event: {raw}");
    assert!(!raw.contains("123-45-6789"), "raw SSN leaked into event: {raw}");
    assert!(
        raw.contains("PII_EMAIL_") || raw.contains("PII_SSN_"),
        "expected PII tokens in the captured event (redaction ran): {raw}"
    );
}

#[tokio::test]
async fn test_capture_burst_produces_one_audit_event_per_transaction() {
    // Bounded load: five distinct transactions with distinct rids. Every rid
    // must arrive — a dropped transaction is a failed audit, not a shrug.
    let test = "capture-burst";
    if skip_unless_sensor_running(test) {
        return;
    }
    require_validator_summary(test).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut rids = Vec::new();
    for i in 0..5 {
        let rid = unique_rid(&format!("{test}-{i}"));
        let resp = client
            .get(format!("{NODE_API_URL}/api/burst?rid={rid}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("node-api unreachable: {e}"));
        assert!(resp.status().is_success());
        rids.push(rid);
    }

    for rid in &rids {
        let events = wait_for_rid(rid).await;
        assert_captured_transaction(&events, rid, "GET");
    }
}

// ─── Level 1: service reachability (required when SENSOR_INTEGRATION=1) ─────

#[tokio::test]
async fn test_websocket_server_completes_handshake() {
    // A real WebSocket opening handshake over TLS — not the old tautological
    // `is_ok() || is_err()` assertion. An unreachable server fails the job.
    let test = "ws-handshake";
    if skip_unless_integration(test) {
        return;
    }
    let client = http_client().await;
    let key = api_sec_sensor::output::base64_encode(b"0123456789abcdef"); // 16 bytes
    let resp = client
        .get(format!("{WS_URL}/ws"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &key)
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!("ws-server unreachable at {WS_URL}: {e} — SENSOR_INTEGRATION=1 \
                    requires every test service (cd tests && docker-compose up -d)")
        });
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SWITCHING_PROTOCOLS,
        "ws-server must complete a WebSocket opening handshake (101)"
    );
}

#[tokio::test]
async fn test_mcp_server_reachable_and_streaming() {
    let test = "mcp-reachable";
    if skip_unless_integration(test) {
        return;
    }
    // KNOWN GAP (audit F20 / capability matrix): the MCP server speaks
    // plaintext HTTP+SSE, and the current capture source only observes TLS
    // plaintext. Capture assertions for MCP are therefore NOT asserted here —
    // they would fail forever until a scoped plaintext capture source exists.
    // The gap is reported instead of being papered over with a vacuous check.
    eprintln!(
        "GAP (unsupported protocol): plaintext MCP/SSE capture is not asserted — \
         the sensor has no ordinary plaintext read/write capture pipeline. \
         See docs/PRODUCTION-READINESS-AUDIT.md capability matrix."
    );
    let client = http_client().await;
    let resp = client
        .get(format!("{MCP_URL}/events"))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!("mcp-server unreachable at {MCP_URL}: {e} — SENSOR_INTEGRATION=1 \
                    requires every test service (cd tests && docker-compose up -d)")
        });
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "mcp-server /events must answer");
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ctype.starts_with("text/event-stream"), "MCP must stream SSE, got {ctype}");
}

#[tokio::test]
async fn test_metrics_endpoint_required_and_complete() {
    let test = "metrics-endpoint";
    if skip_unless_integration(test) {
        return;
    }
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{METRICS_URL}/metrics"))
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!("sensor metrics unreachable at {METRICS_URL}/metrics: {e} — \
                    SENSOR_INTEGRATION=1 requires the sensor to run with \
                    --metrics-port 9090; a required job must not pass silently")
        });
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    for metric in [
        "apisec_events_captured_total",
        "apisec_events_dropped_total",
        "apisec_events_sent_total",
        "apisec_ringbuf_drops_total",
        "apisec_uptime_seconds",
    ] {
        assert!(body.contains(metric), "/metrics must expose {metric}");
    }
}

#[tokio::test]
async fn test_health_endpoint_required() {
    let test = "health-endpoint";
    if skip_unless_integration(test) {
        return;
    }
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{METRICS_URL}/healthz"))
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!("sensor healthz unreachable at {METRICS_URL}/healthz: {e} — \
                    SENSOR_INTEGRATION=1 requires the sensor to be running")
        });
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("ok"), "/healthz must report ok");
}




