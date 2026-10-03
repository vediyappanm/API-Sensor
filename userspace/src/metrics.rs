use axum::{Router, routing::get, response::IntoResponse};
use std::sync::atomic::{AtomicU64, Ordering};

pub static EVENTS_CAPTURED:    AtomicU64 = AtomicU64::new(0);
pub static EVENTS_DROPPED:     AtomicU64 = AtomicU64::new(0);
pub static UNPAIRED_RESPONSES: AtomicU64 = AtomicU64::new(0);
/// Requests discarded because their response never arrived within the stream TTL.
pub static PENDING_EXPIRED:    AtomicU64 = AtomicU64::new(0);
/// HTTP/2 framing violations and HPACK decode failures (lost sync, or not HTTP/2).
pub static H2_PARSE_ERRORS:    AtomicU64 = AtomicU64::new(0);
/// Events skipped because their workload is outside the configured namespace scope.
pub static EVENTS_OUT_OF_SCOPE: AtomicU64 = AtomicU64::new(0);
/// The subset of out-of-scope events skipped because the workload's namespace could not be
/// determined (cgroup not recognised, or the container-runtime lookup has not answered).
/// A high share here, rather than in plain out-of-scope, means enrichment is broken.
pub static EVENTS_SCOPE_UNRESOLVED: AtomicU64 = AtomicU64::new(0);
/// Unix seconds of the last successful ring-buffer poll (capture-loop heartbeat); 0 = never.
pub static LAST_POLL_SECS:     AtomicU64 = AtomicU64::new(0);
/// Unix seconds of the last batch the ingest endpoint accepted; 0 = never.
pub static LAST_SEND_OK_SECS:  AtomicU64 = AtomicU64::new(0);
/// Batches in a row that failed all retries; reset by the next success.
pub static CONSECUTIVE_SEND_FAILURES: AtomicU64 = AtomicU64::new(0);
/// Events lost because their batch could not be delivered (also counted in EVENTS_DROPPED).
pub static EVENTS_LOST_SEND:   AtomicU64 = AtomicU64::new(0);
pub static EVENTS_SENT:        AtomicU64 = AtomicU64::new(0);
pub static SEND_ERRORS:        AtomicU64 = AtomicU64::new(0);
pub static RINGBUF_DROPS:      AtomicU64 = AtomicU64::new(0);
pub static PROTO_HTTP1:        AtomicU64 = AtomicU64::new(0);
pub static PROTO_HTTP2:        AtomicU64 = AtomicU64::new(0);
pub static PROTO_GRPC:         AtomicU64 = AtomicU64::new(0);
pub static PROTO_WEBSOCKET:    AtomicU64 = AtomicU64::new(0);
pub static PROTO_MCP:          AtomicU64 = AtomicU64::new(0);
pub static PROTO_HTTP3:        AtomicU64 = AtomicU64::new(0);
pub static PROTO_GO_TLS:       AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
pub static START_TIME_SECS:    AtomicU64 = AtomicU64::new(0);
pub static CHANNEL_WATERMARK_PCT: AtomicU64 = AtomicU64::new(0);

/// Startup grace period: /readyz returns 200 during this window even without events, and
/// /healthz tolerates a capture loop that has not polled yet while probes are still attaching.
const READYZ_GRACE_SECS: u64 = 30;
const LIVENESS_STARTUP_GRACE_SECS: u64 = 180;
/// A capture loop that has not completed a poll for this long is stuck or broken.
const POLL_STALL_SECS: u64 = 120;
/// Batches in a row that failed all retries before the sensor reports "not ready".
const DELIVERY_FAILURE_THRESHOLD: u64 = 3;

/// Called by the capture loop after every successful ring-buffer poll (also when idle).
pub fn touch_poll_heartbeat() {
    LAST_POLL_SECS.store(now_secs(), Ordering::Relaxed);
}

/// A batch was accepted by the ingest endpoint.
pub fn record_send_success() {
    LAST_SEND_OK_SECS.store(now_secs(), Ordering::Relaxed);
    CONSECUTIVE_SEND_FAILURES.store(0, Ordering::Relaxed);
}

/// A batch of `events` events failed every retry and is gone. Counted as dropped so the loss is
/// visible; before this a dead ingest URL showed zero drops and a green health check.
pub fn record_send_failure(events: u64) {
    CONSECUTIVE_SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
    EVENTS_LOST_SEND.fetch_add(events, Ordering::Relaxed);
    EVENTS_DROPPED.fetch_add(events, Ordering::Relaxed);
}

/// Liveness: is the CAPTURE LOOP alive? Deliberately independent of the ingest endpoint: if the
/// platform is down, restarting every sensor would not help and would drop the probes and state.
fn capture_alive(now: u64, started: u64, last_poll: u64) -> bool {
    if last_poll == 0 {
        return now.saturating_sub(started) < LIVENESS_STARTUP_GRACE_SECS;
    }
    now.saturating_sub(last_poll) < POLL_STALL_SECS
}

/// Readiness: can the sensor DELIVER what it captures?
fn delivery_ok(consecutive_failures: u64) -> bool {
    consecutive_failures < DELIVERY_FAILURE_THRESHOLD
}

async fn metrics_handler() -> impl IntoResponse {
    let captured = EVENTS_CAPTURED.load(Ordering::Relaxed);
    let dropped  = EVENTS_DROPPED.load(Ordering::Relaxed);
    let drop_rate = if captured > 0 { dropped * 10000 / captured } else { 0 };
    let uptime = now_secs().saturating_sub(START_TIME_SECS.load(Ordering::Relaxed));
    let expired = PENDING_EXPIRED.load(Ordering::Relaxed);
    let h2_errors = H2_PARSE_ERRORS.load(Ordering::Relaxed);
    let lost_send = EVENTS_LOST_SEND.load(Ordering::Relaxed);
    let consec_fail = CONSECUTIVE_SEND_FAILURES.load(Ordering::Relaxed);
    let out_of_scope = EVENTS_OUT_OF_SCOPE.load(Ordering::Relaxed);
    let scope_unresolved = EVENTS_SCOPE_UNRESOLVED.load(Ordering::Relaxed);
    let now = now_secs();
    let last_ok = LAST_SEND_OK_SECS.load(Ordering::Relaxed);
    let since_ok = if last_ok == 0 { -1 } else { now.saturating_sub(last_ok) as i64 };
    let last_poll = LAST_POLL_SECS.load(Ordering::Relaxed);
    let poll_age = if last_poll == 0 { -1 } else { now.saturating_sub(last_poll) as i64 };
    let buffer_bytes = crate::types::TOTAL_BUFFER_BYTES.load(Ordering::Relaxed);

    format!(
"# HELP apisec_events_captured_total TLS events captured
# TYPE apisec_events_captured_total counter
apisec_events_captured_total {captured}

# HELP apisec_events_dropped_total Events dropped
# TYPE apisec_events_dropped_total counter
apisec_events_dropped_total {dropped}

# HELP apisec_buffer_bytes Bytes accounted against the memory ceiling (stream buffers + queued requests)
# TYPE apisec_buffer_bytes gauge
apisec_buffer_bytes {buffer_bytes}

# HELP apisec_pending_expired_total Requests dropped because no response was seen within the TTL
# TYPE apisec_pending_expired_total counter
apisec_pending_expired_total {expired}

# HELP apisec_h2_parse_errors_total HTTP/2 framing or HPACK errors (capture lost sync)
# TYPE apisec_h2_parse_errors_total counter
apisec_h2_parse_errors_total {h2_errors}

# HELP apisec_events_lost_send_total Events lost because their batch could not be delivered
# TYPE apisec_events_lost_send_total counter
apisec_events_lost_send_total {lost_send}

# HELP apisec_events_out_of_scope_total Events skipped because their workload is outside the namespace scope
# TYPE apisec_events_out_of_scope_total counter
apisec_events_out_of_scope_total {out_of_scope}

# HELP apisec_events_scope_unresolved_total Out-of-scope events whose namespace could not be determined
# TYPE apisec_events_scope_unresolved_total counter
apisec_events_scope_unresolved_total {scope_unresolved}

# HELP apisec_consecutive_send_failures Batches in a row that failed all retries
# TYPE apisec_consecutive_send_failures gauge
apisec_consecutive_send_failures {consec_fail}

# HELP apisec_seconds_since_last_send_ok Seconds since the ingest endpoint last accepted a batch (-1 = never)
# TYPE apisec_seconds_since_last_send_ok gauge
apisec_seconds_since_last_send_ok {since_ok}

# HELP apisec_poll_heartbeat_age_seconds Seconds since the capture loop last polled the ring buffer (-1 = never)
# TYPE apisec_poll_heartbeat_age_seconds gauge
apisec_poll_heartbeat_age_seconds {poll_age}

# HELP apisec_unpaired_responses_total HTTP responses with no matching request
# TYPE apisec_unpaired_responses_total counter
apisec_unpaired_responses_total {}

# HELP apisec_events_sent_total Individual events sent to ingest
# TYPE apisec_events_sent_total counter
apisec_events_sent_total {}

# HELP apisec_send_errors_total Send errors (HTTP and transport)
# TYPE apisec_send_errors_total counter
apisec_send_errors_total {}

# HELP apisec_drop_rate_bps Drop rate basis points
# TYPE apisec_drop_rate_bps gauge
apisec_drop_rate_bps {drop_rate}

# HELP apisec_active_connections Active TLS connections
# TYPE apisec_active_connections gauge
apisec_active_connections {}

# HELP apisec_ringbuf_drops_total Kernel ring buffer drops
# TYPE apisec_ringbuf_drops_total counter
apisec_ringbuf_drops_total {}

# HELP apisec_protocol_events_total Events by protocol
# TYPE apisec_protocol_events_total counter
apisec_protocol_events_total{{protocol=\"http1\"}} {}
apisec_protocol_events_total{{protocol=\"http2\"}} {}
apisec_protocol_events_total{{protocol=\"grpc\"}} {}
apisec_protocol_events_total{{protocol=\"websocket\"}} {}
apisec_protocol_events_total{{protocol=\"mcp\"}} {}
apisec_protocol_events_total{{protocol=\"http3\"}} {}
apisec_protocol_events_total{{protocol=\"go_tls\"}} {}

# HELP apisec_channel_watermark_pct Channel backpressure watermark
# TYPE apisec_channel_watermark_pct gauge
apisec_channel_watermark_pct {}

# HELP apisec_uptime_seconds Sensor uptime
# TYPE apisec_uptime_seconds gauge
apisec_uptime_seconds {uptime}
",
        UNPAIRED_RESPONSES.load(Ordering::Relaxed),
        EVENTS_SENT.load(Ordering::Relaxed),
        SEND_ERRORS.load(Ordering::Relaxed),
        ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
        RINGBUF_DROPS.load(Ordering::Relaxed),
        PROTO_HTTP1.load(Ordering::Relaxed),
        PROTO_HTTP2.load(Ordering::Relaxed),
        PROTO_GRPC.load(Ordering::Relaxed),
        PROTO_WEBSOCKET.load(Ordering::Relaxed),
        PROTO_MCP.load(Ordering::Relaxed),
        PROTO_HTTP3.load(Ordering::Relaxed),
        PROTO_GO_TLS.load(Ordering::Relaxed),
        CHANNEL_WATERMARK_PCT.load(Ordering::Relaxed),
    )
}

async fn health_handler() -> impl IntoResponse {
    let now = now_secs();
    let started = START_TIME_SECS.load(Ordering::Relaxed);
    let alive = capture_alive(now, started, LAST_POLL_SECS.load(Ordering::Relaxed));
    let dropped = EVENTS_DROPPED.load(Ordering::Relaxed);
    let captured = EVENTS_CAPTURED.load(Ordering::Relaxed);
    let drop_pct = if captured > 0 { dropped * 100 / captured } else { 0 };
    let failing = !delivery_ok(CONSECUTIVE_SEND_FAILURES.load(Ordering::Relaxed));
    let body = format!(
        "{{\"status\":\"{}\",\"delivery\":\"{}\",\"captured\":{captured},\"drop_pct\":{drop_pct}}}",
        if alive { "ok" } else { "stalled" },
        if failing { "failing" } else { "ok" },
    );
    // Liveness answers one question: is the capture loop still running? A high drop rate or an
    // unreachable ingest endpoint is reported in the body and in metrics, but must not make the
    // kubelet kill the sensor.
    if alive {
        (axum::http::StatusCode::OK, body)
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, body)
    }
}

async fn ready_handler() -> impl IntoResponse {
    if !delivery_ok(CONSECUTIVE_SEND_FAILURES.load(Ordering::Relaxed)) {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "{\"ready\":false,\"reason\":\"delivery_failing\"}");
    }
    let captured = EVENTS_CAPTURED.load(Ordering::Relaxed);
    if captured > 0 {
        return (axum::http::StatusCode::OK, "{\"ready\":true}");
    }
    // Grace period: report ready during startup even without events
    let uptime = now_secs().saturating_sub(START_TIME_SECS.load(Ordering::Relaxed));
    if uptime < READYZ_GRACE_SECS {
        (axum::http::StatusCode::OK, "{\"ready\":true}")
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "{\"ready\":false}")
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn start_metrics_server(port: u16) {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(health_handler))
        .route("/readyz",  get(ready_handler));
    let addr = format!("0.0.0.0:{port}");
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            tracing::info!(addr = %addr, "metrics server started");
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "metrics server error");
            }
        }
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "cannot bind metrics server");
        }
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;
    use axum::response::IntoResponse;
    use std::sync::Mutex;

    // The counters are process-global; serialise the tests that set them.
    static LOCK: Mutex<()> = Mutex::new(());

    fn reset() {
        START_TIME_SECS.store(now_secs() - 1000, Ordering::Relaxed); // well past every grace period
        LAST_POLL_SECS.store(now_secs(), Ordering::Relaxed);
        CONSECUTIVE_SEND_FAILURES.store(0, Ordering::Relaxed);
        EVENTS_CAPTURED.store(1000, Ordering::Relaxed);
        EVENTS_DROPPED.store(0, Ordering::Relaxed);
    }

    #[test]
    fn capture_liveness_depends_only_on_the_poll_heartbeat() {
        let t = 10_000;
        assert!(capture_alive(t, t - 10, 0), "still attaching probes: inside the startup grace");
        assert!(!capture_alive(t, t - 1000, 0), "never polled and the grace is over: broken");
        assert!(capture_alive(t, t - 1000, t - 5), "polled 5s ago");
        assert!(!capture_alive(t, t - 1000, t - 500), "no poll for 500s: stalled");
    }

    #[test]
    fn delivery_is_not_ok_after_the_threshold_of_failed_batches() {
        assert!(delivery_ok(0) && delivery_ok(DELIVERY_FAILURE_THRESHOLD - 1));
        assert!(!delivery_ok(DELIVERY_FAILURE_THRESHOLD));
    }

    #[tokio::test]
    async fn an_unreachable_platform_makes_the_sensor_not_ready_but_never_unhealthy() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // Total outage: everything captured is lost, 100% drop rate, 10 batches failed in a row.
        EVENTS_DROPPED.store(1000, Ordering::Relaxed);
        CONSECUTIVE_SEND_FAILURES.store(10, Ordering::Relaxed);

        let ready = ready_handler().await.into_response();
        assert_eq!(ready.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE, "delivery failing => not ready");

        // Liveness must stay green: restarting a sensor cannot fix the platform being down, and a
        // kubelet restart storm across every node would only make the outage worse.
        let health = health_handler().await.into_response();
        assert_eq!(health.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(health.into_body(), 4096).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("\"delivery\":\"failing\"") && text.contains("\"status\":\"ok\""), "{text}");
        assert!(text.contains("\"drop_pct\":100"), "{text}");
    }

    #[tokio::test]
    async fn a_stalled_capture_loop_fails_liveness() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        LAST_POLL_SECS.store(now_secs() - 1000, Ordering::Relaxed);
        let health = health_handler().await.into_response();
        assert_eq!(health.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_healthy_sensor_is_alive_and_ready() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert_eq!(health_handler().await.into_response().status(), axum::http::StatusCode::OK);
        assert_eq!(ready_handler().await.into_response().status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn recording_a_failure_counts_the_events_and_a_success_clears_the_streak() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        record_send_failure(5);
        record_send_failure(6);
        assert_eq!(CONSECUTIVE_SEND_FAILURES.load(Ordering::Relaxed), 2);
        assert_eq!(EVENTS_DROPPED.load(Ordering::Relaxed), 11);
        record_send_success();
        assert_eq!(CONSECUTIVE_SEND_FAILURES.load(Ordering::Relaxed), 0);
    }
}
