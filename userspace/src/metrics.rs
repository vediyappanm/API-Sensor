use axum::{Router, routing::get, response::IntoResponse};
use std::sync::atomic::{AtomicU64, Ordering};

pub static EVENTS_CAPTURED:    AtomicU64 = AtomicU64::new(0);
pub static EVENTS_DROPPED:     AtomicU64 = AtomicU64::new(0);
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

/// Startup grace period — /readyz returns 200 during this window even without events.
const READYZ_GRACE_SECS: u64 = 30;

async fn metrics_handler() -> impl IntoResponse {
    let captured = EVENTS_CAPTURED.load(Ordering::Relaxed);
    let dropped  = EVENTS_DROPPED.load(Ordering::Relaxed);
    let drop_rate = if captured > 0 { dropped * 10000 / captured } else { 0 };
    let uptime = now_secs().saturating_sub(START_TIME_SECS.load(Ordering::Relaxed));

    format!(
"# HELP apisec_events_captured_total TLS events captured
# TYPE apisec_events_captured_total counter
apisec_events_captured_total {captured}

# HELP apisec_events_dropped_total Events dropped
# TYPE apisec_events_dropped_total counter
apisec_events_dropped_total {dropped}

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
    let dropped     = EVENTS_DROPPED.load(Ordering::Relaxed);
    let captured    = EVENTS_CAPTURED.load(Ordering::Relaxed);
    let sent        = EVENTS_SENT.load(Ordering::Relaxed);
    let send_errors = SEND_ERRORS.load(Ordering::Relaxed);
    let ringbuf_drops = RINGBUF_DROPS.load(Ordering::Relaxed);
    let drop_pct = if captured > 0 { dropped * 100 / captured } else { 0 };

    // Degraded if: high drop rate, all sends failing, or excessive ringbuf drops
    let all_sends_failing = send_errors > 0 && sent == 0;
    let high_ringbuf_drops = ringbuf_drops > 100;

    if drop_pct > 20 || all_sends_failing || high_ringbuf_drops {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE,
         format!("{{\"status\":\"degraded\",\"drop_pct\":{drop_pct},\"send_errors\":{send_errors},\"ringbuf_drops\":{ringbuf_drops}}}"))
    } else {
        (axum::http::StatusCode::OK,
         format!("{{\"status\":\"ok\",\"captured\":{captured},\"sent\":{sent},\"drop_pct\":{drop_pct}}}"))
    }
}

async fn ready_handler() -> impl IntoResponse {
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
