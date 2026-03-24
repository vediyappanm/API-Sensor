use axum::{
    extract::Request, middleware::Next, response::IntoResponse, response::Response, routing::get,
    Router,
};
use std::sync::atomic::{AtomicU64, Ordering};

pub static EVENTS_CAPTURED: AtomicU64 = AtomicU64::new(0);
pub static EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static EVENTS_SENT: AtomicU64 = AtomicU64::new(0);
pub static SEND_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static RINGBUF_DROPS: AtomicU64 = AtomicU64::new(0);
pub static PROTO_HTTP1: AtomicU64 = AtomicU64::new(0);
pub static PROTO_HTTP2: AtomicU64 = AtomicU64::new(0);
pub static PROTO_GRPC: AtomicU64 = AtomicU64::new(0);
pub static PROTO_WEBSOCKET: AtomicU64 = AtomicU64::new(0);
pub static PROTO_MCP: AtomicU64 = AtomicU64::new(0);
pub static PROTO_HTTP3: AtomicU64 = AtomicU64::new(0);
pub static PROTO_GO_TLS: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
pub static START_TIME_SECS: AtomicU64 = AtomicU64::new(0);
pub static CHANNEL_WATERMARK_PCT: AtomicU64 = AtomicU64::new(0);

// Granular drop reason counters
pub static DROPS_CHANNEL_FULL: AtomicU64 = AtomicU64::new(0);
pub static DROPS_PARSE_ERROR: AtomicU64 = AtomicU64::new(0);
pub static DROPS_MEMORY_LIMIT: AtomicU64 = AtomicU64::new(0);
pub static DROPS_SAMPLED: AtomicU64 = AtomicU64::new(0);

/// Startup grace period — /readyz returns 200 during this window even without events.
const READYZ_GRACE_SECS: u64 = 30;

use std::sync::OnceLock;
static METRICS_AUTH_TOKEN: OnceLock<Option<String>> = OnceLock::new();

fn metrics_auth_token() -> &'static Option<String> {
    METRICS_AUTH_TOKEN.get_or_init(|| std::env::var("METRICS_AUTH_TOKEN").ok())
}

/// Middleware: if METRICS_AUTH_TOKEN is set, require Bearer token on /metrics.
async fn auth_middleware(req: Request, next: Next) -> Response {
    if let Some(expected) = metrics_auth_token() {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        match auth_header {
            Some(val) if val.strip_prefix("Bearer ").unwrap_or("") == expected => {
                next.run(req).await
            }
            _ => (
                axum::http::StatusCode::UNAUTHORIZED,
                "{\"error\":\"unauthorized\"}",
            )
                .into_response(),
        }
    } else {
        // No token configured — allow all requests
        next.run(req).await
    }
}

async fn metrics_handler() -> impl IntoResponse {
    let captured = EVENTS_CAPTURED.load(Ordering::Relaxed);
    let dropped = EVENTS_DROPPED.load(Ordering::Relaxed);
    let drop_rate = if captured > 0 {
        dropped * 10000 / captured
    } else {
        0
    };
    let drop_ratio = if captured > 0 {
        (dropped as f64) / (captured as f64)
    } else {
        0.0
    };
    let uptime = now_secs().saturating_sub(START_TIME_SECS.load(Ordering::Relaxed));

    let dlq_spilled = crate::ingest::DLQ_SPILLED.load(Ordering::Relaxed);
    let dlq_recovered = crate::ingest::DLQ_RECOVERED.load(Ordering::Relaxed);

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

# HELP apisec_drop_rate_bps Drop rate basis points (0-10000)
# TYPE apisec_drop_rate_bps gauge
apisec_drop_rate_bps {drop_rate}

# HELP apisec_drop_ratio Drop ratio as decimal (0-1.0)
# TYPE apisec_drop_ratio gauge
apisec_drop_ratio {drop_ratio:.6}

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

# HELP apisec_drops_channel_full_total Events dropped due to channel backpressure
# TYPE apisec_drops_channel_full_total counter
apisec_drops_channel_full_total {dcf}

# HELP apisec_drops_parse_error_total Events dropped due to parse errors
# TYPE apisec_drops_parse_error_total counter
apisec_drops_parse_error_total {dpe}

# HELP apisec_drops_memory_limit_total Events dropped due to memory ceiling
# TYPE apisec_drops_memory_limit_total counter
apisec_drops_memory_limit_total {dml}

# HELP apisec_drops_sampled_total Events dropped due to sampling
# TYPE apisec_drops_sampled_total counter
apisec_drops_sampled_total {ds}

# HELP apisec_dlq_spilled_total Events spilled to dead letter queue
# TYPE apisec_dlq_spilled_total counter
apisec_dlq_spilled_total {dlq_spilled}

# HELP apisec_dlq_recovered_total Events recovered from dead letter queue
# TYPE apisec_dlq_recovered_total counter
apisec_dlq_recovered_total {dlq_recovered}
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
        dcf = DROPS_CHANNEL_FULL.load(Ordering::Relaxed),
        dpe = DROPS_PARSE_ERROR.load(Ordering::Relaxed),
        dml = DROPS_MEMORY_LIMIT.load(Ordering::Relaxed),
        ds = DROPS_SAMPLED.load(Ordering::Relaxed),
    )
}

async fn health_handler() -> impl IntoResponse {
    let dropped = EVENTS_DROPPED.load(Ordering::Relaxed);
    let captured = EVENTS_CAPTURED.load(Ordering::Relaxed);
    let sent = EVENTS_SENT.load(Ordering::Relaxed);
    let send_errors = SEND_ERRORS.load(Ordering::Relaxed);
    let ringbuf_drops = RINGBUF_DROPS.load(Ordering::Relaxed);
    let drop_pct = if captured > 0 {
        dropped * 100 / captured
    } else {
        0
    };

    let all_sends_failing = send_errors > 0 && sent == 0;
    let high_ringbuf_drops = ringbuf_drops > 100;

    if drop_pct > 20 || all_sends_failing || high_ringbuf_drops {
        tracing::warn!(
            drop_pct,
            send_errors,
            ringbuf_drops,
            "health check: degraded"
        );
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{\"status\":\"degraded\"}".to_string(),
        )
    } else {
        (
            axum::http::StatusCode::OK,
            "{\"status\":\"ok\"}".to_string(),
        )
    }
}

async fn ready_handler() -> impl IntoResponse {
    let captured = EVENTS_CAPTURED.load(Ordering::Relaxed);
    if captured > 0 {
        return (axum::http::StatusCode::OK, "{\"ready\":true}");
    }
    let uptime = now_secs().saturating_sub(START_TIME_SECS.load(Ordering::Relaxed));
    if uptime < READYZ_GRACE_SECS {
        (axum::http::StatusCode::OK, "{\"ready\":true}")
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{\"ready\":false}",
        )
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn start_metrics_server(port: u16) {
    // /metrics gets optional auth middleware; /healthz and /readyz are always open (for K8s probes)
    let metrics_routes = Router::new()
        .route("/metrics", get(metrics_handler))
        .layer(axum::middleware::from_fn(auth_middleware));

    let probe_routes = Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(ready_handler));

    let app = metrics_routes.merge(probe_routes);
    let addr = format!("0.0.0.0:{port}");
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            if metrics_auth_token().is_some() {
                tracing::info!(addr = %addr, "metrics server started (auth enabled on /metrics)");
            } else {
                tracing::info!(addr = %addr, "metrics server started");
            }
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "metrics server error");
            }
        }
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "cannot bind metrics server");
        }
    }
}
