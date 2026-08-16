/// Output format matching the Finspot/sensor batch schema.
///
/// The wire format uses dotted-key flat JSON (e.g. "SrcInfo.Source") rather
/// than nested objects, so we serialize via serde_json::Map<String, Value>
/// and skip the standard serde derive.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::types::ApiTrafficEvent;

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

// Anchor: wall-clock ms at process start minus monotonic ms at process start.
// Used to convert BPF ktime_get_ns (monotonic) to approximate wall-clock time.
static WALL_MINUS_MONO_MS: std::sync::OnceLock<i64> = std::sync::OnceLock::new();

fn wall_mono_offset_ms() -> i64 {
    *WALL_MINUS_MONO_MS.get_or_init(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        // /proc/uptime gives monotonic seconds since boot
        let mono_ms = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()))
            .map(|up| (up * 1000.0) as i64)
            .unwrap_or(0);
        wall_ms - mono_ms
    })
}

/// Convert BPF ktime_get_ns (nanoseconds since boot, monotonic) to wall-clock ms.
fn bpf_ts_to_wall_ms(bpf_ns: u64) -> u64 {
    let mono_ms = (bpf_ns / 1_000_000) as i64;
    (mono_ms + wall_mono_offset_ms()).max(0) as u64
}

/// `observed_at` is wall-clock epoch ms when >= 1e12 (after 2001-09-09).
/// Smaller values are treated as BPF ktime and converted.
fn wall_ms_for_event(observed_at: u64) -> u64 {
    if observed_at >= 1_000_000_000_000 {
        observed_at
    } else {
        bpf_ts_to_wall_ms(observed_at)
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MsgHeader {
    #[serde(rename = "Version")]
    pub version: &'static str,
    #[serde(rename = "MessageTime")]
    pub message_time: String,
    #[serde(rename = "TenantId")]
    pub tenant_id: String,
    #[serde(rename = "Sequence")]
    pub sequence: u64,
    #[serde(rename = "InternalOPCID")]
    pub internal_opc_id: String,
    #[serde(rename = "PolicyVersion")]
    pub policy_version: String,
}

#[derive(Debug, Serialize)]
pub struct SensorBatch {
    #[serde(rename = "MsgHeader")]
    pub msg_header: MsgHeader,
    #[serde(rename = "Batch")]
    pub batch: Vec<Value>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub fn to_sensor_batch(events: Vec<ApiTrafficEvent>, tenant_id: &str, policy_version: &str) -> SensorBatch {
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let opc_id = format!("{:016x}", now_ms ^ seq.wrapping_shl(16));
    let batch = events.into_iter().map(event_to_value).collect();

    SensorBatch {
        msg_header: MsgHeader {
            version: "2.0",
            message_time: format_message_time(now_ms),
            tenant_id: tenant_id.to_string(),
            sequence: seq,
            internal_opc_id: opc_id,
            policy_version: policy_version.to_string(),
        },
        batch,
    }
}

// ---------------------------------------------------------------------------
// Event → flat-key Value
// ---------------------------------------------------------------------------

fn event_to_value(ev: ApiTrafficEvent) -> Value {
    let mut m = Map::new();

    // SrcInfo
    m.insert("SrcInfo.Source".into(), json!(2));
    m.insert("SrcInfo.RemoteAddress".into(), json!(ev.source_ip.as_deref().unwrap_or("")));

    // Log metadata
    m.insert("LogVersion".into(), json!("v4"));
    m.insert("Id".into(), json!(make_event_id(ev.observed_at, ev.source_port.unwrap_or(0))));

    // SessionStats.StartTime: prefer wall-clock epoch ms from userspace.
    // Legacy events stored BPF ktime (ns or ms since boot) and need conversion.
    let wall_ms = wall_ms_for_event(ev.observed_at);
    m.insert("SessionStats.StartTime".into(), json!(format_iso8601(wall_ms)));
    m.insert("SessionStats.TimeToLastDownstreamTxByte".into(),
        json!(ev.response.latency_ms.unwrap_or(0)));

    // Downstream L3/L4 (client → sensor)
    m.insert("DownstreamL3L4.SourceIP".into(), json!(ev.source_ip.as_deref().unwrap_or("")));
    m.insert("DownstreamL3L4.DestIP".into(),   json!(ev.dest_ip.as_deref().unwrap_or("")));
    m.insert("DownstreamL3L4.L4Protocol".into(), json!("L4Proto_TCP"));
    m.insert("DownstreamL3L4.SourcePort".into(), json!(ev.source_port.unwrap_or(0)));
    m.insert("DownstreamL3L4.DestPort".into(),   json!(ev.dest_port.unwrap_or(0)));

    // Upstream L3/L4 (sensor → backend) — not resolved by eBPF sensor yet
    m.insert("UpstreamL3L4.SourceIP".into(),   json!(""));
    m.insert("UpstreamL3L4.DestIP".into(),     json!(ev.dest_ip.as_deref().unwrap_or("")));
    m.insert("UpstreamL3L4.L4Protocol".into(), json!("L4Proto_Unknown"));
    m.insert("UpstreamL3L4.SourcePort".into(), json!(0));
    m.insert("UpstreamL3L4.DestPort".into(),   json!(ev.dest_port.unwrap_or(0)));

    // L7 protocol enum
    m.insert("L7Protocol".into(), json!(l7_proto_name(&ev.protocol)));

    // HTTP Request fields
    let (uri, query_str) = split_uri_query(&ev.request.path);
    let req_body_bytes = ev.request.body.as_deref().unwrap_or("").as_bytes();
    m.insert("HTTPReq.Method".into(),     json!(ev.request.method));
    m.insert("HTTPReq.Uri".into(),        json!(uri));
    m.insert("HTTPReq.Query".into(),      json!(query_str));
    m.insert("HTTPReq.BodyLength".into(), json!(req_body_bytes.len()));
    m.insert("HTTPReq.Body".into(), json!(
        if req_body_bytes.is_empty() { Value::Null } else { json!(base64_encode(req_body_bytes)) }
    ));
    m.insert("HTTPReq.PathParams".into(), json!("{}"));

    // Named request headers (schema-defined)
    let rh = &ev.request.headers;
    m.insert("Req.Header.user-agent".into(),         json!(rh.get("user-agent").cloned().unwrap_or_default()));
    m.insert("Req.Header.content-length".into(),
        json!(rh.get("content-length").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)));
    m.insert("Req.Header.content-type".into(),       json!(rh.get("content-type").cloned().unwrap_or_default()));
    m.insert("Req.Header.content-encoding".into(),   json!(rh.get("content-encoding").cloned().unwrap_or_default()));
    m.insert("Req.Header.cookie".into(),             json!(rh.get("cookie").cloned().unwrap_or_default()));
    m.insert("Req.Header.x-user-id".into(),          json!(rh.get("x-user-id").cloned().unwrap_or_default()));
    m.insert("Req.Header.authentication".into(),     json!(rh.get("authentication").cloned().unwrap_or_default()));
    m.insert("Req.Header.authorization".into(),      json!(rh.get("authorization").cloned().unwrap_or_default()));
    m.insert("Req.Header.x-Request-id".into(),       json!(rh.get("x-request-id").cloned().unwrap_or_default()));
    m.insert("Req.Header.x-forwarded-for".into(),    json!(rh.get("x-forwarded-for").cloned().unwrap_or_default()));
    m.insert("Req.Header.x-forwarded-proto".into(),  json!(rh.get("x-forwarded-proto").cloned().unwrap_or_default()));
    m.insert("Req.Header.host".into(),               json!(ev.request.host.as_deref().unwrap_or("")));

    // Remaining request headers as stringified JSON object
    const NAMED_REQ_HEADERS: &[&str] = &[
        "user-agent", "content-length", "content-type", "content-encoding",
        "cookie", "x-user-id", "authentication", "authorization",
        "x-request-id", "x-forwarded-for", "x-forwarded-proto", "host",
    ];
    let extra_req: HashMap<&str, &str> = rh.iter()
        .filter(|(k, _)| !NAMED_REQ_HEADERS.contains(&k.as_str()))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    m.insert("Req.Header.extra".into(),
        json!(serde_json::to_string(&extra_req).unwrap_or_else(|_| "{}".to_string())));

    // HTTP Response
    let resp_body_bytes = ev.response.body.as_deref().unwrap_or("").as_bytes();
    m.insert("HTTPResp.BodyLength".into(), json!(resp_body_bytes.len()));
    m.insert("HTTPResp.Body".into(), json!(
        if resp_body_bytes.is_empty() { Value::Null } else { json!(base64_encode(resp_body_bytes)) }
    ));
    m.insert("HTTPResp.ResponseCode".into(),        json!(ev.response.status_code));
    m.insert("HTTPResp.ResponseCodeDetails".into(), json!(""));

    let rsh = &ev.response.headers;
    m.insert("Resp.Header.content-length".into(),
        json!(rsh.get("content-length").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)));
    m.insert("Resp.Header.content-type".into(),     json!(rsh.get("content-type").cloned().unwrap_or_default()));
    m.insert("Resp.Header.content-encoding".into(), json!(rsh.get("content-encoding").cloned().unwrap_or_default()));

    const NAMED_RESP_HEADERS: &[&str] = &["content-length", "content-type", "content-encoding"];
    let extra_resp: HashMap<&str, &str> = rsh.iter()
        .filter(|(k, _)| !NAMED_RESP_HEADERS.contains(&k.as_str()))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    m.insert("Resp.Header.extra".into(),
        json!(serde_json::to_string(&extra_resp).unwrap_or_else(|_| "{}".to_string())));

    // Identity
    m.insert("session_id".into(),      json!(ev.session_id.as_deref().unwrap_or("sid-0")));
    m.insert("auth_session_id".into(), json!(ev.auth_session_id.as_deref().unwrap_or("0")));
    m.insert("user_id".into(),         json!(ev.user_id.as_deref().unwrap_or("unknown")));
    m.insert("user_role".into(),       json!(ev.user_role.as_deref().unwrap_or("unknown")));

    // APIInfo — no catalog yet; Id=0 means uncatalogued
    m.insert("APIInfo.Name".into(),             json!(""));
    m.insert("APIInfo.Id".into(),               json!(0));
    m.insert("APIInfo.File".into(),             json!(""));
    m.insert("APIInfo.DebugErrorRecord".into(), json!(""));

    // OnPremAction — read-only sensor, never blocks
    m.insert("OnPremAction.FinalActionLog".into(),        json!(true));
    m.insert("OnPremAction.ModuleActionBlock".into(),     json!(false));
    m.insert("OnPremAction.SimulationModeOverride".into(), json!(false));
    m.insert("OnPremAction.DropModules".into(),           json!([]));
    m.insert("OnPremAction.MatchedRules".into(),          json!([]));
    m.insert("OnPremAction.Details".into(),               json!(""));

    // MetaDataMap
    let mut meta = Map::new();
    if let Some(ref c) = ev.container {
        if let Some(ref p) = c.pod_name      { meta.insert("pod_name".into(), json!(p)); }
        if let Some(ref n) = c.pod_namespace { meta.insert("namespace".into(), json!(n)); }
        if let Some(ref s) = c.service_name  { meta.insert("service_name".into(), json!(s)); }
    }
    if let Some(ref p) = ev.process_name   { meta.insert("process_name".into(), json!(p)); }
    if let Some(ref sh) = ev.source_hostname { meta.insert("source_hostname".into(), json!(sh)); }
    if let Some(ref dh) = ev.dest_hostname   { meta.insert("dest_hostname".into(), json!(dh)); }
    if let Some(ref af) = ev.anomaly_features {
        meta.insert("shannon_entropy".into(),   json!(af.shannon_entropy));
        meta.insert("path_depth".into(),        json!(af.path_depth));
        if af.has_sqli_pattern    { meta.insert("anomaly_sqli".into(),           json!(true)); }
        if af.has_xss_pattern     { meta.insert("anomaly_xss".into(),            json!(true)); }
        if af.has_path_traversal  { meta.insert("anomaly_path_traversal".into(), json!(true)); }
    }
    m.insert("MetaDataMap".into(), Value::Object(meta));
    m.insert("MetaDataOnly".into(), json!(false));

    // APIID — stable hash of method+path so the same endpoint always maps to
    // the same numeric ID even without a catalog.
    m.insert("APIID".into(), json!(stable_api_id(&ev.request.method, &ev.request.path)));

    // error_flags from anomaly detection
    let mut flags: Vec<&str> = vec![];
    if let Some(ref af) = ev.anomaly_features {
        if af.has_sqli_pattern   { flags.push("sqli"); }
        if af.has_xss_pattern    { flags.push("xss"); }
        if af.has_path_traversal { flags.push("path_traversal"); }
    }
    m.insert("error_flags".into(), json!(flags));

    // Proto
    let proto = match ev.protocol.as_str() {
        p if p.starts_with("gRPC") || p.starts_with("grpc") => "grpc",
        "WebSocket" | "websocket"                            => "websocket",
        "QUIC" | "HTTP/3"                                    => "quic",
        _                                                    => "rest",
    };
    m.insert("Proto".into(), json!(proto));

    Value::Object(m)
}

// ---------------------------------------------------------------------------
// Formatting helpers (no chrono dependency)
// ---------------------------------------------------------------------------

fn format_message_time(ms: u64) -> String {
    let (y, mo, d, h, mi, s) = unix_secs_to_dt(ms / 1000);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}.{:03}", ms % 1000)
}

fn format_iso8601(ms: u64) -> String {
    let (y, mo, d, h, mi, s) = unix_secs_to_dt(ms / 1000);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:06}000", ms % 1000)
}

/// Proleptic Gregorian calendar from Unix epoch seconds → (year, month, day, hour, min, sec).
/// Algorithm from Howard Hinnant's chrono paper (public domain).
fn unix_secs_to_dt(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let time_of_day = secs % 86400;
    let h  = time_of_day / 3600;
    let mi = (time_of_day % 3600) / 60;
    let s  = time_of_day % 60;
    let days = secs / 86400;
    let z   = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y   = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let mo  = if mp < 10 { mp + 3 } else { mp - 9 };
    let y   = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, mi, s)
}

fn split_uri_query(path: &str) -> (String, String) {
    match path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None         => (path.to_string(), String::new()),
    }
}

fn l7_proto_name(proto: &str) -> &'static str {
    match proto {
        "HTTP/1.1" | "http/1.1" | "http1" => "HTTP11",
        "HTTP/2"   | "http/2"   | "http2" => "HTTP2",
        "HTTP/3"   | "http/3"   | "http3" => "HTTP3",
        "gRPC"     | "grpc"               => "GRPC",
        "WebSocket"| "websocket"          => "WebSocket",
        "QUIC"     | "quic"               => "QUIC",
        "MCP"                             => "MCP",
        _                                 => "HTTP11",
    }
}

/// DJB2 hash of method+path, clamped to a positive u32.
fn stable_api_id(method: &str, path: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in method.bytes().chain(std::iter::once(b':')).chain(path.bytes()) {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    (h & 0x7FFF_FFFF).max(1)
}

fn make_event_id(ts_ms: u64, src_port: u16) -> String {
    format!("{:08x}-{:016x}{:04x}", ts_ms >> 32, ts_ms, src_port)
}

/// Standard base64 encoder (RFC 4648). No external crate.
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize]);
        out.push(TABLE[((n >> 12) & 0x3f) as usize]);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 0x3f) as usize] } else { b'=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 0x3f)        as usize] } else { b'=' });
    }
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stable_api_id_deterministic() {
        let a = stable_api_id("GET", "/api/v1/users");
        let b = stable_api_id("GET", "/api/v1/users");
        assert_eq!(a, b);
        let c = stable_api_id("POST", "/api/v1/users");
        assert_ne!(a, c);
    }

    #[test]
    fn test_format_message_time() {
        // Unix epoch = 1970-01-01 00:00:00.000
        let t = format_message_time(0);
        assert!(t.starts_with("1970-01-01 00:00:00."));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_l7_proto_name() {
        assert_eq!(l7_proto_name("HTTP/1.1"), "HTTP11");
        assert_eq!(l7_proto_name("HTTP/2"),   "HTTP2");
        assert_eq!(l7_proto_name("gRPC"),     "GRPC");
    }

    #[test]
    fn wall_ms_for_event_keeps_epoch_ms() {
        let epoch_ms = 1_787_000_000_000;
        assert_eq!(wall_ms_for_event(epoch_ms), epoch_ms);
    }
}
