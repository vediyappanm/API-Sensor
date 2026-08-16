use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;

use crate::container::ContainerResolver;
use crate::dns::{self, DnsResolver};
use crate::grpc::decode_grpc_fields;
use crate::http::{
    HttpMessage, HttpResponseParsed, extract_http_header, is_usable_http_request, split_query,
};
use crate::http2::{
    Http2HpackDecoder, contains_http2_preface, extract_data_frames, parse_http2_frames,
};
use crate::identity::extract_identity;
use crate::mcp::{is_mcp_response, parse_sse_events};
use crate::metrics::*;
use crate::quic;
use crate::redaction::redact_pii;
use crate::types::*;
use crate::websocket::parse_websocket_frame;

const MAX_PENDING_PER_CONN: usize = 100;
const MAX_H2_PENDING_STREAMS: usize = 200;

/// Cap on captured request/response body bytes shipped per event. Bodies are
/// evidence, not archives — the kernel already truncates at 32 KiB, and this
/// keeps batch size and PII-scan cost bounded.
pub const MAX_BODY_CAPTURE_BYTES: usize = 8192;

/// Redact PII from a captured body and cap its length. Returns None for an
/// empty body so the wire field stays null rather than "".
fn redact_and_cap_body(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let capped = &raw[..raw.len().min(MAX_BODY_CAPTURE_BYTES)];
    let text = String::from_utf8_lossy(capped);
    Some(redact_pii(&text))
}

fn skip_unpaired_response() {
    UNPAIRED_RESPONSES.fetch_add(1, Ordering::Relaxed);
}

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn pop_usable_request(queue: &mut VecDeque<ParsedRequest>) -> Option<ParsedRequest> {
    while let Some(req) = queue.pop_front() {
        if is_usable_http_request(&req.method, &req.path) {
            return Some(req);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ShardedStreamState
// ---------------------------------------------------------------------------

pub struct ShardedStreamState {
    shards: Vec<Arc<Mutex<StreamState>>>,
}

impl ShardedStreamState {
    pub fn new(
        account_id: u64,
        role: TrafficRole,
        max_buffer: usize,
        container_resolver: Arc<ContainerResolver>,
        max_total_buffer_bytes: usize,
        dns_resolver: Arc<DnsResolver>,
    ) -> Self {
        Self {
            shards: (0..NUM_SHARDS)
                .map(|_| {
                    Arc::new(Mutex::new(StreamState::new(
                        account_id,
                        role,
                        max_buffer,
                        container_resolver.clone(),
                        max_total_buffer_bytes,
                        dns_resolver.clone(),
                    )))
                })
                .collect(),
        }
    }

    /// Shard by (pid, ssl_ptr) only — born_ms is resolved within the shard.
    fn shard_index(&self, pid: u32, ssl_ptr: u64) -> usize {
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        pid.hash(&mut h);
        ssl_ptr.hash(&mut h);
        (h.finish() as usize) % NUM_SHARDS
    }

    pub fn handle_event(&self, ev: &TlsEventHeader, payload: &[u8]) -> Vec<ApiTrafficEvent> {
        let idx = self.shard_index(ev.pid, ev.ssl_ptr);
        let shard = &self.shards[idx];
        match shard.lock() {
            Ok(mut guard) => guard.handle_event(ev, payload),
            Err(e) => {
                tracing::warn!("shard mutex poisoned, recovering");
                e.into_inner().handle_event(ev, payload)
            }
        }
    }

    pub fn evict_connection(&self, conn_key: &ConnKey) {
        let idx = self.shard_index(conn_key.pid, conn_key.ssl_ptr);
        let shard = &self.shards[idx];
        match shard.lock() {
            Ok(mut guard) => guard.evict_connection_by_ptr(conn_key.pid, conn_key.ssl_ptr),
            Err(e) => {
                tracing::warn!("shard mutex poisoned, recovering");
                e.into_inner().evict_connection_by_ptr(conn_key.pid, conn_key.ssl_ptr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// StreamState
// ---------------------------------------------------------------------------

struct StreamState {
    account_id: u64,
    role: TrafficRole,
    max_buffer: usize,
    max_total_buffer_bytes: usize,
    container_resolver: Arc<ContainerResolver>,
    dns_resolver: Arc<DnsResolver>,
    buffers: HashMap<StreamKey, (Vec<u8>, u64)>,
    pending: HashMap<ConnKey, VecDeque<ParsedRequest>>,
    http2_state: HashMap<ConnKey, Http2Conn>,
    http3_connections: HashSet<ConnKey>,
    ws_connections: HashSet<ConnKey>,
    known_connections: HashSet<ConnKey>,
    /// Maps (pid, ssl_ptr) → first-seen timestamp for born_ms disambiguation.
    conn_born_ms: HashMap<(u32, u64), u64>,
    last_eviction_ms: u64,
}

#[derive(Default)]
pub struct Http2Conn {
    pub buffer: Vec<u8>,
    pub seen_preface: bool,
    pub pending_requests: HashMap<u32, ParsedRequest>,
    pub last_event_ts: u64,
    pub hpack: Http2HpackDecoder,
}

/// Subtract from TOTAL_BUFFER_BYTES with underflow protection.
fn release_memory(amount: usize) {
    if amount == 0 { return; }
    TOTAL_BUFFER_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(amount))
    }).ok();
}

impl StreamState {
    fn new(
        account_id: u64,
        role: TrafficRole,
        max_buffer: usize,
        container_resolver: Arc<ContainerResolver>,
        max_total_buffer_bytes: usize,
        dns_resolver: Arc<DnsResolver>,
    ) -> Self {
        Self {
            account_id,
            role,
            max_buffer,
            max_total_buffer_bytes,
            container_resolver,
            dns_resolver,
            buffers: HashMap::new(),
            pending: HashMap::new(),
            http2_state: HashMap::new(),
            http3_connections: HashSet::new(),
            ws_connections: HashSet::new(),
            known_connections: HashSet::new(),
            conn_born_ms: HashMap::new(),
            last_eviction_ms: 0,
        }
    }

    fn evict_stale(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_eviction_ms) < 10_000 {
            return;
        }
        self.last_eviction_ms = now_ms;

        let mut freed_bytes: usize = 0;

        let old_buffers_size: usize = self.buffers.values().map(|(b, _)| b.len()).sum();
        self.buffers.retain(|_, (_, last_seen)| now_ms.saturating_sub(*last_seen) < STREAM_TTL_MS);
        let new_buffers_size: usize = self.buffers.values().map(|(b, _)| b.len()).sum();
        freed_bytes += old_buffers_size.saturating_sub(new_buffers_size);

        let old_h2_size: usize = self.http2_state.values().map(|c| c.buffer.len()).sum();
        self.http2_state.retain(|_, conn| now_ms.saturating_sub(conn.last_event_ts) < STREAM_TTL_MS);
        let new_h2_size: usize = self.http2_state.values().map(|c| c.buffer.len()).sum();
        freed_bytes += old_h2_size.saturating_sub(new_h2_size);

        self.pending.retain(|_, queue| !queue.is_empty());

        if self.buffers.len() > MAX_STREAM_ENTRIES {
            let excess = self.buffers.len() - MAX_STREAM_ENTRIES;
            let mut keys: Vec<_> = self.buffers.keys().cloned().collect();
            keys.sort_by_key(|k| self.buffers.get(k).map(|(_, ts)| *ts).unwrap_or(0));
            for k in keys.into_iter().take(excess) {
                if let Some((buf, _)) = self.buffers.remove(&k) {
                    freed_bytes += buf.len();
                }
            }
        }
        if self.http2_state.len() > MAX_STREAM_ENTRIES {
            let excess = self.http2_state.len() - MAX_STREAM_ENTRIES;
            let mut keys: Vec<_> = self.http2_state.keys().cloned().collect();
            keys.sort_by_key(|k| self.http2_state.get(k).map(|c| c.last_event_ts).unwrap_or(0));
            for k in keys.into_iter().take(excess) {
                if let Some(conn) = self.http2_state.remove(&k) {
                    freed_bytes += conn.buffer.len();
                }
            }
        }

        if freed_bytes > 0 {
            release_memory(freed_bytes);
        }

        // Clean up known_connections for evicted connections
        self.known_connections.retain(|k| {
            let still_active = self.pending.contains_key(k)
                || self.http2_state.contains_key(k)
                || self.ws_connections.contains(k)
                || self.http3_connections.contains(k);
            if !still_active {
                ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                self.conn_born_ms.remove(&(k.pid, k.ssl_ptr));
            }
            still_active
        });
        // Clean up ws/h3 connections for evicted connections
        self.ws_connections.retain(|k| self.known_connections.contains(k));
        self.http3_connections.retain(|k| self.known_connections.contains(k));
    }

    /// Evict a connection by (pid, ssl_ptr), regardless of born_ms.
    fn evict_connection_by_ptr(&mut self, pid: u32, ssl_ptr: u64) {
        let mut freed_bytes: usize = 0;
        self.buffers.retain(|k, (buf, _)| {
            if k.pid == pid && k.ssl_ptr == ssl_ptr {
                freed_bytes += buf.len();
                false
            } else {
                true
            }
        });
        self.pending.retain(|k, _| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
        self.http2_state.retain(|k, conn| {
            if k.pid == pid && k.ssl_ptr == ssl_ptr {
                freed_bytes += conn.buffer.len();
                false
            } else {
                true
            }
        });
        self.ws_connections.retain(|k| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
        self.http3_connections.retain(|k| !(k.pid == pid && k.ssl_ptr == ssl_ptr));

        let before = self.known_connections.len();
        self.known_connections.retain(|k| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
        let evicted = before - self.known_connections.len();
        if evicted > 0 {
            ACTIVE_CONNECTIONS.fetch_sub(evicted as u64, Ordering::Relaxed);
        }

        self.conn_born_ms.remove(&(pid, ssl_ptr));

        if freed_bytes > 0 {
            release_memory(freed_bytes);
        }
    }

    fn net_context_from_event(&self, ev: &TlsEventHeader) -> NetContext {
        let mut ctx = NetContext::default();
        if ev.cgroup_id != 0 { ctx.cgroup_id = Some(ev.cgroup_id); }
        if ev.netns_ino != 0 { ctx.netns_ino = Some(ev.netns_ino); }
        if ev.src_port != 0  { ctx.source_port = Some(ev.src_port); }
        if ev.dst_port != 0  { ctx.dest_port = Some(ev.dst_port); }
        match ev.ip_family {
            4 => {
                ctx.source_ip = Some(Ipv4Addr::from(u32::from_be(ev.src_ip4)).to_string());
                ctx.dest_ip   = Some(Ipv4Addr::from(u32::from_be(ev.dst_ip4)).to_string());
            }
            6 => {
                ctx.source_ip = Some(Ipv6Addr::from(ev.src_ip6).to_string());
                ctx.dest_ip   = Some(Ipv6Addr::from(ev.dst_ip6).to_string());
            }
            _ => {}
        }
        ctx.container = self.container_resolver.resolve(ev);

        // Process name from BPF comm field (with /proc fallback)
        ctx.process_name = dns::read_process_name(ev.pid, &ev.comm);

        // DNS reverse resolution (non-blocking, returns cached or queues lookup)
        if let Some(ref ip) = ctx.source_ip {
            ctx.source_hostname = self.dns_resolver.lookup_and_queue(ip);
        }
        if let Some(ref ip) = ctx.dest_ip {
            ctx.dest_hostname = self.dns_resolver.lookup_and_queue(ip);
        }

        ctx
    }

    fn handle_event(&mut self, ev: &TlsEventHeader, payload: &[u8]) -> Vec<ApiTrafficEvent> {
        let mut output = Vec::new();
        // Wall clock at userspace emit time. BPF ktime is monotonic-since-boot
        // and was previously double-converted in output.rs, stamping every
        // event with node boot time (Live Feed looked frozen).
        let ts_ms = wall_clock_ms();
        let born_ms = *self.conn_born_ms.entry((ev.pid, ev.ssl_ptr)).or_insert(ts_ms);
        let conn_key = ConnKey { pid: ev.pid, ssl_ptr: ev.ssl_ptr, born_ms };
        let stream_key = StreamKey { pid: ev.pid, ssl_ptr: ev.ssl_ptr, direction: ev.direction };
        let data_len = payload.len();

        self.evict_stale(ts_ms);

        // Track active connections
        if self.known_connections.insert(conn_key.clone()) {
            ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        }

        let is_request_dir = match self.role {
            TrafficRole::Server => ev.direction == 0,
            TrafficRole::Client => ev.direction == 1,
        };

        // HTTP/2 check — only process if already known H2 or preface detected in this event.
        // This avoids creating a shadow buffer for HTTP/1.1 connections.
        let is_known_h2 = self.http2_state.contains_key(&conn_key);
        let data_has_preface = if !is_known_h2 && data_len > 0 {
            contains_http2_preface(payload)
        } else {
            false
        };

        if is_known_h2 || data_has_preface {
            if let Some(events) = self.process_http2_event(conn_key.clone(), ev, payload, ts_ms, is_request_dir, data_has_preface) {
                return events;
            }
        }

        if data_len == 0 {
            return output;
        }

        // HTTP/3 check — detect QUIC/HTTP3 frames from QUIC library probes
        let is_known_h3 = self.http3_connections.contains(&conn_key);
        if is_known_h3 || (!is_known_h2 && quic::looks_like_http3(payload)) {
            self.http3_connections.insert(conn_key.clone());
            let header_sets = quic::extract_h3_headers(payload);
            for headers in header_sets {
                if is_request_dir {
                    if let Some(method) = headers.get(":method") {
                        if !is_usable_http_request(method, headers.get(":path").map(String::as_str).unwrap_or("/")) {
                            continue;
                        }
                        let path = headers.get(":path").cloned().unwrap_or_else(|| "/".to_string());
                        let host = headers.get(":authority").cloned();
                        let net_ctx = self.net_context_from_event(ev);
                        let queue = self.pending.entry(conn_key.clone()).or_default();
                        if queue.len() < MAX_PENDING_PER_CONN {
                            queue.push_back(ParsedRequest {
                                method: method.clone(),
                                path,
                                host,
                                headers: headers.clone(),
                                ts_ms,
                                net_ctx,
                                body: Vec::new(),
                            });
                        }
                    }
                } else if let Some(status) = headers.get(":status") {
                    let Some(request) = pop_usable_request(
                        self.pending.entry(conn_key.clone()).or_default(),
                    ) else {
                        skip_unpaired_response();
                        continue;
                    };
                    let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                    let resp = HttpResponseParsed {
                        status_code: status.parse::<i32>().unwrap_or(0),
                        headers: headers.clone(),
                        body: Vec::new(),
                    };
                    let event = build_event(
                        self.account_id, ts_ms, request, resp, latency_ms, "HTTP/3", "ebpf",
                    );
                    output.push(event);
                }
            }
            return output;
        }

        // WebSocket: count frames but do not emit them as HTTP. Per-frame
        // TEXT/PING/PONG with a hardcoded /ws path flooded Live Feed and
        // created a feedback loop with /api/stream/live.
        if self.ws_connections.contains(&conn_key) {
            let mut pos = 0;
            while pos < payload.len() {
                match parse_websocket_frame(&payload[pos..]) {
                    Some((_frame, consumed)) => {
                        if consumed == 0 { break; }
                        PROTO_WEBSOCKET.fetch_add(1, Ordering::Relaxed);
                        pos += consumed;
                    }
                    None => break,
                }
            }
            return output;
        }

        // HTTP/1.1 parsing — use atomic CAS for memory reservation
        let max_buf = self.max_buffer;
        let max_total = self.max_total_buffer_bytes;
        let parsed = {
            let (buf, last_seen) = self.buffers.entry(stream_key).or_insert_with(|| (Vec::new(), ts_ms));
            *last_seen = ts_ms;

            if !reserve_memory(max_total, data_len) {
                EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
                return output;
            }
            buf.extend_from_slice(payload);

            if buf.len() > max_buf {
                let drain = buf.len() - max_buf;
                release_memory(drain);
                buf.drain(0..drain);
            }

            let mut msgs = Vec::new();
            let before_len = buf.len();
            while let Some((msg, remaining)) = extract_http_header(buf) {
                msgs.push(msg);
                *buf = remaining;
            }
            // Account for consumed bytes in memory ceiling
            let consumed = before_len.saturating_sub(buf.len());
            if consumed > 0 {
                release_memory(consumed);
            }
            msgs
        };

        for msg in parsed {
            match msg {
                HttpMessage::Request(req) => {
                    if is_request_dir && is_usable_http_request(&req.method, &req.path) {
                        let net_ctx = self.net_context_from_event(ev);
                        let queue = self.pending.entry(conn_key.clone()).or_default();
                        if queue.len() < MAX_PENDING_PER_CONN {
                            queue.push_back(ParsedRequest {
                                method: req.method,
                                path: req.path,
                                host: req.host,
                                headers: req.headers,
                                ts_ms,
                                net_ctx,
                                body: req.body,
                            });
                        }
                    }
                }
                HttpMessage::Response(resp) => {
                    if is_request_dir {
                        continue;
                    }

                    // Check for WebSocket upgrade
                    let upgrade_hdr = resp.headers.get("upgrade").map(|v| v.to_lowercase());
                    if upgrade_hdr.as_deref() == Some("websocket") {
                        self.ws_connections.insert(conn_key.clone());
                    }

                    let is_mcp = is_mcp_response(&resp.headers);

                    let Some(request) = pop_usable_request(
                        self.pending.entry(conn_key.clone()).or_default(),
                    ) else {
                        skip_unpaired_response();
                        continue;
                    };
                    let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                    let protocol = if is_mcp { "MCP" } else { "HTTP/1.1" };
                    let mut event = build_event(
                        self.account_id,
                        ts_ms,
                        request,
                        resp,
                        latency_ms,
                        protocol,
                        "ebpf",
                    );
                    if is_mcp {
                        let mcp_events = parse_sse_events(payload);
                        if let Some(mcp_ev) = mcp_events.first() {
                            event.metadata = Some(EventMetadata {
                                has_injection: mcp_ev.has_injection,
                                injection_patterns: if mcp_ev.has_injection {
                                    vec!["prompt_injection".to_string()]
                                } else {
                                    vec![]
                                },
                                permission_flags: mcp_ev.permission_flags.clone(),
                                mcp_method: mcp_ev.method.clone(),
                                mcp_tool_name: mcp_ev.tool_name.clone(),
                            });
                        }
                    }
                    output.push(event);
                }
            }
        }

        output
    }

    fn process_http2_event(
        &mut self,
        conn_key: ConnKey,
        ev: &TlsEventHeader,
        payload: &[u8],
        ts_ms: u64,
        is_request_dir: bool,
        data_has_preface: bool,
    ) -> Option<Vec<ApiTrafficEvent>> {
        let net_ctx = if is_request_dir {
            Some(self.net_context_from_event(ev))
        } else {
            None
        };
        let conn_state = self.http2_state.entry(conn_key).or_default();
        conn_state.last_event_ts = ts_ms;
        if data_has_preface {
            conn_state.seen_preface = true;
        }

        let data_len = payload.len();
        if data_len == 0 {
            return Some(vec![]);
        }

        // Atomic CAS memory reservation
        if !reserve_memory(self.max_total_buffer_bytes, data_len) {
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return Some(vec![]);
        }
        conn_state.buffer.extend_from_slice(payload);

        if !conn_state.seen_preface {
            if contains_http2_preface(&conn_state.buffer) {
                conn_state.seen_preface = true;
            } else {
                return None;
            }
        }

        let mut output = Vec::new();
        if conn_state.buffer.len() > self.max_buffer * 2 {
            let target_drain = conn_state.buffer.len() - self.max_buffer;
            let boundary = find_next_frame_boundary(&conn_state.buffer, target_drain);
            if boundary > 0 {
                release_memory(boundary);
                conn_state.buffer.drain(0..boundary);
            }
        }

        // Bound pending requests to prevent unbounded growth
        if conn_state.pending_requests.len() > MAX_H2_PENDING_STREAMS {
            let excess = conn_state.pending_requests.len() - MAX_H2_PENDING_STREAMS;
            let keys: Vec<u32> = conn_state.pending_requests.keys().copied().take(excess).collect();
            for k in keys {
                conn_state.pending_requests.remove(&k);
            }
        }

        let stream_frames = parse_http2_frames(&mut conn_state.hpack, &conn_state.buffer);
        for (stream_id, headers) in stream_frames {
            if is_request_dir {
                if let Some(method) = headers.get(":method") {
                    let path = headers.get(":path").cloned().unwrap_or_else(|| "/".to_string());
                    if !is_usable_http_request(method, &path) {
                        continue;
                    }
                    let host = headers.get(":authority").cloned();
                    if conn_state.pending_requests.len() < MAX_H2_PENDING_STREAMS {
                        conn_state.pending_requests.insert(stream_id, ParsedRequest {
                            method: method.clone(),
                            path,
                            host,
                            headers: headers.clone(),
                            ts_ms,
                            net_ctx: net_ctx.clone().unwrap_or_default(),
                            body: Vec::new(),
                        });
                    }
                    // Don't clear the buffer here — multiplexed streams may
                    // have additional HEADERS / DATA frames in this same chunk
                    // that we still need to parse. The buffer is drained at
                    // the end of the function (after all frames processed)
                    // and bounded by the max_buffer guard above, so we won't
                    // grow without bound either.
                }
            } else if let Some(status) = headers.get(":status") {
                let Some(request) = conn_state
                    .pending_requests
                    .remove(&stream_id)
                    .filter(|req| is_usable_http_request(&req.method, &req.path))
                else {
                    skip_unpaired_response();
                    continue;
                };
                let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                let is_grpc = headers
                    .get("content-type")
                    .map(|v| v.starts_with("application/grpc"))
                    .unwrap_or(false);

                // This stream's response DATA payloads. For plain HTTP/2 REST
                // this is the response body; for gRPC it's protobuf bytes we
                // decode into fields instead of shipping raw.
                let data = extract_data_frames(&conn_state.buffer, stream_id);
                let resp = HttpResponseParsed {
                    status_code: status.parse::<i32>().unwrap_or(0),
                    headers: headers.clone(),
                    body: if is_grpc { Vec::new() } else { data.clone() },
                };

                let grpc_body = if is_grpc {
                    let fields = decode_grpc_fields(&data);
                    if !fields.is_empty() {
                        serde_json::to_string(&fields).ok()
                    } else {
                        None
                    }
                } else {
                    None
                };

                let protocol = if is_grpc { "gRPC" } else { "HTTP/2" };
                let mut event = build_event(
                    self.account_id,
                    ts_ms,
                    request,
                    resp,
                    latency_ms,
                    protocol,
                    "ebpf",
                );
                // gRPC body belongs in response, not request
                if let Some(body) = grpc_body {
                    event.response.body = Some(body);
                }
                output.push(event);
            }
        }
        if !output.is_empty() {
            let cleared = conn_state.buffer.len();
            conn_state.buffer.clear();
            release_memory(cleared);
        }
        Some(output)
    }
}

// ---------------------------------------------------------------------------
// Anomaly feature computation
// ---------------------------------------------------------------------------

fn compute_shannon_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() { freq[b as usize] += 1; }
    let len = s.len() as f32;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f32 / len;
        -p * p.log2()
    }).sum()
}

fn contains_sqli(path: &str, query: &HashMap<String, String>) -> bool {
    let patterns = ["union select", "' or ", "1=1", "drop table", "insert into",
                    "delete from", "update set", "--", "/*", "*/", "xp_", "exec(",
                    "char(", "concat(", "benchmark(", "sleep("];
    let check = |s: &str| -> bool {
        let lower = s.to_lowercase();
        patterns.iter().any(|p| lower.contains(p))
    };
    check(path) || query.values().any(|v| check(v))
}

fn contains_xss(path: &str, query: &HashMap<String, String>) -> bool {
    let patterns = ["<script", "javascript:", "onerror=", "onload=", "onfocus=",
                    "onmouseover=", "<img", "<svg", "<iframe", "alert(", "document.cookie"];
    let check = |s: &str| -> bool {
        let lower = s.to_lowercase();
        patterns.iter().any(|p| lower.contains(p))
    };
    check(path) || query.values().any(|v| check(v))
}

fn compute_anomaly_features(path: &str, query: &HashMap<String, String>, body_len: usize) -> AnomalyFeatures {
    AnomalyFeatures {
        path_depth: path.matches('/').count().min(255) as u8,
        query_param_count: query.len().min(255) as u8,
        has_encoded_chars: path.contains('%'),
        request_size_bucket: if body_len == 0 { 0 } else { (body_len as f64).log2() as u8 },
        shannon_entropy: compute_shannon_entropy(path),
        has_sqli_pattern: contains_sqli(path, query),
        has_xss_pattern: contains_xss(path, query),
        has_path_traversal: path.contains("../") || path.contains("..\\"),
    }
}

/// Scan for the next valid HTTP/2 frame boundary at or after `start`.
fn find_next_frame_boundary(buf: &[u8], start: usize) -> usize {
    let mut i = start;
    while i + 9 <= buf.len() {
        let frame_len = ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | (buf[i + 2] as usize);
        let frame_type = buf[i + 3];
        if frame_len <= 16384 && frame_type <= 9 && i + 9 + frame_len <= buf.len() {
            return i;
        }
        i += 1;
    }
    buf.len()
}

/// Atomic CAS memory reservation — returns true if reservation succeeded.
/// Uses fetch_update to avoid TOCTOU races between check and increment.
/// `checked_add` defends against an attacker-controlled or buggy `additional`
/// that could otherwise overflow `usize`.
fn reserve_memory(max_total: usize, additional: usize) -> bool {
    TOTAL_BUFFER_BYTES
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            match current.checked_add(additional) {
                Some(next) if next <= max_total => Some(next),
                _ => None,
            }
        })
        .is_ok()
}

// ---------------------------------------------------------------------------
// Event builders
// ---------------------------------------------------------------------------

// Kept for a future WS-session event; per-frame HTTP emission was removed.
#[allow(dead_code)]
pub fn build_ws_event(
    account_id: u64,
    ts_ms: u64,
    opcode_name: String,
    payload: String,
    net_ctx: NetContext,
) -> ApiTrafficEvent {
    ApiTrafficEvent {
        version: "v1".to_string(),
        event_type: "ws_message".to_string(),
        source: "ebpf".to_string(),
        protocol: "WebSocket".to_string(),
        account_id,
        observed_at: ts_ms,
        request: ApiRequest {
            method: opcode_name,
            path: "/ws".to_string(),
            host: None,
            scheme: "wss".to_string(),
            headers: HashMap::new(),
            query: HashMap::new(),
            body: Some(payload),
        },
        response: ApiResponse {
            status_code: 0,
            headers: HashMap::new(),
            body: None,
            latency_ms: None,
        },
        collection_id: None,
        source_ip: net_ctx.source_ip,
        dest_ip: net_ctx.dest_ip,
        source_port: net_ctx.source_port,
        dest_port: net_ctx.dest_port,
        netns_ino: net_ctx.netns_ino,
        cgroup_id: net_ctx.cgroup_id,
        container: net_ctx.container,
        process_name: net_ctx.process_name,
        source_hostname: net_ctx.source_hostname,
        dest_hostname: net_ctx.dest_hostname,
        metadata: None,
        anomaly_features: None,
        user_id: None,
        user_role: None,
        session_id: None,
        auth_session_id: None,
    }
}

pub fn build_event(
    account_id: u64,
    ts_ms: u64,
    req: ParsedRequest,
    resp: HttpResponseParsed,
    latency_ms: u64,
    protocol: &str,
    source: &str,
) -> ApiTrafficEvent {
    // Increment protocol counters
    match protocol {
        "HTTP/1.1" => PROTO_HTTP1.fetch_add(1, Ordering::Relaxed),
        "HTTP/2"   => PROTO_HTTP2.fetch_add(1, Ordering::Relaxed),
        "HTTP/3"   => PROTO_HTTP3.fetch_add(1, Ordering::Relaxed),
        "gRPC"     => PROTO_GRPC.fetch_add(1, Ordering::Relaxed),
        "WebSocket"=> PROTO_WEBSOCKET.fetch_add(1, Ordering::Relaxed),
        "MCP"      => PROTO_MCP.fetch_add(1, Ordering::Relaxed),
        "Go-TLS"   => PROTO_GO_TLS.fetch_add(1, Ordering::Relaxed),
        _          => 0,
    };

    // Compute anomaly features before redaction (on raw path/query)
    let (_, raw_query) = split_query(&req.path);
    let anomaly = compute_anomaly_features(&req.path, &raw_query, 0);

    // Extract identity from raw headers BEFORE PII redaction so JWT tokens
    // are still intact when we parse them.
    let identity = extract_identity(&req.headers);

    // Apply PII redaction to path and header values
    let redacted_path = redact_pii(&req.path);
    let (path, query) = split_query(&redacted_path);
    let net_ctx = req.net_ctx.clone();

    let redacted_req_headers: HashMap<String, String> = req.headers
        .into_iter()
        .map(|(k, v)| (k, redact_pii(&v)))
        .collect();

    // Redact response headers too (may contain Set-Cookie, tokens, etc.)
    let redacted_resp_headers: HashMap<String, String> = resp.headers
        .into_iter()
        .map(|(k, v)| (k, redact_pii(&v)))
        .collect();

    // Bodies are evidence: capture what the kernel gave us, redacted and capped.
    let req_body = redact_and_cap_body(&req.body);
    let resp_body = redact_and_cap_body(&resp.body);

    ApiTrafficEvent {
        version: "v1".to_string(),
        event_type: "api_traffic".to_string(),
        source: source.to_string(),
        protocol: protocol.to_string(),
        account_id,
        observed_at: ts_ms,
        request: ApiRequest {
            method: req.method,
            path,
            host: req.host,
            scheme: "https".to_string(),
            headers: redacted_req_headers,
            query,
            body: req_body,
        },
        response: ApiResponse {
            status_code: resp.status_code,
            headers: redacted_resp_headers,
            body: resp_body,
            latency_ms: Some(latency_ms),
        },
        collection_id: None,
        source_ip: net_ctx.source_ip,
        dest_ip: net_ctx.dest_ip,
        source_port: net_ctx.source_port,
        dest_port: net_ctx.dest_port,
        netns_ino: net_ctx.netns_ino,
        cgroup_id: net_ctx.cgroup_id,
        container: net_ctx.container,
        process_name: net_ctx.process_name,
        source_hostname: net_ctx.source_hostname,
        dest_hostname: net_ctx.dest_hostname,
        metadata: None,
        anomaly_features: Some(anomaly),
        user_id: Some(identity.user_id),
        user_role: Some(identity.user_role),
        session_id: Some(identity.session_id),
        auth_session_id: Some(identity.auth_session_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> ShardedStreamState {
        crate::redaction::init_pii_hash_key_for_tests(&[0x11u8; 32]);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let (dtx, _drx) = tokio::sync::mpsc::channel(8);
        ShardedStreamState::new(
            1,
            TrafficRole::Server,
            65_536,
            Arc::new(ContainerResolver::new(tx, "test-node".into())),
            10_485_760,
            Arc::new(DnsResolver::new(dtx)),
        )
    }

    fn tls_event(direction: u8) -> TlsEventHeader {
        TlsEventHeader {
            ts_ns: 1_700_000_000_000_000,
            pid: 42,
            tid: 42,
            ssl_ptr: 0x1000,
            data_len: 0,
            direction,
            ip_family: 4,
            _pad16: 0,
            comm: *b"nginx\0\0\0\0\0\0\0\0\0\0\0",
            cgroup_id: 0,
            netns_ino: 1,
            src_port: 43210,
            dst_port: 443,
            src_ip4: u32::from_be_bytes([10, 244, 0, 59]),
            dst_ip4: u32::from_be_bytes([10, 244, 0, 1]),
            src_ip6: [0; 16],
            dst_ip6: [0; 16],
        }
    }

    #[test]
    fn unpaired_http1_response_is_not_emitted_as_unknown() {
        let state = test_state();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let events = state.handle_event(&tls_event(1), resp);
        assert!(
            events.is_empty(),
            "unpaired response must not emit UNKNOWN /: {events:?}"
        );
    }

    #[test]
    fn paired_http1_request_response_keeps_method_and_path() {
        let state = test_state();
        let req = b"GET /api/sensors/ HTTP/1.1\r\nHost: sentinel.wecrew.in\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]";
        assert!(state.handle_event(&tls_event(0), req).is_empty());
        let events = state.handle_event(&tls_event(1), resp);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request.method, "GET");
        assert_eq!(events[0].request.path, "/api/sensors/");
        assert_eq!(events[0].response.status_code, 200);
    }

    #[test]
    fn garbage_request_then_response_is_not_emitted_as_unknown() {
        let state = test_state();
        let garbage = b"FOO /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        let _ = state.handle_event(&tls_event(0), garbage);
        let events = state.handle_event(&tls_event(1), resp);
        assert!(
            events.iter().all(|e| e.request.method != "UNKNOWN"),
            "garbage request must not become UNKNOWN /: {events:?}"
        );
        assert!(events.is_empty());
    }

    #[test]
    fn websocket_frames_are_not_emitted_as_http() {
        let state = test_state();
        let req = b"GET /api/stream/live HTTP/1.1\r\nHost: sentinel.wecrew.in\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(state.handle_event(&tls_event(0), req).is_empty());
        let upgrade = state.handle_event(&tls_event(1), resp);
        assert_eq!(upgrade.len(), 1);
        assert_eq!(upgrade[0].request.method, "GET");
        assert_eq!(upgrade[0].request.path, "/api/stream/live");
        assert_eq!(upgrade[0].response.status_code, 101);

        // Unmasked TEXT frame: FIN+text, len=5, "hello"
        let frame = [0x81u8, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let events = state.handle_event(&tls_event(0), &frame);
        assert!(
            events.is_empty(),
            "WS frames must not appear as TEXT /ws: {events:?}"
        );
    }

    /// 9-byte HTTP/2 frame header + payload.
    fn h2_frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut f = vec![
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
            ftype,
            flags,
        ];
        f.extend_from_slice(&stream_id.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// HPACK literal-without-indexing (4-bit prefix) with an indexed name.
    fn hpack_literal(name_index: u8, value: &str) -> Vec<u8> {
        let mut b = if name_index < 15 {
            vec![name_index]
        } else {
            vec![0x0f, name_index - 15]
        };
        b.push(value.len() as u8); // raw string, no Huffman
        b.extend_from_slice(value.as_bytes());
        b
    }

    #[test]
    fn grpc_response_body_decodes_data_frame_payload_not_frame_headers() {
        let state = test_state();

        // Request: :method POST (static idx 3), :path literal (name idx 4),
        // content-type literal (name idx 31).
        let mut req_hpack = vec![0x83u8];
        req_hpack.extend(hpack_literal(4, "/pkg.Svc/Method"));
        req_hpack.extend(hpack_literal(31, "application/grpc"));
        let mut req = HTTP2_PREFACE.to_vec();
        req.extend(h2_frame(0x01, 0x05, 1, &req_hpack)); // HEADERS END_STREAM|END_HEADERS
        assert!(state.handle_event(&tls_event(0), &req).is_empty());

        // Response: HEADERS (:status 200 = static idx 8, grpc content-type)
        // then a DATA frame carrying the gRPC message:
        // [compress=0][len=6][protobuf: field 1, wire type 2, "test"]
        let mut resp_hpack = vec![0x88u8];
        resp_hpack.extend(hpack_literal(31, "application/grpc"));
        let grpc_msg = [0x00, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x04, b't', b'e', b's', b't'];
        let mut resp = h2_frame(0x01, 0x04, 1, &resp_hpack); // HEADERS END_HEADERS
        resp.extend(h2_frame(0x00, 0x01, 1, &grpc_msg)); // DATA END_STREAM

        let events = state.handle_event(&tls_event(1), &resp);
        assert_eq!(events.len(), 1, "expected one paired gRPC event: {events:?}");
        assert_eq!(events[0].protocol, "gRPC");
        let body = events[0].response.body.as_deref().expect("gRPC body decoded");
        let fields: serde_json::Value = serde_json::from_str(body).unwrap();
        let arr = fields.as_array().expect("JSON array of proto fields");
        assert_eq!(arr.len(), 1, "exactly the one real proto field, got {body}");
        assert_eq!(arr[0]["field_number"], 1);
        assert_eq!(arr[0]["wire_type"], 2);
        assert!(
            arr[0]["value_str"].as_str().unwrap().contains("test"),
            "decoded value should contain 'test': {body}"
        );
    }

    #[test]
    fn http1_captures_and_redacts_request_and_response_bodies() {
        let state = test_state();
        let body = "{\"email\":\"alice@example.com\"}";
        let req = format!(
            "POST /api/login HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        assert!(state.handle_event(&tls_event(0), req.as_bytes()).is_empty());

        let resp_body = "{\"status\":\"ok\"}";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(), resp_body
        );
        let events = state.handle_event(&tls_event(1), resp.as_bytes());
        assert_eq!(events.len(), 1);

        let rb = events[0].request.body.as_deref().expect("request body captured");
        assert!(!rb.contains("alice@example.com"), "email must be redacted: {rb}");
        assert!(rb.contains("PII_EMAIL_"), "expected redaction token: {rb}");

        let respb = events[0].response.body.as_deref().expect("response body captured");
        assert!(respb.contains("ok"), "response body should be captured: {respb}");
    }

    #[test]
    fn oversized_request_body_is_capped() {
        let state = test_state();
        let big = "a".repeat(20_000);
        let req = format!(
            "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n{}",
            big.len(), big
        );
        assert!(state.handle_event(&tls_event(0), req.as_bytes()).is_empty());
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let events = state.handle_event(&tls_event(1), resp);
        assert_eq!(events.len(), 1);
        let rb = events[0].request.body.as_deref().expect("request body captured");
        assert!(
            rb.len() <= MAX_BODY_CAPTURE_BYTES,
            "body must be capped to {MAX_BODY_CAPTURE_BYTES}, got {}",
            rb.len()
        );
    }

    #[test]
    fn emitted_event_uses_wall_clock_not_boot_time() {
        let state = test_state();
        let req = b"GET /live-clock HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(state.handle_event(&tls_event(0), req).is_empty());
        let events = state.handle_event(&tls_event(1), resp);
        assert_eq!(events.len(), 1);
        // 2024-01-01 epoch ms; boot-time conversion produced ~2026-08-09.
        assert!(
            events[0].observed_at > 1_704_067_200_000,
            "observed_at should be wall-clock ms, got {}",
            events[0].observed_at
        );
    }
}
