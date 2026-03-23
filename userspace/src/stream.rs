use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;

use crate::container::ContainerResolver;
use crate::dns::{self, DnsResolver};
use crate::grpc::decode_grpc_fields;
use crate::http::{HttpMessage, HttpResponseParsed, extract_http_header, split_query};
use crate::http2::{Http2HpackDecoder, contains_http2_preface, parse_http2_frames};
use crate::mcp::{is_mcp_response, is_mcp_jsonrpc, parse_sse_events, parse_jsonrpc_mcp};
use crate::metrics::*;
use crate::quic;
use crate::redaction::redact_pii;
use crate::types::*;
use crate::websocket::{parse_websocket_frame, ws_opcode_name};

const MAX_PENDING_PER_CONN: usize = 100;
const MAX_H2_PENDING_STREAMS: usize = 200;

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
                if let Some((buf, _)) = self.buffers.remove(&k) { freed_bytes += buf.len(); }
            }
        }
        if self.http2_state.len() > MAX_STREAM_ENTRIES {
            let excess = self.http2_state.len() - MAX_STREAM_ENTRIES;
            let mut keys: Vec<_> = self.http2_state.keys().cloned().collect();
            keys.sort_by_key(|k| self.http2_state.get(k).map(|c| c.last_event_ts).unwrap_or(0));
            for k in keys.into_iter().take(excess) {
                if let Some(conn) = self.http2_state.remove(&k) { freed_bytes += conn.buffer.len(); }
            }
        }

        if freed_bytes > 0 { release_memory(freed_bytes); }

        self.known_connections.retain(|k| {
            let still_active = self.pending.contains_key(k) || self.http2_state.contains_key(k) || self.ws_connections.contains(k) || self.http3_connections.contains(k);
            if !still_active {
                ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                self.conn_born_ms.remove(&(k.pid, k.ssl_ptr));
            }
            still_active
        });
        self.ws_connections.retain(|k| self.known_connections.contains(k));
        self.http3_connections.retain(|k| self.known_connections.contains(k));
    }

    fn evict_connection_by_ptr(&mut self, pid: u32, ssl_ptr: u64) {
        let mut freed_bytes: usize = 0;
        self.buffers.retain(|k, (buf, _)| {
            if k.pid == pid && k.ssl_ptr == ssl_ptr { freed_bytes += buf.len(); false } else { true }
        });
        self.pending.retain(|k, _| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
        self.http2_state.retain(|k, conn| {
            if k.pid == pid && k.ssl_ptr == ssl_ptr { freed_bytes += conn.buffer.len(); false } else { true }
        });
        self.ws_connections.retain(|k| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
        self.http3_connections.retain(|k| !(k.pid == pid && k.ssl_ptr == ssl_ptr));

        let before = self.known_connections.len();
        self.known_connections.retain(|k| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
        let evicted = before - self.known_connections.len();
        if evicted > 0 { ACTIVE_CONNECTIONS.fetch_sub(evicted as u64, Ordering::Relaxed); }
        self.conn_born_ms.remove(&(pid, ssl_ptr));
        if freed_bytes > 0 { release_memory(freed_bytes); }
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
        ctx.process_name = dns::read_process_name(ev.pid, &ev.comm);
        if let Some(ref ip) = ctx.source_ip { ctx.source_hostname = self.dns_resolver.lookup_and_queue(ip); }
        if let Some(ref ip) = ctx.dest_ip { ctx.dest_hostname = self.dns_resolver.lookup_and_queue(ip); }
        ctx
    }

    fn handle_event(&mut self, ev: &TlsEventHeader, payload: &[u8]) -> Vec<ApiTrafficEvent> {
        let mut output = Vec::new();
        let ts_ms = ev.ts_ns / 1_000_000;
        let born_ms = *self.conn_born_ms.entry((ev.pid, ev.ssl_ptr)).or_insert(ts_ms);
        let conn_key = ConnKey { pid: ev.pid, ssl_ptr: ev.ssl_ptr, born_ms };
        let stream_key = StreamKey { pid: ev.pid, ssl_ptr: ev.ssl_ptr, direction: ev.direction };
        let data_len = payload.len();

        self.evict_stale(ts_ms);

        if self.known_connections.insert(conn_key.clone()) {
            ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        }

        // direction: 0=TLS read, 1=TLS write, 2=H3 read, 3=H3 write
        let is_h3_event = ev.direction >= 2;
        let is_request_dir = match self.role {
            TrafficRole::Server => ev.direction == 0 || ev.direction == 2,
            TrafficRole::Client => ev.direction == 1 || ev.direction == 3,
        };

        // QUIC/HTTP3 body events (direction 2/3) — create event directly
        if is_h3_event && data_len > 0 {
            self.http3_connections.insert(conn_key.clone());
            PROTO_HTTP3.fetch_add(1, Ordering::Relaxed);
            let net_ctx = self.net_context_from_event(ev);
            let body_str = String::from_utf8_lossy(payload).to_string();
            if is_request_dir {
                let queue = self.pending.entry(conn_key.clone()).or_default();
                if queue.len() < MAX_PENDING_PER_CONN {
                    queue.push_back(ParsedRequest {
                        method: "GET".to_string(), path: "/".to_string(), host: None,
                        headers: HashMap::new(), body: Some(body_str), ts_ms, net_ctx,
                    });
                }
            } else {
                let request = self.pending.entry(conn_key.clone()).or_default()
                    .pop_front()
                    .unwrap_or_else(|| ParsedRequest {
                        method: "GET".to_string(), path: "/".to_string(), host: None,
                        headers: HashMap::new(), body: None, ts_ms, net_ctx: NetContext::default(),
                    });
                let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                let resp = HttpResponseParsed { status_code: 200, headers: HashMap::new(), body: Some(body_str) };
                output.push(build_event(self.account_id, ts_ms, request, resp, latency_ms, "HTTP/3", "ebpf"));
            }
            return output;
        }

        // Accumulate data for this stream to handle split packets/prefaces
        {
            let (buf, _last_seen) = self.buffers.entry(stream_key.clone()).or_insert_with(|| (Vec::new(), ts_ms));
            if reserve_memory(self.max_total_buffer_bytes, data_len) {
                buf.extend_from_slice(payload);
            } else {
                EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }

        // HTTP/2 check — check accumulated buffer for preface
        // We extract data from the buffer in a separate scope to avoid double mutable borrow.
        let is_known_h2 = self.http2_state.contains_key(&conn_key);
        let (has_preface, h2_data) = if let Some((buf, _)) = self.buffers.get(&stream_key) {
            let preface = if !is_known_h2 { contains_http2_preface(buf) } else { false };
            if is_known_h2 || preface {
                (preface, Some(buf.clone()))
            } else {
                (false, None)
            }
        } else {
            (false, None)
        };

        if let Some(h1_data) = h2_data {
            if let Some((buf, _)) = self.buffers.get_mut(&stream_key) {
                buf.clear();
            }
            if let Some(events) = self.process_http2_event(conn_key.clone(), ev, &h1_data, ts_ms, is_request_dir, has_preface) {
                return events;
            }
        }

        if data_len == 0 { return output; }

        // HTTP/3 check
        let is_known_h3 = self.http3_connections.contains(&conn_key);
        if is_known_h3 || (!is_known_h2 && quic::looks_like_http3(payload)) {
            self.http3_connections.insert(conn_key.clone());
            let header_sets = quic::extract_h3_headers(payload);
            for headers in header_sets {
                if is_request_dir {
                    if let Some(method) = headers.get(":method") {
                        let path = headers.get(":path").cloned().unwrap_or_else(|| "/".to_string());
                        let host = headers.get(":authority").cloned();
                        let net_ctx = self.net_context_from_event(ev);
                        let queue = self.pending.entry(conn_key.clone()).or_default();
                        if queue.len() < MAX_PENDING_PER_CONN {
                            queue.push_back(ParsedRequest {
                                method: method.clone(), path, host, headers: headers.clone(),
                                body: None, ts_ms, net_ctx,
                            });
                        }
                    }
                } else if let Some(status) = headers.get(":status") {
                    let request = self.pending.entry(conn_key.clone()).or_default()
                        .pop_front()
                        .unwrap_or_else(|| ParsedRequest {
                            method: "UNKNOWN".to_string(), path: "/".to_string(), host: None,
                            headers: HashMap::new(), body: None, ts_ms, net_ctx: NetContext::default(),
                        });
                    let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                    let resp = HttpResponseParsed { status_code: status.parse::<i32>().unwrap_or(0), headers: headers.clone(), body: None };
                    output.push(build_event(self.account_id, ts_ms, request, resp, latency_ms, "HTTP/3", "ebpf"));
                }
            }
            return output;
        }

        // WebSocket check
        if self.ws_connections.contains(&conn_key) {
            let mut pos = 0;
            while pos < payload.len() {
                match parse_websocket_frame(&payload[pos..]) {
                    Some((frame, consumed)) => {
                        if consumed == 0 { break; }
                        let opcode_name = ws_opcode_name(frame.opcode).to_string();
                        let payload_str = String::from_utf8_lossy(&frame.payload).into_owned();
                        let redacted_payload = redact_pii(&payload_str);
                        let net_ctx = self.net_context_from_event(ev);
                        output.push(build_ws_event(self.account_id, ts_ms, opcode_name, redacted_payload, net_ctx));
                        PROTO_WEBSOCKET.fetch_add(1, Ordering::Relaxed);
                        pos += consumed;
                    }
                    None => break,
                }
            }
            return output;
        }

        // HTTP/1.1 parsing — re-borrow the buffer after h2/h3/ws checks
        let (buf, last_seen) = self.buffers.entry(stream_key.clone()).or_insert_with(|| (Vec::new(), ts_ms));
        *last_seen = ts_ms;
        if buf.len() > self.max_buffer {
            let drain = buf.len() - self.max_buffer;
            release_memory(drain);
            buf.drain(0..drain);
        }

        let mut msgs = Vec::new();
        let before_len = buf.len();
        while let Some((msg, remaining)) = extract_http_header(buf) {
            msgs.push(msg);
            *buf = remaining;
        }
        let consumed = before_len.saturating_sub(buf.len());
        if consumed > 0 { release_memory(consumed); }

        for msg in msgs {
            match msg {
                HttpMessage::Request(req) => {
                    if is_request_dir {
                        let net_ctx = self.net_context_from_event(ev);
                        let queue = self.pending.entry(conn_key.clone()).or_default();
                        if queue.len() < MAX_PENDING_PER_CONN {
                            queue.push_back(ParsedRequest {
                                method: req.method, path: req.path, host: req.host, headers: req.headers,
                                body: req.body, ts_ms, net_ctx,
                            });
                        }
                    }
                }
                HttpMessage::Response(resp) => {
                    if is_request_dir { continue; }
                    let upgrade_hdr = resp.headers.get("upgrade").map(|v| v.to_lowercase());
                    if upgrade_hdr.as_deref() == Some("websocket") { self.ws_connections.insert(conn_key.clone()); }

                    let is_mcp_sse = is_mcp_response(&resp.headers);
                    let request = self.pending.entry(conn_key.clone()).or_default().pop_front()
                        .unwrap_or_else(|| ParsedRequest {
                            method: "UNKNOWN".to_string(), path: "/".to_string(), host: None,
                            headers: HashMap::new(), body: None, ts_ms, net_ctx: NetContext::default(),
                        });
                    // Also detect MCP from JSON-RPC 2.0 request body with MCP methods
                    let is_mcp_json = !is_mcp_sse &&
                        request.body.as_deref().map(|b| is_mcp_jsonrpc(b)).unwrap_or(false);
                    let is_mcp = is_mcp_sse || is_mcp_json;

                    // Extract response body for MCP analysis before build_event consumes it
                    let mcp_resp_body = if is_mcp_json {
                        resp.body.clone().or_else(|| request.body.clone())
                    } else { None };

                    let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                    let protocol = if is_mcp { "MCP" } else { "HTTP/1.1" };
                    let mut event = build_event(self.account_id, ts_ms, request, resp, latency_ms, protocol, "ebpf");
                    if is_mcp {
                        if is_mcp_sse {
                            let mcp_events = parse_sse_events(payload);
                            if let Some(mcp_ev) = mcp_events.first() {
                                event.metadata = Some(EventMetadata {
                                    has_injection: mcp_ev.has_injection,
                                    injection_patterns: if mcp_ev.has_injection { vec!["prompt_injection".to_string()] } else { vec![] },
                                    permission_flags: mcp_ev.permission_flags.clone(),
                                    mcp_method: mcp_ev.method.clone(),
                                    mcp_tool_name: mcp_ev.tool_name.clone(),
                                });
                            }
                        } else if let Some(body) = mcp_resp_body {
                            if let Some(mcp_ev) = parse_jsonrpc_mcp(&body) {
                                event.metadata = Some(EventMetadata {
                                    has_injection: mcp_ev.has_injection,
                                    injection_patterns: if mcp_ev.has_injection { vec!["prompt_injection".to_string()] } else { vec![] },
                                    permission_flags: mcp_ev.permission_flags.clone(),
                                    mcp_method: mcp_ev.method.clone(),
                                    mcp_tool_name: mcp_ev.tool_name.clone(),
                                });
                            }
                        }
                    }
                    output.push(event);
                }
            }
        }
        output
    }

    fn process_http2_event(&mut self, conn_key: ConnKey, ev: &TlsEventHeader, payload: &[u8], ts_ms: u64, is_request_dir: bool, data_has_preface: bool) -> Option<Vec<ApiTrafficEvent>> {
        let net_ctx = if is_request_dir { Some(self.net_context_from_event(ev)) } else { None };
        let conn_state = self.http2_state.entry(conn_key).or_default();
        conn_state.last_event_ts = ts_ms;
        if data_has_preface { conn_state.seen_preface = true; }

        let data_len = payload.len();
        if data_len == 0 { return Some(vec![]); }
        if !reserve_memory(self.max_total_buffer_bytes, data_len) {
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return Some(vec![]);
        }
        conn_state.buffer.extend_from_slice(payload);

        if !conn_state.seen_preface {
            if contains_http2_preface(&conn_state.buffer) { conn_state.seen_preface = true; } else { return None; }
        }

        let mut output = Vec::new();
        if conn_state.buffer.len() > self.max_buffer * 2 {
            let target_drain = conn_state.buffer.len() - self.max_buffer;
            let boundary = find_next_frame_boundary(&conn_state.buffer, target_drain);
            if boundary > 0 { release_memory(boundary); conn_state.buffer.drain(0..boundary); }
        }

        let stream_frames = parse_http2_frames(&mut conn_state.hpack, &conn_state.buffer);
        for (stream_id, headers) in stream_frames {
            if is_request_dir {
                if let Some(method) = headers.get(":method") {
                    let path = headers.get(":path").cloned().unwrap_or_else(|| "/".to_string());
                    let host = headers.get(":authority").cloned();
                    if conn_state.pending_requests.len() < MAX_H2_PENDING_STREAMS {
                        conn_state.pending_requests.insert(stream_id, ParsedRequest {
                            method: method.clone(), path, host, headers: headers.clone(), body: None, ts_ms,
                            net_ctx: net_ctx.clone().unwrap_or_default(),
                        });
                    }
                }
            } else if let Some(status) = headers.get(":status") {
                let request = conn_state.pending_requests.remove(&stream_id)
                    .unwrap_or_else(|| ParsedRequest {
                        method: "UNKNOWN".to_string(), path: "/".to_string(), host: None,
                        headers: HashMap::new(), body: None, ts_ms, net_ctx: NetContext::default(),
                    });
                let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                let resp = HttpResponseParsed { status_code: status.parse::<i32>().unwrap_or(0), headers: headers.clone(), body: None };
                let is_grpc = headers.get("content-type").map(|v| v.starts_with("application/grpc")).unwrap_or(false)
                    || request.headers.get("content-type").map(|v| v.starts_with("application/grpc")).unwrap_or(false);
                let grpc_body = if is_grpc {
                    let fields = decode_grpc_fields(&conn_state.buffer);
                    if !fields.is_empty() { serde_json::to_string(&fields).ok() } else { None }
                } else { None };

                let protocol = if is_grpc { "gRPC" } else { "HTTP/2" };
                let mut event = build_event(self.account_id, ts_ms, request, resp, latency_ms, protocol, "ebpf");
                if let Some(body) = grpc_body { event.response.body = Some(body); }
                output.push(event);
            }
        }
        // Only clear buffer when it grows too large or all frames have been consumed.
        // This preserves in-flight data for other multiplexed HTTP/2 streams.
        if conn_state.buffer.len() > self.max_buffer {
            let cleared = conn_state.buffer.len();
            conn_state.buffer.clear();
            release_memory(cleared);
        }
        Some(output)
    }
}

pub fn build_ws_event(account_id: u64, ts_ms: u64, opcode_name: String, payload: String, net_ctx: NetContext) -> ApiTrafficEvent {
    ApiTrafficEvent {
        version: "v1".to_string(), event_type: "ws_message".to_string(), source: "ebpf".to_string(), protocol: "WebSocket".to_string(),
        account_id, observed_at: ts_ms,
        request: ApiRequest {
            method: opcode_name, path: "/ws".to_string(), host: None, scheme: "wss".to_string(),
            headers: HashMap::new(), query: HashMap::new(), body: Some(payload),
        },
        response: ApiResponse { status_code: 0, headers: HashMap::new(), body: None, latency_ms: None },
        collection_id: None, source_ip: net_ctx.source_ip, dest_ip: net_ctx.dest_ip, source_port: net_ctx.source_port, dest_port: net_ctx.dest_port,
        netns_ino: net_ctx.netns_ino, cgroup_id: net_ctx.cgroup_id, container: net_ctx.container, process_name: net_ctx.process_name,
        source_hostname: net_ctx.source_hostname, dest_hostname: net_ctx.dest_hostname, metadata: None, anomaly_features: None,
    }
}

pub fn build_event(account_id: u64, ts_ms: u64, req: ParsedRequest, resp: HttpResponseParsed, latency_ms: u64, protocol: &str, source: &str) -> ApiTrafficEvent {
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

    let redacted_path = redact_pii(&req.path);
    let (path, query) = split_query(&redacted_path);
    let net_ctx = req.net_ctx;

    ApiTrafficEvent {
        version: "v1".to_string(), event_type: "api_traffic".to_string(), source: source.to_string(), protocol: protocol.to_string(),
        account_id, observed_at: ts_ms,
        request: ApiRequest {
            method: req.method, path, host: req.host, scheme: "https".to_string(),
            headers: req.headers.into_iter().map(|(k,v)| (k, redact_pii(&v))).collect(),
            query, body: req.body.map(|b| redact_pii(&b)),
        },
        response: ApiResponse {
            status_code: resp.status_code,
            headers: resp.headers.into_iter().map(|(k,v)| (k, redact_pii(&v))).collect(),
            body: resp.body.map(|b| redact_pii(&b)),
            latency_ms: Some(latency_ms),
        },
        collection_id: None, source_ip: net_ctx.source_ip, dest_ip: net_ctx.dest_ip, source_port: net_ctx.source_port, dest_port: net_ctx.dest_port,
        netns_ino: net_ctx.netns_ino, cgroup_id: net_ctx.cgroup_id, container: net_ctx.container, process_name: net_ctx.process_name,
        source_hostname: net_ctx.source_hostname, dest_hostname: net_ctx.dest_hostname,
        metadata: None,
        anomaly_features: None,
    }
}

fn find_next_frame_boundary(buf: &[u8], start: usize) -> usize {
    let mut i = start;
    while i + 9 <= buf.len() {
        let frame_len = ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | (buf[i + 2] as usize);
        let frame_type = buf[i + 3];
        if frame_len <= 16384 && frame_type <= 9 && i + 9 + frame_len <= buf.len() { return i; }
        i += 1;
    }
    buf.len()
}

fn reserve_memory(max_total: usize, additional: usize) -> bool {
    TOTAL_BUFFER_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        if current + additional <= max_total { Some(current + additional) } else { None }
    }).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    /// Reset global atomic counters to avoid cross-test interference.
    fn reset_metrics() {
        TOTAL_BUFFER_BYTES.store(0, Ordering::Relaxed);
        EVENTS_DROPPED.store(0, Ordering::Relaxed);
        ACTIVE_CONNECTIONS.store(0, Ordering::Relaxed);
        PROTO_HTTP1.store(0, Ordering::Relaxed);
        PROTO_HTTP2.store(0, Ordering::Relaxed);
        PROTO_HTTP3.store(0, Ordering::Relaxed);
        PROTO_WEBSOCKET.store(0, Ordering::Relaxed);
    }

    fn make_sharded(max_total_buffer_bytes: usize) -> ShardedStreamState {
        let (lookup_tx, _lookup_rx) = tokio::sync::mpsc::channel(1);
        let container_resolver = Arc::new(ContainerResolver::new(lookup_tx, "test-node".to_string()));
        let (dns_tx, _dns_rx) = tokio::sync::mpsc::channel(1);
        let dns_resolver = Arc::new(DnsResolver::new(dns_tx));
        ShardedStreamState::new(
            42,                       // account_id
            TrafficRole::Server,      // role
            64 * 1024,                // max_buffer
            container_resolver,
            max_total_buffer_bytes,   // max_total_buffer_bytes
            dns_resolver,
        )
    }

    fn make_event(pid: u32, ssl_ptr: u64, direction: u8, data_len: u32, ts_ns: u64) -> TlsEventHeader {
        TlsEventHeader {
            ts_ns,
            pid,
            tid: 0,
            ssl_ptr,
            data_len,
            direction,
            ip_family: 0,
            _pad16: 0,
            comm: *b"test-process\0\0\0\0",
            cgroup_id: 0,
            netns_ino: 0,
            src_port: 0,
            dst_port: 0,
            src_ip4: 0,
            dst_ip4: 0,
            src_ip6: [0u8; 16],
            dst_ip6: [0u8; 16],
        }
    }

    // -----------------------------------------------------------------------
    // 1. HTTP/1.1 request/response correlation
    // -----------------------------------------------------------------------
    #[test]
    fn test_http1_request_response_correlation() {
        reset_metrics();
        let ss = make_sharded(10 * 1024 * 1024);

        let req_payload = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let resp_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

        // direction=0 means TLS read, which is request direction for Server role
        let req_ev = make_event(100, 0xABCD, 0, req_payload.len() as u32, 1_000_000_000);
        let events = ss.handle_event(&req_ev, req_payload);
        // Request alone should not produce output yet
        assert!(events.is_empty(), "request alone should not emit events");

        // direction=1 means TLS write, which is response direction for Server role
        let resp_ev = make_event(100, 0xABCD, 1, resp_payload.len() as u32, 1_001_000_000);
        let events = ss.handle_event(&resp_ev, resp_payload);

        assert_eq!(events.len(), 1, "expected exactly one correlated event");
        let ev = &events[0];
        assert_eq!(ev.protocol, "HTTP/1.1");
        assert_eq!(ev.request.method, "GET");
        assert_eq!(ev.request.path, "/api/users");
        assert_eq!(ev.response.status_code, 200);
        assert_eq!(ev.account_id, 42);
        assert!(ev.response.latency_ms.unwrap() > 0, "latency should be > 0");
    }

    // -----------------------------------------------------------------------
    // 2. HTTP/1.1 pipelining (FIFO correlation)
    // -----------------------------------------------------------------------
    #[test]
    fn test_http1_pipelining() {
        reset_metrics();
        let ss = make_sharded(10 * 1024 * 1024);

        let req1 = b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req2 = b"POST /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let resp2 = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";

        let ts_base: u64 = 2_000_000_000;
        let pid = 200;
        let ssl = 0x1111;

        // Send both requests
        let ev = make_event(pid, ssl, 0, req1.len() as u32, ts_base);
        assert!(ss.handle_event(&ev, req1).is_empty());
        let ev = make_event(pid, ssl, 0, req2.len() as u32, ts_base + 1_000_000);
        assert!(ss.handle_event(&ev, req2).is_empty());

        // Send first response — should correlate with first request (FIFO)
        let ev = make_event(pid, ssl, 1, resp1.len() as u32, ts_base + 10_000_000);
        let out = ss.handle_event(&ev, resp1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].request.method, "GET");
        assert_eq!(out[0].request.path, "/first");
        assert_eq!(out[0].response.status_code, 200);

        // Send second response — should correlate with second request
        let ev = make_event(pid, ssl, 1, resp2.len() as u32, ts_base + 20_000_000);
        let out = ss.handle_event(&ev, resp2);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].request.method, "POST");
        assert_eq!(out[0].request.path, "/second");
        assert_eq!(out[0].response.status_code, 201);
    }

    // -----------------------------------------------------------------------
    // 3. WebSocket upgrade detection
    // -----------------------------------------------------------------------
    #[test]
    fn test_websocket_upgrade_detection() {
        reset_metrics();
        let ss = make_sharded(10 * 1024 * 1024);
        let pid = 300;
        let ssl = 0x2222;
        let ts_base: u64 = 3_000_000_000;

        // HTTP upgrade request
        let req = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let ev = make_event(pid, ssl, 0, req.len() as u32, ts_base);
        assert!(ss.handle_event(&ev, req).is_empty());

        // HTTP 101 Switching Protocols response with Upgrade header
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let ev = make_event(pid, ssl, 1, resp.len() as u32, ts_base + 1_000_000);
        let out = ss.handle_event(&ev, resp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].response.status_code, 101);

        // Now send a WebSocket frame (unmasked text frame with "hello")
        // Opcode 0x1 = text, FIN=1, no mask, payload_len=5
        let mut ws_frame = vec![0x81u8, 0x05]; // FIN + text opcode, len=5
        ws_frame.extend_from_slice(b"hello");
        let ev = make_event(pid, ssl, 1, ws_frame.len() as u32, ts_base + 2_000_000);
        let out = ss.handle_event(&ev, &ws_frame);

        assert_eq!(out.len(), 1, "expected one WebSocket event");
        assert_eq!(out[0].protocol, "WebSocket");
        assert_eq!(out[0].event_type, "ws_message");
        assert_eq!(out[0].request.method, "text"); // opcode name
        assert!(out[0].request.body.as_ref().unwrap().contains("hello"));
    }

    // -----------------------------------------------------------------------
    // 4. Connection eviction (stale connections)
    // -----------------------------------------------------------------------
    #[test]
    fn test_connection_eviction() {
        reset_metrics();
        let ss = make_sharded(10 * 1024 * 1024);

        let pid = 400;
        let ssl = 0x3333;

        // Create a connection with an old timestamp
        let old_ts: u64 = 100_000_000_000; // 100 seconds in ns
        let req = b"GET /old HTTP/1.1\r\nHost: old.com\r\n\r\n";
        let ev = make_event(pid, ssl, 0, req.len() as u32, old_ts);
        ss.handle_event(&ev, req);

        // Verify the connection is active
        let active_before = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
        assert!(active_before >= 1, "should have at least one active connection");

        // Now send an event with a much later timestamp (> STREAM_TTL_MS=60s later)
        // and the eviction interval (10s) has passed. Use different ssl_ptr to avoid
        // reusing the same connection.
        let new_ts: u64 = old_ts + 120_000_000_000; // 120 seconds later
        let new_ssl = 0x4444;
        let req2 = b"GET /new HTTP/1.1\r\nHost: new.com\r\n\r\n";
        let ev2 = make_event(pid, new_ssl, 0, req2.len() as u32, new_ts);
        ss.handle_event(&ev2, req2);

        // The eviction should have cleaned up the old connection's buffers.
        // We verify by evicting explicitly and checking the conn is gone.
        let conn_key = ConnKey { pid, ssl_ptr: ssl, born_ms: old_ts / 1_000_000 };
        ss.evict_connection(&conn_key);

        // After explicit eviction, the old connection should be cleaned up.
        // Send a response on the old connection — it should produce an UNKNOWN
        // request correlation since the pending queue was evicted.
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        // Use old_ts + small delta so we don't trigger another eviction pass
        let ev_resp = make_event(pid, ssl, 1, resp.len() as u32, old_ts + 1_000_000);
        let out = ss.handle_event(&ev_resp, resp);
        // Should correlate with a synthetic UNKNOWN request since original was evicted
        if !out.is_empty() {
            assert_eq!(out[0].request.method, "UNKNOWN");
        }
    }

    // -----------------------------------------------------------------------
    // 5. Memory limit enforcement
    // -----------------------------------------------------------------------
    #[test]
    fn test_memory_limit_enforcement() {
        reset_metrics();
        // Use a limit of 1 byte so that ANY payload will fail to reserve.
        // The global TOTAL_BUFFER_BYTES may have residual value from parallel
        // tests, but with max_total=1 the reserve_memory check
        // `current + additional <= 1` will fail for any payload > 1 byte
        // unless current happens to be 0 (in which case the first succeeds
        // and the second fails).
        let ss = make_sharded(1);

        let pid = 500;
        let ssl = 0x5555;
        let ts: u64 = 5_000_000_000;

        let dropped_before = EVENTS_DROPPED.load(Ordering::Relaxed);

        // Feed incomplete HTTP data (no \r\n\r\n terminator) repeatedly.
        // With max_total_buffer_bytes=1, at most 1 byte can be reserved;
        // every subsequent payload will be dropped.
        let chunk = b"GET /incomplete HTTP/1.1\r\nHost: example.com\r\nX-Data: padding";
        for i in 0..10u64 {
            let ev = make_event(pid, ssl, 0, chunk.len() as u32, ts + i * 100_000);
            ss.handle_event(&ev, chunk);
        }

        let dropped_after = EVENTS_DROPPED.load(Ordering::Relaxed);
        assert!(
            dropped_after > dropped_before,
            "expected EVENTS_DROPPED to increase; before={}, after={}",
            dropped_before, dropped_after
        );
    }

    // -----------------------------------------------------------------------
    // 6. HTTP/3 header extraction
    // -----------------------------------------------------------------------
    #[test]
    fn test_http3_header_extraction() {
        reset_metrics();
        let ss = make_sharded(10 * 1024 * 1024);

        let pid = 600;
        let ssl = 0x6666;
        let ts_base: u64 = 6_000_000_000;

        // Build an HTTP/3 HEADERS frame with QPACK-encoded headers.
        // We use the QPACK static table indexed entries:
        //   index 17 = :method GET  (indexed field line, static: 0x80 | 0x40 | 17 = 0xD1)
        //   index  1 = :path /      (indexed field line, static: 0x80 | 0x40 |  1 = 0xC1)
        // QPACK header block:
        //   byte 0: Required Insert Count = 0 (varint, 8-bit prefix)
        //   byte 1: Sign bit 0 + Delta Base = 0 (varint, 7-bit prefix)
        //   then indexed lines
        let qpack_block: Vec<u8> = vec![
            0x00, // Required Insert Count = 0
            0x00, // S=0, Delta Base = 0
            0xD1, // Indexed, static, index=17 => :method GET
            0xC1, // Indexed, static, index=1  => :path /
        ];

        // HTTP/3 frame: type=0x01 (HEADERS), length = qpack_block.len()
        // Both type and length are QUIC varints. For small values (<64),
        // a single byte suffices (2-bit prefix 00 + 6-bit value).
        let frame_type: u8 = 0x01; // H3_HEADERS
        let frame_len: u8 = qpack_block.len() as u8;
        let mut h3_payload = vec![frame_type, frame_len];
        h3_payload.extend_from_slice(&qpack_block);

        // direction=0 for request (Server role reads requests)
        let ev = make_event(pid, ssl, 0, h3_payload.len() as u32, ts_base);
        let out = ss.handle_event(&ev, &h3_payload);
        // Request alone queues; no output yet
        assert!(out.is_empty(), "H3 request should be queued, not emitted yet");

        // Now send a response with :status 200
        // QPACK: index 25 = :status 200 => 0x80 | 0x40 | 25 = 0xD9
        let qpack_resp = vec![
            0x00, // RIC = 0
            0x00, // Delta Base = 0
            0xD9, // Indexed, static, index=25 => :status 200
        ];
        let mut h3_resp = vec![0x01u8, qpack_resp.len() as u8];
        h3_resp.extend_from_slice(&qpack_resp);

        // direction=1 for response (Server role writes responses)
        let ev = make_event(pid, ssl, 1, h3_resp.len() as u32, ts_base + 5_000_000);
        let out = ss.handle_event(&ev, &h3_resp);

        assert_eq!(out.len(), 1, "expected one HTTP/3 event");
        assert_eq!(out[0].protocol, "HTTP/3");
        assert_eq!(out[0].request.method, "GET");
        assert_eq!(out[0].request.path, "/");
        assert_eq!(out[0].response.status_code, 200);
    }

    // -----------------------------------------------------------------------
    // 7. Max pending per connection limit
    // -----------------------------------------------------------------------
    #[test]
    fn test_max_pending_per_conn() {
        reset_metrics();
        let ss = make_sharded(50 * 1024 * 1024);

        let pid = 700;
        let ssl = 0x7777;
        let ts_base: u64 = 7_000_000_000;

        // Feed more than MAX_PENDING_PER_CONN (100) requests without any responses
        for i in 0..150u64 {
            let req = format!("GET /path/{} HTTP/1.1\r\nHost: example.com\r\n\r\n", i);
            let ev = make_event(pid, ssl, 0, req.len() as u32, ts_base + i * 100_000);
            ss.handle_event(&ev, req.as_bytes());
        }

        // Now send 150 responses and count how many correlate with actual requests
        let mut real_correlations = 0;
        let mut unknown_correlations = 0;
        for i in 0..150u64 {
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let ev = make_event(pid, ssl, 1, resp.len() as u32, ts_base + 200_000_000 + i * 100_000);
            let out = ss.handle_event(&ev, resp);
            for event in &out {
                if event.request.method == "UNKNOWN" {
                    unknown_correlations += 1;
                } else {
                    real_correlations += 1;
                }
            }
        }

        // Should have exactly MAX_PENDING_PER_CONN real correlations
        assert_eq!(
            real_correlations, MAX_PENDING_PER_CONN,
            "should correlate exactly {} requests (the max pending limit)",
            MAX_PENDING_PER_CONN
        );
        // The remaining 50 should correlate with UNKNOWN synthetic requests
        assert_eq!(
            unknown_correlations, 50,
            "50 responses should have UNKNOWN correlation"
        );
    }
}
