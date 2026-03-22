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
use crate::mcp::{is_mcp_response, parse_sse_events};
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

        let is_request_dir = match self.role {
            TrafficRole::Server => ev.direction == 0,
            TrafficRole::Client => ev.direction == 1,
        };

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

                    let is_mcp = is_mcp_response(&resp.headers);
                    let request = self.pending.entry(conn_key.clone()).or_default().pop_front()
                        .unwrap_or_else(|| ParsedRequest {
                            method: "UNKNOWN".to_string(), path: "/".to_string(), host: None,
                            headers: HashMap::new(), body: None, ts_ms, net_ctx: NetContext::default(),
                        });
                    let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                    let protocol = if is_mcp { "MCP" } else { "HTTP/1.1" };
                    let mut event = build_event(self.account_id, ts_ms, request, resp, latency_ms, protocol, "ebpf");
                    if is_mcp {
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
                let is_grpc = headers.get("content-type").map(|v| v.starts_with("application/grpc")).unwrap_or(false);
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
        if !output.is_empty() {
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
