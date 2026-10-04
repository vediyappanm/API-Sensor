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
use crate::http2::{H2Item, Http2Direction};
use crate::identity::extract_identity;
use crate::mcp::{is_mcp_response, parse_sse_events};
use crate::metrics::*;
use crate::quic;
use crate::metrics::PENDING_EXPIRED;
use crate::redaction::{redact_body, redact_header_value, redact_pii, redact_url};
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
    Some(redact_body(&text))
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
    pending: HashMap<ConnKey, PendingQueue>,
    http2_state: HashMap<ConnKey, Http2Conn>,
    /// Server HTTP/2 frames (SETTINGS, WINDOW_UPDATE) that arrived before the
    /// client connection preface. They belong to the response direction and are
    /// replayed once the preface opens the connection.
    h2_early_resp: HashMap<ConnKey, (Vec<u8>, u64)>,
    http3_connections: HashSet<ConnKey>,
    ws_connections: HashSet<ConnKey>,
    known_connections: HashSet<ConnKey>,
    /// Maps (pid, ssl_ptr) → first-seen timestamp for born_ms disambiguation.
    conn_born_ms: HashMap<(u32, u64), u64>,
    last_eviction_ms: u64,
}

/// A response whose HEADERS have been seen but whose stream has not ended yet.
struct InflightResponse {
    headers: HashMap<String, String>,
    body: Vec<u8>,
    charged: usize,
}

impl InflightResponse {
    fn size_of(headers: &HashMap<String, String>, body_len: usize) -> usize {
        const BASE: usize = 256;
        BASE + headers.iter().map(|(k, v)| k.len() + v.len() + 64).sum::<usize>() + body_len
    }
}

/// HTTP/2 responses being assembled (HEADERS seen, END_STREAM not yet), keyed by stream id.
/// Charged against the memory ceiling and released on Drop like the other queues.
#[derive(Default)]
pub struct InflightResponses {
    map: HashMap<u32, InflightResponse>,
    bytes: PendingBytes,
}

impl InflightResponses {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    fn start(&mut self, stream_id: u32, headers: HashMap<String, String>, max_total: usize, cap: usize) -> bool {
        if let Some(old) = self.map.remove(&stream_id) {
            self.bytes.sub(old.charged);
        }
        let charged = InflightResponse::size_of(&headers, 0);
        if self.map.len() >= cap || !self.bytes.add(max_total, charged) {
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.map.insert(stream_id, InflightResponse { headers, body: Vec::new(), charged });
        true
    }

    /// Append DATA up to the capture cap. Returns false if the stream is unknown.
    fn append(&mut self, stream_id: u32, data: &[u8], max_total: usize) -> bool {
        let Some(r) = self.map.get_mut(&stream_id) else { return false };
        let room = MAX_BODY_CAPTURE_BYTES.saturating_sub(r.body.len());
        let take = data.len().min(room);
        if take > 0 && self.bytes.add(max_total, take) {
            r.body.extend_from_slice(&data[..take]);
            r.charged += take;
        }
        true
    }

    /// Trailers (e.g. gRPC `grpc-status`) join the response headers.
    fn merge_trailers(&mut self, stream_id: u32, trailers: HashMap<String, String>, max_total: usize) -> bool {
        let Some(r) = self.map.get_mut(&stream_id) else { return false };
        for (k, v) in trailers {
            let extra = k.len() + v.len() + 64;
            if self.bytes.add(max_total, extra) {
                r.charged += extra;
                r.headers.insert(k, v);
            }
        }
        true
    }

    fn body_full(&self, stream_id: u32) -> bool {
        self.map.get(&stream_id).map_or(false, |r| r.body.len() >= MAX_BODY_CAPTURE_BYTES)
    }

    fn take(&mut self, stream_id: u32) -> Option<(HashMap<String, String>, Vec<u8>)> {
        let r = self.map.remove(&stream_id)?;
        self.bytes.sub(r.charged);
        Some((r.headers, r.body))
    }

    /// Drop responses that never completed. Their request is dropped by `PendingStreams::expire`.
    pub fn expire(&mut self, live: &PendingStreams) -> usize {
        let stale: Vec<u32> = self.map.keys().filter(|id| !live.contains(**id)).copied().collect();
        for id in &stale {
            self.take(*id);
        }
        stale.len()
    }

    #[cfg(test)]
    pub fn accounted(&self) -> usize {
        self.bytes.0
    }

    #[cfg(test)]
    pub fn recount(&self) -> usize {
        self.map.values().map(|r| r.charged).sum()
    }
}

/// One HTTP/2 connection: independent parser state per direction (HPACK tables are per
/// direction), the requests awaiting a response, and responses being assembled.
pub struct Http2Conn {
    /// client -> server bytes (starts with the connection preface)
    pub req: Http2Direction,
    /// server -> client bytes
    pub resp: Http2Direction,
    pub pending_requests: PendingStreams,
    pub responses: InflightResponses,
    pub last_event_ts: u64,
    /// Bytes of incomplete frames held by `req`/`resp`; released on Drop.
    buffered: PendingBytes,
}

impl Default for Http2Conn {
    fn default() -> Self {
        Self {
            req: Http2Direction::new(true),
            resp: Http2Direction::new(false),
            pending_requests: PendingStreams::default(),
            responses: InflightResponses::default(),
            last_event_ts: 0,
            buffered: PendingBytes::default(),
        }
    }
}


/// Server bytes that show up before the client preface: a run of complete
/// connection frames (SETTINGS, PING, WINDOW_UPDATE) on stream 0. A trailing
/// partial frame is allowed. Anything else is left for the HTTP/1 parser.
fn looks_like_h2_connection_frames(buf: &[u8]) -> bool {
    if buf.len() < 9 {
        return false;
    }
    let mut i = 0;
    let mut saw = false;
    while i + 9 <= buf.len() {
        let len = ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | buf[i + 2] as usize;
        let ftype = buf[i + 3];
        let sid = u32::from_be_bytes([buf[i + 5], buf[i + 6], buf[i + 7], buf[i + 8]]) & 0x7fff_ffff;
        if len > 16_384 {
            return false;
        }
        if i + 9 + len > buf.len() {
            return saw;
        }
        if sid != 0 || !matches!(ftype, 0x04 | 0x06 | 0x08) {
            return false;
        }
        saw = true;
        i += 9 + len;
    }
    saw && i == buf.len()
}

/// Subtract from TOTAL_BUFFER_BYTES with underflow protection.
fn release_memory(amount: usize) {
    if amount == 0 { return; }
    TOTAL_BUFFER_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(amount))
    }).ok();
}

/// Bytes held by queued, not-yet-answered requests, charged against the global memory ceiling.
///
/// Releases on `Drop`, so every way a queue can disappear (connection eviction, TTL,
/// `HashMap::retain`, `clear`) hands its bytes back with no bookkeeping at the call site.
/// Before this, only raw stream buffers were charged; queued requests (headers plus a
/// whole captured body each) grew outside the ceiling and were never aged out.
#[derive(Default)]
pub struct PendingBytes(usize);

impl PendingBytes {
    fn add(&mut self, max_total: usize, n: usize) -> bool {
        if reserve_memory(max_total, n) {
            self.0 += n;
            true
        } else {
            false
        }
    }

    fn sub(&mut self, n: usize) {
        let n = n.min(self.0);
        self.0 -= n;
        release_memory(n);
    }
}

impl Drop for PendingBytes {
    fn drop(&mut self) {
        release_memory(self.0);
    }
}

/// HTTP/1.x and HTTP/3 requests awaiting their response on one connection (FIFO).
#[derive(Default)]
pub struct PendingQueue {
    items: VecDeque<ParsedRequest>,
    bytes: PendingBytes,
}

impl PendingQueue {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Queue a request. Returns false, and counts a drop, when the per-connection queue is
    /// full or the global memory ceiling would be exceeded.
    pub fn push(&mut self, mut req: ParsedRequest, max_total: usize) -> bool {
        // Only the first MAX_BODY_CAPTURE_BYTES are ever shipped; do not retain the rest.
        req.body.truncate(MAX_BODY_CAPTURE_BYTES);
        // truncate() keeps the original allocation; release it so real heap matches what is charged.
        req.body.shrink_to_fit();
        let size = req.approx_bytes();
        if self.items.len() >= MAX_PENDING_PER_CONN || !self.bytes.add(max_total, size) {
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.items.push_back(req);
        true
    }

    /// Oldest request that is a usable HTTP request, discarding (and un-charging) junk.
    pub fn pop_usable(&mut self) -> Option<ParsedRequest> {
        while let Some(req) = self.items.pop_front() {
            self.bytes.sub(req.approx_bytes());
            if is_usable_http_request(&req.method, &req.path) {
                return Some(req);
            }
        }
        None
    }

    /// Drop requests older than `ttl_ms` whose response was never seen.
    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let mut expired = 0;
        while self
            .items
            .front()
            .map_or(false, |r| now_ms.saturating_sub(r.ts_ms) >= ttl_ms)
        {
            if let Some(r) = self.items.pop_front() {
                self.bytes.sub(r.approx_bytes());
                expired += 1;
            }
        }
        expired
    }

    #[cfg(test)]
    pub fn accounted(&self) -> usize {
        self.bytes.0
    }

    #[cfg(test)]
    pub fn recount(&self) -> usize {
        self.items.iter().map(ParsedRequest::approx_bytes).sum()
    }
}

/// HTTP/2 requests awaiting their response, keyed by stream id.
#[derive(Default)]
pub struct PendingStreams {
    map: HashMap<u32, ParsedRequest>,
    bytes: PendingBytes,
}

impl PendingStreams {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Insert (replacing any request already on that stream). Returns false, and counts a
    /// drop, when the connection is at `cap` streams or the memory ceiling would be exceeded.
    pub fn insert(&mut self, stream_id: u32, mut req: ParsedRequest, max_total: usize, cap: usize) -> bool {
        req.body.truncate(MAX_BODY_CAPTURE_BYTES);
        // truncate() keeps the original allocation; release it so real heap matches what is charged.
        req.body.shrink_to_fit();
        if let Some(old) = self.map.remove(&stream_id) {
            self.bytes.sub(old.approx_bytes());
        }
        let size = req.approx_bytes();
        if self.map.len() >= cap || !self.bytes.add(max_total, size) {
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.map.insert(stream_id, req);
        true
    }

    pub fn contains(&self, stream_id: u32) -> bool {
        self.map.contains_key(&stream_id)
    }

    /// Append request DATA to a queued request, up to the capture cap.
    pub fn append_body(&mut self, stream_id: u32, data: &[u8], max_total: usize) -> bool {
        let Some(req) = self.map.get_mut(&stream_id) else { return false };
        let take = data.len().min(MAX_BODY_CAPTURE_BYTES.saturating_sub(req.body.len()));
        if take > 0 && self.bytes.add(max_total, take) {
            req.body.reserve_exact(take);
            req.body.extend_from_slice(&data[..take]);
        }
        true
    }

    pub fn remove(&mut self, stream_id: &u32) -> Option<ParsedRequest> {
        let req = self.map.remove(stream_id)?;
        self.bytes.sub(req.approx_bytes());
        Some(req)
    }

    /// Drop requests older than `ttl_ms` whose response was never seen.
    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let stale: Vec<u32> = self
            .map
            .iter()
            .filter(|(_, r)| now_ms.saturating_sub(r.ts_ms) >= ttl_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            self.remove(id);
        }
        stale.len()
    }

    #[cfg(test)]
    pub fn accounted(&self) -> usize {
        self.bytes.0
    }

    #[cfg(test)]
    pub fn recount(&self) -> usize {
        self.map.values().map(ParsedRequest::approx_bytes).sum()
    }
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
            h2_early_resp: HashMap::new(),
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

        // Http2Conn releases everything it holds on Drop, so no byte arithmetic here.
        self.http2_state.retain(|_, conn| now_ms.saturating_sub(conn.last_event_ts) < STREAM_TTL_MS);
        self.h2_early_resp.retain(|_, (_, seen)| now_ms.saturating_sub(*seen) < STREAM_TTL_MS);

        // Requests whose response never arrived would otherwise sit (and hold memory) until
        // the connection closes. Their bytes are released by PendingBytes as they are dropped.
        let mut expired = 0usize;
        for queue in self.pending.values_mut() {
            expired += queue.expire(now_ms, STREAM_TTL_MS);
        }
        for conn in self.http2_state.values_mut() {
            expired += conn.pending_requests.expire(now_ms, STREAM_TTL_MS);
            expired += conn.responses.expire(&conn.pending_requests);
        }
        if expired > 0 {
            PENDING_EXPIRED.fetch_add(expired as u64, Ordering::Relaxed);
        }
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
                self.http2_state.remove(&k);
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
        self.http2_state.retain(|k, _| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
        self.h2_early_resp.retain(|k, _| !(k.pid == pid && k.ssl_ptr == ssl_ptr));
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
        // A connection is HTTP/2 only if its client stream BEGINS with the connection preface and
        // no HTTP/1 bytes were seen on it before. Matching the preface anywhere in a payload let a
        // request body that merely contained that string flip the connection to HTTP/2 and blind
        // the HTTP/1 parser (a trivial evasion).
        let is_known_h2 = self.http2_state.contains_key(&conn_key);
        let starts_h2 = !is_known_h2
            && is_request_dir
            && payload.starts_with(crate::types::HTTP2_PREFACE)
            && !self.buffers.contains_key(&stream_key);
        // A server writes its SETTINGS before it has read the client preface.
        // Those bytes are not a request, and they are not HTTP/1. Hold them
        // until the preface opens the connection, then feed the response direction.
        if !is_known_h2 && !is_request_dir && looks_like_h2_connection_frames(payload) {
            let entry = self.h2_early_resp.entry(conn_key).or_insert_with(|| (Vec::new(), ts_ms));
            if entry.0.len().saturating_add(payload.len()) <= 65_536 {
                entry.0.extend_from_slice(payload);
            }
            entry.1 = ts_ms;
            return output;
        }
        if starts_h2 {
            if let Some((early, _)) = self.h2_early_resp.remove(&conn_key) {
                if !early.is_empty() {
                    output.extend(self.process_http2_event(conn_key.clone(), ev, &early, ts_ms, false));
                }
            }
        }
        if is_known_h2 || starts_h2 {
            output.extend(self.process_http2_event(conn_key, ev, payload, ts_ms, is_request_dir));
            return output;
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
                        let max_total = self.max_total_buffer_bytes;
                        self.pending.entry(conn_key.clone()).or_default().push(
                            ParsedRequest {
                                method: method.clone(),
                                path,
                                host,
                                headers: headers.clone(),
                                ts_ms,
                                net_ctx,
                                body: Vec::new(),
                            },
                            max_total,
                        );
                    }
                } else if let Some(status) = headers.get(":status") {
                    let Some(request) = self.pending.entry(conn_key.clone()).or_default().pop_usable() else {
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
                        self.pending.entry(conn_key.clone()).or_default().push(
                            ParsedRequest {
                                method: req.method,
                                path: req.path,
                                host: req.host,
                                headers: req.headers,
                                ts_ms,
                                net_ctx,
                                body: req.body,
                            },
                            max_total,
                        );
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
                    let upgrade = upgrade_hdr.as_deref() == Some("websocket");

                    let Some(request) = self.pending.entry(conn_key.clone()).or_default().pop_usable() else {
                        skip_unpaired_response();
                        continue;
                    };
                    let latency_ms = ts_ms.saturating_sub(request.ts_ms);
                    // The upgrade itself is the WebSocket event. Later frames are
                    // counted, not emitted: per-frame events on /api/stream/live
                    // fed the live feed back into itself.
                    let protocol = if is_mcp {
                        "MCP"
                    } else if upgrade {
                        "WebSocket"
                    } else {
                        "HTTP/1.1"
                    };
                    // The SSE body carries the JSON-RPC call. The raw TLS chunk
                    // may be only the tail of the headers.
                    let mcp_events = if is_mcp {
                        let source: &[u8] = if resp.body.is_empty() { payload } else { &resp.body };
                        parse_sse_events(source)
                    } else {
                        Vec::new()
                    };
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
    ) -> Vec<ApiTrafficEvent> {
        let net_ctx = if is_request_dir { Some(self.net_context_from_event(ev)) } else { None };
        let account_id = self.account_id;
        let max_total = self.max_total_buffer_bytes;
        let conn = self.http2_state.entry(conn_key).or_default();
        conn.last_event_ts = ts_ms;
        if payload.is_empty() {
            return Vec::new();
        }

        // Charge the incoming chunk while it is parsed; whatever remains buffered afterwards
        // (an incomplete trailing frame) stays charged, the rest is released.
        if !conn.buffered.add(max_total, payload.len()) {
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
        let (before, items, after, announced) = {
            let dir = if is_request_dir { &mut conn.req } else { &mut conn.resp };
            let before = dir.buffered();
            let items = dir.feed(payload);
            (before, items, dir.buffered(), dir.announced_max_frame)
        };
        conn.buffered.sub((payload.len() + before).saturating_sub(after));
        if let Some(size) = announced {
            // What one side announces bounds the frames the other side may send.
            if is_request_dir { conn.resp.set_max_frame(size) } else { conn.req.set_max_frame(size) }
        }

        let mut output = Vec::new();
        for item in items {
            match item {
                H2Item::Headers { stream_id, headers, end_stream } if is_request_dir => {
                    // A second HEADERS block on a known stream is request trailers: not a new request.
                    let Some(method) = headers.get(":method").cloned() else { continue };
                    let path = headers.get(":path").cloned().unwrap_or_else(|| "/".to_string());
                    if !is_usable_http_request(&method, &path) {
                        continue;
                    }
                    let host = headers.get(":authority").cloned();
                    conn.pending_requests.insert(
                        stream_id,
                        ParsedRequest {
                            method,
                            path,
                            host,
                            headers,
                            ts_ms,
                            net_ctx: net_ctx.clone().unwrap_or_default(),
                            body: Vec::new(),
                        },
                        max_total,
                        MAX_H2_PENDING_STREAMS,
                    );
                    let _ = end_stream; // a body-less request: nothing more to wait for
                }
                H2Item::Data { stream_id, data, .. } if is_request_dir => {
                    conn.pending_requests.append_body(stream_id, &data, max_total);
                }
                H2Item::Headers { stream_id, headers, end_stream } => {
                    if let Some(status) = headers.get(":status") {
                        // 1xx are interim responses; the final one follows on the same stream.
                        if status.starts_with('1') {
                            continue;
                        }
                        if !conn.pending_requests.contains(stream_id) {
                            skip_unpaired_response();
                            continue;
                        }
                        conn.responses.start(stream_id, headers, max_total, MAX_H2_PENDING_STREAMS);
                    } else if !conn.responses.merge_trailers(stream_id, headers, max_total) {
                        continue;
                    }
                    if end_stream || conn.responses.body_full(stream_id) {
                        Self::finish_h2_response(conn, stream_id, ts_ms, account_id, &mut output);
                    }
                }
                H2Item::Data { stream_id, data, end_stream } => {
                    if conn.responses.append(stream_id, &data, max_total)
                        && (end_stream || conn.responses.body_full(stream_id))
                    {
                        Self::finish_h2_response(conn, stream_id, ts_ms, account_id, &mut output);
                    }
                }
                H2Item::Reset { stream_id } => {
                    conn.responses.take(stream_id);
                    conn.pending_requests.remove(&stream_id);
                }
            }
        }
        output
    }

    /// Pair a completed (or capped) HTTP/2 response with its request and build the event.
    fn finish_h2_response(
        conn: &mut Http2Conn,
        stream_id: u32,
        ts_ms: u64,
        account_id: u64,
        output: &mut Vec<ApiTrafficEvent>,
    ) {
        let Some((headers, data)) = conn.responses.take(stream_id) else { return };
        let Some(request) = conn
            .pending_requests
            .remove(&stream_id)
            .filter(|req| is_usable_http_request(&req.method, &req.path))
        else {
            skip_unpaired_response();
            return;
        };
        let latency_ms = ts_ms.saturating_sub(request.ts_ms);
        let status_code = headers.get(":status").and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
        let is_grpc = headers
            .get("content-type")
            .map(|v| v.starts_with("application/grpc"))
            .unwrap_or(false);

        // For plain HTTP/2 this DATA is the response body; for gRPC it is protobuf we decode
        // into fields instead of shipping raw.
        let grpc_body = if is_grpc {
            let fields = decode_grpc_fields(&data);
            if fields.is_empty() { None } else { serde_json::to_string(&fields).ok() }
        } else {
            None
        };
        let resp = HttpResponseParsed {
            status_code,
            headers,
            body: if is_grpc { Vec::new() } else { data },
        };
        let protocol = if is_grpc { "gRPC" } else { "HTTP/2" };
        let mut event = build_event(account_id, ts_ms, request, resp, latency_ms, protocol, "ebpf");
        if let Some(body) = grpc_body {
            // Attached after build_event's own redaction, so it must be redacted here.
            event.response.body = Some(redact_body(&body));
        }
        output.push(event);
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
            body: Some(redact_body(&payload)),
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
    let redacted_path = redact_url(&req.path);
    let (path, query) = split_query(&redacted_path);
    let net_ctx = req.net_ctx.clone();

    let redacted_req_headers: HashMap<String, String> = req.headers
        .into_iter()
        .map(|(k, v)| { let r = redact_header_value(&k, &v); (k, r) })
        .collect();

    // Redact response headers too (may contain Set-Cookie, tokens, etc.)
    let redacted_resp_headers: HashMap<String, String> = resp.headers
        .into_iter()
        .map(|(k, v)| { let r = redact_header_value(&k, &v); (k, r) })
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
        user_id: Some(redact_pii(&identity.user_id)),
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
    fn mcp_sse_body_records_method_and_tool() {
        let state = test_state();
        let req = b"POST /mcp HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}";
        assert!(state.handle_event(&tls_event(0), req).is_empty());
        let body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}\n\n";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let events = state.handle_event(&tls_event(1), resp.as_bytes());
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].protocol, "MCP");
        let meta = events[0].metadata.as_ref().expect("mcp metadata");
        assert_eq!(meta.mcp_method.as_deref(), Some("tools/call"));
        assert_eq!(meta.mcp_tool_name.as_deref(), Some("read_file"));
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
        assert_eq!(upgrade[0].protocol, "WebSocket");

        // Unmasked TEXT frame: FIN+text, len=5, "hello"
        let frame = [0x81u8, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let events = state.handle_event(&tls_event(0), &frame);
        assert!(
            events.is_empty(),
            "WS frames must not appear as TEXT /ws: {events:?}"
        );
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
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
        let mut req = crate::types::HTTP2_CONNECTION_PREFACE.to_vec();
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

    /// Bytes captured from a real curl --http2 GET /api/items against an h2 server.
    /// Order is what the server process sees: its SETTINGS goes out before the
    /// client preface is read.
    #[test]
    fn real_curl_http2_exchange_is_collected() {
        let state = test_state();
        let chunks: &[(u8, &str)] = &[
            (1, "00002a04000000000000010000100000020000000000040000ffff000500004000000800000000000300000064000600010000"),
            (0, "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a000012040000000000000300000064000400a000000002000000000000040800000000003e7f0001"),
            (1, "000000040100000000"),
            (0, "0000270105000000018287418b089d5c0b8170dc0bcd34ef04876075998324b4a37a8825b650c3cbb6b83f53032a2f2a"),
            (1, "00000e010400000001885f8b1d75d0620d263d4c7441ea00000b0001000000017b226f6b223a747275657d"),
        ];
        let mut events = Vec::new();
        for (dir, hex) in chunks {
            let bytes = hex_bytes(hex);
            events.extend(state.handle_event(&tls_event(*dir), &bytes));
        }
        assert_eq!(events.len(), 1, "real curl HTTP/2 exchange should emit one event: {events:?}");
        assert_eq!(events[0].protocol, "HTTP/2");
        assert_eq!(events[0].request.method, "GET");
        assert!(events[0].request.path.contains("/api/items"), "{:?}", events[0].request.path);
        assert_eq!(events[0].response.status_code, 200);
        let body = events[0].response.body.as_deref().unwrap_or("");
        assert!(body.contains("ok"), "response body missing: {body}");
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

    // ---- Secret-leak regression tests: bytes in -> serialized event out -----------------

    const LEAK_SECRETS: &[&str] = &[
        "hunter2-correct-horse", "s3ssion-value-abcdef0123456789", "zZ9-api-key-0001",
        "dXNlcjpwYXNzd29yZA==", "refresh-opaque-1a2b3c", "my$ecretPassw0rd",
    ];

    fn assert_no_secret(event: &ApiTrafficEvent) {
        let wire = serde_json::to_string(event).unwrap();
        for s in LEAK_SECRETS {
            assert!(!wire.contains(s), "secret {s:?} reached the wire: {wire}");
        }
    }

    #[test]
    fn http1_secrets_in_headers_url_and_bodies_never_reach_the_wire() {
        let state = test_state();
        let body = "{\"user\":\"alice\",\"password\":\"hunter2-correct-horse\",\"note\":\"ok\"}";
        let req = format!(
            "POST /orders?api_key=zZ9-api-key-0001&page=2 HTTP/1.1\r\nHost: shop.example.com\r\n\
             Authorization: Basic dXNlcjpwYXNzd29yZA==\r\nCookie: sessionid=s3ssion-value-abcdef0123456789; theme=dark\r\n\
             X-Api-Key: zZ9-api-key-0001\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        assert!(state.handle_event(&tls_event(0), req.as_bytes()).is_empty());

        let resp_body = "{\"access_token\":\"refresh-opaque-1a2b3c\",\"expires_in\":3600}";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nSet-Cookie: sid=my$ecretPassw0rd; Path=/; HttpOnly\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(), resp_body
        );
        let events = state.handle_event(&tls_event(1), resp.as_bytes());
        assert_eq!(events.len(), 1);
        let e = &events[0];

        assert_no_secret(e);
        // ...while the information an analyst needs is still there.
        assert_eq!(e.request.method, "POST");
        assert_eq!(e.request.path, "/orders");
        assert_eq!(e.request.query.get("page").map(String::as_str), Some("2"));
        assert_eq!(e.request.host.as_deref(), Some("shop.example.com"));
        assert!(e.request.body.as_deref().unwrap().contains("\"user\":\"alice\""));
        assert!(e.response.body.as_deref().unwrap().contains("\"expires_in\":3600"));
        assert!(e.response.headers.values().any(|v| v.contains("Path=/; HttpOnly")));
        assert!(e.session_id.as_deref().unwrap().starts_with("sid-"));
    }

    #[test]
    fn jwt_email_claim_is_not_shipped_as_the_user_id() {
        let state = test_state();
        let req = "GET /me HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer \
                   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwianRpIjoidG9rLTEifQ.c2ln\r\n\r\n";
        assert!(state.handle_event(&tls_event(0), req.as_bytes()).is_empty());
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let events = state.handle_event(&tls_event(1), resp.as_bytes());
        assert_eq!(events.len(), 1);
        let e = &events[0];
        let uid = e.user_id.as_deref().unwrap();
        assert!(!uid.contains("alice@example.com"), "raw email shipped as user_id: {uid}");
        assert!(uid.starts_with("PII_EMAIL_"), "{uid}");
        assert_eq!(e.user_role.as_deref(), Some("admin"));
        assert!(!serde_json::to_string(e).unwrap().contains("alice@example.com"));
    }

    #[test]
    fn grpc_body_is_redacted_even_though_it_is_attached_after_build_event() {
        let state = test_state();
        let mut req_hpack = vec![0x83u8];
        req_hpack.extend(hpack_literal(4, "/pkg.Svc/Method"));
        req_hpack.extend(hpack_literal(31, "application/grpc"));
        let mut req = crate::types::HTTP2_CONNECTION_PREFACE.to_vec();
        req.extend(h2_frame(0x01, 0x05, 1, &req_hpack));
        assert!(state.handle_event(&tls_event(0), &req).is_empty());

        let mut resp_hpack = vec![0x88u8];
        resp_hpack.extend(hpack_literal(31, "application/grpc"));
        // protobuf field 1, wire type 2, string "alice@example.com"
        let text = b"alice@example.com";
        let mut msg = vec![0x00, 0x00, 0x00, 0x00, (2 + text.len()) as u8, 0x0a, text.len() as u8];
        msg.extend_from_slice(text);
        let mut resp = h2_frame(0x01, 0x04, 1, &resp_hpack);
        resp.extend(h2_frame(0x00, 0x01, 1, &msg));
        let events = state.handle_event(&tls_event(1), &resp);
        assert_eq!(events.len(), 1);
        let wire = serde_json::to_string(&events[0]).unwrap();
        assert!(!wire.contains("alice@example.com"), "gRPC body skipped redaction: {wire}");
        assert!(wire.contains("PII_EMAIL_"), "{wire}");
    }

    // ---- Pending-request accounting ---------------------------------------------------

    fn req_with(ts_ms: u64, body_len: usize) -> ParsedRequest {
        ParsedRequest {
            method: "POST".into(),
            path: "/x".into(),
            host: Some("h".into()),
            headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
            ts_ms,
            net_ctx: NetContext::default(),
            body: vec![b'x'; body_len],
        }
    }

    const PLENTY: usize = usize::MAX / 4;

    #[test]
    fn queue_bookkeeping_matches_its_contents_through_push_pop_and_expiry() {
        let mut q = PendingQueue::default();
        for i in 0..10u64 {
            assert!(q.push(req_with(1_000 + i, 100), PLENTY));
        }
        assert_eq!(q.accounted(), q.recount());
        assert!(q.pop_usable().is_some());
        assert_eq!(q.accounted(), q.recount());
        // everything older than 5s at t=7_000 expires (ts 1_000..1_009)
        assert_eq!(q.expire(7_000, 5_000), 9);
        assert!(q.is_empty());
        assert_eq!((q.accounted(), q.recount()), (0, 0));
    }

    #[test]
    fn fresh_requests_survive_expiry_and_stale_ones_do_not() {
        let mut q = PendingQueue::default();
        q.push(req_with(1_000, 10), PLENTY);
        q.push(req_with(9_000, 10), PLENTY);
        assert_eq!(q.expire(10_000, 5_000), 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.accounted(), q.recount());
    }

    #[test]
    fn stored_bodies_are_capped_so_unused_bytes_are_not_retained() {
        let mut q = PendingQueue::default();
        assert!(q.push(req_with(1, 1_000_000), PLENTY));
        let held = q.pop_usable().unwrap();
        assert_eq!(held.body.len(), MAX_BODY_CAPTURE_BYTES);
        assert_eq!(held.body.capacity(), MAX_BODY_CAPTURE_BYTES, "capacity must be released too");
    }

    #[test]
    fn push_is_refused_and_counted_when_the_ceiling_is_reached() {
        let before = EVENTS_DROPPED.load(Ordering::Relaxed);
        let mut q = PendingQueue::default();
        assert!(!q.push(req_with(1, 10), 1), "ceiling of 1 byte must refuse");
        assert!(q.is_empty());
        assert_eq!(q.accounted(), 0);
        assert!(EVENTS_DROPPED.load(Ordering::Relaxed) > before);
    }

    #[test]
    fn push_is_refused_when_the_per_connection_queue_is_full() {
        let mut q = PendingQueue::default();
        for _ in 0..MAX_PENDING_PER_CONN {
            assert!(q.push(req_with(1, 1), PLENTY));
        }
        assert!(!q.push(req_with(1, 1), PLENTY));
        assert_eq!(q.len(), MAX_PENDING_PER_CONN);
        assert_eq!(q.accounted(), q.recount());
    }

    #[test]
    fn h2_streams_replace_expire_and_stay_consistent() {
        let mut s = PendingStreams::default();
        assert!(s.insert(1, req_with(1_000, 50), PLENTY, 10));
        assert!(s.insert(1, req_with(1_100, 70), PLENTY, 10), "same stream id replaces");
        assert_eq!(s.len(), 1);
        assert_eq!(s.accounted(), s.recount());
        assert!(s.insert(3, req_with(9_000, 50), PLENTY, 10));
        assert_eq!(s.expire(10_000, 5_000), 1);
        assert_eq!(s.len(), 1);
        assert_eq!(s.accounted(), s.recount());
        assert!(s.remove(&3).is_some());
        assert_eq!((s.accounted(), s.recount()), (0, 0));
        // cap
        for id in 0..4u32 { assert!(s.insert(id * 2 + 1, req_with(1, 1), PLENTY, 4)); }
        assert!(!s.insert(99, req_with(1, 1), PLENTY, 4));
    }

    // ---- HTTP/2 stream-level behaviour --------------------------------------------------

    const F_END_STREAM: u8 = 0x01;
    const F_END_HEADERS: u8 = 0x04;

    fn lit_new_name(name: &str, value: &str) -> Vec<u8> {
        let mut v = vec![0x40, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v.push(value.len() as u8);
        v.extend_from_slice(value.as_bytes());
        v
    }

    /// :method POST/GET, :path, and a content-type, as a HEADERS frame on `stream`.
    fn h2_request(stream: u32, method_idx: u8, path: &str, extra: &[u8], flags: u8) -> Vec<u8> {
        let mut hp = vec![0x80 | method_idx];
        hp.extend(hpack_literal(4, path));
        hp.extend_from_slice(extra);
        h2_frame(0x01, flags, stream, &hp)
    }

    fn h2_status_headers(stream: u32, status_idx: u8, extra: &[u8], flags: u8) -> Vec<u8> {
        let mut hp = vec![0x80 | status_idx];
        hp.extend_from_slice(extra);
        h2_frame(0x01, flags, stream, &hp)
    }

    fn client_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut v = crate::types::HTTP2_CONNECTION_PREFACE.to_vec();
        for f in frames {
            v.extend_from_slice(f);
        }
        v
    }

    fn ev_at(direction: u8) -> TlsEventHeader {
        tls_event(direction)
    }

    #[test]
    fn h2_response_body_arriving_in_a_later_read_is_captured_in_one_event() {
        let state = test_state();
        let req = client_bytes(&[h2_request(1, 2, "/items", &[], F_END_HEADERS | F_END_STREAM)]);
        assert!(state.handle_event(&ev_at(0), &req).is_empty());

        // 200 with a JSON content-type, END_HEADERS only: the body has not arrived yet.
        let ct = lit_new_name("content-type", "application/json");
        let hdrs = h2_status_headers(1, 8, &ct, F_END_HEADERS);
        assert!(state.handle_event(&ev_at(1), &hdrs).is_empty(), "must wait for END_STREAM");

        // The body comes in a LATER read. It used to be lost because it was only searched for
        // in the buffer present when the response HEADERS arrived.
        let data = h2_frame(0x00, F_END_STREAM, 1, b"{\"items\":[1,2,3]}");
        let events = state.handle_event(&ev_at(1), &data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol, "HTTP/2");
        assert_eq!(events[0].response.status_code, 200);
        assert_eq!(events[0].response.body.as_deref(), Some("{\"items\":[1,2,3]}"));
    }

    #[test]
    fn h2_request_body_is_captured_and_redacted() {
        let state = test_state();
        let ct = lit_new_name("content-type", "application/json");
        let req = client_bytes(&[
            h2_request(1, 3, "/login", &ct, F_END_HEADERS),
            h2_frame(0x00, F_END_STREAM, 1, b"{\"user\":\"alice\",\"password\":\"hunter2-correct-horse\"}"),
        ]);
        assert!(state.handle_event(&ev_at(0), &req).is_empty());
        let events = state.handle_event(&ev_at(1), &h2_status_headers(1, 8, &[], F_END_HEADERS | F_END_STREAM));
        assert_eq!(events.len(), 1);
        let body = events[0].request.body.as_deref().expect("H2 request body was never captured before");
        assert!(body.contains("\"user\":\"alice\""), "{body}");
        assert!(!body.contains("hunter2-correct-horse"), "password leaked: {body}");
        assert_eq!(events[0].request.method, "POST");
    }

    #[test]
    fn h2_multiplexed_streams_complete_out_of_order_and_pair_correctly() {
        let state = test_state();
        let req = client_bytes(&[
            h2_request(1, 2, "/a", &[], F_END_HEADERS | F_END_STREAM),
            h2_request(3, 2, "/b", &[], F_END_HEADERS | F_END_STREAM),
        ]);
        assert!(state.handle_event(&ev_at(0), &req).is_empty());
        // stream 3 answers first (404 = static idx 13), then stream 1 (200)
        let resp = [
            h2_status_headers(3, 13, &[], F_END_HEADERS | F_END_STREAM),
            h2_status_headers(1, 8, &[], F_END_HEADERS | F_END_STREAM),
        ]
        .concat();
        let events = state.handle_event(&ev_at(1), &resp);
        assert_eq!(events.len(), 2);
        assert_eq!((events[0].request.path.as_str(), events[0].response.status_code), ("/b", 404));
        assert_eq!((events[1].request.path.as_str(), events[1].response.status_code), ("/a", 200));
    }

    #[test]
    fn grpc_trailers_are_merged_into_the_response_headers() {
        let state = test_state();
        let mut gh = vec![0x83u8];
        gh.extend(hpack_literal(4, "/pkg.Svc/Method"));
        gh.extend(hpack_literal(31, "application/grpc"));
        let req = client_bytes(&[h2_frame(0x01, F_END_HEADERS | F_END_STREAM, 1, &gh)]);
        assert!(state.handle_event(&ev_at(0), &req).is_empty());

        let mut rh = vec![0x88u8];
        rh.extend(hpack_literal(31, "application/grpc"));
        let msg = [0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x07]; // field 1 varint 7
        let trailers = [lit_new_name("grpc-status", "0"), lit_new_name("grpc-message", "ok")].concat();
        let resp = [
            h2_frame(0x01, F_END_HEADERS, 1, &rh),
            h2_frame(0x00, 0, 1, &msg),
            h2_frame(0x01, F_END_HEADERS | F_END_STREAM, 1, &trailers),
        ]
        .concat();
        let events = state.handle_event(&ev_at(1), &resp);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol, "gRPC");
        assert_eq!(events[0].response.headers.get("grpc-status").map(String::as_str), Some("0"));
        assert!(events[0].response.body.is_some());
    }

    #[test]
    fn h2_interim_1xx_responses_do_not_complete_the_request() {
        let state = test_state();
        let req = client_bytes(&[h2_request(1, 3, "/up", &[], F_END_HEADERS)]);
        assert!(state.handle_event(&ev_at(0), &req).is_empty());
        let interim = h2_frame(0x01, F_END_HEADERS, 1, &hpack_literal(8, "100"));
        assert!(state.handle_event(&ev_at(1), &interim).is_empty());
        let events = state.handle_event(&ev_at(1), &h2_status_headers(1, 8, &[], F_END_HEADERS | F_END_STREAM));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].response.status_code, 200);
    }

    #[test]
    fn h2_response_without_a_request_is_not_fabricated() {
        let state = test_state();
        assert!(state
            .handle_event(&ev_at(0), &client_bytes(&[h2_frame(0x04, 0, 0, &[])]))
            .is_empty());
        let events = state.handle_event(&ev_at(1), &h2_status_headers(9, 8, &[], F_END_HEADERS | F_END_STREAM));
        assert!(events.is_empty());
    }

    #[test]
    fn h2_reset_stream_drops_the_pending_request() {
        let state = test_state();
        assert!(state
            .handle_event(&ev_at(0), &client_bytes(&[h2_request(1, 2, "/x", &[], F_END_HEADERS | F_END_STREAM)]))
            .is_empty());
        let rst = h2_frame(0x03, 0, 1, &[0, 0, 0, 8]);
        assert!(state.handle_event(&ev_at(1), &rst).is_empty());
        let events = state.handle_event(&ev_at(1), &h2_status_headers(1, 8, &[], F_END_HEADERS | F_END_STREAM));
        assert!(events.is_empty(), "a reset stream must not later pair with a response");
    }

    #[test]
    fn http1_body_containing_the_h2_preface_cannot_blind_the_http1_parser() {
        let state = test_state();
        // An attacker (or any client) sends an HTTP/1 request whose BODY contains the HTTP/2
        // preface. The old detector matched the preface anywhere and switched the whole
        // connection to HTTP/2, after which no HTTP/1 traffic on it was parsed.
        let body = String::from_utf8_lossy(HTTP2_PREFACE).to_string();
        let req = format!(
            "POST /api/x HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        assert!(state.handle_event(&tls_event(0), req.as_bytes()).is_empty());
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let events = state.handle_event(&tls_event(1), resp.as_bytes());
        assert_eq!(events.len(), 1, "the HTTP/1 exchange must still be captured");
        assert_eq!(events[0].protocol, "HTTP/1.1");
        assert_eq!(events[0].request.path, "/api/x");

        // ...and a later write that merely STARTS with the preface on a connection that already
        // spoke HTTP/1 must not switch it to HTTP/2 either.
        state.handle_event(&tls_event(0), HTTP2_PREFACE);
        let h2_conns: usize = state.shards.iter().map(|s| s.lock().unwrap().http2_state.len()).sum();
        assert_eq!(h2_conns, 0, "an HTTP/1 connection was switched to HTTP/2 by a preface-looking write");
    }

    #[test]
    fn h2_state_bytes_are_released_when_the_connection_goes_away() {
        let state = test_state();
        // an incomplete trailing frame stays buffered (and charged)
        let mut req = client_bytes(&[h2_request(1, 2, "/x", &[], F_END_HEADERS | F_END_STREAM)]);
        req.extend_from_slice(&[0x00, 0x00, 0x10, 0x00, 0x00, 0, 0, 0, 3, b'p']); // partial DATA
        assert!(state.handle_event(&ev_at(0), &req).is_empty());
        let held: usize = state
            .shards
            .iter()
            .map(|s| {
                let g = s.lock().unwrap();
                g.http2_state.values().map(|c| c.req.buffered() + c.resp.buffered()).sum::<usize>()
            })
            .sum();
        assert!(held > 0, "the partial frame should be buffered");
        state.evict_connection(&ConnKey { pid: 42, ssl_ptr: 0x1000, born_ms: 0 });
        let left: usize = state.shards.iter().map(|s| s.lock().unwrap().http2_state.len()).sum();
        assert_eq!(left, 0);
    }
}
