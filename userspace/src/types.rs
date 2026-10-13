use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;

// ---------------------------------------------------------------------------
// Global memory ceiling
// ---------------------------------------------------------------------------

/// Tracks total buffer bytes across all shards for memory ceiling enforcement.
pub static TOTAL_BUFFER_BYTES: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// BPF event structs (repr(C) — must match kernel-side layout)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NewProcEvent {
    pub pid: u32,
    pub _pad: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
}

/// Wire ABI version for BPF↔userspace `TlsEventHeader` (F08). Bump together.
pub const TLS_EVENT_ABI_VERSION: u16 = 2;

/// Capture integrity flags on `TlsEventHeader.flags` (F08).
pub const TLS_FLAG_TRUNCATED: u16 = 1 << 0;
/// Tuple came from ssl_ptr→conn map (preferred).
pub const TLS_FLAG_ATTR_SSL: u16 = 1 << 1;
/// Tuple came from thread-local active_connections (low confidence).
pub const TLS_FLAG_ATTR_THREAD: u16 = 1 << 2;

pub const PROVIDER_UNKNOWN: u8 = 0;
pub const PROVIDER_OPENSSL: u8 = 1;
pub const PROVIDER_GNUTLS: u8 = 2;
pub const PROVIDER_GO_TLS: u8 = 3;
pub const PROVIDER_QUIC: u8 = 4;
pub const PROVIDER_KTLS: u8 = 5;
pub const PROVIDER_NSS: u8 = 6;

/// `TlsEventHeader.attribution`: how the tuple was associated with the TLS object.
pub const ATTR_NONE: u8 = 0;
pub const ATTR_SSL: u8 = 1;
pub const ATTR_THREAD: u8 = 2;

/// Role hint from connect/accept (F05): 0 unknown, 1 server/accept, 2 client/connect.
pub const ROLE_HINT_UNKNOWN: u8 = 0;
pub const ROLE_HINT_SERVER: u8 = 1;
pub const ROLE_HINT_CLIENT: u8 = 2;

#[repr(C)]
pub struct TlsEventHeader {
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ssl_ptr: u64,
    pub data_len: u32,
    pub direction: u8,
    pub ip_family: u8,
    pub _pad16: u16,
    pub comm: [u8; 16],
    pub cgroup_id: u64,
    pub netns_ino: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip4: u32,
    pub dst_ip4: u32,
    pub src_ip6: [u8; 16],
    pub dst_ip6: [u8; 16],
    // --- ABI v2 fields (F03/F08) — must match bpf/http_trace.bpf.c ---
    pub abi_version: u16,
    pub flags: u16,
    pub actual_len: u32,
    pub copied_len: u32,
    pub conn_generation: u32,
    pub proc_start_ns: u64,
    pub dir_seq: u32,
    pub attribution: u8,
    pub provider_id: u8,
    pub role_hint: u8,
    pub _pad8: u8,
    pub sock_cookie: u64,
    // data follows inline (variable length)
}

impl TlsEventHeader {
    pub const HEADER_SIZE: usize = std::mem::size_of::<Self>();

    /// Zeroed header with `abi_version` set — use in tests via field updates.
    pub fn blank() -> Self {
        Self {
            ts_ns: 0,
            pid: 0,
            tid: 0,
            ssl_ptr: 0,
            data_len: 0,
            direction: 0,
            ip_family: 0,
            _pad16: 0,
            comm: [0; 16],
            cgroup_id: 0,
            netns_ino: 0,
            src_port: 0,
            dst_port: 0,
            src_ip4: 0,
            dst_ip4: 0,
            src_ip6: [0; 16],
            dst_ip6: [0; 16],
            abi_version: TLS_EVENT_ABI_VERSION,
            flags: 0,
            actual_len: 0,
            copied_len: 0,
            conn_generation: 0,
            proc_start_ns: 0,
            dir_seq: 0,
            attribution: 0,
            provider_id: PROVIDER_UNKNOWN,
            role_hint: ROLE_HINT_UNKNOWN,
            _pad8: 0,
            sock_cookie: 0,
        }
    }

    /// Safely parse a TlsEventHeader from a raw byte slice from the BPF ring buffer.
    ///
    /// Uses `read_unaligned` to handle any pointer alignment from the ring buffer,
    /// returning an owned copy of the header so no raw reference escapes.
    /// `data_len` / `copied_len` from the kernel are clamped defensively to prevent OOB reads.
    pub fn from_bytes(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }
        // SAFETY: data.len() >= HEADER_SIZE guarantees the read is in-bounds.
        // read_unaligned handles any alignment — ring buffer data may not be
        // aligned to TlsEventHeader's 8-byte alignment requirement.
        let header: Self = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        let max_payload = data.len().saturating_sub(Self::HEADER_SIZE);
        let reported = if header.copied_len > 0 {
            header.copied_len as usize
        } else {
            header.data_len as usize
        };
        let data_len = reported.min(max_payload);
        let payload = &data[Self::HEADER_SIZE..Self::HEADER_SIZE + data_len];
        Some((header, payload))
    }

    pub fn is_truncated(&self) -> bool {
        (self.flags & TLS_FLAG_TRUNCATED) != 0
            || (self.actual_len > 0 && self.copied_len > 0 && self.actual_len > self.copied_len)
    }

    pub fn attribution_confident(&self) -> bool {
        (self.flags & TLS_FLAG_ATTR_SSL) != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloseEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ssl_ptr: u64,
    pub proc_start_ns: u64,
    pub generation: u32,
    pub _pad: u32,
}

// ---------------------------------------------------------------------------
// API traffic model
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Default)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub scheme: String,
    pub headers: HashMap<String, String>,
    pub query: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct ApiResponse {
    pub status_code: i32,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Serialize, Default)]
pub struct EventMetadata {
    pub has_injection: bool,
    pub injection_patterns: Vec<String>,
    pub permission_flags: Vec<String>,
    pub mcp_method: Option<String>,
    pub mcp_tool_name: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct ApiTrafficEvent {
    pub version: String,
    pub event_type: String,
    pub source: String,
    pub account_id: u64,
    pub observed_at: u64,
    pub protocol: String,
    pub request: ApiRequest,
    pub response: ApiResponse,
    pub collection_id: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub netns_ino: Option<u32>,
    pub cgroup_id: Option<u64>,
    pub container: Option<ContainerContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EventMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_features: Option<AnomalyFeatures>,
    // Identity fields — populated from JWT, headers, and cookies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_session_id: Option<String>,
    /// Set when the transaction did not complete normally: `timed_out`, `connection_closed`,
    /// `capture_gap`. The response is then absent, never fabricated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// `incoming` when the observed process received the request (it is the server),
    /// `outgoing` when it sent it. Absent when the request direction is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<&'static str>,
}

impl ApiTrafficEvent {
    /// Heap bytes this event holds, plus its fixed size. Charged against the export queue and
    /// batch byte budgets; it errs high (map entries are charged a fixed overhead each).
    pub fn approx_bytes(&self) -> usize {
        const ENTRY_OVERHEAD: usize = 48;
        fn s(v: &Option<String>) -> usize {
            v.as_ref().map_or(0, String::len)
        }
        fn map(m: &HashMap<String, String>) -> usize {
            m.iter().map(|(k, v)| k.len() + v.len() + ENTRY_OVERHEAD).sum()
        }
        let r = &self.request;
        let mut n = std::mem::size_of::<Self>()
            + self.version.len() + self.event_type.len() + self.source.len() + self.protocol.len()
            + r.method.len() + r.path.len() + r.scheme.len() + s(&r.host) + s(&r.body)
            + map(&r.headers) + map(&r.query)
            + map(&self.response.headers) + s(&self.response.body)
            + s(&self.collection_id) + s(&self.source_ip) + s(&self.dest_ip)
            + s(&self.process_name) + s(&self.source_hostname) + s(&self.dest_hostname)
            + s(&self.user_id) + s(&self.user_role) + s(&self.session_id) + s(&self.auth_session_id)
            + s(&self.outcome);
        if let Some(c) = &self.container {
            n += std::mem::size_of::<ContainerContext>() + c.container_id.len() + c.node_name.len()
                + s(&c.pod_name) + s(&c.pod_namespace) + s(&c.container_name)
                + s(&c.service_name) + s(&c.workload_type);
        }
        if let Some(m) = &self.metadata {
            n += std::mem::size_of::<EventMetadata>() + s(&m.mcp_method) + s(&m.mcp_tool_name)
                + m.injection_patterns.iter().chain(&m.permission_flags).map(|p| p.len() + 24).sum::<usize>();
        }
        if self.anomaly_features.is_some() {
            n += std::mem::size_of::<AnomalyFeatures>();
        }
        n
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerContext {
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub container_id: String,
    pub container_name: Option<String>,
    pub node_name: String,
    pub service_name: Option<String>,
    pub workload_type: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct AnomalyFeatures {
    pub path_depth: u8,
    pub query_param_count: u8,
    pub has_encoded_chars: bool,
    pub request_size_bucket: u8,
    pub shannon_entropy: f32,
    pub has_sqli_pattern: bool,
    pub has_xss_pattern: bool,
    pub has_path_traversal: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NetContext {
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub netns_ino: Option<u32>,
    pub cgroup_id: Option<u64>,
    pub container: Option<ContainerContext>,
    pub process_name: Option<String>,
    pub source_hostname: Option<String>,
    pub dest_hostname: Option<String>,
    pub direction: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficRole {
    Server,
    Client,
    /// Infer per-connection role from accept/connect + HTTP preface/syntax (F05).
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub pid: u32,
    pub ssl_ptr: u64,
    pub direction: u8,
    pub proc_start_ns: u64,
    pub generation: u32,
}

impl StreamKey {
    pub fn from_event(ev: &TlsEventHeader) -> Self {
        Self {
            pid: ev.pid,
            ssl_ptr: ev.ssl_ptr,
            direction: ev.direction,
            proc_start_ns: ev.proc_start_ns,
            generation: ev.conn_generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub pid: u32,
    pub ssl_ptr: u64,
    pub born_ms: u64,
    pub proc_start_ns: u64,
    pub generation: u32,
}

impl ConnKey {
    pub fn from_event(ev: &TlsEventHeader, born_ms: u64) -> Self {
        Self {
            pid: ev.pid,
            ssl_ptr: ev.ssl_ptr,
            born_ms,
            proc_start_ns: ev.proc_start_ns,
            generation: ev.conn_generation,
        }
    }

    pub fn from_close(ev: &CloseEvent) -> Self {
        Self {
            pid: ev.pid,
            ssl_ptr: ev.ssl_ptr,
            born_ms: 0,
            proc_start_ns: ev.proc_start_ns,
            generation: ev.generation,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub ts_ms: u64,
    pub net_ctx: NetContext,
    pub body: Vec<u8>,
}

impl ParsedRequest {
    /// Estimated heap footprint, used to charge queued requests against the memory ceiling.
    /// Deliberately a slight over-estimate (per-entry String/HashMap overhead is counted).
    pub fn approx_bytes(&self) -> usize {
        const ENTRY_OVERHEAD: usize = 64; // two String headers + hash bucket
        const NET_CTX_OVERHEAD: usize = 384; // ip/hostname/container/process strings
        std::mem::size_of::<Self>()
            + NET_CTX_OVERHEAD
            + self.method.len()
            + self.path.len()
            + self.host.as_ref().map_or(0, |h| h.len())
            + self.headers.iter().map(|(k, v)| k.len() + v.len() + ENTRY_OVERHEAD).sum::<usize>()
            + self.body.len()
    }
}

#[derive(Debug, Serialize)]
pub struct EventBatch {
    pub version: String,
    pub events: Vec<ApiTrafficEvent>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic that begins the client connection preface. A scan uses this short
/// prefix so HTTP/2 is recognised even when the 24-byte preface is split.
pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0";

/// Full client connection preface, RFC 9113 §3.4. The 10 bytes after the
/// magic (`\r\n\r\nSM\r\n\r\n`) are part of the preface, not a frame.
pub const HTTP2_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const MAX_STREAM_ENTRIES: usize = 10_000;
pub const STREAM_TTL_MS: u64 = 300_000;
pub const NUM_SHARDS: usize = 16;

#[cfg(test)]
mod abi_tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    /// Offsets mirror `struct tls_event_hdr` in bpf/http_trace.bpf.c. A mismatch here means the
    /// kernel and userspace disagree on every field after the first divergence.
    #[test]
    fn tls_event_header_layout_matches_bpf() {
        assert_eq!(offset_of!(TlsEventHeader, ts_ns), 0);
        assert_eq!(offset_of!(TlsEventHeader, data_len), 24);
        assert_eq!(offset_of!(TlsEventHeader, comm), 32);
        assert_eq!(offset_of!(TlsEventHeader, cgroup_id), 48);
        assert_eq!(offset_of!(TlsEventHeader, src_ip6), 72);
        assert_eq!(offset_of!(TlsEventHeader, dst_ip6), 88);
        assert_eq!(offset_of!(TlsEventHeader, abi_version), 104);
        assert_eq!(offset_of!(TlsEventHeader, flags), 106);
        assert_eq!(offset_of!(TlsEventHeader, actual_len), 108);
        assert_eq!(offset_of!(TlsEventHeader, copied_len), 112);
        assert_eq!(offset_of!(TlsEventHeader, conn_generation), 116);
        assert_eq!(offset_of!(TlsEventHeader, proc_start_ns), 120);
        assert_eq!(offset_of!(TlsEventHeader, dir_seq), 128);
        assert_eq!(offset_of!(TlsEventHeader, attribution), 132);
        assert_eq!(offset_of!(TlsEventHeader, provider_id), 133);
        assert_eq!(offset_of!(TlsEventHeader, role_hint), 134);
        assert_eq!(offset_of!(TlsEventHeader, sock_cookie), 136);
        assert_eq!(size_of::<TlsEventHeader>(), 144);
    }

    #[test]
    fn close_event_layout_matches_bpf() {
        assert_eq!(offset_of!(CloseEvent, ssl_ptr), 16);
        assert_eq!(offset_of!(CloseEvent, proc_start_ns), 24);
        assert_eq!(offset_of!(CloseEvent, generation), 32);
        assert_eq!(size_of::<CloseEvent>(), 40);
    }

    fn raw(h: &TlsEventHeader, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; TlsEventHeader::HEADER_SIZE];
        unsafe { std::ptr::write_unaligned(v.as_mut_ptr() as *mut TlsEventHeader, std::ptr::read(h)) };
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn truncated_call_reports_both_lengths_and_is_flagged() {
        let mut h = TlsEventHeader::blank();
        h.actual_len = 32_768;
        h.copied_len = 32_767;
        h.data_len = 32_767;
        h.flags = TLS_FLAG_TRUNCATED;
        let bytes = raw(&h, &vec![b'a'; 32_767]);
        let (parsed, payload) = TlsEventHeader::from_bytes(&bytes).unwrap();
        assert_eq!(payload.len(), 32_767);
        assert!(parsed.is_truncated());
    }

    #[test]
    fn complete_call_is_not_flagged() {
        let mut h = TlsEventHeader::blank();
        h.actual_len = 100;
        h.copied_len = 100;
        h.data_len = 100;
        let bytes = raw(&h, &[b'x'; 100]);
        let (parsed, payload) = TlsEventHeader::from_bytes(&bytes).unwrap();
        assert_eq!(payload.len(), 100);
        assert!(!parsed.is_truncated());
    }

    #[test]
    fn kernel_lengths_beyond_the_record_are_clamped() {
        let mut h = TlsEventHeader::blank();
        h.copied_len = 10_000;
        h.data_len = 10_000;
        let bytes = raw(&h, b"short");
        let (_, payload) = TlsEventHeader::from_bytes(&bytes).unwrap();
        assert_eq!(payload, b"short");
    }
}
