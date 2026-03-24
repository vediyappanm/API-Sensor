use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;

/// BPF event struct version — must match BPF_EVENT_VERSION in http_trace.bpf.c
pub const BPF_EVENT_VERSION: u8 = 1;

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
    // data follows inline (variable length)
}

impl TlsEventHeader {
    pub const HEADER_SIZE: usize = std::mem::size_of::<Self>();

    /// Safely parse a TlsEventHeader from a raw byte slice from the BPF ring buffer.
    ///
    /// Uses `read_unaligned` to handle any pointer alignment from the ring buffer,
    /// returning an owned copy of the header so no raw reference escapes.
    /// `data_len` from the kernel is clamped defensively to prevent OOB reads.
    pub fn from_bytes(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }
        // SAFETY: data.len() >= HEADER_SIZE guarantees the read is in-bounds.
        // read_unaligned handles any alignment — ring buffer data may not be
        // aligned to TlsEventHeader's 8-byte alignment requirement.
        let header: Self = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        // Sanity check — reject events with clearly invalid fields
        if header.pid == 0 || header.data_len as usize > data.len() {
            return None;
        }
        // Clamp kernel-supplied data_len to the actual remaining bytes to prevent
        // any possibility of out-of-bounds slice indexing.
        let max_payload = data.len().saturating_sub(Self::HEADER_SIZE);
        let data_len = (header.data_len as usize).min(max_payload);
        let payload = &data[Self::HEADER_SIZE..Self::HEADER_SIZE + data_len];
        Some((header, payload))
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloseEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ssl_ptr: u64,
}

// ---------------------------------------------------------------------------
// API traffic model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub scheme: String,
    pub headers: HashMap<String, String>,
    pub query: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    pub status_code: i32,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventMetadata {
    pub has_injection: bool,
    pub injection_patterns: Vec<String>,
    pub permission_flags: Vec<String>,
    pub mcp_method: Option<String>,
    pub mcp_tool_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerContext {
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub container_id: String,
    pub container_name: Option<String>,
    pub node_name: String,
    pub service_name: Option<String>,
    pub workload_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficRole {
    Server,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub pid: u32,
    pub ssl_ptr: u64,
    pub direction: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub pid: u32,
    pub ssl_ptr: u64,
    pub born_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub ts_ms: u64,
    pub net_ctx: NetContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    pub version: String,
    pub events: Vec<ApiTrafficEvent>,
}

// ---------------------------------------------------------------------------
// Mount namespace helpers
// ---------------------------------------------------------------------------

/// Translate a container-internal path to a host-accessible path via procfs.
///
/// When the sensor runs in a different mount namespace than the target process
/// (e.g. sensor container observing a Node.js container), paths extracted from
/// `/proc/<pid>/maps` refer to the *target's* filesystem.  The sensor cannot
/// open those paths directly because its own root filesystem is different.
///
/// `/proc/<pid>/root/<path>` is a kernel-provided symlink that lets any process
/// with `CAP_SYS_PTRACE` read files through another process's mount namespace.
/// This works for both `fs::read` *and* libbpf uprobe attachment (the kernel
/// resolves the correct inode through procfs).
///
/// When `pid <= 0` (meaning "all processes" / no specific target), the path is
/// returned unchanged — the sensor and target share the same namespace.
pub fn proc_root_path(pid: i32, path: &str) -> String {
    if pid > 0 {
        format!("/proc/{}/root{}", pid, path)
    } else {
        path.to_string()
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0";
pub const MAX_STREAM_ENTRIES: usize = 10_000;
pub const STREAM_TTL_MS: u64 = 60_000;
pub const NUM_SHARDS: usize = 16;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_root_path_positive_pid() {
        assert_eq!(
            proc_root_path(12345, "/usr/lib/libssl.so.3"),
            "/proc/12345/root/usr/lib/libssl.so.3"
        );
    }

    #[test]
    fn proc_root_path_with_go_binary() {
        assert_eq!(
            proc_root_path(99, "/usr/local/bin/node"),
            "/proc/99/root/usr/local/bin/node"
        );
    }

    #[test]
    fn proc_root_path_no_pid_passthrough() {
        // pid <= 0 means "all processes" — no namespace translation
        assert_eq!(
            proc_root_path(-1, "/usr/lib/libssl.so.3"),
            "/usr/lib/libssl.so.3"
        );
        assert_eq!(
            proc_root_path(0, "/usr/lib/libssl.so.3"),
            "/usr/lib/libssl.so.3"
        );
    }

    #[test]
    fn proc_root_path_preserves_deep_paths() {
        assert_eq!(
            proc_root_path(1, "/app/vendor/lib/x86_64-linux-gnu/libssl.so.3"),
            "/proc/1/root/app/vendor/lib/x86_64-linux-gnu/libssl.so.3"
        );
    }
}
