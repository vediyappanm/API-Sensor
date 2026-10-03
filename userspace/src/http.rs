use std::collections::HashMap;
use std::fs;

// ---------------------------------------------------------------------------
// HTTP/1.1 parsing types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct HttpRequestParsed {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct HttpResponseParsed {
    pub status_code: i32,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum HttpMessage {
    Request(HttpRequestParsed),
    Response(HttpResponseParsed),
}

// ---------------------------------------------------------------------------
// HTTP/1.1 parsing helpers
// ---------------------------------------------------------------------------

pub fn split_query(path: &str) -> (String, HashMap<String, String>) {
    let mut query = HashMap::new();
    if let Some((base, qs)) = path.split_once('?') {
        for pair in qs.split('&') {
            if pair.is_empty() { continue; }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            query.insert(k.to_string(), v.to_string());
        }
        return (base.to_string(), query);
    }
    (path.to_string(), query)
}

pub fn decode_chunked_body(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut body = Vec::new();
    let mut pos  = 0;
    loop {
        let line_end = data[pos..].windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&data[pos..pos + line_end]).ok()?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(hex_part, 16).ok()?;
        pos += line_end + 2;

        if chunk_size == 0 {
            if data.len() >= pos + 2 { pos += 2; }
            return Some((body, pos));
        }

        if pos + chunk_size + 2 > data.len() { return None; }
        body.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size + 2;
    }
}

pub fn extract_http_header(buf: &[u8]) -> Option<(HttpMessage, Vec<u8>)> {
    let needle = b"\r\n\r\n";
    let pos = buf.windows(needle.len()).position(|w| w == needle)?;
    let header_bytes = &buf[..pos + needle.len()];
    let body_start = pos + needle.len();
    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => {
            let remaining = buf[body_start..].to_vec();
            return Some((HttpMessage::Request(HttpRequestParsed {
                method: "UNKNOWN".to_string(),
                path: "/".to_string(),
                host: None,
                headers: HashMap::new(),
                body: Vec::new(),
            }), remaining));
        }
    };
    let mut lines = header_str.split("\r\n");
    let first = lines.next().unwrap_or("");
    if first.starts_with("HTTP/") {
        let mut parts = first.split_whitespace();
        let _ = parts.next();
        let status = parts.next().unwrap_or("0").parse::<i32>().unwrap_or(0);
        let headers = parse_headers(lines);
        let (body, remaining) = split_body(&headers, buf, body_start);
        return Some((HttpMessage::Response(HttpResponseParsed { status_code: status, headers, body }), remaining));
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    if !is_http_method(&method) {
        // Consume the bytes so the stream buffer can advance, but do not
        // invent a fake GET /. Callers must not queue this as a request.
        let remaining = buf[body_start..].to_vec();
        return Some((HttpMessage::Request(HttpRequestParsed {
            method: "UNKNOWN".to_string(),
            path: "/".to_string(),
            host: None,
            headers: HashMap::new(),
            body: Vec::new(),
        }), remaining));
    }
    let path    = parts.next().unwrap_or("/").to_string();
    let headers = parse_headers(lines);
    let host    = headers.get("host").cloned();
    let (body, remaining) = split_body(&headers, buf, body_start);
    Some((HttpMessage::Request(HttpRequestParsed { method, path, host, headers, body }), remaining))
}

/// Split the bytes after the header block into (body, remaining-after-body).
/// Only a fully-present body (per content-length / chunked framing) is
/// returned; a partial body yields an empty body and leaves the bytes in
/// `remaining` so the caller can wait for the rest.
fn split_body(
    headers: &HashMap<String, String>,
    buf: &[u8],
    body_start: usize,
) -> (Vec<u8>, Vec<u8>) {
    let body_slice = &buf[body_start..];

    if headers.get("transfer-encoding").map(|v| v.contains("chunked")).unwrap_or(false) {
        if let Some((decoded, consumed)) = decode_chunked_body(body_slice) {
            return (decoded, body_slice[consumed..].to_vec());
        }
        return (Vec::new(), body_slice.to_vec());
    }

    if let Some(len_str) = headers.get("content-length") {
        if let Ok(content_len) = len_str.trim().parse::<usize>() {
            if body_slice.len() >= content_len {
                return (body_slice[..content_len].to_vec(), body_slice[content_len..].to_vec());
            }
            return (Vec::new(), body_slice.to_vec());
        }
    }

    (Vec::new(), body_slice.to_vec())
}

pub fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() { break; }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    headers
}

pub fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

/// True when method/path are real HTTP, not the sensor's unpaired-response placeholder.
pub fn is_usable_http_request(method: &str, path: &str) -> bool {
    is_http_method(method) && !path.is_empty()
}

/// TLS libraries to attach to. `pid > 0`: the libraries mapped by that process. `pid <= 0` (the
/// DaemonSet default): every distinct libssl/libgnutls mapped by any process on the node. This used
/// to return an empty list for `pid <= 0`, which made `--discover-libs` a silent no-op node-wide, so
/// a sensor started the documented way watched only its own container's library.
pub fn discover_tls_libs(pid: i32) -> Vec<String> {
    if pid <= 0 {
        return discover_tls_libs_in(std::path::Path::new("/proc"));
    }
    let mut libs = HashMap::<String, bool>::new();
    let maps_path = format!("/proc/{}/maps", pid);
    let Ok(contents) = fs::read_to_string(&maps_path) else { return Vec::new(); };
    for line in contents.lines() {
        if let Some(path) = line.split_whitespace().nth(5) {
            if path.contains("libssl") || path.contains("libgnutls") {
                libs.insert(path.to_string(), true);
            }
        }
    }
    libs.keys().cloned().collect()
}

/// Upper bound on libraries attached node-wide. Each one costs several probes; an unbounded
/// number of distinct images on a busy node must not turn into unbounded kernel state.
const MAX_DISCOVERED_LIBS: usize = 512;

/// Scan `<proc_root>/<pid>/maps` for every process and return each distinct libssl/libgnutls once.
///
/// "Distinct" means the same underlying file (device + inode): thousands of processes map one
/// library, and uprobes attach to the file, not the process. Each library is returned as
/// `<proc_root>/<pid>/root<path>` because that is the only way to open a file that lives in
/// another container's mount namespace. The result is sorted so the choice is deterministic.
pub fn discover_tls_libs_in(proc_root: &std::path::Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut seen = std::collections::HashSet::<(u64, u64)>::new();
    let mut found = Vec::<String>::new();
    let Ok(entries) = fs::read_dir(proc_root) else { return found };
    let mut pids: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .collect();
    pids.sort_by_key(|p| p.parse::<u64>().unwrap_or(u64::MAX));
    for pid in pids {
        let Ok(maps) = fs::read_to_string(proc_root.join(&pid).join("maps")) else { continue };
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else { continue };
            if !path.starts_with('/') || path.ends_with("(deleted)") {
                continue;
            }
            let name = path.rsplit('/').next().unwrap_or("");
            if !(name.starts_with("libssl.so") || name.starts_with("libgnutls.so")) {
                continue;
            }
            let via_proc = proc_root.join(&pid).join("root").join(path.trim_start_matches('/'));
            let Ok(meta) = fs::metadata(&via_proc) else { continue };
            if seen.insert((meta.dev(), meta.ino())) {
                found.push(via_proc.to_string_lossy().into_owned());
                if found.len() >= MAX_DISCOVERED_LIBS {
                    found.sort();
                    return found;
                }
            }
        }
    }
    found.sort();
    found
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("discover-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Fake process `pid` that maps `lib` (a path inside its own root).
    fn fake_process(proc_root: &Path, pid: u32, lib: &str, content: &[u8]) {
        let root = proc_root.join(pid.to_string()).join("root");
        let file = root.join(lib.trim_start_matches('/'));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, content).unwrap();
        std::fs::write(
            proc_root.join(pid.to_string()).join("maps"),
            format!("7f00-7f10 r-xp 00000000 08:01 12345 {lib}\n7f20-7f30 r--p 0 08:01 99 /usr/lib/libc.so.6\n"),
        )
        .unwrap();
    }

    #[test]
    fn finds_each_distinct_library_once_reached_through_proc_root() {
        let p = scratch("distinct");
        fake_process(&p, 100, "/usr/lib/x86_64-linux-gnu/libssl.so.3", b"openssl-A");
        fake_process(&p, 200, "/lib/libssl.so.1.1", b"openssl-B"); // different image, different file
        let libs = discover_tls_libs_in(&p);
        assert_eq!(libs.len(), 2, "{libs:?}");
        assert!(libs.iter().all(|l| l.contains("/root/")), "must go through /proc/<pid>/root: {libs:?}");
        assert!(libs.windows(2).all(|w| w[0] <= w[1]), "deterministic order");
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn a_library_shared_by_many_processes_is_attached_once() {
        let p = scratch("shared");
        fake_process(&p, 100, "/usr/lib/libssl.so.3", b"same-file");
        // process 300 maps the very same file (hard link => same device + inode)
        let a = p.join("100/root/usr/lib/libssl.so.3");
        let b_dir = p.join("300/root/usr/lib");
        std::fs::create_dir_all(&b_dir).unwrap();
        std::fs::hard_link(&a, b_dir.join("libssl.so.3")).unwrap();
        std::fs::write(p.join("300/maps"), "7f00-7f10 r-xp 0 08:01 12345 /usr/lib/libssl.so.3\n").unwrap();
        assert_eq!(discover_tls_libs_in(&p).len(), 1, "same inode must be deduplicated");
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn ignores_other_libraries_deleted_mappings_and_non_pid_entries() {
        let p = scratch("ignore");
        fake_process(&p, 100, "/usr/lib/libcrypto.so.3", b"not-tls-entry-point"); // libcrypto is not libssl
        std::fs::create_dir_all(p.join("self")).unwrap();
        std::fs::write(p.join("self/maps"), "7f00-7f10 r-xp 0 08:01 1 /usr/lib/libssl.so.3\n").unwrap();
        std::fs::create_dir_all(p.join("400")).unwrap();
        std::fs::write(p.join("400/maps"), "7f00-7f10 r-xp 0 08:01 1 /usr/lib/libssl.so.3 (deleted)\n[heap]\nanon\n").unwrap();
        assert!(discover_tls_libs_in(&p).is_empty());
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn unreadable_or_missing_proc_yields_nothing_instead_of_failing() {
        assert!(discover_tls_libs_in(Path::new("/definitely/not/a/proc")).is_empty());
        let p = scratch("nomaps");
        std::fs::create_dir_all(p.join("500")).unwrap(); // a pid dir with no maps file
        assert!(discover_tls_libs_in(&p).is_empty());
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn node_wide_discovery_finds_the_libraries_of_the_real_machine() {
        // pid <= 0 must now scan /proc rather than return an empty list. Only assert when this
        // machine actually has a TLS library mapped by some process we can read.
        let from_proc = discover_tls_libs(-1);
        let direct = discover_tls_libs_in(Path::new("/proc"));
        assert_eq!(from_proc, direct);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_query() {
        let (path, query) = split_query("/api/v1/user?id=123&name=test");
        assert_eq!(path, "/api/v1/user");
        assert_eq!(query.get("id").unwrap(), "123");
        assert_eq!(query.get("name").unwrap(), "test");

        let (path, query) = split_query("/health");
        assert_eq!(path, "/health");
        assert!(query.is_empty());
    }

    #[test]
    fn test_extract_http_header_request() {
        let buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\nRemaining data".to_vec();
        let (msg, remaining) = extract_http_header(&buf).unwrap();
        if let HttpMessage::Request(req) = msg {
            assert_eq!(req.method, "GET");
            assert_eq!(req.path, "/index.html");
            assert_eq!(req.headers.get("host").unwrap(), "example.com");
            assert_eq!(req.headers.get("user-agent").unwrap(), "test");
        } else {
            panic!("Expected Request");
        }
        assert_eq!(remaining, b"Remaining data");
    }

    #[test]
    fn test_extract_http_header_response() {
        // Body is 16 bytes; append a sentinel to verify pipelining (remaining = bytes after body)
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"status\": \"ok\"}PIPELINE".to_vec();
        let (msg, remaining) = extract_http_header(&buf).unwrap();
        if let HttpMessage::Response(resp) = msg {
            assert_eq!(resp.status_code, 200);
            assert_eq!(resp.headers.get("content-type").unwrap(), "application/json");
        } else {
            panic!("Expected Response");
        }
        assert_eq!(remaining, b"PIPELINE");
    }

    #[test]
    fn test_chunked_body_decode() {
        let chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (body, consumed) = decode_chunked_body(chunked).unwrap();
        assert_eq!(&body, b"hello world");
        assert_eq!(consumed, chunked.len());
    }

    #[test]
    fn usable_request_rejects_unknown_placeholder() {
        assert!(is_usable_http_request("GET", "/api/sensors/"));
        assert!(is_usable_http_request("POST", "/v2/"));
        assert!(!is_usable_http_request("UNKNOWN", "/"));
        assert!(!is_usable_http_request("TEXT", "/ws"));
        assert!(!is_usable_http_request("GET", ""));
    }

    #[test]
    fn invalid_first_line_is_unknown_placeholder_not_queued_as_http() {
        let buf = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let (msg, _) = extract_http_header(buf).unwrap();
        match msg {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "UNKNOWN");
                assert_eq!(req.path, "/");
                assert!(!is_usable_http_request(&req.method, &req.path));
            }
            other => panic!("expected placeholder request, got {other:?}"),
        }
    }
}
