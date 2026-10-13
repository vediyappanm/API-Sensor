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

        let end = pos.checked_add(chunk_size)?.checked_add(2)?;
        if end > data.len() { return None; }
        body.extend_from_slice(&data[pos..pos + chunk_size]);
        pos = end;
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
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if line.is_empty() { break; }
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim().to_lowercase(), v.trim());
            // Repeated fields are combined (RFC 9110 §5.3) rather than silently overwritten.
            match headers.get_mut(&k) {
                Some(existing) => {
                    existing.push_str(if k == "set-cookie" { "\n" } else { ", " });
                    existing.push_str(v);
                }
                None => {
                    headers.insert(k, v.to_string());
                }
            }
        }
    }
    headers
}

// ---------------------------------------------------------------------------
// Incremental HTTP/1.x framing (RFC 9112 §6–7)
// ---------------------------------------------------------------------------

/// Header blocks larger than this are treated as invalid framing.
pub const MAX_HTTP1_HEADER_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE: usize = 1024;

/// One decoded HTTP/1 message with body completeness evidence.
#[derive(Debug)]
pub struct Http1Message {
    pub msg: HttpMessage,
    /// Body bytes seen on the wire (after chunk decoding).
    pub body_total: u64,
    /// The retained body is shorter than `body_total` (preview cap).
    pub body_truncated: bool,
    /// The message ended before its framing said it should (close-delimited or upgraded).
    pub partial: bool,
}

#[derive(Debug)]
pub enum Http1Item {
    Message(Http1Message),
    /// Framing could not be parsed; the caller must resynchronise.
    Invalid(&'static str),
}

#[derive(Debug)]
enum Body {
    Fixed(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkCrlf,
    Trailers,
}

#[derive(Debug, Default)]
enum Http1State {
    #[default]
    Head,
    Body { pending: Box<Http1Message>, body: Body },
    /// After `101 Switching Protocols` or a `CONNECT` 2xx: bytes are not HTTP/1.
    Upgraded,
    /// A response with no length: everything until close is body; never re-parsed as HTTP.
    UntilClose,
}

/// Incremental per-direction HTTP/1 decoder. Feed bytes in order; it reports how many were
/// consumed. Only an incomplete header line/block is left for the caller to retain, so body
/// size does not drive buffer size: bodies are counted in full and previewed up to `preview_cap`.
#[derive(Debug)]
pub struct Http1Decoder {
    state: Http1State,
    preview_cap: usize,
}

impl Http1Decoder {
    pub fn new(preview_cap: usize) -> Self {
        Self { state: Http1State::Head, preview_cap }
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.state, Http1State::Head)
    }

    pub fn is_upgraded(&self) -> bool {
        matches!(self.state, Http1State::Upgraded | Http1State::UntilClose)
    }

    /// Decode from `buf`. `response_to_head` says the next response answers a HEAD request
    /// (and `response_to_connect` a CONNECT), which changes how its body is framed.
    /// Returns (bytes consumed, completed items).
    pub fn feed(
        &mut self,
        buf: &[u8],
        response_to_head: bool,
        response_to_connect: bool,
    ) -> (usize, Vec<Http1Item>) {
        let mut pos = 0usize;
        let mut out = Vec::new();
        loop {
            match std::mem::take(&mut self.state) {
                Http1State::Upgraded => {
                    self.state = Http1State::Upgraded;
                    return (buf.len(), out);
                }
                Http1State::UntilClose => {
                    self.state = Http1State::UntilClose;
                    return (buf.len(), out);
                }
                Http1State::Head => {
                    let rest = &buf[pos..];
                    let Some(end) = rest.windows(4).position(|w| w == b"\r\n\r\n") else {
                        if rest.len() > MAX_HTTP1_HEADER_BYTES {
                            out.push(Http1Item::Invalid("header block too large"));
                            return (buf.len(), out);
                        }
                        return (pos, out);
                    };
                    let head = &rest[..end + 4];
                    pos += end + 4;
                    match parse_head(head, response_to_head, response_to_connect) {
                        Ok((msg, framing)) => {
                            let pending = Box::new(Http1Message { msg, body_total: 0, body_truncated: false, partial: false });
                            match framing {
                                Framing::None => out.push(Http1Item::Message(*pending)),
                                Framing::Upgrade => {
                                    out.push(Http1Item::Message(*pending));
                                    self.state = Http1State::Upgraded;
                                    return (buf.len(), out);
                                }
                                Framing::Fixed(0) => out.push(Http1Item::Message(*pending)),
                                Framing::Fixed(n) => self.state = Http1State::Body { pending, body: Body::Fixed(n) },
                                Framing::Chunked => self.state = Http1State::Body { pending, body: Body::ChunkSize },
                                Framing::UntilClose => {
                                    let mut m = *pending;
                                    let take = (buf.len() - pos).min(self.preview_cap);
                                    append_body(&mut m.msg, &buf[pos..pos + take]);
                                    m.body_total = (buf.len() - pos) as u64;
                                    m.body_truncated = take < buf.len() - pos;
                                    m.partial = true;
                                    out.push(Http1Item::Message(m));
                                    self.state = Http1State::UntilClose;
                                    return (buf.len(), out);
                                }
                            }
                        }
                        Err(reason) => {
                            out.push(Http1Item::Invalid(reason));
                            return (buf.len(), out);
                        }
                    }
                }
                Http1State::Body { mut pending, body } => {
                    let rest = &buf[pos..];
                    match body {
                        Body::Fixed(remaining) => {
                            let take = (rest.len() as u64).min(remaining) as usize;
                            self.preview(&mut pending, &rest[..take]);
                            pos += take;
                            let left = remaining - take as u64;
                            if left == 0 {
                                out.push(Http1Item::Message(*pending));
                            } else {
                                self.state = Http1State::Body { pending, body: Body::Fixed(left) };
                                return (pos, out);
                            }
                        }
                        Body::ChunkSize => {
                            let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
                                if rest.len() > MAX_CHUNK_LINE {
                                    out.push(Http1Item::Invalid("chunk size line too long"));
                                    return (buf.len(), out);
                                }
                                self.state = Http1State::Body { pending, body: Body::ChunkSize };
                                return (pos, out);
                            };
                            let line = std::str::from_utf8(&rest[..eol]).unwrap_or("");
                            let hex = line.split(';').next().unwrap_or("").trim();
                            let size = match u64::from_str_radix(hex, 16) {
                                Ok(s) if !hex.is_empty() && hex.len() <= 16 => s,
                                _ => {
                                    out.push(Http1Item::Invalid("bad chunk size"));
                                    return (buf.len(), out);
                                }
                            };
                            pos += eol + 2;
                            let body = if size == 0 { Body::Trailers } else { Body::ChunkData(size) };
                            self.state = Http1State::Body { pending, body };
                        }
                        Body::ChunkData(remaining) => {
                            let take = (rest.len() as u64).min(remaining) as usize;
                            self.preview(&mut pending, &rest[..take]);
                            pos += take;
                            let left = remaining - take as u64;
                            let body = if left == 0 { Body::ChunkCrlf } else { Body::ChunkData(left) };
                            let stop = left != 0;
                            self.state = Http1State::Body { pending, body };
                            if stop {
                                return (pos, out);
                            }
                        }
                        Body::ChunkCrlf => {
                            if rest.len() < 2 {
                                self.state = Http1State::Body { pending, body: Body::ChunkCrlf };
                                return (pos, out);
                            }
                            if &rest[..2] != b"\r\n" {
                                out.push(Http1Item::Invalid("missing CRLF after chunk"));
                                return (buf.len(), out);
                            }
                            pos += 2;
                            self.state = Http1State::Body { pending, body: Body::ChunkSize };
                        }
                        Body::Trailers => {
                            // Trailer section: zero or more fields, then an empty line.
                            let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
                                if rest.len() > MAX_HTTP1_HEADER_BYTES {
                                    out.push(Http1Item::Invalid("trailers too large"));
                                    return (buf.len(), out);
                                }
                                self.state = Http1State::Body { pending, body: Body::Trailers };
                                return (pos, out);
                            };
                            let line = &rest[..eol];
                            pos += eol + 2;
                            if line.is_empty() {
                                out.push(Http1Item::Message(*pending));
                            } else {
                                if let Ok(s) = std::str::from_utf8(line) {
                                    if let Some((k, v)) = s.split_once(':') {
                                        let hdrs = headers_mut(&mut pending.msg);
                                        hdrs.entry(k.trim().to_lowercase()).or_insert_with(|| v.trim().to_string());
                                    }
                                }
                                self.state = Http1State::Body { pending, body: Body::Trailers };
                            }
                        }
                    }
                }
            }
            if pos >= buf.len() && matches!(self.state, Http1State::Head) {
                return (pos, out);
            }
        }
    }

    fn preview(&self, m: &mut Http1Message, bytes: &[u8]) {
        m.body_total = m.body_total.saturating_add(bytes.len() as u64);
        let have = body_len(&m.msg);
        let room = self.preview_cap.saturating_sub(have);
        let take = bytes.len().min(room);
        append_body(&mut m.msg, &bytes[..take]);
        if take < bytes.len() {
            m.body_truncated = true;
        }
    }
}

enum Framing {
    None,
    Fixed(u64),
    Chunked,
    UntilClose,
    Upgrade,
}

fn body_len(msg: &HttpMessage) -> usize {
    match msg {
        HttpMessage::Request(r) => r.body.len(),
        HttpMessage::Response(r) => r.body.len(),
    }
}

fn append_body(msg: &mut HttpMessage, bytes: &[u8]) {
    match msg {
        HttpMessage::Request(r) => r.body.extend_from_slice(bytes),
        HttpMessage::Response(r) => r.body.extend_from_slice(bytes),
    }
}

fn headers_mut(msg: &mut HttpMessage) -> &mut HashMap<String, String> {
    match msg {
        HttpMessage::Request(r) => &mut r.headers,
        HttpMessage::Response(r) => &mut r.headers,
    }
}

/// Body framing per RFC 9112 §6.3. Conflicting or ambiguous lengths are rejected rather than
/// guessed, because a guess is exactly what request smuggling exploits.
fn body_framing(headers: &HashMap<String, String>, is_request: bool) -> Result<Framing, &'static str> {
    let te = headers.get("transfer-encoding");
    let cl = headers.get("content-length");
    if te.is_some() && cl.is_some() {
        return Err("both transfer-encoding and content-length");
    }
    if let Some(te) = te {
        let last = te.rsplit(',').next().unwrap_or("").trim().to_ascii_lowercase();
        if last == "chunked" {
            return Ok(Framing::Chunked);
        }
        return if is_request { Err("request transfer-encoding without final chunked") } else { Ok(Framing::UntilClose) };
    }
    if let Some(cl) = cl {
        let mut value: Option<u64> = None;
        for part in cl.split(',') {
            let n: u64 = part.trim().parse().map_err(|_| "invalid content-length")?;
            if value.is_some_and(|v| v != n) {
                return Err("conflicting content-length");
            }
            value = Some(n);
        }
        return Ok(Framing::Fixed(value.unwrap_or(0)));
    }
    Ok(if is_request { Framing::None } else { Framing::UntilClose })
}

fn parse_head(head: &[u8], response_to_head: bool, response_to_connect: bool) -> Result<(HttpMessage, Framing), &'static str> {
    let text = std::str::from_utf8(head).map_err(|_| "non-UTF-8 header block")?;
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    if let Some(rest) = first.strip_prefix("HTTP/") {
        let mut parts = rest.split_whitespace();
        let _version = parts.next();
        let status: i32 = parts.next().and_then(|s| s.parse().ok()).ok_or("bad status line")?;
        if !(100..=999).contains(&status) {
            return Err("bad status code");
        }
        let headers = parse_headers(lines);
        let framing = if status == 101 || (response_to_connect && (200..300).contains(&status)) {
            Framing::Upgrade
        } else if (100..200).contains(&status) || status == 204 || status == 304 || response_to_head {
            Framing::None
        } else {
            body_framing(&headers, false)?
        };
        return Ok((HttpMessage::Response(HttpResponseParsed { status_code: status, headers, body: Vec::new() }), framing));
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().ok_or("missing request target")?;
    let version = parts.next().unwrap_or("");
    if !is_http_method(method) || !version.starts_with("HTTP/1.") {
        return Err("not an HTTP/1 request line");
    }
    let headers = parse_headers(lines);
    let host = headers.get("host").cloned();
    let framing = body_framing(&headers, true)?;
    Ok((
        HttpMessage::Request(HttpRequestParsed {
            method: method.to_string(),
            path: path.to_string(),
            host,
            headers,
            body: Vec::new(),
        }),
        framing,
    ))
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

    fn decode_all(chunks: &[&[u8]], head: bool, cap: usize) -> Vec<Http1Item> {
        let mut d = Http1Decoder::new(cap);
        let mut buf = Vec::new();
        let mut out = Vec::new();
        for c in chunks {
            buf.extend_from_slice(c);
            let (n, items) = d.feed(&buf, head, false);
            buf.drain(..n);
            out.extend(items);
        }
        out
    }

    fn messages(items: Vec<Http1Item>) -> Vec<Http1Message> {
        items
            .into_iter()
            .map(|i| match i {
                Http1Item::Message(m) => m,
                Http1Item::Invalid(r) => panic!("unexpected invalid: {r}"),
            })
            .collect()
    }

    fn body_of(m: &Http1Message) -> &[u8] {
        match &m.msg {
            HttpMessage::Request(r) => &r.body,
            HttpMessage::Response(r) => &r.body,
        }
    }

    const PIPELINE: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: h\r\n\r\nPUT /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n";

    #[test]
    fn every_split_point_yields_identical_messages() {
        let whole = messages(decode_all(&[PIPELINE], false, 1024));
        assert_eq!(whole.len(), 3);
        for split in 1..PIPELINE.len() {
            let got = messages(decode_all(&[&PIPELINE[..split], &PIPELINE[split..]], false, 1024));
            assert_eq!(got.len(), 3, "split at {split}");
            for (a, b) in whole.iter().zip(&got) {
                assert_eq!(body_of(a), body_of(b), "split at {split}");
            }
        }
        assert_eq!(body_of(&whole[0]), b"hello");
        assert_eq!(body_of(&whole[2]), b"abcde");
        if let HttpMessage::Request(r) = &whole[2].msg {
            assert_eq!(r.headers.get("x-trailer").map(String::as_str), Some("t"));
        }
    }

    #[test]
    fn byte_at_a_time_feeding_matches() {
        let chunks: Vec<&[u8]> = PIPELINE.chunks(1).collect();
        assert_eq!(messages(decode_all(&chunks, false, 1024)).len(), 3);
    }

    #[test]
    fn interim_100_then_final_response() {
        let got = messages(decode_all(&[b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"], false, 64));
        let codes: Vec<i32> = got
            .iter()
            .map(|m| match &m.msg { HttpMessage::Response(r) => r.status_code, _ => 0 })
            .collect();
        assert_eq!(codes, vec![100, 200]);
        assert_eq!(body_of(&got[1]), b"ok");
    }

    #[test]
    fn head_204_and_304_responses_have_no_body() {
        let head = messages(decode_all(&[b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 200 OK\r\n"], true, 64));
        assert_eq!(head.len(), 1, "HEAD response must not wait for 999 body bytes");
        for status in ["204 No Content", "304 Not Modified"] {
            let raw = format!("HTTP/1.1 {status}\r\nContent-Length: 10\r\n\r\n");
            assert_eq!(messages(decode_all(&[raw.as_bytes()], false, 64)).len(), 1);
        }
    }

    #[test]
    fn body_larger_than_preview_is_consumed_and_flagged() {
        let mut raw = b"POST /up HTTP/1.1\r\nContent-Length: 100000\r\n\r\n".to_vec();
        raw.extend(std::iter::repeat(b'x').take(100_000));
        raw.extend_from_slice(b"GET /next HTTP/1.1\r\n\r\n");
        let got = messages(decode_all(&raw.chunks(4096).collect::<Vec<_>>(), false, 8192));
        assert_eq!(got.len(), 2, "the following request must not be swallowed");
        assert_eq!(got[0].body_total, 100_000);
        assert!(got[0].body_truncated);
        assert_eq!(body_of(&got[0]).len(), 8192);
    }

    #[test]
    fn ambiguous_or_hostile_framing_is_invalid() {
        for raw in [
            &b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFF\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        ] {
            let items = decode_all(&[raw], false, 64);
            assert!(matches!(items.last(), Some(Http1Item::Invalid(_))), "{:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn huge_but_valid_chunk_length_does_not_overflow() {
        let items = decode_all(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\nab"], false, 64);
        assert!(items.is_empty(), "incomplete chunk must wait, not panic or complete");
    }

    #[test]
    fn close_delimited_response_is_partial_and_never_reparsed() {
        let mut d = Http1Decoder::new(64);
        let (_, items) = d.feed(b"HTTP/1.1 200 OK\r\n\r\nstream-start", false, false);
        let m = messages(items);
        assert!(m[0].partial);
        let (n, items) = d.feed(b"HTTP/1.1 200 OK\r\n\r\n", false, false);
        assert_eq!(n, 19);
        assert!(items.is_empty(), "bytes after a close-delimited body are body, not a new response");
    }

    #[test]
    fn repeated_headers_are_combined() {
        let got = messages(decode_all(&[b"GET / HTTP/1.1\r\nAccept: a\r\nAccept: b\r\n\r\n"], false, 64));
        if let HttpMessage::Request(r) = &got[0].msg {
            assert_eq!(r.headers.get("accept").map(String::as_str), Some("a, b"));
        }
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
