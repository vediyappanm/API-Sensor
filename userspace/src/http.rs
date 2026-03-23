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
    pub body: Option<String>,
}

#[derive(Debug)]
pub struct HttpResponseParsed {
    pub status_code: i32,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
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
        if pos + 2 > data.len() { return None; }
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
                body: None,
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
        let (body, remaining) = advance_past_body(&headers, buf, body_start)?;
        return Some((HttpMessage::Response(HttpResponseParsed {
            status_code: status,
            headers,
            body: if body.is_empty() { None } else { Some(String::from_utf8_lossy(&body).to_string()) }
        }), remaining));
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    if !is_http_method(&method) {
        let remaining = buf[body_start..].to_vec();
        return Some((HttpMessage::Request(HttpRequestParsed {
            method: "UNKNOWN".to_string(),
            path: "/".to_string(),
            host: None,
            headers: HashMap::new(),
            body: None,
        }), remaining));
    }
    let path    = parts.next().unwrap_or("/").to_string();
    let headers = parse_headers(lines);
    let host    = headers.get("host").cloned();
    let (body, remaining) = advance_past_body(&headers, buf, body_start)?;
    Some((HttpMessage::Request(HttpRequestParsed {
        method,
        path,
        host,
        headers,
        body: if body.is_empty() { None } else { Some(String::from_utf8_lossy(&body).to_string()) }
    }), remaining))
}

/// Returns None if a body is expected but not yet fully received (caller should
/// keep buffering).  Returns Some((body, remaining)) when the message is complete.
fn advance_past_body(
    headers: &HashMap<String, String>,
    buf: &[u8],
    body_start: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let body_slice = &buf[body_start..];

    if headers.get("transfer-encoding").map(|v| v.contains("chunked")).unwrap_or(false) {
        if let Some((decoded, consumed)) = decode_chunked_body(body_slice) {
            return Some((decoded, body_slice[consumed..].to_vec()));
        }
        return None; // chunked body not yet complete
    }

    if let Some(len_str) = headers.get("content-length") {
        if let Ok(content_len) = len_str.trim().parse::<usize>() {
            if body_slice.len() >= content_len {
                return Some((body_slice[..content_len].to_vec(), body_slice[content_len..].to_vec()));
            }
            // Wait for complete body if reasonably small; emit without body for large payloads
            if content_len <= 8192 {
                return None;
            }
            return Some((Vec::new(), body_slice.to_vec()));
        }
    }

    Some((Vec::new(), body_slice.to_vec()))
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

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

pub fn discover_tls_libs(pid: i32) -> Vec<String> {
    let pids = if pid > 0 {
        vec![pid]
    } else {
        enumerate_pids()
    };
    if pids.is_empty() { return Vec::new(); }

    let mut libs = HashMap::<String, bool>::new();
    for p in &pids {
        let maps_path = format!("/proc/{}/maps", p);
        let Ok(contents) = fs::read_to_string(&maps_path) else { continue };
        for line in contents.lines() {
            if let Some(path) = line.split_whitespace().nth(5) {
                if path.contains("libssl") || path.contains("libgnutls") {
                    let host_path = crate::types::proc_root_path(*p, path);
                    if !libs.contains_key(&host_path) {
                        tracing::debug!(original = %path, resolved = %host_path, pid = p, "TLS lib discovered");
                        libs.insert(host_path, true);
                    }
                }
            }
        }
    }
    if pid <= 0 && !libs.is_empty() {
        tracing::info!(count = libs.len(), pids_scanned = pids.len(), "global TLS lib discovery complete");
    }
    libs.keys().cloned().collect()
}

pub fn enumerate_pids() -> Vec<i32> {
    let mut pids = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else { return pids };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<i32>() {
            if pid > 2 {
                pids.push(pid);
            }
        }
    }
    pids
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
    }
}
