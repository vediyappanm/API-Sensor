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
}

#[derive(Debug)]
pub struct HttpResponseParsed {
    pub status_code: i32,
    pub headers: HashMap<String, String>,
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
        let remaining = advance_past_body(&headers, buf, body_start);
        return Some((HttpMessage::Response(HttpResponseParsed { status_code: status, headers }), remaining));
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
        }), remaining));
    }
    let path    = parts.next().unwrap_or("/").to_string();
    let headers = parse_headers(lines);
    let host    = headers.get("host").cloned();
    let remaining = advance_past_body(&headers, buf, body_start);
    Some((HttpMessage::Request(HttpRequestParsed { method, path, host, headers }), remaining))
}

fn advance_past_body(
    headers: &HashMap<String, String>,
    buf: &[u8],
    body_start: usize,
) -> Vec<u8> {
    let body_slice = &buf[body_start..];

    if headers.get("transfer-encoding").map(|v| v.contains("chunked")).unwrap_or(false) {
        if let Some((_decoded, consumed)) = decode_chunked_body(body_slice) {
            return body_slice[consumed..].to_vec();
        }
        return body_slice.to_vec();
    }

    if let Some(len_str) = headers.get("content-length") {
        if let Ok(content_len) = len_str.trim().parse::<usize>() {
            if body_slice.len() >= content_len {
                return body_slice[content_len..].to_vec();
            }
            return body_slice.to_vec();
        }
    }

    body_slice.to_vec()
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

pub fn discover_tls_libs(pid: i32) -> Vec<String> {
    if pid <= 0 { return Vec::new(); }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
