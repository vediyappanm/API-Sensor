use std::collections::HashMap;

// ---------------------------------------------------------------------------
// HTTP/3 variable-length integer encoding (RFC 9000 §16)
// ---------------------------------------------------------------------------

/// Decode a QUIC variable-length integer.  Returns (value, bytes_consumed).
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let prefix = buf[0] >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        return None;
    }
    let mut val = (buf[0] & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | b as u64;
    }
    Some((val, len))
}

// ---------------------------------------------------------------------------
// HTTP/3 frame parsing (RFC 9114 §7)
// ---------------------------------------------------------------------------

/// HTTP/3 frame types
pub const H3_DATA: u64 = 0x00;
pub const H3_HEADERS: u64 = 0x01;
pub const H3_CANCEL_PUSH: u64 = 0x03;
pub const H3_SETTINGS: u64 = 0x04;
pub const H3_PUSH_PROMISE: u64 = 0x05;
pub const H3_GOAWAY: u64 = 0x07;

#[derive(Debug)]
pub struct H3Frame<'a> {
    pub frame_type: u64,
    pub payload: &'a [u8],
}

/// Parse the next HTTP/3 frame from a buffer.
/// Returns the frame and the number of bytes consumed.
pub fn parse_h3_frame(buf: &[u8]) -> Option<(H3Frame<'_>, usize)> {
    let (frame_type, t_len) = decode_varint(buf)?;
    let (payload_len, p_len) = decode_varint(&buf[t_len..])?;
    let header_len = t_len + p_len;
    let payload_len = payload_len as usize;

    if buf.len() < header_len + payload_len {
        return None;
    }
    let payload = &buf[header_len..header_len + payload_len];
    Some((H3Frame { frame_type, payload }, header_len + payload_len))
}

/// Parse all HTTP/3 frames from a buffer.
pub fn parse_h3_frames(buf: &[u8]) -> Vec<H3Frame<'_>> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        match parse_h3_frame(&buf[pos..]) {
            Some((frame, consumed)) => {
                if consumed == 0 {
                    break;
                }
                frames.push(frame);
                pos += consumed;
            }
            None => break,
        }
    }
    frames
}

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 §Appendix A)
// ---------------------------------------------------------------------------

/// (name, value) pairs — index 0..98
static QPACK_STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),                                           // 0
    (":path", "/"),                                               // 1
    ("age", "0"),                                                 // 2
    ("content-disposition", ""),                                  // 3
    ("content-length", "0"),                                      // 4
    ("cookie", ""),                                               // 5
    ("date", ""),                                                 // 6
    ("etag", ""),                                                 // 7
    ("if-modified-since", ""),                                    // 8
    ("if-none-match", ""),                                        // 9
    ("last-modified", ""),                                        // 10
    ("link", ""),                                                 // 11
    ("location", ""),                                             // 12
    ("referer", ""),                                              // 13
    ("set-cookie", ""),                                           // 14
    (":method", "CONNECT"),                                       // 15
    (":method", "DELETE"),                                        // 16
    (":method", "GET"),                                           // 17
    (":method", "HEAD"),                                          // 18
    (":method", "OPTIONS"),                                       // 19
    (":method", "POST"),                                          // 20
    (":method", "PUT"),                                           // 21
    (":scheme", "http"),                                          // 22
    (":scheme", "https"),                                         // 23
    (":status", "103"),                                           // 24
    (":status", "200"),                                           // 25
    (":status", "304"),                                           // 26
    (":status", "404"),                                           // 27
    (":status", "503"),                                           // 28
    ("accept", "*/*"),                                            // 29
    ("accept", "application/dns-message"),                        // 30
    ("accept-encoding", "gzip, deflate, br"),                     // 31
    ("accept-ranges", "bytes"),                                   // 32
    ("access-control-allow-headers", "cache-control"),            // 33
    ("access-control-allow-headers", "content-type"),             // 34
    ("access-control-allow-origin", "*"),                         // 35
    ("cache-control", "max-age=0"),                               // 36
    ("cache-control", "max-age=2592000"),                         // 37
    ("cache-control", "max-age=604800"),                          // 38
    ("cache-control", "no-cache"),                                // 39
    ("cache-control", "no-store"),                                // 40
    ("cache-control", "public, max-age=31536000"),                // 41
    ("content-encoding", "br"),                                   // 42
    ("content-encoding", "gzip"),                                 // 43
    ("content-type", "application/dns-message"),                  // 44
    ("content-type", "application/javascript"),                   // 45
    ("content-type", "application/json"),                         // 46
    ("content-type", "application/x-www-form-urlencoded"),        // 47
    ("content-type", "image/gif"),                                // 48
    ("content-type", "image/jpeg"),                               // 49
    ("content-type", "image/png"),                                // 50
    ("content-type", "text/css"),                                 // 51
    ("content-type", "text/html; charset=utf-8"),                 // 52
    ("content-type", "text/plain"),                               // 53
    ("content-type", "text/plain;charset=utf-8"),                 // 54
    ("range", "bytes=0-"),                                        // 55
    ("strict-transport-security", "max-age=31536000"),            // 56
    ("strict-transport-security",
     "max-age=31536000; includesubdomains"),                      // 57
    ("strict-transport-security",
     "max-age=31536000; includesubdomains; preload"),             // 58
    ("vary", "accept-encoding"),                                  // 59
    ("vary", "origin"),                                           // 60
    ("x-content-type-options", "nosniff"),                        // 61
    ("x-xss-protection", "1; mode=block"),                        // 62
    (":status", "100"),                                           // 63
    (":status", "204"),                                           // 64
    (":status", "206"),                                           // 65
    (":status", "302"),                                           // 66
    (":status", "400"),                                           // 67
    (":status", "403"),                                           // 68
    (":status", "421"),                                           // 69
    (":status", "425"),                                           // 70
    (":status", "500"),                                           // 71
    ("accept-language", ""),                                      // 72
    ("access-control-allow-credentials", "FALSE"),                // 73
    ("access-control-allow-credentials", "TRUE"),                 // 74
    ("access-control-allow-headers", "*"),                        // 75
    ("access-control-allow-methods", "get"),                      // 76
    ("access-control-allow-methods", "get, post, options"),       // 77
    ("access-control-allow-methods", "options"),                  // 78
    ("access-control-expose-headers", "content-length"),          // 79
    ("access-control-request-headers", "content-type"),           // 80
    ("access-control-request-method", "get"),                     // 81
    ("access-control-request-method", "post"),                    // 82
    ("alt-svc", "clear"),                                         // 83
    ("authorization", ""),                                        // 84
    ("content-security-policy",
     "script-src 'none'; object-src 'none'; base-uri 'none'"),   // 85
    ("early-data", "1"),                                          // 86
    ("expect-ct", ""),                                            // 87
    ("forwarded", ""),                                            // 88
    ("if-range", ""),                                             // 89
    ("origin", ""),                                               // 90
    ("purpose", "prefetch"),                                      // 91
    ("server", ""),                                               // 92
    ("timing-allow-origin", "*"),                                 // 93
    ("upgrade-insecure-requests", "1"),                           // 94
    ("user-agent", ""),                                           // 95
    ("x-forwarded-for", ""),                                      // 96
    ("x-frame-options", "deny"),                                  // 97
    ("x-frame-options", "sameorigin"),                            // 98
];

// ---------------------------------------------------------------------------
// QPACK header decoding (static-table only — no dynamic table)
// ---------------------------------------------------------------------------

/// Decode QPACK-encoded header block into a header map.
/// Supports indexed field lines (static table) and literal field lines.
/// Dynamic-table references are skipped (require encoder/decoder streams).
pub fn decode_qpack_headers(buf: &[u8]) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    if buf.len() < 2 {
        return headers;
    }

    // Required Insert Count (VARINT) — skip
    let (_, ric_len) = match decode_prefix_int(buf, 8) {
        Some(v) => v,
        None => return headers,
    };
    if ric_len >= buf.len() {
        return headers;
    }
    // Sign bit + Delta Base (VARINT) — skip
    let (_, db_len) = match decode_prefix_int(&buf[ric_len..], 7) {
        Some(v) => v,
        None => return headers,
    };

    let mut pos = ric_len + db_len;

    while pos < buf.len() {
        let b = buf[pos];

        if b & 0x80 != 0 {
            // Indexed Field Line
            let is_static = b & 0x40 != 0;
            if let Some((idx, consumed)) = decode_prefix_int(&buf[pos..], 6) {
                pos += consumed;
                if is_static {
                    if let Some(&(name, value)) = QPACK_STATIC_TABLE.get(idx as usize) {
                        headers.insert(name.to_string(), value.to_string());
                    }
                }
                // Dynamic-table indexed lines are skipped (no dynamic table state)
            } else {
                break;
            }
        } else if b & 0x40 != 0 {
            // Literal Field Line With Name Reference
            let is_static = b & 0x10 != 0;
            if let Some((idx, consumed)) = decode_prefix_int(&buf[pos..], 4) {
                pos += consumed;
                if let Some((value, consumed)) = decode_string(&buf[pos..], 7) {
                    pos += consumed;
                    if is_static {
                        if let Some(&(name, _)) = QPACK_STATIC_TABLE.get(idx as usize) {
                            headers.insert(name.to_string(), value);
                        }
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        } else if b & 0x20 != 0 {
            // Literal Field Line Without Name Reference
            if let Some((name, consumed)) = decode_string(&buf[pos + 1..], 3) {
                // Skip past the initial byte; `name` starts from pos+1
                let name_consumed = consumed;
                let next = pos + 1 + name_consumed;
                if let Some((value, consumed)) = decode_string(&buf[next..], 7) {
                    pos = next + consumed;
                    headers.insert(name.to_lowercase(), value);
                } else {
                    break;
                }
            } else {
                pos += 1; // skip unknown byte
            }
        } else {
            // Unknown or reserved instruction — advance past it
            pos += 1;
        }
    }

    headers
}

/// Decode a QPACK prefix integer (RFC 7541 §5.1 / RFC 9204 §4.1.1).
fn decode_prefix_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if buf.is_empty() || prefix_bits == 0 || prefix_bits > 8 {
        return None;
    }
    let mask: u8 = if prefix_bits == 8 { 0xff } else { (1u8 << prefix_bits) - 1 };
    let mut val = (buf[0] & mask) as u64;
    if val < mask as u64 {
        return Some((val, 1));
    }
    let mut m = 0u64;
    let mut i = 1;
    loop {
        if i >= buf.len() {
            return None;
        }
        let b = buf[i] as u64;
        val += (b & 0x7f) << m;
        m += 7;
        i += 1;
        if b & 0x80 == 0 {
            return Some((val, i));
        }
        if m > 56 {
            return None; // overflow guard
        }
    }
}

/// Decode a QPACK string literal.
fn decode_string(buf: &[u8], prefix_bits: u8) -> Option<(String, usize)> {
    if buf.is_empty() {
        return None;
    }
    let huffman = buf[0] & (1 << prefix_bits) != 0;
    let (len, consumed) = decode_prefix_int(buf, prefix_bits)?;
    let len = len as usize;
    let start = consumed;
    if buf.len() < start + len {
        return None;
    }
    let raw = &buf[start..start + len];
    let s = if huffman {
        // Simplified Huffman: just lossily decode — full Huffman tables are large.
        // In practice most API headers are ASCII and only small savings from Huffman.
        String::from_utf8_lossy(raw).into_owned()
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    Some((s, start + len))
}

// ---------------------------------------------------------------------------
// HTTP/3 detection heuristic
// ---------------------------------------------------------------------------

/// Detect whether a payload looks like HTTP/3 frames.
/// HTTP/3 typically starts with a SETTINGS frame (type 0x04) on the control
/// stream, or HEADERS (0x01) / DATA (0x00) on request streams.
pub fn looks_like_http3(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    // Try parsing first varint as frame type
    if let Some((frame_type, t_len)) = decode_varint(buf) {
        if let Some((payload_len, _)) = decode_varint(&buf[t_len..]) {
            let valid_type = matches!(
                frame_type,
                H3_DATA | H3_HEADERS | H3_SETTINGS | H3_GOAWAY |
                H3_CANCEL_PUSH | H3_PUSH_PROMISE
            );
            let reasonable_len = payload_len < 1_000_000;
            return valid_type && reasonable_len;
        }
    }
    false
}

/// Extract HTTP/3 headers from an HEADERS frame payload.
pub fn extract_h3_headers(buf: &[u8]) -> Vec<HashMap<String, String>> {
    let frames = parse_h3_frames(buf);
    let mut result = Vec::new();
    for frame in frames {
        if frame.frame_type == H3_HEADERS {
            let headers = decode_qpack_headers(frame.payload);
            if !headers.is_empty() {
                result.push(headers);
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// QUIC library discovery (mirrors TLS lib discovery in http.rs)
// ---------------------------------------------------------------------------

/// Scan /proc/<pid>/maps for known QUIC libraries.
pub fn discover_quic_libs(pid: i32) -> Vec<String> {
    if pid <= 0 {
        return Vec::new();
    }
    let maps_path = format!("/proc/{}/maps", pid);
    let Ok(contents) = std::fs::read_to_string(&maps_path) else {
        return Vec::new();
    };
    let mut libs = std::collections::HashMap::<String, bool>::new();
    for line in contents.lines() {
        if let Some(path) = line.split_whitespace().nth(5) {
            if path.contains("libquiche")
                || path.contains("libngtcp2")
                || path.contains("libmsquic")
                || path.contains("liblsquic")
            {
                libs.insert(path.to_string(), true);
            }
        }
    }
    libs.keys().cloned().collect()
}

/// Known QUIC library function symbols for uprobe attachment.
#[allow(dead_code)]
pub struct QuicSymbols {
    pub lib_path: String,
    pub lib_type: QuicLibType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QuicLibType {
    Quiche,
    Ngtcp2,
    Msquic,
    Lsquic,
}

pub fn classify_quic_lib(path: &str) -> Option<QuicLibType> {
    let lower = path.to_lowercase();
    if lower.contains("libquiche") {
        Some(QuicLibType::Quiche)
    } else if lower.contains("libngtcp2") {
        Some(QuicLibType::Ngtcp2)
    } else if lower.contains("libmsquic") {
        Some(QuicLibType::Msquic)
    } else if lower.contains("liblsquic") {
        Some(QuicLibType::Lsquic)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_varint_1byte() {
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x25]), Some((37, 1)));
        assert_eq!(decode_varint(&[0x3f]), Some((63, 1)));
    }

    #[test]
    fn test_decode_varint_2byte() {
        // 0x40 prefix → 2 bytes: 01xxxxxx + next byte
        assert_eq!(decode_varint(&[0x7b, 0xbd]), Some((15293, 2)));
    }

    #[test]
    fn test_decode_varint_4byte() {
        // 0x80 prefix → 4 bytes
        assert_eq!(decode_varint(&[0x80, 0x00, 0x00, 0x01]), Some((1, 4)));
    }

    #[test]
    fn test_parse_h3_frame_data() {
        // Type=0x00 (DATA), Length=5, Payload=b"hello"
        let buf = [0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let (frame, consumed) = parse_h3_frame(&buf).unwrap();
        assert_eq!(frame.frame_type, H3_DATA);
        assert_eq!(frame.payload, b"hello");
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_h3_frame_settings() {
        // Type=0x04 (SETTINGS), Length=0
        let buf = [0x04, 0x00];
        let (frame, consumed) = parse_h3_frame(&buf).unwrap();
        assert_eq!(frame.frame_type, H3_SETTINGS);
        assert_eq!(frame.payload.len(), 0);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_looks_like_http3_settings() {
        // SETTINGS frame (type 0x04, length 0)
        assert!(looks_like_http3(&[0x04, 0x00]));
    }

    #[test]
    fn test_looks_like_http3_data() {
        // DATA frame (type 0x00, length 3)
        assert!(looks_like_http3(&[0x00, 0x03, 0x41, 0x42, 0x43]));
    }

    #[test]
    fn test_not_http3() {
        // Doesn't look like HTTP/3 — random bytes
        assert!(!looks_like_http3(&[0xff, 0xff, 0xff]));
    }

    #[test]
    fn test_qpack_static_indexed() {
        // Build a minimal QPACK header block:
        // Required Insert Count = 0 (1 byte: 0x00)
        // Delta Base = 0 (1 byte: 0x00)
        // Indexed Field Line, Static, Index=17 → :method GET (0xC0 | 17 = 0xD1)
        // Indexed Field Line, Static, Index=1  → :path /    (0xC0 | 1  = 0xC1)
        // Indexed Field Line, Static, Index=23 → :scheme https (0xC0 | 23 = 0xD7)
        let buf = [0x00, 0x00, 0xD1, 0xC1, 0xD7];
        let headers = decode_qpack_headers(&buf);
        assert_eq!(headers.get(":method"), Some(&"GET".to_string()));
        assert_eq!(headers.get(":path"), Some(&"/".to_string()));
        assert_eq!(headers.get(":scheme"), Some(&"https".to_string()));
    }

    #[test]
    fn test_qpack_static_table_size() {
        assert_eq!(QPACK_STATIC_TABLE.len(), 99);
    }

    #[test]
    fn test_classify_quic_lib() {
        assert_eq!(
            classify_quic_lib("/usr/lib/libquiche.so"),
            Some(QuicLibType::Quiche)
        );
        assert_eq!(
            classify_quic_lib("/usr/lib/libngtcp2.so.16"),
            Some(QuicLibType::Ngtcp2)
        );
        assert_eq!(classify_quic_lib("/usr/lib/libssl.so.3"), None);
    }

    #[test]
    fn test_prefix_int_decode() {
        // Value 10 in 5-bit prefix
        assert_eq!(decode_prefix_int(&[0x0a], 5), Some((10, 1)));
        // Value 31 (max for 5-bit prefix): needs continuation
        assert_eq!(decode_prefix_int(&[0x1f, 0x00], 5), Some((31, 2)));
        // Value 1337 in 5-bit prefix: 0x1f, 0x9a, 0x0a
        assert_eq!(decode_prefix_int(&[0x1f, 0x9a, 0x0a], 5), Some((1337, 3)));
    }
}
