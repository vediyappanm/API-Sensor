use hpack::decoder::Decoder;
use std::collections::HashMap;

use crate::types::HTTP2_PREFACE;

// ---------------------------------------------------------------------------
// Http2HpackDecoder wrapper (HPACK resync)
// ---------------------------------------------------------------------------

pub struct Http2HpackDecoder {
    inner:       Decoder<'static>,
    pub error_count: u32,
}

impl Http2HpackDecoder {
    pub const RESET_THRESHOLD: u32 = 3;

    pub fn new() -> Self {
        let mut d = Decoder::new();
        d.set_max_table_size(8192);
        Self { inner: d, error_count: 0 }
    }

    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ()> {
        // Pre-validate the HPACK block to avoid panics in the hpack crate.
        // The hpack-0.3.0 crate has bugs where it calls .unwrap() on
        // decode_integer() which returns None on truncated varint sequences.
        if !Self::validate_hpack_block(block) {
            self.error_count += 1;
            if self.error_count >= Self::RESET_THRESHOLD {
                tracing::warn!("HPACK decoder reset after desync");
                *self = Self::new();
            }
            return Err(());
        }
        match self.inner.decode(block) {
            Ok(headers) => {
                self.error_count = 0;
                Ok(headers)
            }
            Err(_) => {
                self.error_count += 1;
                if self.error_count >= Self::RESET_THRESHOLD {
                    tracing::warn!("HPACK decoder reset after desync");
                    *self = Self::new();
                }
                Err(())
            }
        }
    }

    /// Validate an HPACK block to ensure it won't trigger panics in the
    /// hpack crate due to truncated varint sequences. The hpack-0.3.0 crate
    /// calls `.unwrap()` on `decode_integer()` which returns None on truncated
    /// input. This walks all entries validating varints and string lengths.
    fn validate_hpack_block(block: &[u8]) -> bool {
        if block.is_empty() { return true; }
        let mut i = 0;
        while i < block.len() {
            let byte = block[i];
            if byte & 0x80 != 0 {
                // Indexed header field (prefix = 7 bits)
                match Self::read_hpack_int(block, i, 7) {
                    Some((_, consumed)) => i += consumed,
                    None => return false,
                }
            } else if byte & 0xC0 == 0x40 {
                // Literal with incremental indexing (prefix = 6 bits)
                let (index, consumed) = match Self::read_hpack_int(block, i, 6) {
                    Some(v) => v, None => return false,
                };
                i += consumed;
                if index == 0 {
                    // New name: validate name string
                    match Self::skip_hpack_string(block, i) {
                        Some(n) => i += n, None => return false,
                    }
                }
                // Validate value string
                match Self::skip_hpack_string(block, i) {
                    Some(n) => i += n, None => return false,
                }
            } else if byte & 0xE0 == 0x20 {
                // Dynamic table size update (prefix = 5 bits)
                match Self::read_hpack_int(block, i, 5) {
                    Some((_, consumed)) => i += consumed,
                    None => return false,
                }
            } else {
                // Literal without indexing / never indexed (prefix = 4 bits)
                let (index, consumed) = match Self::read_hpack_int(block, i, 4) {
                    Some(v) => v, None => return false,
                };
                i += consumed;
                if index == 0 {
                    match Self::skip_hpack_string(block, i) {
                        Some(n) => i += n, None => return false,
                    }
                }
                match Self::skip_hpack_string(block, i) {
                    Some(n) => i += n, None => return false,
                }
            }
        }
        true
    }

    /// Read an HPACK integer with the given prefix bit-width, returning
    /// (value, bytes_consumed). Returns None if truncated or too many octets.
    /// Matches the hpack crate's octet_limit of 5 total bytes to avoid
    /// triggering panics from TooManyOctets errors.
    fn read_hpack_int(block: &[u8], pos: usize, prefix_bits: u8) -> Option<(u64, usize)> {
        if pos >= block.len() { return None; }
        let mask = (1u16 << prefix_bits) - 1;
        let val = (block[pos] as u64) & (mask as u64);
        if val < mask as u64 {
            return Some((val, 1));
        }
        // Extended integer — hpack crate limits to 5 total bytes
        let mut i = pos + 1;
        let mut total = 1usize;
        let mut result = mask as u64;
        let mut shift = 0u32;
        loop {
            if i >= block.len() { return None; }
            let b = block[i] as u64;
            result += (b & 0x7F) << shift;
            total += 1;
            i += 1;
            if b & 0x80 == 0 { break; }
            shift += 7;
            // Match hpack crate's octet_limit = 5
            if total >= 5 { return None; }
        }
        Some((result, i - pos))
    }

    /// Skip an HPACK string (Huffman or raw), returning bytes consumed.
    fn skip_hpack_string(block: &[u8], pos: usize) -> Option<usize> {
        let (str_len, int_consumed) = Self::read_hpack_int(block, pos, 7)?;
        let total = int_consumed + str_len as usize;
        if pos + total > block.len() { return None; }
        Some(total)
    }
}

impl Default for Http2HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HTTP/2 frame parsing
// ---------------------------------------------------------------------------

pub fn contains_http2_preface(buffer: &[u8]) -> bool {
    buffer.windows(HTTP2_PREFACE.len()).any(|w| w == HTTP2_PREFACE)
}

/// RFC 7540 §4.2 default; SETTINGS_MAX_FRAME_SIZE (id=0x5) may raise this up
/// to 2^24-1 via a SETTINGS frame.
const H2_DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

/// Scan `buffer` for a SETTINGS frame (type=0x04) and return the negotiated
/// SETTINGS_MAX_FRAME_SIZE value, or the RFC default (16 384) if absent.
fn extract_settings_max_frame_size(buffer: &[u8]) -> usize {
    let mut i = 0;
    // Skip the client preface if present.
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if buffer.starts_with(preface) {
        i = preface.len();
    }
    while i + 9 <= buffer.len() {
        let frame_len = ((buffer[i] as usize) << 16)
            | ((buffer[i + 1] as usize) << 8)
            | (buffer[i + 2] as usize);
        let frame_type = buffer[i + 3];
        let flags      = buffer[i + 4];
        // Stream ID must be 0 for SETTINGS (RFC 7540 §6.5).
        let stream_id  = u32::from_be_bytes([
            buffer[i + 5], buffer[i + 6], buffer[i + 7], buffer[i + 8],
        ]) & 0x7fff_ffff;

        if i + 9 + frame_len > buffer.len() {
            break;
        }

        if frame_type == 0x04 && stream_id == 0 && flags & 0x01 == 0 {
            // SETTINGS payload: repeated (u16 id, u32 value) tuples.
            let payload = &buffer[i + 9..i + 9 + frame_len];
            let mut j = 0;
            while j + 6 <= payload.len() {
                let id  = u16::from_be_bytes([payload[j], payload[j + 1]]);
                let val = u32::from_be_bytes([
                    payload[j + 2], payload[j + 3], payload[j + 4], payload[j + 5],
                ]) as usize;
                if id == 0x0005 {
                    // Clamp to the legal range (RFC 7540 §6.5.2).
                    let clamped = val.clamp(H2_DEFAULT_MAX_FRAME_SIZE, (1 << 24) - 1);
                    return clamped;
                }
                j += 6;
            }
        }
        i += 9 + frame_len;
    }
    H2_DEFAULT_MAX_FRAME_SIZE
}

/// Returns per-stream decoded headers: Vec<(stream_id, headers)>.
pub fn parse_http2_frames(
    decoder: &mut Http2HpackDecoder,
    buffer: &[u8],
) -> Vec<(u32, HashMap<String, String>)> {
    let max_frame_size = extract_settings_max_frame_size(buffer);
    let blocks = extract_hpack_blocks(buffer, max_frame_size);
    if blocks.is_empty() {
        let mut map = HashMap::new();
        hpack_static_scan(buffer, &mut map, max_frame_size);
        for key in &[":method", ":path", ":authority", ":status", "content-type"] {
            if !map.contains_key(*key) {
                if let Some(value) = find_token_value(buffer, key) {
                    map.insert(key.to_string(), value);
                }
            }
        }
        if map.is_empty() {
            return Vec::new();
        }
        return vec![(0, map)];
    }

    let mut results = Vec::new();
    for (stream_id, header_block) in blocks {
        if let Ok(decoded) = decoder.decode(&header_block) {
            let mut map = HashMap::new();
            for (name, value) in decoded {
                let name  = String::from_utf8_lossy(&name).to_ascii_lowercase();
                let value = String::from_utf8_lossy(&value).to_string();
                if !name.is_empty() && !value.is_empty() {
                    map.insert(name, value);
                }
            }
            if !map.is_empty() {
                results.push((stream_id, map));
            }
        }
    }
    results
}

/// Backward-compat wrapper used by tests.
#[cfg(test)]
fn parse_http2_metadata(
    decoder: &mut Http2HpackDecoder,
    buffer: &[u8],
) -> HashMap<String, String> {
    parse_http2_frames(decoder, buffer)
        .into_iter()
        .next()
        .map(|(_, h)| h)
        .unwrap_or_default()
}

fn hpack_static_scan(buffer: &[u8], map: &mut HashMap<String, String>, max_frame_size: usize) {
    const STATIC_TABLE: &[(u8, &str, &str)] = &[
        (2,  ":method", "GET"),
        (3,  ":method", "POST"),
        (4,  ":path",   "/"),
        (5,  ":path",   "/index.html"),
        (8,  ":status", "200"),
        (9,  ":status", "204"),
        (10, ":status", "206"),
        (11, ":status", "304"),
        (12, ":status", "400"),
        (13, ":status", "404"),
        (14, ":status", "500"),
    ];

    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let start = buffer.windows(preface.len())
        .position(|w| w == preface)
        .map(|p| p + preface.len())
        .unwrap_or(0);
    let mut i = start;
    while i + 9 < buffer.len() {
        let frame_len = ((buffer[i] as usize) << 16)
            | ((buffer[i + 1] as usize) << 8)
            | (buffer[i + 2] as usize);
        let frame_type = buffer[i + 3];

        if frame_len > max_frame_size || i + 9 + frame_len > buffer.len() {
            i += 1;
            continue;
        }

        if frame_type == 0x01 && frame_len > 0 {
            let payload_start = i + 9;
            let payload_end = (payload_start + frame_len).min(buffer.len());
            let mut j = payload_start;
            while j < payload_end {
                let byte = buffer[j];
                if byte & 0x80 != 0 {
                    let index = byte & 0x7F;
                    for &(idx, name, value) in STATIC_TABLE {
                        if index == idx {
                            map.entry(name.to_string()).or_insert_with(|| value.to_string());
                        }
                    }
                }
                j += 1;
            }
        }

        if frame_len == 0 { i += 9; } else { i += 9 + frame_len; }
        if i > 65536 { break; }
    }
}

fn extract_hpack_blocks(buffer: &[u8], max_frame_size: usize) -> Vec<(u32, Vec<u8>)> {
    let mut blocks = Vec::new();
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let start = buffer.windows(preface.len())
        .position(|w| w == preface)
        .map(|p| p + preface.len())
        .unwrap_or(0);
    let mut i = start;
    while i + 9 <= buffer.len() {
        let frame_len = ((buffer[i] as usize) << 16)
            | ((buffer[i + 1] as usize) << 8)
            | (buffer[i + 2] as usize);
        let frame_type = buffer[i + 3];
        let flags = buffer[i + 4];
        let stream_id = u32::from_be_bytes([
            buffer[i + 5], buffer[i + 6], buffer[i + 7], buffer[i + 8],
        ]) & 0x7fffffff;

        if frame_len > max_frame_size || i + 9 + frame_len > buffer.len() {
            i += 1;
            continue;
        }

        if frame_type == 0x01 && frame_len > 0 {
            let mut payload = &buffer[i + 9..i + 9 + frame_len];
            if flags & 0x08 != 0 {
                if payload.is_empty() { break; }
                let pad_len = payload[0] as usize;
                payload = &payload[1..];
                if pad_len <= payload.len() {
                    payload = &payload[..payload.len() - pad_len];
                } else {
                    break;
                }
            }
            if flags & 0x20 != 0 {
                if payload.len() < 5 { break; }
                payload = &payload[5..];
            }

            let mut header_block = payload.to_vec();
            let mut end_headers = flags & 0x04 != 0;
            let mut j = i + 9 + frame_len;
            while !end_headers && j + 9 <= buffer.len() {
                let len2 = ((buffer[j] as usize) << 16)
                    | ((buffer[j + 1] as usize) << 8)
                    | (buffer[j + 2] as usize);
                let type2  = buffer[j + 3];
                let flags2 = buffer[j + 4];
                let stream2 = u32::from_be_bytes([
                    buffer[j + 5], buffer[j + 6], buffer[j + 7], buffer[j + 8],
                ]) & 0x7fffffff;

                if type2 != 0x09 || stream2 != stream_id || j + 9 + len2 > buffer.len() {
                    break;
                }
                header_block.extend_from_slice(&buffer[j + 9..j + 9 + len2]);
                end_headers = flags2 & 0x04 != 0;
                j += 9 + len2;
            }
            blocks.push((stream_id, header_block));
            i = j;
        } else {
            i += 9 + frame_len;
        }

        if i > 65536 { break; }
    }
    blocks
}

pub fn find_token_value(buffer: &[u8], key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    if buffer.len() < key_bytes.len() + 1 {
        return None;
    }
    for i in 0..buffer.len() - key_bytes.len() {
        if equals_ignore_ascii_case(&buffer[i..i + key_bytes.len()], key_bytes)
            && buffer.get(i + key_bytes.len()).is_some_and(|b| *b == b':')
        {
            let mut idx = i + key_bytes.len() + 1;
            while idx < buffer.len() && (buffer[idx] == b' ' || buffer[idx] == b'\t') {
                idx += 1;
            }
            let start = idx;
            while idx < buffer.len() && !matches!(buffer[idx], b'\r' | b'\n' | 0) {
                idx += 1;
            }
            if start < idx {
                let value = String::from_utf8_lossy(&buffer[start..idx]).trim().to_string();
                if !value.is_empty() { return Some(value); }
            }
        }
    }
    None
}

pub fn equals_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_http2_preface() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
        assert!(!contains_http2_preface(&buf));
        buf.extend_from_slice(HTTP2_PREFACE);
        assert!(contains_http2_preface(&buf));
    }

    #[test]
    fn test_find_token_value() {
        let buf = b"PRI * HTTP/2.0\r\n:method: GET\r\n:path: /health\r\n:status: 200\r\n\r\n";
        assert_eq!(find_token_value(buf, ":method").unwrap(), "GET");
        assert_eq!(find_token_value(buf, ":path").unwrap(), "/health");
        assert_eq!(find_token_value(buf, ":status").unwrap(), "200");
        assert_eq!(find_token_value(buf, ":authority"), None);
    }

    #[test]
    fn test_equals_ignore_ascii_case() {
        assert!(equals_ignore_ascii_case(b"Host", b"host"));
        assert!(equals_ignore_ascii_case(b"CONTENT-TYPE", b"content-type"));
        assert!(!equals_ignore_ascii_case(b"Host", b"User-Agent"));
    }

    #[test]
    fn test_hpack_static_index_decode() {
        let mut decoder = Http2HpackDecoder::new();
        let mut buf = Vec::new();
        // HTTP/2 frame header: len=2, type=HEADERS(0x01), flags=END_HEADERS(0x04), stream_id=1
        buf.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01]);
        // HPACK indexed headers: 0x82 (:method GET), 0x84 (:path /)
        buf.extend_from_slice(&[0x82, 0x84]);
        let headers = parse_http2_metadata(&mut decoder, &buf);
        assert_eq!(headers.get(":method").unwrap(), "GET");
        assert_eq!(headers.get(":path").unwrap(), "/");
    }

    #[test]
    fn test_hpack_decoder_reset_on_errors() {
        let mut dec = Http2HpackDecoder::new();
        // Feed garbage 3 times to trigger reset
        for _ in 0..3 {
            let _ = dec.decode(b"\xff\xff\xff\xff\xff\xff");
        }
        // After reset, error_count should be 0 and decode should still work
        assert!(dec.error_count == 0 || dec.error_count < Http2HpackDecoder::RESET_THRESHOLD);
    }
}
