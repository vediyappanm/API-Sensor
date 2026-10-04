use hpack::decoder::Decoder;
use std::collections::HashMap;

use crate::types::{HTTP2_CONNECTION_PREFACE, HTTP2_PREFACE};

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
        // Table size stays at the protocol default (4096): the peer's encoder starts there and
        // announces any change in-band. A larger local limit lets the tables drift apart.
        Self { inner: Decoder::new(), error_count: 0 }
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
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.inner.decode(block)));
        let decoded = match decoded {
            Ok(r) => r,
            Err(_) => {
                // The decoder's state is unknown after a panic: start clean.
                tracing::warn!("HPACK decoder panicked; resetting");
                *self = Self::new();
                return Err(());
            }
        };
        match decoded {
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

/// Concatenated DATA-frame (type 0x00) payloads for `stream_id`, with the
/// PADDED flag's pad-length octet and trailing padding stripped. This is the
/// byte stream a gRPC message actually lives in — never the raw connection
/// buffer, whose 9-byte frame headers are not protobuf.
pub fn extract_data_frames(buffer: &[u8], stream_id: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let max_frame_size = extract_settings_max_frame_size(buffer);
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut i = buffer
        .windows(preface.len())
        .position(|w| w == preface)
        .map(|p| p + preface.len())
        .unwrap_or(0);
    while i + 9 <= buffer.len() {
        let frame_len = ((buffer[i] as usize) << 16)
            | ((buffer[i + 1] as usize) << 8)
            | (buffer[i + 2] as usize);
        let frame_type = buffer[i + 3];
        let flags = buffer[i + 4];
        let sid = u32::from_be_bytes([
            buffer[i + 5], buffer[i + 6], buffer[i + 7], buffer[i + 8],
        ]) & 0x7fff_ffff;
        if frame_len > max_frame_size || i + 9 + frame_len > buffer.len() {
            // Garbage head (e.g. the truncated HTTP2_PREFACE token) or a
            // truncated trailing frame — slide one byte to resync, matching
            // the other frame walkers in this module.
            i += 1;
            continue;
        }
        if frame_type == 0x00 && sid == stream_id {
            let mut payload = &buffer[i + 9..i + 9 + frame_len];
            if flags & 0x08 != 0 && !payload.is_empty() {
                // PADDED: first octet is pad length, padding trails the data.
                let pad = payload[0] as usize;
                payload = &payload[1..];
                payload = &payload[..payload.len().saturating_sub(pad)];
            }
            out.extend_from_slice(payload);
        }
        i += 9 + frame_len;
    }
    out
}

// ---------------------------------------------------------------------------
// Incremental, per-direction HTTP/2 parser
//
// HTTP/2 keeps SEPARATE HPACK dynamic tables for each direction (each side's encoder and
// the peer's decoder), and frames are only meaningful inside one direction's byte stream.
// The previous code put both directions in one buffer, re-parsed the whole buffer with one
// stateful decoder on every event, and so decoded the same header block repeatedly (each
// pass inserting into the dynamic table again) and mixed request and response bytes. Here
// every direction owns its buffer and decoder, and every frame is consumed exactly once.
// ---------------------------------------------------------------------------

/// Largest frame payload that will be buffered. The protocol default is 16 KiB and
/// endpoints rarely raise it; a larger length is treated as a desync rather than waited for
/// (a corrupt length would otherwise stall the stream waiting for megabytes that never come).
pub const H2_MAX_ACCEPTED_FRAME: usize = 1 << 20;

/// Something completed by the bytes fed to an [`Http2Direction`].
#[derive(Debug, Clone, PartialEq)]
pub enum H2Item {
    Headers { stream_id: u32, headers: HashMap<String, String>, end_stream: bool },
    Data { stream_id: u32, data: Vec<u8>, end_stream: bool },
    Reset { stream_id: u32 },
}

struct HeaderBlock {
    stream_id: u32,
    bytes: Vec<u8>,
    end_stream: bool,
    /// PUSH_PROMISE blocks must be decoded (they change the dynamic table) but are not shown.
    promise: bool,
}

pub struct Http2Direction {
    buf: Vec<u8>,
    hpack: Http2HpackDecoder,
    preface_done: bool,
    continuation: Option<HeaderBlock>,
    max_frame: usize,
    /// SETTINGS_MAX_FRAME_SIZE this side announced; it bounds the frames the OTHER side sends.
    pub announced_max_frame: Option<usize>,
    broken: bool,
}

impl Http2Direction {
    /// `expect_preface` is true for the client-to-server direction, which begins with the
    /// 24-byte connection preface.
    pub fn new(expect_preface: bool) -> Self {
        Self {
            buf: Vec::new(),
            hpack: Http2HpackDecoder::new(),
            preface_done: !expect_preface,
            continuation: None,
            max_frame: H2_DEFAULT_MAX_FRAME_SIZE,
            announced_max_frame: None,
            broken: false,
        }
    }

    /// Bytes currently held (an incomplete trailing frame).
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Raise/lower the frame size this direction will accept (learned from the peer's SETTINGS).
    pub fn set_max_frame(&mut self, size: usize) {
        self.max_frame = size.clamp(H2_DEFAULT_MAX_FRAME_SIZE, H2_MAX_ACCEPTED_FRAME);
    }

    fn fail(&mut self) {
        // A framing violation means we lost sync (dropped capture, or not HTTP/2 at all). There is
        // no safe way to find the next frame boundary or repair the HPACK table, so stop
        // interpreting this direction rather than guess and fabricate headers.
        self.broken = true;
        self.buf.clear();
        self.continuation = None;
        crate::metrics::H2_PARSE_ERRORS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Feed bytes of this direction; returns everything they completed. Each frame is consumed
    /// exactly once, so HPACK state advances exactly once per header block.
    pub fn feed(&mut self, data: &[u8]) -> Vec<H2Item> {
        let mut out = Vec::new();
        if self.broken {
            return out;
        }
        self.buf.extend_from_slice(data);

        if !self.preface_done {
            // RFC 9113 §3.4: 24 bytes. Stopping at the 14-byte "PRI * HTTP/2.0"
            // magic leaves "\r\n\r\nSM\r\n\r\n" to be parsed as a frame, which
            // declares an illegal length and breaks the whole direction.
            if self.buf.len() >= HTTP2_CONNECTION_PREFACE.len() {
                if self.buf.starts_with(HTTP2_CONNECTION_PREFACE) {
                    self.buf.drain(..HTTP2_CONNECTION_PREFACE.len());
                    self.preface_done = true;
                } else {
                    self.fail();
                    return out;
                }
            } else if HTTP2_CONNECTION_PREFACE.starts_with(&self.buf) {
                return out; // preface split across reads: wait for the rest
            } else {
                self.fail();
                return out;
            }
        }

        let mut pos = 0usize;
        while self.buf.len() - pos >= 9 {
            let b = &self.buf[pos..];
            let len = ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize);
            if len > self.max_frame {
                self.fail();
                return out;
            }
            if b.len() < 9 + len {
                break; // incomplete frame: keep it for the next read
            }
            let ftype = b[3];
            let flags = b[4];
            let stream_id = u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff;
            let payload = b[9..9 + len].to_vec();
            pos += 9 + len;
            self.on_frame(ftype, flags, stream_id, payload, &mut out);
            if self.broken {
                return out;
            }
        }
        self.buf.drain(..pos);
        out
    }

    /// Strip the PADDED length octet and trailing padding. None = malformed.
    fn unpad(flags: u8, payload: &[u8]) -> Option<&[u8]> {
        if flags & 0x08 == 0 {
            return Some(payload);
        }
        let pad = *payload.first()? as usize;
        let rest = &payload[1..];
        if pad > rest.len() {
            return None;
        }
        Some(&rest[..rest.len() - pad])
    }

    fn on_frame(&mut self, ftype: u8, flags: u8, stream_id: u32, payload: Vec<u8>, out: &mut Vec<H2Item>) {
        // While a header block is open only its CONTINUATION frames may arrive (RFC 9113 §6.10).
        if let Some(mut open) = self.continuation.take() {
            if ftype != 0x09 || stream_id != open.stream_id {
                self.fail();
                return;
            }
            open.bytes.extend_from_slice(&payload);
            if flags & 0x04 != 0 {
                self.finish_block(open, out);
            } else {
                self.continuation = Some(open);
            }
            return;
        }

        match ftype {
            0x00 => {
                // DATA
                if stream_id == 0 {
                    return self.fail();
                }
                let Some(data) = Self::unpad(flags, &payload) else { return self.fail() };
                out.push(H2Item::Data { stream_id, data: data.to_vec(), end_stream: flags & 0x01 != 0 });
            }
            0x01 => {
                // HEADERS
                if stream_id == 0 {
                    return self.fail();
                }
                let Some(mut frag) = Self::unpad(flags, &payload) else { return self.fail() };
                if flags & 0x20 != 0 {
                    // PRIORITY: 4-byte stream dependency + 1-byte weight precede the block
                    if frag.len() < 5 {
                        return self.fail();
                    }
                    frag = &frag[5..];
                }
                let block = HeaderBlock { stream_id, bytes: frag.to_vec(), end_stream: flags & 0x01 != 0, promise: false };
                if flags & 0x04 != 0 {
                    self.finish_block(block, out);
                } else {
                    self.continuation = Some(block);
                }
            }
            0x03 => {
                if stream_id != 0 {
                    out.push(H2Item::Reset { stream_id });
                }
            }
            0x04 => {
                // SETTINGS (not an ACK): remember what this side tells the peer about frame size
                if flags & 0x01 == 0 && payload.len() % 6 == 0 {
                    for s in payload.chunks_exact(6) {
                        let id = u16::from_be_bytes([s[0], s[1]]);
                        let val = u32::from_be_bytes([s[2], s[3], s[4], s[5]]) as usize;
                        if id == 0x0005 {
                            self.announced_max_frame = Some(val.clamp(H2_DEFAULT_MAX_FRAME_SIZE, (1 << 24) - 1));
                        }
                    }
                }
            }
            0x05 => {
                // PUSH_PROMISE: promised stream id (4 bytes) then a header block that mutates the
                // HPACK table, so it must be decoded even though its headers are not reported.
                let Some(frag) = Self::unpad(flags, &payload) else { return self.fail() };
                if frag.len() < 4 {
                    return self.fail();
                }
                let block = HeaderBlock { stream_id, bytes: frag[4..].to_vec(), end_stream: false, promise: true };
                if flags & 0x04 != 0 {
                    self.finish_block(block, out);
                } else {
                    self.continuation = Some(block);
                }
            }
            0x09 => self.fail(), // CONTINUATION with no open header block
            _ => {}               // PRIORITY, PING, GOAWAY, WINDOW_UPDATE, unknown: nothing to report
        }
    }

    fn finish_block(&mut self, block: HeaderBlock, out: &mut Vec<H2Item>) {
        match self.hpack.decode(&block.bytes) {
            Ok(fields) => {
                if block.promise {
                    return;
                }
                let mut headers = HashMap::new();
                for (name, value) in fields {
                    let name = String::from_utf8_lossy(&name).to_ascii_lowercase();
                    if name.is_empty() {
                        continue;
                    }
                    insert_header(&mut headers, name, String::from_utf8_lossy(&value).into_owned());
                }
                out.push(H2Item::Headers { stream_id: block.stream_id, headers, end_stream: block.end_stream });
            }
            Err(()) => {
                crate::metrics::H2_PARSE_ERRORS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// Add a header, merging repeated names the way RFC 9113 §8.2.3 / RFC 9110 §5.3 define:
/// HTTP/2 splits `cookie` into several fields (rejoin with "; "), `set-cookie` must stay
/// distinct (kept newline-separated), everything else is comma-joined. A plain map insert
/// kept only the LAST cookie crumb.
fn insert_header(map: &mut HashMap<String, String>, name: String, value: String) {
    match map.get_mut(&name) {
        None => {
            map.insert(name, value);
        }
        Some(existing) => {
            let sep = match name.as_str() {
                "cookie" => "; ",
                "set-cookie" => "\n",
                _ => ", ",
            };
            existing.push_str(sep);
            existing.push_str(&value);
        }
    }
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

    fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
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

    #[test]
    fn extract_data_frames_concatenates_one_stream_and_strips_padding() {
        let mut buf = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        buf.extend(frame(0x01, 0x04, 1, &[0x88])); // HEADERS, not DATA
        buf.extend(frame(0x00, 0x00, 1, b"hello "));
        // PADDED DATA: pad_len=3, then payload, then 3 pad bytes
        let mut padded = vec![3u8];
        padded.extend_from_slice(b"world");
        padded.extend_from_slice(&[0, 0, 0]);
        buf.extend(frame(0x00, 0x08, 1, &padded));
        buf.extend(frame(0x00, 0x01, 3, b"other-stream")); // different stream
        buf.extend(&[0x00, 0x00, 0x10, 0x00]); // truncated trailing frame header

        assert_eq!(extract_data_frames(&buf, 1), b"hello world");
        assert_eq!(extract_data_frames(&buf, 3), b"other-stream");
        assert!(extract_data_frames(&buf, 5).is_empty());
    }

    #[test]
    fn extract_data_frames_resyncs_past_garbage_head() {
        // Buffers routinely start with the truncated HTTP2_PREFACE token
        // ("PRI * HTTP/2.0", 14 bytes) or mid-connection garbage rather than
        // the full 24-byte preface. The walker must resync to the first real
        // frame boundary instead of misreading "PRI" as a frame length.
        let mut buf = HTTP2_PREFACE.to_vec();
        buf.extend(frame(0x01, 0x04, 1, &[0x88]));
        buf.extend(frame(0x00, 0x01, 1, b"grpc-bytes"));
        assert_eq!(extract_data_frames(&buf, 1), b"grpc-bytes");
    }

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

#[cfg(test)]
mod direction_tests {
    use super::*;

    fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, ftype, flags];
        f.extend_from_slice(&stream_id.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Literal header with incremental indexing, new name (adds an entry to the dynamic table).
    fn lit_new(name: &str, value: &str) -> Vec<u8> {
        let mut v = vec![0x40, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v.push(value.len() as u8);
        v.extend_from_slice(value.as_bytes());
        v
    }

    const END_STREAM: u8 = 0x01;
    const END_HEADERS: u8 = 0x04;

    fn headers(items: &[H2Item]) -> Vec<(u32, HashMap<String, String>)> {
        items
            .iter()
            .filter_map(|i| match i {
                H2Item::Headers { stream_id, headers, .. } => Some((*stream_id, headers.clone())),
                _ => None,
            })
            .collect()
    }

    fn client_stream(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut v = HTTP2_CONNECTION_PREFACE.to_vec();
        for f in frames {
            v.extend_from_slice(f);
        }
        v
    }

    #[test]
    fn real_curl_request_headers_decode() {
        let c0 = hex_bytes("505249202a20485454502f322e300d0a0d0a534d0d0a0d0a000012040000000000000300000064000400a000000002000000000000040800000000003e7f0001");
        let c1 = hex_bytes("0000270105000000018287418b089d5c0b8170dc0bcd34ef04876075998324b4a37a8825b650c3cbb6b83f53032a2f2a");
        let mut d = Http2Direction::new(true);
        let a = d.feed(&c0);
        assert!(a.is_empty(), "preface/settings produce no headers, broken={}", d.is_broken());
        assert!(!d.is_broken());
        let b = d.feed(&c1);
        let h = headers(&b);
        assert!(!d.is_broken(), "request direction broke");
        assert_eq!(h.len(), 1, "items={b:?} buffered={}", d.buffered());
        assert_eq!(h[0].1.get(":method").map(String::as_str), Some("GET"), "{:?}", h[0].1);
        assert!(h[0].1.get(":path").unwrap_or(&String::new()).contains("api"), "{:?}", h[0].1);
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap()).collect()
    }

    #[test]
    fn each_direction_has_its_own_hpack_table() {
        // client request 1 adds `x-req: A` (dynamic index 62 in the CLIENT table)
        let mut req_dir = Http2Direction::new(true);
        let r1 = frame(0x01, END_HEADERS | END_STREAM, 1, &[&[0x82, 0x84][..], &lit_new("x-req", "A")].concat());
        let items = req_dir.feed(&client_stream(&[r1]));
        assert_eq!(headers(&items)[0].1["x-req"], "A");

        // server response adds `x-resp: B` to the SERVER table, also at index 62
        let mut resp_dir = Http2Direction::new(false);
        let s1 = frame(0x01, END_HEADERS, 1, &[&[0x88][..], &lit_new("x-resp", "B")].concat());
        assert_eq!(headers(&resp_dir.feed(&s1))[0].1["x-resp"], "B");

        // client request 2 refers to index 62 => must still be `x-req: A`
        let r2 = frame(0x01, END_HEADERS | END_STREAM, 3, &[0x82, 0x84, 0xBE]);
        let h = headers(&req_dir.feed(&r2));
        assert_eq!(h[0].1.get("x-req").map(String::as_str), Some("A"), "{h:?}");
        assert!(!h[0].1.contains_key("x-resp"));
    }

    #[test]
    fn a_single_decoder_for_both_directions_corrupts_headers() {
        // Documents WHY the directions are separate: the old design's one shared decoder
        // resolves the client's index 62 to the server's header.
        let mut shared = Http2HpackDecoder::new();
        shared.decode(&[&[0x82, 0x84][..], &lit_new("x-req", "A")].concat()).unwrap();
        shared.decode(&[&[0x88][..], &lit_new("x-resp", "B")].concat()).unwrap();
        let wrong = shared.decode(&[0x82, 0x84, 0xBE]).unwrap();
        let names: Vec<String> = wrong.iter().map(|(n, _)| String::from_utf8_lossy(n).into()).collect();
        assert!(names.contains(&"x-resp".to_string()) && !names.contains(&"x-req".to_string()), "{names:?}");
    }

    #[test]
    fn frames_are_consumed_once_so_the_table_is_not_reinserted() {
        let mut d = Http2Direction::new(true);
        let f1 = frame(0x01, END_HEADERS | END_STREAM, 1, &[&[0x82, 0x84][..], &lit_new("x-a", "1")].concat());
        let f2 = frame(0x01, END_HEADERS | END_STREAM, 3, &[&[0x82, 0x84][..], &lit_new("x-b", "2")].concat());
        // x-b is index 62, x-a shifted to 63
        let f3 = frame(0x01, END_HEADERS | END_STREAM, 5, &[0x82, 0x84, 0xBF, 0xBE]);
        d.feed(&client_stream(&[f1]));
        d.feed(&f2);
        let h = headers(&d.feed(&f3));
        assert_eq!(h.len(), 1);
        assert_eq!((h[0].1["x-a"].as_str(), h[0].1["x-b"].as_str()), ("1", "2"));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn byte_by_byte_feed_equals_a_single_feed() {
        let f1 = frame(0x01, END_HEADERS, 1, &[&[0x82, 0x84][..], &lit_new("x-a", "1")].concat());
        let f2 = frame(0x00, END_STREAM, 1, b"hello");
        let stream = client_stream(&[f1, f2]);
        let whole = Http2Direction::new(true).feed(&stream);
        let mut d = Http2Direction::new(true);
        let mut piecewise = Vec::new();
        for b in &stream {
            piecewise.extend(d.feed(std::slice::from_ref(b)));
        }
        assert_eq!(whole, piecewise);
        assert_eq!(whole.len(), 2);
    }

    #[test]
    fn header_block_split_across_continuation_frames_and_reads() {
        let block = [&[0x82, 0x84][..], &lit_new("x-long", "value")].concat();
        let (a, b) = block.split_at(3);
        let h = frame(0x01, 0, 1, a); // no END_HEADERS
        let c = frame(0x09, END_HEADERS, 1, b);
        let mut d = Http2Direction::new(true);
        assert!(d.feed(&client_stream(&[h])).is_empty());
        let items = d.feed(&c);
        assert_eq!(headers(&items)[0].1["x-long"], "value");
        // an unrelated frame while a block is open is a protocol violation, not silently accepted
        let mut d2 = Http2Direction::new(false);
        d2.feed(&frame(0x01, 0, 1, a));
        d2.feed(&frame(0x00, 0, 1, b"x"));
        assert!(d2.is_broken());
    }

    #[test]
    fn padded_and_prioritised_headers_decode() {
        let block = [0x82u8, 0x84];
        let mut payload = vec![2u8]; // pad length
        payload.extend_from_slice(&[0, 0, 0, 0, 16]); // PRIORITY: dependency + weight
        payload.extend_from_slice(&block);
        payload.extend_from_slice(&[0, 0]); // padding
        let f = frame(0x01, END_HEADERS | 0x08 | 0x20, 1, &payload);
        let items = Http2Direction::new(true).feed(&client_stream(&[f]));
        assert_eq!(headers(&items)[0].1[":method"], "GET");
    }

    #[test]
    fn data_padding_is_stripped_and_end_stream_reported() {
        let mut payload = vec![3u8];
        payload.extend_from_slice(b"world");
        payload.extend_from_slice(&[0, 0, 0]);
        let items = Http2Direction::new(false).feed(&frame(0x00, 0x08 | END_STREAM, 1, &payload));
        assert_eq!(items, vec![H2Item::Data { stream_id: 1, data: b"world".to_vec(), end_stream: true }]);
    }

    #[test]
    fn repeated_cookie_crumbs_are_rejoined_and_set_cookie_kept_distinct() {
        let block = [
            &[0x82u8, 0x84][..],
            &lit_new("cookie", "a=1"),
            &lit_new("cookie", "b=2"),
            &lit_new("set-cookie", "s1=x"),
            &lit_new("set-cookie", "s2=y"),
            &lit_new("accept", "a"),
            &lit_new("accept", "b"),
        ]
        .concat();
        let items = Http2Direction::new(true).feed(&client_stream(&[frame(0x01, END_HEADERS, 1, &block)]));
        let h = &headers(&items)[0].1;
        assert_eq!(h["cookie"], "a=1; b=2", "the old map insert kept only the last crumb");
        assert_eq!(h["set-cookie"], "s1=x\ns2=y");
        assert_eq!(h["accept"], "a, b");
    }

    #[test]
    fn oversized_or_garbage_framing_breaks_the_direction_without_panicking() {
        // declared length 0xFFFFFF
        let mut d = Http2Direction::new(false);
        assert!(d.feed(&[0xff, 0xff, 0xff, 0x00, 0x00, 0, 0, 0, 1]).is_empty());
        assert!(d.is_broken());
        // not an HTTP/2 client stream at all
        let mut d = Http2Direction::new(true);
        assert!(d.feed(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_empty());
        assert!(d.is_broken());
        // HEADERS on stream 0 is illegal
        let mut d = Http2Direction::new(false);
        d.feed(&frame(0x01, END_HEADERS, 0, &[0x82]));
        assert!(d.is_broken());
        // a broken direction stays inert
        assert!(d.feed(&frame(0x00, 0, 1, b"x")).is_empty());
    }

    #[test]
    fn a_preface_split_across_reads_is_awaited() {
        let mut d = Http2Direction::new(true);
        assert!(d.feed(&HTTP2_CONNECTION_PREFACE[..10]).is_empty());
        assert!(!d.is_broken());
        let rest = [&HTTP2_CONNECTION_PREFACE[10..], &frame(0x01, END_HEADERS, 1, &[0x82, 0x84])[..]].concat();
        assert_eq!(headers(&d.feed(&rest))[0].1[":method"], "GET");
    }

    #[test]
    fn announced_max_frame_size_is_reported_and_honoured() {
        let mut settings = vec![0x00, 0x05];
        settings.extend_from_slice(&(100_000u32).to_be_bytes());
        let mut announcer = Http2Direction::new(false);
        announcer.feed(&frame(0x04, 0, 0, &settings));
        assert_eq!(announcer.announced_max_frame, Some(100_000));
        // the OTHER direction may then carry a 50 KB DATA frame, which the default 16 KB would reject
        let mut peer = Http2Direction::new(true);
        peer.feed(HTTP2_CONNECTION_PREFACE);
        peer.set_max_frame(100_000);
        let big = vec![b'x'; 50_000];
        let items = peer.feed(&frame(0x00, END_STREAM, 1, &big));
        assert!(matches!(&items[0], H2Item::Data { data, .. } if data.len() == 50_000));
        assert!(!peer.is_broken());
    }
}
