#![no_main]
//! Fuzz the ACTIVE streaming HTTP/2 decoder (audit F20): `Http2Direction::feed`
//! is what stream.rs uses in production — incremental, per-direction, with its
//! own HPACK table, preface handling and CONTINUATION state. The previous
//! target only drove the legacy `parse_http2_frames` scanner, leaving the
//! production path unfuzzed.
//!
//! The first input byte selects the direction profile; the rest is fed in
//! chunks of varying size to exercise every split point (partial frames,
//! preface splits, CONTINUATION chains).

use libfuzzer_sys::fuzz_target;
use api_sec_sensor::http2::{Http2Direction, Http2HpackDecoder, parse_http2_frames};

fuzz_target!(|data: &[u8]| {
    let (selector, rest) = match data.split_first() {
        Some((s, r)) => (*s, r),
        None => return,
    };

    // Primary target: the production streaming decoder, both directions, fed
    // in small chunks so frame boundaries and HPACK state cross feed() calls.
    let mut req = Http2Direction::new(true); // client direction expects preface
    let mut resp = Http2Direction::new(false);
    let mut offset = 0usize;
    let mut flip = false;
    while offset < rest.len() {
        // Chunk sizes cycle through 1..=97 bytes to hit all split classes.
        let chunk = 1 + (selector as usize + offset) % 97;
        let end = (offset + chunk).min(rest.len());
        let dir = if flip { &mut resp } else { &mut req };
        let items = dir.feed(&rest[offset..end]);
        // Touch the observable surface so optimizers keep the work. A broken
        // direction may still return items completed by earlier frames in the
        // same feed() call, so no invariant is asserted here.
        let _ = (dir.is_broken(), dir.buffered(), items.len());
        flip = !flip;
        offset = end;
    }

    // Secondary target: keep the legacy whole-buffer scanner covered too.
    let mut decoder = Http2HpackDecoder::new();
    let _ = parse_http2_frames(&mut decoder, rest);
});

