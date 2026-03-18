#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::http2::{Http2HpackDecoder, parse_http2_frames};

fuzz_target!(|data: &[u8]| {
    let mut decoder = Http2HpackDecoder::new();
    let _ = parse_http2_frames(&mut decoder, data);
});
