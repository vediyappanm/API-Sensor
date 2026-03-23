#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::http2::{Http2HpackDecoder, parse_http2_frames, contains_http2_preface};

fuzz_target!(|data: &[u8]| {
    let _ = contains_http2_preface(data);
    let mut decoder = Http2HpackDecoder::default();
    let _ = parse_http2_frames(&mut decoder, data);
});
