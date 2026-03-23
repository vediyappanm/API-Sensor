#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::quic::{looks_like_http3, extract_h3_headers, decode_varint, decode_qpack_headers};

fuzz_target!(|data: &[u8]| {
    let _ = looks_like_http3(data);
    let _ = extract_h3_headers(data);
    let _ = decode_varint(data);
    let _ = decode_qpack_headers(data);
});
