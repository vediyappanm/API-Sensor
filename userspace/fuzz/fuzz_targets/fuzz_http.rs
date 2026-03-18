#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::http::extract_http_header;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    while let Some((_, remaining)) = extract_http_header(&buf) {
        if remaining.len() >= buf.len() { break; }
        buf = remaining;
    }
});
