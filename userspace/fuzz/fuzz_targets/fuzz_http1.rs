#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::http::extract_http_header;

fuzz_target!(|data: &[u8]| {
    let _ = extract_http_header(data);
});
