#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::websocket::parse_websocket_frame;

fuzz_target!(|data: &[u8]| {
    let _ = parse_websocket_frame(data);
});
