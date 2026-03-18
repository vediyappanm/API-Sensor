#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::mcp::parse_sse_events;

fuzz_target!(|data: &[u8]| {
    let _ = parse_sse_events(data);
});
