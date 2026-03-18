#![no_main]
use libfuzzer_sys::fuzz_target;
use api_sec_sensor::grpc::decode_grpc_fields;

fuzz_target!(|data: &[u8]| {
    let _ = decode_grpc_fields(data);
});
