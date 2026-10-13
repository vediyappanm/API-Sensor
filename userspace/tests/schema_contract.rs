//! Wire-schema contract (audit F20).
//!
//! The production exporter (userspace/src/output.rs) and the integration
//! validator (tests/test-servers/validator/server.py) must agree on the exact
//! `MsgHeader`/`Batch` envelope with flat dotted-key events. These tests run in
//! the default `cargo test` suite so a schema regression fails CI before any
//! live capture is involved.

use api_sec_sensor::output::to_sensor_batch;
use api_sec_sensor::types::{ApiRequest, ApiResponse, ApiTrafficEvent};

fn sample_event() -> ApiTrafficEvent {
    ApiTrafficEvent {
        observed_at: 1_787_000_000_000,
        protocol: "HTTP/1.1".into(),
        request: ApiRequest {
            method: "GET".into(),
            path: "/api/users?rid=schema-1".into(),
            host: Some("localhost".into()),
            scheme: "https".into(),
            headers: Default::default(),
            query: Default::default(),
            body: None,
        },
        response: ApiResponse {
            status_code: 200,
            latency_ms: Some(12),
            ..Default::default()
        },
        source_ip: Some("10.0.0.5".into()),
        dest_ip: Some("10.0.0.9".into()),
        source_port: Some(40000),
        dest_port: Some(443),
        ..Default::default()
    }
}

#[test]
fn envelope_is_exactly_msgheader_and_batch() {
    let batch = to_sensor_batch(vec![sample_event()], "tenant-1", "1");
    let value = serde_json::to_value(&batch).unwrap();
    let obj = value.as_object().expect("envelope must be an object");

    let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["Batch", "MsgHeader"],
        "the wire envelope has exactly MsgHeader and Batch and nothing else — \
         the validator rejects the legacy nested 'events' schema. (Key order is \
         not significant: serde_json::Map is unordered.)"
    );

    let header = obj["MsgHeader"].as_object().expect("MsgHeader object");
    for field in ["Version", "MessageTime", "TenantId", "Sequence",
                  "InternalOPCID", "PolicyVersion"] {
        assert!(header.contains_key(field), "MsgHeader missing {field}");
    }
    assert_eq!(header["Version"], "2.0");
    assert_eq!(header["TenantId"], "tenant-1");
    assert!(header["Sequence"].is_u64(), "Sequence must be a JSON integer");
    assert!(header["MessageTime"].is_string());

    let batch_arr = obj["Batch"].as_array().expect("Batch array");
    assert_eq!(batch_arr.len(), 1);
}

#[test]
fn every_event_carries_the_dotted_keys_the_validator_requires() {
    let batch = to_sensor_batch(vec![sample_event()], "tenant-1", "1");
    let value = serde_json::to_value(&batch).unwrap();
    let event = &value["Batch"][0];

    // Keep this list in sync with REQUIRED_EVENT_FIELDS in
    // tests/test-servers/validator/server.py — the validator 400s on any
    // missing key, which would silently drop the whole batch in production.
    let str_keys = ["LogVersion", "Id", "SessionStats.StartTime", "L7Protocol",
                    "HTTPReq.Method", "HTTPReq.Uri", "HTTPReq.Query",
                    "DownstreamL3L4.SourceIP", "DownstreamL3L4.DestIP",
                    "Proto"];
    for key in str_keys {
        assert!(event[key].is_string(), "{key} must be a string, got {event}");
    }
    let int_keys = ["SrcInfo.Source", "HTTPReq.BodyLength", "HTTPResp.ResponseCode",
                    "DownstreamL3L4.SourcePort", "DownstreamL3L4.DestPort", "APIID"];
    for key in int_keys {
        assert!(event[key].is_i64(), "{key} must be an integer, got {event}");
    }
    assert!(event["MetaDataMap"].is_object(), "MetaDataMap must be an object");

    // Correlation contract: `output::split_uri_query` puts the path in
    // `HTTPReq.Uri` and the query string in `HTTPReq.Query`, so the rid lives in
    // `HTTPReq.Query`. The validator's `GET /events?rid=` filter searches the whole
    // serialized event, so a rid=<id> parameter is still matchable end-to-end.
    assert_eq!(event["HTTPReq.Uri"].as_str().unwrap(), "/api/users");
    assert!(event["HTTPReq.Query"].as_str().unwrap().contains("rid=schema-1"));
}

#[test]
fn sequence_increases_across_batches() {
    let a = serde_json::to_value(to_sensor_batch(vec![sample_event()], "t", "1")).unwrap();
    let b = serde_json::to_value(to_sensor_batch(vec![sample_event()], "t", "1")).unwrap();
    let seq_a = a["MsgHeader"]["Sequence"].as_u64().unwrap();
    let seq_b = b["MsgHeader"]["Sequence"].as_u64().unwrap();
    assert!(seq_b > seq_a, "batch sequence must increase monotonically");
}

#[test]
fn message_time_is_backend_readable_format() {
    let batch = to_sensor_batch(vec![sample_event()], "t", "1");
    let value = serde_json::to_value(&batch).unwrap();
    let t = value["MsgHeader"]["MessageTime"].as_str().unwrap();
    // "%Y-%m-%d %H:%M:%S.%3f" — the backend rejects anything else.
    let ok = t.len() == 23
        && t.as_bytes()[4] == b'-' && t.as_bytes()[7] == b'-'
        && t.as_bytes()[10] == b' ' && t.as_bytes()[13] == b':'
        && t.as_bytes()[16] == b':' && t.as_bytes()[19] == b'.';
    assert!(ok, "MessageTime must be 'YYYY-MM-DD HH:MM:SS.mmm', got {t}");
}
