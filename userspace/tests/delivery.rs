//! Delivery accounting: a batch that cannot be delivered must be visible, with its real cause.
//!
//! Before this, a dead ingest URL gave `events_sent=0`, `events_dropped=0`, a green /healthz, and a
//! log line that said only "error sending request for url" - the sensor had silently lost everything.
//! One test function, because the counters are process-global.

use std::sync::atomic::Ordering;

use api_sec_sensor::ingest::send_batch_with_client;
use api_sec_sensor::metrics::{
    CONSECUTIVE_SEND_FAILURES, EVENTS_DROPPED, EVENTS_LOST_SEND, EVENTS_SENT, LAST_SEND_OK_SECS,
};
use api_sec_sensor::types::ApiTrafficEvent;
use axum::{http::StatusCode, routing::post, Router};

fn events(n: usize) -> Vec<ApiTrafficEvent> {
    (0..n).map(|_| ApiTrafficEvent::default()).collect()
}

async fn serve(status: StatusCode) -> String {
    let app = Router::new().route("/v1/events", post(move || async move { status }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/v1/events")
}

fn snapshot() -> (u64, u64, u64, u64) {
    (
        EVENTS_SENT.load(Ordering::Relaxed),
        EVENTS_DROPPED.load(Ordering::Relaxed),
        EVENTS_LOST_SEND.load(Ordering::Relaxed),
        CONSECUTIVE_SEND_FAILURES.load(Ordering::Relaxed),
    )
}

#[tokio::test]
async fn failed_batches_are_counted_with_their_cause_and_success_resets_the_streak() {
    let client = reqwest::Client::new();

    // 1. connection refused: nothing listens on port 1
    let (sent0, dropped0, lost0, _) = snapshot();
    let err = send_batch_with_client(&client, "http://127.0.0.1:1/v1/events", "k", "t", "p", events(7))
        .await
        .expect_err("a refused connection must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("connect") && msg.len() > "error sending request for url".len() + 20,
        "the error must carry the real cause, not just 'error sending request': {msg}"
    );
    let (sent, dropped, lost, consec) = snapshot();
    assert_eq!(sent, sent0, "nothing was delivered");
    assert_eq!(dropped, dropped0 + 7, "the 7 lost events must be counted as dropped");
    assert_eq!(lost, lost0 + 7);
    assert_eq!(consec, 1);

    // 2. the server answers 500 on every attempt
    let bad = serve(StatusCode::INTERNAL_SERVER_ERROR).await;
    let err = send_batch_with_client(&client, &bad, "k", "t", "p", events(3)).await.expect_err("500 must fail");
    assert!(format!("{err:#}").contains("500"), "{err:#}");
    let (_, dropped, lost, consec) = snapshot();
    assert_eq!((dropped, lost), (dropped0 + 10, lost0 + 10));
    assert_eq!(consec, 2);

    // 3. a 403 (wrong sensor key) is not retried but is still a loss that must be visible
    let forbidden = serve(StatusCode::FORBIDDEN).await;
    let err = send_batch_with_client(&client, &forbidden, "wrong", "t", "p", events(2)).await.expect_err("403 must fail");
    assert!(format!("{err:#}").contains("403"), "{err:#}");
    assert_eq!(snapshot().3, 3);

    // 4. recovery: one accepted batch resets the failure streak and records the time
    let ok = serve(StatusCode::OK).await;
    send_batch_with_client(&client, &ok, "k", "t", "p", events(5)).await.expect("200 must succeed");
    let (sent, _, _, consec) = snapshot();
    assert_eq!(sent, sent0 + 5);
    assert_eq!(consec, 0, "a success must reset the consecutive-failure streak");
    assert!(LAST_SEND_OK_SECS.load(Ordering::Relaxed) > 0);
}
