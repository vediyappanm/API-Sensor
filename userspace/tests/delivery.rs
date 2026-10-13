//! Delivery accounting: a batch that cannot be delivered must be visible, with its real cause.
//!
//! Before this, a dead ingest URL gave `events_sent=0`, `events_dropped=0`, a green /healthz, and a
//! log line that said only "error sending request for url" - the sensor had silently lost everything.
//! One test function, because the counters are process-global.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use api_sec_sensor::ingest::send_batch_with_client;
use api_sec_sensor::metrics::{
    CONSECUTIVE_SEND_FAILURES, EVENTS_DROPPED, EVENTS_LOST_SEND, EVENTS_SENT, LAST_SEND_OK_SECS,
    SEND_TIMEOUTS,
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

async fn serve_with_body(status: StatusCode, body: &'static str) -> String {
    let app = Router::new().route("/v1/events", post(move || async move {
        (status, body)
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/v1/events")
}

// The delivery counters are process-global, so tests in this binary must not overlap.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn init_test_key() {
    if std::env::var("PII_HASH_KEY").is_err() {
        std::env::set_var("PII_HASH_KEY", "11".repeat(32));
    }
    let _ = api_sec_sensor::redaction::init_pii_hash_key();
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
    let _serial = SERIAL.lock().await;
    init_test_key();
    let client = reqwest::Client::new();

    // 1. connection refused: nothing listens on port 1
    let (sent0, dropped0, lost0, consec0) = snapshot();
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
    assert_eq!(consec, consec0 + 1);

    // 2. the server answers 500 on every attempt
    let bad = serve(StatusCode::INTERNAL_SERVER_ERROR).await;
    let err = send_batch_with_client(&client, &bad, "k", "t", "p", events(3)).await.expect_err("500 must fail");
    assert!(format!("{err:#}").contains("500"), "{err:#}");
    let (_, dropped, lost, consec) = snapshot();
    assert_eq!((dropped, lost), (dropped0 + 10, lost0 + 10));
    assert_eq!(consec, consec0 + 2);

    // 3. a 403 (wrong sensor key) is not retried but is still a loss that must be visible
    let forbidden = serve(StatusCode::FORBIDDEN).await;
    let err = send_batch_with_client(&client, &forbidden, "wrong", "t", "p", events(2)).await.expect_err("403 must fail");
    assert!(format!("{err:#}").contains("403"), "{err:#}");
    assert_eq!(snapshot().3, consec0 + 3);

    // 4. recovery: one accepted batch resets the failure streak and records the time
    let ok = serve(StatusCode::OK).await;
    send_batch_with_client(&client, &ok, "k", "t", "p", events(5)).await.expect("200 must succeed");
    let (sent, _, _, consec) = snapshot();
    assert_eq!(sent, sent0 + 5);
    assert_eq!(consec, 0, "a success must reset the consecutive-failure streak");
    assert!(LAST_SEND_OK_SECS.load(Ordering::Relaxed) > 0);
}

/// A server that counts the requests it receives, answers `status`, and takes `delay` to do so.
async fn serve_counting(status: StatusCode, delay: Duration) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = Router::new().route("/v1/events", post(move || {
        let h = h.clone();
        async move {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            status
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/v1/events"), hits)
}

#[tokio::test]
async fn a_batch_is_resent_only_when_the_server_certainly_did_not_process_it() {
    let _serial = SERIAL.lock().await;
    init_test_key();
    let client = reqwest::Client::builder().timeout(Duration::from_millis(300)).build().unwrap();

    // Canary 1: the backend committed every timed-out attempt, so each batch was stored 3 times.
    let (slow, hits) = serve_counting(StatusCode::OK, Duration::from_secs(2)).await;
    let timeouts0 = SEND_TIMEOUTS.load(Ordering::Relaxed);
    let lost0 = EVENTS_LOST_SEND.load(Ordering::Relaxed);
    let err = send_batch_with_client(&client, &slow, "k", "t", "p", events(4)).await.expect_err("timeout must fail");
    assert!(format!("{err:#}").contains("not resent"), "{err:#}");
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a timed-out batch must not be sent again");
    assert_eq!(SEND_TIMEOUTS.load(Ordering::Relaxed), timeouts0 + 1);
    assert_eq!(EVENTS_LOST_SEND.load(Ordering::Relaxed), lost0 + 4, "unacknowledged events stay visible");

    // A 500 may come after a partial commit: outcome unknown, not resent.
    let (failing, hits) = serve_counting(StatusCode::INTERNAL_SERVER_ERROR, Duration::ZERO).await;
    send_batch_with_client(&client, &failing, "k", "t", "p", events(1)).await.expect_err("500 must fail");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a 500 must not be resent");

    // 503 and 429 mean the server refused the batch, so resending cannot duplicate it.
    for status in [StatusCode::SERVICE_UNAVAILABLE, StatusCode::TOO_MANY_REQUESTS] {
        let (refusing, hits) = serve_counting(status, Duration::ZERO).await;
        send_batch_with_client(&client, &refusing, "k", "t", "p", events(1)).await.expect_err("refusal must fail");
        assert_eq!(hits.load(Ordering::SeqCst), 3, "{status} is retried up to the attempt limit");
    }
}

#[tokio::test]
async fn error_body_reading_is_bounded_and_redacted() {
    let _serial = SERIAL.lock().await;
    init_test_key();
    let client = reqwest::Client::new();

    // 1. Error body larger than limit is truncated
    let large_body: &'static str = Box::leak("x".repeat(2000).into_boxed_str());
    let large_error = serve_with_body(StatusCode::INTERNAL_SERVER_ERROR, large_body).await;
    let err = send_batch_with_client(&client, &large_error, "k", "t", "p", events(1))
        .await
        .expect_err("500 must fail");
    let msg = format!("{err:#}");
    assert!(!msg.contains("x".repeat(1000).as_str()), "error body should be truncated");
    assert!(msg.contains("500"), "should still include status");

    // 2. Error body is redacted before logging
    let sensitive = serve_with_body(StatusCode::FORBIDDEN, r#"{"password":"secret123"}"#).await;
    let err = send_batch_with_client(&client, &sensitive, "k", "t", "p", events(1))
        .await
        .expect_err("403 must fail");
    let msg = format!("{err:#}");
    assert!(!msg.contains("secret123"), "sensitive data in error body should be redacted");
    assert!(msg.contains("403"), "should still include status");
}
