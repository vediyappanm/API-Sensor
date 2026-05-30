use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::metrics::{EVENTS_SENT, SEND_ERRORS};
use crate::types::{ApiTrafficEvent, EventBatch};

static CONSECUTIVE_FAILURES: AtomicU64 = AtomicU64::new(0);
static CIRCUIT_OPEN_UNTIL: AtomicU64 = AtomicU64::new(0);

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

const MAX_RETRIES: u32 = 3;

pub async fn send_batch_with_client(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    events: Vec<ApiTrafficEvent>,
) -> Result<()> {
    use std::io::Write as IoWrite;

    // Circuit breaker: skip if circuit is open
    let now = now_epoch_ms();
    let open_until = CIRCUIT_OPEN_UNTIL.load(Ordering::Relaxed);
    if now < open_until {
        EVENTS_SENT.fetch_add(0, Ordering::Relaxed); // no-op, just for clarity
        tracing::debug!(
            reopen_in_ms = open_until - now,
            "circuit breaker open, skipping batch"
        );
        return Err(anyhow::anyhow!(
            "circuit breaker open, {} events deferred",
            events.len()
        ));
    }

    let event_count = events.len() as u64;
    let body_struct = EventBatch {
        version: "v1".to_string(),
        events,
    };
    let json_bytes = serde_json::to_vec(&body_struct)?;

    let (payload, content_encoding) = if json_bytes.len() > 4096 {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&json_bytes)?;
        (encoder.finish()?, Some("gzip"))
    } else {
        (json_bytes, None)
    };

    let mut last_err: Option<String> = None;
    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(200 * (1 << attempt))).await;
        }
        let mut req = client
            .post(url)
            .bearer_auth(api_key)
            .header("Content-Type", "application/json");
        if let Some(enc) = content_encoding {
            req = req.header("Content-Encoding", enc);
        }
        match req.body(payload.clone()).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    EVENTS_SENT.fetch_add(event_count, Ordering::Relaxed);
                    CONSECUTIVE_FAILURES.store(0, Ordering::Relaxed);
                    return Ok(());
                }
                // Client errors are not retryable — bad key, bad payload, etc.
                if status == reqwest::StatusCode::UNAUTHORIZED
                    || status == reqwest::StatusCode::FORBIDDEN
                {
                    SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                    return Err(anyhow::anyhow!(
                        "ingest auth error HTTP {} (check API key, not retryable)",
                        status
                    ));
                }
                if status.is_client_error() {
                    SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                    let text = resp.text().await.unwrap_or_default();
                    return Err(anyhow::anyhow!(
                        "ingest HTTP {} (not retryable): {}",
                        status,
                        text
                    ));
                }
                // Server errors — retry if attempts remain
                if status.is_server_error() && attempt + 1 < MAX_RETRIES {
                    last_err = Some(format!("HTTP {}", status));
                    continue;
                }
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow::anyhow!("ingest HTTP {}: {}", status, text));
            }
            Err(e) => {
                if attempt + 1 < MAX_RETRIES {
                    last_err = Some(e.to_string());
                    continue;
                }
                // Final failure — count the error
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                let failures = CONSECUTIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= 5 {
                    // Open circuit for exponential backoff: 5s, 10s, 20s, 40s... max 300s
                    let backoff_ms = (5000u64 * (1 << (failures - 5).min(6))).min(300_000);
                    CIRCUIT_OPEN_UNTIL.store(now_epoch_ms() + backoff_ms, Ordering::Relaxed);
                    tracing::warn!(failures, backoff_ms, "circuit breaker opened");
                }
                return Err(e.into());
            }
        }
    }
    SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
    let failures = CONSECUTIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
    if failures >= 5 {
        // Open circuit for exponential backoff: 5s, 10s, 20s, 40s... max 300s
        let backoff_ms = (5000u64 * (1 << (failures - 5).min(6))).min(300_000);
        CIRCUIT_OPEN_UNTIL.store(now_epoch_ms() + backoff_ms, Ordering::Relaxed);
        tracing::warn!(failures, backoff_ms, "circuit breaker opened");
    }
    Err(anyhow::anyhow!(
        "ingest failed after {} retries: {:?}",
        MAX_RETRIES,
        last_err
    ))
}
