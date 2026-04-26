use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::metrics::{EVENTS_SENT, SEND_ERRORS};
use crate::types::{ApiTrafficEvent, EventBatch};

/// Number of attempts including the initial try. With 3, we make one initial
/// request and up to 2 retries — matching the `is_server_error()` branch.
const MAX_ATTEMPTS: u32 = 3;
const COMPRESS_THRESHOLD_BYTES: usize = 4096;
const BASE_BACKOFF_MS: u64 = 200;
const MAX_BACKOFF_MS: u64 = 10_000;

/// Lightweight LCG so we don't pull in the `rand` crate (which has its own
/// RUSTSEC advisory and adds 100KB+ to the binary). Quality of randomness is
/// irrelevant here — we just want backoff jitter to stagger sensor fleets.
fn jittered_backoff_ms(attempt: u32) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let base = (BASE_BACKOFF_MS << attempt.min(6)).min(MAX_BACKOFF_MS);
    // Full jitter (Marc Brooker, AWS): sleep = random_between(0, base).
    // Avoids thundering herd when many sensors retry after a backend recovery.
    let mix = nanos.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    base.saturating_sub(1).min(mix % base.max(1))
}

pub async fn send_batch_with_client(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    events: Vec<ApiTrafficEvent>,
) -> Result<()> {
    use std::io::Write as IoWrite;

    let event_count = events.len() as u64;
    let body_struct = EventBatch { version: "v1".to_string(), events };
    let json_bytes = serde_json::to_vec(&body_struct)?;

    let (payload, content_encoding) = if json_bytes.len() > COMPRESS_THRESHOLD_BYTES {
        // `default()` (Compression::default = level 6) gives a much better
        // ratio than `fast()` (level 1) and is still well under our latency
        // budget for batches up to a few MB.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&json_bytes)?;
        (encoder.finish()?, Some("gzip"))
    } else {
        (json_bytes, None)
    };

    let mut last_err: Option<String> = None;
    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(jittered_backoff_ms(attempt))).await;
        }
        let mut req = client
            .post(url)
            .bearer_auth(api_key)
            .header("Content-Type", "application/json");
        if let Some(enc) = content_encoding {
            req = req.header("Content-Encoding", enc);
        }
        let span = tracing::debug_span!("ingest_attempt", attempt);
        let _enter = span.enter();
        match req.body(payload.clone()).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    EVENTS_SENT.fetch_add(event_count, Ordering::Relaxed);
                    return Ok(());
                }
                // Honour Retry-After on 429 / 503 if the server provided one.
                let retry_after_ms = resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|secs| secs.saturating_mul(1000));
                let retryable = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status.is_server_error();
                if retryable && attempt + 1 < MAX_ATTEMPTS {
                    if let Some(ms) = retry_after_ms {
                        tokio::time::sleep(Duration::from_millis(ms.min(MAX_BACKOFF_MS))).await;
                    }
                    last_err = Some(format!("HTTP {status}"));
                    continue;
                }
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                // Read body but cap it — buggy backends can stream gigabytes
                // back on error, which would consume sensor memory.
                let text = resp
                    .text()
                    .await
                    .map(|s| s.chars().take(512).collect::<String>())
                    .unwrap_or_default();
                return Err(anyhow::anyhow!("ingest HTTP {}: {}", status, text));
            }
            Err(e) => {
                if attempt + 1 < MAX_ATTEMPTS {
                    last_err = Some(e.to_string());
                    continue;
                }
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                return Err(e.into());
            }
        }
    }
    SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
    Err(anyhow::anyhow!("ingest failed after {} attempts: {:?}", MAX_ATTEMPTS, last_err))
}
