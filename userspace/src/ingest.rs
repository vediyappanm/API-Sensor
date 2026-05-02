use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::metrics::{EVENTS_SENT, SEND_ERRORS};
use crate::output::to_sensor_batch;
use crate::types::ApiTrafficEvent;

const MAX_ATTEMPTS: u32 = 3;
const COMPRESS_THRESHOLD_BYTES: usize = 4096;
const BASE_BACKOFF_MS: u64 = 200;
const MAX_BACKOFF_MS: u64 = 10_000;

fn jittered_backoff_ms(attempt: u32) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let base = (BASE_BACKOFF_MS << attempt.min(6)).min(MAX_BACKOFF_MS);
    let mix = nanos.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    base.saturating_sub(1).min(mix % base.max(1))
}

pub async fn send_batch_with_client(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    tenant_id: &str,
    policy_version: &str,
    events: Vec<ApiTrafficEvent>,
) -> Result<()> {
    use std::io::Write as IoWrite;

    let event_count = events.len() as u64;
    let batch = to_sensor_batch(events, tenant_id, policy_version);
    let json_bytes = serde_json::to_vec(&batch)?;

    let (payload, content_encoding) = if json_bytes.len() > COMPRESS_THRESHOLD_BYTES {
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
