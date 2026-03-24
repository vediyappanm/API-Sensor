use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::metrics::{EVENTS_SENT, SEND_ERRORS};
use crate::types::{ApiTrafficEvent, EventBatch};

static CONSECUTIVE_FAILURES: AtomicU64 = AtomicU64::new(0);
static CIRCUIT_OPEN_UNTIL: AtomicU64 = AtomicU64::new(0);

/// Counter for events spilled to dead letter queue.
pub static DLQ_SPILLED: AtomicU64 = AtomicU64::new(0);
/// Counter for events recovered from dead letter queue.
pub static DLQ_RECOVERED: AtomicU64 = AtomicU64::new(0);

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

const MAX_RETRIES: u32 = 3;
/// Maximum number of spill files to keep (prevents unbounded disk usage).
const MAX_DLQ_FILES: usize = 1000;
/// Maximum age of spill files before they are discarded (1 hour).
const MAX_DLQ_AGE_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// Dead Letter Queue — disk-backed spill for failed batches
// ---------------------------------------------------------------------------

/// Spill a failed batch to disk so it can be retried later.
pub async fn spill_to_dlq(dlq_dir: &Path, events: &[ApiTrafficEvent]) {
    use std::io::Write as IoWrite;

    if events.is_empty() {
        return;
    }

    if let Err(e) = tokio::fs::create_dir_all(dlq_dir).await {
        tracing::error!(error = %e, "cannot create DLQ directory");
        return;
    }

    let batch = EventBatch {
        version: "v1".to_string(),
        events: events.to_vec(),
    };
    let json_bytes = match serde_json::to_vec(&batch) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "DLQ serialization failed");
            return;
        }
    };

    // Compress before writing to save disk space
    let compressed = {
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        if enc.write_all(&json_bytes).is_err() {
            return;
        }
        match enc.finish() {
            Ok(c) => c,
            Err(_) => return,
        }
    };

    let filename = format!("dlq_{}.json.gz", now_epoch_ms());
    let path = dlq_dir.join(&filename);
    match tokio::fs::write(&path, &compressed).await {
        Ok(_) => {
            DLQ_SPILLED.fetch_add(events.len() as u64, Ordering::Relaxed);
            tracing::info!(
                events = events.len(),
                file = %filename,
                "batch spilled to dead letter queue"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "DLQ write failed");
        }
    }
}

/// Background task: periodically retry spilled batches from the DLQ directory.
pub async fn dlq_retry_loop(
    dlq_dir: PathBuf,
    client: std::sync::Arc<reqwest::Client>,
    url: String,
    api_key: String,
) {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;

        let mut entries = match tokio::fs::read_dir(&dlq_dir).await {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut files: Vec<PathBuf> = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("gz") {
                files.push(path);
            }
        }
        files.sort(); // oldest first (timestamp in filename)

        // Enforce max files — discard oldest if over limit
        while files.len() > MAX_DLQ_FILES {
            if let Some(old) = files.first() {
                let _ = tokio::fs::remove_file(old).await;
                files.remove(0);
            }
        }

        for file_path in &files {
            // Discard files older than MAX_DLQ_AGE_SECS
            if let Ok(meta) = tokio::fs::metadata(file_path).await {
                let expired = meta
                    .modified()
                    .ok()
                    .and_then(|t: std::time::SystemTime| t.elapsed().ok())
                    .map(|age| age.as_secs() > MAX_DLQ_AGE_SECS)
                    .unwrap_or(false);
                if expired {
                    tracing::debug!(file = ?file_path, "DLQ file expired, discarding");
                    let _ = tokio::fs::remove_file(file_path).await;
                    continue;
                }
            }

            // Don't retry if circuit is still open
            let now = now_epoch_ms();
            if now < CIRCUIT_OPEN_UNTIL.load(Ordering::Relaxed) {
                break;
            }

            let compressed = match tokio::fs::read(file_path).await {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut decoder = GzDecoder::new(&compressed[..]);
            let mut json_bytes = Vec::new();
            if decoder.read_to_end(&mut json_bytes).is_err() {
                // Corrupted file — discard
                let _ = tokio::fs::remove_file(file_path).await;
                continue;
            }

            let batch: EventBatch = match serde_json::from_slice(&json_bytes) {
                Ok(b) => b,
                Err(_) => {
                    let _ = tokio::fs::remove_file(file_path).await;
                    continue;
                }
            };

            let event_count = batch.events.len() as u64;
            match send_batch_with_client(&client, &url, &api_key, batch.events).await {
                Ok(_) => {
                    DLQ_RECOVERED.fetch_add(event_count, Ordering::Relaxed);
                    let _ = tokio::fs::remove_file(file_path).await;
                    tracing::info!(
                        events = event_count,
                        file = ?file_path.file_name(),
                        "DLQ batch recovered and sent"
                    );
                }
                Err(_) => {
                    // Still failing — stop retrying this cycle, try next interval
                    tracing::debug!("DLQ retry failed, will retry next cycle");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Batch sender with retries + circuit breaker
// ---------------------------------------------------------------------------

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
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                let failures = CONSECUTIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= 5 {
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
