use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::metrics::{EVENTS_SENT, SEND_ERRORS};
use crate::types::{ApiTrafficEvent, EventBatch};

const MAX_RETRIES: u32 = 3;

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
                if resp.status().is_success() {
                    EVENTS_SENT.fetch_add(event_count, Ordering::Relaxed);
                    return Ok(());
                }
                if resp.status().is_server_error() && attempt + 1 < MAX_RETRIES {
                    last_err = Some(format!("HTTP {}", resp.status()));
                    continue;
                }
                // Final failure — count the error
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                let status = resp.status();
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
                return Err(e.into());
            }
        }
    }
    SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
    Err(anyhow::anyhow!("ingest failed after {} retries: {:?}", MAX_RETRIES, last_err))
}
