use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::metrics::{record_send_failure, record_send_success, EVENTS_SENT, SEND_ERRORS};
use crate::output::to_sensor_batch;
use crate::types::ApiTrafficEvent;

const MAX_ATTEMPTS: u32 = 3;
const COMPRESS_THRESHOLD_BYTES: usize = 4096;
const BASE_BACKOFF_MS: u64 = 200;
const MAX_BACKOFF_MS: u64 = 10_000;

/// Full cause chain of an error. reqwest's Display is just "error sending request for url (...)",
/// which hides whether the cause was a refused connection, a DNS failure or a TLS error.
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut cur = err.source();
    while let Some(e) = cur {
        let part = e.to_string();
        if !out.contains(&part) {
            out.push_str(": ");
            out.push_str(&part);
        }
        cur = e.source();
    }
    out
}

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

const MAX_ERROR_BODY_BYTES: usize = 512;

/// At most `limit` bytes of an error response, read chunk by chunk. A body without
/// Content-Length (chunked or close-delimited) can be arbitrarily large, so it is never
/// buffered whole; the rest is abandoned with the connection.
async fn read_error_body(mut resp: reqwest::Response, limit: usize) -> String {
    let mut buf = Vec::with_capacity(limit.min(4096));
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(limit - buf.len());
                buf.extend_from_slice(&chunk[..take]);
                if buf.len() >= limit {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) if buf.is_empty() => return "[error reading body]".to_string(),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Encode a serialized batch envelope for the wire. Payloads above the
/// threshold are gzip-compressed and labelled `Content-Encoding: gzip`; the
/// validator on the receiving side (tests/test-servers/validator/server.py)
/// accepts exactly this contract.
pub fn encode_batch_payload(json_bytes: &[u8]) -> Result<(Vec<u8>, Option<&'static str>)> {
    use std::io::Write as IoWrite;

    if json_bytes.len() > COMPRESS_THRESHOLD_BYTES {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(json_bytes)?;
        Ok((encoder.finish()?, Some("gzip")))
    } else {
        Ok((json_bytes.to_vec(), None))
    }
}

async fn try_send_batch(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    tenant_id: &str,
    policy_version: &str,
    events: Vec<ApiTrafficEvent>,
) -> Result<()> {
    let event_count = events.len() as u64;
    let batch = to_sensor_batch(events, tenant_id, policy_version);
    let json_bytes = serde_json::to_vec(&batch)?;
    let (payload, content_encoding) = encode_batch_payload(&json_bytes)?;

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
                let text = read_error_body(resp, MAX_ERROR_BODY_BYTES).await;
                let redacted_text = crate::redaction::redact_text(&text);
                return Err(anyhow::anyhow!("ingest HTTP {}: {}", status, redacted_text));
            }
            Err(e) => {
                if attempt + 1 < MAX_ATTEMPTS {
                    last_err = Some(error_chain(&e));
                    continue;
                }
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("ingest request failed: {}", error_chain(&e)));
            }
        }
    }
    SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
    Err(anyhow::anyhow!("ingest failed after {} attempts: {:?}", MAX_ATTEMPTS, last_err))
}

/// Send one batch. On failure the batch is gone (it is not retried beyond MAX_ATTEMPTS), so the
/// loss is recorded: events counted as dropped, consecutive-failure counter raised, which is what
/// `/readyz` and the metrics report. On success the failure streak resets.
pub async fn send_batch_with_client(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    tenant_id: &str,
    policy_version: &str,
    events: Vec<ApiTrafficEvent>,
) -> Result<()> {
    let count = events.len() as u64;
    match try_send_batch(client, url, api_key, tenant_id, policy_version, events).await {
        Ok(()) => {
            record_send_success();
            Ok(())
        }
        Err(e) => {
            record_send_failure(count);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decompress(data: &[u8]) -> Vec<u8> {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut out = Vec::new();
        GzDecoder::new(data).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn small_payload_is_plain_json_without_encoding() {
        let (payload, enc) = encode_batch_payload(b"{\"MsgHeader\":{},\"Batch\":[]}").unwrap();
        assert_eq!(enc, None, "below threshold nothing must be compressed");
        assert_eq!(payload, b"{\"MsgHeader\":{},\"Batch\":[]}");
    }

    #[test]
    fn large_payload_is_gzip_and_round_trips() {
        // Just above the 4096-byte threshold the sensor must switch to gzip —
        // this is the contract the integration validator enforces.
        let big = serde_json::to_vec(&serde_json::json!({
            "filler": "A".repeat(COMPRESS_THRESHOLD_BYTES + 256)
        }))
        .unwrap();
        let (payload, enc) = encode_batch_payload(&big).unwrap();
        assert_eq!(enc, Some("gzip"), "above threshold payload must be gzip");
        assert_eq!(
            payload[..2],
            [0x1f, 0x8b],
            "gzip magic must be present for servers that ignore the header"
        );
        assert!(payload.len() < big.len(), "compression must shrink the payload");
        assert_eq!(decompress(&payload), big, "gzip must round-trip losslessly");
    }

    #[tokio::test]
    async fn an_endless_chunked_error_body_is_read_only_up_to_the_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sent_srv = sent.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 4096];
            let _ = sock.read(&mut req).await;
            let head = b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n";
            if sock.write_all(head).await.is_err() {
                return;
            }
            let chunk = format!("{:x}\r\n{}\r\n", 64 * 1024, "e".repeat(64 * 1024));
            // 1 GiB if nobody stops reading; the client must give up long before.
            for _ in 0..16 * 1024 {
                if sock.write_all(chunk.as_bytes()).await.is_err() {
                    return;
                }
                sent_srv.fetch_add(64 * 1024, Ordering::Relaxed);
            }
        });
        let client = reqwest::Client::new();
        let resp = client.post(format!("http://{addr}/")).body("x").send().await.unwrap();
        let text = tokio::time::timeout(Duration::from_secs(10), read_error_body(resp, MAX_ERROR_BODY_BYTES))
            .await
            .expect("reading a capped error body must not wait for the whole stream");
        assert_eq!(text.len(), MAX_ERROR_BODY_BYTES);
        assert!(
            sent.load(Ordering::Relaxed) < 64 * 1024 * 1024,
            "client consumed {} bytes for a 512-byte log line",
            sent.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn exactly_threshold_is_not_compressed() {
        let exact = vec![b'x'; COMPRESS_THRESHOLD_BYTES];
        let (_, enc) = encode_batch_payload(&exact).unwrap();
        assert_eq!(enc, None, "threshold boundary itself stays uncompressed");
    }
}
