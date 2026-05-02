mod types;
mod metrics;
mod redaction;
mod identity;
mod output;
mod websocket;
mod grpc;
mod mcp;
mod http2;
mod http;
mod go_tls;
mod boringssl;
mod container;
mod stream;
mod ingest;
mod bpf;
mod dns;
mod quic;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder};
use std::ffi::OsStr;
use std::env;
use std::fs;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

use crate::bpf::{attach_tls_uprobes, attach_kernel_probes, attach_quic_uprobes,
                  attach_nss_uprobes, attach_ktls_kprobes, attach_lsm_hooks};
use crate::boringssl::{attach_boring_ssl_static, attach_mbedtls_static, attach_wolfssl_static};
use crate::container::{ContainerLookupRequest, ContainerResolver, fetch_container_metadata};
use crate::dns::{DnsResolver, reverse_dns_lookup};
use crate::go_tls::{attach_go_tls_probes, detect_go_binary, find_go_tls_offsets};
use crate::http::discover_tls_libs;
use crate::ingest::send_batch_with_client;
use crate::metrics::*;
use crate::quic::discover_quic_libs;
use crate::stream::ShardedStreamState;
use crate::types::*;

// ---------------------------------------------------------------------------
// CLI Args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(about = "API Security eBPF Sensor")]
struct Args {
    #[arg(long)]
    bpf: String,
    #[arg(long)]
    ingest: String,
    #[arg(long, env = "API_KEY", default_value = "")]
    api_key: String,
    #[arg(long, default_value = "1000000")]
    account_id: u64,
    #[arg(long, default_value = "default")]
    tenant_id: String,
    #[arg(long, default_value = "1")]
    policy_version: String,
    #[arg(long, default_value = "200")]
    batch_size: usize,
    #[arg(long, default_value = "server")]
    role: String,
    #[arg(long, value_delimiter = ',', default_value = "/usr/lib/x86_64-linux-gnu/libssl.so.3")]
    tls_libs: Vec<String>,
    #[arg(long, default_value = "auto")]
    tls_provider: String,
    #[arg(long, default_value = "-1")]
    pid: i32,
    #[arg(long, default_value_t = false)]
    discover_libs: bool,
    #[arg(long, default_value = "65536")]
    max_buffer_bytes: usize,
    #[arg(long, default_value = "104857600")]
    max_total_buffer_bytes: usize,
    #[arg(long, default_value = "9090")]
    metrics_port: u16,
    #[arg(long, default_value_t = false)]
    go_tls: bool,
    #[arg(long, default_value = "100")]
    sample_default: u8,
    #[arg(long, default_value = "5")]
    sample_health: u8,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Record start time
    let start_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    START_TIME_SECS.store(start_secs, Ordering::Relaxed);

    let args = Args::parse();

    // Validate required args
    if args.api_key.is_empty() {
        anyhow::bail!("--api-key or API_KEY env var is required");
    }
    if !args.ingest.starts_with("http://") && !args.ingest.starts_with("https://") {
        anyhow::bail!("--ingest must be an http:// or https:// URL, got: {}", args.ingest);
    }
    // Refuse to start without an explicit PII hash key. A guessable / hardcoded
    // key would let any reader of the binary or environment de-tokenize all
    // redacted PII downstream — that defeats the entire redaction guarantee.
    redaction::init_pii_hash_key()
        .map_err(|e| anyhow::anyhow!("PII redaction init failed: {e}"))?;
    let role = match args.role.as_str() {
        "server" => TrafficRole::Server,
        "client" => TrafficRole::Client,
        other => anyhow::bail!("invalid --role '{}': must be 'server' or 'client'", other),
    };
    let sample_default = args.sample_default.min(100);
    let sample_health = args.sample_health.min(100);

    tracing::info!(bpf = %args.bpf, ingest = %args.ingest, "starting sensor");

    // Start metrics server
    tokio::spawn(start_metrics_server(args.metrics_port));

    let obj_data = fs::read(&args.bpf)?;
    let mut obj = ObjectBuilder::default().open_memory(&obj_data)?.load()?;

    let mut links = Vec::new();
    let mut tls_libs = args.tls_libs.clone();
    if args.discover_libs {
        let discovered = discover_tls_libs(args.pid);
        if !discovered.is_empty() {
            tls_libs = discovered;
        }
    }
    // Discover and attach NSS uprobes (libnss3) alongside TLS libs
    let nss_libs: Vec<String> = tls_libs.iter()
        .filter(|l| l.to_lowercase().contains("libnss") || l.to_lowercase().contains("nss3"))
        .cloned()
        .collect();
    attach_tls_uprobes(&mut obj, &args.tls_provider, args.pid, args.go_tls, &tls_libs, &mut links)?;
    if !nss_libs.is_empty() {
        attach_nss_uprobes(&mut obj, args.pid, &nss_libs, &mut links);
    }
    attach_kernel_probes(&mut obj, &mut links)?;
    attach_ktls_kprobes(&mut obj, &mut links);
    attach_lsm_hooks(&mut obj, &mut links);

    // Initialize sampling_config — must happen before polling starts.
    // BPF arrays are zero-initialized; rate=0 means "filter everything".
    if let Some(map) = obj.maps().find(|m| m.name() == OsStr::new("sampling_config")) {
        let key: u32 = 0;
        let cfg_bytes: [u8; 4] = [sample_default, sample_health, 0, 0];
        if let Err(e) = map.update(&key.to_ne_bytes(), &cfg_bytes, libbpf_rs::MapFlags::ANY) {
            tracing::warn!(error = %e, "failed to set sampling_config");
        }
    } else {
        tracing::warn!("sampling_config map not found in BPF object");
    }

    // Enable BPF dynptr path on kernel ≥5.19 (variable-length ring buffer slots).
    {
        let (maj, min) = kernel_version_maj_min();
        if maj > 5 || (maj == 5 && min >= 19) {
            if let Some(map) = obj.maps().find(|m| m.name() == OsStr::new("use_dynptr")) {
                let key: u32 = 0;
                let val: u32 = 1;
                if let Err(e) = map.update(&key.to_ne_bytes(), &val.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
                    tracing::warn!(error = %e, "failed to enable use_dynptr");
                } else {
                    tracing::info!(kernel_major = maj, kernel_minor = min, "BPF dynptr path enabled");
                }
            }
        } else {
            tracing::info!(kernel_major = maj, kernel_minor = min, "BPF dynptr path disabled (requires kernel ≥5.19)");
        }
    }

    // Go TLS probes
    if args.go_tls {
        tracing::info!(pid = args.pid, "Go TLS: scanning");
        if let Some(go_bin) = detect_go_binary(args.pid) {
            tracing::info!(binary = %go_bin, "Go TLS: detected binary");
            if let Some(offsets) = find_go_tls_offsets(&go_bin) {
                tracing::info!(binary = %go_bin, version = %offsets.go_version, "attaching Go TLS probes");
                attach_go_tls_probes(&mut obj, &offsets, &mut links, args.pid);
            } else {
                tracing::warn!(binary = %go_bin, "Go TLS: no offsets found");
            }
        } else {
            tracing::warn!(pid = args.pid, "Go TLS: no Go binary found");
        }
        // Check for static BoringSSL in the target binary
        if args.pid > 0 {
            let maps_path = format!("/proc/{}/maps", args.pid);
            if let Ok(maps) = fs::read_to_string(&maps_path) {
                for line in maps.lines() {
                    if line.contains("r-xp") {
                        if let Some(path) = line.split_whitespace().last() {
                            if path.starts_with('/') {
                                attach_boring_ssl_static(&mut obj, path, args.pid, &mut links);
                                attach_mbedtls_static(&mut obj, path, args.pid, &mut links);
                                attach_wolfssl_static(&mut obj, path, args.pid, &mut links);
                                // Warn if this is a known TLS-terminating sidecar — our uprobes
                                // capture app-level plaintext but miss the outer TLS metadata.
                                let basename = std::path::Path::new(path)
                                    .file_name().and_then(|f| f.to_str()).unwrap_or("");
                                if matches!(basename, "envoy" | "pilot-agent" | "linkerd2-proxy"
                                            | "istio-proxy" | "nginx" | "haproxy") {
                                    tracing::warn!(
                                        binary = %path,
                                        "sidecar/proxy detected: uprobes capture app-layer plaintext \
                                         but outer TLS metadata (mTLS peer identity) is not captured"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Final guard: if --go-tls and nothing attached, bail
    if args.go_tls && links.is_empty() {
        anyhow::bail!("no probes attached; --go-tls enabled but no TLS library or Go binary found");
    }

    let node_name = env::var("NODE_NAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-node".to_string());
    let cri_socket = env::var("CRI_SOCKET")
        .unwrap_or_else(|_| "/run/containerd/containerd.sock".to_string());

    let (lookup_tx, mut lookup_rx) = mpsc::channel::<ContainerLookupRequest>(1024);
    let container_resolver = Arc::new(ContainerResolver::new(lookup_tx, node_name));
    let resolver_handle = container_resolver.clone();
    tokio::spawn(async move {
        while let Some(req) = lookup_rx.recv().await {
            match fetch_container_metadata(&cri_socket, &req.container_id_full).await {
                Ok(meta) => resolver_handle.update_from_cri(req.cgroup_id, meta),
                Err(e) => {
                    tracing::warn!(container = %req.container_id_full, error = %e, "CRI lookup failed");
                    resolver_handle.mark_lookup_failed(req.cgroup_id);
                }
            }
        }
    });

    // DNS reverse-resolution (background worker)
    let (dns_tx, mut dns_rx) = mpsc::channel::<std::net::IpAddr>(4096);
    let dns_resolver = Arc::new(DnsResolver::new(dns_tx));
    let dns_handle = dns_resolver.clone();
    tokio::spawn(async move {
        while let Some(ip) = dns_rx.recv().await {
            let handle = dns_handle.clone();
            tokio::spawn(async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::task::spawn_blocking(move || reverse_dns_lookup(ip)),
                )
                .await;
                match result {
                    Ok(Ok(hostname)) => handle.insert(ip, hostname),
                    _ => handle.insert(ip, None),
                }
            });
        }
    });

    // Discover and attach QUIC library probes
    if args.discover_libs || args.go_tls {
        let quic_libs = discover_quic_libs(args.pid);
        if !quic_libs.is_empty() {
            tracing::info!(libs = ?quic_libs, "discovered QUIC libraries");
            match attach_quic_uprobes(&mut obj, args.pid, &quic_libs, &mut links) {
                Ok(n) if n > 0 => tracing::info!(attached = n, "QUIC probes active"),
                Ok(_) => tracing::debug!("no QUIC symbols resolved"),
                Err(e) => tracing::warn!(error = %e, "QUIC uprobe attachment failed"),
            }
        }
    }

    let (tx, mut rx) = mpsc::channel::<ApiTrafficEvent>(10000);

    let http_client = Arc::new(
        reqwest::Client::builder()
            .pool_max_idle_per_host(16)
            .timeout(Duration::from_secs(10))
            .build()?,
    );

    let ingest_url      = args.ingest.clone();
    let api_key         = args.api_key.clone();
    let tenant_id       = args.tenant_id.clone();
    let policy_version  = args.policy_version.clone();
    let batch_size      = args.batch_size;
    let client_handle   = http_client.clone();
    let batch_handle = tokio::spawn(async move {
        let mut batch: Vec<ApiTrafficEvent> = Vec::new();
        let mut flush_interval = time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    match ev {
                        Some(event) => {
                            batch.push(event);
                            if batch.len() >= batch_size {
                                let payload = std::mem::take(&mut batch);
                                if let Err(e) = send_batch_with_client(&client_handle, &ingest_url, &api_key, &tenant_id, &policy_version, payload).await {
                                    tracing::error!(error = %e, "batch send failed");
                                }
                            }
                        }
                        None => {
                            // Channel closed — flush remaining events before exit
                            if !batch.is_empty() {
                                let payload = std::mem::take(&mut batch);
                                if let Err(e) = send_batch_with_client(&client_handle, &ingest_url, &api_key, &tenant_id, &policy_version, payload).await {
                                    tracing::error!(error = %e, "final flush failed");
                                }
                            }
                            break;
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !batch.is_empty() {
                        let payload = std::mem::take(&mut batch);
                        if let Err(e) = send_batch_with_client(&client_handle, &ingest_url, &api_key, &tenant_id, &policy_version, payload).await {
                            tracing::error!(error = %e, "interval flush failed");
                        }
                    }
                }
            }
        }
    });

    // Use ShardedStreamState
    let state = Arc::new(ShardedStreamState::new(
        args.account_id,
        role,
        args.max_buffer_bytes,
        container_resolver.clone(),
        args.max_total_buffer_bytes,
        dns_resolver.clone(),
    ));

    let mut ringbuf = RingBufferBuilder::new();
    let sender = tx.clone();
    let state_handle = state.clone();

    let events_map = obj.maps()
        .find(|m| m.name() == OsStr::new("events"))
        .ok_or_else(|| anyhow::anyhow!("missing events map"))?;
    let close_events_map = obj.maps()
        .find(|m| m.name() == OsStr::new("close_events"))
        .ok_or_else(|| anyhow::anyhow!("missing close_events map"))?;
    let proc_map_opt = obj.maps().find(|m| m.name() == OsStr::new("proc_events"));

    let channel_capacity = 10000u64;
    ringbuf.add(&events_map, move |data| {
        if let Some((header, payload)) = TlsEventHeader::from_bytes(data) {
            EVENTS_CAPTURED.fetch_add(1, Ordering::Relaxed);
            // Compute channel watermark for backpressure monitoring
            let current_len = channel_capacity.saturating_sub(sender.capacity() as u64);
            let watermark = (current_len * 100) / channel_capacity;
            CHANNEL_WATERMARK_PCT.store(watermark, Ordering::Relaxed);

            let events = state_handle.handle_event(&header, payload);
            for item in events {
                if sender.try_send(item).is_err() {
                    EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        0
    })?;

    let state_handle_close = state.clone();
    ringbuf.add(&close_events_map, move |data| {
        if data.len() < size_of::<CloseEvent>() {
            return 0;
        }
        let ev = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const CloseEvent) };
        let key = ConnKey { pid: ev.pid, ssl_ptr: ev.ssl_ptr, born_ms: 0 };
        state_handle_close.evict_connection(&key);
        0
    })?;

    // proc_events ring buffer (optional — map may not exist).
    // Only log new process info; do NOT call detect_go_binary here as it
    // reads entire binaries from disk and would block ring buffer processing.
    if let Some(ref proc_map) = proc_map_opt {
        let _ = ringbuf.add(proc_map, move |data| {
            if data.len() < size_of::<NewProcEvent>() {
                return 0;
            }
            let ev = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NewProcEvent) };
            let filename_end = ev.filename.iter().position(|&b| b == 0).unwrap_or(ev.filename.len());
            let filename = String::from_utf8_lossy(&ev.filename[..filename_end]);
            tracing::debug!(pid = ev.pid, file = %filename, "new process");
            0
        });
    }

    let ringbuf = ringbuf.build()?;
    tracing::info!("probes attached, polling ring buffer");

    // Graceful shutdown on SIGINT/SIGTERM
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        let sigint_res = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt());
        let sigterm_res = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let (Ok(mut sigint), Ok(mut sigterm)) = (sigint_res, sigterm_res) {
            tokio::select! {
                _ = sigint.recv() => tracing::info!("received SIGINT, shutting down"),
                _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down"),
            }
        } else {
            tracing::warn!("failed to register SIGINT/SIGTERM handlers; waiting for ctrl-c");
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("received ctrl-c, shutting down");
        }
        r.store(false, Ordering::Relaxed);
    });

    // Poll loop with exponential backoff on repeated errors
    let mut poll_backoff_ms = 0u64;
    while running.load(Ordering::Relaxed) {
        if poll_backoff_ms > 0 {
            tokio::time::sleep(Duration::from_millis(poll_backoff_ms)).await;
        }
        match ringbuf.poll(Duration::from_millis(200)) {
            Ok(()) => { poll_backoff_ms = 0; }
            Err(e) => {
                poll_backoff_ms = (poll_backoff_ms * 2 + 10).min(1000);
                tracing::warn!(error = %e, backoff_ms = poll_backoff_ms, "ring buffer poll error");
                RINGBUF_DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // Drop tx to signal batch task to flush remaining events, then await it
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), batch_handle).await;

    tracing::info!("shutdown complete");
    Ok(())
}

/// True if the BPF comm field belongs to a known TLS-terminating sidecar.
/// Callers should emit a tracing::warn so operators know outer TLS metadata is missing.
pub fn is_sidecar_comm(comm: &[u8; 16]) -> bool {
    let s = comm.iter().take_while(|&&b| b != 0).copied().collect::<Vec<_>>();
    let name = std::str::from_utf8(&s).unwrap_or("").trim_end_matches('\0');
    matches!(name, "envoy" | "pilot-agent" | "linkerd2-proxy" | "istio-proxy"
                 | "nginx" | "haproxy" | "traefik" | "caddy")
}

/// Returns (major, minor) from /proc/sys/kernel/osrelease (e.g. "6.8.0-110-generic" → (6, 8)).
fn kernel_version_maj_min() -> (u32, u32) {
    let s = match fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let mut parts = s.trim().split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    fn resolve_owner_pid_tgid(owner: Option<u64>, current: u64) -> u64 {
        owner.unwrap_or(current)
    }

    #[test]
    fn test_ssl_ptr_to_pid_resolution() {
        let owner   = Some(0x1234_0000_0001u64);
        let current = 0x9999_0000_0002u64;
        assert_eq!(resolve_owner_pid_tgid(owner, current), 0x1234_0000_0001);
        assert_eq!(resolve_owner_pid_tgid(None, current), current);
    }
}
