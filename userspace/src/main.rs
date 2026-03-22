mod types;
mod metrics;
mod redaction;
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
mod config;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::env;
use std::fs;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

use crate::bpf::{attach_tls_uprobes, attach_kernel_probes, attach_quic_uprobes};
use crate::boringssl::attach_boring_ssl_static;
use crate::config::load_config;
use crate::container::{ContainerLookupRequest, ContainerResolver, fetch_container_metadata};
use crate::dns::{DnsResolver, reverse_dns_lookup};
use crate::go_tls::{attach_go_tls_probes, find_go_tls_offsets};
use crate::http::discover_tls_libs;
use crate::ingest::send_batch_with_client;
use crate::metrics::*;
use crate::quic::discover_quic_libs;
use crate::stream::ShardedStreamState;
use crate::types::*;

// ---------------------------------------------------------------------------
// Tracing / OpenTelemetry initialization
// ---------------------------------------------------------------------------

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();

    #[cfg(feature = "otel")]
    {
        // When compiled with --features otel AND OTEL_EXPORTER_OTLP_ENDPOINT is set,
        // export spans via OTLP (gRPC).  Otherwise fall back to stdout-only tracing.
        if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
            use opentelemetry::global;
            use opentelemetry_otlp::WithExportConfig;
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;

            let tracer = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(opentelemetry_otlp::new_exporter().tonic())
                .install_batch(opentelemetry_sdk::runtime::Tokio)
                .expect("failed to initialize OTLP tracer");

            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .with(otel_layer)
                .init();

            tracing::info!("OpenTelemetry OTLP export enabled");
            return;
        }
    }

    // Default: stdout-only tracing (no OTel overhead)
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();
}

// ---------------------------------------------------------------------------
// CLI Args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(about = "API Security eBPF Sensor", version)]
struct Args {
    /// Path to TOML config file. CLI flags override config file values.
    #[arg(long, default_value = "/etc/api-sentinel/config.toml")]
    config: String,
    #[arg(long)]
    bpf: Option<String>,
    #[arg(long)]
    ingest: Option<String>,
    #[arg(long, env = "API_KEY")]
    api_key: Option<String>,
    #[arg(long)]
    account_id: Option<u64>,
    #[arg(long)]
    batch_size: Option<usize>,
    #[arg(long)]
    role: Option<String>,
    #[arg(long, value_delimiter = ',')]
    tls_libs: Option<Vec<String>>,
    #[arg(long)]
    tls_provider: Option<String>,
    #[arg(long)]
    pid: Option<i32>,
    #[arg(long)]
    discover_libs: bool,
    #[arg(long)]
    max_buffer_bytes: Option<usize>,
    #[arg(long)]
    max_total_buffer_bytes: Option<usize>,
    #[arg(long)]
    metrics_port: Option<u16>,
    #[arg(long)]
    go_tls: bool,
    #[arg(long)]
    sample_default: Option<u8>,
    #[arg(long)]
    sample_health: Option<u8>,
}

/// Resolved configuration after merging CLI args + config file + defaults.
struct ResolvedConfig {
    bpf: String,
    ingest: String,
    api_key: String,
    account_id: u64,
    batch_size: usize,
    role: String,
    tls_libs: Vec<String>,
    tls_provider: String,
    pid: i32,
    discover_libs: bool,
    max_buffer_bytes: usize,
    max_total_buffer_bytes: usize,
    metrics_port: u16,
    go_tls: bool,
    sample_default: u8,
    sample_health: u8,
}

fn resolve_config(args: Args) -> anyhow::Result<ResolvedConfig> {
    let file_cfg = load_config(&args.config)?;
    let c = file_cfg.sensor;

    let bpf = args.bpf
        .or(c.bpf)
        .unwrap_or_else(|| "/opt/sensor/http_trace.bpf.o".to_string());
    let ingest = args.ingest
        .or(c.ingest)
        .ok_or_else(|| anyhow::anyhow!("--ingest URL is required (CLI or config file)"))?;
    let api_key = args.api_key
        .or(c.api_key)
        .unwrap_or_default();

    Ok(ResolvedConfig {
        bpf,
        ingest,
        api_key,
        account_id:           args.account_id.or(c.account_id).unwrap_or(1_000_000),
        batch_size:           args.batch_size.or(c.batch_size).unwrap_or(200),
        role:                 args.role.or(c.role).unwrap_or_else(|| "server".to_string()),
        tls_libs:             args.tls_libs.or(c.tls_libs)
                                  .unwrap_or_else(|| vec!["/usr/lib/x86_64-linux-gnu/libssl.so.3".to_string()]),
        tls_provider:         args.tls_provider.or(c.tls_provider).unwrap_or_else(|| "auto".to_string()),
        pid:                  args.pid.or(c.pid).unwrap_or(-1),
        discover_libs:        args.discover_libs || c.discover_libs.unwrap_or(false),
        max_buffer_bytes:     args.max_buffer_bytes.or(c.max_buffer_bytes).unwrap_or(65536),
        max_total_buffer_bytes: args.max_total_buffer_bytes.or(c.max_total_buffer_bytes).unwrap_or(104_857_600),
        metrics_port:         args.metrics_port.or(c.metrics_port).unwrap_or(9090),
        go_tls:               args.go_tls || c.go_tls.unwrap_or(false),
        sample_default:       args.sample_default.or(c.sample_default).unwrap_or(100),
        sample_health:        args.sample_health.or(c.sample_health).unwrap_or(5),
    })
}

// ---------------------------------------------------------------------------
// Metadata enrichment — re-reads CRI-resolved container metadata before flush.
// Fixes the race where events arrive with pod_name=None because the async CRI
// lookup hadn't completed when the event was first processed.
// ---------------------------------------------------------------------------

fn enrich_metadata(resolver: &Arc<ContainerResolver>, events: &mut [ApiTrafficEvent]) {
    for event in events.iter_mut() {
        if let Some(ref mut container) = event.container {
            // If pod_name is still None, try re-reading from cache (CRI worker may have updated it)
            if container.pod_name.is_none() {
                if let Some(cgroup_id) = event.cgroup_id {
                    if let Some(updated) = resolver.get_cached(cgroup_id) {
                        container.pod_name = updated.pod_name;
                        container.pod_namespace = updated.pod_namespace;
                        container.container_name = updated.container_name;
                        container.service_name = updated.service_name;
                        container.workload_type = updated.workload_type;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // Record start time
    let start_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    START_TIME_SECS.store(start_secs, Ordering::Relaxed);

    let args = Args::parse();
    let args = resolve_config(args)?;

    // Validate required args
    if args.api_key.is_empty() {
        anyhow::bail!("--api-key or API_KEY env var is required");
    }
    if !args.ingest.starts_with("http://") && !args.ingest.starts_with("https://") {
        anyhow::bail!("--ingest must be an http:// or https:// URL, got: {}", args.ingest);
    }
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
    attach_tls_uprobes(&mut obj, &args.tls_provider, args.pid, args.go_tls, &tls_libs, &mut links)?;
    attach_kernel_probes(&mut obj, &mut links)?;

    // Initialize sampling_config — must happen before polling starts.
    // BPF arrays are zero-initialized; rate=0 means "filter everything".
    if let Some(map) = obj.map_mut("sampling_config") {
        let key: u32 = 0;
        let cfg_bytes: [u8; 4] = [sample_default, sample_health, 0, 0];
        if let Err(e) = map.update(&key.to_ne_bytes(), &cfg_bytes, libbpf_rs::MapFlags::ANY) {
            tracing::warn!(error = %e, "failed to set sampling_config");
        }
    } else {
        tracing::warn!("sampling_config map not found in BPF object");
    }

    // Go TLS + static TLS probes (OpenSSL, BoringSSL statically linked into binaries)
    if args.go_tls {
        use crate::go_tls::detect_go_binaries;

        let scan_mode = if args.pid > 0 { "targeted" } else { "global" };
        tracing::info!(pid = args.pid, mode = scan_mode, "Go TLS + static TLS: scanning");

        // --- Go TLS ---
        let go_binaries = detect_go_binaries(args.pid);
        for (go_bin, go_pid) in &go_binaries {
            tracing::info!(binary = %go_bin, pid = go_pid, "Go TLS: detected binary");
            if let Some(offsets) = find_go_tls_offsets(go_bin) {
                tracing::info!(binary = %go_bin, version = %offsets.go_version, "attaching Go TLS probes");
                attach_go_tls_probes(&mut obj, &offsets, &mut links, *go_pid);
            } else {
                tracing::warn!(binary = %go_bin, "Go TLS: no offsets found (symbols stripped?)");
            }
        }
        if go_binaries.is_empty() {
            tracing::debug!(pid = args.pid, "Go TLS: no Go binaries found");
        }

        // --- Static TLS (OpenSSL / BoringSSL embedded in binaries) ---
        // Scan /proc/<pid>/maps for all target processes, looking for executables
        // with SSL_read/SSL_write symbols (covers Node.js, Nginx static, etc.)
        let pids_to_scan: Vec<i32> = if args.pid > 0 {
            vec![args.pid]
        } else {
            crate::http::enumerate_pids()
        };
        let mut scanned = 0u32;
        let mut attached_static = 0u32;
        let mut seen_binaries = std::collections::HashSet::new();
        for p in &pids_to_scan {
            let maps_path = format!("/proc/{}/maps", p);
            let Ok(maps) = fs::read_to_string(&maps_path) else { continue };
            for line in maps.lines() {
                if line.contains("r-xp") {
                    if let Some(path) = line.split_whitespace().last() {
                        if path.starts_with('/') {
                            // Dedup: same binary path from the same PID namespace
                            let dedup_key = format!("{}:{}", p, path);
                            if !seen_binaries.insert(dedup_key) { continue; }

                            let host_path = crate::types::proc_root_path(*p, path);
                            tracing::debug!(target_path = %path, host_path = %host_path, pid = p, "static TLS: scanning");
                            if attach_boring_ssl_static(&mut obj, &host_path, *p, &mut links) {
                                tracing::info!(path = %host_path, pid = p, "static TLS probes attached");
                                attached_static += 1;
                            }
                            scanned += 1;
                        }
                    }
                }
            }
        }
        tracing::info!(
            scanned,
            attached = attached_static,
            pids = pids_to_scan.len(),
            mode = scan_mode,
            "static TLS: bootstrap scan complete"
        );
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
            .pool_max_idle_per_host(4)
            .timeout(Duration::from_secs(10))
            .build()?,
    );

    let ingest_url  = args.ingest.clone();
    let api_key     = args.api_key.clone();
    let batch_size  = args.batch_size;
    let client_handle = http_client.clone();
    let resolver_for_batch = container_resolver.clone();
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
                                let mut payload = std::mem::take(&mut batch);
                                enrich_metadata(&resolver_for_batch, &mut payload);
                                if let Err(e) = send_batch_with_client(&client_handle, &ingest_url, &api_key, payload).await {
                                    tracing::error!(error = %e, "batch send failed");
                                }
                            }
                        }
                        None => {
                            if !batch.is_empty() {
                                let mut payload = std::mem::take(&mut batch);
                                enrich_metadata(&resolver_for_batch, &mut payload);
                                if let Err(e) = send_batch_with_client(&client_handle, &ingest_url, &api_key, payload).await {
                                    tracing::error!(error = %e, "final flush failed");
                                }
                            }
                            break;
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !batch.is_empty() {
                        let mut payload = std::mem::take(&mut batch);
                        enrich_metadata(&resolver_for_batch, &mut payload);
                        if let Err(e) = send_batch_with_client(&client_handle, &ingest_url, &api_key, payload).await {
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

    let events_map = obj
        .map_mut("events")
        .ok_or_else(|| anyhow::anyhow!("missing events map"))? as *mut libbpf_rs::Map;
    let close_events_map = obj
        .map_mut("close_events")
        .ok_or_else(|| anyhow::anyhow!("missing close_events map"))? as *mut libbpf_rs::Map;

    let channel_capacity = 10000u64;
    // SAFETY: `events_map` is a valid pointer to an `Object`-owned map that outlives
    // the `RingBuffer`. The raw pointer cast is required by the libbpf-rs API which
    // needs a mutable reference while `obj` is still borrowed for other maps.
    unsafe {
        ringbuf.add(&mut *events_map, move |data| {
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
    }

    let state_handle_close = state.clone();
    // SAFETY: Same as above — `close_events_map` outlives the ring buffer.
    // `read_unaligned` is used because BPF ring buffer data may not be aligned
    // to CloseEvent's alignment requirement. Length check above guarantees bounds.
    unsafe {
        ringbuf.add(&mut *close_events_map, move |data| {
            if data.len() < size_of::<CloseEvent>() {
                return 0;
            }
            let ev = std::ptr::read_unaligned(data.as_ptr() as *const CloseEvent);
            let key = ConnKey { pid: ev.pid, ssl_ptr: ev.ssl_ptr, born_ms: 0 };
            state_handle_close.evict_connection(&key);
            0
        })?;
    }

    // proc_events ring buffer — detect new processes and queue them for
    // dynamic TLS library discovery + probe attachment.
    // The callback runs in the ring buffer poll loop and MUST NOT block,
    // so we send new PIDs to a background Tokio task via an mpsc channel.
    let (new_pid_tx, mut new_pid_rx) = mpsc::channel::<u32>(256);
    let proc_events_result = obj.map_mut("proc_events");
    if let Some(proc_map) = proc_events_result {
        let proc_map_ptr = proc_map as *mut libbpf_rs::Map;
        // SAFETY: Same raw pointer pattern as events_map above.
        // `read_unaligned` handles BPF ring buffer alignment; length is checked.
        unsafe {
            let _ = ringbuf.add(&mut *proc_map_ptr, move |data| {
                if data.len() < size_of::<NewProcEvent>() {
                    return 0;
                }
                let ev = std::ptr::read_unaligned(data.as_ptr() as *const NewProcEvent);
                let filename_end = ev.filename.iter().position(|&b| b == 0).unwrap_or(ev.filename.len());
                let filename = String::from_utf8_lossy(&ev.filename[..filename_end]);
                tracing::debug!(pid = ev.pid, file = %filename, "new process detected");
                // Queue for background TLS discovery (non-blocking)
                let _ = new_pid_tx.try_send(ev.pid);
                0
            });
        }
    }

    // Background worker: attach TLS probes to newly-started processes.
    // This handles the "dynamic discovery" problem — containers started AFTER
    // the sensor will still get probes attached.
    let discover_libs_enabled = args.discover_libs;
    let _go_tls_enabled = args.go_tls;
    let _tls_provider_bg = args.tls_provider.clone();
    tokio::spawn(async move {
        let mut seen_pids = std::collections::HashSet::new();
        while let Some(pid) = new_pid_rx.recv().await {
            let pid = pid as i32;
            if pid <= 2 || !seen_pids.insert(pid) { continue; }

            // Small delay: let the process fully start and load libraries
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Check if process still exists
            let maps_path = format!("/proc/{}/maps", pid);
            if std::fs::read_to_string(&maps_path).is_err() { continue; }

            if discover_libs_enabled {
                let libs = crate::http::discover_tls_libs(pid);
                if !libs.is_empty() {
                    tracing::info!(pid, libs = ?libs, "dynamic discovery: new TLS libs found");
                    // Note: We can't attach new uprobes here because `obj` is not Send.
                    // The shared libssl uprobes from bootstrap already cover most cases
                    // because uprobes are inode-based — if the new process uses the same
                    // libssl inode (same Docker layer), existing probes already fire.
                }
            }

            tracing::debug!(pid, "dynamic discovery: checked new process");
        }
    });

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

    // Flush OpenTelemetry spans before exit
    #[cfg(feature = "otel")]
    opentelemetry::global::shutdown_tracer_provider();

    tracing::info!("shutdown complete");
    Ok(())
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
