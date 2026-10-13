mod types;
mod metrics;
mod redaction;
mod identity;
mod output;
mod export;
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
use libbpf_rs::{MapCore, RingBufferBuilder};
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
                  attach_nss_uprobes, attach_ktls_kprobes, attach_lsm_hooks,
                  kernel_has_bpf_lsm, kernel_has_ktls, load_attempts, open_and_load, LoadFeatures};
use crate::boringssl::{attach_boring_ssl_static, attach_mbedtls_static, attach_wolfssl_static};
use crate::container::{ContainerLookupRequest, ContainerResolver, fetch_container_metadata};
use crate::dns::{DnsResolver, reverse_dns_lookup};
use crate::go_tls::{attach_go_tls_probes, detect_go_binary, discover_go_binaries, find_go_tls_offsets};
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
    /// Traffic direction mode: `auto` (per-connection, default), `server`, or `client` (diagnostic overrides).
    #[arg(long, default_value = "auto")]
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
    /// Capture only workloads in these Kubernetes namespaces (comma-separated). Everything else on
    /// the node, including host processes, is skipped before it is buffered. Without it the sensor
    /// reads the decrypted traffic of EVERY process it can attach to.
    #[arg(long, env = "ONLY_NAMESPACES", value_delimiter = ',')]
    only_namespaces: Vec<String>,
    /// Load the BPF LSM connect-blocking hook. Enforcement is separate from observation and off by default.
    #[arg(long, env = "ENABLE_LSM", default_value_t = false)]
    enable_lsm: bool,
    /// Reverse-resolve peer IPs to hostnames. Lookups are bounded in concurrency either way.
    #[arg(long, env = "REVERSE_DNS", default_value_t = true, action = clap::ArgAction::Set)]
    reverse_dns: bool,
    /// How long shutdown may spend draining the export queue. Keep below the pod's termination grace period.
    #[arg(long, default_value = "20")]
    shutdown_timeout_secs: u64,
    /// Attach QUIC library probes and decode HTTP/3. Experimental: static-table QPACK only,
    /// connection-FIFO pairing, no provider-specific adapters. Off unless explicitly requested.
    #[arg(long, env = "EXPERIMENTAL_HTTP3", default_value_t = false)]
    experimental_http3: bool,
    /// Run every startup check (credentials, ingest URL, capture scope, PII key, role) and exit
    /// without loading BPF. Exit status 0 means the sensor would start with this configuration.
    #[arg(long, default_value_t = false)]
    check_config: bool,
    /// Byte budget of events waiting for export; events beyond it are dropped and counted.
    #[arg(long, env = "MAX_QUEUE_BYTES", default_value = "67108864")]
    max_queue_bytes: usize,
    /// A batch never holds more than --batch-size events or this many bytes. A single event
    /// larger than this is dropped and counted in apisec_export_oversized_drops_total.
    #[arg(long, env = "MAX_BATCH_BYTES", default_value = "4194304")]
    max_batch_bytes: usize,
}

const MIN_EXPORT_BUDGET_BYTES: usize = 64 * 1024;

/// An opt-in variable counts only when set to an explicit yes; `APISEC_ALLOW_HTTP=false`
/// must not allow plaintext. Anything other than a recognised yes/no is a configuration error.
fn env_opt_in(name: &str) -> Result<bool> {
    match std::env::var(name) {
        Err(_) => Ok(false),
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "" | "0" | "false" | "no" | "off" => Ok(false),
            other => anyhow::bail!("{name} must be true or false, got '{other}'"),
        },
    }
}

/// Periodic library rescan; exec notifications trigger an earlier one.
const LIB_RESCAN_INTERVAL: Duration = Duration::from_secs(30);
/// Reverse DNS lookups running at once. A permit is held until the blocking lookup returns,
/// so a slow resolver cannot pile up threads behind an expired timeout.
const DNS_MAX_INFLIGHT: usize = 8;
/// Event-count cap of the export queue; `--max-queue-bytes` bounds its memory.
const EXPORT_QUEUE_EVENTS: usize = 10_000;

// ---------------------------------------------------------------------------
// Aggregate BPF producer stats (F02, F09)
// ---------------------------------------------------------------------------

/// Aggregate per-CPU producer_stats counters into global metrics.
/// Map indices: 0=attempted, 1=submitted, 2=reserve_fail, 3=copy_fail, 4=sampled, 5=map_fail
///
/// Uses lookup_percpu() to read all CPU values and sum them correctly.
fn aggregate_producer_stats(map: &libbpf_rs::Map) {
    let mut totals = [0u64; 6];
    let mut any_error = false;

    // Read each key (0-5) from the PERCPU_ARRAY
    // lookup_percpu returns Vec<Vec<u8>> - one value per CPU
    for key in 0u32..6u32 {
        let key_bytes = key.to_ne_bytes();
        match map.lookup_percpu(&key_bytes, libbpf_rs::MapFlags::ANY) {
            Ok(Some(per_cpu_values)) => {
                // Sum all CPU values for this key
                let mut sum = 0u64;
                for cpu_value in per_cpu_values {
                    if cpu_value.len() >= 8 {
                        let val = u64::from_ne_bytes([
                            cpu_value[0], cpu_value[1], cpu_value[2], cpu_value[3],
                            cpu_value[4], cpu_value[5], cpu_value[6], cpu_value[7]
                        ]);
                        sum = sum.saturating_add(val);
                    }
                }
                totals[key as usize] = sum;
            }
            Ok(None) => {
                // Key not found - treat as zero
                totals[key as usize] = 0;
            }
            Err(e) => {
                tracing::warn!(key, error = %e, "BPF producer_stats lookup_percpu failed");
                any_error = true;
                totals[key as usize] = 0;
            }
        }
    }

    // Report if any lookup errors occurred
    if any_error {
        metrics::BPF_MAP_FAIL.fetch_add(1, Ordering::Relaxed);
    }

    // Update global metrics if we have any data
    if totals[0] > 0 || totals[1] > 0 || totals[2] > 0 || totals[3] > 0 || totals[4] > 0 {
        metrics::BPF_ATTEMPTED.store(totals[0], Ordering::Relaxed);
        metrics::BPF_SUBMITTED.store(totals[1], Ordering::Relaxed);
        metrics::BPF_RESERVE_FAIL.store(totals[2], Ordering::Relaxed);
        metrics::BPF_COPY_FAIL.store(totals[3], Ordering::Relaxed);
        metrics::BPF_SAMPLED.store(totals[4], Ordering::Relaxed);
    }
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
    // F21: Enforce HTTPS in production, warn about HTTP
    // For test environments, allow HTTP with explicit opt-in via env var
    if args.ingest.starts_with("http://") {
        if !env_opt_in("APISEC_ALLOW_HTTP")? {
            anyhow::bail!(
                "HTTP ingest URL is not allowed without APISEC_ALLOW_HTTP=true. \
                 Credentials would be sent in plaintext. Use HTTPS in production."
            );
        }
        tracing::warn!(
            ingest = %args.ingest,
            "HTTP ingest URL allowed only because APISEC_ALLOW_HTTP=true. \
             Credentials are sent in plaintext. Do not use in production."
        );
    }
    let scope: Vec<String> = args.only_namespaces.iter().map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).collect();
    if scope.is_empty() {
        if !env_opt_in("APISEC_ALLOW_CAPTURE_ALL")? {
            anyhow::bail!(
                "No --only-namespaces set. The sensor would capture the decrypted traffic of \
                 EVERY workload on this host. Set APISEC_ALLOW_CAPTURE_ALL=true to explicitly \
                 allow this (dedicated nodes only), or set --only-namespaces to limit capture."
            );
        }
        tracing::warn!(
            "No --only-namespaces set: capturing the decrypted traffic of EVERY workload on this host. \
             This is allowed only because APISEC_ALLOW_CAPTURE_ALL=true."
        );
    }
    // Refuse to start without an explicit PII hash key. A guessable / hardcoded
    // key would let any reader of the binary or environment de-tokenize all
    // redacted PII downstream — that defeats the entire redaction guarantee.
    redaction::init_pii_hash_key()
        .map_err(|e| anyhow::anyhow!("PII redaction init failed: {e}"))?;
    let role = match args.role.as_str() {
        "auto" => TrafficRole::Auto,
        "server" => TrafficRole::Server,
        "client" => TrafficRole::Client,
        other => anyhow::bail!("invalid --role '{}': must be 'auto', 'server', or 'client'", other),
    };
    let sample_default = args.sample_default.min(100);
    let sample_health = args.sample_health.min(100);
    // Events larger than the batch budget are dropped, so a tiny budget would drop everything.
    for (name, value) in [("--max-queue-bytes", args.max_queue_bytes), ("--max-batch-bytes", args.max_batch_bytes)] {
        if value < MIN_EXPORT_BUDGET_BYTES {
            anyhow::bail!("{name} must be at least {MIN_EXPORT_BUDGET_BYTES} bytes, got {value}");
        }
    }
    if args.check_config {
        println!("configuration valid");
        return Ok(());
    }

    tracing::info!(bpf = %args.bpf, ingest = %args.ingest, "starting sensor");

    // Start metrics server
    tokio::spawn(start_metrics_server(args.metrics_port));

    let obj_data = fs::read(&args.bpf)?;
    let (maj, min) = kernel_version_maj_min();
    let want = LoadFeatures {
        dynptr: maj > 5 || (maj == 5 && min >= 19),
        lsm: args.enable_lsm && kernel_has_bpf_lsm(),
        ktls: kernel_has_ktls(),
    };
    if args.enable_lsm && !want.lsm {
        tracing::warn!("--enable-lsm set but BPF LSM is not active on this kernel; enforcement disabled");
    }
    let mut loaded = None;
    let mut last_err = None;
    for f in load_attempts(want) {
        match open_and_load(&obj_data, f) {
            Ok(o) => {
                loaded = Some((o, f));
                break;
            }
            Err(e) => {
                tracing::warn!(features = ?f, error = %e, "BPF load failed; retrying without optional features");
                last_err = Some(e);
            }
        }
    }
    let Some((mut obj, active)) = loaded else {
        return Err(last_err.unwrap_or_else(|| anyhow::anyhow!("BPF load failed")));
    };
    tracing::info!(kernel_major = maj, kernel_minor = min, dynptr = active.dynptr, lsm = active.lsm, ktls = active.ktls, "BPF object loaded");

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
    attach_tls_uprobes(&obj, &args.tls_provider, args.pid, args.go_tls, &tls_libs, &mut links)?;
    let mut attached_libs = bpf::AttachedLibs::default();
    attached_libs.take_new(&tls_libs);
    if !nss_libs.is_empty() {
        attach_nss_uprobes(&mut obj, args.pid, &nss_libs, &mut links);
    }
    attach_kernel_probes(&mut obj, &mut links)?;
    if active.ktls {
        attach_ktls_kprobes(&mut obj, &mut links);
    }
    if active.lsm {
        attach_lsm_hooks(&mut obj, &mut links);
    }

    // Initialize sampling_config — must happen before polling starts.
    // BPF arrays are zero-initialized; rate=0 means "filter everything". The kernel always
    // captures 100% of scoped bytes: per-chunk sampling corrupts pairing and HPACK state (F07).
    // `--sample-*` rates are applied to completed transactions in userspace instead.
    if let Some(map) = obj.maps().find(|m| m.name() == OsStr::new("sampling_config")) {
        let key: u32 = 0;
        let cfg_bytes: [u8; 4] = [100, 100, 0, 0];
        if let Err(e) = map.update(&key.to_ne_bytes(), &cfg_bytes, libbpf_rs::MapFlags::ANY) {
            tracing::warn!(error = %e, "failed to set sampling_config");
        }
    } else {
        tracing::warn!("sampling_config map not found in BPF object");
    }

    // Go TLS probes
    if args.go_tls {
        tracing::info!(pid = args.pid, "Go TLS: scanning");
        let go_bins = if args.pid > 0 {
            detect_go_binary(args.pid).into_iter().collect::<Vec<_>>()
        } else {
            // DaemonSet runs with pid -1. Scanning one pid found nothing and
            // left every Go process on the node unprobed.
            discover_go_binaries(8)
        };
        if go_bins.is_empty() {
            tracing::warn!(pid = args.pid, "Go TLS: no Go binary found");
        }
        for go_bin in &go_bins {
            tracing::info!(binary = %go_bin, "Go TLS: detected binary");
            if let Some(offsets) = find_go_tls_offsets(go_bin) {
                tracing::info!(binary = %go_bin, version = %offsets.go_version, "attaching Go TLS probes");
                match attach_go_tls_probes(&mut obj, &offsets, &mut links, args.pid) {
                    Ok(n) => tracing::info!(binary = %go_bin, probes = n, "Go TLS probes attached"),
                    Err(e) => {
                        PROBE_ATTACH_FAILURES.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(binary = %go_bin, error = %e, "Go TLS attach failed; binary not captured");
                    }
                }
            } else {
                tracing::warn!(binary = %go_bin, "Go TLS: no offsets found");
            }
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
    let reverse_dns = args.reverse_dns;
    tokio::spawn(async move {
        let permits = Arc::new(tokio::sync::Semaphore::new(DNS_MAX_INFLIGHT));
        while let Some(ip) = dns_rx.recv().await {
            if !reverse_dns {
                dns_handle.insert(ip, None);
                continue;
            }
            let Ok(permit) = permits.clone().acquire_owned().await else { break };
            let handle = dns_handle.clone();
            tokio::spawn(async move {
                let lookup = tokio::task::spawn_blocking(move || {
                    let r = reverse_dns_lookup(ip);
                    drop(permit);
                    r
                });
                match tokio::time::timeout(Duration::from_secs(2), lookup).await {
                    Ok(Ok(hostname)) => handle.insert(ip, hostname),
                    _ => handle.insert(ip, None),
                }
            });
        }
    });

    // Discover and attach QUIC library probes (opt-in, F18)
    if args.experimental_http3 && (args.discover_libs || args.go_tls) {
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

    let (tx, mut rx) = export::export_channel(EXPORT_QUEUE_EVENTS, args.max_queue_bytes);

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
    let mut batch       = export::Batch::new(args.batch_size, args.max_batch_bytes);
    let client_handle   = http_client.clone();
    let batch_handle = tokio::spawn(async move {
        let mut flush_interval = time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    match ev {
                        Some((event, size)) => {
                            for payload in batch.push(event, size) {
                                if let Err(e) = send_batch_with_client(&client_handle, &ingest_url, &api_key, &tenant_id, &policy_version, payload).await {
                                    tracing::error!(error = %e, "batch send failed");
                                }
                            }
                        }
                        None => {
                            // Channel closed — flush remaining events before exit
                            if !batch.is_empty() {
                                let payload = batch.take();
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
                        let payload = batch.take();
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
    )
    .with_sampler(stream::TransactionSampler { default_rate: sample_default, health_rate: sample_health }));

    if !scope.is_empty() {
        state.set_namespace_scope(&scope);
        tracing::info!(namespaces = ?scope, "capture restricted to these namespaces");
    }

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

    let channel_capacity = sender.max_events() as u64;
    ringbuf.add(&events_map, move |data| {
        if let Some((header, payload)) = TlsEventHeader::from_bytes(data) {
            if header.abi_version != TLS_EVENT_ABI_VERSION {
                ABI_MISMATCH.fetch_add(1, Ordering::Relaxed);
                return 0;
            }
            EVENTS_CAPTURED.fetch_add(1, Ordering::Relaxed);
            // Compute channel watermark for backpressure monitoring
            let current_len = sender.queued_events() as u64;
            let watermark = (current_len * 100) / channel_capacity;
            CHANNEL_WATERMARK_PCT.store(watermark, Ordering::Relaxed);

            for item in state_handle.handle_event(&header, payload) {
                sender.try_send(item);
            }
        }
        0
    })?;

    let state_handle_close = state.clone();
    let close_sender = tx.clone();
    ringbuf.add(&close_events_map, move |data| {
        if data.len() < size_of::<CloseEvent>() {
            return 0;
        }
        let ev = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const CloseEvent) };
        let key = ConnKey::from_close(&ev);
        for item in state_handle_close.evict_connection(&key) {
            close_sender.try_send(item);
        }
        0
    })?;

    // Library rediscovery (F11) runs off the capture path; the poll loop only attaches new files.
    let (exec_tx, mut exec_rx) = mpsc::channel::<()>(1);
    let (libs_tx, mut libs_rx) = mpsc::channel::<Vec<String>>(2);
    if args.discover_libs && args.pid <= 0 {
        tokio::spawn(async move {
            let mut tick = time::interval(LIB_RESCAN_INTERVAL);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    Some(()) = exec_rx.recv() => {
                        // Give the new process time to map (or dlopen) its TLS library.
                        time::sleep(Duration::from_secs(2)).await;
                    }
                }
                let Ok(libs) = tokio::task::spawn_blocking(|| discover_tls_libs(-1)).await else { continue };
                if libs_tx.send(libs).await.is_err() {
                    break;
                }
            }
        });
    }

    // proc_events ring buffer (optional — map may not exist).
    // Only signal the rescan task; do NOT scan here, /proc and ELF reads would block capture.
    if let Some(ref proc_map) = proc_map_opt {
        let _ = ringbuf.add(proc_map, move |data| {
            let _ = exec_tx.try_send(());
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
    let mut last_aggregate = std::time::Instant::now();
    let aggregate_interval = Duration::from_secs(5);

    // F02, F09: Aggregate BPF producer stats periodically
    let producer_stats_map = obj.maps()
        .find(|m| m.name() == OsStr::new("producer_stats"));

    while running.load(Ordering::Relaxed) {
        if poll_backoff_ms > 0 {
            tokio::time::sleep(Duration::from_millis(poll_backoff_ms)).await;
        }
        match ringbuf.poll(Duration::from_millis(200)) {
            Ok(()) => {
                poll_backoff_ms = 0;
                metrics::touch_poll_heartbeat();

                while let Ok(libs) = libs_rx.try_recv() {
                    let fresh = attached_libs.take_new(&libs);
                    if !fresh.is_empty() {
                        let usable = bpf::attach_tls_libs(&obj, &args.tls_provider, args.pid, &fresh, &mut links);
                        tracing::info!(new_libs = ?fresh, usable, "rediscovery attached TLS probes");
                    }
                }

                // Aggregate BPF producer stats every 5 seconds
                if last_aggregate.elapsed() >= aggregate_interval {
                    if let Some(ref map) = producer_stats_map {
                        aggregate_producer_stats(map);
                    }
                    // Expire unanswered requests even when no traffic arrives to drive it.
                    for item in state.sweep() {
                        tx.try_send(item);
                    }
                    last_aggregate = std::time::Instant::now();
                }
            }
            Err(e) => {
                poll_backoff_ms = (poll_backoff_ms * 2 + 10).min(1000);
                tracing::warn!(error = %e, backoff_ms = poll_backoff_ms, "ring buffer poll error");
                RINGBUF_DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // Ordered shutdown (F16): stop producers, drain what the kernel already accepted, release the
    // callbacks' senders so the export channel can close, then drain export under a deadline.
    drop(links);
    if let Err(e) = ringbuf.consume() {
        tracing::warn!(error = %e, "final ring buffer drain failed");
    }
    drop(ringbuf);
    for item in state.drain_incomplete("sensor_shutdown") {
        tx.try_send(item);
    }
    let queued_at_close = tx.queued_events();
    let queued_bytes_at_close = tx.queued_bytes();
    drop(tx);
    let deadline = Duration::from_secs(args.shutdown_timeout_secs);
    match tokio::time::timeout(deadline, batch_handle).await {
        Ok(_) => tracing::info!(queued_at_close, queued_bytes_at_close, "export queue drained"),
        Err(_) => tracing::warn!(
            queued_at_close,
            queued_bytes_at_close,
            deadline_secs = args.shutdown_timeout_secs,
            "export drain deadline reached; events still queued or retrying were not delivered"
        ),
    }

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
