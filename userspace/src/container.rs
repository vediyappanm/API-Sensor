use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tower::service_fn;

use crate::types::{ContainerContext, TlsEventHeader};

mod cri {
    tonic::include_proto!("runtime.v1");
}

use cri::runtime_service_client::RuntimeServiceClient;
use cri::ContainerStatusRequest;

#[derive(Debug, Clone)]
pub struct CgroupInfo {
    #[allow(dead_code)]
    pub pod_uid: Option<String>,
    pub container_id_full: Option<String>,
    pub container_id_short: Option<String>,
}

#[derive(Debug, Clone)]
struct ContainerCacheEntry {
    context: ContainerContext,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct ContainerLookupRequest {
    pub cgroup_id: u64,
    pub container_id_full: String,
}

#[derive(Debug, Clone)]
pub struct ContainerMetadata {
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub container_name: Option<String>,
    pub service_name: Option<String>,
    pub workload_type: Option<String>,
}

const MAX_CACHE_ENTRIES: usize = 10_000;

pub struct ContainerResolver {
    cache: Mutex<HashMap<u64, ContainerCacheEntry>>,
    pending: Mutex<HashSet<u64>>,
    lookup_tx: mpsc::Sender<ContainerLookupRequest>,
    node_name: String,
    ttl: Duration,
}

impl ContainerResolver {
    pub fn new(lookup_tx: mpsc::Sender<ContainerLookupRequest>, node_name: String) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
            lookup_tx,
            node_name,
            ttl: Duration::from_secs(600),
        }
    }

    pub fn resolve(&self, ev: &TlsEventHeader) -> Option<ContainerContext> {
        if ev.cgroup_id == 0 {
            return None;
        }
        let now = Instant::now();

        // Cache lookup — recover from mutex poisoning
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(&ev.cgroup_id) {
            if now.duration_since(entry.last_seen) < self.ttl {
                entry.last_seen = now;
                return Some(entry.context.clone());
            }
        }

        // Evict stale entries if cache is too large
        if cache.len() > MAX_CACHE_ENTRIES {
            let ttl = self.ttl;
            cache.retain(|_, entry| now.duration_since(entry.last_seen) < ttl);
        }

        let cgroup_info = parse_cgroup_info(ev.pid as i32);
        let container_short = cgroup_info
            .as_ref()
            .and_then(|info| info.container_id_short.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let container_id_full = cgroup_info
            .as_ref()
            .and_then(|info| info.container_id_full.clone());

        let context = ContainerContext {
            pod_name: None,
            pod_namespace: None,
            container_id: container_short,
            container_name: None,
            node_name: self.node_name.clone(),
            service_name: None,
            workload_type: None,
        };

        cache.insert(
            ev.cgroup_id,
            ContainerCacheEntry {
                context: context.clone(),
                last_seen: now,
            },
        );
        drop(cache); // release lock before channel send

        if let Some(full_id) = container_id_full {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if !pending.contains(&ev.cgroup_id) {
                pending.insert(ev.cgroup_id);
                let _ = self.lookup_tx.try_send(ContainerLookupRequest {
                    cgroup_id: ev.cgroup_id,
                    container_id_full: full_id,
                });
            }
        }

        Some(context)
    }

    pub fn update_from_cri(&self, cgroup_id: u64, metadata: ContainerMetadata) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(&cgroup_id) {
            entry.context.pod_name = metadata.pod_name;
            entry.context.pod_namespace = metadata.pod_namespace;
            entry.context.container_name = metadata.container_name;
            entry.context.service_name = metadata.service_name;
            entry.context.workload_type = metadata.workload_type;
            entry.last_seen = Instant::now();
        }
        drop(cache);
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.remove(&cgroup_id);
    }

    /// Remove from pending set so a failed lookup can be retried.
    pub fn mark_lookup_failed(&self, cgroup_id: u64) {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.remove(&cgroup_id);
    }

    /// Check if a CRI lookup is still pending for this cgroup_id.
    pub fn is_pending(&self, cgroup_id: u64) -> bool {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.contains(&cgroup_id)
    }

    /// Re-read the cached context (which may have been updated by CRI worker).
    /// Returns the latest version of the container context.
    pub fn get_cached(&self, cgroup_id: u64) -> Option<ContainerContext> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.get(&cgroup_id).map(|e| e.context.clone())
    }
}

// ---------------------------------------------------------------------------
// Cgroup parsing
// ---------------------------------------------------------------------------

pub fn parse_cgroup_info(pid: i32) -> Option<CgroupInfo> {
    if pid <= 0 {
        return None;
    }
    let path = read_cgroup_path(pid)?;
    if let Some(info) = parse_cgroup_v1(&path) {
        return Some(info);
    }
    parse_cgroup_v2(&path)
}

fn read_cgroup_path(pid: i32) -> Option<String> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let contents = fs::read_to_string(cgroup_path).ok()?;
    for line in contents.lines() {
        if let Some(path) = line.split(':').nth(2) {
            if path.contains("kubepods") {
                return Some(path.to_string());
            }
        }
    }
    None
}

fn parse_cgroup_v1(path: &str) -> Option<CgroupInfo> {
    if !path.contains("/kubepods/") {
        return None;
    }
    let mut pod_uid = None;
    let mut container_id_full = None;
    for seg in path.split('/') {
        if seg.starts_with("pod") && seg.len() > 3 {
            pod_uid = Some(seg.trim_start_matches("pod").to_string());
        } else if seg.len() >= 32 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
            container_id_full = Some(seg.to_string());
        }
    }
    let container_id_short = container_id_full.as_ref().map(|id| short_id(id));
    Some(CgroupInfo { pod_uid, container_id_full, container_id_short })
}

fn parse_cgroup_v2(path: &str) -> Option<CgroupInfo> {
    if !path.contains("kubepods.slice") {
        return None;
    }
    let mut pod_uid = None;
    let mut container_id_full = None;
    for seg in path.split('/') {
        if seg.contains("pod") && seg.ends_with(".slice") {
            pod_uid = extract_pod_uid(seg);
        } else if seg.ends_with(".scope") {
            container_id_full = extract_container_id(seg);
        }
    }
    let container_id_short = container_id_full.as_ref().map(|id| short_id(id));
    Some(CgroupInfo { pod_uid, container_id_full, container_id_short })
}

fn extract_pod_uid(segment: &str) -> Option<String> {
    let pod_pos = segment.rfind("pod")?;
    let mut uid = String::new();
    for ch in segment[pod_pos + 3..].chars() {
        if ch.is_ascii_hexdigit() || ch == '-' {
            uid.push(ch);
        } else {
            break;
        }
    }
    if uid.is_empty() { None } else { Some(uid) }
}

fn extract_container_id(segment: &str) -> Option<String> {
    let mut s = segment.trim_end_matches(".scope").to_string();
    for prefix in ["cri-containerd-", "docker-", "crio-", "containerd-"] {
        if s.starts_with(prefix) {
            s = s.trim_start_matches(prefix).to_string();
            break;
        }
    }
    if s.len() < 12 { return None; }
    // Reject anything that isn't a valid hex container ID
    if !s.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
    Some(s)
}

fn short_id(full: &str) -> String {
    full.chars().take(12).collect()
}

// ---------------------------------------------------------------------------
// CRI metadata fetch
// ---------------------------------------------------------------------------

pub async fn fetch_container_metadata(
    socket_path: &str,
    container_id_full: &str,
) -> Result<ContainerMetadata> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fetch_container_metadata_inner(socket_path, container_id_full),
    )
    .await
    .map_err(|_| anyhow::anyhow!("CRI lookup timed out after 5s"))?
}

async fn fetch_container_metadata_inner(
    socket_path: &str,
    container_id_full: &str,
) -> Result<ContainerMetadata> {
    let path = socket_path.to_string();
    let endpoint = tonic::transport::Endpoint::try_from("http://[::]:0")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_uri| UnixStream::connect(path.clone())))
        .await?;

    let mut client = RuntimeServiceClient::new(channel);
    let req = ContainerStatusRequest {
        container_id: container_id_full.to_string(),
        verbose: true,
    };
    let resp: cri::ContainerStatusResponse =
        client.container_status(tonic::Request::new(req)).await?.into_inner();
    let status = resp.status
        .ok_or_else(|| anyhow::anyhow!("missing container status"))?;
    let labels = status.labels;

    Ok(ContainerMetadata {
        pod_name: labels.get("io.kubernetes.pod.name").cloned(),
        pod_namespace: labels.get("io.kubernetes.pod.namespace").cloned(),
        container_name: labels.get("io.kubernetes.container.name").cloned(),
        service_name: labels.get("app.kubernetes.io/name").cloned()
            .or_else(|| labels.get("app").cloned()),
        workload_type: labels.get("app.kubernetes.io/component").cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cgroup_v1() {
        let path = "/kubepods/burstable/pod123e4567-e89b-12d3-a456-426614174000/abcdef0123456789abcdef0123456789";
        let info = parse_cgroup_v1(path).expect("v1 parse");
        assert_eq!(info.pod_uid.unwrap(), "123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(info.container_id_short.unwrap(), "abcdef012345");
    }

    #[test]
    fn test_parse_cgroup_v2() {
        let path = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123e4567-e89b-12d3-a456-426614174000.slice/cri-containerd-abcdef0123456789abcdef0123456789.scope";
        let info = parse_cgroup_v2(path).expect("v2 parse");
        assert_eq!(info.pod_uid.unwrap(), "123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(info.container_id_short.unwrap(), "abcdef012345");
    }
}
