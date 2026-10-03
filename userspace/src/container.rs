use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use hyper_util::rt::TokioIo;
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
/// Cap on in-flight CRI lookups. A permanently-failing cgroup (e.g. container
/// already deleted) would otherwise grow `pending` without bound as new
/// events keep arriving for stale cgroup ids.
const MAX_PENDING_LOOKUPS: usize = 4_096;

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

        // Fast path: cache hit — lock held only for the lookup, no /proc I/O
        {
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
        } // cache lock dropped before /proc read

        // /proc/<pid>/cgroup read happens outside all locks — no mutex chain contention
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

        // Re-acquire to insert; concurrent miss for same cgroup_id is benign (idempotent insert)
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(
                ev.cgroup_id,
                ContainerCacheEntry {
                    context: context.clone(),
                    last_seen: now,
                },
            );
        }

        if let Some(full_id) = container_id_full {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            // Drop oldest pending lookups when at capacity. A bounded set
            // prevents permanently-failing cgroups (e.g. container exited
            // before our CRI lookup landed) from accumulating forever.
            if !pending.contains(&ev.cgroup_id) {
                if pending.len() >= MAX_PENDING_LOOKUPS {
                    if let Some(victim) = pending.iter().next().copied() {
                        pending.remove(&victim);
                    }
                }
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
}

// ---------------------------------------------------------------------------
// Cgroup parsing
// ---------------------------------------------------------------------------

pub fn parse_cgroup_info(pid: i32) -> Option<CgroupInfo> {
    if pid <= 0 {
        return None;
    }
    let contents = fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    parse_cgroup_text(&contents)
}

/// Parse the text of `/proc/<pid>/cgroup` (cgroup v1 lists one line per controller, v2 one line).
/// The first line whose path names a container wins.
pub fn parse_cgroup_text(contents: &str) -> Option<CgroupInfo> {
    contents
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .find_map(parse_cgroup_path)
}

/// Extract the container ID and pod UID from a cgroup path, whatever the layout.
///
/// The old parser accepted only `/kubepods/...` (v1) or a path containing the literal text
/// `kubepods.slice` (v2). Real clusters differ: kind nests everything under
/// `kubelet-kubepods-<qos>.slice`, paths may start with `../..` outside the container's cgroup
/// namespace, runtimes name the scope `cri-containerd-`, `crio-`, `docker-` or just the bare ID,
/// and systemd writes the pod UID with underscores. For every such container it returned nothing,
/// so the sensor could neither enrich events nor apply its namespace scope.
pub fn parse_cgroup_path(path: &str) -> Option<CgroupInfo> {
    let mut pod_uid = None;
    let mut container_id_full = None;
    for seg in path.split('/') {
        if seg.is_empty() || seg == ".." || seg == "." {
            continue;
        }
        if let Some(uid) = pod_uid_from_segment(seg) {
            pod_uid = Some(uid);
        }
        if let Some(id) = container_id_from_segment(seg) {
            container_id_full = Some(id);
        }
    }
    // No container ID means this is not a container's cgroup (a system service, a user session).
    let id = container_id_full?;
    Some(CgroupInfo { pod_uid, container_id_short: Some(short_id(&id)), container_id_full: Some(id) })
}

/// A container ID segment: optional runtime prefix, 32+ hex digits, optional `.scope`.
fn container_id_from_segment(segment: &str) -> Option<String> {
    let mut s = segment.strip_suffix(".scope").unwrap_or(segment);
    for prefix in ["cri-containerd-", "cri-o-", "crio-", "docker-", "libpod-", "containerd-"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    if s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(s.to_string())
    } else {
        None
    }
}

/// A pod segment: `pod<uid>` (cgroupfs) or `...-pod<uid with underscores>.slice` (systemd). Only a
/// UUID-shaped value counts, so `kubepods-burstable.slice` is never mistaken for a pod.
fn pod_uid_from_segment(segment: &str) -> Option<String> {
    let s = segment.strip_suffix(".slice").unwrap_or(segment);
    let start = if s.starts_with("pod") { Some(0) } else { s.rfind("-pod").map(|i| i + 1) }?;
    let uid = s[start + 3..].replace('_', "-");
    is_uuid(&uid).then_some(uid)
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts.iter().zip([8usize, 4, 4, 4, 12]).all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
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
        .connect_with_connector(service_fn(move |_uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
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

    const UID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn ids(path: &str) -> (Option<String>, Option<String>) {
        let i = parse_cgroup_path(path).expect("container cgroup");
        (i.pod_uid, i.container_id_full)
    }

    #[test]
    fn cgroup_v1_cgroupfs_layout() {
        let path = format!("/kubepods/burstable/pod{UID}/abcdef0123456789abcdef0123456789");
        let info = parse_cgroup_path(&path).unwrap();
        assert_eq!(info.pod_uid.unwrap(), UID);
        assert_eq!(info.container_id_short.unwrap(), "abcdef012345");
    }

    #[test]
    fn cgroup_v2_systemd_layout() {
        let path = format!("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{}.slice/cri-containerd-abcdef0123456789abcdef0123456789.scope", UID.replace('-', "_"));
        let info = parse_cgroup_path(&path).unwrap();
        assert_eq!(info.pod_uid.unwrap(), UID, "systemd writes the UID with underscores; the old code truncated it");
        assert_eq!(info.container_id_short.unwrap(), "abcdef012345");
    }

    #[test]
    fn guaranteed_pods_have_no_qos_slice() {
        let path = format!("/kubepods.slice/kubepods-pod{}.slice/crio-{}.scope", UID.replace('-', "_"), "ab".repeat(32));
        assert_eq!(ids(&path), (Some(UID.to_string()), Some("ab".repeat(32))));
    }

    #[test]
    fn the_layout_seen_on_the_real_kind_cluster() {
        // Verbatim from the production node: nested under kubelet-, relative to the sensor's cgroup
        // namespace root, UID with underscores. The old parser returned None for this.
        let id = "5dda869170205a9ac36dc25615ead3a914072192c76a8cdf53ebc21ae7b16f0e";
        for suffix in [".scope", ""] {
            let path = format!("/../../../kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podc5497c64_1dfa_4501_8a37_0ba1c309829c.slice/cri-containerd-{id}{suffix}");
            assert_eq!(
                ids(&path),
                (Some("c5497c64-1dfa-4501-8a37-0ba1c309829c".to_string()), Some(id.to_string())),
                "suffix {suffix:?}"
            );
        }
    }

    #[test]
    fn other_runtimes_and_standalone_docker() {
        let id = "cd".repeat(32);
        assert_eq!(ids(&format!("/system.slice/docker-{id}.scope")).1, Some(id.clone()));
        assert_eq!(ids(&format!("/machine.slice/libpod-{id}.scope")).1, Some(id.clone()), "podman");
        assert_eq!(ids(&format!("/kubepods.slice/kubepods-burstable.slice/cri-o-{id}.scope")).1, Some(id));
    }

    #[test]
    fn a_non_container_cgroup_is_not_a_container() {
        assert!(parse_cgroup_path("/system.slice/ssh.service").is_none());
        assert!(parse_cgroup_path("/user.slice/user-1000.slice/session-3.scope").is_none());
        assert!(parse_cgroup_path("/kubepods.slice/kubepods-burstable.slice").is_none());
        assert!(parse_cgroup_path("/").is_none());
        assert!(parse_cgroup_path("").is_none());
    }

    #[test]
    fn kubepods_slice_names_are_never_mistaken_for_a_pod() {
        let id = "ef".repeat(32);
        let info = parse_cgroup_path(&format!("/kubepods.slice/kubepods-besteffort.slice/cri-containerd-{id}.scope")).unwrap();
        assert!(info.pod_uid.is_none());
    }

    #[test]
    fn proc_cgroup_text_v1_hybrid_picks_the_line_that_names_a_container() {
        let id = "01".repeat(32);
        let text = format!("12:memory:/kubepods/pod{UID}/{id}\n1:name=systemd:/\n0::/\n");
        assert_eq!(parse_cgroup_text(&text).unwrap().container_id_full, Some(id));
        assert!(parse_cgroup_text("0::/user.slice/user-0.slice/session-1.scope\n").is_none());
    }
}
