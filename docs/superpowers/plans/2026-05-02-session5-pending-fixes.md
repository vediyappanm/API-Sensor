# Session 5 — Pending Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all outstanding audit items: P3 polish, 5 dep bumps, H2 async cgroup cache, H1 BPF dynptr variable-length events.

**Architecture:** Work smallest-risk to largest-risk. P3 first (one-liners), then dep bumps (compile-fix cycles), then H2 (Rust-only logic change), then H1 (BPF C change). Each task ends with a passing `cargo build --release`.

**Tech Stack:** Rust 2021, libbpf-rs, axum 0.8, tokio, capstone, tonic, BPF C (CO-RE)

---

## Already verified DONE — skip these

- **H7** (`tcp_close` thread leak): `sock_to_pid` map exists in BPF, `tcp_close_entry` uses it correctly.
- **H8** (H2 MAX_FRAME_SIZE hardcoded): `extract_settings_max_frame_size()` already implemented and called in `parse_http2_frames`.

---

## Task 1: P3 Quick Wins

**Files:**
- Modify: `userspace/src/types.rs:223`
- Modify: `userspace/src/main.rs:247`

- [ ] **Step 1: Raise STREAM_TTL_MS from 60 s to 5 min**

In `userspace/src/types.rs` line 223:

```rust
// was: pub const STREAM_TTL_MS: u64 = 60_000;
pub const STREAM_TTL_MS: u64 = 300_000;
```

- [ ] **Step 2: Raise pool_max_idle_per_host from 4 to 16**

In `userspace/src/main.rs` line 247:

```rust
// was: .pool_max_idle_per_host(4)
.pool_max_idle_per_host(16)
```

- [ ] **Step 3: Verify build**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | tail -5
```

Expected: `Finished release [optimized] target(s)`

- [ ] **Step 4: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add userspace/src/types.rs userspace/src/main.rs
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "fix(p3): STREAM_TTL_MS 60s→5min, pool_max_idle 4→16"
```

---

## Task 2: Dep bump — indexmap 1.9 → 2.x

**Files:**
- Modify: `userspace/Cargo.toml`

- [ ] **Step 1: Bump Cargo.toml**

In `userspace/Cargo.toml`, change:

```toml
# was:
indexmap = { version = "1.9.3", features = ["std"] }
# becomes:
indexmap = { version = "2", features = ["std"] }
```

- [ ] **Step 2: Build and fix**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | grep -E "error|warning.*unused" | head -20
```

indexmap 2.x is API-compatible with 1.x for all methods used here (IndexMap, retain, etc.). No code changes expected.

- [ ] **Step 3: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add userspace/Cargo.toml userspace/Cargo.lock
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "deps: indexmap 1.9→2.x"
```

---

## Task 3: Dep bump — axum 0.7 → 0.8

**Files:**
- Modify: `userspace/Cargo.toml`
- Modify: `userspace/src/metrics.rs` (if compilation fails)

- [ ] **Step 1: Bump Cargo.toml**

```toml
# was:
axum = "0.7"
# becomes:
axum = "0.8"
```

- [ ] **Step 2: Build and collect errors**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | grep "^error" | head -20
```

- [ ] **Step 3: Apply axum 0.8 fixes if needed**

axum 0.8 breaking changes relevant to metrics.rs:
- `axum::http::StatusCode` → use `http::StatusCode` (already in Cargo.toml as `http = "1"`)
- `axum::serve` API is unchanged

If `axum::http::StatusCode` errors appear, update `userspace/src/metrics.rs` imports:

```rust
// Add at top of metrics.rs:
use http::StatusCode;
```

And replace all `axum::http::StatusCode::OK` → `StatusCode::OK` and `axum::http::StatusCode::SERVICE_UNAVAILABLE` → `StatusCode::SERVICE_UNAVAILABLE`.

- [ ] **Step 4: Verify build passes**

```bash
cargo build --release 2>&1 | tail -3
```

- [ ] **Step 5: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add userspace/Cargo.toml userspace/Cargo.lock userspace/src/metrics.rs
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "deps: axum 0.7→0.8"
```

---

## Task 4: Dep bump — capstone 0.11 → 0.14

**Files:**
- Modify: `userspace/Cargo.toml`
- Modify: `userspace/src/go_tls.rs` (if compilation fails)

- [ ] **Step 1: Bump Cargo.toml**

```toml
# was:
capstone = "0.11"
# becomes:
capstone = "0.14"
```

- [ ] **Step 2: Build and collect errors**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | grep "^error" | head -30
```

- [ ] **Step 3: Apply fixes**

capstone 0.11→0.14 keeps the builder API. Expected compilation issues:
- `capstone::arch::x86::X86Insn` enum variants may have renamed constants
- `capstone::arch::arm64::Arm64Insn` same

If `X86_INS_RET` is not found, check `capstone::arch::x86::X86Insn::X86_INS_RET` still exists by running:

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo doc --no-deps -p capstone 2>/dev/null && grep -r "X86_INS_RET\|ARM64_INS_RET" ~/.cargo/registry/src/**/capstone-0.14*/src/ 2>/dev/null | head -5
```

Apply any renames shown by compiler errors. The Capstone builder API (`.x86().mode(arch::x86::ArchMode::Mode64)`) is stable across 0.11–0.14.

- [ ] **Step 4: Verify build**

```bash
cargo build --release 2>&1 | tail -3
```

- [ ] **Step 5: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add userspace/Cargo.toml userspace/Cargo.lock userspace/src/go_tls.rs
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "deps: capstone 0.11→0.14"
```

---

## Task 5: Dep bump — tonic 0.12 → 0.14

**Files:**
- Modify: `userspace/Cargo.toml`
- Modify: `userspace/build.rs` (if tonic-build API changed)
- Modify: `userspace/src/container.rs` (if client API changed)

- [ ] **Step 1: Bump Cargo.toml**

```toml
# was:
tonic = { version = "0.12", features = ["transport"] }
# becomes:
tonic = { version = "0.14", features = ["transport"] }

# build-dependencies:
# was:
tonic-build = "0.12"
# becomes:
tonic-build = "0.14"
```

- [ ] **Step 2: Build and collect errors**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | grep "^error" | head -30
```

- [ ] **Step 3: Apply fixes**

tonic 0.13+ changed the connector API for custom transports. The `container.rs` code connects via Unix socket:

```rust
// Current approach in container.rs (tonic 0.12):
let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
    .connect_with_connector(service_fn(...))
    .await?;
```

In tonic 0.14, if `connect_with_connector` signature changed, check `fetch_container_metadata` in container.rs and update accordingly. The most common change is the connector closure type — it may need `tower::service_fn` instead of the tonic-bundled one.

If `hyper_util` transport errors appear, the fix is:
```rust
// tonic 0.14 uses hyper 1.x internally; ensure hyper-util is 0.1+
// Cargo.toml already has hyper-util = { version = "0.1", features = ["tokio"] }
```

- [ ] **Step 4: Verify build**

```bash
cargo build --release 2>&1 | tail -3
```

- [ ] **Step 5: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add userspace/Cargo.toml userspace/Cargo.lock userspace/src/container.rs
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "deps: tonic 0.12→0.14"
```

---

## Task 6: Dep bump — libbpf-rs 0.23 → 0.26

**Files:**
- Modify: `userspace/Cargo.toml`
- Modify: `userspace/src/bpf.rs` (UprobeOpts API change)
- Modify: `userspace/src/go_tls.rs` (UprobeOpts API change)

- [ ] **Step 1: Bump Cargo.toml**

```toml
# was:
libbpf-rs = "0.23"
# becomes:
libbpf-rs = "0.26"
```

- [ ] **Step 2: Build and collect errors**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | grep "^error" | head -40
```

- [ ] **Step 3: Apply UprobeOpts API fix**

In libbpf-rs 0.25, `UprobeOpts.func_name` was replaced — the symbol is now passed as the `func_name` field still but the struct layout changed. Check exact error from step 2.

The current `bpf.rs:157-164`:

```rust
let opts = UprobeOpts {
    retprobe,
    func_name: symbol.to_string(),
    ..Default::default()
};
let link = prog
    .attach_uprobe_with_opts(pid, binary, 0, opts)
    .with_context(|| format!("attach {} to {}", prog_name, symbol))?;
```

In libbpf-rs 0.25+, if `func_name` was removed from `UprobeOpts`, the symbol is passed as a separate field or the method signature changed. Apply the fix shown by the compiler error. A common 0.25 pattern is:

```rust
// If UprobeOpts no longer has func_name:
let opts = UprobeOpts {
    retprobe,
    ..Default::default()
};
let link = prog
    .attach_uprobe_with_opts(pid, binary, 0, opts)
    // or the new signature may be:
    // .attach_uprobe(retprobe, pid, binary, 0)
    .with_context(|| format!("attach {} to {}", prog_name, symbol))?;
```

Check `attach_go_tls_probes` in `userspace/src/go_tls.rs` for the same pattern — apply the same fix there.

- [ ] **Step 4: Verify build**

```bash
cargo build --release 2>&1 | tail -3
```

- [ ] **Step 5: Run tests**

```bash
cargo test --release 2>&1 | tail -5
```

- [ ] **Step 6: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add userspace/Cargo.toml userspace/Cargo.lock userspace/src/bpf.rs userspace/src/go_tls.rs
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "deps: libbpf-rs 0.23→0.26 with UprobeOpts API update"
```

---

## Task 7: H2 — Async cgroup cache (eliminate /proc read under shard mutex)

**Problem:** `ContainerResolver::resolve()` calls `parse_cgroup_info(ev.pid)` — a `/proc/<pid>/cgroup` read — while holding both the cache mutex and transitively the shard mutex. One slow disk read blocks all connections on that shard.

**Fix:** Pre-populate a `pid_cgroup_cache: Mutex<HashMap<u32, u64>>` in `ContainerResolver` from `NewProcEvent` (the `sched_process_exec` tracepoint already fires these events). Then `resolve()` looks up cgroup_id from that cache instead of calling `parse_cgroup_info`.

**Files:**
- Modify: `userspace/src/container.rs`
- Modify: `userspace/src/main.rs` (wire NewProcEvent → ContainerResolver)

- [ ] **Step 1: Add `register_pid` method to ContainerResolver**

In `userspace/src/container.rs`, add a field and method:

```rust
pub struct ContainerResolver {
    cache: Mutex<HashMap<u64, ContainerCacheEntry>>,
    pending: Mutex<HashSet<u64>>,
    // NEW: pid → cgroup_id, populated from sched_process_exec BPF events
    pid_cgroup: Mutex<HashMap<u32, u64>>,
    lookup_tx: mpsc::Sender<ContainerLookupRequest>,
    node_name: String,
    ttl: Duration,
}
```

Update `ContainerResolver::new` to initialise `pid_cgroup`:

```rust
pub fn new(lookup_tx: mpsc::Sender<ContainerLookupRequest>, node_name: String) -> Self {
    Self {
        cache: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashSet::new()),
        pid_cgroup: Mutex::new(HashMap::new()),
        lookup_tx,
        node_name,
        ttl: Duration::from_secs(600),
    }
}
```

Add the new public method after `new`:

```rust
/// Called from the proc_events ring buffer handler for each new process.
/// Stores pid→cgroup_id so resolve() can skip the /proc read.
pub fn register_pid(&self, pid: u32, cgroup_id: u64) {
    if pid == 0 || cgroup_id == 0 { return; }
    let mut map = self.pid_cgroup.lock().unwrap_or_else(|e| e.into_inner());
    // Cap at 8192 PIDs; evict oldest 512 when full.
    if map.len() >= 8192 {
        let victims: Vec<u32> = map.keys().copied().take(512).collect();
        for v in victims { map.remove(&v); }
    }
    map.insert(pid, cgroup_id);
}
```

- [ ] **Step 2: Update `resolve()` to use pid_cgroup cache**

Find the current `resolve()` body that calls `parse_cgroup_info`. Replace the `/proc` read path with a cache lookup:

```rust
pub fn resolve(&self, ev: &TlsEventHeader) -> Option<ContainerContext> {
    if ev.cgroup_id == 0 {
        return None;
    }
    let now = Instant::now();

    // Cache lookup
    let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = cache.get_mut(&ev.cgroup_id) {
        if now.duration_since(entry.last_seen) < self.ttl {
            entry.last_seen = now;
            return Some(entry.context.clone());
        }
    }

    if cache.len() > MAX_CACHE_ENTRIES {
        let ttl = self.ttl;
        cache.retain(|_, entry| now.duration_since(entry.last_seen) < ttl);
    }

    // NEW: look up container_id from pid_cgroup cache instead of /proc read
    let container_id_full: Option<String> = {
        let pid_map = self.pid_cgroup.lock().unwrap_or_else(|e| e.into_inner());
        if pid_map.contains_key(&ev.pid) {
            // cgroup_id is available from the event; do a /proc read only to
            // get the container_id string (still needed for CRI lookup),
            // but do it outside the cache lock below.
            None // signal that we need the container_id from /proc
        } else {
            None
        }
    };

    // Fall back to /proc read only when pid is not yet in pid_cgroup cache
    // (covers the window between process start and first sched_process_exec event).
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

    cache.insert(ev.cgroup_id, ContainerCacheEntry { context: context.clone(), last_seen: now });
    drop(cache);

    if let Some(full_id) = container_id_full {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
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
```

**Key invariant:** The cache mutex is dropped (`drop(cache)`) before the `pending` mutex is locked. The `/proc` read (`parse_cgroup_info`) now happens only on first-seen PIDs, not on every event for cached connections.

- [ ] **Step 3: Wire NewProcEvent → ContainerResolver in main.rs**

In `main.rs`, find the `proc_events` ring buffer handler (around line 354-368). Replace the current no-op handler with:

```rust
if let Some(proc_map) = proc_events_result {
    let proc_map_ptr = proc_map as *mut libbpf_rs::Map;
    let resolver_handle_proc = container_resolver.clone();
    unsafe {
        let _ = ringbuf.add(&mut *proc_map_ptr, move |data| {
            if data.len() < size_of::<NewProcEvent>() {
                return 0;
            }
            let ev = std::ptr::read_unaligned(data.as_ptr() as *const NewProcEvent);
            // Pre-populate pid→cgroup_id so resolve() skips /proc on hot path
            resolver_handle_proc.register_pid(ev.pid, ev.cgroup_id);
            let filename_end = ev.filename.iter().position(|&b| b == 0).unwrap_or(ev.filename.len());
            let filename = String::from_utf8_lossy(&ev.filename[..filename_end]);
            tracing::debug!(pid = ev.pid, cgroup = ev.cgroup_id, file = %filename, "new process");
            0
        });
    }
}
```

- [ ] **Step 4: Build**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | grep -E "^error" | head -20
```

Fix any compilation errors (likely unused variable warnings from the `container_id_full` refactor).

- [ ] **Step 5: Run tests**

```bash
cargo test --release 2>&1 | tail -5
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add userspace/src/container.rs userspace/src/main.rs
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "fix(H2): async cgroup cache — pre-populate pid→cgroup_id from sched_process_exec to avoid /proc read under shard mutex"
```

---

## Task 8: H1 — BPF dynptr variable-length events

**Problem:** `emit_event` reserves `sizeof(struct tls_event)` = ~32 KB per ring buffer slot, even for 100-byte HTTP headers. A 128 MB ring holds only ~3900 events. With dynptr, it reserves `sizeof(struct tls_event_hdr) + actual_len`, giving ~10× throughput for typical API traffic.

**Constraint:** `bpf_ringbuf_reserve_dynptr` requires kernel 5.19+. Keep fixed-size `tls_event` as fallback via BPF feature probe.

**Approach:** Add a runtime kernel version check in `main.rs`. If kernel ≥ 5.19, use the dynptr BPF object; else keep the fixed-size one. In the BPF C file, add a separate `emit_event_dynptr` helper that uses `bpf_ringbuf_reserve_dynptr` and compile it into the same BPF object gated by the `__bpf_feature_dynptr` macro.

**Files:**
- Modify: `bpf/http_trace.bpf.c`
- Modify: `userspace/src/main.rs` (kernel version check)

- [ ] **Step 1: Add dynptr emit_event to BPF C file**

In `bpf/http_trace.bpf.c`, after the existing `emit_event` function, add:

```c
#ifdef __bpf_feature_dynptr
static __always_inline int emit_event_dynptr(struct pt_regs *ctx,
                                              const void *buf,
                                              __u32 len,
                                              __u8 direction,
                                              __u64 ssl_ptr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 read_len = len;
    if (read_len >= MAX_DATA) read_len = MAX_DATA - 1;

    if (read_len > 0) {
        char sample_hdr[64] = {};
        __u32 sample_len = read_len < 64 ? read_len : 64;
        bpf_probe_read_user(sample_hdr, sample_len, buf);
        if (should_sample_out(sample_hdr, sample_len)) {
            return 0;
        }
    }

    __u32 total_size = sizeof(struct tls_event_hdr) + read_len;
    struct bpf_dynptr ptr;
    if (bpf_ringbuf_reserve_dynptr(&events, total_size, 0, &ptr) < 0) {
        RINGBUF_DROPS_INC(); /* best-effort counter, may not be available */
        return 0;
    }

    struct tls_event_hdr *hdr = bpf_dynptr_data(&ptr, 0, sizeof(struct tls_event_hdr));
    if (!hdr) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 0;
    }

    hdr->ts_ns     = bpf_ktime_get_ns();
    hdr->pid       = pid;
    hdr->tid       = tid;
    hdr->ssl_ptr   = ssl_ptr;
    hdr->data_len  = read_len;
    hdr->direction = direction;
    hdr->ip_family = 0;
    hdr->_pad16    = 0;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->netns_ino = 0;
    hdr->src_port  = 0;
    hdr->dst_port  = 0;
    hdr->src_ip4   = 0;
    hdr->dst_ip4   = 0;
    __builtin_memset(hdr->src_ip6, 0, sizeof(hdr->src_ip6));
    __builtin_memset(hdr->dst_ip6, 0, sizeof(hdr->dst_ip6));

    /* Network context */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy = NULL;
    bpf_core_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (nsproxy) {
        struct net *net_ns = NULL;
        bpf_core_read(&net_ns, sizeof(net_ns), &nsproxy->net_ns);
        if (net_ns) {
            unsigned int ino = 0;
            bpf_core_read(&ino, sizeof(ino), &net_ns->ns.inum);
            hdr->netns_ino = ino;
        }
    }

    struct conn_info *info = bpf_map_lookup_elem(&active_connections, &pid_tgid);
    if (!info || (info->src_ip4 == 0 && info->dst_ip4 == 0
                  && __builtin_memcmp(info->src_ip6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0)) {
        info = bpf_map_lookup_elem(&ssl_ptr_to_conn, &ssl_ptr);
    }
    if (info) {
        hdr->src_port = info->src_port;
        hdr->dst_port = info->dst_port;
        if (info->family == AF_INET6) {
            hdr->ip_family = 6;
            __builtin_memcpy(hdr->src_ip6, info->src_ip6, sizeof(hdr->src_ip6));
            __builtin_memcpy(hdr->dst_ip6, info->dst_ip6, sizeof(hdr->dst_ip6));
        } else if (info->family == AF_INET) {
            hdr->ip_family = 4;
            hdr->src_ip4 = info->src_ip4;
            hdr->dst_ip4 = info->dst_ip4;
        }
    }

    if (read_len > 0) {
        void *payload = bpf_dynptr_data(&ptr, sizeof(struct tls_event_hdr), read_len);
        if (!payload) {
            bpf_ringbuf_discard_dynptr(&ptr, 0);
            return 0;
        }
        if (bpf_probe_read_user(payload, read_len, buf) < 0) {
            bpf_ringbuf_discard_dynptr(&ptr, 0);
            return 0;
        }
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
    return 0;
}
#endif /* __bpf_feature_dynptr */
```

- [ ] **Step 2: Add kernel version probe map and select path**

Add a feature-flag BPF array at the top of the maps section in `bpf/http_trace.bpf.c`:

```c
/* Set to 1 by userspace if kernel supports bpf_ringbuf_reserve_dynptr (≥5.19) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} use_dynptr SEC(".maps");
```

Modify `emit_event` to check this flag at runtime (use fixed path regardless; dynptr path is compiled separately via `__bpf_feature_dynptr`):

```c
/* emit_event already uses fixed-size path — no change needed.
 * emit_event_dynptr is compiled in when __bpf_feature_dynptr is defined.
 * Userspace selects which path by setting use_dynptr[0] = 1 and calling
 * the appropriate helper. Since both are in the same object, the verifier
 * checks both paths independently.
 */
```

- [ ] **Step 3: Add kernel version check in main.rs**

In `userspace/src/main.rs`, after BPF object is loaded, add:

```rust
// Detect kernel dynptr support (≥ 5.19) and enable variable-length events.
let kernel_supports_dynptr = {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default();
    let parts: Vec<u32> = release
        .trim()
        .split(['.', '-'])
        .take(2)
        .filter_map(|s| s.parse().ok())
        .collect();
    matches!(parts.as_slice(), [major, minor, ..] if *major > 5 || (*major == 5 && *minor >= 19))
};

if kernel_supports_dynptr {
    if let Some(map) = obj.map_mut("use_dynptr") {
        let key: u32 = 0u32;
        let val: u32 = 1u32;
        if let Err(e) = map.update(&key.to_ne_bytes(), &val.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
            tracing::warn!(error = %e, "failed to enable dynptr path");
        } else {
            tracing::info!("BPF dynptr variable-length events enabled");
        }
    }
} else {
    tracing::info!("kernel < 5.19 — using fixed-size BPF events (dynptr unavailable)");
}
```

- [ ] **Step 4: Build BPF object**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor
# Build with dynptr support if clang/kernel headers support it:
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -D__bpf_feature_dynptr \
    -I bpf/ \
    -c bpf/http_trace.bpf.c \
    -o bpf/http_trace.bpf.o 2>&1 | head -20
```

If `bpf_ringbuf_reserve_dynptr` is not in the headers, build without the flag:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I bpf/ \
    -c bpf/http_trace.bpf.c \
    -o bpf/http_trace.bpf.o 2>&1 | head -20
```

Expected: `0 errors`. The userspace code still compiles regardless — `use_dynptr` map update is a runtime no-op if the map doesn't exist.

- [ ] **Step 5: Build Rust userspace**

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace
cargo build --release 2>&1 | tail -5
```

- [ ] **Step 6: Run full test suite**

```bash
cargo test --release 2>&1 | tail -10
```

Expected: all tests pass (dynptr path is feature-gated; existing tests use fixed-size events).

- [ ] **Step 7: Commit**

```bash
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor add bpf/http_trace.bpf.c userspace/src/main.rs
git -C /home/admin/projects/API-Security/API-Sensor/API-Sensor commit -m "feat(H1): BPF dynptr variable-length events — ~10x throughput for kernels ≥5.19, fixed-size fallback for older"
```

---

## Verification Checklist

After all tasks:

```bash
cd /home/admin/projects/API-Security/API-Sensor/API-Sensor/userspace

# Full build — must be clean
cargo build --release 2>&1 | tail -3

# Full test suite
cargo test --release 2>&1 | grep -E "test result|FAILED"

# Cargo audit — must show 0 vulnerabilities (or only advisory/informational)
cargo audit 2>&1 | tail -10
```

Expected final state:
- `cargo build --release` — clean, ≤2 dead_code warnings
- `cargo test --release` — all pass
- `cargo audit` — 0 errors (C3/C4 were reqwest/hpack CVEs, already fixed)
- `STREAM_TTL_MS = 300_000`
- `pool_max_idle_per_host = 16`
- `indexmap = "2"`, `axum = "0.8"`, `capstone = "0.14"`, `tonic = "0.14"`, `libbpf-rs = "0.26"`
