# API-Sentinel-Sensor

A production-grade **eBPF-based TLS traffic capture sensor** for the API Sentinel platform. Intercepts encrypted HTTPS traffic at the kernel level using uprobes — no application changes required.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Linux Kernel (eBPF)                      │
│                                                             │
│  SSL_read/SSL_write uprobes  →  ring buffer  →  userspace  │
│  crypto/tls.(*Conn).Read/Write uprobes (Go TLS)            │
│  connect/accept kprobes (connection tracking)              │
└─────────────────────────────────────────────────────────────┘
          ↓ ring buffer events
┌─────────────────────────────────────────────────────────────┐
│              Rust Userspace Sensor (Tokio async)            │
│                                                             │
│  • Parse HTTP/1.1 + HTTP/2 (HPACK)                         │
│  • PII detection & redaction                               │
│  • Injection detection (SQLi, XSS, path traversal)         │
│  • Prometheus metrics (/metrics, /healthz)                  │
│  • Batch → gzip → POST to ingest endpoint                  │
└─────────────────────────────────────────────────────────────┘
          ↓ JSON over HTTP
┌──────────────┐
│  Ingest API  │  (cloud backend)
└──────────────┘
```

---

## Components

| Path | Description |
|------|-------------|
| `bpf/http_trace.bpf.c` | BPF kernel program — OpenSSL/Go TLS uprobes, connection kprobes, ring buffer |
| `userspace/src/main.rs` | Rust sensor — HTTP parsing, PII redaction, ingest shipping, Prometheus metrics |
| `Dockerfile.verify` | Ubuntu 24.04 build + verification image (clang, Rust, Go 1.21) |
| `scripts/root-verify.sh` | 9-check mechanical verification suite |
| `scripts/docker-entrypoint.sh` | Docker entrypoint — mounts bpffs/debugfs, runs verification |
| `scripts/verify_env.sh` | Kernel + TLS symbol sanity checks |
| `tests/` | Integration test servers (Go, Node, Python, WebSocket, MCP) |

---

## Requirements

- Linux kernel **5.8+** (kernel 6.8+ recommended, tested on 6.8.0)
- Root / `CAP_BPF`
- `clang`, `llvm`, `libbpf-dev`
- Rust stable (`cargo`)
- `bpftool` (from `linux-tools-common`)

---

## Build

```bash
cd sensor/ebpf
make
```

This compiles both the BPF object (`bpf/http_trace.bpf.o`) and the Rust sensor binary (`userspace/target/release/api-sec-sensor`).

---

## Run

```bash
sudo ./userspace/target/release/api-sec-sensor \
  --bpf ./bpf/http_trace.bpf.o \
  --ingest https://api.example.com/api/ingestion/v2/events \
  --api-key <token> \
  --account-id 1000000 \
  --role server \
  --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3 \
  --discover-libs
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--bpf <path>` | required | Path to compiled BPF object |
| `--ingest <url>` | required | Ingest endpoint URL |
| `--api-key <key>` | `$API_KEY` | API authentication token |
| `--account-id <id>` | `1000000` | Account ID sent in event metadata |
| `--role client\|server` | `server` | Traffic role for event tagging |
| `--batch-size <n>` | `200` | Events per batch |
| `--metrics-port <port>` | `9090` | Prometheus metrics port |
| `--tls-libs <path>` | system libssl | Path to libssl shared library (comma-separated) |
| `--tls-provider <name>` | `auto` | Force TLS provider: `openssl`, `gnutls`, or `auto` |
| `--discover-libs` | `false` | Auto-detect TLS libraries from `/proc/<pid>/maps` |
| `--go-tls` | `false` | Enable Go TLS interception via `crypto/tls` uprobes |
| `--pid <pid>` | `-1` (all) | Scope probes to a single process PID |
| `--max-buffer-bytes <n>` | `65536` | Max per-connection buffer size |
| `--max-total-buffer-bytes <n>` | `104857600` | Global memory ceiling (100MB) |
| `--sample-default <0-100>` | `100` | Default sampling rate (100 = capture all) |
| `--sample-health <0-100>` | `5` | Sampling rate for health/metrics endpoints |

---

## TLS Interception

### OpenSSL / BoringSSL
Attaches uprobes to `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex` in the target libssl shared library. Supports both shared library and statically linked BoringSSL (auto-detected via ELF symbol scan).

### Go TLS
Intercepts Go's `crypto/tls.(*Conn).Read` and `crypto/tls.(*Conn).Write` without needing `libssl`:

1. Scans `/proc/<pid>/maps` for executable segments
2. Identifies Go binary via buildinfo magic (`\xff Go buildinf:`)
3. Parses ELF symbol table to locate TLS function virtual addresses
4. Converts virtual addresses → file offsets via ELF PT_LOAD program headers
5. Disassembles with Capstone to find all RET instruction offsets
6. Attaches uprobes at function entry and every return point

Use `--go-tls --pid <go-server-pid>` to enable.

---

## HTTP/2 Support

Detects the HTTP/2 client preface (`PRI * HTTP/2.0`) and decodes headers using a built-in HPACK decoder (61 static entries + dynamic table). Emitted events include `protocol=HTTP/2` and `source=ebpf-grpc`.

---

## PII Detection & Redaction

The following patterns are detected and redacted before events are shipped:

| Type | Pattern | Redacted Token |
|------|---------|---------------|
| Email | `alice@example.com` | `PII_EMAIL_*` |
| SSN | `123-45-6789` | `PII_SSN_*` |
| Credit card | `4111111111111111` (Luhn validated) | `PII_CARD_*` |
| Phone | `+1-800-555-1234` | `PII_PHONE_*` |
| JWT | `eyJhbG...` | `PII_JWT_*` |
| Bearer Token | `Bearer abc123...` | `PII_TOKEN_*` |
| Private Key | `-----BEGIN RSA PRIVATE KEY-----` | `PII_PRIVATE_KEY_REDACTED` |
| AWS Access Key | `AKIA...` (20 chars) | `PII_AWSKEY_*` |
| GCP OAuth Token | `ya29....` | `PII_GCPTOKEN_*` |
| Indian PAN | `ABCDE1234F` | `PII_PAN_*` |
| Aadhaar | `1234 5678 9012` | `PII_AADHAAR_*` |

Applied to URL query parameters, request/response headers, and body fields. Credit card detection includes Luhn checksum validation to minimize false positives.

---

## Injection Detection

Flags events with `has_injection: true` when the following are detected:

- **SQL injection**: `UNION SELECT`, `OR 1=1`, `DROP TABLE`, comment sequences
- **XSS**: `<script>`, `javascript:`, `onerror=`, `onload=`
- **Path traversal**: `../`, `%2e%2e%2f`

---

## Protocol Support Matrix

| Protocol | Detection Method | Event Fields |
|----------|-----------------|--------------|
| HTTP/1.1 | Header parsing (`GET`/`POST`/...) | method, path, status, headers, latency |
| HTTP/2 | Client preface + HPACK decode | :method, :path, :status, :authority |
| gRPC | HTTP/2 + `content-type: application/grpc` | protobuf field decode |
| WebSocket | HTTP Upgrade header detection | opcode, payload |
| MCP/SSE | `content-type: text/event-stream` | JSON-RPC method, tool_name, injection flags |
| Go TLS | ELF symbol + capstone RET scan | Same as HTTP/1.1 or HTTP/2 |

## Anomaly Features (AEGIS SWARM)

Each event includes optional `anomaly_features` for downstream ML:

| Feature | Description |
|---------|-------------|
| `path_depth` | Number of `/` segments in URL path |
| `query_param_count` | Number of query string parameters |
| `has_encoded_chars` | URL contains `%`-encoded characters |
| `request_size_bucket` | log2 bucket of request body size |
| `shannon_entropy` | Shannon entropy of URL path |
| `has_sqli_pattern` | SQL injection keywords detected |
| `has_xss_pattern` | XSS patterns detected |
| `has_path_traversal` | `../` or `..\` patterns found |

---

## Prometheus Metrics

Available at `http://localhost:9090/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `apisec_events_captured_total` | counter | Total TLS events captured |
| `apisec_events_dropped_total` | counter | Events dropped (backpressure) |
| `apisec_events_sent_total` | counter | Events sent to ingest |
| `apisec_send_errors_total` | counter | HTTP/transport send errors |
| `apisec_ringbuf_drops_total` | counter | Kernel ring buffer drops |
| `apisec_active_connections` | gauge | Active TLS connections |
| `apisec_channel_watermark_pct` | gauge | Channel backpressure watermark (0-100%) |
| `apisec_drop_rate_bps` | gauge | Drop rate in basis points |
| `apisec_protocol_events_total` | counter | Events by protocol (http1, http2, grpc, websocket, mcp, go_tls) |
| `apisec_uptime_seconds` | gauge | Sensor uptime in seconds |

Health check: `GET /healthz` returns 200 (ok) or 503 (degraded, >20% drop rate)
Readiness: `GET /readyz` returns 200 if events captured or within 30s grace period

---

## Kubernetes DaemonSet Deployment

### Prerequisites

- Kubernetes 1.25+ cluster with Linux nodes (kernel 5.8+)
- `kubectl` and `helm` v3 installed
- Container registry (GHCR, ECR, Docker Hub, Harbor, etc.)
- Nodes must have BPF support enabled (standard on most distros)

### Step 1: Build the Docker Image

```bash
cd sensor/ebpf

# Build the production image (multi-stage: BPF compile → Rust compile → minimal runtime)
docker build -t ghcr.io/api-sentinel-team/sensor:latest .

# Tag with a version
docker tag ghcr.io/api-sentinel-team/sensor:latest \
           ghcr.io/api-sentinel-team/sensor:v1.0.0
```

### Step 2: Push to Container Registry

```bash
# GHCR (GitHub Container Registry)
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
docker push ghcr.io/api-sentinel-team/sensor:v1.0.0
docker push ghcr.io/api-sentinel-team/sensor:latest

# Or ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT>.dkr.ecr.us-east-1.amazonaws.com
docker tag ghcr.io/api-sentinel-team/sensor:v1.0.0 <ACCOUNT>.dkr.ecr.us-east-1.amazonaws.com/api-sentinel-sensor:v1.0.0
docker push <ACCOUNT>.dkr.ecr.us-east-1.amazonaws.com/api-sentinel-sensor:v1.0.0

# Or Docker Hub
docker tag ghcr.io/api-sentinel-team/sensor:v1.0.0 yourorg/api-sentinel-sensor:v1.0.0
docker push yourorg/api-sentinel-sensor:v1.0.0
```

### Step 3: Create the API Key Secret

```bash
kubectl create namespace api-sentinel

kubectl create secret generic api-sentinel-sensor \
  --namespace api-sentinel \
  --from-literal=api-key=<YOUR_API_KEY>
```

### Step 4: Install with Helm

```bash
# From the repo root
helm install api-sentinel-sensor deploy/helm/api-sentinel-sensor/ \
  --namespace api-sentinel \
  --set image.repository=ghcr.io/api-sentinel-team/sensor \
  --set image.tag=v1.0.0 \
  --set sensor.ingestUrl=https://ingest.example.com/v1/events \
  --set sensor.accountId="1000000"
```

#### Common Helm Overrides

```bash
helm install api-sentinel-sensor deploy/helm/api-sentinel-sensor/ \
  --namespace api-sentinel \
  --set image.repository=ghcr.io/api-sentinel-team/sensor \
  --set image.tag=v1.0.0 \
  --set sensor.ingestUrl=https://ingest.example.com/v1/events \
  --set sensor.accountId="1000000" \
  --set sensor.batchSize="500" \
  --set sensor.sampleDefault="50" \
  --set sensor.sampleHealth="1" \
  --set sensor.role=server \
  --set resources.limits.cpu=1000m \
  --set resources.limits.memory=512Mi \
  --set resources.requests.cpu=200m \
  --set resources.requests.memory=256Mi
```

#### Using a Custom values.yaml

```bash
cp deploy/helm/api-sentinel-sensor/values.yaml my-values.yaml
# Edit my-values.yaml with your settings
helm install api-sentinel-sensor deploy/helm/api-sentinel-sensor/ \
  --namespace api-sentinel -f my-values.yaml
```

### Helm Values Reference

| Value | Default | Description |
|-------|---------|-------------|
| `image.repository` | `ghcr.io/api-sentinel-team/sensor` | Container image repository |
| `image.tag` | `latest` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `sensor.ingestUrl` | `http://api-sentinel-ingest:8080/v1/events` | Backend ingest endpoint |
| `sensor.accountId` | `1000000` | Account ID for event metadata |
| `sensor.batchSize` | `200` | Events per batch |
| `sensor.role` | `server` | Traffic role (`server` or `client`) |
| `sensor.sampleDefault` | `100` | Default sampling rate (0-100) |
| `sensor.sampleHealth` | `5` | Health endpoint sampling rate |
| `sensor.metricsPort` | `9090` | Prometheus metrics port |
| `sensor.maxBufferBytes` | `65536` | Per-connection buffer size |
| `sensor.maxTotalBufferBytes` | `104857600` | Global memory ceiling (100MB) |
| `apiKeySecret.name` | `api-sentinel-sensor` | K8s Secret name for API key |
| `apiKeySecret.key` | `api-key` | Key within the Secret |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `256Mi` | Memory limit |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `nodeSelector` | `{}` | Node selector labels |
| `tolerations` | `[]` | Tolerations for taints |

### What the DaemonSet Does

The Helm chart deploys the sensor as a **DaemonSet** (one pod per node) with:

- **`hostPID: true`** — required to see all processes and attach uprobes
- **Capabilities** (not `privileged: true`):
  - `CAP_BPF` — load BPF programs
  - `CAP_PERFMON` — attach perf events / uprobes
  - `CAP_SYS_ADMIN` — access debugfs, BPF maps
  - `CAP_SYS_PTRACE` — read `/proc/<pid>/maps` for TLS library discovery
- **Volume Mounts**:
  - `/sys/kernel/debug` (read-only) — required for uprobe attachment
  - `/sys/fs/bpf` — BPF map pinning
  - `/sys/fs/cgroup` (read-only) — container-to-PID mapping
- **Prometheus annotations** — auto-scraped by Prometheus Operator
- **Liveness probe** — `GET /healthz` (degraded if >20% drop rate)
- **Readiness probe** — `GET /readyz` (ready once events are captured or within 30s grace)

### Step 5: Verify the Deployment

```bash
# Check DaemonSet rollout
kubectl -n api-sentinel get daemonset api-sentinel-sensor
kubectl -n api-sentinel rollout status daemonset/api-sentinel-sensor

# Check pods are running on all nodes
kubectl -n api-sentinel get pods -o wide

# View sensor logs
kubectl -n api-sentinel logs -l app.kubernetes.io/name=api-sentinel-sensor --tail=50

# Check metrics from a pod
kubectl -n api-sentinel port-forward daemonset/api-sentinel-sensor 9090:9090 &
curl -s http://localhost:9090/metrics | grep apisec_events_captured
curl -s http://localhost:9090/healthz
```

### Upgrade

```bash
helm upgrade api-sentinel-sensor deploy/helm/api-sentinel-sensor/ \
  --namespace api-sentinel \
  --set image.tag=v1.1.0
```

### Uninstall

```bash
helm uninstall api-sentinel-sensor --namespace api-sentinel
kubectl delete namespace api-sentinel
```

### Monitoring with Prometheus

The sensor exposes Prometheus metrics with auto-scrape annotations. If you use **kube-prometheus-stack**:

```yaml
# ServiceMonitor (optional — Helm already adds pod annotations)
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api-sentinel-sensor
  namespace: api-sentinel
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: api-sentinel-sensor
  endpoints:
    - port: metrics
      interval: 15s
```

Useful Grafana queries:
- **Event capture rate**: `rate(apisec_events_captured_total[5m])`
- **Drop rate**: `apisec_drop_rate_bps / 100` (percentage)
- **Send errors**: `rate(apisec_send_errors_total[5m])`
- **Events by protocol**: `rate(apisec_protocol_events_total[5m])`
- **Memory pressure**: `apisec_channel_watermark_pct`

### Troubleshooting

| Symptom | Check | Fix |
|---------|-------|-----|
| Pod in CrashLoopBackOff | `kubectl logs <pod>` | Ensure kernel 5.8+, check BPF object path |
| No events captured | Check `apisec_events_captured_total` metric | Verify TLS traffic exists on node, check `--discover-libs` |
| High drop rate | Check `apisec_drop_rate_bps` | Increase `resources.limits.memory`, reduce `sampleDefault` |
| Probe failures | `kubectl describe pod <pod>` | Check `metricsPort` matches, ensure sensor started |
| Permission denied | `kubectl logs <pod>` | Verify securityContext capabilities, node kernel supports BPF |
| Image pull error | `kubectl describe pod <pod>` | Check registry credentials, imagePullSecrets |

### Container Enrichment

The sensor maps PIDs to container names/namespaces via:
- **cgroups v1/v2** — reads `/proc/<pid>/cgroup` and `/sys/fs/cgroup` hierarchy
- **containerd CRI socket** — queries `/run/containerd/containerd.sock` (override with `CRI_SOCKET` env var)

Each event includes `container_name` and `container_namespace` when running inside Kubernetes.

---

## Verification (Docker)

Run the full 9-check mechanical verification suite on any Linux host with Docker:

```bash
# Build the verification image (one time)
docker build -f Dockerfile.verify -t api-sentinel-verify .

# Run all checks
docker run --rm --privileged --network=host --pid=host \
  -v "$(pwd)":/sensor/ebpf \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /usr/lib/linux-tools/$(uname -r)/bpftool:/usr/sbin/bpftool:ro \
  api-sentinel-verify \
  bash /sensor/ebpf/scripts/docker-entrypoint.sh
```

### Checks Performed

| # | Check | What it validates |
|---|-------|------------------|
| 1 | BPF verifier | All BPF programs accepted by kernel verifier |
| 2 | Sensor startup | Binary loads, uprobes attach, ring buffer starts |
| 3 | Prometheus metrics | `/metrics` and `/healthz` respond correctly |
| 4 | OpenSSL capture | `SSL_read` uprobe captures real HTTPS traffic |
| 5 | Go TLS capture | `crypto/tls` uprobe captures Go HTTPS traffic |
| 6 | Ring buffer stress | 10,000 concurrent requests with < 1% drop rate |

### Expected Output

```
═══════════════════════════════════════════════════════════════
  APISentinel Sensor — Mechanical Verification Suite
═══════════════════════════════════════════════════════════════

[PASS] BPF verifier accepted all programs
[PASS] Sensor started and is running
[PASS] /metrics contains apisec_events_captured_total
[PASS] /metrics contains apisec_ringbuf_drops_total
[PASS] /metrics contains apisec_uptime_seconds
[PASS] /healthz returns {"status":"ok"}
[PASS] Events captured: 2 (OpenSSL uprobe working)
[PASS] Go TLS events captured (before=0 after=11)
[PASS] Ring buffer drops = 0 — perfect

═══════════════════════════════════════════════════════════════
  Results: 9 passed  •  0 failed
═══════════════════════════════════════════════════════════════
  ALL CHECKS PASSED — sensor is production ready
```

Skip individual checks:
```bash
# Skip stress test
bash scripts/docker-entrypoint.sh --skip-stress

# Skip Go TLS test
bash scripts/docker-entrypoint.sh --skip-gotls
```

---

## Fuzz Testing

All parsers have been fuzz-tested with `cargo-fuzz` (libfuzzer) — 350M+ total executions, 0 panics:

| Fuzz Target | Parser | Status |
|-------------|--------|--------|
| `fuzz_http` | HTTP/1.1 request parser | PASS (645K+ runs) |
| `fuzz_http2` | HTTP/2 HPACK decoder | PASS (crash found & fixed) |
| `fuzz_websocket` | WebSocket frame parser | PASS (crash found & fixed) |
| `fuzz_grpc` | gRPC protobuf decoder | PASS (crash found & fixed) |
| `fuzz_redaction` | PII redaction engine | PASS |
| `fuzz_stream` | Stream reassembly | PASS |

Fixes applied:
- **HPACK**: Pre-validator prevents panics from upstream `hpack-0.3.0` crate bug (`.ok().unwrap()`)
- **WebSocket**: `checked_add()` prevents integer overflow on malformed 64-bit frame lengths
- **gRPC**: `saturating_add()` prevents integer overflow on malformed varint lengths

---

## Validated Environment

| Component | Version |
|-----------|---------|
| Linux kernel | 6.8.0-101-generic |
| Ubuntu | 24.04 |
| OpenSSL | 3.x |
| Go | 1.22.4 |
| Rust | stable |
| bpftool | v7.4.0 |
| libbpf | 1.x |
