# Real Traffic Testing Runbook

## Overview
Complete strategy for testing API-Sentinel sensor against real Kubernetes traffic:
1. **Staging Deployment** — Non-destructive traffic capture
2. **Shadow Traffic** — Mirror production without impact
3. **Load Testing** — Sustained high-volume traffic (500+ VUs)
4. **Production Canary** — 0.1% production traffic sampling

---

## Phase 1: Staging Deployment

### Prerequisites
```bash
# Verify sensor is deployed
kubectl get daemonset -n api-sensor
kubectl get pods -n api-sensor

# Check metrics endpoint
kubectl port-forward -n api-sensor svc/sensor-metrics 9091:9091 &
curl http://localhost:9091/metrics
```

### Deploy to Staging
```bash
# 1. Build Docker image
cd userspace
cargo build --release
docker build -t api-sentinel:latest .

# 2. Push to registry (if needed)
docker tag api-sentinel:latest your-registry/api-sentinel:latest
docker push your-registry/api-sentinel:latest

# 3. Update DaemonSet image
kubectl set image daemonset/api-sentinel-sensor \
  sensor=your-registry/api-sentinel:latest \
  -n api-sensor

# 4. Verify rollout
kubectl rollout status daemonset/api-sentinel-sensor -n api-sensor
```

### Validate Baseline Metrics
```bash
# Get current metrics
kubectl exec -n api-sensor -it $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath='{.items[0].metadata.name}') -- \
  curl localhost:9091/metrics | grep apisec_

# Expected baseline (no traffic):
# apisec_events_captured_total 0
# apisec_events_sent_total 0
# apisec_active_connections 0
```

---

## Phase 2: Shadow Traffic Test (10 minutes)

### Setup Mirror Traffic
```bash
# Option A: Istio VirtualService (if Istio installed)
cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: api-shadow
  namespace: staging
spec:
  hosts:
  - api.staging
  http:
  - match:
    - uri:
        prefix: /api
    route:
    - destination:
        host: api
        port:
          number: 80
      weight: 100
    mirror:
      host: api-sensor-sidecar
      port:
        number: 8080
    mirrorPercent: 100
EOF

# Option B: Manual iptables (if not using service mesh)
kubectl exec -n api-sensor $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath='{.items[0].metadata.name}') -- \
  iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TEE --gateway $(kubectl get svc api -n staging -o jsonpath='{.spec.clusterIP}')
```

### Run Shadow Test
```bash
# Monitor metrics during traffic
watch -n 5 'kubectl exec -n api-sensor $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath "{.items[0].metadata.name}") -- \
  curl -s localhost:9091/metrics | grep apisec_'

# Expected output (after 5-10 minutes of mirrored traffic):
# apisec_events_captured_total 500+     (depends on traffic volume)
# apisec_events_sent_total 500+
# apisec_events_dropped_total 0
# apisec_drop_rate_bps 0                (0% drop rate)
# apisec_active_connections 10-100+     (varies with traffic)
# apisec_protocol_events_total{protocol="http1"} 100+
# apisec_protocol_events_total{protocol="http2"} 200+
# apisec_protocol_events_total{protocol="grpc"} 100+
```

### Collect Baseline Data
```bash
# Export metrics for analysis
kubectl exec -n api-sensor $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath='{.items[0].metadata.name}') -- \
  curl -s localhost:9091/metrics > shadow-traffic-baseline.txt

# Check for any errors or anomalies
grep "apisec_send_errors_total" shadow-traffic-baseline.txt
grep "apisec_ringbuf_drops_total" shadow-traffic-baseline.txt
```

---

## Phase 3: Load Testing (15 minutes)

### Prerequisites
```bash
# Install k6 (local machine or in-cluster)
brew install k6  # macOS
apt-get install k6  # Linux
# or: docker run -i --network=host grafana/k6:latest run -

# Configure target URL
export TARGET_URL="http://staging-api.local"  # Replace with your staging endpoint
export GRPC_URL="staging-api.local:50051"     # If gRPC available
```

### Run Load Test
```bash
# Run k6 load test against staging services
k6 run \
  --vus 500 \
  --duration 15m \
  --out csv=load-test-results.csv \
  k6-load-test.js

# Real-time metrics visible in k6 output:
# iteration_duration
# http_req_duration (p95, p99)
# http_req_failed (error rate)
# errors (custom metric)
```

### Monitor Sensor During Load
```bash
# Terminal 1: Continuous metrics
watch -n 2 'kubectl exec -n api-sensor $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath "{.items[0].metadata.name}") -- \
  curl -s localhost:9091/metrics | tail -20'

# Terminal 2: Check sensor logs for errors
kubectl logs -n api-sensor -f -l app=api-sentinel --tail=50

# Terminal 3: Pod resource usage
kubectl top pod -n api-sensor --sort-by=memory
```

### Expected Load Test Results
```
STAGING LOAD TEST (500 VUs, 15 min sustained):
- Total requests: 50,000 - 100,000 (depending on endpoint latency)
- HTTP/1.1: ~40% (20,000-40,000 events)
- HTTP/2: ~35% (17,500-35,000 events)
- gRPC: ~15% (7,500-15,000 events)
- WebSocket: ~10% (5,000-10,000 events)

SENSOR METRICS:
- apisec_events_captured_total: 50,000+ ✓
- apisec_events_dropped_total: 0 (or <1%) ✓
- apisec_drop_rate_bps: 0 (0% drop) ✓
- apisec_send_errors_total: 0 ✓
- apisec_active_connections: 50-200 ✓
- apisec_ringbuf_drops_total: 0 ✓
- Memory usage: <512Mi ✓
- CPU usage: <500m ✓
```

### Analysis
```bash
# Extract key metrics
kubectl exec -n api-sensor $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath='{.items[0].metadata.name}') -- \
  curl -s localhost:9091/metrics > load-test-final-metrics.txt

# Parse results
echo "=== Load Test Results ==="
grep "apisec_events_captured_total" load-test-final-metrics.txt
grep "apisec_events_dropped_total" load-test-final-metrics.txt
grep "apisec_drop_rate_bps" load-test-final-metrics.txt
grep "apisec_send_errors_total" load-test-final-metrics.txt
grep "apisec_active_connections" load-test-final-metrics.txt

# k6 results
tail -50 load-test-results.csv | grep "summary"
```

---

## Phase 4: Production Canary (Optional - Requires Approval)

### Pre-Canary Checklist
- [ ] Staging tests all pass (0% drop rate, 0 errors)
- [ ] Load test stable (no memory leaks, CPU < 500m)
- [ ] Security review completed
- [ ] Rollback plan documented
- [ ] On-call team notified

### Canary Deployment
```bash
# 1. Deploy to production with high pod disruption budget
cat <<EOF | kubectl apply -f -
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: sensor-pdb
  namespace: api-sensor
spec:
  minAvailable: "80%"
  selector:
    matchLabels:
      app: api-sentinel
EOF

# 2. Update prod namespace selector (if separate cluster)
kubectl label namespace production sensor=enabled --overwrite

# 3. Monitor canary metrics (first 5 minutes)
watch -n 10 'kubectl exec -n api-sensor $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath "{.items[0].metadata.name}") -- \
  curl -s localhost:9091/metrics | grep -E "apisec_(captured|dropped|errors|active)"'

# 4. Exit metrics should show:
# apisec_events_captured_total: 100+/min (0.1% of prod traffic)
# apisec_events_dropped_total: 0
# apisec_send_errors_total: 0
```

### Rollback Plan
```bash
# If issues detected (drop rate > 1%, errors > 0):
kubectl delete daemonset api-sentinel-sensor -n api-sensor
# Sensor stops immediately, zero impact on traffic (read-only eBPF probes)
```

---

## Post-Test Analysis

### Metrics Export & Visualization
```bash
# Export all metrics from final state
kubectl exec -n api-sensor $(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath='{.items[0].metadata.name}') -- \
  curl -s localhost:9091/metrics > final-metrics-report.txt

# If Prometheus configured:
# Query: apisec_events_captured_total (over time graph)
# Query: rate(apisec_events_captured_total[5m]) (events/sec)
# Query: apisec_drop_rate_bps (should be near 0)
```

### Test Report Template
```
TEST REPORT: API-Sentinel Real Traffic Validation
Date: $(date)

SHADOW TRAFFIC PHASE:
- Duration: 10 minutes
- Events captured: ___
- Drop rate: ___% (target: <1%)
- Send errors: ___ (target: 0)

LOAD TEST PHASE:
- VUs: 500
- Duration: 15 minutes
- Total requests: ___
- HTTP/1.1: ___%
- HTTP/2: ___%
- gRPC: ___%
- Avg latency: ___ms
- p95 latency: ___ms
- p99 latency: ___ms
- Error rate: ___% (target: <0.1%)

SENSOR METRICS:
- Memory: ___Mi (target: <512Mi)
- CPU: ___m (target: <500m)
- Active connections peak: ___
- Ring buffer drops: ___ (target: 0)

VERDICT: [ ] PASS [ ] FAIL
Issues: ___
```

---

## Troubleshooting

### High Drop Rate (>1%)
```bash
# 1. Check memory ceiling
kubectl exec -n api-sensor <pod> -- \
  curl localhost:9091/metrics | grep ringbuf_drops

# 2. Check ring buffer backpressure
kubectl exec -n api-sensor <pod> -- \
  curl localhost:9091/metrics | grep channel_watermark_pct

# 3. If watermark >80%: increase ring buffer size in sensor code
# If ringbuf drops >0: reduce VUs in load test

# Solution: Reduce load or increase sensor pod resources
kubectl set resources daemonset api-sentinel-sensor \
  -n api-sensor --limits=memory=1Gi,cpu=1000m
```

### Send Errors (>0)
```bash
# 1. Check ingest endpoint reachability
kubectl exec -n api-sensor <pod> -- \
  curl -v $INGEST_URL/health

# 2. Check ingest server capacity
kubectl logs -n api-sensor <pod> | grep "send error"

# 3. Scale ingest server
kubectl scale deployment ingest --replicas=5 -n api-sensor
```

### High Memory Usage (>512Mi)
```bash
# 1. Check for stream state leaks
kubectl exec -n api-sensor <pod> -- \
  curl localhost:9091/metrics | grep active_connections

# 2. If growing: potential memory leak in stream.rs
# Solution: Restart pod or reduce max concurrent connections

# Monitor memory trend over time (Prometheus)
# Query: apisec_memory_bytes (if exposed)
```

---

## Success Criteria

✅ **All tests must pass for production readiness:**

| Test | Metric | Target | Status |
|------|--------|--------|--------|
| Shadow Traffic | Drop rate | <1% | |
| Shadow Traffic | Send errors | 0 | |
| Load 500 VUs | Captured events | >50k | |
| Load 500 VUs | Drop rate | <0.1% | |
| Load 500 VUs | Memory usage | <512Mi | |
| Load 500 VUs | CPU usage | <500m | |
| Load 500 VUs | p95 latency | <500ms | |
| Protocol Mix | HTTP/1.1 | 30-50% | |
| Protocol Mix | HTTP/2 | 30-50% | |
| Protocol Mix | gRPC | 10-20% | |
| Production Canary | Events captured | Consistent | |
| Production Canary | 0.1% traffic | No errors | |

---

## Next Steps
1. [ ] Deploy sensor to staging
2. [ ] Run shadow traffic test (10 min)
3. [ ] Run load test (15 min)
4. [ ] Analyze results
5. [ ] Get production approval
6. [ ] Deploy canary (5% traffic)
7. [ ] Full production deployment
