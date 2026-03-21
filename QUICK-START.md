# Quick Start: Deploy & Test API-Sentinel

## Option 1: Automated (One Command)

```bash
cd /home/admin/API-Sensor/API-Sensor

# Run complete deployment + testing pipeline
bash deploy-and-test.sh
```

This will:
- ✓ Build Docker image
- ✓ Deploy to Kubernetes
- ✓ Verify sensor is running
- ✓ Run shadow traffic test (10 min)
- ✓ Run load test (15 min, 500 VUs)
- ✓ Collect all metrics
- ✓ Generate test report

**Time:** ~45 minutes total

---

## Option 2: Manual Step-by-Step

### Step 1: Build Binary
```bash
cd userspace
cargo build --release
cd ..
```

### Step 2: Build Docker Image
```bash
docker build -t api-sentinel:latest .
```

### Step 3: Deploy to Kubernetes
```bash
kubectl apply -f k8s-sensor-daemonset.yaml
```

### Step 4: Verify Deployment
```bash
# Check pods running
kubectl get pods -n api-sensor

# Check metrics
SENSOR_POD=$(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n api-sensor $SENSOR_POD -- curl localhost:9091/metrics
```

### Step 5: Run Shadow Traffic Test (10 min)
```bash
# Send real traffic to target service
for i in {1..120}; do
  curl -s --http1.1 http://httpbin.org/get > /dev/null
  curl -s --http2 http://httpbin.org/post -X POST -d '{"test":"data"}' > /dev/null
  sleep 5
done

# Check metrics during test
kubectl exec -n api-sensor $SENSOR_POD -- curl localhost:9091/metrics | grep apisec_
```

### Step 6: Run Load Test (k6)
```bash
# Install k6 if not present
brew install k6  # macOS
# or: apt-get install k6  # Linux

# Run load test
k6 run \
  --vus 500 \
  --duration 15m \
  --ramp-up 2m \
  --out csv=results.csv \
  k6-load-test.js
```

### Step 7: Collect Results
```bash
# Get final metrics
SENSOR_POD=$(kubectl get pod -n api-sensor -l app=api-sentinel -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n api-sensor $SENSOR_POD -- curl -s localhost:9091/metrics > final-metrics.txt

# Show key metrics
echo "=== Events ==="
grep "apisec_events_captured_total\|apisec_events_sent_total\|apisec_events_dropped_total" final-metrics.txt

echo "=== Quality ==="
grep "apisec_drop_rate_bps\|apisec_send_errors_total\|apisec_ringbuf_drops_total" final-metrics.txt

echo "=== Protocols ==="
grep "apisec_protocol_events_total" final-metrics.txt
```

---

## Configuration Options

Set environment variables before running:

```bash
# Target service to test
export TARGET_URL="http://staging-api.local"

# Load test parameters
export K6_VUS=500
export K6_DURATION=15m
export K6_RAMP_UP=2m

# Kubernetes settings
export SENSOR_NAMESPACE="api-sensor"
export SENSOR_IMAGE="api-sentinel:latest"

# Then run
bash deploy-and-test.sh
```

---

## Expected Results

After all tests complete, you should see:

```
=== Events ===
apisec_events_captured_total 50000+     ✓
apisec_events_sent_total 50000+         ✓
apisec_events_dropped_total 0           ✓

=== Quality ===
apisec_drop_rate_bps 0                  ✓ (0% drop rate)
apisec_send_errors_total 0              ✓ (no errors)
apisec_ringbuf_drops_total 0            ✓ (no buffer overflows)

=== Protocols ===
apisec_protocol_events_total{protocol="http1"} 20000+
apisec_protocol_events_total{protocol="http2"} 17500+
apisec_protocol_events_total{protocol="grpc"} 7500+

=== Resource Usage ===
Memory: <256Mi
CPU: <200m
```

---

## Troubleshooting

### Docker Image Not Found
```bash
# Make sure you built the image first
docker build -t api-sentinel:latest .

# Verify it exists
docker images | grep api-sentinel
```

### Kubernetes Permissions
```bash
# Check you can access the cluster
kubectl auth can-i create daemonsets -n api-sensor

# If denied, ask your cluster admin for permissions
```

### k6 Not Installed
```bash
# macOS
brew install k6

# Linux
apt-get install k6

# Or use Docker
docker run -i --network=host grafana/k6:latest run - < k6-load-test.js
```

### Sensor Pod Crashing
```bash
# Check logs
kubectl logs -n api-sensor -l app=api-sentinel --tail=100

# Check pod status
kubectl describe pod -n api-sensor <pod-name>

# May need: elevated privileges, BPF filesystem, etc.
```

---

## Next Steps (After Tests Pass)

1. **Review Test Report**
   ```bash
   cat TEST-REPORT-*.md
   ```

2. **Prometheus Integration**
   - Query: `apisec_events_captured_total`
   - Dashboard: `/metrics` on port 9091

3. **Production Canary**
   - Deploy to 0.1% of production traffic
   - Monitor for 24 hours
   - Then full rollout

4. **Continuous Monitoring**
   - Set alerts for drop_rate_bps > 100
   - Monitor active_connections for leaks
   - Check ringbuf_drops trending

---

## Files Generated

After running tests:
- `final-metrics.txt` — Complete metrics export
- `load-test-output.log` — k6 test output
- `load-test-results-*.csv` — Detailed k6 results
- `TEST-REPORT-*.md` — Formatted test report
- `baseline-metrics.txt` — Pre-test metrics snapshot

All reports available in current directory.
