# Start infra
cd tests
docker compose up -d
cd ..
Start-Sleep -Seconds 20

# Start sensor
docker rm -f sentinel-sensor 2>$null
docker run -d --name sentinel-sensor --privileged --pid=host `
  --network tests_default --init `
  -p 9090:9090 -e RUST_LOG=info `
  api-sentinel-sensor:v0.2.0 `
  --bpf /opt/sensor/http_trace.bpf.o `
  --ingest http://ingest-validator:9999/ingest `
  --api-key "test-key" `
  --discover-libs `
  --go-tls

# Wait for global scan to complete
Start-Sleep -Seconds 30

# Reset validator counters
curl.exe -s http://localhost:19999/reset

# === TEST EACH PROTOCOL ===

# 1. HTTP/1.1
curl.exe -s http://localhost:18080/get >$null
curl.exe -s -X POST http://localhost:18080/post -d '{"protocol":"http1"}' >$null
Write-Host "HTTP/1.1 sent"

# 2. Node.js HTTPS (static OpenSSL)
curl.exe -sk https://localhost:18444/health >$null
curl.exe -sk https://localhost:18444/api/echo >$null
Write-Host "Node HTTPS sent"

# 3. Go TLS
curl.exe -sk https://localhost:18443/health >$null
curl.exe -sk https://localhost:18443/api/users >$null
Write-Host "Go TLS sent"

# 4. MCP/SSE (JSON-RPC)
curl.exe -s -X POST http://localhost:17777 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' >$null
curl.exe -s -X POST http://localhost:17777 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' >$null
Write-Host "MCP sent"

# Wait for batch flush
Start-Sleep -Seconds 10

# === RESULTS ===
Write-Host "=== PROTOCOL EVENTS ==="
curl.exe -s http://localhost:9090/metrics | findstr "apisec_protocol_events"

Write-Host ""
Write-Host "=== TOTAL CAPTURED ==="
curl.exe -s http://localhost:9090/metrics | findstr "apisec_events_captured"

Write-Host ""
Write-Host "=== VALIDATOR COUNTS ==="
curl.exe -s http://localhost:19999/counts
