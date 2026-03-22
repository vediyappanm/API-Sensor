#!/usr/bin/env pwsh
# APISentinel Protocol Test Suite — tests all supported protocols
# Run from repo root: .\tests\run_protocol_tests.ps1

$ErrorActionPreference = "Continue"
$SENSOR_URL = "http://localhost:9090"
$VALIDATOR_URL = "http://localhost:19999"
$PASS = 0
$FAIL = 0

function Write-Header($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Pass($msg) { Write-Host "  PASS $msg" -ForegroundColor Green; $script:PASS++ }
function Write-Fail($msg) { Write-Host "  FAIL $msg" -ForegroundColor Red; $script:FAIL++ }

Write-Host ""
Write-Host "======================================" -ForegroundColor Yellow
Write-Host "  APISentinel Protocol Test Suite"
Write-Host "======================================" -ForegroundColor Yellow

# --- Step 1: Start test infrastructure ---
Write-Header "Starting test infrastructure"
Push-Location tests
docker compose up -d --build 2>&1 | Select-String -Pattern "Created|Running|Error"
Pop-Location
Write-Host "Waiting 20s for services to be healthy..."
Start-Sleep -Seconds 20

# --- Step 2: Start sensor in global mode ---
Write-Header "Starting sensor (global bootstrap scan)"
docker kill sentinel-sensor 2>$null | Out-Null
Start-Sleep -Seconds 2
docker rm -f sentinel-sensor 2>$null | Out-Null
docker run -d --name sentinel-sensor --privileged --pid=host `
  --network tests_default --init `
  -p 9090:9090 -e RUST_LOG=info `
  api-sentinel-sensor:v0.2.0 `
  --bpf /opt/sensor/http_trace.bpf.o `
  --ingest http://ingest-validator:9999/ingest `
  --api-key "test-key" `
  --discover-libs `
  --go-tls | Out-Null

Write-Host "Waiting 30s for global scan to complete (248+ PIDs)..."
Start-Sleep -Seconds 30

# Reset validator
curl.exe -s "$VALIDATOR_URL/reset" | Out-Null
Write-Host "Validator reset."

# --- Step 3: Generate traffic for each protocol ---

Write-Header "HTTP/1.1 over TLS (Node.js)"
curl.exe -sk https://localhost:18444/health | Out-Null
curl.exe -sk https://localhost:18444/api/echo | Out-Null
Write-Host "  Sent 2 HTTPS requests to Node.js"

Write-Header "HTTP/2 over TLS (Go server)"
# Windows curl lacks --http2. Use curl inside an Alpine container on the test network instead.
docker run --rm --network tests_default curlimages/curl:latest `
  -sk --http2 https://go-api:8443/health https://go-api:8443/api/users https://go-api:8443/api/echo 2>$null
Write-Host "  Sent 3 HTTP/2 requests to Go server (via container curl)"

Write-Header "WebSocket over TLS"
$testDir = (Resolve-Path ".\tests").Path
docker run --rm --network tests_default -v "${testDir}:/tests" python:3.11-slim bash -c "pip install -q websockets 2>/dev/null && python3 /tests/ws_client.py ws-server" 2>&1
Write-Host "  Sent 2 WebSocket messages"

Write-Header "MCP/SSE over TLS (JSON-RPC)"
curl.exe -sk -X POST https://localhost:17778 `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | Out-Null
curl.exe -sk -X POST https://localhost:17778 `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | Out-Null
# Skip /events SSE stream (hangs forever). Two POST requests are enough to prove MCP over TLS.
curl.exe -sk https://localhost:17778/health | Out-Null
Write-Host "  Sent 3 MCP requests over HTTPS"

Write-Header "gRPC over TLS"
docker run --rm --network tests_default -v "${testDir}:/tests" python:3.11-slim bash -c "pip install -q grpcio grpcio-reflection 2>/dev/null && python3 /tests/grpc_client.py grpc-server" 2>&1
Write-Host "  Sent gRPC reflection request"

# --- Step 4: Wait for batch flush ---
Write-Host "`nWaiting 8s for batch flush..."
Start-Sleep -Seconds 8

# --- Step 5: Results ---
Write-Header "SENSOR METRICS"
$metrics = curl.exe -s "$SENSOR_URL/metrics"
$captured = ($metrics | Select-String "apisec_events_captured_total (\d+)").Matches.Groups[1].Value
Write-Host "  Total events captured: $captured"
Write-Host ""
$metrics | Select-String "apisec_protocol_events_total"

Write-Header "INGEST VALIDATOR"
$counts = curl.exe -s "$VALIDATOR_URL/counts"
Write-Host "  Protocol counts: $counts"

Write-Header "SENSOR SCAN RESULTS"
docker logs sentinel-sensor 2>&1 | Select-String "global TLS|static TLS|Go TLS|bootstrap|probes attached"

# --- Step 6: Cleanup ---
Write-Header "Cleanup"
docker kill sentinel-sensor 2>$null | Out-Null
Start-Sleep -Seconds 2
docker rm -f sentinel-sensor 2>$null | Out-Null
Push-Location tests; docker compose down 2>&1 | Out-Null; Pop-Location
Write-Host "  Done."

Write-Host "`n======================================" -ForegroundColor Yellow
Write-Host "  Test complete. Review results above."
Write-Host "======================================" -ForegroundColor Yellow
