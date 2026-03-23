#!/bin/bash
set -e

cd /tmp

# Generate self-signed cert — quiche expects ./cert.crt and ./cert.key
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/cert.key -out /tmp/cert.crt \
  -days 365 -nodes -subj "/CN=quic-test-server" 2>/dev/null

echo "HTTP/3 (QUIC) server starting on 0.0.0.0:8447"
# quiche http3-server expects positional: <host> <port>
# cert loaded from ./cert.crt and ./cert.key (hardcoded in quiche example)
exec http3-server 0.0.0.0 8447
