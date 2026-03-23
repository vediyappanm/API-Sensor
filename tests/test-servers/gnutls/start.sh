#!/bin/bash
set -e

# Generate self-signed cert for GnuTLS server
certtool --generate-privkey --outfile /tmp/server.key 2>/dev/null

cat > /tmp/cert.cfg <<EOF
cn = gnutls-test-server
expiration_days = 365
signing_key
tls_www_server
EOF

certtool --generate-self-signed \
  --load-privkey /tmp/server.key \
  --template /tmp/cert.cfg \
  --outfile /tmp/server.crt 2>/dev/null

echo "GnuTLS test server starting on :8446 (TLS)"
exec gnutls-serv --http \
  --port 8446 \
  --x509certfile /tmp/server.crt \
  --x509keyfile /tmp/server.key
