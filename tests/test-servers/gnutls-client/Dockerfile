FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gnutls-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Default: connect to gnutls-server and send a GET request
CMD ["sh", "-c", "echo -e 'GET / HTTP/1.1\\r\\nHost: gnutls-server\\r\\nConnection: close\\r\\n\\r\\n' | gnutls-cli --insecure -p 8446 gnutls-server 2>/dev/null || true"]
