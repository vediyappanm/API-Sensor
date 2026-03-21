FROM ubuntu:24.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libc6 \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built binary
COPY api-sec-sensor /usr/local/bin/api-sec-sensor

# Set permissions
RUN chmod +x /usr/local/bin/api-sec-sensor && \
    mkdir -p /sys/fs/bpf /sys/kernel/debug

# Expose metrics and health ports
EXPOSE 9091 8080

# Default command
ENTRYPOINT ["/usr/local/bin/api-sec-sensor"]
CMD ["--metrics-port", "9091"]
