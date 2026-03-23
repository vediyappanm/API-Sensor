# Build quiche C shared library + HTTP/3 server example.
# Links against libquiche.so dynamically so quiche_conn_stream_recv/send
# symbols are visible in /proc/PID/maps for the sensor's QUIC uprobes.
FROM rust:1.88-bookworm AS quiche-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake g++ perl pkg-config libssl-dev git \
    libev-dev uthash-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clone quiche (with submodules for BoringSSL)
RUN git clone --recursive --depth 1 --branch 0.22.0 \
    https://github.com/cloudflare/quiche.git

WORKDIR /build/quiche

# Build the quiche C shared library (libquiche.so)
RUN cargo build --release --features ffi

# Build the C HTTP/3 server example linked against libquiche.so
WORKDIR /build/quiche/quiche/examples
RUN cc -Wall -g \
    -I../include \
    -L../../target/release \
    http3-server.c \
    -o /build/http3-server \
    -lquiche -lev -ldl -pthread -lm

# Build the C HTTP/3 client example too (for testing)
RUN cc -Wall -g \
    -I../include \
    -L../../target/release \
    http3-client.c \
    -o /build/http3-client \
    -lquiche -lev -ldl -pthread -lm

# Copy shared library
RUN cp /build/quiche/target/release/libquiche.so /build/libquiche.so

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 openssl libev4 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=quiche-builder /build/http3-server /usr/local/bin/http3-server
COPY --from=quiche-builder /build/http3-client /usr/local/bin/http3-client
COPY --from=quiche-builder /build/libquiche.so /usr/lib/libquiche.so
RUN ldconfig

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 8447/udp

CMD ["/start.sh"]
