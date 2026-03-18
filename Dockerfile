# ---- Stage 1: Build BPF object ----
FROM ubuntu:24.04 AS bpf-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang llvm libbpf-dev linux-tools-common \
    build-essential pkg-config libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY bpf/ bpf/
RUN clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c bpf/http_trace.bpf.c \
    -o bpf/http_trace.bpf.o

# ---- Stage 2: Build Rust binary ----
FROM rust:1.82-bookworm AS rust-builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev libelf-dev zlib1g-dev libzstd-dev clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY userspace/ userspace/
COPY --from=bpf-builder /build/bpf/http_trace.bpf.o userspace/bpf/http_trace.bpf.o

WORKDIR /build/userspace
RUN cargo build --release

# ---- Stage 3: Minimal runtime image ----
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    libssl3 libelf1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false sensor

COPY --from=bpf-builder /build/bpf/http_trace.bpf.o /opt/sensor/http_trace.bpf.o
COPY --from=rust-builder /build/userspace/target/release/api-sec-sensor /opt/sensor/api-sec-sensor

WORKDIR /opt/sensor

EXPOSE 9090

ENTRYPOINT ["/opt/sensor/api-sec-sensor"]
CMD ["--bpf", "/opt/sensor/http_trace.bpf.o", "--discover-libs", "--metrics-port", "9090"]
