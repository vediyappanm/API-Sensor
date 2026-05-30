# ---- Stage 1: Build BPF object ----
FROM ubuntu:24.04 AS bpf-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang llvm libbpf-dev linux-tools-common \
    build-essential pkg-config libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# TARGETARCH is provided automatically by `docker buildx` (amd64 | arm64).
ARG TARGETARCH=amd64
COPY bpf/ bpf/
# Compile the BPF object from the committed, arch-specific vmlinux.h so the build
# is reproducible from a clean checkout — independent of the build host's
# /sys/kernel/btf/vmlinux. CO-RE relocates field offsets against the TARGET
# kernel's BTF at load time, so the kernel that produced this header does not
# constrain which kernels the object can run on.
RUN set -eux; \
    case "$TARGETARCH" in \
      arm64) BPF_ARCH=arm64; MARCH=aarch64; INC=/usr/include/aarch64-linux-gnu ;; \
      *)     BPF_ARCH=x86;   MARCH=x86_64;  INC=/usr/include/x86_64-linux-gnu  ;; \
    esac; \
    if [ ! -f "bpf/vmlinux.${MARCH}.h" ]; then \
      echo "ERROR: bpf/vmlinux.${MARCH}.h is not committed. Generate it on a ${MARCH} node with:" >&2; \
      echo "  bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.${MARCH}.h" >&2; \
      exit 1; \
    fi; \
    cp "bpf/vmlinux.${MARCH}.h" bpf/vmlinux.h; \
    clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} -I"${INC}" \
      -c bpf/http_trace.bpf.c -o bpf/http_trace.bpf.o

# ---- Stage 2: Build Rust binary ----
FROM rust:1.85-bookworm AS rust-builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev libelf-dev zlib1g-dev libzstd-dev clang protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/userspace

# Cache dependencies — only re-fetched when Cargo.toml/Cargo.lock change
COPY userspace/Cargo.toml userspace/Cargo.lock ./
COPY userspace/proto/ proto/
COPY userspace/build.rs build.rs
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

# Now copy real source and build (deps already cached)
COPY userspace/src/ src/
COPY --from=bpf-builder /build/bpf/http_trace.bpf.o bpf/http_trace.bpf.o
RUN touch src/main.rs src/lib.rs && cargo build --release

# ---- Stage 3: Minimal runtime image ----
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libelf1 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# NOTE: Sensor runs as root — CAP_BPF, CAP_SYS_ADMIN, CAP_SYS_PTRACE require it.
# Kubernetes DaemonSet restricts capabilities via securityContext (not USER).

COPY --from=bpf-builder /build/bpf/http_trace.bpf.o /opt/sensor/http_trace.bpf.o
COPY --from=rust-builder /build/userspace/target/release/api-sec-sensor /opt/sensor/api-sec-sensor

# Default config directory — mount a ConfigMap here in K8s
RUN mkdir -p /etc/api-sentinel
COPY config/config.example.toml /etc/api-sentinel/config.toml

WORKDIR /opt/sensor

ENV RUST_LOG=info

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:9090/healthz || exit 1

ENTRYPOINT ["/opt/sensor/api-sec-sensor"]
CMD ["--config", "/etc/api-sentinel/config.toml"]
