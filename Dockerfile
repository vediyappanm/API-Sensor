# syntax=docker/dockerfile:1.7
#
# Reproducible build of the sensor: BPF object + Rust binary from this repository's sources.
# (The previous Dockerfile COPY'd a prebuilt, gitignored binary, so no image could be rebuilt or
# audited from the repo.)
#
#   docker build -t api-sentinel-sensor:dev .
#   docker build --build-arg CARGO_BUILD_JOBS=3 -t api-sentinel-sensor:dev .   # on a shared host
#
# bpf/vmlinux.h is a checked-in type header generated from a recent kernel's BTF. The program uses
# CO-RE, so the kernel it actually runs on is matched at load time, not at build time.

FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev libelf-dev zlib1g-dev libzstd-dev pkg-config libssl-dev \
        build-essential curl ca-certificates protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Pinned toolchain: the same compiler produces the same binary.
ARG RUST_VERSION=1.99.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}
ENV PATH=/root/.cargo/bin:${PATH}

WORKDIR /src
COPY bpf ./bpf
RUN clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c bpf/http_trace.bpf.c -o /http_trace.bpf.o

COPY userspace ./userspace
ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
RUN cd userspace && cargo build --release --locked \
    && cp target/release/api-sec-sensor /api-sec-sensor

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 libelf1 zlib1g curl bash \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /api-sec-sensor /usr/local/bin/api-sec-sensor
COPY --from=build /http_trace.bpf.o /app/bpf/http_trace.bpf.o

# Loading eBPF programs needs root plus a few capabilities (see deploy/helm/api-sentinel-sensor);
# the container is never run privileged.
EXPOSE 9091
ENTRYPOINT ["/usr/local/bin/api-sec-sensor"]
CMD ["--help"]
