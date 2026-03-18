ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_ARCH_DEFINE := $(if $(filter arm64,$(ARCH)),arm64,x86)
BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH_DEFINE)

VMLINUX ?= /sys/kernel/btf/vmlinux
VMLINUX_HDR ?= bpf/vmlinux.h

all: bpf/http_trace.bpf.o userspace

$(VMLINUX_HDR):
	bpftool btf dump file $(VMLINUX) format c > $(VMLINUX_HDR)

bpf/http_trace.bpf.o: $(VMLINUX_HDR) bpf/http_trace.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/http_trace.bpf.c -o bpf/http_trace.bpf.o

userspace:
	cd userspace && cargo build --release

clean:
	rm -f bpf/http_trace.bpf.o bpf/vmlinux.h
	cd userspace && cargo clean

verify-env:
	bash scripts/verify_env.sh
