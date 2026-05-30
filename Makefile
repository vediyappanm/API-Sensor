ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_ARCH_DEFINE := $(if $(filter arm64,$(ARCH)),arm64,x86)
BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH_DEFINE)

MACHINE ?= $(shell uname -m)
VMLINUX ?= /sys/kernel/btf/vmlinux
VMLINUX_HDR ?= bpf/vmlinux.h
VMLINUX_COMMITTED := bpf/vmlinux.$(MACHINE).h

all: bpf/http_trace.bpf.o userspace

# Prefer the live kernel's BTF (best for local dev); fall back to the committed,
# arch-specific header so builds work on hosts without BTF. CO-RE relocates at
# load time, so either source produces a portable object.
$(VMLINUX_HDR):
	@if [ -r $(VMLINUX) ]; then \
		echo "Generating $(VMLINUX_HDR) from live kernel BTF ($(VMLINUX))"; \
		bpftool btf dump file $(VMLINUX) format c > $(VMLINUX_HDR); \
	elif [ -f $(VMLINUX_COMMITTED) ]; then \
		echo "No live BTF; using committed $(VMLINUX_COMMITTED)"; \
		cp $(VMLINUX_COMMITTED) $(VMLINUX_HDR); \
	else \
		echo "ERROR: no live BTF at $(VMLINUX) and no committed $(VMLINUX_COMMITTED)"; \
		echo "  Generate with: bpftool btf dump file $(VMLINUX) format c > $(VMLINUX_COMMITTED)"; \
		exit 1; \
	fi

bpf/http_trace.bpf.o: $(VMLINUX_HDR) bpf/http_trace.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/http_trace.bpf.c -o bpf/http_trace.bpf.o

userspace:
	cd userspace && cargo build --release

clean:
	rm -f bpf/http_trace.bpf.o bpf/vmlinux.h
	cd userspace && cargo clean

verify-env:
	bash scripts/verify_env.sh
