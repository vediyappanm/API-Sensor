// TLS uprobe-based HTTP capture (CO-RE).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DATA 32768

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// Fixed header — layout must match types.rs:TlsEventHeader exactly.
// Used as the dynptr-path event header (no trailing data[] array).
struct tls_event_hdr {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl_ptr;
    __u32 data_len;
    __u8  direction; // 0 = READ (ingress), 1 = WRITE (egress)
    __u8  ip_family; // 4 = IPv4, 6 = IPv6, 0 = unknown
    __u16 _pad16;
    char  comm[16];
    __u64 cgroup_id;
    __u32 netns_ino;
    __u16 src_port;
    __u16 dst_port;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u8  src_ip6[16];
    __u8  dst_ip6[16];
};

// Full fixed-size event (fallback for kernels < 5.19 without dynptr support).
struct tls_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl_ptr;
    __u32 data_len;
    __u8 direction;
    __u8 ip_family;
    __u16 _pad16;
    char comm[16];
    __u64 cgroup_id;
    __u32 netns_ino;
    __u16 src_port;
    __u16 dst_port;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u8 src_ip6[16];
    __u8 dst_ip6[16];
    char data[MAX_DATA];
};

struct read_args {
    __u64 ssl_ptr;
    const void *buf;
    __u32 len;
};

struct write_args {
    __u64 ssl_ptr;
    const void *buf;
    __u32 len;
};

struct read_ex_args {
    __u64 ssl_ptr;
    void *buf;
    __u64 *bytes_ptr;
    __u64 len;
};

struct write_ex_args {
    __u64 ssl_ptr;
    const void *buf;
    __u64 *bytes_ptr;
    __u64 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 27);
} events SEC(".maps");


struct close_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} close_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct read_args);
} ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct write_args);
} ssl_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // ssl_ptr
    __type(value, __u64); // pid_tgid
} ssl_ptr_to_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct read_ex_args);
} ssl_read_ex_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct write_ex_args);
} ssl_write_ex_args SEC(".maps");

// Separate GnuTLS maps to avoid key collision with OpenSSL maps (BUG-3)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct write_args);
} gnutls_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct read_args);
} gnutls_read_args SEC(".maps");

struct conn_info {
    __u16 family;
    __u16 src_port;
    __u16 dst_port;
    __u16 _pad;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u8 src_ip6[16];
    __u8 dst_ip6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); // pid_tgid
    __type(value, struct conn_info);
} active_connections SEC(".maps");

// ssl_ptr -> conn_info: populated by SSL_set_fd uprobe for async-runtime accuracy.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);  // ssl_ptr
    __type(value, struct conn_info);
} ssl_ptr_to_conn SEC(".maps");

// sock_ptr -> pid_tgid: populated at tcp_connect / inet_csk_accept so that
// tcp_close can delete the correct active_connections entry even when the
// closing thread differs from the thread that opened the connection.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);  // struct sock *
    __type(value, __u64); // pid_tgid
} sock_to_pid SEC(".maps");

// Go TLS support
struct go_write_args {
    __u64 conn_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u32 _pad;
};

struct go_read_args {
    __u64 conn_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // goroutine_id or pid_tgid fallback
    __type(value, struct go_write_args);
} go_tls_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // goroutine_id or pid_tgid fallback
    __type(value, struct go_read_args);
} go_tls_read_args SEC(".maps");

// Single-element array updated from userspace with correct Go version offset
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);  // goid offset in g struct
} go_goid_offset SEC(".maps");

// Process lifecycle tracking
struct new_proc_event {
    __u32 pid;
    __u32 _pad;
    __u64 cgroup_id;
    char  comm[16];
    char  filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} proc_events SEC(".maps");

// Sampling maps
struct sample_config {
    __u8  default_rate;   // 0-100
    __u8  health_rate;    // rate for health/metrics endpoints
    __u8  _pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sample_config);
} sampling_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} event_counter SEC(".maps");

// Per-CPU scratch buffer for dynptr payload writes (avoids BPF stack limit).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_DATA]);
} dynptr_scratch SEC(".maps");

// Userspace sets this to 1 on kernel ≥5.19 to enable variable-length ring buffer slots.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} use_dynptr SEC(".maps");

static __always_inline void fill_conn_info(struct conn_info *out, struct sock *sk)
{
    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    out->family = family;
    if (family == AF_INET6) {
        bpf_core_read(out->src_ip6, sizeof(out->src_ip6), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(out->dst_ip6, sizeof(out->dst_ip6), &sk->__sk_common.skc_v6_daddr);
    } else {
        bpf_core_read(&out->src_ip4, sizeof(out->src_ip4), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&out->dst_ip4, sizeof(out->dst_ip4), &sk->__sk_common.skc_daddr);
    }
    bpf_core_read(&out->src_port, sizeof(out->src_port), &sk->__sk_common.skc_num);
    bpf_core_read(&out->dst_port, sizeof(out->dst_port), &sk->__sk_common.skc_dport);
    out->dst_port = bpf_ntohs(out->dst_port);
}

// Find offset of path in HTTP request line (after "METHOD ")
static __always_inline __u32 find_path_start(const char *data, __u32 len)
{
    __u32 i;
    for (i = 0; i < 8 && i < len; i++) {
        if (data[i] == ' ') return i + 1;
    }
    return 0;
}

static __always_inline bool should_sample_out(const char *data, __u32 len)
{
    __u32 key = 0;
    struct sample_config *cfg = bpf_map_lookup_elem(&sampling_config, &key);
    if (!cfg) return false;

    __u64 *counter = bpf_map_lookup_elem(&event_counter, &key);
    if (!counter) return false;

    if (len < 10) return false;

    __u32 path_start = find_path_start(data, len);
    if (path_start == 0 || path_start >= len) {
        // Apply default rate
        if (cfg->default_rate >= 100) return false;
        __u64 n = __sync_fetch_and_add(counter, 1);
        return (n % 100) >= cfg->default_rate;
    }

    const char *path = data + path_start;
    __u32 path_len   = len - path_start;

    // Auth/security paths: always capture (each comparison guarded by its length)
    if ((path_len >= 5 && __builtin_memcmp(path, "/auth",  5) == 0) ||
        (path_len >= 6 && __builtin_memcmp(path, "/login", 6) == 0) ||
        (path_len >= 6 && __builtin_memcmp(path, "/token", 6) == 0) ||
        (path_len >= 6 && __builtin_memcmp(path, "/oauth", 6) == 0) ||
        (path_len >= 6 && __builtin_memcmp(path, "/admin", 6) == 0) ||
        (path_len >= 4 && __builtin_memcmp(path, "/mcp",   4) == 0)) {
        return false; // do NOT sample out
    }

    // Health/metrics: apply health rate
    __u8 rate = cfg->default_rate;
    if ((path_len >= 7 && __builtin_memcmp(path, "/health",  7) == 0) ||
        (path_len >= 7 && __builtin_memcmp(path, "/readyz",  7) == 0) ||
        (path_len >= 6 && __builtin_memcmp(path, "/livez",   6) == 0) ||
        (path_len >= 8 && __builtin_memcmp(path, "/metrics", 8) == 0)) {
        rate = cfg->health_rate;
    }

    if (rate >= 100) return false;
    __u64 n = __sync_fetch_and_add(counter, 1);
    return (n % 100) >= rate;
}

// Variable-length ring buffer event path (kernel ≥5.19).
// Reserves only sizeof(tls_event_hdr) + actual payload bytes instead of 32 KB.
static __always_inline int emit_event_dynptr(struct pt_regs *ctx, const void *buf, __u32 len, __u8 direction, __u64 ssl_ptr)
{
    struct bpf_dynptr dp;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 read_len = len;
    if (read_len >= MAX_DATA) read_len = MAX_DATA - 1;

    if (read_len > 0) {
        char sample_hdr[64] = {};
        __u32 sample_len = read_len < 64 ? read_len : 64;
        bpf_probe_read_user(sample_hdr, sample_len, buf);
        if (should_sample_out(sample_hdr, sample_len)) {
            return 0;
        }
    }

    __u32 total_size = ((__u32)sizeof(struct tls_event_hdr)) + read_len;
    if (bpf_ringbuf_reserve_dynptr(&events, total_size, 0, &dp) < 0) {
        return 0;
    }

    struct tls_event_hdr *hdr = bpf_dynptr_data(&dp, 0, sizeof(struct tls_event_hdr));
    if (!hdr) {
        bpf_ringbuf_discard_dynptr(&dp, 0);
        return 0;
    }

    hdr->ts_ns = bpf_ktime_get_ns();
    hdr->pid = pid;
    hdr->tid = tid;
    hdr->ssl_ptr = ssl_ptr;
    hdr->data_len = read_len;
    hdr->direction = direction;
    hdr->ip_family = 0;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->netns_ino = 0;
    hdr->src_port = 0;
    hdr->dst_port = 0;
    hdr->src_ip4 = 0;
    hdr->dst_ip4 = 0;
    __builtin_memset(hdr->src_ip6, 0, sizeof(hdr->src_ip6));
    __builtin_memset(hdr->dst_ip6, 0, sizeof(hdr->dst_ip6));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy = NULL;
    bpf_core_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (nsproxy) {
        struct net *net_ns = NULL;
        bpf_core_read(&net_ns, sizeof(net_ns), &nsproxy->net_ns);
        if (net_ns) {
            unsigned int ino = 0;
            bpf_core_read(&ino, sizeof(ino), &net_ns->ns.inum);
            hdr->netns_ino = ino;
        }
    }

    struct conn_info *info = bpf_map_lookup_elem(&active_connections, &pid_tgid);
    if (!info || (info->src_ip4 == 0 && info->dst_ip4 == 0
                  && __builtin_memcmp(info->src_ip6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0)) {
        info = bpf_map_lookup_elem(&ssl_ptr_to_conn, &ssl_ptr);
    }
    if (info) {
        hdr->src_port = info->src_port;
        hdr->dst_port = info->dst_port;
        if (info->family == AF_INET6) {
            hdr->ip_family = 6;
            __builtin_memcpy(hdr->src_ip6, info->src_ip6, sizeof(hdr->src_ip6));
            __builtin_memcpy(hdr->dst_ip6, info->dst_ip6, sizeof(hdr->dst_ip6));
        } else if (info->family == AF_INET) {
            hdr->ip_family = 4;
            hdr->src_ip4 = info->src_ip4;
            hdr->dst_ip4 = info->dst_ip4;
        }
    }

    if (read_len > 0) {
        __u32 scratch_key = 0;
        char *scratch = bpf_map_lookup_elem(&dynptr_scratch, &scratch_key);
        if (!scratch) {
            bpf_ringbuf_discard_dynptr(&dp, 0);
            return 0;
        }
        bpf_probe_read_user(scratch, read_len & (MAX_DATA - 1), buf);
        bpf_dynptr_write(&dp, sizeof(struct tls_event_hdr), scratch, read_len & (MAX_DATA - 1), 0);
    }

    bpf_ringbuf_submit_dynptr(&dp, 0);
    return 0;
}

static __always_inline int emit_event(struct pt_regs *ctx, const void *buf, __u32 len, __u8 direction, __u64 ssl_ptr)
{
    __u32 dynptr_key = 0;
    __u32 *dynptr_flag = bpf_map_lookup_elem(&use_dynptr, &dynptr_key);
    if (dynptr_flag && *dynptr_flag) {
        return emit_event_dynptr(ctx, buf, len, direction, ssl_ptr);
    }

    struct tls_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 read_len = len;
    if (read_len >= MAX_DATA) read_len = MAX_DATA - 1;

    // Apply sampling filter
    if (read_len > 0) {
        char sample_hdr[64] = {};
        __u32 sample_len = read_len < 64 ? read_len : 64;
        bpf_probe_read_user(sample_hdr, sample_len, buf);
        if (should_sample_out(sample_hdr, sample_len)) {
            return 0;
        }
    }

    /* Production Fix: Use constant size for verifier stability.
     * Some kernels/distros reject dynamic size in ringbuf_reserve even if bounded.
     * By using sizeof(struct tls_event), we use a compile-time constant.
     */
    e = bpf_ringbuf_reserve(&events, sizeof(struct tls_event), 0);
    if (!e) {
        return 0;
    }
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->ssl_ptr = ssl_ptr;
    e->data_len = read_len;
    e->direction = direction;
    e->ip_family = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->netns_ino = 0;
    e->src_port = 0;
    e->dst_port = 0;
    e->src_ip4 = 0;
    e->dst_ip4 = 0;
    __builtin_memset(e->src_ip6, 0, sizeof(e->src_ip6));
    __builtin_memset(e->dst_ip6, 0, sizeof(e->dst_ip6));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy = NULL;
    bpf_core_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (nsproxy) {
        struct net *net_ns = NULL;
        bpf_core_read(&net_ns, sizeof(net_ns), &nsproxy->net_ns);
        if (net_ns) {
            unsigned int ino = 0;
            bpf_core_read(&ino, sizeof(ino), &net_ns->ns.inum);
            e->netns_ino = ino;
        }
    }

    // Prefer pid_tgid-based connection info; fall back to ssl_ptr-based mapping
    // for async runtimes where the SSL thread differs from the connect thread.
    struct conn_info *info = bpf_map_lookup_elem(&active_connections, &pid_tgid);
    if (!info || (info->src_ip4 == 0 && info->dst_ip4 == 0
                  && __builtin_memcmp(info->src_ip6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0)) {
        info = bpf_map_lookup_elem(&ssl_ptr_to_conn, &ssl_ptr);
    }
    if (info) {
        e->src_port = info->src_port;
        e->dst_port = info->dst_port;
        if (info->family == AF_INET6) {
            e->ip_family = 6;
            __builtin_memcpy(e->src_ip6, info->src_ip6, sizeof(e->src_ip6));
            __builtin_memcpy(e->dst_ip6, info->dst_ip6, sizeof(e->dst_ip6));
        } else if (info->family == AF_INET) {
            e->ip_family = 4;
            e->src_ip4 = info->src_ip4;
            e->dst_ip4 = info->dst_ip4;
        }
    }

    /* Verification already ensured read_len < MAX_DATA. */
    e->data_len = read_len;
    if (read_len > 0)
        bpf_probe_read_user(e->data, read_len & (MAX_DATA - 1), buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_connect")
int tcp_connect_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    struct conn_info info = {};
    fill_conn_info(&info, sk);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_connections, &pid_tgid, &info, BPF_ANY);
    __u64 sk_ptr = (__u64)sk;
    bpf_map_update_elem(&sock_to_pid, &sk_ptr, &pid_tgid, BPF_ANY);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int tcp_accept_ret(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) {
        return 0;
    }
    struct conn_info info = {};
    fill_conn_info(&info, sk);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_connections, &pid_tgid, &info, BPF_ANY);
    __u64 sk_ptr = (__u64)sk;
    bpf_map_update_elem(&sock_to_pid, &sk_ptr, &pid_tgid, BPF_ANY);
    return 0;
}

// OpenSSL/BoringSSL
SEC("uprobe/SSL_write")
int ssl_write_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (const void *)PT_REGS_PARM2(ctx);
    args.len = (__u32)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_ptr_to_pid, &args.ssl_ptr, &pid_tgid, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int ssl_write_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_args *args = bpf_map_lookup_elem(&ssl_write_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) {
        return 0;
    }
    if (ret > 0) {
        emit_event(ctx, args->buf, (__u32)ret, 1, args->ssl_ptr);
    }
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_read")
int ssl_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (const void *)PT_REGS_PARM2(ctx);
    args.len = (__u32)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_ptr_to_pid, &args.ssl_ptr, &pid_tgid, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int ssl_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) {
        return 0;
    }
    if (ret > 0) {
        emit_event(ctx, args->buf, (__u32)ret, 0, args->ssl_ptr);
    }
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
    return 0;
}

// OpenSSL 1.1+/3.x extended APIs
SEC("uprobe/SSL_read_ex")
int ssl_read_ex_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_ex_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.len = (__u64)PT_REGS_PARM3(ctx);
    args.bytes_ptr = (__u64 *)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&ssl_read_ex_args, &pid_tgid, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_ptr_to_pid, &args.ssl_ptr, &pid_tgid, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int ssl_read_ex_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_ex_args *args = bpf_map_lookup_elem(&ssl_read_ex_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) {
        return 0;
    }
    if (ret > 0 && args->bytes_ptr) {
        __u64 bytes = 0;
        if (bpf_probe_read_user(&bytes, sizeof(bytes), args->bytes_ptr) == 0) {
            if (bytes > 0) {
                emit_event(ctx, args->buf, (__u32)bytes, 0, args->ssl_ptr);
            }
        }
    }
    bpf_map_delete_elem(&ssl_read_ex_args, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_write_ex")
int ssl_write_ex_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_ex_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (const void *)PT_REGS_PARM2(ctx);
    args.len = (__u64)PT_REGS_PARM3(ctx);
    args.bytes_ptr = (__u64 *)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&ssl_write_ex_args, &pid_tgid, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_ptr_to_pid, &args.ssl_ptr, &pid_tgid, BPF_ANY);
    return 0;
}

// SSL_set_fd(SSL *ssl, int fd) — resolve ssl_ptr -> socket for async runtimes.
SEC("uprobe/SSL_set_fd")
int ssl_set_fd_entry(struct pt_regs *ctx)
{
    __u64 ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    int fd = (int)PT_REGS_PARM2(ctx);
    if (fd < 0) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = NULL;
    bpf_core_read(&files, sizeof(files), &task->files);
    if (!files) {
        return 0;
    }

    struct fdtable *fdt = NULL;
    bpf_core_read(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt) {
        return 0;
    }

    struct file **fdarray = NULL;
    bpf_core_read(&fdarray, sizeof(fdarray), &fdt->fd);
    if (!fdarray) {
        return 0;
    }

    struct file *filep = NULL;
    bpf_core_read(&filep, sizeof(filep), &fdarray[fd]);
    if (!filep) {
        return 0;
    }

    // file->private_data points to struct socket for socket fds
    void *private_data = NULL;
    bpf_core_read(&private_data, sizeof(private_data), &filep->private_data);
    if (!private_data) {
        return 0;
    }

    struct socket *sock = (struct socket *)private_data;
    struct sock *sk = NULL;
    bpf_core_read(&sk, sizeof(sk), &sock->sk);
    if (!sk) {
        return 0;
    }

    struct conn_info info = {};
    fill_conn_info(&info, sk);
    bpf_map_update_elem(&ssl_ptr_to_conn, &ssl_ptr, &info, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_free")
int ssl_free_entry(struct pt_regs *ctx)
{
    __u64 ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    __u64 *owner = bpf_map_lookup_elem(&ssl_ptr_to_pid, &ssl_ptr);
    __u64 pid_tgid = owner ? *owner : bpf_get_current_pid_tgid();

    struct close_event *e = bpf_ringbuf_reserve(&close_events, sizeof(*e), 0);
    if (e) {
        e->ts_ns = bpf_ktime_get_ns();
        e->pid = pid_tgid >> 32;
        e->tid = (__u32)pid_tgid;
        e->ssl_ptr = ssl_ptr;
        bpf_ringbuf_submit(e, 0);
    }

    // Only clean up ssl_ptr-keyed maps.  Do NOT delete from pid_tgid-keyed
    // args maps — in async runtimes the looked-up pid_tgid may belong to a
    // different, still-active connection.  Args maps self-clean in each
    // uretprobe exit handler after the operation completes.
    bpf_map_delete_elem(&ssl_ptr_to_pid, &ssl_ptr);
    bpf_map_delete_elem(&ssl_ptr_to_conn, &ssl_ptr);
    bpf_map_delete_elem(&active_connections, &pid_tgid);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int ssl_write_ex_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_ex_args *args = bpf_map_lookup_elem(&ssl_write_ex_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) {
        return 0;
    }
    if (ret > 0 && args->bytes_ptr) {
        __u64 bytes = 0;
        if (bpf_probe_read_user(&bytes, sizeof(bytes), args->bytes_ptr) == 0) {
            if (bytes > 0) {
                emit_event(ctx, args->buf, (__u32)bytes, 1, args->ssl_ptr);
            }
        }
    }
    bpf_map_delete_elem(&ssl_write_ex_args, &pid_tgid);
    return 0;
}

// GnuTLS
SEC("uprobe/gnutls_record_send")
int gnutls_send_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (const void *)PT_REGS_PARM2(ctx);
    args.len = (__u32)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&gnutls_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_record_send")
int gnutls_send_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_args *args = bpf_map_lookup_elem(&gnutls_write_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) {
        return 0;
    }
    if (ret > 0) {
        emit_event(ctx, args->buf, (__u32)ret, 1, args->ssl_ptr);
    }
    bpf_map_delete_elem(&gnutls_write_args, &pid_tgid);
    return 0;
}

SEC("uprobe/gnutls_record_recv")
int gnutls_recv_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (const void *)PT_REGS_PARM2(ctx);
    args.len = (__u32)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&gnutls_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_record_recv")
int gnutls_recv_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args *args = bpf_map_lookup_elem(&gnutls_read_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) {
        return 0;
    }
    if (ret > 0) {
        emit_event(ctx, args->buf, (__u32)ret, 0, args->ssl_ptr);
    }
    bpf_map_delete_elem(&gnutls_read_args, &pid_tgid);
    return 0;
}

// Helper to get goroutine ID
// x86_64: read from fsbase + goid_offset
// arm64: read from TPIDR_EL0 (tp_value) + goid_offset
static __always_inline __u64 get_goroutine_id(void)
{
    __u64 goroutine_id = 0;
    __u32 key = 0;
    __u64 *offset_ptr = bpf_map_lookup_elem(&go_goid_offset, &key);
    __u64 goid_offset = offset_ptr ? *offset_ptr : 152; // default Go 1.18+

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if defined(__TARGET_ARCH_x86)
    __u64 fsbase = 0;
    bpf_core_read(&fsbase, sizeof(fsbase), &task->thread.fsbase);
    if (fsbase != 0) {
        bpf_probe_read_user(&goroutine_id, sizeof(goroutine_id),
                            (void *)(fsbase + goid_offset));
    }
#elif defined(__TARGET_ARCH_arm64)
    __u64 tp_value = 0;
    bpf_core_read(&tp_value, sizeof(tp_value), &task->thread.uw.tp_value);
    if (tp_value != 0) {
        bpf_probe_read_user(&goroutine_id, sizeof(goroutine_id),
                            (void *)(tp_value + goid_offset));
    }
#endif

    if (goroutine_id == 0) {
        goroutine_id = bpf_get_current_pid_tgid();
    }
    return goroutine_id;
}

// Go TLS (*Conn).Write entry — attached at function start offset from userspace
// Go ABIInternal x86_64: conn=AX, buf.ptr=BX, buf.len=CX
// Go ABIInternal arm64:  conn=R0, buf.ptr=R1, buf.len=R2
SEC("uprobe/go_tls_write_entry")
int go_tls_write_entry(struct pt_regs *ctx)
{
    __u64 goroutine_id = get_goroutine_id();
    struct go_write_args args = {};

#if defined(__TARGET_ARCH_x86)
    args.conn_ptr = ctx->ax;
    args.buf_ptr  = ctx->bx;
    args.buf_len  = (__u32)ctx->cx;
#elif defined(__TARGET_ARCH_arm64)
    args.conn_ptr = ctx->regs[0];
    args.buf_ptr  = ctx->regs[1];
    args.buf_len  = (__u32)ctx->regs[2];
#endif

    bpf_map_update_elem(&go_tls_write_args, &goroutine_id, &args, BPF_ANY);
    return 0;
}

// Go TLS (*Conn).Write exit — attached at each RET instruction offset from userspace
SEC("uprobe/go_tls_write_exit")
int go_tls_write_exit(struct pt_regs *ctx)
{
    __u64 goroutine_id = get_goroutine_id();
    struct go_write_args *args = bpf_map_lookup_elem(&go_tls_write_args, &goroutine_id);
    if (!args) return 0;

    // Return value (n int) is in AX on x86_64, R0 on arm64
    __u32 n = 0;
#if defined(__TARGET_ARCH_x86)
    n = (__u32)ctx->ax;
#elif defined(__TARGET_ARCH_arm64)
    n = (__u32)ctx->regs[0];
#endif

    if (n > 0) {
        emit_event(ctx, (const void *)args->buf_ptr, n, 1, args->conn_ptr);
    }
    bpf_map_delete_elem(&go_tls_write_args, &goroutine_id);
    return 0;
}

// Go TLS (*Conn).Read entry
SEC("uprobe/go_tls_read_entry")
int go_tls_read_entry(struct pt_regs *ctx)
{
    __u64 goroutine_id = get_goroutine_id();
    struct go_read_args args = {};

#if defined(__TARGET_ARCH_x86)
    args.conn_ptr = ctx->ax;
    args.buf_ptr  = ctx->bx;
    args.buf_len  = (__u32)ctx->cx;
#elif defined(__TARGET_ARCH_arm64)
    args.conn_ptr = ctx->regs[0];
    args.buf_ptr  = ctx->regs[1];
    args.buf_len  = (__u32)ctx->regs[2];
#endif

    bpf_map_update_elem(&go_tls_read_args, &goroutine_id, &args, BPF_ANY);
    return 0;
}

// Go TLS (*Conn).Read exit — attached at each RET instruction offset
SEC("uprobe/go_tls_read_exit")
int go_tls_read_exit(struct pt_regs *ctx)
{
    __u64 goroutine_id = get_goroutine_id();
    struct go_read_args *args = bpf_map_lookup_elem(&go_tls_read_args, &goroutine_id);
    if (!args) return 0;

    __u32 n = 0;
#if defined(__TARGET_ARCH_x86)
    n = (__u32)ctx->ax;
#elif defined(__TARGET_ARCH_arm64)
    n = (__u32)ctx->regs[0];
#endif

    if (n > 0) {
        emit_event(ctx, (const void *)args->buf_ptr, n, 0, args->conn_ptr);
    }
    bpf_map_delete_elem(&go_tls_read_args, &goroutine_id);
    return 0;
}

// ---------------------------------------------------------------------------
// QUIC library probes (quiche, ngtcp2, lsquic)
//
// These capture decrypted HTTP/3 stream data from QUIC libraries.
// Signature (quiche):
//   ssize_t quiche_conn_stream_recv(conn, stream_id, buf, buf_len, &fin);
//   ssize_t quiche_conn_stream_send(conn, stream_id, buf, buf_len,  fin);
// ngtcp2 application stream data follows a similar pattern.
// ---------------------------------------------------------------------------

struct quic_stream_args {
    __u64 conn_ptr;
    __u64 stream_id;
    void *buf;
    __u32 buf_len;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct quic_stream_args);
} quic_recv_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct quic_stream_args);
} quic_send_args SEC(".maps");

// quiche_conn_stream_recv(conn, stream_id, buf, buf_len, &fin)
SEC("uprobe/quic_stream_recv")
int quic_stream_recv_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct quic_stream_args args = {};
    args.conn_ptr  = (__u64)PT_REGS_PARM1(ctx);
    args.stream_id = (__u64)PT_REGS_PARM2(ctx);
    args.buf       = (void *)PT_REGS_PARM3(ctx);
    args.buf_len   = (__u32)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&quic_recv_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/quic_stream_recv")
int quic_stream_recv_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct quic_stream_args *args = bpf_map_lookup_elem(&quic_recv_args, &pid_tgid);
    long ret = (long)PT_REGS_RC(ctx);
    if (!args) return 0;
    if (ret > 0) {
        __u32 len = (__u32)ret;
        len &= (MAX_DATA - 1);
        // direction 0 = READ (ingress)
        emit_event(ctx, args->buf, len, 0, args->conn_ptr);
    }
    bpf_map_delete_elem(&quic_recv_args, &pid_tgid);
    return 0;
}

// quiche_conn_stream_send(conn, stream_id, buf, buf_len, fin)
SEC("uprobe/quic_stream_send")
int quic_stream_send_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct quic_stream_args args = {};
    args.conn_ptr  = (__u64)PT_REGS_PARM1(ctx);
    args.stream_id = (__u64)PT_REGS_PARM2(ctx);
    args.buf       = (void *)PT_REGS_PARM3(ctx);
    args.buf_len   = (__u32)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&quic_send_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/quic_stream_send")
int quic_stream_send_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct quic_stream_args *args = bpf_map_lookup_elem(&quic_send_args, &pid_tgid);
    long ret = (long)PT_REGS_RC(ctx);
    if (!args) return 0;
    if (ret > 0) {
        __u32 len = (__u32)ret;
        len &= (MAX_DATA - 1);
        // direction 1 = WRITE (egress)
        emit_event(ctx, args->buf, len, 1, args->conn_ptr);
    }
    bpf_map_delete_elem(&quic_send_args, &pid_tgid);
    return 0;
}

SEC("kprobe/tcp_close")
int tcp_close_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u64 sk_ptr = (__u64)sk;

    // Look up which thread originally opened this connection.  tcp_close may
    // be called from a thread different from the one that called tcp_connect /
    // inet_csk_accept, so using bpf_get_current_pid_tgid() here would delete
    // the wrong (or no) entry in active_connections, leaking the original
    // entry forever.
    __u64 *owner = bpf_map_lookup_elem(&sock_to_pid, &sk_ptr);
    __u64 pid_tgid = owner ? *owner : bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&active_connections, &pid_tgid);
    bpf_map_delete_elem(&sock_to_pid, &sk_ptr);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_new_process(struct trace_event_raw_sched_process_exec *ctx)
{
    struct new_proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // __data_loc encoding: lower 16 bits = offset, upper 16 bits = length
    __u32 data_loc = ctx->__data_loc_filename;
    __u16 offset   = (__u16)(data_loc & 0xFFFF);
    const char *fn = (const char *)ctx + offset;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), fn);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
