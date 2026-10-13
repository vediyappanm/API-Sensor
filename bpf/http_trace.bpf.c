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
#ifndef EPERM
#define EPERM 1
#endif

// Capture ABI version — bump together with types.rs:TLS_EVENT_ABI_VERSION.
#define TLS_EVENT_ABI_VERSION 2

// tls_event_hdr.flags
#define FLAG_TRUNCATED   (1 << 0)
#define FLAG_ATTR_SSL    (1 << 1)
#define FLAG_ATTR_THREAD (1 << 2)

// tls_event_hdr.attribution
#define ATTR_NONE   0
#define ATTR_SSL    1
#define ATTR_THREAD 2

// tls_event_hdr.provider_id
#define PROVIDER_OPENSSL 1
#define PROVIDER_GNUTLS  2
#define PROVIDER_GO_TLS  3
#define PROVIDER_QUIC    4
#define PROVIDER_KTLS    5
#define PROVIDER_NSS     6

// conn_info.role / tls_event_hdr.role_hint
#define ROLE_SERVER 1
#define ROLE_CLIENT 2

// Fixed header — layout must match types.rs:TlsEventHeader exactly (no implicit padding).
// Used as the dynptr-path event header (no trailing data[] array).
struct tls_event_hdr {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl_ptr;
    __u32 data_len;  // == copied_len
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
    // ABI v2
    __u16 abi_version;
    __u16 flags;
    __u32 actual_len;      // bytes the TLS call returned
    __u32 copied_len;      // bytes present after this header
    __u32 conn_generation; // bumped on SSL_free so a reused pointer is a new connection
    __u64 proc_start_ns;   // thread-group leader start time: process incarnation
    __u32 dir_seq;         // per-connection, per-direction attempt counter (gaps = loss)
    __u8  attribution;
    __u8  provider_id;
    __u8  role_hint;
    __u8  _pad8;
    __u64 sock_cookie;     // socket inode when known, else 0
};

// Full fixed-size event (fallback for kernels < 5.19 without dynptr support).
struct tls_event {
    struct tls_event_hdr hdr;
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
    __u64 proc_start_ns;
    __u32 generation;
    __u32 _pad;
};

// TLS state is keyed per process: the same virtual address in two processes is two objects (F03).
struct ssl_key {
    __u32 tgid;
    __u32 _pad;
    __u64 ptr;
};

struct ssl_state {
    __u32 generation;
    __u32 seq[2];
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ssl_key);
    __type(value, struct ssl_state);
} ssl_state_map SEC(".maps");

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
    __type(key, struct ssl_key);
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

// Tuple is local (src) / remote (dst) as seen by the traced process; role says who initiated.
struct conn_info {
    __u16 family;
    __u16 src_port;
    __u16 dst_port;
    __u8  role;
    __u8  _pad;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u8 src_ip6[16];
    __u8 dst_ip6[16];
    __u64 sock_ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); // pid_tgid
    __type(value, struct conn_info);
} active_connections SEC(".maps");

// (tgid, ssl_ptr) -> conn_info: populated by SSL_set_fd. Exact association, preferred over
// the per-thread fallback in active_connections.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ssl_key);
    __type(value, struct conn_info);
} ssl_ptr_to_conn SEC(".maps");

// struct sock * -> ROLE_SERVER / ROLE_CLIENT, recorded at accept/connect for SSL_set_fd.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} sock_role SEC(".maps");

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

// A goroutine can move between OS threads inside one call, so entry/exit are paired by the
// goroutine's `g` pointer within one process, never by thread id.
struct go_call_key {
    __u32 tgid;
    __u32 _pad;
    __u64 g;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct go_call_key);
    __type(value, struct go_write_args);
} go_tls_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct go_call_key);
    __type(value, struct go_read_args);
} go_tls_read_args SEC(".maps");

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

// Per-CPU producer loss counters (F02, F09): track BPF-side losses separately
// from userspace polling drops. Index layout:
// 0 = attempted records, 1 = submitted records, 2 = reserve failures,
// 3 = copy failures, 4 = intentional sampling, 5 = map failures
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} producer_stats SEC(".maps");

// Per-CPU scratch buffer for dynptr payload writes (avoids BPF stack limit).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_DATA]);
} dynptr_scratch SEC(".maps");

// Set by userspace BEFORE load on kernel >=5.19. It lives in frozen read-only data so the
// verifier prunes the dynptr branch on older kernels, where its helpers do not exist.
// The section holds only this value: userspace writes it at offset 0 of map ".rodata.cfg".
const volatile __u32 cfg_use_dynptr SEC(".rodata.cfg") = 0;

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

    struct socket *skt = NULL;
    bpf_core_read(&skt, sizeof(skt), &sk->sk_socket);
    if (skt) {
        struct file *f = NULL;
        bpf_core_read(&f, sizeof(f), &skt->file);
        if (f) {
            struct inode *ino = NULL;
            bpf_core_read(&ino, sizeof(ino), &f->f_inode);
            if (ino) {
                unsigned long i_ino = 0;
                bpf_core_read(&i_ino, sizeof(i_ino), &ino->i_ino);
                out->sock_ino = i_ino;
            }
        }
    }
}

static __always_inline void ssl_key_for(struct ssl_key *k, __u64 ptr)
{
    k->tgid = bpf_get_current_pid_tgid() >> 32;
    k->_pad = 0;
    k->ptr = ptr;
}

static __always_inline void remember_ssl_owner(__u64 ssl_ptr, __u64 pid_tgid)
{
    struct ssl_key k;
    ssl_key_for(&k, ssl_ptr);
    bpf_map_update_elem(&ssl_ptr_to_pid, &k, &pid_tgid, BPF_ANY);
}

static __always_inline __u64 current_proc_start_ns(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *leader = NULL;
    __u64 start = 0;
    bpf_core_read(&leader, sizeof(leader), &task->group_leader);
    if (leader) {
        bpf_core_read(&start, sizeof(start), &leader->start_time);
    }
    return start;
}

static __always_inline void count_stat(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&producer_stats, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

// Current generation and the next per-direction sequence number for this TLS object.
static __always_inline void next_seq(__u64 ssl_ptr, __u8 direction, __u32 *generation, __u32 *seq)
{
    struct ssl_key k;
    ssl_key_for(&k, ssl_ptr);
    struct ssl_state *st = bpf_map_lookup_elem(&ssl_state_map, &k);
    if (!st) {
        struct ssl_state init = {};
        bpf_map_update_elem(&ssl_state_map, &k, &init, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&ssl_state_map, &k);
    }
    if (!st) {
        *generation = 0;
        *seq = 0;
        count_stat(5);
        return;
    }
    *generation = st->generation;
    // TLS libraries serialise I/O per object and direction; a fetch-and-add that
    // returns the old value would require BPF ISA v3 (kernel 5.12+).
    __u32 cur = st->seq[direction & 1];
    st->seq[direction & 1] = cur + 1;
    *seq = cur;
}

// Populate every header field. Payload bytes are written by the caller.
static __always_inline void fill_event_hdr(struct tls_event_hdr *hdr, __u64 pid_tgid, __u64 ssl_ptr,
                                           __u32 actual_len, __u32 copy_len, __u8 direction,
                                           __u8 provider, __u32 generation, __u32 seq)
{
    hdr->ts_ns = bpf_ktime_get_ns();
    hdr->pid = pid_tgid >> 32;
    hdr->tid = (__u32)pid_tgid;
    hdr->ssl_ptr = ssl_ptr;
    hdr->data_len = copy_len;
    hdr->direction = direction;
    hdr->ip_family = 0;
    hdr->_pad16 = 0;
    __builtin_memset(hdr->comm, 0, sizeof(hdr->comm));
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->netns_ino = 0;
    hdr->src_port = 0;
    hdr->dst_port = 0;
    hdr->src_ip4 = 0;
    hdr->dst_ip4 = 0;
    __builtin_memset(hdr->src_ip6, 0, sizeof(hdr->src_ip6));
    __builtin_memset(hdr->dst_ip6, 0, sizeof(hdr->dst_ip6));
    hdr->abi_version = TLS_EVENT_ABI_VERSION;
    hdr->flags = actual_len > copy_len ? FLAG_TRUNCATED : 0;
    hdr->actual_len = actual_len;
    hdr->copied_len = copy_len;
    hdr->conn_generation = generation;
    hdr->proc_start_ns = current_proc_start_ns();
    hdr->dir_seq = seq;
    hdr->attribution = ATTR_NONE;
    hdr->provider_id = provider;
    hdr->role_hint = 0;
    hdr->_pad8 = 0;
    hdr->sock_cookie = 0;

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

    // Prefer the exact (process, TLS object) association. The per-thread entry is only a
    // fallback: an event-loop thread serves many sockets, so it is marked low confidence.
    struct ssl_key k;
    ssl_key_for(&k, ssl_ptr);
    struct conn_info *info = bpf_map_lookup_elem(&ssl_ptr_to_conn, &k);
    if (info) {
        hdr->attribution = ATTR_SSL;
        hdr->flags |= FLAG_ATTR_SSL;
    } else {
        info = bpf_map_lookup_elem(&active_connections, &pid_tgid);
        if (info) {
            hdr->attribution = ATTR_THREAD;
            hdr->flags |= FLAG_ATTR_THREAD;
        }
    }
    if (info) {
        hdr->src_port = info->src_port;
        hdr->dst_port = info->dst_port;
        hdr->role_hint = info->role;
        hdr->sock_cookie = info->sock_ino;
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
static __always_inline int emit_event_dynptr(struct pt_regs *ctx, const void *buf, __u32 len, __u8 direction,
                                             __u64 ssl_ptr, __u8 provider)
{
    struct bpf_dynptr dp;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 read_len = len;
    if (read_len >= MAX_DATA) read_len = MAX_DATA - 1;

    // F02, F09: count attempted records; the sequence advances even if the record is lost.
    count_stat(0);
    __u32 generation = 0, seq = 0;
    next_seq(ssl_ptr, direction, &generation, &seq);

    if (read_len > 0) {
        char sample_hdr[64] = {};
        __u32 sample_len = read_len < 64 ? read_len : 64;
        bpf_probe_read_user(sample_hdr, sample_len, buf);
        if (should_sample_out(sample_hdr, sample_len)) {
            count_stat(4);
            return 0;
        }
    }

    __u32 total_size = ((__u32)sizeof(struct tls_event_hdr)) + read_len;
    /* Invert the reserve check: branch into the SUCCESS block, let FAILURE fall
     * through to the unconditional discard below.  When the condition is
     * (reserve < 0), clang emits a direct jump to the caller's return/cleanup
     * code, which bypasses the discard and causes the BPF verifier to complain
     * "Unreleased reference" for the dynptr's ref_id.  By making SUCCESS the
     * taken branch, the failure path is always the fall-through and the discard
     * cannot be optimized away. */
    if (bpf_ringbuf_reserve_dynptr(&events, total_size, 0, &dp) >= 0) {
        struct tls_event_hdr *hdr = bpf_dynptr_data(&dp, 0, sizeof(struct tls_event_hdr));
        if (!hdr) {
            count_stat(2);
            bpf_ringbuf_discard_dynptr(&dp, 0);
            return 0;
        }

        // F02: initialize all header fields before any payload copy
        fill_event_hdr(hdr, pid_tgid, ssl_ptr, len, read_len, direction, provider, generation, seq);

        // F02: check copy return values; discard on failure and count as copy error
        if (read_len > 0) {
            __u32 scratch_key = 0;
            char *scratch = bpf_map_lookup_elem(&dynptr_scratch, &scratch_key);
            if (!scratch) {
                count_stat(3);
                bpf_ringbuf_discard_dynptr(&dp, 0);
                return 0;
            }
            __u32 copy_len = read_len & (MAX_DATA - 1);
            if (bpf_probe_read_user(scratch, copy_len, buf) != 0) {
                count_stat(3);
                bpf_ringbuf_discard_dynptr(&dp, 0);
                return 0;
            }
            if (bpf_dynptr_write(&dp, sizeof(struct tls_event_hdr), scratch, copy_len, 0) != 0) {
                count_stat(3);
                bpf_ringbuf_discard_dynptr(&dp, 0);
                return 0;
            }
        }

        count_stat(1);
        bpf_ringbuf_submit_dynptr(&dp, 0);
        return 0;
    }
    /* Reserve failed — discard releases the verifier's reference tracking even
     * though the dynptr holds no valid ring-buffer slot at runtime. */
    count_stat(2);
    bpf_ringbuf_discard_dynptr(&dp, 0);
    return 0;
}

static __always_inline int emit_event(struct pt_regs *ctx, const void *buf, __u32 len, __u8 direction,
                                      __u64 ssl_ptr, __u8 provider)
{
    if (cfg_use_dynptr) {
        return emit_event_dynptr(ctx, buf, len, direction, ssl_ptr, provider);
    }

    struct tls_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 read_len = len;
    if (read_len >= MAX_DATA) read_len = MAX_DATA - 1;

    count_stat(0);
    __u32 generation = 0, seq = 0;
    next_seq(ssl_ptr, direction, &generation, &seq);

    if (read_len > 0) {
        char sample_hdr[64] = {};
        __u32 sample_len = read_len < 64 ? read_len : 64;
        bpf_probe_read_user(sample_hdr, sample_len, buf);
        if (should_sample_out(sample_hdr, sample_len)) {
            count_stat(4);
            return 0;
        }
    }

    /* Production Fix: Use constant size for verifier stability.
     * Some kernels/distros reject dynamic size in ringbuf_reserve even if bounded.
     * By using sizeof(struct tls_event), we use a compile-time constant.
     */
    e = bpf_ringbuf_reserve(&events, sizeof(struct tls_event), 0);
    if (!e) {
        count_stat(2);
        return 0;
    }

    fill_event_hdr(&e->hdr, pid_tgid, ssl_ptr, len, read_len, direction, provider, generation, seq);

    if (read_len > 0) {
        if (bpf_probe_read_user(e->data, read_len & (MAX_DATA - 1), buf) != 0) {
            count_stat(3);
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
    }

    count_stat(1);
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
    info.role = ROLE_CLIENT;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_connections, &pid_tgid, &info, BPF_ANY);
    __u64 sk_ptr = (__u64)sk;
    bpf_map_update_elem(&sock_to_pid, &sk_ptr, &pid_tgid, BPF_ANY);
    __u8 role = ROLE_CLIENT;
    bpf_map_update_elem(&sock_role, &sk_ptr, &role, BPF_ANY);
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
    info.role = ROLE_SERVER;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_connections, &pid_tgid, &info, BPF_ANY);
    __u64 sk_ptr = (__u64)sk;
    bpf_map_update_elem(&sock_to_pid, &sk_ptr, &pid_tgid, BPF_ANY);
    __u8 role = ROLE_SERVER;
    bpf_map_update_elem(&sock_role, &sk_ptr, &role, BPF_ANY);
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
    remember_ssl_owner(args.ssl_ptr, pid_tgid);
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
        emit_event(ctx, args->buf, (__u32)ret, 1, args->ssl_ptr, PROVIDER_OPENSSL);
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
    remember_ssl_owner(args.ssl_ptr, pid_tgid);
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
        emit_event(ctx, args->buf, (__u32)ret, 0, args->ssl_ptr, PROVIDER_OPENSSL);
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
    remember_ssl_owner(args.ssl_ptr, pid_tgid);
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
                emit_event(ctx, args->buf, (__u32)bytes, 0, args->ssl_ptr, PROVIDER_OPENSSL);
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
    remember_ssl_owner(args.ssl_ptr, pid_tgid);
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
    __u64 sk_ptr = (__u64)sk;
    __u8 *role = bpf_map_lookup_elem(&sock_role, &sk_ptr);
    if (role) info.role = *role;
    struct ssl_key k;
    ssl_key_for(&k, ssl_ptr);
    bpf_map_update_elem(&ssl_ptr_to_conn, &k, &info, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_free")
int ssl_free_entry(struct pt_regs *ctx)
{
    __u64 ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    struct ssl_key k;
    ssl_key_for(&k, ssl_ptr);
    __u64 *owner = bpf_map_lookup_elem(&ssl_ptr_to_pid, &k);
    __u64 pid_tgid = owner ? *owner : bpf_get_current_pid_tgid();

    // The close names the generation it ends; the next object at this address gets a new one,
    // so a late close cannot evict a reused pointer's state.
    __u32 generation = 0;
    struct ssl_state *st = bpf_map_lookup_elem(&ssl_state_map, &k);
    if (st) {
        generation = st->generation;
        st->generation = generation + 1;
        st->seq[0] = 0;
        st->seq[1] = 0;
    }

    struct close_event *e = bpf_ringbuf_reserve(&close_events, sizeof(*e), 0);
    if (e) {
        e->ts_ns = bpf_ktime_get_ns();
        e->pid = pid_tgid >> 32;
        e->tid = (__u32)pid_tgid;
        e->ssl_ptr = ssl_ptr;
        e->proc_start_ns = current_proc_start_ns();
        e->generation = generation;
        e->_pad = 0;
        bpf_ringbuf_submit(e, 0);
    }

    // Only clean up ssl_ptr-keyed maps.  Do NOT delete from pid_tgid-keyed
    // args maps — in async runtimes the looked-up pid_tgid may belong to a
    // different, still-active connection.  Args maps self-clean in each
    // uretprobe exit handler after the operation completes.
    bpf_map_delete_elem(&ssl_ptr_to_pid, &k);
    bpf_map_delete_elem(&ssl_ptr_to_conn, &k);
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
                emit_event(ctx, args->buf, (__u32)bytes, 1, args->ssl_ptr, PROVIDER_OPENSSL);
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
        emit_event(ctx, args->buf, (__u32)ret, 1, args->ssl_ptr, PROVIDER_GNUTLS);
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
        emit_event(ctx, args->buf, (__u32)ret, 0, args->ssl_ptr, PROVIDER_GNUTLS);
    }
    bpf_map_delete_elem(&gnutls_read_args, &pid_tgid);
    return 0;
}

// Current goroutine for Go >= 1.17 (register ABI): R14 on amd64, R28 on arm64.
// Older Go releases are refused in userspace. Returns 0 when no goroutine is available,
// in which case the call is skipped rather than paired by thread.
static __always_inline int go_call_key_for(struct pt_regs *ctx, struct go_call_key *k)
{
    __u64 g = 0;
#if defined(__TARGET_ARCH_x86)
    g = ctx->r14;
#elif defined(__TARGET_ARCH_arm64)
    g = ctx->regs[28];
#endif
    if (g == 0) return 0;
    k->tgid = bpf_get_current_pid_tgid() >> 32;
    k->_pad = 0;
    k->g = g;
    return 1;
}

// Go returns n as a signed int; anything outside [1, buf_len] is not a byte count we can trust.
static __always_inline __u32 go_ret_len(__s64 n, __u32 buf_len)
{
    if (n <= 0) return 0;
    if ((__u64)n > buf_len) return buf_len;
    return (__u32)n;
}

// Go TLS (*Conn).Write entry — attached at function start offset from userspace
// Go ABIInternal x86_64: conn=AX, buf.ptr=BX, buf.len=CX
// Go ABIInternal arm64:  conn=R0, buf.ptr=R1, buf.len=R2
SEC("uprobe/go_tls_write_entry")
int go_tls_write_entry(struct pt_regs *ctx)
{
    struct go_call_key k;
    if (!go_call_key_for(ctx, &k)) return 0;
    struct go_write_args args = {};

#if defined(__TARGET_ARCH_x86)
    args.conn_ptr = ctx->ax;
    args.buf_ptr  = ctx->bx;
    args.buf_len  = ctx->cx > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (__u32)ctx->cx;
#elif defined(__TARGET_ARCH_arm64)
    args.conn_ptr = ctx->regs[0];
    args.buf_ptr  = ctx->regs[1];
    args.buf_len  = ctx->regs[2] > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (__u32)ctx->regs[2];
#endif

    bpf_map_update_elem(&go_tls_write_args, &k, &args, BPF_ANY);
    return 0;
}

// Go TLS (*Conn).Write exit — attached at each RET instruction offset from userspace
SEC("uprobe/go_tls_write_exit")
int go_tls_write_exit(struct pt_regs *ctx)
{
    struct go_call_key k;
    if (!go_call_key_for(ctx, &k)) return 0;
    struct go_write_args *args = bpf_map_lookup_elem(&go_tls_write_args, &k);
    if (!args) return 0;

    // Return value (n int) is in AX on x86_64, R0 on arm64
    __s64 ret = 0;
#if defined(__TARGET_ARCH_x86)
    ret = (__s64)ctx->ax;
#elif defined(__TARGET_ARCH_arm64)
    ret = (__s64)ctx->regs[0];
#endif

    __u32 n = go_ret_len(ret, args->buf_len);
    if (n > 0) {
        emit_event(ctx, (const void *)args->buf_ptr, n, 1, args->conn_ptr, PROVIDER_GO_TLS);
    }
    bpf_map_delete_elem(&go_tls_write_args, &k);
    return 0;
}

// Go TLS (*Conn).Read entry
SEC("uprobe/go_tls_read_entry")
int go_tls_read_entry(struct pt_regs *ctx)
{
    struct go_call_key k;
    if (!go_call_key_for(ctx, &k)) return 0;
    struct go_read_args args = {};

#if defined(__TARGET_ARCH_x86)
    args.conn_ptr = ctx->ax;
    args.buf_ptr  = ctx->bx;
    args.buf_len  = ctx->cx > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (__u32)ctx->cx;
#elif defined(__TARGET_ARCH_arm64)
    args.conn_ptr = ctx->regs[0];
    args.buf_ptr  = ctx->regs[1];
    args.buf_len  = ctx->regs[2] > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (__u32)ctx->regs[2];
#endif

    bpf_map_update_elem(&go_tls_read_args, &k, &args, BPF_ANY);
    return 0;
}

// Go TLS (*Conn).Read exit — attached at each RET instruction offset
SEC("uprobe/go_tls_read_exit")
int go_tls_read_exit(struct pt_regs *ctx)
{
    struct go_call_key k;
    if (!go_call_key_for(ctx, &k)) return 0;
    struct go_read_args *args = bpf_map_lookup_elem(&go_tls_read_args, &k);
    if (!args) return 0;

    __s64 ret = 0;
#if defined(__TARGET_ARCH_x86)
    ret = (__s64)ctx->ax;
#elif defined(__TARGET_ARCH_arm64)
    ret = (__s64)ctx->regs[0];
#endif

    __u32 n = go_ret_len(ret, args->buf_len);
    if (n > 0) {
        emit_event(ctx, (const void *)args->buf_ptr, n, 0, args->conn_ptr, PROVIDER_GO_TLS);
    }
    bpf_map_delete_elem(&go_tls_read_args, &k);
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
        // emit_event caps the copy and records the full length; masking would turn 32768 into 0.
        __u32 len = ret > 0xFFFFFFFFL ? 0xFFFFFFFFU : (__u32)ret;
        // direction 0 = READ (ingress)
        emit_event(ctx, args->buf, len, 0, args->conn_ptr, PROVIDER_QUIC);
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
        __u32 len = ret > 0xFFFFFFFFL ? 0xFFFFFFFFU : (__u32)ret;
        // direction 1 = WRITE (egress)
        emit_event(ctx, args->buf, len, 1, args->conn_ptr, PROVIDER_QUIC);
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
    bpf_map_delete_elem(&sock_role, &sk_ptr);
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

// ---------------------------------------------------------------------------
// NSS TLS (libnss3): PR_Read / PR_Write
// Argument layout matches SSL_read/SSL_write — first arg used as conn handle.
// ---------------------------------------------------------------------------
SEC("uprobe/PR_Write")
int nss_write_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf     = (const void *)PT_REGS_PARM2(ctx);
    args.len     = (__u32)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/PR_Write")
int nss_write_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct write_args *args = bpf_map_lookup_elem(&ssl_write_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) return 0;
    if (ret > 0) emit_event(ctx, args->buf, (__u32)ret, 1, args->ssl_ptr, PROVIDER_NSS);
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
    return 0;
}

SEC("uprobe/PR_Read")
int nss_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf     = (const void *)PT_REGS_PARM2(ctx);
    args.len     = (__u32)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/PR_Read")
int nss_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    int ret = (int)PT_REGS_RC(ctx);
    if (!args) return 0;
    if (ret > 0) emit_event(ctx, args->buf, (__u32)ret, 0, args->ssl_ptr, PROVIDER_NSS);
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
    return 0;
}

// ---------------------------------------------------------------------------
// kTLS: tls_sw_sendmsg / tls_sw_recvmsg (CONFIG_TLS=y required)
// Captures plaintext before kernel-TLS encrypts (send) or after it decrypts
// (recv), covering apps that call setsockopt(SO_TLS_TX/SO_TLS_RX).
// ---------------------------------------------------------------------------

struct ktls_args {
    const void *iov_base;
    __u32       iov_len;
    __u64       sock_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct ktls_args);
} ktls_sendmsg_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct ktls_args);
} ktls_recvmsg_args SEC(".maps");

static __always_inline void ktls_save_args(
    struct sock *sk, struct msghdr *msg,
    struct ktls_args *args)
{
    args->sock_ptr = (__u64)sk;
    const struct iovec *iov = NULL;
    bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.__iov); /* kernel ≥6.0 field name */
    if (iov) {
        void *base = NULL;
        size_t len = 0;
        bpf_core_read(&base, sizeof(base), &iov->iov_base);
        bpf_core_read(&len,  sizeof(len),  &iov->iov_len);
        args->iov_base = base;
        args->iov_len  = (__u32)len;
    }
    if (sk) {
        struct conn_info info = {};
        fill_conn_info(&info, sk);
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&active_connections, &pid_tgid, &info, BPF_ANY);
        __u64 sk_ptr = (__u64)sk;
        bpf_map_update_elem(&sock_to_pid, &sk_ptr, &pid_tgid, BPF_ANY);
    }
}

SEC("kprobe/tls_sw_sendmsg")
int ktls_send_entry(struct pt_regs *ctx)
{
    struct sock *sk    = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct ktls_args args = {};
    ktls_save_args(sk, msg, &args);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ktls_sendmsg_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tls_sw_sendmsg")
int ktls_send_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ktls_args *args = bpf_map_lookup_elem(&ktls_sendmsg_args, &pid_tgid);
    if (!args) return 0;
    int ret = (int)PT_REGS_RC(ctx);
    if (ret > 0 && args->iov_base)
        emit_event(ctx, args->iov_base, (__u32)ret, 1, args->sock_ptr, PROVIDER_KTLS);
    bpf_map_delete_elem(&ktls_sendmsg_args, &pid_tgid);
    return 0;
}

SEC("kprobe/tls_sw_recvmsg")
int ktls_recv_entry(struct pt_regs *ctx)
{
    struct sock *sk    = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct ktls_args args = {};
    ktls_save_args(sk, msg, &args);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ktls_recvmsg_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tls_sw_recvmsg")
int ktls_recv_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ktls_args *args = bpf_map_lookup_elem(&ktls_recvmsg_args, &pid_tgid);
    if (!args) return 0;
    int ret = (int)PT_REGS_RC(ctx);
    if (ret > 0 && args->iov_base)
        emit_event(ctx, args->iov_base, (__u32)ret, 0, args->sock_ptr, PROVIDER_KTLS);
    bpf_map_delete_elem(&ktls_recvmsg_args, &pid_tgid);
    return 0;
}

// ---------------------------------------------------------------------------
// eBPF LSM: outbound IP block list (socket_connect)
// Requires CONFIG_BPF_LSM=y and "bpf" in lsm= kernel parameter.
// Userspace populates blocked_ips[] with CIDR entries and sets blocked_ips_count.
// ---------------------------------------------------------------------------

// Maximum blocked CIDR entries — kept at 16 so the verifier can prove
// loop termination via #pragma unroll (unrolled loops have no back-edge).
#define MAX_BLOCKED_CIDRS 16

struct blocked_cidr {
    __be32 ip;
    __be32 mask;
};

// ARRAY map — index 0..MAX_BLOCKED_CIDRS-1, each entry one CIDR rule.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BLOCKED_CIDRS);
    __type(key, __u32);
    __type(value, struct blocked_cidr);
} blocked_ips SEC(".maps");

// Single-entry ARRAY: blocked_ips_count[0] = number of active rules.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} blocked_ips_count SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!address || addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &address->sa_family);
    if (family != AF_INET)
        return 0;

    __be32 dst_ip = 0;
    bpf_core_read(&dst_ip, sizeof(dst_ip),
                  &((struct sockaddr_in *)address)->sin_addr.s_addr);
    if (!dst_ip) return 0;

    // Scan all slots — entries with mask==0 are unused and never match.
    // #pragma unroll produces a fixed sequence with no back-edges, which is
    // what the BPF verifier requires to prove termination.
#pragma unroll
    for (__u32 i = 0; i < MAX_BLOCKED_CIDRS; i++) {
        __u32 idx = i;
        struct blocked_cidr *cidr = bpf_map_lookup_elem(&blocked_ips, &idx);
        if (cidr && cidr->mask &&
            (dst_ip & cidr->mask) == (cidr->ip & cidr->mask))
            return -EPERM;
    }
    return 0;
}
