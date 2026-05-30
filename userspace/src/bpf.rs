use anyhow::{Context, Result};
use libbpf_rs::UprobeOpts;

// ---------------------------------------------------------------------------
// BPF attachment helpers
// ---------------------------------------------------------------------------

pub fn attach_tls_uprobes(
    obj: &mut libbpf_rs::Object,
    tls_provider: &str,
    pid: i32,
    go_tls_enabled: bool,
    tls_libs: &[String],
    links: &mut Vec<libbpf_rs::Link>,
) -> Result<()> {
    let provider = tls_provider;
    let mut attached = 0;
    for lib in tls_libs {
        let lib_lower = lib.to_lowercase();
        let looks_openssl = lib_lower.contains("libssl") || lib_lower.contains("openssl");
        let looks_gnutls  = lib_lower.contains("gnutls");

        if provider == "openssl" || (provider == "auto" && looks_openssl) {
            if try_attach(obj, "ssl_write_entry",   lib, "SSL_write",    false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_write_exit",    lib, "SSL_write",    true,  pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_entry",    lib, "SSL_read",     false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_exit",     lib, "SSL_read",     true,  pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_ex_entry", lib, "SSL_read_ex",  false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_ex_exit",  lib, "SSL_read_ex",  true,  pid, links) { attached += 1; }
            if try_attach(obj, "ssl_write_ex_entry",lib, "SSL_write_ex", false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_write_ex_exit", lib, "SSL_write_ex", true,  pid, links) { attached += 1; }
            if try_attach(obj, "ssl_free_entry",    lib, "SSL_free",     false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_set_fd_entry",  lib, "SSL_set_fd",   false, pid, links) { attached += 1; }
        }
        if provider == "gnutls" || (provider == "auto" && looks_gnutls) {
            if try_attach(obj, "gnutls_send_entry", lib, "gnutls_record_send", false, pid, links) { attached += 1; }
            if try_attach(obj, "gnutls_send_exit",  lib, "gnutls_record_send", true,  pid, links) { attached += 1; }
            if try_attach(obj, "gnutls_recv_entry", lib, "gnutls_record_recv", false, pid, links) { attached += 1; }
            if try_attach(obj, "gnutls_recv_exit",  lib, "gnutls_record_recv", true,  pid, links) { attached += 1; }
        }
        if provider == "auto" && !looks_openssl && !looks_gnutls {
            if try_attach(obj, "ssl_write_entry", lib, "SSL_write", false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_write_exit",  lib, "SSL_write", true,  pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_entry",  lib, "SSL_read",  false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_exit",   lib, "SSL_read",  true,  pid, links) { attached += 1; }
        }
    }
    if attached == 0 && !go_tls_enabled {
        anyhow::bail!("no TLS uprobes attached; verify --tls-libs or --discover-libs and symbols");
    }
    tracing::info!(attached, "TLS uprobes attached");
    Ok(())
}

/// Attach the kernel-side connection-tracking probes (best-effort).
///
/// These kprobes/kretprobes hook stable, arch-agnostic kernel functions
/// (`tcp_connect`, `inet_csk_accept`, `tcp_close`) and read the `struct sock`
/// via CO-RE, so they are portable across kernels that expose BTF. They are,
/// however, NON-ESSENTIAL: they only enrich events with the kernel-resolved
/// source/dest IP 4-tuple. The core TLS capture runs entirely off the uprobes.
///
/// Therefore a failed attach must NOT abort the sensor. On a kernel where a
/// symbol is missing, locked down, or otherwise unattachable, we log and keep
/// running uprobe-only — TLS capture stays intact, only tuple enrichment is
/// degraded. Returns the number of probes successfully attached.
pub fn attach_kernel_probes(
    obj: &mut libbpf_rs::Object,
    links: &mut Vec<libbpf_rs::Link>,
) -> usize {
    const PROBES: &[(&str, &str)] = &[
        ("tcp_connect_entry", "kprobe/tcp_connect"),
        ("tcp_accept_ret", "kretprobe/inet_csk_accept"),
        ("tcp_close_entry", "kprobe/tcp_close"),
    ];

    let mut attached = 0usize;
    for &(prog_name, desc) in PROBES {
        match obj.prog_mut(prog_name) {
            Some(prog) => match prog.attach() {
                Ok(link) => {
                    links.push(link);
                    attached += 1;
                    tracing::debug!(probe = desc, "kernel probe attached");
                }
                Err(e) => {
                    tracing::warn!(
                        probe = desc,
                        error = %e,
                        "kernel probe attach failed; continuing without it \
                         (connection-tuple enrichment degraded on this kernel)"
                    );
                }
            },
            None => {
                tracing::warn!(
                    probe = desc,
                    program = prog_name,
                    "kernel probe program not present in BPF object; skipping"
                );
            }
        }
    }

    if attached == 0 {
        tracing::warn!(
            "no kernel connection-tracking probes attached — running uprobe-only; \
             TLS capture is intact but source/dest IP enrichment is limited"
        );
    } else {
        tracing::info!(
            attached,
            total = PROBES.len(),
            "kernel connection-tracking probes attached"
        );
    }
    attached
}

/// Attach the plaintext-capture syscall tracepoints (best-effort, opt-in).
///
/// These hook the socket send/recv syscalls to capture non-TLS HTTP traffic
/// (the BPF side content-sniffs for HTTP and resolves the fd to a socket, so
/// only real plaintext HTTP is emitted). They are global syscall hooks, hence
/// gated behind `--capture-plaintext`. Each attach is independent and a failure
/// is non-fatal. Returns the number of tracepoints attached.
pub fn attach_plaintext_probes(
    obj: &mut libbpf_rs::Object,
    links: &mut Vec<libbpf_rs::Link>,
) -> usize {
    const TPS: &[&str] = &[
        "tp_sys_enter_write",
        "tp_sys_enter_sendto",
        "tp_sys_enter_read",
        "tp_sys_enter_recvfrom",
        "tp_sys_exit_read",
        "tp_sys_exit_recvfrom",
    ];

    let mut attached = 0usize;
    for prog_name in TPS {
        match obj.prog_mut(prog_name) {
            Some(prog) => match prog.attach() {
                Ok(link) => {
                    links.push(link);
                    attached += 1;
                    tracing::debug!(tracepoint = prog_name, "plaintext tracepoint attached");
                }
                Err(e) => {
                    tracing::warn!(
                        tracepoint = prog_name,
                        error = %e,
                        "plaintext tracepoint attach failed; continuing"
                    );
                }
            },
            None => {
                tracing::warn!(
                    tracepoint = prog_name,
                    "plaintext tracepoint program not present in BPF object; skipping"
                );
            }
        }
    }

    if attached > 0 {
        tracing::info!(
            attached,
            total = TPS.len(),
            "plaintext (non-TLS) capture enabled — hooking socket send/recv syscalls"
        );
    } else {
        tracing::warn!("plaintext capture requested but no tracepoints attached");
    }
    attached
}

/// Attempt to attach a uprobe, logging success at debug and failure at warn.
/// Returns true if the attach succeeded, false otherwise.
fn try_attach(
    obj: &mut libbpf_rs::Object,
    prog_name: &str,
    binary: &str,
    symbol: &str,
    retprobe: bool,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> bool {
    match attach_symbol(obj, prog_name, binary, symbol, retprobe, pid, links) {
        Ok(()) => {
            tracing::debug!(prog = prog_name, symbol, binary, retprobe, "uprobe attached");
            true
        }
        Err(e) => {
            tracing::warn!(prog = prog_name, symbol, binary, error = %e, "uprobe attach failed");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// QUIC library uprobe attachment
// ---------------------------------------------------------------------------

pub fn attach_quic_uprobes(
    obj: &mut libbpf_rs::Object,
    pid: i32,
    quic_libs: &[String],
    links: &mut Vec<libbpf_rs::Link>,
) -> Result<usize> {
    use crate::quic::{classify_quic_lib, QuicLibType};

    let mut attached = 0;
    for lib in quic_libs {
        let lib_type = classify_quic_lib(lib);
        let (recv_sym, send_sym) = match lib_type {
            Some(QuicLibType::Quiche) => (
                "quiche_conn_stream_recv",
                "quiche_conn_stream_send",
            ),
            Some(QuicLibType::Ngtcp2) => (
                "ngtcp2_conn_read_stream",
                "ngtcp2_conn_write_stream",
            ),
            Some(QuicLibType::Lsquic) => (
                "lsquic_stream_read",
                "lsquic_stream_write",
            ),
            Some(QuicLibType::Msquic) => (
                "MsQuicStreamReceive",
                "MsQuicStreamSend",
            ),
            None => continue,
        };
        if try_attach(obj, "quic_stream_recv_entry", lib, recv_sym, false, pid, links) { attached += 1; }
        if try_attach(obj, "quic_stream_recv_exit",  lib, recv_sym, true,  pid, links) { attached += 1; }
        if try_attach(obj, "quic_stream_send_entry", lib, send_sym, false, pid, links) { attached += 1; }
        if try_attach(obj, "quic_stream_send_exit",  lib, send_sym, true,  pid, links) { attached += 1; }

        // Hook h3-level C FFI body functions. The quiche h3 layer inlines
        // internal Rust methods, so we hook the C FFI functions that the
        // application binary calls via PLT.
        if lib_type == Some(QuicLibType::Quiche) {
            if try_attach(obj, "h3_recv_body_entry", lib, "quiche_h3_recv_body", false, pid, links) { attached += 1; }
            if try_attach(obj, "h3_recv_body_exit",  lib, "quiche_h3_recv_body", true,  pid, links) { attached += 1; }
            if try_attach(obj, "h3_send_body_entry", lib, "quiche_h3_send_body", false, pid, links) { attached += 1; }
        }
    }
    if attached > 0 {
        tracing::info!(attached, "QUIC uprobes attached");
    }
    Ok(attached)
}

pub fn attach_symbol(
    obj: &mut libbpf_rs::Object,
    prog_name: &str,
    binary: &str,
    symbol: &str,
    retprobe: bool,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> Result<()> {
    let prog = obj
        .prog_mut(prog_name)
        .with_context(|| format!("missing BPF program {}", prog_name))?;
    let opts = UprobeOpts {
        retprobe,
        func_name: symbol.to_string(),
        ..Default::default()
    };
    let link = prog
        .attach_uprobe_with_opts(pid, binary, 0, opts)
        .with_context(|| format!("attach {} to {}", prog_name, symbol))?;
    links.push(link);
    Ok(())
}
