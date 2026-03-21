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

pub fn attach_kernel_probes(
    obj: &mut libbpf_rs::Object,
    links: &mut Vec<libbpf_rs::Link>,
) -> Result<()> {
    let tcp_connect = obj
        .prog_mut("tcp_connect_entry")
        .context("missing tcp_connect_entry program")?;
    links.push(tcp_connect.attach().context("attach kprobe tcp_connect")?);

    let tcp_accept = obj
        .prog_mut("tcp_accept_ret")
        .context("missing tcp_accept_ret program")?;
    links.push(tcp_accept.attach().context("attach kretprobe inet_csk_accept")?);

    let tcp_close = obj
        .prog_mut("tcp_close_entry")
        .context("missing tcp_close_entry program")?;
    links.push(tcp_close.attach().context("attach kprobe tcp_close")?);

    Ok(())
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
