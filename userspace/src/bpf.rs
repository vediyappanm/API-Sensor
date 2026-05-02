use anyhow::{Context, Result};
use libbpf_rs::UprobeOpts;
use std::ffi::OsStr;

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
        let looks_mbedtls = lib_lower.contains("mbedtls");
        let looks_wolfssl = lib_lower.contains("wolfssl");

        if provider == "mbedtls" || (provider == "auto" && looks_mbedtls) {
            if try_attach(obj, "ssl_write_entry", lib, "mbedtls_ssl_write", false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_write_exit",  lib, "mbedtls_ssl_write", true,  pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_entry",  lib, "mbedtls_ssl_read",  false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_exit",   lib, "mbedtls_ssl_read",  true,  pid, links) { attached += 1; }
        }
        if provider == "wolfssl" || (provider == "auto" && looks_wolfssl) {
            if try_attach(obj, "ssl_write_entry", lib, "wolfSSL_write", false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_write_exit",  lib, "wolfSSL_write", true,  pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_entry",  lib, "wolfSSL_read",  false, pid, links) { attached += 1; }
            if try_attach(obj, "ssl_read_exit",   lib, "wolfSSL_read",  true,  pid, links) { attached += 1; }
        }
        if provider == "auto" && !looks_openssl && !looks_gnutls && !looks_mbedtls && !looks_wolfssl {
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
    let mut tcp_connect = obj.progs_mut()
        .find(|p| p.name() == OsStr::new("tcp_connect_entry"))
        .context("missing tcp_connect_entry program")?;
    links.push(tcp_connect.attach().context("attach kprobe tcp_connect")?);

    let mut tcp_accept = obj.progs_mut()
        .find(|p| p.name() == OsStr::new("tcp_accept_ret"))
        .context("missing tcp_accept_ret program")?;
    links.push(tcp_accept.attach().context("attach kretprobe inet_csk_accept")?);

    let mut tcp_close = obj.progs_mut()
        .find(|p| p.name() == OsStr::new("tcp_close_entry"))
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

/// Attach NSS TLS uprobes (libnss3: PR_Read / PR_Write).
pub fn attach_nss_uprobes(
    obj: &mut libbpf_rs::Object,
    pid: i32,
    nss_libs: &[String],
    links: &mut Vec<libbpf_rs::Link>,
) -> usize {
    let mut attached = 0;
    for lib in nss_libs {
        if try_attach(obj, "nss_write_entry", lib, "PR_Write", false, pid, links) { attached += 1; }
        if try_attach(obj, "nss_write_exit",  lib, "PR_Write", true,  pid, links) { attached += 1; }
        if try_attach(obj, "nss_read_entry",  lib, "PR_Read",  false, pid, links) { attached += 1; }
        if try_attach(obj, "nss_read_exit",   lib, "PR_Read",  true,  pid, links) { attached += 1; }
    }
    if attached > 0 { tracing::info!(attached, "NSS uprobes attached"); }
    attached
}

/// Attach kTLS kprobes (tls_sw_sendmsg / tls_sw_recvmsg). Requires CONFIG_TLS=y.
/// Failures are logged at debug level — kTLS is optional.
pub fn attach_ktls_kprobes(
    obj: &mut libbpf_rs::Object,
    links: &mut Vec<libbpf_rs::Link>,
) -> usize {
    let mut attached = 0;
    for prog_name in ["ktls_send_entry", "ktls_send_exit", "ktls_recv_entry", "ktls_recv_exit"] {
        if let Some(mut p) = obj.progs_mut().find(|p| p.name() == OsStr::new(prog_name)) {
            match p.attach() {
                Ok(link) => { links.push(link); attached += 1; }
                Err(e)   => { tracing::debug!(prog = prog_name, error = %e, "kTLS kprobe skipped"); }
            }
        }
    }
    if attached > 0 { tracing::info!(attached, "kTLS kprobes attached"); }
    attached
}

/// Attach eBPF LSM hook for outbound IP block list.
/// Requires CONFIG_BPF_LSM=y and "bpf" in the kernel lsm= parameter.
pub fn attach_lsm_hooks(
    obj: &mut libbpf_rs::Object,
    links: &mut Vec<libbpf_rs::Link>,
) -> usize {
    let mut attached = 0;
    if let Some(mut p) = obj.progs_mut().find(|p| p.name() == OsStr::new("lsm_socket_connect")) {
        match p.attach_lsm() {
            Ok(link) => { links.push(link); attached += 1; tracing::info!("eBPF LSM hook attached (socket_connect)"); }
            Err(e)   => { tracing::debug!(error = %e, "eBPF LSM skipped (CONFIG_BPF_LSM=y + bpf in lsm= required)"); }
        }
    }
    attached
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
    let prog = obj.progs_mut()
        .find(|p| p.name() == OsStr::new(prog_name))
        .with_context(|| format!("missing BPF program {}", prog_name))?;
    let opts = UprobeOpts {
        retprobe,
        func_name: Some(symbol.to_string()),
        ..Default::default()
    };
    let link = prog
        .attach_uprobe_with_opts(pid, binary, 0, opts)
        .with_context(|| format!("attach {} to {}", prog_name, symbol))?;
    links.push(link);
    Ok(())
}
