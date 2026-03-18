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
            if attach_symbol(obj, "ssl_write_entry",   lib, "SSL_write",    false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_write_exit",    lib, "SSL_write",    true,  pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_read_entry",    lib, "SSL_read",     false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_read_exit",     lib, "SSL_read",     true,  pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_read_ex_entry", lib, "SSL_read_ex",  false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_read_ex_exit",  lib, "SSL_read_ex",  true,  pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_write_ex_entry",lib, "SSL_write_ex", false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_write_ex_exit", lib, "SSL_write_ex", true,  pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_free_entry",    lib, "SSL_free",     false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_set_fd_entry",  lib, "SSL_set_fd",   false, pid, links).is_ok() { attached += 1; }
        }
        if provider == "gnutls" || (provider == "auto" && looks_gnutls) {
            if attach_symbol(obj, "gnutls_send_entry", lib, "gnutls_record_send", false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "gnutls_send_exit",  lib, "gnutls_record_send", true,  pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "gnutls_recv_entry", lib, "gnutls_record_recv", false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "gnutls_recv_exit",  lib, "gnutls_record_recv", true,  pid, links).is_ok() { attached += 1; }
        }
        if provider == "auto" && !looks_openssl && !looks_gnutls {
            if attach_symbol(obj, "ssl_write_entry", lib, "SSL_write", false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_write_exit",  lib, "SSL_write", true,  pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_read_entry",  lib, "SSL_read",  false, pid, links).is_ok() { attached += 1; }
            if attach_symbol(obj, "ssl_read_exit",   lib, "SSL_read",  true,  pid, links).is_ok() { attached += 1; }
        }
    }
    if attached == 0 && !go_tls_enabled {
        anyhow::bail!("no TLS uprobes attached; verify --tls-libs or --discover-libs and symbols");
    }
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
