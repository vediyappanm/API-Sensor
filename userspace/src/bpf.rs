use anyhow::{Context, Result};
use libbpf_rs::{ObjectBuilder, UprobeOpts};
use std::ffi::OsStr;
use std::io::BufRead;

// ---------------------------------------------------------------------------
// Load-time feature selection (F10)
// ---------------------------------------------------------------------------

/// Optional parts of the object. Core TLS capture must never depend on any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadFeatures {
    pub dynptr: bool,
    pub lsm: bool,
    pub ktls: bool,
}

pub const LSM_PROGS: &[&str] = &["lsm_socket_connect"];
pub const KTLS_PROGS: &[&str] = &["ktls_send_entry", "ktls_send_exit", "ktls_recv_entry", "ktls_recv_exit"];

/// Feature sets to try, most capable first. A verifier or CO-RE failure in an optional program
/// falls back to core capture instead of stopping the sensor.
pub fn load_attempts(want: LoadFeatures) -> Vec<LoadFeatures> {
    let mut out = vec![want];
    let core = LoadFeatures { lsm: false, ktls: false, ..want };
    if core != want {
        out.push(core);
    }
    if core.dynptr {
        out.push(LoadFeatures { dynptr: false, ..core });
    }
    out
}

fn is_disabled(name: &str, f: LoadFeatures) -> bool {
    (!f.lsm && LSM_PROGS.contains(&name)) || (!f.ktls && KTLS_PROGS.contains(&name))
}

/// Open the object, switch off unselected optional programs, set read-only config, then load.
pub fn open_and_load(data: &[u8], f: LoadFeatures) -> Result<libbpf_rs::Object> {
    let mut open = ObjectBuilder::default().open_memory(data)?;
    for mut p in open.progs_mut() {
        let name = p.name().to_string_lossy().into_owned();
        if is_disabled(&name, f) {
            let _ = p.set_autoload(false);
        }
    }
    if f.dynptr {
        let mut set = false;
        for mut m in open.maps_mut() {
            if m.name() == OsStr::new(".rodata.cfg") {
                if let Some(buf) = m.initial_value_mut() {
                    if buf.len() >= 4 {
                        buf[..4].copy_from_slice(&1u32.to_ne_bytes());
                        set = true;
                    }
                }
            }
        }
        anyhow::ensure!(set, "BPF object has no .rodata.cfg section; cannot enable dynptr");
    }
    Ok(open.load()?)
}

/// BPF LSM programs attach only when "bpf" is in the active LSM list.
pub fn kernel_has_bpf_lsm() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| lsm_list_has_bpf(&s))
        .unwrap_or(false)
}

pub fn lsm_list_has_bpf(list: &str) -> bool {
    list.split(',').any(|m| m.trim() == "bpf")
}

/// kTLS probes need the software TLS module's symbols.
pub fn kernel_has_ktls() -> bool {
    let Ok(f) = std::fs::File::open("/proc/kallsyms") else { return false };
    std::io::BufReader::new(f)
        .lines()
        .map_while(|l| l.ok())
        .any(|l| l.split_whitespace().nth(2) == Some("tls_sw_sendmsg"))
}

// ---------------------------------------------------------------------------
// BPF attachment helpers
// ---------------------------------------------------------------------------

/// Symbols for one provider: (entry prog, exit prog, symbol) for write then read.
type ProbePlan = [(&'static str, &'static str, &'static str); 2];

static OPENSSL_PLAN: ProbePlan = [("ssl_write_entry", "ssl_write_exit", "SSL_write"), ("ssl_read_entry", "ssl_read_exit", "SSL_read")];
static OPENSSL_EX_PLAN: ProbePlan = [("ssl_write_ex_entry", "ssl_write_ex_exit", "SSL_write_ex"), ("ssl_read_ex_entry", "ssl_read_ex_exit", "SSL_read_ex")];
static GNUTLS_PLAN: ProbePlan = [("gnutls_send_entry", "gnutls_send_exit", "gnutls_record_send"), ("gnutls_recv_entry", "gnutls_recv_exit", "gnutls_record_recv")];
static MBEDTLS_PLAN: ProbePlan = [("ssl_write_entry", "ssl_write_exit", "mbedtls_ssl_write"), ("ssl_read_entry", "ssl_read_exit", "mbedtls_ssl_read")];
static WOLFSSL_PLAN: ProbePlan = [("ssl_write_entry", "ssl_write_exit", "wolfSSL_write"), ("ssl_read_entry", "ssl_read_exit", "wolfSSL_read")];

/// Which provider plans apply to a library path for the configured `--tls-provider`.
pub fn plans_for(provider: &str, lib: &str) -> Vec<&'static ProbePlan> {
    let l = lib.to_lowercase();
    let openssl = l.contains("libssl") || l.contains("openssl");
    let gnutls = l.contains("gnutls");
    let mbedtls = l.contains("mbedtls");
    let wolfssl = l.contains("wolfssl");
    let auto = provider == "auto";
    let mut out: Vec<&'static ProbePlan> = Vec::new();
    if provider == "openssl" || (auto && openssl) {
        out.push(&OPENSSL_PLAN);
        out.push(&OPENSSL_EX_PLAN);
    }
    if provider == "gnutls" || (auto && gnutls) {
        out.push(&GNUTLS_PLAN);
    }
    if provider == "mbedtls" || (auto && mbedtls) {
        out.push(&MBEDTLS_PLAN);
    }
    if provider == "wolfssl" || (auto && wolfssl) {
        out.push(&WOLFSSL_PLAN);
    }
    if auto && !openssl && !gnutls && !mbedtls && !wolfssl {
        out.push(&OPENSSL_PLAN);
    }
    out
}

/// Attach an entry/exit pair, or neither: an entry without its exit never emits and leaks state.
fn attach_pair(
    obj: &libbpf_rs::Object,
    entry: &str,
    exit: &str,
    lib: &str,
    symbol: &str,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> bool {
    let mut pair = Vec::with_capacity(2);
    if try_attach(obj, entry, lib, symbol, false, pid, &mut pair) && try_attach(obj, exit, lib, symbol, true, pid, &mut pair) {
        links.extend(pair);
        true
    } else {
        false
    }
}

/// Attach TLS probes to each library. Returns how many libraries have usable coverage, meaning
/// both the write and the read pair of at least one provider plan attached.
pub fn attach_tls_libs(
    obj: &libbpf_rs::Object,
    tls_provider: &str,
    pid: i32,
    tls_libs: &[String],
    links: &mut Vec<libbpf_rs::Link>,
) -> usize {
    let mut usable = 0;
    for lib in tls_libs {
        let mut lib_ok = false;
        for plan in plans_for(tls_provider, lib) {
            let write = attach_pair(obj, plan[0].0, plan[0].1, lib, plan[0].2, pid, links);
            let read = attach_pair(obj, plan[1].0, plan[1].1, lib, plan[1].2, pid, links);
            lib_ok |= write && read;
        }
        if lib_ok {
            usable += 1;
        } else {
            crate::metrics::PROBE_ATTACH_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(lib = %lib, "no complete read/write probe pair attached; library not captured");
        }
        // SSL_set_fd and SSL_free improve attribution but are not required for capture.
        if plans_for(tls_provider, lib).iter().any(|p| std::ptr::eq(*p, &OPENSSL_PLAN)) {
            try_attach(obj, "ssl_set_fd_entry", lib, "SSL_set_fd", false, pid, links);
            try_attach(obj, "ssl_free_entry", lib, "SSL_free", false, pid, links);
        }
    }
    usable
}

pub fn attach_tls_uprobes(
    obj: &libbpf_rs::Object,
    tls_provider: &str,
    pid: i32,
    go_tls_enabled: bool,
    tls_libs: &[String],
    links: &mut Vec<libbpf_rs::Link>,
) -> Result<()> {
    let usable = attach_tls_libs(obj, tls_provider, pid, tls_libs, links);
    if usable == 0 && !go_tls_enabled {
        anyhow::bail!("no TLS library has a complete read/write probe set; verify --tls-libs or --discover-libs and symbols");
    }
    tracing::info!(usable_libs = usable, total_libs = tls_libs.len(), "TLS uprobes attached");
    Ok(())
}

/// Upper bound on distinct TLS library files probed; each costs several uprobe links.
pub const MAX_ATTACHED_LIBS: usize = 256;

/// Libraries already probed, by file identity, so periodic rediscovery attaches only new ones.
#[derive(Default)]
pub struct AttachedLibs {
    seen: std::collections::HashSet<(u64, u64)>,
}

impl AttachedLibs {
    /// Returns the paths whose file has not been seen before and records them.
    pub fn take_new(&mut self, paths: &[String]) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        paths
            .iter()
            .filter(|p| match std::fs::metadata(p) {
                Ok(m) if self.seen.len() < MAX_ATTACHED_LIBS => self.seen.insert((m.dev(), m.ino())),
                Ok(_) => {
                    tracing::warn!(lib = %p, max = MAX_ATTACHED_LIBS, "TLS library limit reached; not attaching");
                    false
                }
                Err(_) => false,
            })
            .cloned()
            .collect()
    }
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

    // Exec notifications trigger library rediscovery; periodic rescans cover a missed attach.
    if let Some(mut exec) = obj.progs_mut().find(|p| p.name() == OsStr::new("handle_new_process")) {
        match exec.attach() {
            Ok(link) => links.push(link),
            Err(e) => tracing::warn!(error = %e, "exec tracepoint not attached; relying on periodic rescans"),
        }
    }

    Ok(())
}

/// Attempt to attach a uprobe, logging success at debug and failure at warn.
/// Returns true if the attach succeeded, false otherwise.
fn try_attach(
    obj: &libbpf_rs::Object,
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
    for &prog_name in KTLS_PROGS {
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
    obj: &libbpf_rs::Object,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_program_failure_falls_back_to_core_capture() {
        let all = LoadFeatures { dynptr: true, lsm: true, ktls: true };
        assert_eq!(
            load_attempts(all),
            vec![
                all,
                LoadFeatures { dynptr: true, lsm: false, ktls: false },
                LoadFeatures { dynptr: false, lsm: false, ktls: false },
            ]
        );
        let core = LoadFeatures { dynptr: false, lsm: false, ktls: false };
        assert_eq!(load_attempts(core), vec![core], "nothing optional means a single attempt");
    }

    #[test]
    fn unselected_optional_programs_are_not_loaded() {
        let core = LoadFeatures { dynptr: true, lsm: false, ktls: false };
        assert!(is_disabled("lsm_socket_connect", core));
        assert!(KTLS_PROGS.iter().all(|p| is_disabled(p, core)));
        assert!(!is_disabled("ssl_write_entry", core), "core capture is never switched off");
        let all = LoadFeatures { dynptr: true, lsm: true, ktls: true };
        assert!(!is_disabled("lsm_socket_connect", all));
    }

    #[test]
    fn the_built_object_exposes_the_load_time_switches() {
        let data = std::fs::read(concat!(env!("OUT_DIR"), "/http_trace.bpf.o")).expect("BPF object");
        let open = ObjectBuilder::default().open_memory(&data).expect("open");
        let maps: Vec<String> = open.maps().map(|m| m.name().to_string_lossy().into_owned()).collect();
        assert!(maps.iter().any(|m| m == ".rodata.cfg"), "dynptr switch map missing: {maps:?}");
        let progs: Vec<String> = open.progs().map(|p| p.name().to_string_lossy().into_owned()).collect();
        for p in LSM_PROGS.iter().chain(KTLS_PROGS) {
            assert!(progs.iter().any(|n| n == p), "optional program {p} not in object");
        }
    }

    #[test]
    fn provider_plans_follow_the_library_name_in_auto_mode() {
        assert_eq!(plans_for("auto", "/usr/lib/libssl.so.3").len(), 2, "SSL_* and SSL_*_ex");
        assert!(std::ptr::eq(plans_for("auto", "/lib/libgnutls.so.30")[0], &GNUTLS_PLAN));
        assert!(std::ptr::eq(plans_for("auto", "/lib/libmbedtls.so")[0], &MBEDTLS_PLAN));
        assert!(std::ptr::eq(plans_for("auto", "/opt/custom-tls.so")[0], &OPENSSL_PLAN));
        assert!(plans_for("gnutls", "/usr/lib/libssl.so.3").iter().all(|p| std::ptr::eq(*p, &GNUTLS_PLAN)));
        for plan in plans_for("auto", "/usr/lib/libssl.so.3") {
            assert!(plan[0].0.contains("write") && plan[1].0.contains("read"), "write pair first, then read");
        }
    }

    #[test]
    fn rediscovery_attaches_each_library_file_once() {
        let dir = std::env::temp_dir().join(format!("libs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("libssl.so.3");
        std::fs::write(&a, b"x").unwrap();
        let link = dir.join("libssl-link.so.3");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&a, &link).unwrap();
        let mut seen = AttachedLibs::default();
        let a_s = a.to_string_lossy().into_owned();
        let link_s = link.to_string_lossy().into_owned();
        assert_eq!(seen.take_new(&[a_s.clone()]), vec![a_s.clone()]);
        assert!(seen.take_new(&[a_s, link_s]).is_empty(), "same file under another path is not re-attached");
        assert!(seen.take_new(&["/nonexistent/libssl.so".into()]).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bpf_lsm_detection_needs_bpf_in_the_active_list() {
        assert!(lsm_list_has_bpf("lockdown,capability,landlock,yama,apparmor,bpf\n"));
        assert!(!lsm_list_has_bpf("lockdown,capability,yama,apparmor"));
        assert!(!lsm_list_has_bpf("bpffs"));
    }
}
