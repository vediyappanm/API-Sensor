use std::fs;

use crate::go_tls::{find_elf_symbol, find_elf_symbol_dyn, attach_at_offset, va_to_file_offset};

/// Scan a binary for statically-linked TLS (OpenSSL or BoringSSL) and attach uprobes.
///
/// Works for any binary that has `SSL_read`/`SSL_write` symbols embedded —
/// covers Node.js (static OpenSSL), Go with CGO, Nginx static builds,
/// and Chrome/Electron (BoringSSL).
pub fn attach_static_tls(
    obj: &mut libbpf_rs::Object,
    binary_path: &str,
    _pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> bool {
    // Always use pid=-1 (system-wide) for uprobes. The uprobe is inode-based,
    // so it fires for ANY process using this binary/library regardless of PID
    // or mount namespace. Using a specific PID fails when the sensor runs in
    // a different container (mount namespace) than the target process.
    let pid = -1;
    let data = match fs::read(binary_path) {
        Ok(d) => {
            tracing::debug!(path = %binary_path, size = d.len(), "static TLS: read binary");
            d
        }
        Err(e) => {
            tracing::debug!(path = %binary_path, error = %e, "static TLS: cannot read binary");
            return false;
        }
    };
    let elf_file = match elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(path = %binary_path, error = %e, "static TLS: not a valid ELF");
            return false;
        }
    };

    // Resolve symbol VA -> file offset for PIE binary correctness
    let resolve = |name: &str| -> Option<usize> {
        let va = find_elf_symbol(&elf_file, name)
            .or_else(|| find_elf_symbol_dyn(&elf_file, name))?;
        Some(va_to_file_offset(&elf_file, va).unwrap_or(va))
    };

    let write_off = resolve("SSL_write");
    let read_off  = resolve("SSL_read");

    // If the binary has neither SSL_read nor SSL_write, skip it entirely.
    if write_off.is_none() && read_off.is_none() {
        tracing::debug!(path = %binary_path, "static TLS: no SSL_read/SSL_write symbols");
        return false;
    }

    let free_off  = resolve("SSL_free");
    let tls_type = detect_tls_type(&elf_file, &data);

    tracing::info!(
        path = %binary_path,
        tls_type = %tls_type,
        ssl_write = ?write_off,
        ssl_read = ?read_off,
        ssl_free = ?free_off,
        "static TLS: symbols found, attaching probes"
    );

    let mut attached = false;
    if let Some(off) = write_off {
        if attach_at_offset(obj, "ssl_write_entry", binary_path, off, false, pid, links).is_ok() { attached = true; }
        let _ = attach_at_offset(obj, "ssl_write_exit", binary_path, off, true, pid, links);
    }
    if let Some(off) = read_off {
        if attach_at_offset(obj, "ssl_read_entry", binary_path, off, false, pid, links).is_ok() { attached = true; }
        let _ = attach_at_offset(obj, "ssl_read_exit", binary_path, off, true, pid, links);
    }
    if let Some(off) = free_off {
        let _ = attach_at_offset(obj, "ssl_free_entry", binary_path, off, false, pid, links);
    }

    // Also try _ex variants (OpenSSL 1.1.1+)
    if let Some(off) = resolve("SSL_read_ex") {
        let _ = attach_at_offset(obj, "ssl_read_ex_entry", binary_path, off, false, pid, links);
        let _ = attach_at_offset(obj, "ssl_read_ex_exit", binary_path, off, true, pid, links);
    }
    if let Some(off) = resolve("SSL_write_ex") {
        let _ = attach_at_offset(obj, "ssl_write_ex_entry", binary_path, off, false, pid, links);
        let _ = attach_at_offset(obj, "ssl_write_ex_exit", binary_path, off, true, pid, links);
    }
    if let Some(off) = resolve("SSL_set_fd") {
        let _ = attach_at_offset(obj, "ssl_set_fd_entry", binary_path, off, false, pid, links);
    }

    if attached {
        tracing::info!(binary = %binary_path, tls_type = %tls_type, "static TLS probes attached");
    }
    attached
}

/// Keep the old name as an alias for backward compatibility.
pub fn attach_boring_ssl_static(
    obj: &mut libbpf_rs::Object,
    binary_path: &str,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> bool {
    attach_static_tls(obj, binary_path, pid, links)
}

/// Detect which TLS library is embedded in the binary (for logging only).
fn detect_tls_type(elf_file: &elf::ElfBytes<elf::endian::AnyEndian>, data: &[u8]) -> &'static str {
    // Check for BoringSSL-specific symbols
    let boring_syms = [
        "BORINGSSL_bcm_power_on_self_test",
        "CRYPTO_is_confidential_build",
        "SSL_CTX_set_grease_enabled",
    ];
    let has_boring_sym = |symtab: &elf::symbol::SymbolTable<'_, _>,
                           strtab: &elf::string_table::StringTable<'_>| -> bool {
        for sym in symtab.iter() {
            if let Ok(name) = strtab.get(sym.st_name as usize) {
                if boring_syms.contains(&name) { return true; }
            }
        }
        false
    };
    if let Ok(Some((ref st, ref sr))) = elf_file.symbol_table() {
        if has_boring_sym(st, sr) { return "BoringSSL"; }
    }
    if let Ok(Some((ref st, ref sr))) = elf_file.dynamic_symbol_table() {
        if has_boring_sym(st, sr) { return "BoringSSL"; }
    }
    // Byte-pattern fallback for BoringSSL
    let has_boring_str = data.windows(9).any(|w| w == b"BoringSSL");
    let has_bcm = data.windows(13).any(|w| w == b"BORINGSSL_bcm");
    if has_boring_str && has_bcm { return "BoringSSL"; }

    // If it has SSL_read/SSL_write but not BoringSSL markers, it's OpenSSL
    "OpenSSL"
}
