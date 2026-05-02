use std::fs;

use crate::go_tls::{find_elf_symbol, find_elf_symbol_dyn, attach_at_offset, va_to_file_offset};

pub fn attach_boring_ssl_static(
    obj: &mut libbpf_rs::Object,
    binary_path: &str,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> bool {
    let data = match fs::read(binary_path) { Ok(d) => d, Err(_) => return false };
    let elf_file = match elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data) {
        Ok(e) => e, Err(_) => return false,
    };

    if !is_boring_ssl(&elf_file, &data) { return false; }

    // Resolve symbol VA → file offset for PIE binary correctness
    let resolve = |name: &str| -> Option<usize> {
        let va = find_elf_symbol(&elf_file, name)
            .or_else(|| find_elf_symbol_dyn(&elf_file, name))?;
        Some(va_to_file_offset(&elf_file, va).unwrap_or(va))
    };

    let write_off = resolve("SSL_write");
    let read_off  = resolve("SSL_read");
    let free_off  = resolve("SSL_free");

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
    if attached {
        tracing::info!(binary = %binary_path, "BoringSSL static link found");
    }
    attached
}

fn is_boring_ssl(elf_file: &elf::ElfBytes<elf::endian::AnyEndian>, data: &[u8]) -> bool {
    let boring_only = [
        "BORINGSSL_bcm_power_on_self_test",
        "BORINGSSL_self_test",
        "CRYPTO_is_confidential_build",
        "SSL_CTX_set_grease_enabled",
        "SSL_CTX_set_alps_use_new_codepoint",
        "CRYPTO_get_ex_data_implementation",
    ];
    let check_sym = |symtab: elf::symbol::SymbolTable<'_, _>,
                      strtab: elf::string_table::StringTable<'_>| -> bool {
        for sym in symtab.iter() {
            if let Ok(name) = strtab.get(sym.st_name as usize) {
                if boring_only.contains(&name) { return true; }
            }
        }
        false
    };
    if let Ok(Some((st, sr))) = elf_file.symbol_table() {
        if check_sym(st, sr) { return true; }
    }
    if let Ok(Some((st, sr))) = elf_file.dynamic_symbol_table() {
        if check_sym(st, sr) { return true; }
    }
    // Byte-pattern fallback
    let has_version_str = data.windows(9).any(|w| w == b"BoringSSL");
    let has_bcm_marker  = data.windows(13).any(|w| w == b"BORINGSSL_bcm");
    has_version_str && has_bcm_marker
}

// ---------------------------------------------------------------------------
// mbedTLS static binary detection + uprobe attachment
// ---------------------------------------------------------------------------

pub fn attach_mbedtls_static(
    obj: &mut libbpf_rs::Object,
    binary_path: &str,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> bool {
    let data = match fs::read(binary_path) { Ok(d) => d, Err(_) => return false };
    let elf_file = match elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data) {
        Ok(e) => e, Err(_) => return false,
    };
    if !has_symbol_any(&elf_file, &["mbedtls_ssl_init", "mbedtls_ssl_handshake"]) { return false; }

    let resolve = |name: &str| -> Option<usize> {
        let va = find_elf_symbol(&elf_file, name)
            .or_else(|| find_elf_symbol_dyn(&elf_file, name))?;
        Some(va_to_file_offset(&elf_file, va).unwrap_or(va))
    };

    let mut attached = false;
    if let Some(off) = resolve("mbedtls_ssl_write") {
        if attach_at_offset(obj, "ssl_write_entry", binary_path, off, false, pid, links).is_ok() { attached = true; }
        let _ = attach_at_offset(obj, "ssl_write_exit", binary_path, off, true, pid, links);
    }
    if let Some(off) = resolve("mbedtls_ssl_read") {
        if attach_at_offset(obj, "ssl_read_entry", binary_path, off, false, pid, links).is_ok() { attached = true; }
        let _ = attach_at_offset(obj, "ssl_read_exit", binary_path, off, true, pid, links);
    }
    if attached { tracing::info!(binary = %binary_path, "mbedTLS static link found"); }
    attached
}

// ---------------------------------------------------------------------------
// WolfSSL static binary detection + uprobe attachment
// ---------------------------------------------------------------------------

pub fn attach_wolfssl_static(
    obj: &mut libbpf_rs::Object,
    binary_path: &str,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> bool {
    let data = match fs::read(binary_path) { Ok(d) => d, Err(_) => return false };
    let elf_file = match elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data) {
        Ok(e) => e, Err(_) => return false,
    };
    if !has_symbol_any(&elf_file, &["wolfSSL_Init", "wolfSSL_CTX_new"]) { return false; }

    let resolve = |name: &str| -> Option<usize> {
        let va = find_elf_symbol(&elf_file, name)
            .or_else(|| find_elf_symbol_dyn(&elf_file, name))?;
        Some(va_to_file_offset(&elf_file, va).unwrap_or(va))
    };

    let mut attached = false;
    if let Some(off) = resolve("wolfSSL_write") {
        if attach_at_offset(obj, "ssl_write_entry", binary_path, off, false, pid, links).is_ok() { attached = true; }
        let _ = attach_at_offset(obj, "ssl_write_exit", binary_path, off, true, pid, links);
    }
    if let Some(off) = resolve("wolfSSL_read") {
        if attach_at_offset(obj, "ssl_read_entry", binary_path, off, false, pid, links).is_ok() { attached = true; }
        let _ = attach_at_offset(obj, "ssl_read_exit", binary_path, off, true, pid, links);
    }
    if attached { tracing::info!(binary = %binary_path, "WolfSSL static link found"); }
    attached
}

fn has_symbol_any(elf_file: &elf::ElfBytes<elf::endian::AnyEndian>, names: &[&str]) -> bool {
    let check = |symtab: elf::symbol::SymbolTable<'_, _>,
                  strtab: elf::string_table::StringTable<'_>| -> bool {
        for sym in symtab.iter() {
            if let Ok(name) = strtab.get(sym.st_name as usize) {
                if names.contains(&name) { return true; }
            }
        }
        false
    };
    if let Ok(Some((st, sr))) = elf_file.symbol_table() {
        if check(st, sr) { return true; }
    }
    if let Ok(Some((st, sr))) = elf_file.dynamic_symbol_table() {
        if check(st, sr) { return true; }
    }
    false
}
