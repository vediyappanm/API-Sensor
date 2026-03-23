use std::fs;

// ---------------------------------------------------------------------------
// Go TLS ELF scanning + capstone RET finding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GoTlsOffsets {
    pub binary_path: String,
    pub write_offset: usize,
    pub write_rets: Vec<usize>,
    pub read_offset: usize,
    pub read_rets: Vec<usize>,
    pub go_version: String,
    pub goid_offset: u64,
}

pub fn find_go_tls_offsets(binary_path: &str) -> Option<GoTlsOffsets> {
    let data = fs::read(binary_path).ok()?;
    let elf_file = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data).ok()?;

    let go_version = parse_go_version_from_binary(&data).unwrap_or_else(|| "unknown".to_string());
    let goid_offset = goid_offset_for_version(&go_version);

    let write_offset = find_elf_symbol(&elf_file, "crypto/tls.(*Conn).Write")
        .or_else(|| find_elf_symbol_dyn(&elf_file, "crypto/tls.(*Conn).Write"));
    let read_offset = find_elf_symbol(&elf_file, "crypto/tls.(*Conn).Read")
        .or_else(|| find_elf_symbol_dyn(&elf_file, "crypto/tls.(*Conn).Read"));

    let write_offset = match write_offset {
        Some(o) => o,
        None => {
            tracing::info!(binary = %binary_path, "Go binary has stripped symbols — Go TLS skipped");
            return None;
        }
    };
    let read_offset = read_offset?;

    let write_size = get_elf_symbol_size(&elf_file, write_offset).unwrap_or(4096);
    let read_size = get_elf_symbol_size(&elf_file, read_offset).unwrap_or(4096);

    let arch = detect_elf_arch(&elf_file);

    // Symbol values are virtual addresses; convert to file offsets for disassembly and uprobe attachment.
    let write_file_off = va_to_file_offset(&elf_file, write_offset).unwrap_or(write_offset);
    let read_file_off = va_to_file_offset(&elf_file, read_offset).unwrap_or(read_offset);

    let write_rets = find_ret_offsets(&data, write_file_off, write_size, &arch).ok()?;
    let read_rets = find_ret_offsets(&data, read_file_off, read_size, &arch).ok()?;

    if write_rets.is_empty() || read_rets.is_empty() {
        tracing::warn!(binary = %binary_path, "no RET instructions found in Go TLS");
        return None;
    }

    Some(GoTlsOffsets {
        binary_path: binary_path.to_string(),
        write_offset: write_file_off,
        write_rets,
        read_offset: read_file_off,
        read_rets,
        go_version,
        goid_offset,
    })
}

pub fn find_elf_symbol(
    elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    name: &str,
) -> Option<usize> {
    let (symtab, strtab) = elf_file.symbol_table().ok()??;
    for sym in symtab.iter() {
        if sym.st_value > 0 {
            if let Ok(sym_name) = strtab.get(sym.st_name as usize) {
                if sym_name == name {
                    return Some(sym.st_value as usize);
                }
            }
        }
    }
    None
}

pub fn find_elf_symbol_dyn(
    elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    name: &str,
) -> Option<usize> {
    let (symtab, strtab) = elf_file.dynamic_symbol_table().ok()??;
    for sym in symtab.iter() {
        if sym.st_value > 0 {
            if let Ok(sym_name) = strtab.get(sym.st_name as usize) {
                if sym_name == name {
                    return Some(sym.st_value as usize);
                }
            }
        }
    }
    None
}

fn get_elf_symbol_size(
    elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    offset: usize,
) -> Option<usize> {
    if let Ok(Some((symtab, _))) = elf_file.symbol_table() {
        for sym in symtab.iter() {
            if sym.st_value as usize == offset && sym.st_size > 0 {
                return Some(sym.st_size as usize);
            }
        }
    }
    None
}

fn detect_elf_arch(elf_file: &elf::ElfBytes<elf::endian::AnyEndian>) -> String {
    match elf_file.ehdr.e_machine {
        elf::abi::EM_X86_64 => "x86_64".to_string(),
        elf::abi::EM_AARCH64 => "aarch64".to_string(),
        other => format!("unknown_{}", other),
    }
}

/// Convert an ELF virtual address to a file offset using PT_LOAD segments.
pub fn va_to_file_offset(
    elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    va: usize,
) -> Option<usize> {
    let segments = elf_file.segments()?;
    for phdr in segments.iter() {
        if phdr.p_type != elf::abi::PT_LOAD {
            continue;
        }
        let seg_start = phdr.p_vaddr as usize;
        let seg_end = seg_start + phdr.p_filesz as usize;
        if va >= seg_start && va < seg_end {
            return Some(va - seg_start + phdr.p_offset as usize);
        }
    }
    None
}

fn find_ret_offsets(
    data: &[u8],
    func_offset: usize,
    func_size: usize,
    arch: &str,
) -> anyhow::Result<Vec<usize>> {
    use capstone::prelude::*;
    let end = (func_offset + func_size).min(data.len());
    if func_offset >= data.len() || func_offset >= end {
        return Ok(vec![]);
    }
    let func_bytes = &data[func_offset..end];

    let cs = match arch {
        "x86_64" => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .map_err(|e| anyhow::anyhow!("capstone x86_64: {:?}", e))?,
        "aarch64" => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| anyhow::anyhow!("capstone arm64: {:?}", e))?,
        _ => return Ok(vec![]),
    };

    let insns = cs
        .disasm_all(func_bytes, func_offset as u64)
        .map_err(|e| anyhow::anyhow!("disasm: {:?}", e))?;

    let ret_ids: &[u32] = match arch {
        "x86_64" => &[
            capstone::arch::x86::X86Insn::X86_INS_RET as u32,
            capstone::arch::x86::X86Insn::X86_INS_RETF as u32,
        ],
        "aarch64" => &[capstone::arch::arm64::Arm64Insn::ARM64_INS_RET as u32],
        _ => &[],
    };

    let mut offsets = Vec::new();
    for insn in insns.as_ref() {
        if ret_ids.contains(&(insn.id().0)) {
            offsets.push(insn.address() as usize);
        }
    }
    Ok(offsets)
}

fn parse_go_version_from_binary(data: &[u8]) -> Option<String> {
    // Go 1.18+ build info magic — NOTE: "buildinf" (not "buildinfo")
    let magic = b"\xff Go buildinf:";
    if let Some(pos) = data.windows(magic.len()).position(|w| w == magic) {
        // After magic (14B) + 2B header: scan forward for the embedded "go1." version string
        let scan_start = pos + magic.len() + 2;
        let scan_end = (scan_start + 32).min(data.len());
        for i in scan_start..scan_end.saturating_sub(4) {
            if &data[i..i + 4] == b"go1." {
                let end = (i + 16).min(data.len());
                if let Ok(s) = std::str::from_utf8(&data[i..end]) {
                    let ver: String = s
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '.')
                        .collect();
                    if ver.len() > 3 {
                        return Some(ver);
                    }
                }
            }
        }
        // Fallback: return a placeholder so we still recognise it as a Go binary
        return Some("go1".to_string());
    }
    // Fallback: search for "go1." anywhere in the binary (no size limit)
    let search_end = data.len();
    for i in 0..search_end.saturating_sub(4) {
        if &data[i..i + 4] == b"go1." {
            let end = (i + 12).min(data.len());
            if let Ok(s) = std::str::from_utf8(&data[i..end]) {
                let ver: String = s
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '.')
                    .collect();
                if ver.len() > 3 {
                    return Some(ver);
                }
            }
        }
    }
    None
}

fn goid_offset_for_version(version: &str) -> u64 {
    if version.contains("go1.17") || version.contains("go1.16") {
        192
    } else {
        152
    }
}

/// Maximum file size to read when scanning for Go binaries (200 MB).
const MAX_GO_SCAN_SIZE: u64 = 200 * 1024 * 1024;

/// Detect Go binaries. When pid > 0, scans that single process.
/// When pid <= 0, scans all running processes (global bootstrap).
/// Returns a list of (host_path, pid) tuples for each detected Go binary.
pub fn detect_go_binaries(pid: i32) -> Vec<(String, i32)> {
    let pids = if pid > 0 {
        vec![pid]
    } else {
        crate::http::enumerate_pids()
    };

    let mut results = Vec::new();
    let mut seen_binaries = std::collections::HashSet::new();

    for p in &pids {
        let maps_path = format!("/proc/{}/maps", p);
        let maps = match fs::read_to_string(&maps_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        for line in maps.lines() {
            if !line.contains("r-xp") {
                continue;
            }
            let path = match line.split_whitespace().last() {
                Some(p) => p,
                None => continue,
            };
            if path.starts_with('/') {
                if path.contains(".so") {
                    continue;
                }
                // Dedup by container-internal path + pid namespace to avoid
                // re-scanning the same binary from multiple r-xp mappings.
                let dedup_key = format!("{}:{}", p, path);
                if !seen_binaries.insert(dedup_key) {
                    continue;
                }

                let host_path = crate::types::proc_root_path(*p, path);
                if let Ok(meta) = fs::metadata(&host_path) {
                    if meta.len() > MAX_GO_SCAN_SIZE {
                        continue;
                    }
                }
                let data = match fs::read(&host_path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                if parse_go_version_from_binary(&data).is_some() {
                    tracing::debug!(original = %path, resolved = %host_path, pid = p, "Go binary detected");
                    results.push((host_path, *p));
                }
            }
        }
    }
    results
}

pub fn attach_go_tls_probes(
    obj: &mut libbpf_rs::Object,
    offsets: &GoTlsOffsets,
    links: &mut Vec<libbpf_rs::Link>,
    pid: i32,
) {
    let _ = attach_at_offset(
        obj,
        "go_tls_write_entry",
        &offsets.binary_path,
        offsets.write_offset,
        false,
        pid,
        links,
    );
    for &ret in &offsets.write_rets {
        let _ = attach_at_offset(
            obj,
            "go_tls_write_exit",
            &offsets.binary_path,
            ret,
            false,
            pid,
            links,
        );
    }
    let _ = attach_at_offset(
        obj,
        "go_tls_read_entry",
        &offsets.binary_path,
        offsets.read_offset,
        false,
        pid,
        links,
    );
    for &ret in &offsets.read_rets {
        let _ = attach_at_offset(
            obj,
            "go_tls_read_exit",
            &offsets.binary_path,
            ret,
            false,
            pid,
            links,
        );
    }
}

pub fn attach_at_offset(
    obj: &mut libbpf_rs::Object,
    prog_name: &str,
    binary: &str,
    offset: usize,
    retprobe: bool,
    pid: i32,
    links: &mut Vec<libbpf_rs::Link>,
) -> anyhow::Result<()> {
    let prog = obj
        .prog_mut(prog_name)
        .ok_or_else(|| anyhow::anyhow!("missing BPF program {}", prog_name))?;
    // Use attach_uprobe (not attach_uprobe_with_opts) so that func_name is NULL and
    // libbpf uses func_offset directly without attempting an ELF symbol lookup.
    let link = prog
        .attach_uprobe(retprobe, pid, binary, offset)
        .map_err(|e| anyhow::anyhow!("attach {} at offset {:#x}: {}", prog_name, offset, e))?;
    links.push(link);
    Ok(())
}
