//! Kernel compatibility preflight.
//!
//! The sensor follows the Falco `modern_bpf` / Cilium portability model: a
//! single CO-RE BPF object that relocates against the target kernel's BTF at
//! load time, with a documented minimum kernel of **5.8** (the floor required
//! by the BPF ring buffer and the CO-RE helper set this program uses).
//!
//! This module runs BEFORE the BPF object is loaded so that an unsupported
//! kernel produces a clear, actionable error instead of a cryptic libbpf load
//! failure deep in the startup path.
//!
//! Portability tiers:
//!   * **Tier 1 (verified):** kernel >= 5.8 with BTF (`/sys/kernel/btf/vmlinux`).
//!     Covers Ubuntu 20.04+, RHEL 9, Debian 11+, Amazon Linux 2022+, and all
//!     modern managed Kubernetes node images.
//!   * **Tier 2 (BTF-less, e.g. RHEL 7 / Ubuntu 18.04):** requires shipping a
//!     tailored BTF (BTFHub / `bpftool gen min_core_btf`) and feeding it to
//!     libbpf via `btf_custom_path`. Detected and reported here with remediation;
//!     the runtime wiring is the documented next step (see docs/PORTABILITY.md).

use anyhow::{bail, Result};

/// Minimum supported kernel: ring buffer (5.8) + CO-RE relocations.
pub const MIN_KERNEL_MAJOR: u32 = 5;
pub const MIN_KERNEL_MINOR: u32 = 8;

const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// Facts about the running kernel relevant to BPF portability.
#[derive(Debug, Clone)]
pub struct KernelInfo {
    /// Full `uname -r` release string, e.g. "6.8.0-111-generic".
    pub release: String,
    /// Parsed major version (0 if unknown).
    pub major: u32,
    /// Parsed minor version (0 if unknown).
    pub minor: u32,
    /// `uname -m` machine, e.g. "x86_64" / "aarch64".
    pub machine: String,
    /// Whether the kernel exposes BTF at `/sys/kernel/btf/vmlinux`.
    pub has_btf: bool,
}

impl KernelInfo {
    /// True when the running kernel meets the supported minimum (>= 5.8).
    /// A major of 0 means we could not parse the release; we treat that as
    /// "assume modern" rather than blocking startup on a parse failure.
    pub fn meets_minimum(&self) -> bool {
        if self.major == 0 {
            return true;
        }
        self.major > MIN_KERNEL_MAJOR
            || (self.major == MIN_KERNEL_MAJOR && self.minor >= MIN_KERNEL_MINOR)
    }
}

/// Read kernel release + machine via `uname(2)` and probe for BTF.
pub fn detect() -> KernelInfo {
    let mut release = String::new();
    let mut machine = String::new();

    // SAFETY: `uname` fully populates a zeroed `utsname`; each field is a
    // NUL-terminated C string which `CStr::from_ptr` reads safely. Using
    // `libc::c_char` keeps the pointer type correct on both x86_64 (i8) and
    // aarch64 (u8).
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) == 0 {
            release = cstr_to_string(uts.release.as_ptr());
            machine = cstr_to_string(uts.machine.as_ptr());
        }
    }

    let (major, minor) = parse_kernel_version(&release);
    let has_btf = std::path::Path::new(KERNEL_BTF_PATH).exists();

    KernelInfo {
        release,
        major,
        minor,
        machine,
        has_btf,
    }
}

/// SAFETY: `p` must point to a NUL-terminated C string valid for the call.
unsafe fn cstr_to_string(p: *const libc::c_char) -> String {
    std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
}

/// Extract (major, minor) from a kernel release string such as
/// "6.8.0-111-generic" or "5.10.0". Returns (0, 0) if unparseable.
fn parse_kernel_version(release: &str) -> (u32, u32) {
    let mut nums = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().unwrap_or(0));
    let major = nums.next().unwrap_or(0);
    let minor = nums.next().unwrap_or(0);
    (major, minor)
}

/// Validate the running kernel and log a compatibility report.
///
/// Fails fast (with an operator-actionable message) when:
///   * the kernel is older than the supported minimum (ring buffer unavailable), or
///   * the kernel lacks BTF and no custom BTF was supplied (CO-RE cannot relocate).
///
/// On success returns the detected [`KernelInfo`] for downstream use/logging.
pub fn preflight(custom_btf: Option<&str>) -> Result<KernelInfo> {
    let k = detect();

    tracing::info!(
        kernel = %k.release,
        arch = %k.machine,
        btf = k.has_btf,
        min_kernel = %format!("{}.{}", MIN_KERNEL_MAJOR, MIN_KERNEL_MINOR),
        "kernel compatibility preflight"
    );

    // --- Minimum-kernel gate (BPF ring buffer requires >= 5.8) -------------
    if !k.meets_minimum() {
        bail!(
            "unsupported kernel {} (detected {}.{}): minimum supported is {}.{}. \
             The BPF ring buffer and CO-RE relocations this sensor relies on require \
             kernel {}.{}+ (the Falco modern_bpf / Cilium baseline). \
             Run the sensor on a {}.{}+ node, or build a perf-buffer variant for older kernels.",
            k.release,
            k.major,
            k.minor,
            MIN_KERNEL_MAJOR,
            MIN_KERNEL_MINOR,
            MIN_KERNEL_MAJOR,
            MIN_KERNEL_MINOR,
            MIN_KERNEL_MAJOR,
            MIN_KERNEL_MINOR,
        );
    }

    // --- BTF gate (CO-RE needs the target kernel's BTF) --------------------
    if !k.has_btf {
        match custom_btf {
            Some(p) if std::path::Path::new(p).exists() => {
                tracing::warn!(
                    btf = %p,
                    kernel_btf = KERNEL_BTF_PATH,
                    "kernel lacks native BTF; using supplied custom BTF for CO-RE relocation"
                );
            }
            Some(p) => bail!(
                "supplied custom BTF path does not exist: {} \
                 (kernel {} has no {KERNEL_BTF_PATH})",
                p,
                k.release
            ),
            None => bail!(
                "kernel {} exposes no BTF ({KERNEL_BTF_PATH} missing — built with \
                 CONFIG_DEBUG_INFO_BTF=n). CO-RE cannot relocate the BPF program. \
                 Remediation: (1) run on a kernel built with CONFIG_DEBUG_INFO_BTF=y \
                 (all modern distro kernels), or (2) supply a tailored BTF generated \
                 with `bpftool gen min_core_btf` or downloaded from BTFHub. \
                 See docs/PORTABILITY.md for the BTF-less (RHEL 7 / Ubuntu 18.04) path.",
                k.release
            ),
        }
    }

    Ok(k)
}

/// Linux bpffs magic from `<uapi/linux/magic.h>`.
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

/// Pre-flight the BPF filesystem WITHOUT the classic "write a temp file" mistake.
///
/// A real bpffs accepts BPF object **pins** but rejects regular-file creation and
/// `mkdir` with `EPERM`. The previous check wrote a regular file to `/sys/fs/bpf`
/// and therefore FATAL-ed on startup on **every** properly-mounted bpffs node
/// (i.e. every real Kubernetes node, including the one the Helm DaemonSet mounts).
///
/// This sensor streams events over a ring buffer and does **not** pin maps, so
/// bpffs is not strictly required. We detect the situation via `statfs` magic,
/// log it, and never abort on it.
pub fn check_bpf_fs() {
    let path = "/sys/fs/bpf";
    if !std::path::Path::new(path).exists() {
        tracing::warn!(
            path,
            "bpffs not present; BPF object pinning unavailable (ring-buffer capture is \
             unaffected). To enable pinning: `mount -t bpf bpf /sys/fs/bpf` — the Helm \
             DaemonSet mounts it automatically."
        );
        return;
    }
    if is_bpf_fs(path) {
        tracing::info!(path, "bpffs detected (BPF object pinning available)");
    } else {
        tracing::warn!(
            path,
            "/sys/fs/bpf exists but is not a bpffs mount; pinning unavailable \
             (ring-buffer capture is unaffected)."
        );
    }
}

/// True if `path` is a mounted BPF filesystem (by `statfs` magic).
fn is_bpf_fs(path: &str) -> bool {
    let cpath = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // SAFETY: `statfs` fully populates a zeroed struct; `cpath` is a valid C string.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        libc::statfs(cpath.as_ptr(), &mut s) == 0 && (s.f_type as u64) == BPF_FS_MAGIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_release() {
        assert_eq!(parse_kernel_version("6.8.0-111-generic"), (6, 8));
        assert_eq!(parse_kernel_version("5.10.0"), (5, 10));
        assert_eq!(parse_kernel_version("4.18.0-553.el8_10.x86_64"), (4, 18));
    }

    #[test]
    fn parses_unknown_release() {
        assert_eq!(parse_kernel_version(""), (0, 0));
        assert_eq!(parse_kernel_version("custom-kernel"), (0, 0));
    }

    #[test]
    fn minimum_gate() {
        let mk = |major, minor| KernelInfo {
            release: String::new(),
            major,
            minor,
            machine: String::new(),
            has_btf: true,
        };
        assert!(!mk(4, 18).meets_minimum());
        assert!(!mk(5, 4).meets_minimum());
        assert!(mk(5, 8).meets_minimum());
        assert!(mk(5, 15).meets_minimum());
        assert!(mk(6, 8).meets_minimum());
        // Unparseable release => assume modern, don't block startup.
        assert!(mk(0, 0).meets_minimum());
    }
}
