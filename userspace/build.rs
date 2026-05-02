use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Proto compilation
    println!("cargo:rerun-if-changed=proto/runtime/v1/api.proto");
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(&["proto/runtime/v1/api.proto"], &["proto"])?;

    // BPF compilation — optional; skipped if clang/bpftool not installed
    compile_bpf();
    Ok(())
}

fn compile_bpf() {
    let bpf_src = PathBuf::from("../bpf/http_trace.bpf.c");
    if !bpf_src.exists() { return; }

    println!("cargo:rerun-if-changed=../bpf/http_trace.bpf.c");
    println!("cargo:rerun-if-changed=../bpf/vmlinux.h");

    // Detect target arch for BPF compilation
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let arch_flag = match arch.as_str() {
        "aarch64" => "-D__TARGET_ARCH_arm64",
        _         => "-D__TARGET_ARCH_x86",
    };

    // Candidate include paths (distribution-agnostic)
    let includes = [
        "/usr/include/bpf",
        "/usr/include/linux",
        "/usr/local/include",
        "../bpf",
    ];

    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
    let bpf_obj = format!("{}/http_trace.bpf.o", out_dir);

    // Verify clang is available
    let clang_ok = Command::new("clang").arg("--version").output().is_ok();
    if !clang_ok {
        println!("cargo:warning=clang not found — BPF object will not be recompiled. Install clang to enable.");
        return;
    }

    let mut cmd = Command::new("clang");
    cmd.args(["-g", "-O2", "-target", "bpf", arch_flag,
              "-Wno-unused-value", "-Wno-pointer-sign",
              "-Wno-compare-distinct-pointer-types"]);
    for inc in &includes {
        cmd.arg(format!("-I{}", inc));
    }
    cmd.args(["-c", bpf_src.to_str().unwrap(), "-o", &bpf_obj]);

    match cmd.status() {
        Ok(s) if s.success() => {
            println!("cargo:rustc-env=BPF_OBJECT_PATH={}", bpf_obj);
            println!("cargo:warning=BPF object compiled → {}", bpf_obj);
            // Run bpftool to generate a skeleton header if available
            let skel_h = format!("{}/http_trace.skel.h", out_dir);
            let _ = Command::new("bpftool")
                .args(["gen", "skeleton", &bpf_obj])
                .arg("-o").arg(&skel_h)
                .status();
        }
        Ok(_)  => println!("cargo:warning=BPF compilation failed (clang returned non-zero)"),
        Err(e) => println!("cargo:warning=BPF compilation error: {}", e),
    }
}
