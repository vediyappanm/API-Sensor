fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/runtime/v1/api.proto");
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(&["proto/runtime/v1/api.proto"], &["proto"])?;
    Ok(())
}
