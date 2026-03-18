fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/runtime/v1/api.proto");
    tonic_build::configure()
        .build_server(false)
        .compile(&["proto/runtime/v1/api.proto"], &["proto"])?;
    Ok(())
}
