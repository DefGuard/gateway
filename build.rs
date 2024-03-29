fn main() -> Result<(), Box<dyn std::error::Error>> {
    // compiling protos using path on build time
    let mut config = prost_build::Config::new();
    // enable optional fields
    config.protoc_arg("--experimental_allow_proto3_optional");
    tonic_build::configure().compile_with_config(
        config,
        &["proto/wireguard/gateway.proto"],
        &["proto/wireguard"],
    )?;
    Ok(())
}
