fn main() -> Result<(), Box<dyn std::error::Error>> {
    // compiling protos using path on build time
    tonic_build::compile_protos("proto/wireguard/wireguard_service.proto")?;
    Ok(())
}
