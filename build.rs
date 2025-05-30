use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // set VERGEN_GIT_SHA env variable based on git commit hash
    let git2 = Git2Builder::default().branch(true).sha(true).build()?;
    Emitter::default().add_instructions(&git2)?.emit()?;

    // compiling protos using path on build time
    let mut config = tonic_build::Config::new();
    // enable optional fields
    config.protoc_arg("--experimental_allow_proto3_optional");
    tonic_build::configure().compile_protos_with_config(
        config,
        &[
            "proto/wireguard/gateway.proto",
            "proto/enterprise/firewall/firewall.proto",
        ],
        &["proto/wireguard", "proto/enterprise/firewall"],
    )?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
