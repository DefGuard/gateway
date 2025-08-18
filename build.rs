use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // set VERGEN_GIT_SHA env variable based on git commit hash
    let git2 = Git2Builder::default().branch(true).sha(true).build()?;
    Emitter::default().add_instructions(&git2)?.emit()?;

    tonic_prost_build::configure()
        // enable optional fields
        .protoc_arg("--experimental_allow_proto3_optional")
        // compiling protos using path on build time
        .compile_protos(
            &[
                "proto/wireguard/gateway.proto",
                "proto/enterprise/firewall/firewall.proto",
            ],
            &["proto/wireguard", "proto/enterprise/firewall"],
        )?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
