use vergen_git2::{Emitter, Git2};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // set VERGEN_GIT_SHA env variable based on git commit hash
    let git2 = Git2::builder().sha(true).build();
    Emitter::default().add_instructions(&git2)?.emit()?;

    tonic_prost_build::configure()
        // Skip `Debug` for types with sensitive information.
        .skip_debug([
            "defguard.gateway.v2.Configuration",
            "defguard.gateway.v2.CoreResponse",
            "defguard.gateway.v2.Peer",
            "defguard.gateway.v2.Update",
        ])
        // enable optional fields
        .protoc_arg("--experimental_allow_proto3_optional")
        // compiling protos using path on build time
        .compile_protos(
            &[
                "proto/v2/gateway.proto",
                "proto/enterprise/v2/firewall/firewall.proto",
            ],
            &["proto"],
        )?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
