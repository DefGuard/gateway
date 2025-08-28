use defguard_version::Version;

const MIN_CORE_VERSION: Version = Version::new(1, 5, 0);

/// Ensures the core version meets minimum version requirements.
/// Terminates the process if it doesn't.
pub(crate) fn ensure_core_version_supported(core_version: Option<&Version>) {
    let Some(core_version) = core_version else {
        error!("Missing core component version information. This most likely means that core component uses unsupported version. Exiting.");
        std::process::exit(1);
    };
    if core_version < &MIN_CORE_VERSION {
        error!("Core version {core_version} is not supported. Minimal supported core version is {MIN_CORE_VERSION}. Exiting.");
        std::process::exit(1);
    }

    info!("Core version {core_version} is supported");
}
