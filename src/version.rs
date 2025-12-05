use defguard_version::{Version, is_version_lower};

const MIN_CORE_VERSION: Version = Version::new(1, 6, 0);

/// Ensures Defguard Core version meets minimum version requirements.
/// Terminates the process if it doesn't.
pub(crate) fn ensure_core_version_supported(core_version: Option<&Version>) {
    let Some(core_version) = core_version else {
        error!(
            "Missing Defguard Core version information. This most likely means that Defguard Core \
            uses outdated version. Exiting."
        );
        std::process::exit(1);
    };

    if is_version_lower(core_version, &MIN_CORE_VERSION) {
        error!(
            "Defguard Core version {core_version} is not supported. Minimal supported version is \
            {MIN_CORE_VERSION}. Exiting."
        );
        std::process::exit(1);
    }

    info!("Defguard Core version {core_version} is supported");
}
