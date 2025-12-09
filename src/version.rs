use defguard_version::{Version, is_version_lower};

const MIN_CORE_VERSION: Version = Version::new(1, 6, 0);

/// Checks if Defguard Core's version meets minimum version requirements.
pub(crate) fn is_core_version_supported(core_version: Option<&Version>) -> bool {
    let Some(core_version) = core_version else {
        error!(
            "Missing Defguard Core version information. This most likely means that Defguard Core \
            uses outdated version."
        );
        return false;
    };

    if is_version_lower(core_version, &MIN_CORE_VERSION) {
        error!(
            "Defguard Core version {core_version} is not supported. Minimal supported version is \
            {MIN_CORE_VERSION}."
        );
        false
    } else {
        info!("Defguard Core version {core_version} is supported");
        true
    }
}
