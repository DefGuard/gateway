#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
use std::fs::{File, OpenOptions};

#[cfg(target_os = "linux")]
use nftnl::Batch;

use super::{FirewallError, FirewallRule, Policy};

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
const DEV_PF: &str = "/dev/pf";

#[allow(dead_code)]
pub struct FirewallApi {
    pub(crate) ifname: String,
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    pub(crate) file: File,
    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
    pub(crate) default_policy: Policy,
    #[cfg(target_os = "linux")]
    pub(crate) batch: Option<Batch>,
}

impl FirewallApi {
    pub fn new<S: Into<String>>(ifname: S) -> Result<Self, FirewallError> {
        Ok(Self {
            ifname: ifname.into(),
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
            file: OpenOptions::new().read(true).write(true).open(DEV_PF)?,
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "netbsd"))]
            default_policy: Policy::Deny,
            #[cfg(target_os = "linux")]
            batch: None,
        })
    }
}

pub(crate) trait FirewallManagementApi {
    /// Set up the firewall with `default_policy`, `priority`, and cleans up any existing rules.
    fn setup(&mut self, default_policy: Policy, priority: Option<i32>)
        -> Result<(), FirewallError>;

    /// Clean up the firewall rules.
    fn cleanup(&mut self) -> Result<(), FirewallError>;

    /// Add fireall `rules`.
    fn add_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), FirewallError>;

    /// Set masquerade status.
    fn set_masquerade_status(&mut self, enabled: bool) -> Result<(), FirewallError>;

    /// Begin rule transaction.
    fn begin(&mut self) -> Result<(), FirewallError>;

    /// Commit rule transaction.
    fn commit(&mut self) -> Result<(), FirewallError>;
}
