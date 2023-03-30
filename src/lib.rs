#![allow(clippy::derive_partial_eq_without_eq)]

mod error;
pub mod gateway;
mod utils;
pub mod wireguard;

pub mod proto {
    tonic::include_proto!("gateway");
}

#[macro_use]
extern crate log;

use clap::Parser;

#[derive(Debug, Parser, Clone)]
#[clap(about = "Defguard VPN gateway service")]
pub struct Config {
    #[clap(
        long,
        short = 't',
        required_unless_present = "version",
        env = "DEFGUARD_TOKEN",
        help = "Token received on Defguard after completing network wizard",
        default_value = ""
    )]
    pub token: String,

    #[clap(
        long,
        short = 'g',
        required_unless_present = "version",
        env = "DEFGUARD_GRPC_URL",
        help = "Defguard server gRPC endpoint URL",
        default_value = ""
    )]
    pub grpc_url: String,

    #[clap(
        long,
        short = 'u',
        env = "DEFGUARD_USERSPACE",
        help = "Use userspace WireGuard implementation e.g. wireguard-go"
    )]
    pub userspace: bool,

    #[clap(long, env = "DEFGUARD_GRPC_CA")]
    pub grpc_ca: String,

    #[clap(
        long,
        short = 'p',
        env = "DEFGUARD_STATS_PERIOD",
        default_value = "60",
        help = "Defines how often (seconds) should interface statistics be sent to Defguard server"
    )]
    pub stats_period: u64,

    #[clap(
        long,
        short = 'i',
        env = "DEFGUARD_IFNAME",
        default_value = "wg0",
        help = "Interface name (e.g. wg0)"
    )]
    pub ifname: String,

    #[clap(long, help = "Write pid to this file")]
    pub pidfile: Option<String>,

    #[clap(long, short = 's', help = "Log to syslog")]
    pub use_syslog: bool,

    #[clap(long, default_value = "LOG_USER", help = "Log to syslog")]
    pub syslog_facility: String,

    #[clap(long, default_value = "/var/run/log", help = "Log to syslog")]
    pub syslog_socket: String,

    #[clap(long, short = 'v', action, help = "Show version and quit")]
    pub version: bool,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Masks object's field with "***" string.
/// Used to log sensitive/secret objects.
#[macro_export]
macro_rules! mask {
    ($object:expr, $field:ident) => {{
        let mut object = $object.clone();
        object.$field = String::from("***");
        object
    }};
}
