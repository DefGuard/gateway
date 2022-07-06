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

#[derive(Debug, Parser)]
#[clap(name = "vpn-gateway", about = "DefGuard VPN gateway service")]
pub struct Config {
    #[clap(
        long,
        short = 'u',
        env = "DEFGUARD_USERSPACE",
        help = "Use userspace wireguard implementation, useful on systems without native wireguard support"
    )]
    userspace: bool,

    #[clap(
        long,
        short = 'g',
        env = "DEFGUARD_GRPC_URL",
        default_value = "http://localhost:50055",
        help = "Defguard server gRPC endpoint URL"
    )]
    grpc_url: String,

    #[clap(long, env = "DEFGUARD_GRPC_CA")]
    grpc_ca: Option<String>,

    #[clap(
        long,
        short = 'p',
        env = "DEFGUARD_STATS_PERIOD",
        default_value = "60",
        help = "Defines how often (seconds) should interface statistics be sent to DefGuard server"
    )]
    stats_period: u64,

    #[clap(
        long,
        short = 't',
        env = "DEFGUARD_TOKEN",
        help = "Token received on Defguard after completing network wizard"
    )]
    token: String,

    #[clap(
        long,
        short = 'i',
        env = "DEFGUARD_IFNAME",
        default_value = "wg0",
        help = "Interface name (e.g. wg0)"
    )]
    ifname: String,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
