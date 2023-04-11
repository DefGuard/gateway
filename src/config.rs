use crate::error::GatewayError;
use clap::Parser;
use serde::Deserialize;
use std::fs;
use toml;

#[derive(Debug, Parser, Clone, Deserialize)]
#[clap(about = "Defguard VPN gateway service")]
#[command(version)]
pub struct Config {
    #[clap(
        long,
        short = 't',
        required_unless_present = "config_path",
        env = "DEFGUARD_TOKEN",
        help = "Token received on Defguard after completing network wizard",
        default_value = ""
    )]
    pub token: String,

    #[clap(
        long,
        short = 'g',
        required_unless_present = "config_path",
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
    pub grpc_ca: Option<String>,

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

    #[clap(long = "config", short, help = "Config file")]
    #[serde(skip)]
    config_path: Option<std::path::PathBuf>,
}

pub fn get_config() -> Result<Config, GatewayError> {
    // parse CLI arguments to get config file path
    let cli_config = Config::parse();

    // load config from file if one was specified
    if let Some(config_path) = cli_config.config_path {
        let config_toml = fs::read_to_string(config_path).map_err(|err| GatewayError::InvalidConfigFile(err.to_string()))?;
        let file_config: Config = toml::from_str(&config_toml).map_err(|err| GatewayError::InvalidConfigFile(err.message().to_string()))?;
        return Ok(file_config);
    }

    Ok(cli_config)
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Config::command().debug_assert()
}
