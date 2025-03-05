use std::{fs, path::PathBuf};

use clap::Parser;
use serde::Deserialize;
use toml;

use crate::error::GatewayError;

#[derive(Debug, Parser, Clone, Deserialize)]
#[clap(about = "Defguard VPN gateway service")]
#[command(version)]
pub struct Config {
    /// Token received from Defguard after completing the network wizard
    #[arg(
        long,
        short = 't',
        required_unless_present = "config_path",
        env = "DEFGUARD_TOKEN",
        default_value = ""
    )]
    pub token: String,

    #[arg(long, env = "DEFGUARD_GATEWAY_NAME")]
    pub name: Option<String>,

    /// defguard server gRPC endpoint URL
    #[arg(
        long,
        short = 'g',
        required_unless_present = "config_path",
        env = "DEFGUARD_GRPC_URL",
        default_value = ""
    )]
    pub grpc_url: String,

    /// Use userspace WireGuard implementation e.g. wireguard-go
    #[arg(long, short = 'u', env = "DEFGUARD_USERSPACE")]
    pub userspace: bool,

    /// Path to CA file
    #[arg(long, env = "DEFGUARD_GRPC_CA")]
    pub grpc_ca: Option<PathBuf>,

    /// Defines how often (in seconds) interface statistics are sent to Defguard server
    #[arg(long, short = 'p', env = "DEFGUARD_STATS_PERIOD", default_value = "30")]
    pub stats_period: u64,

    /// Network interface name (e.g. wg0)
    #[arg(long, short = 'i', env = "DEFGUARD_IFNAME", default_value = "wg0")]
    pub ifname: String,

    /// Write process ID (PID) to this file
    #[arg(long)]
    pub pidfile: Option<PathBuf>,

    /// Log to syslog
    #[arg(long, short = 's')]
    pub use_syslog: bool,

    /// Syslog facility
    #[arg(long, default_value = "LOG_USER")]
    pub syslog_facility: String,

    /// Syslog socket path
    #[arg(long, default_value = "/var/run/log")]
    pub syslog_socket: PathBuf,

    /// Configuration file path
    #[arg(long = "config", short)]
    #[serde(skip)]
    config_path: Option<PathBuf>,

    /// Command to run before bringing up the interface.
    #[arg(long, env = "PRE_UP")]
    pub pre_up: Option<String>,

    /// Command to run after bringing up the interface.
    #[arg(long, env = "POST_UP")]
    pub post_up: Option<String>,

    /// Command to run before bringing down the interface.
    #[arg(long, env = "PRE_DOWN")]
    pub pre_down: Option<String>,

    /// Command to run after bringing down the interface.
    #[arg(long, env = "POST_DOWN")]
    pub post_down: Option<String>,
    /// A HTTP port that will expose the REST HTTP gateway health status
    /// 200 Gateway is working and is connected to CORE
    /// 503 - gateway works but is not connected to CORE
    #[arg(long, env = "HEALTH_PORT")]
    pub health_port: Option<u16>,

    /// Whether the firewall should automatically apply masquerading
    #[arg(long, env = "MASQUERADE")]
    #[serde(default)]
    pub masquerade: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            token: "TOKEN".into(),
            name: None,
            grpc_url: "http://localhost:50051".into(),
            userspace: false,
            grpc_ca: None,
            stats_period: 15,
            ifname: "wg0".into(),
            pidfile: None,
            use_syslog: false,
            syslog_facility: String::new(),
            syslog_socket: PathBuf::new(),
            config_path: None,
            pre_up: None,
            post_up: None,
            pre_down: None,
            post_down: None,
            health_port: None,
            masquerade: false,
        }
    }
}

pub fn get_config() -> Result<Config, GatewayError> {
    // parse CLI arguments to get config file path
    let cli_config = Config::parse();

    // load config from file if one was specified
    if let Some(config_path) = cli_config.config_path {
        let config_toml = fs::read_to_string(config_path)
            .map_err(|err| GatewayError::InvalidConfigFile(err.to_string()))?;
        let file_config: Config = toml::from_str(&config_toml)
            .map_err(|err| GatewayError::InvalidConfigFile(err.message().to_string()))?;
        return Ok(file_config);
    }

    Ok(cli_config)
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Config::command().debug_assert();
}
