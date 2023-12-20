pub mod config;
pub mod error;
pub mod gateway;
pub mod server;

pub mod proto {
    tonic::include_proto!("gateway");
}

#[macro_use]
extern crate log;

use std::{process, str::FromStr, time::SystemTime};

use config::Config;
use defguard_wireguard_rs::{host::Peer, net::IpAddrMask, InterfaceConfiguration};
use error::GatewayError;
use syslog::{BasicLogger, Facility, Formatter3164};

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

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

/// Initialize logging to syslog.
pub fn init_syslog(config: &Config, pid: u32) -> Result<(), GatewayError> {
    let formatter = Formatter3164 {
        facility: Facility::from_str(&config.syslog_facility).unwrap_or_default(),
        hostname: None,
        process: "defguard-gateway".into(),
        pid,
    };
    let logger = syslog::unix_custom(formatter, &config.syslog_socket)?;
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))?;
    log::set_max_level(log::LevelFilter::Debug);
    Ok(())
}

/// Execute command passed as argument.
pub fn execute_command(command: &str) -> Result<(), GatewayError> {
    let mut command_parts = command.split_whitespace();

    if let Some(command) = command_parts.next() {
        let output = process::Command::new(command)
            .args(command_parts)
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            info!("Command executed successfully. Stdout:\n{}", stdout);
            if !stderr.is_empty() {
                error!("Stderr:\n{stderr}");
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Error executing command. Stderr:\n{stderr}");
        }
    }
    Ok(())
}

impl From<proto::Configuration> for InterfaceConfiguration {
    fn from(config: proto::Configuration) -> Self {
        let peers = config.peers.into_iter().map(Peer::from).collect();
        InterfaceConfiguration {
            name: config.name,
            prvkey: config.prvkey,
            address: config.address,
            port: config.port,
            peers,
        }
    }
}

impl From<proto::Peer> for Peer {
    fn from(proto_peer: proto::Peer) -> Self {
        let mut peer = Self::new(proto_peer.pubkey.as_str().try_into().unwrap_or_default());
        peer.allowed_ips = proto_peer
            .allowed_ips
            .iter()
            .filter_map(|entry| IpAddrMask::from_str(entry).ok())
            .collect();
        peer
    }
}

impl From<&Peer> for proto::Peer {
    fn from(peer: &Peer) -> Self {
        Self {
            pubkey: peer.public_key.to_string(),
            allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
        }
    }
}

impl From<&Peer> for proto::PeerStats {
    fn from(peer: &Peer) -> Self {
        Self {
            public_key: peer.public_key.to_string(),
            endpoint: peer
                .endpoint
                .map_or(String::new(), |endpoint| endpoint.to_string()),
            allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
            latest_handshake: peer.last_handshake.map_or(0, |ts| {
                ts.duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs() as i64)
            }),
            download: peer.rx_bytes as i64,
            upload: peer.tx_bytes as i64,
            keepalive_interval: i64::from(peer.persistent_keepalive_interval.unwrap_or_default()),
        }
    }
}
