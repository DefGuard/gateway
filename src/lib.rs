pub mod config;
pub mod error;
pub mod gateway;
pub mod server;
mod version;

pub mod generated {
    pub mod defguard {
        pub mod common {
            pub mod v2 {
                tonic::include_proto!("defguard.common.v2");
            }
        }
        pub mod gateway {
            pub mod v2 {

                tonic::include_proto!("defguard.gateway.v2");
            }
        }
        pub mod enterprise {
            pub mod firewall {
                pub mod v2 {

                    tonic::include_proto!("defguard.enterprise.firewall.v2");
                }
            }
        }
    }
}

pub mod proto {
    pub mod common {
        pub use crate::generated::defguard::common::v2::*;
    }
    pub mod gateway {
        pub use crate::generated::defguard::gateway::v2::*;
    }
    pub mod enterprise {
        pub mod firewall {
            pub use crate::generated::defguard::enterprise::firewall::v2::*;
        }
    }
}

#[macro_use]
extern crate log;

use std::{process::Command, str::FromStr, time::SystemTime};

use config::Config;
use defguard_wireguard_rs::{InterfaceConfiguration, net::IpAddrMask, peer::Peer};
use error::GatewayError;
use prost_types::Timestamp;
use syslog::{BasicLogger, Facility, Formatter3164};

pub mod enterprise;
pub mod logging;
pub mod setup;

#[cfg(test)]
mod tests;

pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("VERGEN_GIT_SHA"));

/// Install the `ring` CryptoProvider as the process-wide default for rustls.
///
/// Must be called once near process startup, before any TLS code runs. Both
/// `ring` and `aws-lc-rs` may be present as transitive dependencies; without
/// an explicit selection rustls panics at runtime.  Subsequent calls are
/// silently ignored (`.ok()` swallows the `AlreadySet` error).
pub fn init_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

pub const GRPC_CERT_NAME: &str = "gateway_grpc_cert.pem";
pub const GRPC_KEY_NAME: &str = "gateway_grpc_key.pem";
pub const GRPC_CA_CERT_NAME: &str = "grpc_ca_cert.pem";
pub const CORE_CLIENT_CERT_NAME: &str = "core_client_cert.pem";

/// Masks object's field with "***" string.
/// Used to log sensitive/secret objects.
#[macro_export]
macro_rules! mask {
    ($object:expr_2021, $field:ident) => {{
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
        let output = Command::new(command)
            .args(command_parts)
            .output()
            .map_err(|err| {
                error!("Failed to execute command {command}. Error: {err}");
                GatewayError::CommandExecutionFailed {
                    command: command.to_string(),
                    error: err.to_string(),
                }
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            info!("Command {command} executed successfully. Stdout: {stdout}",);
            if !stderr.is_empty() {
                error!("Stderr:\n{stderr}");
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Error executing command {command}. Stderr:\n{stderr}");
        }
    }
    Ok(())
}

impl From<proto::gateway::Configuration> for InterfaceConfiguration {
    fn from(config: proto::gateway::Configuration) -> Self {
        let peers = config.peers.into_iter().map(Peer::from).collect();
        // Try to convert an array of `String`s to `IpAddrMask`, leaving out the failed ones.
        let addresses = config
            .addresses
            .into_iter()
            .filter_map(|s| IpAddrMask::from_str(&s).ok())
            .collect();
        InterfaceConfiguration {
            name: config.name,
            prvkey: config.private_key,
            addresses,
            port: config.port as u16,
            peers,
            mtu: Some(config.mtu),
            fwmark: Some(config.fwmark),
        }
    }
}

impl From<proto::gateway::Peer> for Peer {
    fn from(proto_peer: proto::gateway::Peer) -> Self {
        let mut peer = Self::new(proto_peer.pubkey.as_str().try_into().unwrap_or_default());
        peer.persistent_keepalive_interval = proto_peer
            .keepalive_interval
            .and_then(|interval| u16::try_from(interval).ok());
        peer.preshared_key = proto_peer
            .preshared_key
            .map(|key| key.as_str().try_into().unwrap_or_default());
        peer.allowed_ips = proto_peer
            .allowed_ips
            .iter()
            .filter_map(|entry| IpAddrMask::from_str(entry).ok())
            .collect();
        peer
    }
}

impl From<&Peer> for proto::gateway::Peer {
    fn from(peer: &Peer) -> Self {
        let preshared_key = peer.preshared_key.as_ref().map(ToString::to_string);
        Self {
            pubkey: peer.public_key.to_string(),
            allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
            preshared_key,
            keepalive_interval: peer.persistent_keepalive_interval.map(u32::from),
        }
    }
}

impl From<&Peer> for proto::gateway::PeerStats {
    fn from(peer: &Peer) -> Self {
        Self {
            public_key: peer.public_key.to_string(),
            endpoint: peer
                .endpoint
                .map_or(String::new(), |endpoint| endpoint.to_string()),
            allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
            latest_handshake: peer.last_handshake.and_then(|ts| {
                ts.duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|d| Timestamp {
                        seconds: d.as_secs() as i64,
                        nanos: d.subsec_nanos() as i32,
                    })
            }),
            download: peer.rx_bytes,
            upload: peer.tx_bytes,
            keepalive_interval: u32::from(peer.persistent_keepalive_interval.unwrap_or_default()),
        }
    }
}
