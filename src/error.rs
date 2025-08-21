use defguard_version::DefguardVersionError;
use defguard_wireguard_rs::error::WireguardInterfaceError;
use thiserror::Error;

use crate::enterprise::firewall::FirewallError;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Command {command} execution failed. Error: {error}")]
    CommandExecutionFailed { command: String, error: String },

    #[error("WireGuard key error")]
    KeyDecode(#[from] base64::DecodeError),

    #[error("Logger error")]
    Logger(#[from] log::SetLoggerError),

    #[error("Syslog error")]
    Syslog(#[from] syslog::Error),

    #[error("Token parsing error")]
    Token(#[from] tonic::metadata::errors::InvalidMetadataValue),

    #[error("Tonic error")]
    Tonic(#[from] tonic::transport::Error),

    #[error("Uri error")]
    Uri(#[from] tonic::codegen::http::uri::InvalidUri),

    #[error("Invalid config file. Error: {0}")]
    InvalidConfigFile(String),

    #[error("WireGuard error {0}")]
    WireguardError(#[from] WireguardInterfaceError),

    #[error("HTTP error")]
    HttpServer(String),

    #[error("Invalid CA file. Error")]
    InvalidCaFile,

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("Firewall error: {0}")]
    FirewallError(#[from] FirewallError),

    #[error(transparent)]
    DefguardVersionError(#[from] DefguardVersionError),

    #[error(transparent)]
    SemverError(#[from] semver::Error),
}
