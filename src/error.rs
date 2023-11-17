use defguard_wireguard_rs::error::WireguardInterfaceError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Command execution failed")]
    CommandExecutionFailed(#[from] std::io::Error),

    #[error("Command returned error status")]
    CommandExecutionError { stderr: String },

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

    #[error("Wireguard error")]
    WireguardError(#[from] WireguardInterfaceError),
    #[error("HTTP error")]
    HttpServer(String),
}
