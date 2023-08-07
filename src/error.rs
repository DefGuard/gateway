use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Command execution failed")]
    CommandExecutionFailed(#[from] std::io::Error),

    #[error("Command returned error status")]
    CommandExecutionError { stderr: String },

    #[cfg(feature = "boringtun")]
    #[error("BorningTun error")]
    BorningTun(boringtun::device::Error),

    #[error("WireGuard key error")]
    KeyDecode(#[from] base64::DecodeError),

    #[error("IP address/mask error")]
    IpAddrMask(#[from] super::wireguard::IpAddrParseError),

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
}
