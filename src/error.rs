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
}
