use thiserror::Error;

#[derive(Debug, Error)]
pub enum OriWireGuardError {
    #[error("Command execution failed")]
    CommandExecutionFailed {
        #[from]
        source: std::io::Error,
    },

    #[error("Command returned error status")]
    CommandExecutionError {
        stderr: String
    },
}
