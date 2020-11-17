use std::process::{Command, ExitStatus};
use std::io;

pub fn run_command(command: &str, args: &[&str]) -> Result<ExitStatus, io::Error> {
    let mut command = Command::new(command);
    command.args(args);
    log::debug!("Running command: {:?}", command);
    let status = command.status();
    log::info!("Ran command {:?}, exit status: {:?}", command, status);
    status
}
