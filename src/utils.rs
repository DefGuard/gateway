use std::{
    io,
    process::{Command, Output},
};

/// Runs specified command.
///
/// # Arguments
///
/// * `command` - Command to run
/// * `args` - Command arguments
pub fn run_command(args: &[&str]) -> io::Result<Output> {
    debug!("Running command: {:?}", args);
    let output = Command::new("sudo").args(args).output();
    info!("Ran command {:?}", args);
    output
}
