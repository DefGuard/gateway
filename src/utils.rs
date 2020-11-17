use std::process::{Command, ExitStatus};
use std::io;

pub fn run_command(command: &str, args: &[&str]) -> Result<ExitStatus, io::Error> {
    let mut command = Command::new(command);
    command.args(args);
    println!("Running command: {:?}", command);
    command.status()
}
