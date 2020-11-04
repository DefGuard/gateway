use std::process::{Command, ExitStatus};
use std::io;
use std::fs;
use uuid::Uuid;

fn run_command(command: &str, args: &[&str]) -> Result<ExitStatus, io::Error> {
    let mut command = Command::new(command);
    command.args(args);
    println!("Running command: {:?}", command);
    command.status()
}

pub fn assign_addr(
    interface: &str,
    addr: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["ip", "addr", "add", addr, "dev", interface])
}

pub fn set_private_key(
    interface: &str,
    key: &str 
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't write private keys to file
    let path = &format!("/tmp/{}", Uuid::new_v4());
    fs::write(path, key)?;
    // FIXME: don't use sudo
    let status = run_command("sudo", &["wg", "set", interface, "private-key", path]);
    fs::remove_file(path)?;
    status
}

pub fn set_link_up(
    interface: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["ip", "link", "set", interface, "up"])
}

pub fn set_link_down(
    interface: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["ip", "link", "set", interface, "down"])
}

pub fn set_peer(
    interface: &str,
    pubkey: &str,
    allowed_ips: &str, 
    endpoint: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["wg", "set", interface, "peer", pubkey, "allowed-ips", allowed_ips, "endpoint", endpoint])
}
