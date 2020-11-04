use std::process::Command;
use std::fs;
use uuid::Uuid;

pub fn assign_addr(
    interface: &str,
    addr: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    let mut command = Command::new("sudo");
    command.args(&["ip", "addr", "add", addr, "dev", interface]);
    println!("{:?}", command);
    command.status()
}

pub fn set_private_key(
    interface: &str,
    key: &str 
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't write private keys to file
    let path = &format!("/tmp/{}", Uuid::new_v4());
    fs::write(path, key)?;
    // FIXME: don't use sudo
    let mut command = Command::new("sudo");
    command.args(&["wg", "set", interface, "private-key", path]);
    println!("{:?}", command);
    let status = command.status();
    fs::remove_file(path)?;
    status
}

pub fn set_link_up(
    interface: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    let mut command = Command::new("sudo");
    command.args(&["ip", "link", "set", interface, "up"]);
    println!("{:?}", command);
    command.status()
}

pub fn set_link_down(
    interface: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    let mut command = Command::new("sudo");
    command.args(&["ip", "link", "set", interface, "down"]);
    println!("{:?}", command);
    command.status()
}

pub fn set_peer(
    interface: &str,
    pubkey: &str,
    allowed_ips: &str, 
    endpoint: &str,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // FIXME: don't use sudo
    let mut command = Command::new("sudo");
    command.args(&["wg", "set", interface, "peer", pubkey, "allowed-ips", allowed_ips, "endpoint", endpoint]);
    println!("{:?}", command);
    command.status()
}