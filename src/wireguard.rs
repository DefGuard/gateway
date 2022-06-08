use crate::{error::OriWireGuardError, gateway::Configuration, utils::run_command};
use boringtun::{
    device::drop_privileges::drop_privileges,
    device::{DeviceConfig, DeviceHandle},
};
use std::{fs, process::Output};
use uuid::Uuid;

/// Creates wireguard interface using userspace implementation.
/// https://github.com/cloudflare/boringtun
///
/// # Arguments
///
/// * `name` - Interface name
pub fn create_interface_userspace(ifname: &str) -> Result<(), OriWireGuardError> {
    let enable_drop_privileges = true;

    let config = DeviceConfig::default();

    let mut device_handle =
        DeviceHandle::new(ifname, config).map_err(OriWireGuardError::BorningTun)?;

    if enable_drop_privileges {
        if let Err(e) = drop_privileges() {
            error!("Failed to drop privileges: {:?}", e);
        }
    }

    tokio::spawn(async move {
        device_handle.wait();
    });
    Ok(())
}

/// Checks if command exited successfully, returns CommandExecutionError with stderr if not.
///
/// # Arguments
///
/// * `output` - command output
fn map_output(output: &Output) -> Result<String, OriWireGuardError> {
    if output.status.success() {
        Ok(String::from_utf8(output.stdout.clone()).unwrap_or_default())
    } else {
        Err(OriWireGuardError::CommandExecutionError {
            stderr: String::from_utf8(output.stderr.clone()).unwrap_or_default(),
        })
    }
}

/// Creates wireguard interface.
///
/// # Arguments
///
/// * `name` - Interface name
pub fn create_interface(ifname: &str) -> Result<String, OriWireGuardError> {
    let output = if cfg!(target_os = "linux") {
        run_command(&["ip", "link", "add", ifname, "type", "wireguard"])
    } else {
        run_command(&["ifconfig", "create", ifname])
    }?;
    map_output(&output)
}

/// Assigns address to interface.
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `addr` - Address to assign to interface
pub fn assign_addr(ifname: &str, addr: &str) -> Result<String, OriWireGuardError> {
    let output = if cfg!(target_os = "linux") {
        run_command(&["ip", "addr", "add", addr, "dev", ifname])
    } else {
        run_command(&["ifconfig", ifname, addr, addr])
    }?;
    map_output(&output)
}

/// Assigns private key to interface
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `key` - Private key to assign to interface
pub fn set_private_key(ifname: &str, key: &str) -> Result<String, OriWireGuardError> {
    // FIXME: don't write private keys to file
    let path = &format!("/tmp/{}", Uuid::new_v4());
    fs::write(path, key)?;
    let output = run_command(&["wg", "set", ifname, "private-key", path])?;
    fs::remove_file(path)?;
    map_output(&output)
}

/// Assigns port to interface
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `port` - Port to assign to interface
pub fn set_port(interface: &str, port: u16) -> Result<String, OriWireGuardError> {
    let output = run_command(&["wg", "set", interface, "listen-port", &port.to_string()])?;
    map_output(&output)
}

/// Starts an interface
///
/// # Arguments
///
/// * `interface` - Interface to start
pub fn set_link_up(ifname: &str) -> Result<String, OriWireGuardError> {
    let output = if cfg!(target_os = "linux") {
        run_command(&["ip", "link", "set", ifname, "up"])
    } else {
        run_command(&["ifconfig", ifname, "up"])
    }?;
    map_output(&output)
}

/// Stops an interface
///
/// # Arguments
///
/// * `interface` - Interface to stop
#[allow(dead_code)]
pub fn set_link_down(ifname: &str) -> Result<String, OriWireGuardError> {
    let output = if cfg!(target_os = "linux") {
        run_command(&["ip", "link", "set", ifname, "down"])
    } else {
        run_command(&["ifconfig", ifname, "down"])
    }?;
    map_output(&output)
}

/// Sets wireguard interface peer
///
/// # Arguments
///
/// * `interface` - WireGuard interface
/// * `pubkey` - Peer public key
/// * `allowed_ips` - Peer allowed IPs/masks, e.g. 10.0.0.1/24
/// * `endpoint` - Peer endpoint, e.g. 192.168.1.10:54545
pub fn set_peer(
    interface: &str,
    pubkey: &str,
    allowed_ips: &[String],
) -> Result<String, OriWireGuardError> {
    let output = run_command(&[
        "wg",
        "set",
        interface,
        "peer",
        pubkey,
        "allowed-ips",
        &allowed_ips.join(" "),
    ])?;
    map_output(&output)
}

/// Displays interface statistics
///
/// # Arguments
///
/// * `interface` - Interface name
pub fn interface_stats(interface: &str) -> Result<String, OriWireGuardError> {
    let output = run_command(&["wg", "show", interface, "dump"])?;
    map_output(&output)
}

/// Helper method performing interface configuration
pub fn setup_interface(
    name: &str,
    userspace: bool,
    config: &Configuration,
) -> Result<(), OriWireGuardError> {
    if userspace {
        create_interface_userspace(name)?;
    } else {
        create_interface(name)?;
    }

    assign_addr(name, &config.address)?;
    set_private_key(name, &config.prvkey)?;
    set_port(name, config.port as u16)?;
    set_link_up(name)?;
    for peer in &config.peers {
        set_peer(name, &peer.pubkey, &peer.allowed_ips)?;
    }

    Ok(())
}

/// Helper method - deletes specified interface
pub fn delete_interface(ifname: &str) -> Result<String, OriWireGuardError> {
    let output = if cfg!(target_os = "linux") {
        run_command(&["ip", "link", "delete", ifname])
    } else {
        run_command(&["ifconfig", "destroy", ifname])
    }?;
    map_output(&output)
}
