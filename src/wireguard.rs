use crate::error::OriWireGuardError;
use crate::gateway::Configuration;
use crate::utils::{bytes_to_string, run_command};
use boringtun::device::drop_privileges::*;
use boringtun::device::*;
use boringtun::noise::Verbosity;
use std::fs;
use std::os::unix::net::UnixDatagram;
use std::process::{exit, Output};
use uuid::Uuid;

type Result = std::result::Result<String, OriWireGuardError>;

/// Creates wireguard interface using userspace implementation.
/// https://github.com/cloudflare/boringtun
///
/// # Arguments
///
/// * `name` - Interface name
pub fn create_interface_userspace(name: &str) -> Result {
    let tun_name = name;
    let n_threads = 4;
    let log_level = Verbosity::None; // "silent" / "info" / "debug"
    let use_connected_socket = true;
    let use_multi_queue = true;
    let enable_drop_privileges = true;

    // Create a socketpair to communicate between forked processes
    let (sock, _) = UnixDatagram::pair().unwrap();
    let _ = sock.set_nonblocking(true);

    let config = DeviceConfig {
        n_threads,
        log_level,
        use_connected_socket,
        #[cfg(target_os = "linux")]
        use_multi_queue,
    };

    let mut device_handle = match DeviceHandle::new(tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Failed to initialize tunnel: {:?}", e);
            sock.send(&[0]).unwrap();
            exit(1);
        }
    };

    if enable_drop_privileges {
        if let Err(e) = drop_privileges() {
            log::error!("Failed to drop privileges: {:?}", e);
            sock.send(&[0]).unwrap();
            exit(1);
        }
    }

    drop(sock);
    device_handle.wait();
    Ok(String::new())
}

/// Checks if command exited successfully, returns CommandExecutionError with stderr if not.
///
/// # Arguments
///
/// * `output` - command output
fn map_output(output: &Output) -> Result {
    match output.status.code() {
        Some(0) | None => Ok(std::str::from_utf8(&output.stdout)
            .unwrap_or("")
            .to_string()),
        _ => Err(OriWireGuardError::CommandExecutionError {
            stderr: bytes_to_string(&output.stderr),
        }),
    }
}

/// Creates wireguard interface.
///
/// # Arguments
///
/// * `name` - Interface name
pub fn create_interface(name: &str) -> Result {
    // FIXME: don't use sudo
    let output = run_command("sudo", &["ip", "link", "add", name, "type", "wireguard"])?;
    map_output(&output)
}

/// Assigns address to interface.
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `addr` - Address to assign to interface
pub fn assign_addr(interface: &str, addr: &str) -> Result {
    // FIXME: don't use sudo
    let output = run_command("sudo", &["ip", "addr", "add", addr, "dev", interface])?;
    map_output(&output)
}

/// Assigns private key to interface
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `key` - Private key to assign to interface
pub fn set_private_key(interface: &str, key: &str) -> Result {
    // FIXME: don't write private keys to file
    let path = &format!("/tmp/{}", Uuid::new_v4());
    fs::write(path, key)?;
    // FIXME: don't use sudo
    let output = run_command("sudo", &["wg", "set", interface, "private-key", path])?;
    fs::remove_file(path)?;
    map_output(&output)
}

/// Assigns port to interface
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `port` - Port to assign to interface
pub fn set_port(interface: &str, port: u16) -> Result {
    let output = run_command(
        "sudo",
        &["wg", "set", interface, "listen-port", &port.to_string()],
    )?;
    map_output(&output)
}

/// Starts an interface
///
/// # Arguments
///
/// * `interface` - Interface to start
pub fn set_link_up(interface: &str) -> Result {
    // FIXME: don't use sudo
    let output = run_command("sudo", &["ip", "link", "set", interface, "up"])?;
    map_output(&output)
}

/// Stops an interface
///
/// # Arguments
///
/// * `interface` - Interface to stop
pub fn set_link_down(interface: &str) -> Result {
    // FIXME: don't use sudo
    let output = run_command("sudo", &["ip", "link", "set", interface, "down"])?;
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
pub fn set_peer(interface: &str, pubkey: &str, allowed_ips: &[String]) -> Result {
    // FIXME: don't use sudo
    let output = run_command(
        "sudo",
        &[
            "wg",
            "set",
            interface,
            "peer",
            pubkey,
            "allowed-ips",
            &allowed_ips.join(" "),
        ],
    )?;
    map_output(&output)
}

/// Displays interface statistics
///
/// # Arguments
///
/// * `interface` - Interface name
pub fn interface_stats(interface: &str) -> Result {
    // FIXME: don't use sudo
    let output = run_command("sudo", &["wg", "show", interface, "dump"])?;
    map_output(&output)
}

/// Helper method performing interface configuration
pub fn setup_interface(name: &str, userspace: bool, config: &Configuration) -> Result {
    match userspace {
        true => create_interface_userspace(name),
        false => create_interface(name),
    }?;

    assign_addr(name, &config.address)?;
    set_private_key(name, &config.prvkey)?;
    set_port(name, config.port as u16)?;
    set_link_up(name)?;
    for peer in &config.peers {
        set_peer(name, &peer.pubkey, &peer.allowed_ips)?;
    }

    Ok(String::new())
}

/// Helper method - deletes specified interface
pub fn delete_interface(name: &str) -> Result {
    let output = run_command("sudo", &["ip", "link", "delete", name])?;
    map_output(&output)
}
