use crate::utils::run_command;
use std::fs;
use std::os::unix::net::UnixDatagram;
use std::process::{Output, exit};
use std::io;
use uuid::Uuid;

use boringtun::device::drop_privileges::*;
use boringtun::device::*;
use boringtun::noise::Verbosity;

pub fn _create_interface_userspace(name: &str) {
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

    let mut device_handle = match DeviceHandle::new(&tun_name, config) {
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
}

pub fn create_interface(name: &str) -> Result<Output, io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["ip", "link", "add", name, "type", "wireguard"])
}

pub fn assign_addr(
    interface: &str,
    addr: &str,
) -> Result<Output, io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["ip", "addr", "add", addr, "dev", interface])
}

pub fn set_private_key(
    interface: &str,
    key: &str,
) -> Result<Output, io::Error> {
    // FIXME: don't write private keys to file
    let path = &format!("/tmp/{}", Uuid::new_v4());
    fs::write(path, key)?;
    // FIXME: don't use sudo
    let status = run_command("sudo", &["wg", "set", interface, "private-key", path]);
    fs::remove_file(path)?;
    status
}

pub fn set_link_up(interface: &str) -> Result<Output, io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["ip", "link", "set", interface, "up"])
}

pub fn set_link_down(interface: &str) -> Result<Output, io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["ip", "link", "set", interface, "down"])
}

pub fn set_peer(
    interface: &str,
    pubkey: &str,
    allowed_ips: &str,
    endpoint: &str,
) -> Result<Output, io::Error> {
    // FIXME: don't use sudo
    run_command(
        "sudo",
        &[
            "wg",
            "set",
            interface,
            "peer",
            pubkey,
            "allowed-ips",
            allowed_ips,
            "endpoint",
            endpoint,
        ],
    )
}

pub fn interface_stats(interface: &str) -> Result<Output, io::Error> {
    // FIXME: don't use sudo
    run_command("sudo", &["wg", "show", interface, "transfer"])
}