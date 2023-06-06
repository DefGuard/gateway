pub mod host;
pub mod key;
pub mod net;
#[cfg(target_os = "linux")]
pub mod netlink;
pub mod wgapi;

use crate::{error::GatewayError, proto::Configuration};
#[cfg(feature = "boringtun")]
use boringtun::{
    device::drop_privileges::drop_privileges,
    device::{DeviceConfig, DeviceHandle},
};
use std::{process::Command, str::FromStr};
use wgapi::WGApi;

/// Creates wireguard interface using userspace implementation.
/// https://github.com/cloudflare/boringtun
///
/// # Arguments
///
/// * `name` - Interface name
#[cfg(feature = "boringtun")]
pub fn create_interface_userspace(ifname: &str) -> Result<(), GatewayError> {
    let enable_drop_privileges = true;

    let config = DeviceConfig::default();

    let mut device_handle = DeviceHandle::new(ifname, config).map_err(GatewayError::BorningTun)?;

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

/// Assigns address to interface.
///
/// # Arguments
///
/// * `interface` - Interface name
/// * `addr` - Address to assign to interface
pub fn assign_addr(ifname: &str, addr: &IpAddrMask) -> Result<(), GatewayError> {
    if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        netlink::address_interface(ifname, addr)?;
    } else if cfg!(target_os = "macos") {
        // On macOS, interface is point-to-point and requires a pair of addresses
        let address_string = addr.ip.to_string();
        Command::new("ifconfig")
            .args([ifname, &address_string, &address_string])
            .output()?;
    } else {
        Command::new("ifconfig")
            .args([ifname, &addr.to_string()])
            .output()?;
    }

    Ok(())
}

/// Helper method performing interface configuration
pub fn setup_interface(
    ifname: &str,
    userspace: bool,
    config: &Configuration,
) -> Result<(), GatewayError> {
    if userspace {
        #[cfg(feature = "boringtun")]
        create_interface_userspace(ifname)?;
    } else {
        #[cfg(target_os = "linux")]
        netlink::create_interface(ifname)?;
    }

    let address = IpAddrMask::from_str(&config.address)?;
    assign_addr(ifname, &address)?;
    let key = config.prvkey.as_str().try_into()?;
    let mut host = Host::new(config.port as u16, key);
    for peercfg in &config.peers {
        let key: Key = peercfg.pubkey.as_str().try_into()?;
        let mut peer = Peer::new(key.clone());
        let allowed_ips = peercfg
            .allowed_ips
            .iter()
            .filter_map(|entry| IpAddrMask::from_str(entry).ok())
            .collect();
        peer.set_allowed_ips(allowed_ips);

        host.peers.insert(key, peer);
    }
    let api = WGApi::new(ifname.into(), userspace);
    api.write_host(&host)?;

    Ok(())
}

pub use {
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
};
