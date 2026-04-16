use std::net::IpAddr;

use defguard_wireguard_rs::{
    InterfaceConfiguration, WireguardInterfaceApi, error::WireguardInterfaceError, host::Host,
    key::Key, net::IpAddrMask, peer::Peer as WgPeer,
};

/// A minimal no-op WireGuard API implementation for use in tests.
///
/// All operations return an error — the gateway warns and continues on
/// interface creation failure, and no other WireGuard operations are invoked
/// during the mTLS handshake tests.
pub(crate) struct NullWgApi;

impl WireguardInterfaceApi for NullWgApi {
    fn create_interface(&mut self) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface(
            "test: no WireGuard available".into(),
        ))
    }

    fn assign_address(&self, _address: &IpAddrMask) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    fn configure_peer_routing(&self, _peers: &[WgPeer]) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    fn configure_interface(
        &self,
        _config: &InterfaceConfiguration,
    ) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    #[cfg(not(target_os = "windows"))]
    fn remove_interface(&self) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    #[cfg(target_os = "windows")]
    fn remove_interface(&mut self) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    fn configure_peer(&self, _peer: &WgPeer) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    fn remove_peer(&self, _peer_pubkey: &Key) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }

    fn configure_dns(
        &self,
        _dns: &[IpAddr],
        _search_domains: &[&str],
    ) -> Result<(), WireguardInterfaceError> {
        Err(WireguardInterfaceError::Interface("test".into()))
    }
}
