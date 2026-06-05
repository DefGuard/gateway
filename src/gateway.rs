#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use defguard_wireguard_rs::{WireguardInterfaceApi, net::IpAddrMask};
use tokio::{
    signal,
    sync::{mpsc, oneshot},
    time::interval,
};
use tonic::Status;
use tracing::instrument;

use crate::{
    config::Config,
    enterprise::firewall::{
        FirewallConfig, FirewallError, FirewallRule, SnatBinding,
        api::{FirewallApi, FirewallManagementApi},
    },
    error::GatewayError,
    gateway_server::GatewayServer,
    mask,
    proto::{
        common::LogEntry,
        gateway::{Configuration, CoreRequest, Peer, Update, core_request, update},
    },
    setup::run_setup,
};

/// Keeps the gRPC server running, but allows it to be stopped and
/// restarted in setup mode when a purge request arrives.
pub async fn run_gateway_loop(
    config: Config,
    gateway: Arc<Mutex<Gateway>>,
    logs_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>,
    mut tls_config: TlsConfig,
) {
    loop {
        // Channel used by the gRPC service to request entering setup mode.
        // The purge RPC sends on this channel.
        let (reset_tx, mut reset_rx) = oneshot::channel();
        // Build and start a gRPC server instance wired with the reset signal.
        let mut gateway_server =
            GatewayServer::new(Arc::clone(&gateway), config.cert_dir.clone(), reset_tx);
        gateway_server.set_tls_config(tls_config.clone());
        let mut server_handle = tokio::spawn(gateway_server.start(config.clone()));

        tokio::select! {
            biased;
            // Handle Ctrl-C
            _ = signal::ctrl_c() => {
                if !config.keep_on_quit {
                    gateway.lock().unwrap().purge();
                }
                break;
            }
            // The purge RPC requested setup mode.
            signal = &mut reset_rx => {
                // Handle channel closed event.
                if signal.is_err() {
                    match server_handle.await {
                        Ok(Ok(())) => (),
                        Ok(Err(err)) => {
                            error!("gRPC server task failed: {err}");
                            return;
                        }
                        Err(err) => {
                            error!("gRPC server task failed: {err}");
                            return;
                        }
                    }
                    break;
                }

                // Entering setup mode - stop current gRPC server.
                server_handle.abort();
                let _ = server_handle.await;

                // Run setup server to obtain new TLS certs, then loop to restart gRPC.
                log::info!("Restarting setup server after purge request");
                tls_config = match run_setup(&config, Arc::clone(&logs_rx)).await {
                    Ok(config) => config,
                    Err(err) => {
                        error!("Failed to run setup {err}");
                        return;
                    }
                }
            }
            // Server exited on its own (error or normal shutdown).
            result = &mut server_handle => {
                match result {
                    Ok(Ok(())) => (),
                    Ok(Err(err)) => {
                        error!("gRPC server task failed: {err}");
                        return;
                    }
                    Err(err) => {
                        error!("gRPC server task failed: {err}");
                        return;
                    }
                }
                break;
            }
        }
    }
}

// Helper struct which stores just the interface config without peers.
#[derive(Clone, PartialEq)]
struct InterfaceConfiguration {
    name: String,
    private_key: String,
    addresses: Vec<IpAddrMask>,
    port: u16,
    mtu: u32,
    fwmark: u32,
}

impl From<Configuration> for InterfaceConfiguration {
    fn from(config: Configuration) -> Self {
        // Try to convert an array of `String`s to `IpAddrMask`, leaving out the failed ones.
        let addresses = config
            .addresses
            .into_iter()
            .filter_map(|s| IpAddrMask::from_str(&s).ok())
            .collect();
        Self {
            name: config.name,
            private_key: config.private_key,
            addresses,
            port: config.port as u16,
            mtu: config.mtu,
            fwmark: config.fwmark,
        }
    }
}

type PubKey = String;

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub grpc_cert_pem: String,
    pub grpc_key_pem: String,
    /// PEM-encoded CA certificate used to verify Core's mTLS client certificate chain.
    pub grpc_ca_cert_pem: String,
    /// DER-encoded Core client certificate; used to extract and pin the expected serial.
    pub core_client_cert_der: Vec<u8>,
}

pub struct Gateway {
    config: Config,
    interface_configuration: Option<InterfaceConfiguration>,
    peers: HashMap<PubKey, Peer>,
    pub(crate) wgapi: Arc<Mutex<dyn WireguardInterfaceApi + Send + Sync + 'static>>,
    firewall_config: Option<FirewallConfig>,
    pub connected: Arc<AtomicBool>,
    // Transmission channel. Important: allows only one connected client.
    pub(crate) client_tx: Option<mpsc::UnboundedSender<Result<CoreRequest, Status>>>,
    pub(crate) tls_config: Option<TlsConfig>,
}

impl Gateway {
    pub fn new(
        config: Config,
        wgapi: impl WireguardInterfaceApi + Send + Sync + 'static,
    ) -> Result<Self, GatewayError> {
        Ok(Self {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            firewall_config: None,
            connected: Arc::new(AtomicBool::new(false)),
            client_tx: None,
            tls_config: None,
        })
    }

    /// Purge the `Gateway` and prepare to enter setup mode.
    pub(crate) fn purge(&mut self) {
        // Drop the interface.
        if let Err(err) = self
            .wgapi
            .lock()
            .expect("Failed to lock Gateway::wgapi")
            .remove_interface()
        {
            error!("Gateway purge failed to drop the interface: {err}");
        }
        // Cleanup the firewall.
        if let Err(err) = self.cleanup_firewall() {
            error!("Gateway purge failed to cleanup firewall rules: {err}");
        }
        // Reset connection state.
        self.interface_configuration = None;
        self.peers.clear();
        self.client_tx = None;
        self.connected.store(false, Ordering::Relaxed);
    }

    // Replace current peer map with a new list of peers.
    fn replace_peers(&mut self, new_peers: Vec<Peer>) {
        debug!("Replacing stored peers with {} new peers", new_peers.len());
        let peers = new_peers
            .into_iter()
            .map(|peer| (peer.pubkey.clone(), peer))
            .collect();
        self.peers = peers;
    }

    // Check if new received configuration is different than current one.
    fn is_interface_config_changed(
        &self,
        new_interface_configuration: &InterfaceConfiguration,
        new_peers: &[Peer],
    ) -> bool {
        if let Some(current_configuration) = &self.interface_configuration {
            return current_configuration != new_interface_configuration
                || self.is_peer_list_changed(new_peers);
        }
        true
    }

    // Check if new peers are the same as the stored ones.
    fn is_peer_list_changed(&self, new_peers: &[Peer]) -> bool {
        // check if number of peers is different
        if self.peers.len() != new_peers.len() {
            return true;
        }

        // check if all pubkeys are the same
        if !new_peers
            .iter()
            .map(|peer| &peer.pubkey)
            .all(|k| self.peers.contains_key(k))
        {
            return true;
        }

        // Check if all IP addresses are the same.
        !new_peers.iter().all(|peer| {
            self.peers
                .get(&peer.pubkey)
                .is_some_and(|p| peer.allowed_ips == p.allowed_ips)
        })
    }

    /// Checks whether the firewall config have changed.
    fn has_firewall_config_changed(&self, new_fw_config: &FirewallConfig) -> bool {
        if let Some(current_config) = &self.firewall_config {
            return current_config.default_policy != new_fw_config.default_policy
                || self.have_firewall_rules_changed(&new_fw_config.rules)
                || self.have_snat_bindings_changed(&new_fw_config.snat_bindings);
        }

        true
    }

    /// Checks whether the firewall rules have changed.
    fn have_firewall_rules_changed(&self, new_rules: &[FirewallRule]) -> bool {
        debug!("Checking if Defguard ACL rules have changed");
        if let Some(current_config) = &self.firewall_config {
            let current_rules = &current_config.rules;
            if current_rules.len() != new_rules.len() {
                debug!("Number of Defguard ACL rules is different, so the rules have changed");
                return true;
            }

            for rule in new_rules {
                if !current_rules.contains(rule) {
                    debug!("Found a new Defguard ACL rule: {rule:?}. Rules have changed.");
                    return true;
                }
            }

            for rule in current_rules {
                if !new_rules.contains(rule) {
                    debug!("Found a removed Defguard ACL rule: {rule:?}. Rules have changed.");
                    return true;
                }
            }

            debug!(
                "Defguard ACL rules are the same. Rules have not changed. My rules: \
                {current_rules:?}, new rules: {new_rules:?}"
            );
            false
        } else {
            debug!(
                "There are new Defguard ACL rules in the new configuration, but we don't have \
                any in the current one. Rules have changed."
            );
            true
        }
    }

    /// Checks whether SNAT bindings have changed.
    fn have_snat_bindings_changed(&self, new_bindings: &[SnatBinding]) -> bool {
        debug!("Checking if SNAT bindings have changed");
        if let Some(current_config) = &self.firewall_config {
            let current_bindings = &current_config.snat_bindings;
            if current_bindings.len() != new_bindings.len() {
                debug!("Number of SNAT bindings is different, so the bindings have changed");
                return true;
            }

            for binding in new_bindings {
                if !current_bindings.contains(binding) {
                    debug!("Found a new SNAT binding: {binding:?}. Bindings have changed.");
                    return true;
                }
            }

            for binding in current_bindings {
                if !new_bindings.contains(binding) {
                    debug!("Found a removed SNAT binding: {binding:?}. Bindings have changed.");
                    return true;
                }
            }

            debug!(
                "SNAT bindings are the same. Bindings have not changed. My bindings: \
                {current_bindings:?}, new bindings: {new_bindings:?}"
            );
            false
        } else {
            debug!(
                "There are new SNAT bindings in the new configuration, but we don't have any in \
                the current one. Bindings have changed."
            );
            true
        }
    }

    /// Process and apply firewall configuration changes.
    /// - If the main config changed (default policy), reconfigure the whole firewall.
    /// - If only the rules changed, apply the new rules. Currently also reconfigures the whole
    ///   firewall but that should be temporary.
    fn process_firewall_changes(
        &mut self,
        fw_config: Option<&FirewallConfig>,
    ) -> Result<(), GatewayError> {
        if let Some(fw_config) = fw_config {
            debug!("Received firewall configuration: {fw_config:?}");
            if self.has_firewall_config_changed(fw_config) {
                debug!(
                    "Received firewall configuration is different than current one. \
                    Reconfiguring firewall..."
                );
                let mut firewall_api = FirewallApi::new(&self.config.ifname)?;
                firewall_api.setup(fw_config.default_policy, self.config.fw_priority)?;
                firewall_api.setup_nat(self.config.masquerade, &fw_config.snat_bindings)?;
                firewall_api.add_rules(&fw_config.rules)?;
                self.firewall_config = Some(fw_config.clone());
                info!("Reconfigured firewall with new configuration");
            } else {
                debug!(
                    "Received firewall configuration is the same as current one. Skipping \
                    reconfiguration."
                );
            }
        } else {
            debug!("Received firewall configuration is empty, cleaning up firewall rules...");
            self.cleanup_firewall()?;
            debug!("Cleaned up firewall rules");
        }

        Ok(())
    }

    fn cleanup_firewall(&mut self) -> Result<(), FirewallError> {
        let mut firewall_api = FirewallApi::new(&self.config.ifname)?;
        firewall_api.cleanup()?;
        firewall_api.setup_nat(self.config.masquerade, &[])?;
        self.firewall_config = None;

        Ok(())
    }

    /// Performs complete interface reconfiguration based on `configuration` object.
    /// Called when gateway (re)connects to gRPC endpoint and retrieves complete
    /// network and peers data.
    pub(crate) fn configure(
        &mut self,
        new_configuration: Configuration,
    ) -> Result<(), GatewayError> {
        debug!(
            "Received configuration, reconfiguring WireGuard interface {} (addresses: {:?})",
            new_configuration.name, new_configuration.addresses
        );
        trace!(
            "Received configuration: {:?}",
            mask!(new_configuration, private_key)
        );

        // check if new configuration is different than current one
        let new_interface_configuration = new_configuration.clone().into();

        if self.is_interface_config_changed(&new_interface_configuration, &new_configuration.peers)
        {
            debug!(
                "Received configuration is different than the current one. Reconfiguring interface."
            );
            let config =
                defguard_wireguard_rs::InterfaceConfiguration::from(new_configuration.clone());

            self.wgapi.lock().unwrap().configure_interface(&config)?;
            info!(
                "Reconfigured WireGuard interface {} (addresses: {:?})",
                new_configuration.name, new_configuration.addresses
            );
            trace!(
                "Reconfigured WireGuard interface. Configuration: {:?}",
                mask!(new_configuration, private_key)
            );
            // store new configuration and peers
            self.interface_configuration = Some(new_interface_configuration);
            self.replace_peers(new_configuration.peers);
        } else {
            debug!(
                "Received configuration is identical to the current one. Skipping interface \
                reconfiguration."
            );
        }

        // Process received firewall configuration, unless firewall management is disabled.
        if self.config.disable_firewall_management {
            debug!("Firewall management is disabled. Skipping updating firewall configuration");
        } else {
            let new_firewall_configuration =
                if let Some(firewall_config) = new_configuration.firewall_config {
                    Some(FirewallConfig::from_proto(firewall_config)?)
                } else {
                    None
                };

            self.process_firewall_changes(new_firewall_configuration.as_ref())?;
        }

        Ok(())
    }

    /// Send message to the connected client.
    fn send_to_client(&self, message: &CoreRequest) {
        if let Some(tx) = &self.client_tx
            && tx.send(Ok(message.clone())).is_err()
        {
            warn!("Failed to send message to Core.");
        }
    }

    #[instrument(skip_all)]
    pub(crate) fn handle_updates(&mut self, update: Update) {
        debug!("Received update: {update:?}");
        match update.update {
            Some(update::Update::Network(configuration)) => {
                if let Err(err) = self.configure(configuration) {
                    error!("Failed to update network configuration: {err}");
                }
            }
            Some(update::Update::Peer(peer_config)) => {
                debug!("Applying peer configuration: {peer_config:?}");
                // UpdateType::Delete
                if update.update_type == 2 {
                    debug!("Deleting peer {peer_config:?}");
                    self.peers.remove(&peer_config.pubkey);
                    if let Err(err) =
                        self.wgapi.lock().unwrap().remove_peer(
                            &peer_config.pubkey.as_str().try_into().unwrap_or_default(),
                        )
                    {
                        error!("Failed to delete peer: {err}");
                    }
                }
                // UpdateType::Create, UpdateType::Modify
                else {
                    debug!(
                        "Updating peer {peer_config:?}, update type: {}",
                        update.update_type
                    );
                    self.peers
                        .insert(peer_config.pubkey.clone(), peer_config.clone());
                    if let Err(err) = self
                        .wgapi
                        .lock()
                        .unwrap()
                        .configure_peer(&peer_config.into())
                    {
                        error!("Failed to update peer: {err}");
                    }
                }
            }
            Some(update::Update::FirewallConfig(config)) => {
                if self.config.disable_firewall_management {
                    debug!(
                        "Received firewall config update, but firewall management is disabled. \
                        Skipping processing this update: {config:?}"
                    );
                    return;
                }

                debug!("Applying received firewall configuration: {config:?}");
                let config_str = format!("{config:?}");
                match FirewallConfig::from_proto(config) {
                    Ok(new_firewall_config) => {
                        debug!(
                            "Parsed the received firewall configuration: {new_firewall_config:?}, \
                            processing it and applying changes"
                        );
                        if let Err(err) = self.process_firewall_changes(Some(&new_firewall_config))
                        {
                            error!("Failed to process received firewall configuration: {err}");
                        }
                    }
                    Err(err) => {
                        error!(
                            "Failed to parse received firewall configuration: {err}. \
                            Configuration: {config_str}"
                        );
                    }
                }
            }
            Some(update::Update::DisableFirewall(())) => {
                if self.config.disable_firewall_management {
                    debug!(
                        "Received firewall disable request, but firewall management is disabled. \
                        Skipping processing this update"
                    );
                    return;
                }

                debug!("Disabling firewall configuration");
                if let Err(err) = self.process_firewall_changes(None) {
                    error!("Failed to disable firewall configuration: {err}");
                }
            }
            _ => warn!("Unsupported kind of update: {update:?}"),
        }
    }
}

/// Gather WireGuard statistics and send them to Core through gRPC.
pub async fn run_stats(gateway: Arc<Mutex<Gateway>>, period: Duration) {
    // Helper map to track if peer data is actually changing to avoid sending duplicate stats.
    let mut peer_map = HashMap::new();
    let mut interval = interval(period);
    let mut id = 1;
    loop {
        // Wait until next iteration.
        interval.tick().await;

        // FIXME: the whole thread should only run when core is connected
        // Skip stats if not connected.
        if !gateway
            .lock()
            .expect("Stats thread failed to lock gateway")
            .connected
            .load(Ordering::Relaxed)
        {
            debug!("Gateway disconnected, skipping stats collection");
            continue;
        }

        debug!("Obtaining peer statistics from WireGuard");
        let result = gateway
            .lock()
            .expect("gateway mutex poison")
            .wgapi
            .lock()
            .expect("wgapi mutex poison")
            .read_interface_data();
        match result {
            Ok(host) => {
                let peers = host.peers;
                debug!(
                    "Found {} peers configured on WireGuard interface",
                    peers.len()
                );
                // Filter out never connected peers.
                for peer in peers.into_values().filter(|p| {
                    p.last_handshake
                        .is_some_and(|last_hs| last_hs != SystemTime::UNIX_EPOCH)
                }) {
                    let has_changed = match peer_map.get(&peer.public_key) {
                        Some(last_peer) => *last_peer != peer,
                        None => true,
                    };
                    if has_changed {
                        peer_map.insert(peer.public_key.clone(), peer.clone());
                        let payload = core_request::Payload::PeerStats((&peer).into());
                        let message = CoreRequest {
                            id,
                            payload: Some(payload),
                        };
                        id += 1;
                        gateway
                            .lock()
                            .expect("gateway mutex poison")
                            .send_to_client(&message);
                        debug!("Sent statistics for peer {}", peer.public_key);
                    } else {
                        debug!(
                            "Statistics for peer {} have not changed. Skipping.",
                            peer.public_key
                        );
                    }
                }
            }
            Err(err) => error!("Failed to retrieve WireGuard interface statistics: {err}"),
        }
    }
}
