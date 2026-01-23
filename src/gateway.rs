use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use defguard_version::{
    ComponentInfo, DefguardComponent, Version, get_tracing_variables, server::DefguardVersionLayer,
};
use defguard_wireguard_rs::{WireguardInterfaceApi, net::IpAddrMask};
use gethostname::gethostname;
use tokio::{sync::mpsc, time::interval};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{
    Request, Response, Status, Streaming,
    transport::{Identity, Server, ServerTlsConfig},
};
use tower::ServiceBuilder;
use tracing::instrument;

use crate::{
    VERSION,
    config::Config,
    enterprise::firewall::{
        FirewallConfig, FirewallRule, SnatBinding,
        api::{FirewallApi, FirewallManagementApi},
    },
    error::GatewayError,
    execute_command, mask,
    proto::gateway::{
        Configuration, ConfigurationRequest, CoreRequest, CoreResponse, Peer, Update, core_request,
        core_response, gateway_server, update,
    },
    version::is_core_version_supported,
};

// Helper struct which stores just the interface config without peers.
#[derive(Clone, PartialEq)]
struct InterfaceConfiguration {
    name: String,
    prvkey: String,
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
            prvkey: config.prvkey,
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
}

pub struct Gateway {
    config: Config,
    interface_configuration: Option<InterfaceConfiguration>,
    peers: HashMap<PubKey, Peer>,
    wgapi: Arc<Mutex<dyn WireguardInterfaceApi + Send + Sync + 'static>>,
    firewall_api: FirewallApi,
    firewall_config: Option<FirewallConfig>,
    pub connected: Arc<AtomicBool>,
    // Transmission channel. Important: allows only one connected client.
    client_tx: Option<mpsc::UnboundedSender<Result<CoreRequest, Status>>>,
    pub(crate) tls_config: Option<TlsConfig>,
}

impl Gateway {
    pub fn new(
        config: Config,
        wgapi: impl WireguardInterfaceApi + Send + Sync + 'static,
        firewall_api: FirewallApi,
    ) -> Result<Self, GatewayError> {
        Ok(Self {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            firewall_api,
            firewall_config: None,
            connected: Arc::new(AtomicBool::new(false)),
            client_tx: None,
            tls_config: None,
        })
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
    ///
    /// TODO: Reduce cloning here
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
                self.firewall_api.begin()?;
                self.firewall_api
                    .setup(fw_config.default_policy, self.config.fw_priority)?;
                self.firewall_api
                    .setup_nat(self.config.masquerade, &fw_config.snat_bindings)?;
                self.firewall_api.add_rules(fw_config.rules.clone())?;
                self.firewall_api.commit()?;
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
            self.firewall_api.begin()?;
            self.firewall_api.cleanup()?;
            self.firewall_api.setup_nat(self.config.masquerade, &[])?;
            self.firewall_api.commit()?;
            self.firewall_config = None;
            debug!("Cleaned up firewall rules");
        }

        Ok(())
    }

    /// Performs complete interface reconfiguration based on `configuration` object.
    /// Called when gateway (re)connects to gRPC endpoint and retrieves complete
    /// network and peers data.
    fn configure(&mut self, new_configuration: Configuration) -> Result<(), GatewayError> {
        debug!(
            "Received configuration, reconfiguring WireGuard interface {} (addresses: {:?})",
            new_configuration.name, new_configuration.addresses
        );
        trace!(
            "Received configuration: {:?}",
            mask!(new_configuration, prvkey)
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
                mask!(new_configuration, prvkey)
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
            debug!("Failed to send message to Core.");
        }
    }

    #[instrument(skip_all)]
    fn handle_updates(&mut self, update: Update) {
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

pub struct GatewayServer {
    message_id: AtomicU64,
    gateway: Arc<Mutex<Gateway>>,
}

impl GatewayServer {
    #[must_use]
    pub fn new(gateway: Arc<Mutex<Gateway>>) -> Self {
        Self {
            message_id: AtomicU64::new(0),
            gateway,
        }
    }

    /// Starts the gateway process.
    /// * Retrieves configuration and configuration updates from Defguard gRPC server
    /// * Manages the interface according to configuration and updates
    /// * Sends interface statistics to Defguard server periodically
    pub async fn start(self, config: Config) -> Result<(), GatewayError> {
        info!(
            "Starting Defguard Gateway version {VERSION} with configuration: {:?}",
            config
        );

        // Try to create network interface for WireGuard.
        // FIXME: check if the interface already exists, or somehow be more clever.
        {
            #[allow(unused)]
            let mut gateway = &mut self.gateway.lock().expect("gateway mutex poison");
            if let Err(err) = gateway
                .wgapi
                .lock()
                .expect("wgapi mutex poison")
                .create_interface()
            {
                warn!(
                    "Couldn't create network interface {}: {err}. Proceeding anyway.",
                    config.ifname
                );
            } else {
                #[cfg(target_os = "linux")]
                if !config.disable_firewall_management && config.masquerade {
                    gateway.firewall_api.begin()?;
                    gateway.firewall_api.setup_nat(config.masquerade, &[])?;
                    let _ = &gateway.firewall_api.commit()?;
                }
            }
        }

        if let Some(post_up) = &config.post_up {
            debug!("Executing specified POST_UP command: {post_up}");
            execute_command(post_up)?;
        }

        let grpc_cert = self
            .gateway
            .lock()
            .unwrap()
            .tls_config
            .as_ref()
            .map(|c| c.grpc_cert_pem.clone());
        let grpc_key = self
            .gateway
            .lock()
            .unwrap()
            .tls_config
            .as_ref()
            .map(|c| c.grpc_key_pem.clone());

        // Build gRPC server.
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.grpc_port);
        info!("gRPC server is listening on {addr}");
        let mut builder = if let (Some(cert), Some(key)) = (grpc_cert, grpc_key) {
            let identity = Identity::from_pem(cert, key);
            Server::builder().tls_config(ServerTlsConfig::new().identity(identity))?
        } else {
            Server::builder()
        };

        // Start gRPC server. This should run indefinitely.
        debug!("Serving gRPC");
        builder
            .add_service(
                ServiceBuilder::new()
                    // .layer(InterceptorLayer::new(CoreVersionInterceptor::new(
                    //     MIN_CORE_VERSION,
                    //     incompatible_components,
                    // )))
                    .layer(DefguardVersionLayer::new(Version::parse(VERSION)?))
                    .service(gateway_server::GatewayServer::new(self)),
            )
            .serve(addr)
            .await?;

        Ok(())
    }

    pub fn set_tls_config(&mut self, tls_config: TlsConfig) {
        if let Ok(mut gateway) = self.gateway.lock() {
            gateway.tls_config = Some(tls_config);
        }
    }
}

#[tonic::async_trait]
impl gateway_server::Gateway for GatewayServer {
    type BidiStream = UnboundedReceiverStream<Result<CoreRequest, Status>>;

    /// Handle bidirectional communication with Defguard Core.
    async fn bidi(
        &self,
        request: Request<Streaming<CoreResponse>>,
    ) -> Result<Response<Self::BidiStream>, Status> {
        let Some(address) = request.remote_addr() else {
            error!("Failed to determine Defguard Core's address for request: {request:?}");
            return Err(Status::internal(
                "Failed to determine Defguard Core's address",
            ));
        };
        info!("Defguard Core gRPC client connected from {address}");

        let core_info = ComponentInfo::from_metadata(request.metadata());
        let (version, info) = get_tracing_variables(&core_info);

        // Tracing span.
        let span = tracing::info_span!(
            "core_communication",
            component = %DefguardComponent::Core,
            version = version.to_string(),
            info
        );
        let _guard = span.enter();

        // Check Defguard Core's version and exit if it's not supported.
        let version = core_info.as_ref().map(|info| &info.version);
        if !is_core_version_supported(version) {
            return Err(Status::internal("Unsupported Defguard Core version"));
        }

        // Drop new connections if another Core has already been connected.
        if self
            .gateway
            .lock()
            .expect("Gateway lock poison")
            .client_tx
            .is_some()
        {
            error!("Only one client connection is allowed.");
            return Err(Status::internal("Client already connected"));
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let Ok(hostname) = gethostname().into_string() else {
            error!("Unable to get hostname");
            return Err(Status::internal("failed to get hostname"));
        };

        // First, send configuration request.
        #[allow(deprecated)]
        let payload = ConfigurationRequest {
            name: None, // TODO: remove?
            hostname,
        };
        let req = CoreRequest {
            id: self.message_id.fetch_add(1, Ordering::Relaxed),
            payload: Some(core_request::Payload::ConfigRequest(payload)),
        };

        match tx.send(Ok(req)) {
            Ok(()) => info!("Requesting network configuration from {address}"),
            Err(err) => {
                error!("Unable to send network configuration request to {address}: {err}");
                return Err(Status::internal("failed to send configuration request"));
            }
        }

        self.gateway.lock().expect("Gateway lock poison").client_tx = Some(tx);

        let gateway = Arc::clone(&self.gateway);
        let mut stream = request.into_inner();
        tokio::spawn(async move {
            loop {
                match stream.message().await {
                    Ok(Some(response)) => {
                        debug!("Received message from Defguard Core: {response:?}");
                        // Discard empty payloads.
                        if let Some(payload) = response.payload {
                            match payload {
                                core_response::Payload::Config(configuration) => {
                                    match gateway.lock() {
                                        Ok(mut gw) => {
                                            gw.connected.store(true, Ordering::Relaxed);
                                            let _ = gw.configure(configuration);
                                        }
                                        Err(err) => error!("Lock failed: {err}"),
                                    }
                                }
                                core_response::Payload::Update(update) => match gateway.lock() {
                                    Ok(mut gw) => {
                                        gw.handle_updates(update);
                                    }
                                    Err(err) => error!("Lock failed: {err}"),
                                },
                                core_response::Payload::Empty(()) => (),
                            }
                        }
                    }
                    Ok(None) => {
                        info!("gRPC stream from Defguard Core has been closed");
                        break;
                    }
                    Err(err) => {
                        error!("gRPC stream from Defguard Core failed with error: {err}");
                        break;
                    }
                }
            }
            info!("Defguard Core gRPC stream has been disconnected: {address}");
            if let Ok(mut gateway) = gateway.lock() {
                gateway.connected.store(false, Ordering::Relaxed);
                gateway.client_tx = None;
            }
        });

        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}

/// Gather WireGuard statistics and send them to Core through gRPC.
pub async fn run_stats(gateway: Arc<Mutex<Gateway>>, period: Duration) -> Result<(), GatewayError> {
    // Helper map to track if peer data is actually changing to avoid sending duplicate stats.
    let mut peer_map = HashMap::new();
    let mut interval = interval(period);
    let mut id = 1;
    loop {
        // Wait until next iteration.
        interval.tick().await;

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

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, slice::from_ref};

    #[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
    use defguard_wireguard_rs::Kernel;
    #[cfg(any(target_os = "macos", target_os = "netbsd"))]
    use defguard_wireguard_rs::Userspace;
    use defguard_wireguard_rs::WGApi;
    use ipnetwork::IpNetwork;

    use super::*;
    use crate::enterprise::firewall::{Address, FirewallRule, Policy, Port, Protocol};

    #[cfg(any(target_os = "macos", target_os = "netbsd"))]
    type WG = WGApi<Userspace>;
    #[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
    type WG = WGApi<Kernel>;

    #[tokio::test]
    async fn test_configuration_comparison() {
        let old_config = InterfaceConfiguration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            addresses: vec!["10.6.1.1/24".parse().unwrap()],
            port: 50051,
            mtu: 1420,
            fwmark: 0,
        };

        let old_peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.3/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];
        let old_peers_map = old_peers
            .clone()
            .into_iter()
            .map(|peer| (peer.pubkey.clone(), peer))
            .collect();

        let wgapi = WG::new("wg0").unwrap();
        let config = Config::default();
        let firewall_api = FirewallApi::new("wg0").unwrap();
        let gateway = Gateway {
            config,
            interface_configuration: Some(old_config.clone()),
            peers: old_peers_map,
            wgapi: Arc::new(Mutex::new(wgapi)),
            firewall_api,
            firewall_config: None,
            connected: Arc::new(AtomicBool::new(false)),
            client_tx: None,
            tls_config: None,
        };

        // new config is the same
        let new_config = old_config.clone();
        let new_peers = old_peers.clone();
        assert!(!gateway.is_interface_config_changed(&new_config, &new_peers));

        // only interface config is different
        let new_config = InterfaceConfiguration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            addresses: vec!["10.6.1.2/24".parse().unwrap()],
            port: 50051,
            mtu: 1420,
            fwmark: 0,
        };
        let new_peers = old_peers.clone();
        assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

        // peer was removed
        let new_config = old_config.clone();
        let mut new_peers = old_peers.clone();
        new_peers.pop();

        assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

        // peer was added
        let new_config = old_config.clone();
        let mut new_peers = old_peers.clone();
        new_peers.push(Peer {
            pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
            allowed_ips: vec!["10.6.1.4/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        });

        assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

        // peer pubkey changed
        let new_config = old_config.clone();
        let new_peers = vec![
            Peer {
                pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.3/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];

        assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

        // peer IP changed
        let new_config = old_config.clone();
        let new_peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.4/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];

        assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

        // peer preshared key changed
        let new_config = old_config.clone();
        let new_peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: Some("VGhpc2lzdGhlcGFzc3dvcmQzMWNoYXJhY3RlcnNsbwo=".into()),
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.4/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];

        assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

        // peer keepalive interval changed
        let new_config = old_config.clone();
        let new_peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: Some("VGhpc2lzdGhlcGFzc3dvcmQzMWNoYXJhY3RlcnNsbwo=".into()),
                keepalive_interval: Some(15),
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.4/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];

        assert!(gateway.is_interface_config_changed(&new_config, &new_peers));
    }

    #[tokio::test]
    async fn test_firewall_rules_comparison() {
        use std::net::IpAddr;

        let rule1 = FirewallRule {
            comment: Some("Rule 1".to_string()),
            destination_addrs: vec![Address::Network(
                IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32).unwrap(),
            )],
            destination_ports: vec![Port::Single(80)],
            id: 1,
            verdict: Policy::Allow,
            protocols: vec![Protocol::Tcp],
            source_addrs: vec![Address::Network(
                IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 32).unwrap(),
            )],
            ipv4: true,
        };

        let rule2 = FirewallRule {
            comment: Some("Rule 2".to_string()),
            destination_addrs: vec![Address::Network(
                IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 32).unwrap(),
            )],
            destination_ports: vec![Port::Single(443)],
            id: 2,
            verdict: Policy::Allow,
            protocols: vec![Protocol::Tcp],
            source_addrs: vec![Address::Network(
                IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 32).unwrap(),
            )],
            ipv4: true,
        };

        let rule3 = FirewallRule {
            comment: Some("Rule 3".to_string()),
            destination_addrs: vec![Address::Network(
                IpNetwork::from_str("10.0.1.0/24").unwrap(),
            )],
            destination_ports: vec![Port::Range(1000, 2000)],
            id: 3,
            verdict: Policy::Deny,
            protocols: vec![Protocol::Udp],
            source_addrs: vec![Address::Network(
                IpNetwork::from_str("192.168.0.0/16").unwrap(),
            )],
            ipv4: true,
        };

        let config1 = FirewallConfig {
            rules: vec![rule1.clone(), rule2.clone()],
            default_policy: Policy::Allow,
            snat_bindings: Vec::new(),
        };

        let config_empty = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Allow,
            snat_bindings: Vec::new(),
        };

        let wgapi = WG::new("wg0").unwrap();
        let config = Config::default();
        let mut gateway = Gateway {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            firewall_api: FirewallApi::new("test_interface").unwrap(),
            firewall_config: None,
            connected: Arc::new(AtomicBool::new(false)),
            client_tx: None,
            tls_config: None,
        };

        // Gateway has no firewall config, new rules are empty
        gateway.firewall_config = None;
        assert!(gateway.have_firewall_rules_changed(&[]));

        // Gateway has no firewall config, but new rules exist
        gateway.firewall_config = None;
        assert!(gateway.have_firewall_rules_changed(from_ref(&rule1)));

        // Gateway has firewall config, with empty rules list
        gateway.firewall_config = Some(config1.clone());
        assert!(gateway.have_firewall_rules_changed(&[]));

        // Gateway has firewall config, new rules have different length
        gateway.firewall_config = Some(config1.clone());
        assert!(gateway.have_firewall_rules_changed(from_ref(&rule1)));

        // Gateway has firewall config, new rules have different content
        gateway.firewall_config = Some(config1.clone());
        assert!(gateway.have_firewall_rules_changed(&[rule1.clone(), rule3.clone()]));

        // Gateway has firewall config, new rules are identical
        gateway.firewall_config = Some(config1.clone());
        assert!(!gateway.have_firewall_rules_changed(&[rule1.clone(), rule2.clone()]));

        // Gateway has empty firewall config, new rules exist
        gateway.firewall_config = Some(config_empty.clone());
        assert!(gateway.have_firewall_rules_changed(from_ref(&rule1)));

        // Both configs are empty
        gateway.firewall_config = Some(config_empty);
        assert!(!gateway.have_firewall_rules_changed(&[]));
    }

    #[tokio::test]
    async fn test_firewall_config_comparison() {
        let config1 = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Allow,
            snat_bindings: Vec::new(),
        };

        let config2 = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Deny,
            snat_bindings: Vec::new(),
        };

        let config3 = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Allow,
            snat_bindings: Vec::new(),
        };

        let wgapi = WG::new("wg0").unwrap();
        let config = Config::default();
        let mut gateway = Gateway {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            firewall_api: FirewallApi::new("test_interface").unwrap(),
            firewall_config: None,
            connected: Arc::new(AtomicBool::new(false)),
            client_tx: None,
            tls_config: None,
        };
        // Gateway has no config
        gateway.firewall_config = None;
        assert!(gateway.has_firewall_config_changed(&config1));

        // Gateway has config, new config has different default_policy
        gateway.firewall_config = Some(config1.clone());
        assert!(gateway.has_firewall_config_changed(&config2));

        // Gateway has config, new config is identical
        gateway.firewall_config = Some(config1.clone());
        assert!(!gateway.has_firewall_config_changed(&config3));

        // Rules are not being ignored
        let config4 = FirewallConfig {
            rules: vec![FirewallRule {
                comment: None,
                destination_addrs: Vec::new(),
                destination_ports: Vec::new(),
                id: 0,
                verdict: Policy::Allow,
                protocols: Vec::new(),
                source_addrs: Vec::new(),
                ipv4: true,
            }],
            default_policy: Policy::Allow,
            snat_bindings: Vec::new(),
        };
        gateway.firewall_config = Some(config1);
        assert!(gateway.has_firewall_config_changed(&config4));

        // Rule IP versions are not being ignored
        let config5 = FirewallConfig {
            rules: vec![FirewallRule {
                comment: None,
                destination_addrs: Vec::new(),
                destination_ports: Vec::new(),
                id: 0,
                verdict: Policy::Allow,
                protocols: Vec::new(),
                source_addrs: Vec::new(),
                ipv4: false,
            }],
            default_policy: Policy::Allow,
            snat_bindings: Vec::new(),
        };
        gateway.firewall_config = Some(config4);
        assert!(gateway.has_firewall_config_changed(&config5));
    }
}
