use std::{
    collections::HashMap,
    fs::read_to_string,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

use defguard_version::{
    client::{DefguardVersionClientLayer, DefguardVersionClientService},
    parse_metadata,
};
use defguard_wireguard_rs::{net::IpAddrMask, WireguardInterfaceApi};
use gethostname::gethostname;
use tokio::{
    select,
    sync::mpsc,
    task::{spawn, JoinHandle},
    time::{interval, sleep},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{
    codegen::InterceptedService,
    metadata::{Ascii, MetadataValue},
    service::Interceptor,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
    Request, Status, Streaming,
};
use tower::Layer;

use crate::{
    config::Config,
    enterprise::firewall::{
        api::{FirewallApi, FirewallManagementApi},
        FirewallConfig, FirewallRule, SnatBinding,
    },
    error::GatewayError,
    execute_command, mask,
    proto::gateway::{
        gateway_service_client::GatewayServiceClient, stats_update::Payload, update, Configuration,
        ConfigurationRequest, Peer, StatsUpdate, Update,
    },
    VERSION,
};

const TEN_SECS: Duration = Duration::from_secs(10);

// helper struct which stores just the interface config without peers
#[derive(Clone, PartialEq)]
struct InterfaceConfiguration {
    name: String,
    prvkey: String,
    addresses: Vec<IpAddrMask>,
    port: u32,
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
            port: config.port,
        }
    }
}

#[derive(Clone)]
struct AuthInterceptor {
    hostname: MetadataValue<Ascii>,
    token: MetadataValue<Ascii>,
}

impl AuthInterceptor {
    fn new(token: &str) -> Result<Self, GatewayError> {
        let token = MetadataValue::try_from(token)?;
        let hostname = MetadataValue::try_from(
            gethostname()
                .to_str()
                .expect("Unable to get current hostname during gRPC connection setup."),
        )?;

        Ok(Self { hostname, token })
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let metadata = request.metadata_mut();
        metadata.insert("authorization", self.token.clone());
        metadata.insert("hostname", self.hostname.clone());

        Ok(request)
    }
}

type PubKey = String;

pub struct Gateway {
    config: Config,
    interface_configuration: Option<InterfaceConfiguration>,
    peers: HashMap<PubKey, Peer>,
    wgapi: Arc<Mutex<dyn WireguardInterfaceApi + Send + Sync + 'static>>,
    #[cfg_attr(not(target_os = "linux"), allow(unused))]
    firewall_api: FirewallApi,
    #[cfg_attr(not(target_os = "linux"), allow(unused))]
    firewall_config: Option<FirewallConfig>,
    pub connected: Arc<AtomicBool>,
    client: GatewayServiceClient<
        InterceptedService<DefguardVersionClientService<Channel>, AuthInterceptor>,
    >,
    core_version: (String, String),
    stats_thread: Option<JoinHandle<()>>,
}

impl Gateway {
    pub fn new(
        config: Config,
        wgapi: impl WireguardInterfaceApi + Send + Sync + 'static,
        firewall_api: FirewallApi,
    ) -> Result<Self, GatewayError> {
        let client = Self::setup_client(&config)?;
        Ok(Self {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            client,
            stats_thread: None,
            firewall_api,
            firewall_config: None,
            core_version: Default::default(),
        })
    }

    // replace current peer map with a new list of peers
    fn replace_peers(&mut self, new_peers: Vec<Peer>) {
        debug!("Replacing stored peers with {} new peers", new_peers.len());
        let peers = new_peers
            .into_iter()
            .map(|peer| (peer.pubkey.clone(), peer))
            .collect();
        self.peers = peers;
    }

    // check if new received configuration is different than current one
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

    // check if new peers are the same as the stored ones
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

        // check if all IPs are the same
        !new_peers.iter().all(|peer| {
            self.peers
                .get(&peer.pubkey)
                .is_some_and(|p| peer.allowed_ips == p.allowed_ips)
        })
    }

    /// Starts tokio thread collecting stats and sending them to backend service via gRPC.
    fn spawn_stats_thread(&mut self) -> UnboundedReceiverStream<StatsUpdate> {
        if let Some(handle) = self.stats_thread.take() {
            debug!("Aborting previous stats thread before starting a new one");
            handle.abort();
        }
        // Create an async stream that periodically yields WireGuard interface statistics.
        let period = Duration::from_secs(self.config.stats_period);
        let wgapi = Arc::clone(&self.wgapi);
        let (tx, rx) = mpsc::unbounded_channel();
        debug!("Spawning stats thread");
        let handle = spawn(async move {
            // helper map to track if peer data is actually changing
            // and avoid sending duplicate stats
            let mut peer_map = HashMap::new();
            let mut interval = interval(period);
            let mut id = 1;
            'outer: loop {
                // wait until next iteration
                interval.tick().await;
                debug!("Sending active peer stats updates.");
                let interface_data = wgapi.lock().unwrap().read_interface_data();
                match interface_data {
                    Ok(host) => {
                        let peers = host.peers;
                        debug!(
                            "Found {} peers configured on WireGuard interface",
                            peers.len()
                        );
                        for peer in peers.into_values().filter(|p| {
                            p.last_handshake
                                .is_some_and(|lhs| lhs != SystemTime::UNIX_EPOCH)
                        }) {
                            let has_changed = peer_map
                                .get(&peer.public_key)
                                .is_none_or(|last_peer| *last_peer != peer);
                            if has_changed {
                                peer_map.insert(peer.public_key.clone(), peer.clone());
                                id += 1;
                                if tx
                                    .send(StatsUpdate {
                                        id,
                                        payload: Some(Payload::PeerStats((&peer).into())),
                                    })
                                    .is_err()
                                {
                                    debug!("Stats stream disappeared");
                                    break 'outer;
                                }
                            } else {
                                debug!(
                                    "Stats for peer {} have not changed. Skipping.",
                                    peer.public_key
                                );
                            }
                        }
                    }
                    Err(err) => error!("Failed to retrieve WireGuard interface stats: {err}"),
                }
                debug!("Sent peer stats updates for all peers.");
            }
        });
        self.stats_thread = Some(handle);
        UnboundedReceiverStream::new(rx)
    }

    async fn handle_stats_thread(
        mut client: GatewayServiceClient<
            InterceptedService<DefguardVersionClientService<Channel>, AuthInterceptor>,
        >,
        rx: UnboundedReceiverStream<StatsUpdate>,
    ) {
        let status = client.stats(rx).await;
        match status {
            Ok(_) => info!("Stats thread terminated successfully."),
            Err(err) => error!("Stats thread terminated with error: {err}"),
        }
    }

    /// Checks whether the firewall config changed
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

            debug!("Defguard ACL rules are the same. Rules have not changed. My rules: {current_rules:?}, new rules: {new_rules:?}");
            false
        } else {
            debug!("There are new Defguard ACL rules in the new configuration, but we don't have any in the current one. Rules have changed.");
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

            debug!("SNAT bindings are the same. Bindings have not changed. My bindings: {current_bindings:?}, new bindings: {new_bindings:?}");
            false
        } else {
            debug!("There are new SNAT bindings in the new configuration, but we don't have any in the current one. Bindings have changed.");
            true
        }
    }

    /// Process and apply firewall configuration changes.
    /// - If the main config changed (default policy), reconfigure the whole firewall.
    /// - If only the rules changed, apply the new rules. Currently also reconfigures the whole firewall but that
    ///   should be temporary.
    ///
    /// TODO: Reduce cloning here
    fn process_firewall_changes(
        &mut self,
        fw_config: Option<&FirewallConfig>,
    ) -> Result<(), GatewayError> {
        if let Some(fw_config) = fw_config {
            debug!("Received firewall configuration: {fw_config:?}");
            if self.has_firewall_config_changed(fw_config) {
                debug!("Received firewall configuration is different than current one. Reconfiguring firewall...");
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
                debug!("Received firewall configuration is the same as current one. Skipping reconfiguration.");
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
                "Received configuration is different than the current one. Reconfiguring interface..."
            );
            self.wgapi
                .lock()
                .unwrap()
                .configure_interface(&new_configuration.clone().into())?;
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
            debug!("Received configuration is identical to the current one. Skipping interface reconfiguration.");
        }

        // process received firewall config unless firewall management is disabled
        if !self.config.disable_firewall_management {
            let new_firewall_configuration =
                if let Some(firewall_config) = new_configuration.firewall_config {
                    Some(FirewallConfig::from_proto(firewall_config)?)
                } else {
                    None
                };

            self.process_firewall_changes(new_firewall_configuration.as_ref())?;
        } else {
            debug!("Firewall management is disabled. Skipping updating firewall configuration");
        }

        Ok(())
    }

    /// Continuously tries to connect to gRPC endpoint. Once the connection is established
    /// configures the interface, starts the stats thread, connects and returns the updates stream.
    async fn connect(&mut self) -> Streaming<Update> {
        // set diconnected if we are in this function and drop mutex
        self.connected.store(false, Ordering::Relaxed);
        loop {
            debug!(
                "Connecting to Defguard gRPC endpoint: {}",
                self.config.grpc_url
            );
            let (response, stream) = {
                let response = self
                    .client
                    .config(ConfigurationRequest {
                        name: self.config.name.clone(),
                    })
                    .await;
                let stream = self.client.updates(()).await;
                (response, stream)
            };
            match (response, stream) {
                (Ok(response), Ok(stream)) => {
                    let (version, info) = parse_metadata(response.metadata()).unwrap();
                    self.core_version = (version.to_string(), info.to_string());

                    let span = tracing::info_span!(
                        "core_connect",
                        gateway_version = %version,
                        gateway_info = %info,
                    );
                    let _guard = span.enter();

                    if let Err(err) = self.configure(response.into_inner()) {
                        error!("Interface configuration failed: {err}");
                        continue;
                    }
                    info!(
                        "Connected to Defguard gRPC endpoint: {}",
                        self.config.grpc_url
                    );
                    self.connected.store(true, Ordering::Relaxed);
                    break stream.into_inner();
                }
                (Err(err), _) => {
                    error!("Couldn't retrieve gateway configuration from the core. Using gRPC URL: {}. Retrying in 10s. Error: {err}",
                    self.config.grpc_url);
                }
                (_, Err(err)) => {
                    error!("Couldn't establish streaming connection to the core. Using gRPC URL: {}. Retrying in 10s. Error: {err}",
                    self.config.grpc_url);
                }
            }
            sleep(TEN_SECS).await;
        }
    }

    fn setup_client(
        config: &Config,
    ) -> Result<
        GatewayServiceClient<
            InterceptedService<DefguardVersionClientService<Channel>, AuthInterceptor>,
        >,
        GatewayError,
    > {
        debug!("Preparing gRPC client configuration");
        let tls = ClientTlsConfig::new();
        // Use CA if provided, otherwise load certificates from system.
        let tls = if let Some(ca) = &config.grpc_ca {
            let ca = read_to_string(ca).map_err(|err| {
                error!("Failed to read CA file: {err}");
                GatewayError::InvalidCaFile
            })?;
            tls.ca_certificate(Certificate::from_pem(ca))
        } else {
            tls.with_enabled_roots()
        };
        let endpoint = Endpoint::from_shared(config.grpc_url.clone())?
            .http2_keep_alive_interval(TEN_SECS)
            .tcp_keepalive(Some(TEN_SECS))
            .keep_alive_while_idle(true)
            .tls_config(tls)?;
        let channel = endpoint.connect_lazy();

        // Apply version layer to the channel
        let versioned_service = DefguardVersionClientLayer::new(VERSION)?.layer(channel);

        let auth_interceptor = AuthInterceptor::new(&config.token)?;
        let client = GatewayServiceClient::with_interceptor(versioned_service, auth_interceptor);

        debug!("gRPC client configuration done");
        Ok(client)
    }

    async fn handle_updates(&mut self, updates_stream: &mut Streaming<Update>) {
        loop {
            match updates_stream.message().await {
                Ok(Some(update)) => {
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
                                if let Err(err) = self.wgapi.lock().unwrap().remove_peer(
                                    &peer_config.pubkey.as_str().try_into().unwrap_or_default(),
                                ) {
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
                            };
                        }
                        Some(update::Update::FirewallConfig(config)) => {
                            if self.config.disable_firewall_management {
                                debug!("Received firewall config update, but firewall management is disabled. Skipping processing this update: {config:?}");
                                continue;
                            }

                            debug!("Applying received firewall configuration: {config:?}");
                            let config_str = format!("{config:?}");
                            match FirewallConfig::from_proto(config) {
                                Ok(new_firewall_config) => {
                                    debug!(
                                        "Parsed the received firewall configuration: \
                                        {new_firewall_config:?}, processing it and applying \
                                        changes"
                                    );
                                    if let Err(err) =
                                        self.process_firewall_changes(Some(&new_firewall_config))
                                    {
                                        error!(
                                            "Failed to process received firewall configuration: \
                                            {err}"
                                        );
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
                                debug!("Received firewall disable request, but firewall management is disabled. Skipping processing this update");
                                continue;
                            }

                            debug!("Disabling firewall configuration");
                            if let Err(err) = self.process_firewall_changes(None) {
                                error!("Failed to disable firewall configuration: {err}");
                            }
                        }
                        _ => warn!("Unsupported kind of update: {update:?}"),
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(err) => {
                    error!(
                        "Disconnected from Defguard gRPC endoint: {}: {err}",
                        self.config.grpc_url
                    );
                    break;
                }
            }
        }
    }

    /// Starts the gateway process.
    /// * Retrieves configuration and configuration updates from Defguard gRPC server
    /// * Manages the interface according to configuration and updates
    /// * Sends interface statistics to Defguard server periodically
    pub async fn start(&mut self) -> Result<(), GatewayError> {
        info!(
            "Starting Defguard gateway version {VERSION} with configuration: {:?}",
            mask!(self.config, token)
        );

        // Try to create network interface for WireGuard.
        // FIXME: check if the interface already exists, or somehow be more clever.
        if let Err(err) = self.wgapi.lock().unwrap().create_interface() {
            warn!(
                "Couldn't create network interface {}: {err}. Proceeding anyway.",
                self.config.ifname
            );
        } else {
            #[cfg(target_os = "linux")]
            if !self.config.disable_firewall_management && self.config.masquerade {
                self.firewall_api.begin()?;
                self.firewall_api.setup_nat(self.config.masquerade, &[])?;
                self.firewall_api.commit()?;
            }
        }

        info!(
            "Trying to connect to {} and obtain the gateway configuration from Defguard...",
            self.config.grpc_url
        );
        loop {
            let mut updates_stream = self.connect().await;
            if let Some(post_up) = &self.config.post_up {
                debug!("Executing specified POST_UP command: {post_up}");
                execute_command(post_up)?;
            }
            let span = tracing::info_span!(
                "core_grpc_loop",
                core_version = %self.core_version.0,
                core_info = %self.core_version.1,
            );
            let _guard = span.enter();
            let stats_stream = self.spawn_stats_thread();
            let client = self.client.clone();
            select! {
                biased;
                () = Self::handle_stats_thread(client, stats_stream) => {
                    error!("Stats stream aborted; reconnecting");
                }
                () = self.handle_updates(&mut updates_stream) => {
                    error!("Updates stream aborted; reconnecting");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    #[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
    use defguard_wireguard_rs::Kernel;
    #[cfg(target_os = "macos")]
    use defguard_wireguard_rs::Userspace;
    use defguard_wireguard_rs::WGApi;
    use ipnetwork::IpNetwork;

    use super::*;
    use crate::enterprise::firewall::{Address, FirewallRule, Policy, Port, Protocol};

    #[tokio::test]
    async fn test_configuration_comparison() {
        let old_config = InterfaceConfiguration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            addresses: vec!["10.6.1.1/24".parse().unwrap()],
            port: 50051,
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

        #[cfg(any(target_os = "macos", target_os = "netbsd"))]
        let wgapi = WGApi::<Userspace>::new("wg0".into()).unwrap();
        #[cfg(not(target_os = "macos"))]
        let wgapi = WGApi::<Kernel>::new("wg0".into()).unwrap();
        let config = Config::default();
        let client = Gateway::setup_client(&config).unwrap();
        let firewall_api = FirewallApi::new("wg0").unwrap();
        let gateway = Gateway {
            config,
            interface_configuration: Some(old_config.clone()),
            peers: old_peers_map,
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            client,
            stats_thread: None,
            firewall_api,
            firewall_config: None,
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
            snat_bindings: vec![],
        };

        let config_empty = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Allow,
            snat_bindings: vec![],
        };

        #[cfg(target_os = "macos")]
        let wgapi = WGApi::<Userspace>::new("wg0".into()).unwrap();
        #[cfg(not(target_os = "macos"))]
        let wgapi = WGApi::<Kernel>::new("wg0".into()).unwrap();

        let config = Config::default();
        let client = Gateway::setup_client(&config).unwrap();
        let mut gateway = Gateway {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            client,
            stats_thread: None,
            firewall_api: FirewallApi::new("test_interface").unwrap(),
            firewall_config: None,
        };

        // Gateway has no firewall config, new rules are empty
        gateway.firewall_config = None;
        assert!(gateway.have_firewall_rules_changed(&[]));

        // Gateway has no firewall config, but new rules exist
        gateway.firewall_config = None;
        assert!(gateway.have_firewall_rules_changed(&[rule1.clone()]));

        // Gateway has firewall config, with empty rules list
        gateway.firewall_config = Some(config1.clone());
        assert!(gateway.have_firewall_rules_changed(&[]));

        // Gateway has firewall config, new rules have different length
        gateway.firewall_config = Some(config1.clone());
        assert!(gateway.have_firewall_rules_changed(&[rule1.clone()]));

        // Gateway has firewall config, new rules have different content
        gateway.firewall_config = Some(config1.clone());
        assert!(gateway.have_firewall_rules_changed(&[rule1.clone(), rule3.clone()]));

        // Gateway has firewall config, new rules are identical
        gateway.firewall_config = Some(config1.clone());
        assert!(!gateway.have_firewall_rules_changed(&[rule1.clone(), rule2.clone()]));

        // Gateway has empty firewall config, new rules exist
        gateway.firewall_config = Some(config_empty.clone());
        assert!(gateway.have_firewall_rules_changed(&[rule1.clone()]));

        // Both configs are empty
        gateway.firewall_config = Some(config_empty);
        assert!(!gateway.have_firewall_rules_changed(&[]));
    }

    #[tokio::test]
    async fn test_firewall_config_comparison() {
        let config1 = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Allow,
            snat_bindings: vec![],
        };

        let config2 = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Deny,
            snat_bindings: vec![],
        };

        let config3 = FirewallConfig {
            rules: Vec::new(),
            default_policy: Policy::Allow,
            snat_bindings: vec![],
        };

        #[cfg(target_os = "macos")]
        let wgapi = WGApi::<Userspace>::new("wg0".into()).unwrap();
        #[cfg(not(target_os = "macos"))]
        let wgapi = WGApi::<Kernel>::new("wg0".into()).unwrap();

        let config = Config::default();
        let client = Gateway::setup_client(&config).unwrap();
        let mut gateway = Gateway {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            client,
            stats_thread: None,
            firewall_api: FirewallApi::new("test_interface").unwrap(),
            firewall_config: None,
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
            snat_bindings: vec![],
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
            snat_bindings: vec![],
        };
        gateway.firewall_config = Some(config4);
        assert!(gateway.has_firewall_config_changed(&config5));
    }
}
