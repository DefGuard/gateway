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

use crate::{
    config::Config,
    enterprise::firewall::{
        api::{FirewallApi, FirewallManagementApi},
        FirewallConfig, FirewallRule,
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
    firewall_api: Option<FirewallApi>,
    firewall_rules: Vec<FirewallRule>,
    pub connected: Arc<AtomicBool>,
    client: GatewayServiceClient<InterceptedService<Channel, AuthInterceptor>>,
    stats_thread: Option<JoinHandle<()>>,
}

impl Gateway {
    pub fn new(
        config: Config,
        wgapi: impl WireguardInterfaceApi + Send + Sync + 'static,
        firewallapi: Option<FirewallApi>,
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
            firewall_api: firewallapi,
            firewall_rules: vec![],
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

    fn is_firewall_config_changed(&self, new_fw_config: &FirewallConfig) -> bool {
        if let Some(firewall_api) = &self.firewall_api {
            return firewall_api.config_changed(new_fw_config);
        }
        true
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
                .map_or(false, |p| peer.allowed_ips == p.allowed_ips)
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
                                .map_or(false, |lhs| lhs != SystemTime::UNIX_EPOCH)
                        }) {
                            let has_changed = peer_map
                                .get(&peer.public_key)
                                .map_or(true, |last_peer| *last_peer != peer);
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
        mut client: GatewayServiceClient<InterceptedService<Channel, AuthInterceptor>>,
        rx: UnboundedReceiverStream<StatsUpdate>,
    ) {
        let status = client.stats(rx).await;
        match status {
            Ok(_) => info!("Stats thread terminated successfully."),
            Err(err) => error!("Stats thread terminated with error: {err}"),
        }
    }

    fn did_firewall_rules_change(&self, new_rules: &[FirewallRule]) -> bool {
        debug!("Checking if Defguard ACL rules have changed");

        if self.firewall_rules.len() != new_rules.len() {
            debug!("Number of Defguard ACL rules is different, so the rules have changed");
            return true;
        }

        for rule in new_rules {
            if !self.firewall_rules.contains(rule) {
                debug!("Found a new Defguard ACL rule: {rule:?}. Rules have changed.");
                return true;
            }
        }

        for rule in &self.firewall_rules {
            if !new_rules.contains(rule) {
                debug!("Found a removed Defguard ACL rule: {rule:?}. Rules have changed.");
                return true;
            }
        }

        debug!("Defguard ACL rules have not changed");
        false
    }

    /// Process and apply firewall configuration changes.
    /// - If the main config changed (default policy, IP version), reconfigure the whole firewall.
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
            if self.is_firewall_config_changed(fw_config) {
                debug!("Received firewall configuration is different than current one. Reconfiguring firewall...");
                if let Some(api) = &mut self.firewall_api {
                    api.maybe_update_from_config(fw_config)?;
                    api.setup()?;
                } else {
                    let api = FirewallApi::from_config(
                        &self.config.ifname,
                        fw_config,
                        self.config.masquerade,
                    );
                    api.setup()?;
                    self.firewall_api = Some(api);
                }

                if self.did_firewall_rules_change(&fw_config.rules) {
                    debug!("Received firewall rules are different than the current ones. Applying the new rules.");
                    if let Some(api) = &self.firewall_api {
                        api.apply_rules(fw_config.rules.clone())?;
                        self.firewall_rules = fw_config.rules.clone();
                    } else {
                        error!(
                            "Firewall API not initialized. Configuration: {:?}",
                            fw_config.rules
                        );
                    }
                } else {
                    debug!("Received firewall rules are the same as the current ones. Skipping applying the rules.");
                }
            } else if self.did_firewall_rules_change(&fw_config.rules) {
                debug!("Received firewall rules are different than the current ones. Applying the new rules.");
                if let Some(api) = &self.firewall_api {
                    // Temporary simplest approach is to drop everything and reapply all rules
                    api.setup()?;
                    api.apply_rules(fw_config.rules.clone())?;
                    self.firewall_rules = fw_config.rules.clone();
                } else {
                    error!(
                        "Firewall API not initialized. Configuration: {:?}",
                        fw_config.rules
                    );
                }
            } else {
                debug!("Received firewall configuration and rules are identical to current one. Skipping firewall reconfiguration");
            }
        } else {
            debug!("Received firewall configuration is empty, cleaning up firewall rules...");
            if let Some(api) = &self.firewall_api {
                api.cleanup()?;
                self.firewall_api = None;
                self.firewall_rules = vec![];
            }
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

        if !self.is_interface_config_changed(&new_interface_configuration, &new_configuration.peers)
        {
            debug!("Received configuration is identical to current one. Skipping interface reconfiguration");
        } else {
            debug!(
                "Received configuration is different than current one. Reconfiguring interface..."
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
        }

        let new_firewall_configuration =
            if let Some(firewall_config) = new_configuration.firewall_config {
                Some(FirewallConfig::from_proto(firewall_config)?)
            } else {
                None
            };

        self.process_firewall_changes(new_firewall_configuration.as_ref())?;

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
    ) -> Result<GatewayServiceClient<InterceptedService<Channel, AuthInterceptor>>, GatewayError>
    {
        debug!("Preparing gRPC client configuration");
        // Use CA if provided, otherwise load certificates from system.
        let tls = if let Some(ca) = &config.grpc_ca {
            let ca = read_to_string(ca).map_err(|err| {
                error!("Failed to read CA file: {err}");
                GatewayError::InvalidCaFile
            })?;
            ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca))
        } else {
            ClientTlsConfig::new().with_native_roots()
        };
        let endpoint = Endpoint::from_shared(config.grpc_url.clone())?
            .http2_keep_alive_interval(TEN_SECS)
            .tcp_keepalive(Some(TEN_SECS))
            .keep_alive_while_idle(true)
            .tls_config(tls)?;
        let channel = endpoint.connect_lazy();

        let auth_interceptor = AuthInterceptor::new(&config.token)?;
        let client = GatewayServiceClient::with_interceptor(channel, auth_interceptor);

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
                            debug!("Applying received firewall configuration: {config:?}");
                            let config_str = format!("{:?}", config);
                            match FirewallConfig::from_proto(config) {
                                Ok(new_firewall_config) => {
                                    debug!("Parsed the received firewall configuration: {new_firewall_config:?}, processing it and applying changes");
                                    if let Err(err) =
                                        self.process_firewall_changes(Some(&new_firewall_config))
                                    {
                                        error!("Failed to process received firewall configuration: {err}");
                                    }
                                }
                                Err(err) => {
                                    error!(
                                        "Failed to parse received firewall configuration: {err}. Configuration: {config_str}"
                                    );
                                }
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
    #[cfg(not(target_os = "macos"))]
    use defguard_wireguard_rs::Kernel;
    #[cfg(target_os = "macos")]
    use defguard_wireguard_rs::Userspace;
    use defguard_wireguard_rs::WGApi;

    use super::*;

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

        #[cfg(target_os = "macos")]
        let wgapi = WGApi::<Userspace>::new("wg0".into()).unwrap();
        #[cfg(not(target_os = "macos"))]
        let wgapi = WGApi::<Kernel>::new("wg0".into()).unwrap();
        let config = Config::default();
        let client = Gateway::setup_client(&config).unwrap();
        let gateway = Gateway {
            config,
            interface_configuration: Some(old_config.clone()),
            peers: old_peers_map,
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            client,
            stats_thread: None,
            firewall_api: None,
            firewall_rules: vec![],
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
}
