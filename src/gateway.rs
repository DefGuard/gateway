use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

use gethostname::gethostname;
use tokio::{
    task::{spawn, JoinHandle},
    time::{interval, sleep},
};
use tonic::{
    codegen::InterceptedService,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
    Request, Status, Streaming,
};

use crate::{
    config::Config,
    error::GatewayError,
    execute_command, mask,
    proto::{
        gateway_service_client::GatewayServiceClient, stats_update::Payload, update, Configuration,
        ConfigurationRequest, Peer, StatsUpdate, Update,
    },
    VERSION,
};
use defguard_wireguard_rs::{WGApi, WireguardInterfaceApi};

const TEN_SECS: Duration = Duration::from_secs(10);

// helper struct which stores just the interface config without peers
#[derive(Clone, PartialEq)]
struct InterfaceConfiguration {
    name: String,
    prvkey: String,
    address: String,
    port: u32,
}

impl From<Configuration> for InterfaceConfiguration {
    fn from(config: Configuration) -> Self {
        Self {
            name: config.name,
            prvkey: config.prvkey,
            address: config.address,
            port: config.port,
        }
    }
}

type Pubkey = String;

pub struct Gateway {
    config: Config,
    interface_configuration: Option<InterfaceConfiguration>,
    peers: HashMap<Pubkey, Peer>,
    wgapi: WGApi,
    pub connected: Arc<AtomicBool>,
    stats_thread_handle: Option<JoinHandle<()>>,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self, GatewayError> {
        let wgapi = WGApi::new(config.ifname.clone(), config.userspace)?;
        Ok(Self {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi,
            connected: Arc::new(AtomicBool::new(false)),
            stats_thread_handle: None,
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
    fn is_config_changed(
        &self,
        new_interface_configuration: &InterfaceConfiguration,
        new_peers: &[Peer],
    ) -> bool {
        if let Some(current_configuration) = self.interface_configuration.clone() {
            return current_configuration != *new_interface_configuration
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
        if !new_peers
            .iter()
            .all(|peer| match self.peers.get(&peer.pubkey) {
                Some(p) => peer.allowed_ips == p.allowed_ips,
                None => false,
            })
        {
            return true;
        }
        false
    }

    /// Starts tokio thread collecting stats and sending them to backend service via gRPC.
    fn spawn_stats_thread(
        &mut self,
        mut client: GatewayServiceClient<
            InterceptedService<
                Channel,
                impl Fn(Request<()>) -> Result<Request<()>, Status> + Send + Sync + 'static,
            >,
        >,
    ) {
        // Create an async stream that periodically yields WireGuard interface statistics.
        let period = Duration::from_secs(self.config.stats_period);
        let ifname = self.config.ifname.clone();
        let userspace = self.config.userspace;
        let stats_stream = async_stream::stream! {
            let wgapi = WGApi::new(ifname, userspace).expect(
                "Failed to initialize WireGuard interface API, interface name: {ifname}, userspace: {userspace}"
            );
            // helper map to track if peer data is actually changing
            // and avoid sending duplicate stats
            let mut peer_map = HashMap::new();
            let mut interval = interval(period);
            let mut id = 1;
            loop {
                // wait till next iteration
                interval.tick().await;
                let mut peer_stats_sent = false;

                debug!("Sending active peer stats update.");
                match wgapi.read_interface_data() {
                    Ok(host) => {
                        let peers = host.peers;
                        debug!("Found {} peers configured on WireGuard interface", peers.len());
                        for peer in peers
                            .into_values()
                            .filter(|p| p.last_handshake.map_or(
                                false,
                                |lhs| lhs != SystemTime::UNIX_EPOCH)
                            ) {
                                let has_changed = match peer_map.get(&peer.public_key) {
                                    Some(last_peer) => *last_peer != peer,
                                    None => true,
                                };
                                if has_changed {
                                    peer_map.insert(peer.public_key.clone(), peer.clone());
                                    id += 1;
                                    yield StatsUpdate {
                                        id,
                                        payload: Some(Payload::PeerStats((&peer).into())),
                                    };
                                    peer_stats_sent = true;
                                };
                                debug!("Stats for peer {} have not changed. Skipping...", peer.public_key);
                            }
                    },
                    Err(err) => error!("Failed to retrieve WireGuard interface stats {err}"),
                }

                if !peer_stats_sent {
                    id += 1;
                    yield StatsUpdate {
                        id,
                        payload: Some(Payload::Empty(()))
                    };
                    debug!("Sent empty stats message.");
                }
            }
        };
        debug!("Spawning stats thread");
        // Spawn the thread
        self.stats_thread_handle = Some(spawn(async move {
            let status = client.stats(Request::new(stats_stream)).await;
            match status {
                Ok(_) => info!("Stats thread terminated successfully."),
                Err(err) => error!("Stats thread terminated with error: {err}"),
            }
        }));
        info!("Stats thread spawned.");
    }

    /// Performs complete interface reconfiguration based on `configuration` object.
    /// Called when gateway (re)connects to GRPC endpoint and retrieves complete
    /// network and peers data.
    fn configure(&mut self, new_configuration: Configuration) -> Result<(), GatewayError> {
        debug!(
            "Received configuration, reconfiguring WireGuard interface {} (address: {})",
            new_configuration.name, new_configuration.address
        );
        trace!(
            "Received configuration: {:?}",
            mask!(new_configuration, prvkey)
        );

        // check if new configuration is different than current one
        let new_interface_configuration = new_configuration.clone().into();
        if !self.is_config_changed(&new_interface_configuration, &new_configuration.peers) {
            debug!("Received configuration is identical to current one. Skipping interface reconfiguration");
            return Ok(());
        };

        self.wgapi
            .configure_interface(&new_configuration.clone().into())?;
        info!(
            "Reconfigured WireGuard interface {} (address: {})",
            new_configuration.name, new_configuration.address
        );
        trace!(
            "Reconfigured WireGuard interface. Configuration: {:?}",
            mask!(new_configuration, prvkey)
        );

        // store new configuration and peers
        self.interface_configuration = Some(new_interface_configuration);
        self.replace_peers(new_configuration.peers);

        Ok(())
    }

    /// Continuously tries to connect to GRPC endpoint. Once the connection is established
    /// configures the interface, starts the stats thread, connects and returns the updates stream
    async fn connect(
        &mut self,
        mut client: GatewayServiceClient<
            InterceptedService<
                Channel,
                impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone + Send + Sync + 'static,
            >,
        >,
    ) -> Result<Streaming<Update>, GatewayError> {
        // set diconnected if we are in this function and drop mutex
        self.connected.store(false, Ordering::Relaxed);
        loop {
            debug!(
                "Connecting to defguard gRPC endpoint: {}",
                self.config.grpc_url
            );
            let (response, stream) = {
                let response = client
                    .config(ConfigurationRequest {
                        name: self.config.name.clone(),
                    })
                    .await;
                let stream = client.updates(()).await;
                (response, stream)
            };
            match (response, stream) {
                (Ok(response), Ok(stream)) => {
                    if let Err(err) = self.configure(response.into_inner()) {
                        error!("Interface configuration failed: {err}");
                        continue;
                    }
                    if self
                        .stats_thread_handle
                        .as_ref()
                        .is_some_and(|handle| !handle.is_finished())
                    {
                        debug!("Stats thread already running. Not starting a new one.");
                    } else {
                        self.spawn_stats_thread(client);
                    }
                    info!(
                        "Connected to defguard gRPC endpoint: {}",
                        self.config.grpc_url
                    );
                    self.connected.store(true, Ordering::Relaxed);
                    break Ok(stream.into_inner());
                }
                (Err(err), _) => {
                    error!("Couldn't retrieve gateway configuration from the core. Using gRPC url: {}. Retrying in 10s. Error: {err}",
                    self.config.grpc_url);
                }
                (_, Err(err)) => {
                    error!("Couldn't establish streaming connection to the core. Using gRPC url: {}. Retrying in 10s. Error: {err}",
                    self.config.grpc_url);
                }
            }
            sleep(TEN_SECS).await;
        }
    }

    fn setup_client(
        &self,
    ) -> Result<
        GatewayServiceClient<
            InterceptedService<
                Channel,
                impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone + Send + Sync + 'static,
            >,
        >,
        GatewayError,
    > {
        debug!("Preparing gRPC client configuration");
        let endpoint = Endpoint::from_shared(self.config.grpc_url.clone())?;
        let endpoint = endpoint
            .http2_keep_alive_interval(TEN_SECS)
            .tcp_keepalive(Some(TEN_SECS))
            .keep_alive_while_idle(true);
        // if CA certificate is provided, use it (and only it)
        // otherwise load certs from system
        let endpoint = if let Some(ca) = &self.config.grpc_ca {
            let ca = std::fs::read_to_string(ca)?;
            let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca));
            endpoint.tls_config(tls)?
        } else {
            endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?
        };
        let channel = endpoint.connect_lazy();

        let token = MetadataValue::try_from(&self.config.token)?;
        let hostname = gethostname()
            .into_string()
            .expect("Unable to get current hostname during gRPC connection setup.");
        debug!("Using hostname: {hostname}");
        let hostname = MetadataValue::try_from(hostname).unwrap();
        let jwt_auth_interceptor = move |mut req: Request<()>| -> Result<Request<()>, Status> {
            req.metadata_mut().insert("authorization", token.clone());
            req.metadata_mut().insert("hostname", hostname.clone());
            Ok(req)
        };
        let client = GatewayServiceClient::with_interceptor(channel, jwt_auth_interceptor);
        debug!("gRPC client configuration done");
        Ok(client)
    }

    /// Starts the gateway process.
    /// * Retrieves configuration and configuration updates from defguard gRPC server
    /// * Manages the interface according to configuration and updates
    /// * Sends interface statistics to defguard server periodically
    pub async fn start(&mut self) -> Result<(), GatewayError> {
        info!(
            "Starting defguard gateway version {VERSION} with configuration: {:?}",
            mask!(self.config, token)
        );

        let client = self.setup_client()?;

        let wgapi = WGApi::new(self.config.ifname.clone(), self.config.userspace)?;

        // Try to create network interface for WireGuard.
        // FIXME: check if the interface already exists, or somehow be more clever.
        if let Err(err) = wgapi.create_interface() {
            warn!(
                "Couldn't create network interface {}: {err}. Proceeding anyway.",
                self.config.ifname
            );
        }

        info!(
            "Trying to connect to {} and obtain the gateway configuration from defguard...",
            self.config.grpc_url
        );
        let mut updates_stream = self.connect(client.clone()).await?;
        if let Some(post_up) = &self.config.post_up {
            debug!("Executing specified POST_UP command: {post_up}");
            execute_command(post_up)?;
        }
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
                                if let Err(err) = wgapi.remove_peer(
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
                                if let Err(err) = wgapi.configure_peer(&peer_config.into()) {
                                    error!("Failed to update peer: {err}");
                                }
                            };
                        }
                        _ => warn!("Unsupported kind of update: {update:?}"),
                    }
                }
                Ok(None) => {
                    warn!("Received empty message, reconnecting");
                    updates_stream = self.connect(client.clone()).await?;
                }
                Err(err) => {
                    error!(
                        "Disconnected from defguard gRPC endoint: {:?}",
                        self.config.grpc_url
                    );
                    error!("Server error {err}, reconnecting");
                    updates_stream = self.connect(client.clone()).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::Config,
        gateway::{Gateway, InterfaceConfiguration},
        proto::Peer,
    };
    use defguard_wireguard_rs::WGApi;
    use std::sync::{atomic::AtomicBool, Arc};

    #[test]
    fn test_configuration_comparison() {
        let old_config = InterfaceConfiguration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.1/24".to_string(),
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

        let gateway = Gateway {
            config: Config::default(),
            interface_configuration: Some(old_config.clone()),
            peers: old_peers_map,
            wgapi: WGApi::new("wg0".into(), false).unwrap(),
            connected: Arc::new(AtomicBool::new(false)),
            stats_thread_handle: None,
        };

        // new config is the same
        let new_config = old_config.clone();
        let new_peers = old_peers.clone();
        assert!(!gateway.is_config_changed(&new_config, &new_peers));

        // only interface config is different
        let new_config = InterfaceConfiguration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.2/24".to_string(),
            port: 50051,
        };
        let new_peers = old_peers.clone();
        assert!(gateway.is_config_changed(&new_config, &new_peers));

        // peer was removed
        let new_config = old_config.clone();
        let mut new_peers = old_peers.clone();
        new_peers.pop();

        assert!(gateway.is_config_changed(&new_config, &new_peers));

        // peer was added
        let new_config = old_config.clone();
        let mut new_peers = old_peers.clone();
        new_peers.push(Peer {
            pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
            allowed_ips: vec!["10.6.1.4/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        });

        assert!(gateway.is_config_changed(&new_config, &new_peers));

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

        assert!(gateway.is_config_changed(&new_config, &new_peers));

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

        assert!(gateway.is_config_changed(&new_config, &new_peers));

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

        assert!(gateway.is_config_changed(&new_config, &new_peers));

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

        assert!(gateway.is_config_changed(&new_config, &new_peers));
    }
}
