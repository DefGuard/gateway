use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use gethostname::gethostname;
use tokio::{
    sync::Mutex,
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
        gateway_service_client::GatewayServiceClient, update, Configuration, ConfigurationRequest,
        Peer, Update,
    },
    wireguard_rs::{WGApi, WireguardInterfaceApi},
    VERSION,
};

// helper struct which stores just the interface config without peers
#[derive(Clone, PartialEq)]
pub struct InterfaceConfiguration {
    pub name: String,
    pub prvkey: String,
    pub address: String,
    pub port: u32,
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
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self, GatewayError> {
        let wgapi = WGApi::new(config.ifname.clone(), config.userspace)?;
        Ok(Self {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi,
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
        new_peers: &Vec<Peer>,
    ) -> bool {
        if let Some(current_configuration) = self.interface_configuration.clone() {
            return current_configuration != *new_interface_configuration
                || self.is_peer_list_changed(new_peers);
        }
        true
    }

    // check if new peers are the same as the stored ones
    fn is_peer_list_changed(&self, new_peers: &Vec<Peer>) -> bool {
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
        &self,
        client: Arc<
            Mutex<
                GatewayServiceClient<
                    InterceptedService<
                        Channel,
                        impl Fn(Request<()>) -> Result<Request<()>, Status> + Send + 'static,
                    >,
                >,
            >,
        >,
    ) {
        // Create an async stream that periodically yields wireguard interface statistics.
        info!("Spawning stats thread");
        let period = Duration::from_secs(self.config.stats_period);
        let ifname = self.config.ifname.clone();
        let userspace = self.config.userspace;
        let stats_stream = async_stream::stream! {
            let wgapi = WGApi::new(ifname, userspace).expect("Failed to initialize WireGuard interface API");
            // helper map to track if peer data is actually changing
            // and avoid sending duplicate stats
            let mut peer_map = HashMap::new();
            let mut interval = interval(period);
            loop {
                // wait till next iteration
                interval.tick().await;
                debug!("Sending active peer stats update");
                match wgapi.read_interface_data() {
                    Ok(host) => {
                        let peers = host.peers;
                        debug!("Found {} peers configured on WireGuard interface: {peers:?}", peers.len());
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
                                    yield (&peer).into();
                                };
                                debug!("Stats for peer {peer:?} have not changed. Skipping...");
                            }
                    },
                    Err(err) => error!("Failed to retrieve WireGuard interface stats {}", err),
                }
                debug!("Finished sending active peer stats update");
            }
        };
        // Spawn the thread
        tokio::spawn(async move {
            let mut client = client.lock().await;
            let _r = client.stats(Request::new(stats_stream)).await;
        });
    }

    /// Performs complete interface reconfiguration based on `configuration` object.
    /// Called when gateway (re)connects to GRPC endpoint and retrieves complete
    /// network and peers data.
    fn configure(&mut self, new_configuration: Configuration) -> Result<(), GatewayError> {
        debug!(
            "Received configuration, reconfiguring WireGuard interface: {:?}",
            mask!(new_configuration, prvkey)
        );

        // check if new configuration is different than current one
        let new_interface_configuration = new_configuration.clone().into();
        if !self.is_config_changed(&new_interface_configuration, &new_configuration.peers) {
            debug!("Received configuration is identical to current one. Skipping interface reconfiguration");
            return Ok(());
        };

        // if !self.config.userspace {
        //     if let Some(pre_down) = &self.config.pre_down {
        //         info!("Executing specified PRE_DOWN command: {}", pre_down);
        //         execute_command(pre_down)?;
        //     }
        //     #[cfg(target_os = "linux")]
        //     let _ = delete_interface(&self.config.ifname);
        // }
        self.wgapi
            .configure_interface(&new_configuration.clone().into())?;
        info!(
            "Reconfigured WireGuard interface: {:?}",
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
        client: Arc<
            Mutex<
                GatewayServiceClient<
                    InterceptedService<
                        Channel,
                        impl Fn(Request<()>) -> Result<Request<()>, Status> + Send + 'static,
                    >,
                >,
            >,
        >,
    ) -> Result<Streaming<Update>, GatewayError> {
        loop {
            debug!(
                "Connecting to Defguard GRPC endpoint: {}",
                self.config.grpc_url
            );
            let (response, stream) = {
                let mut client = client.lock().await;
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
                    self.configure(response.into_inner())?;
                    self.spawn_stats_thread(client.clone());
                    info!(
                        "Connected to Defguard GRPC endpoint: {}",
                        self.config.grpc_url
                    );
                    break Ok(stream.into_inner());
                }
                (Err(err), _) => {
                    error!("Couldn't retrieve gateway configuration, retrying: {}", err);
                }
                (_, Err(err)) => {
                    error!("Couldn't establish streaming connection, retrying: {}", err);
                }
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    fn setup_client(
        &self,
    ) -> Result<
        Arc<
            Mutex<
                GatewayServiceClient<
                    InterceptedService<
                        Channel,
                        impl Fn(Request<()>) -> Result<Request<()>, Status> + Send + 'static,
                    >,
                >,
            >,
        >,
        GatewayError,
    > {
        debug!("Setting up gRPC server connection");
        let endpoint = Endpoint::from_shared(self.config.grpc_url.clone())?;
        let endpoint = endpoint.http2_keep_alive_interval(Duration::from_secs(10));
        let endpoint = endpoint.tcp_keepalive(Some(Duration::from_secs(10)));
        let endpoint = if let Some(ca) = &self.config.grpc_ca {
            let ca = std::fs::read_to_string(ca)?;
            let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca));
            endpoint.tls_config(tls)?
        } else {
            endpoint
        };
        let channel = endpoint.connect_lazy();

        let token = MetadataValue::try_from(&self.config.token)?;
        let hostname = gethostname()
            .into_string()
            .expect("Unable to get current hostname");
        let hostname = MetadataValue::try_from(hostname).unwrap();
        let jwt_auth_interceptor = move |mut req: Request<()>| -> Result<Request<()>, Status> {
            req.metadata_mut().insert("authorization", token.clone());
            req.metadata_mut().insert("hostname", hostname.clone());
            Ok(req)
        };
        let client = Arc::new(Mutex::new(GatewayServiceClient::with_interceptor(
            channel,
            jwt_auth_interceptor,
        )));
        Ok(client)
    }

    /// Starts the gateway process.
    /// * Retrieves configuration and configuration updates from Defguard GRPC server
    /// * Manages the interface according to configuration and updates
    /// * Sends interface statistics to Defguard server periodically
    pub async fn start(&mut self) -> Result<(), GatewayError> {
        info!(
            "Starting Defguard gateway version {VERSION} with configuration: {:?}",
            mask!(self.config, token)
        );

        let client = self.setup_client()?;

        let wgapi = WGApi::new(self.config.ifname.clone(), self.config.userspace)?;
        let mut updates_stream = self.connect(Arc::clone(&client)).await?;
        if let Some(post_up) = &self.config.post_up {
            info!("Executing specified POST_UP command: {}", post_up);
            execute_command(post_up)?;
        }
        loop {
            match updates_stream.message().await {
                Ok(Some(update)) => {
                    debug!("Received update: {:?}", update);
                    match update.update {
                        Some(update::Update::Network(configuration)) => {
                            self.configure(configuration)?;
                        }
                        Some(update::Update::Peer(peer_config)) => {
                            info!("Applying peer configuration: {peer_config:?}");
                            // UpdateType::Delete
                            if update.update_type == 2 {
                                debug!("Deleting peer {peer_config:?}");
                                self.peers.remove(&peer_config.pubkey);
                                wgapi.remove_peer(
                                    &peer_config.pubkey.as_str().try_into().unwrap_or_default(),
                                )
                            }
                            // UpdateType::Create, UpdateType::Modify
                            else {
                                debug!(
                                    "Updating peer {peer_config:?}, update type: {}",
                                    update.update_type
                                );
                                self.peers
                                    .insert(peer_config.pubkey.clone(), peer_config.clone());
                                wgapi.configure_peer(&peer_config.into())
                            }?;
                        }
                        _ => warn!("Unsupported kind of update"),
                    }
                }
                Ok(None) => {
                    warn!("Received empty message, reconnecting");
                    updates_stream = self.connect(Arc::clone(&client)).await?;
                }
                Err(err) => {
                    error!("Server error {err}, reconnecting");
                    updates_stream = self.connect(Arc::clone(&client)).await?;
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
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.3/24".to_string()],
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
        });

        assert!(gateway.is_config_changed(&new_config, &new_peers));

        // peer pubkey changed
        let new_config = old_config.clone();
        let new_peers = vec![
            Peer {
                pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.3/24".to_string()],
            },
        ];

        assert!(gateway.is_config_changed(&new_config, &new_peers));

        // peer IP changed
        let new_config = old_config.clone();
        let new_peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.4/24".to_string()],
            },
        ];

        assert!(gateway.is_config_changed(&new_config, &new_peers));
    }
}
