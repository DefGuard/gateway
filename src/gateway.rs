use std::{
    collections::HashMap,
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use gethostname::gethostname;
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::{spawn, JoinHandle},
    time::{interval, sleep},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{
    codegen::InterceptedService,
    metadata::{Ascii, MetadataValue},
    service::Interceptor,
    transport::{
        Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
    },
    Request, Response, Status, Streaming,
};

use crate::{
    config::Config,
    error::GatewayError,
    execute_command,
    grpc::ClientMap,
    mask,
    proto::{
        self, core_request, core_response, gateway_server, Configuration, ConfigurationRequest,
        CoreRequest, CoreResponse, Peer, Update,
    },
    state::InterfaceConfiguration,
    VERSION,
};
use defguard_wireguard_rs::WireguardInterfaceApi;

const TEN_SECS: Duration = Duration::from_secs(10);

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

pub struct Gateway {
    config: Config,
    interface_configuration: Option<InterfaceConfiguration>,
    wgapi: Arc<Mutex<dyn WireguardInterfaceApi + Send + Sync + 'static>>,
    pub connected: Arc<AtomicBool>,
    stats_thread_handle: Option<JoinHandle<()>>,
    // TODO: allow only one client.
    clients: Arc<Mutex<ClientMap>>,
}

impl Gateway {
    pub fn new(
        config: Config,
        wgapi: impl WireguardInterfaceApi + Send + Sync + 'static,
        clients: Arc<Mutex<ClientMap>>,
    ) -> Result<Self, GatewayError> {
        Ok(Self {
            config,
            interface_configuration: None,
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            stats_thread_handle: None,
            clients,
        })
    }

    /// Starts tokio thread collecting stats and sending them to backend service via gRPC.
    // fn spawn_stats_thread(&mut self) {
    //     let mut client = self.client.clone();
    //     // Create an async stream that periodically yields WireGuard interface statistics.
    //     let period = Duration::from_secs(self.config.stats_period);
    //     let wgapi = Arc::clone(&self.wgapi);
    //     let (tx, rx) = mpsc::unbounded_channel();
    //     debug!("Spawning stats thread");
    //     spawn(async move {
    //         // helper map to track if peer data is actually changing
    //         // and avoid sending duplicate stats
    //         let mut peer_map = HashMap::new();
    //         let mut interval = interval(period);
    //         let mut id = 1;
    //         loop {
    //             // wait until next iteration
    //             interval.tick().await;
    //             let mut payload = Payload::Empty(());

    //             debug!("Sending active peer stats update.");
    //             match wgapi.lock().unwrap().read_interface_data() {
    //                 Ok(host) => {
    //                     let peers = host.peers;
    //                     debug!(
    //                         "Found {} peers configured on WireGuard interface",
    //                         peers.len()
    //                     );
    //                     for peer in peers.into_values().filter(|p| {
    //                         p.last_handshake
    //                             .map_or(false, |lhs| lhs != SystemTime::UNIX_EPOCH)
    //                     }) {
    //                         let has_changed = match peer_map.get(&peer.public_key) {
    //                             Some(last_peer) => *last_peer != peer,
    //                             None => true,
    //                         };
    //                         if has_changed {
    //                             peer_map.insert(peer.public_key.clone(), peer.clone());
    //                             payload = Payload::PeerStats((&peer).into());
    //                         } else {
    //                             debug!(
    //                                 "Stats for peer {} have not changed. Skipping.",
    //                                 peer.public_key
    //                             );
    //                         }
    //                     }
    //                 }
    //                 Err(err) => error!("Failed to retrieve WireGuard interface stats: {err}"),
    //             }

    //             id += 1;
    //             if tx
    //                 .send(StatsUpdate {
    //                     id,
    //                     payload: Some(payload),
    //                 })
    //                 .is_err()
    //             {
    //                 debug!("Stats stream disappeared");
    //                 break;
    //             }
    //         }
    //     });

    //     self.stats_thread_handle = Some(spawn(async move {
    //         let status = client.stats(UnboundedReceiverStream::new(rx)).await;
    //         match status {
    //             Ok(_) => info!("Stats thread terminated successfully."),
    //             Err(err) => error!("Stats thread terminated with error: {err}"),
    //         }
    //     }));
    //     info!("Stats thread spawned.");
    // }

    /// Performs complete interface reconfiguration based on `configuration` object.
    /// Called when gateway (re)connects to gRPC endpoint and retrieves complete
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
        if let Some(if_config) = &self.interface_configuration {
            if if_config.same_as(&new_configuration) {
                debug!("Received configuration is identical to current one. Skipping interface reconfiguration.");
                return Ok(());
            }
        }

        self.wgapi
            .lock()
            .unwrap()
            .configure_interface(&new_configuration.clone().into())?;
        info!(
            "Reconfigured WireGuard interface {} (address: {})",
            new_configuration.name, new_configuration.address
        );
        trace!(
            "Reconfigured WireGuard interface. Configuration: {:?}",
            mask!(new_configuration, prvkey)
        );

        self.interface_configuration = Some(new_configuration.into());

        Ok(())
    }

    /// Continuously tries to connect to gRPC endpoint. Once the connection is established
    /// configures the interface, starts the stats thread, connects and returns the updates stream.
    // async fn connect(&mut self) -> Result<Streaming<Update>, GatewayError> {
    //     // set diconnected if we are in this function and drop mutex
    //     self.connected.store(false, Ordering::Relaxed);
    //     loop {
    //         debug!(
    //             "Connecting to Defguard gRPC endpoint: {}",
    //             self.config.grpc_url
    //         );
    //         let (response, stream) = {
    //             let response = self
    //                 .client
    //                 .config(ConfigurationRequest {
    //                     name: self.config.name.clone(),
    //                 })
    //                 .await;
    //             let stream = self.client.updates(()).await;
    //             (response, stream)
    //         };
    //         match (response, stream) {
    //             (Ok(response), Ok(stream)) => {
    //                 if let Err(err) = self.configure(response.into_inner()) {
    //                     error!("Interface configuration failed: {err}");
    //                     continue;
    //                 }
    //                 if self
    //                     .stats_thread_handle
    //                     .as_ref()
    //                     .is_some_and(|handle| !handle.is_finished())
    //                 {
    //                     debug!("Stats thread already running. Not starting a new one.");
    //                 } else {
    //                     self.spawn_stats_thread();
    //                 }
    //                 info!(
    //                     "Connected to Defguard gRPC endpoint: {}",
    //                     self.config.grpc_url
    //                 );
    //                 self.connected.store(true, Ordering::Relaxed);
    //                 break Ok(stream.into_inner());
    //             }
    //             (Err(err), _) => {
    //                 error!("Couldn't retrieve gateway configuration from the core. Using gRPC URL: {}. Retrying in 10s. Error: {err}",
    //                 self.config.grpc_url);
    //             }
    //             (_, Err(err)) => {
    //                 error!("Couldn't establish streaming connection to the core. Using gRPC URL: {}. Retrying in 10s. Error: {err}",
    //                 self.config.grpc_url);
    //             }
    //         }
    //         sleep(TEN_SECS).await;
    //     }
    // }

    // TODO: this should be sent when a client connects.
    fn get_config(&self) {
        self.clients.lock().unwrap().retain(
            move |addr, tx: &mut UnboundedSender<Result<proto::CoreRequest, Status>>| {
                eprintln!("Sending peer update to {addr}");
                let payload = ConfigurationRequest {
                    name: self.config.name.clone(),
                };
                let req = CoreRequest {
                    id: 1, // FIXME: count IDs
                    payload: Some(core_request::Payload::ConfigRequest(payload)),
                };
                tx.send(Ok(req)).is_ok()
            },
        );
    }

    // fn setup_client(
    //     config: &Config,
    // ) -> Result<GatewayServiceClient<InterceptedService<Channel, AuthInterceptor>>, GatewayError>
    // {
    //     debug!("Preparing gRPC client configuration");
    //     // Use CA if provided, otherwise load certificates from system.
    //     let tls = if let Some(ca) = &config.grpc_ca {
    //         let ca = read_to_string(ca)?;
    //         ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca))
    //     } else {
    //         ClientTlsConfig::new().with_native_roots()
    //     };
    //     let endpoint = Endpoint::from_shared(config.grpc_url.clone())?
    //         .http2_keep_alive_interval(TEN_SECS)
    //         .tcp_keepalive(Some(TEN_SECS))
    //         .keep_alive_while_idle(true)
    //         .tls_config(tls)?;
    //     let channel = endpoint.connect_lazy();

    //     let auth_interceptor = AuthInterceptor::new(&config.token)?;
    //     let client = GatewayServiceClient::with_interceptor(channel, auth_interceptor);

    //     debug!("gRPC client configuration done");
    //     Ok(client)
    // }

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

        info!("Trying to obtain gateway configuration from core...");
        // let mut updates_stream = self.connect().await?;
        self.get_config();
        info!("Finished get_config()");
        if let Some(post_up) = &self.config.post_up {
            debug!("Executing specified post-up command: {post_up}");
            execute_command(post_up)?;
        }
        // loop {
        //     match updates_stream.message().await {
        //         Ok(Some(update)) => {
        //             debug!("Received update: {update:?}");
        //             match update.update {
        //                 Some(update::Update::Network(configuration)) => {
        //                     if let Err(err) = self.configure(configuration) {
        //                         error!("Failed to update network configuration: {err}");
        //                     }
        //                 }
        //                 Some(update::Update::Peer(peer_config)) => {
        //                     debug!("Applying peer configuration: {peer_config:?}");
        //                     // UpdateType::Delete
        //                     if update.update_type == 2 {
        //                         debug!("Deleting peer {peer_config:?}");
        //                         self.peers.remove(&peer_config.pubkey);
        //                         if let Err(err) = self.wgapi.lock().unwrap().remove_peer(
        //                             &peer_config.pubkey.as_str().try_into().unwrap_or_default(),
        //                         ) {
        //                             error!("Failed to delete peer: {err}");
        //                         }
        //                     }
        //                     // UpdateType::Create, UpdateType::Modify
        //                     else {
        //                         debug!(
        //                             "Updating peer {peer_config:?}, update type: {}",
        //                             update.update_type
        //                         );
        //                         self.peers
        //                             .insert(peer_config.pubkey.clone(), peer_config.clone());
        //                         if let Err(err) = self
        //                             .wgapi
        //                             .lock()
        //                             .unwrap()
        //                             .configure_peer(&peer_config.into())
        //                         {
        //                             error!("Failed to update peer: {err}");
        //                         }
        //                     };
        //                 }
        //                 _ => warn!("Unsupported kind of update: {update:?}"),
        //             }
        //         }
        //         Ok(None) => {
        //             warn!("Stream has been closed, reconnecting");
        //             updates_stream = self.connect().await?;
        //         }
        //         Err(err) => {
        //             error!(
        //                 "Disconnected from Defguard gRPC endoint: {:?}",
        //                 self.config.grpc_url
        //             );
        //             error!("Server error {err}, reconnecting");
        //             updates_stream = self.connect().await?;
        //         }
        //     }
        // }

        Ok(())
    }
}
