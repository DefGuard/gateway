use std::{
    collections::HashMap,
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use gethostname::gethostname;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{
    codegen::InterceptedService,
    metadata::{Ascii, MetadataValue},
    service::Interceptor,
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status, Streaming,
};

use crate::{
    config::Config,
    error::GatewayError,
    execute_command, mask,
    proto::{
        core_request, core_response, gateway_server, update, Configuration, CoreRequest,
        CoreResponse, Update, UpdateType,
    },
    state::InterfaceConfiguration,
    VERSION,
};
use defguard_wireguard_rs::WireguardInterfaceApi;

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

type ClientMap = HashMap<SocketAddr, mpsc::UnboundedSender<Result<CoreRequest, Status>>>;

pub struct Gateway {
    config: Config,
    interface_configuration: Option<InterfaceConfiguration>,
    wgapi: Arc<Mutex<dyn WireguardInterfaceApi + Send + Sync + 'static>>,
    pub connected: Arc<AtomicBool>,
    stats_thread_handle: Option<JoinHandle<()>>,
    // TODO: allow only one client.
    // clients: Arc<Mutex<ClientMap>>,
}

impl Gateway {
    pub fn new(
        config: Config,
        wgapi: impl WireguardInterfaceApi + Send + Sync + 'static,
    ) -> Result<Self, GatewayError> {
        Ok(Self {
            config,
            interface_configuration: None,
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            stats_thread_handle: None,
            // clients: Arc::new(Mutex::new(ClientMap::new())),
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

    /// Performs complete interface reconfiguration based on `Configuration` object.
    /// Called when gateway (re)connects to gRPC endpoint and retrieves complete
    /// network and peers data.
    fn configure(&mut self, new_configuration: Configuration) {
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
                return;
            }
        }

        match self
            .wgapi
            .lock()
            .unwrap()
            .configure_interface(&new_configuration.clone().into())
        {
            Ok(()) => {
                info!(
                    "Reconfigured WireGuard interface {} (address: {})",
                    new_configuration.name, new_configuration.address
                );
                trace!(
                    "Reconfigured WireGuard interface. Configuration: {:?}",
                    mask!(new_configuration, prvkey)
                );
            }
            Err(err) => error!("Failed to configure WireGuard interface: {err}"),
        }

        self.interface_configuration = Some(new_configuration.into());
    }

    // Continuously tries to connect to gRPC endpoint. Once the connection is established
    // configures the interface, starts the stats thread, connects and returns the updates stream.
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

    // fn get_config(&self) {
    //     info!("Trying to obtain gateway configuration from core.");
    //     self.clients.lock().unwrap().retain(
    //         move |addr, tx: &mut UnboundedSender<Result<proto::CoreRequest, Status>>| {
    //             eprintln!("Sending peer update to {addr}");
    //             let payload = ConfigurationRequest {
    //                 name: self.config.name.clone(),
    //             };
    //             let req = CoreRequest {
    //                 id: 1, // FIXME: count IDs
    //                 payload: Some(core_request::Payload::ConfigRequest(payload)),
    //             };
    //             tx.send(Ok(req)).is_ok()
    //         },
    //     );
    //     debug!("Finished get_config()");
    // }

    // fn setup_client(
    //     config: &Config,
    // ) -> Result<GatewayServiceClient<InterceptedService<Channel, AuthInterceptor>>, GatewayError>
    // {
    // ...
    //     let auth_interceptor = AuthInterceptor::new(&config.token)?;
    //     let client = GatewayServiceClient::with_interceptor(channel, auth_interceptor);
    // }

    fn handle_update(&mut self, update: Update) {
        debug!("Received update: {update:?}");
        match update.update {
            Some(update::Update::Network(configuration)) => {
                self.configure(configuration);
            }
            Some(update::Update::Peer(peer_config)) => {
                if let Some(if_config) = &mut self.interface_configuration {
                    debug!("Applying peer configuration: {peer_config:?}");

                    if update.update_type == UpdateType::Delete as i32 {
                        debug!("Deleting peer {peer_config:?}");
                        if_config.peers.remove(&peer_config.pubkey);
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
                        if_config
                            .peers
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
                } else {
                    error!("Peer modification request failed: current interface configuration is empty");
                }
            }
            _ => warn!("Unsupported kind of update: {update:?}"),
        }
    }
}

pub struct GatewayServer {
    gateway: Arc<Mutex<Gateway>>,
    // TODO: allow only one client.
    clients: Arc<Mutex<ClientMap>>,
}

impl GatewayServer {
    #[must_use]
    pub fn new(gateway: Gateway) -> Self {
        Self {
            gateway: Arc::new(Mutex::new(gateway)),
            clients: Arc::new(Mutex::new(ClientMap::new())),
        }
    }

    /// Starts the gateway process.
    /// * Retrieves configuration and configuration updates from Defguard gRPC server
    /// * Manages the interface according to configuration and updates
    /// * Sends interface statistics to Defguard server periodically
    pub async fn start(self, config: Config) -> Result<(), GatewayError> {
        info!(
            "Starting Defguard gateway version {VERSION} with configuration: {:?}",
            mask!(config, token)
        );

        // Try to create network interface for WireGuard.
        // FIXME: check if the interface already exists, or somehow be more clever.
        // if let Err(err) = self.wgapi.lock().unwrap().create_interface() {
        //     warn!(
        //         "Couldn't create network interface {}: {err}. Proceeding anyway.",
        //         self.config.ifname
        //     );
        // }

        // let mut updates_stream = self.connect().await?;
        // self.get_config();
        // if let Some(post_up) = &self.config.post_up {
        //     debug!("Executing specified post-up command: {post_up}");
        //     execute_command(post_up)?;
        // }

        // read gRPC TLS cert and key
        debug!("Configuring certificates for gRPC");
        let grpc_cert = config
            .grpc_cert
            .as_ref()
            .and_then(|path| read_to_string(path).ok());
        let grpc_key = config
            .grpc_key
            .as_ref()
            .and_then(|path| read_to_string(path).ok());
        debug!("Configured certificates for gRPC, cert: {grpc_cert:?}");

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
            .add_service(gateway_server::GatewayServer::new(self))
            // TODO: .layer(interceptor(auth_interceptor))
            .serve(addr)
            .await?;

        Ok(())
    }
}

#[tonic::async_trait]
impl gateway_server::Gateway for GatewayServer {
    type BidiStream = UnboundedReceiverStream<Result<CoreRequest, Status>>;

    /// Handle bidirectional communication with Defguard core.
    async fn bidi(
        &self,
        request: Request<Streaming<CoreResponse>>,
    ) -> Result<Response<Self::BidiStream>, Status> {
        let Some(address) = request.remote_addr() else {
            error!("Failed to determine client address for request: {request:?}");
            return Err(Status::internal("Failed to determine client address"));
        };
        info!("Defguard core RPC client connected from: {address}");

        let (tx, rx) = mpsc::unbounded_channel();
        self.clients.lock().unwrap().insert(address, tx);

        let gateway = Arc::clone(&self.gateway);
        let clients = Arc::clone(&self.clients);
        let mut stream = request.into_inner();
        tokio::spawn(async move {
            loop {
                match stream.message().await {
                    Ok(Some(response)) => {
                        debug!("Received message from Defguard core: {response:?}");
                        // Discard empty payloads.
                        if let Some(payload) = response.payload {
                            match payload {
                                core_response::Payload::Config(configuration) => {
                                    match gateway.lock() {
                                        Ok(mut gw) => {
                                            gw.connected.store(true, Ordering::Relaxed);
                                            gw.configure(configuration);
                                        }
                                        Err(err) => error!("Lock failed: {err}"),
                                    }
                                }
                                core_response::Payload::Update(update) => match gateway.lock() {
                                    Ok(mut gw) => {
                                        gw.handle_update(update);
                                    }
                                    Err(err) => error!("Lock failed: {err}"),
                                },
                                core_response::Payload::Empty(()) => (),
                            }
                        }
                    }
                    Ok(None) => {
                        info!("gRPC stream has been closed");
                        break;
                    }
                    Err(err) => {
                        error!("gRPC client error: {err}");
                        break;
                    }
                }
            }
            info!("Defguard core client disconnected: {address}");
            gateway
                .lock()
                .unwrap()
                .connected
                .store(false, Ordering::Relaxed);
            clients.lock().unwrap().remove(&address);
        });

        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}
