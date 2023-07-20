use crate::mask;
use crate::proto::ConfigurationRequest;
#[cfg(target_os = "linux")]
use crate::{
    config::Config,
    error::GatewayError,
    proto::{gateway_service_client::GatewayServiceClient, update, Configuration, Update},
    wireguard::{netlink::delete_interface, setup_interface, wgapi::WGApi},
    VERSION,
};
use gethostname::gethostname;
use lazy_static::lazy_static;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{sync::Mutex, time::sleep};
use tonic::{
    codegen::InterceptedService,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
    Request, Status, Streaming,
};

lazy_static! {
    static ref HOSTNAME: String = gethostname()
        .into_string()
        .expect("Unable to get current hostname");
}

pub struct Gateway {
    config: Config,
    interface_configuration: Option<Configuration>,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self, GatewayError> {
        Ok(Self {
            config,
            interface_configuration: None,
        })
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
            let api = WGApi::new(ifname, userspace);
            loop {
                debug!("Sending peer stats update");
                match api.read_host() {
                    Ok(host) => {
                        for peer in host
                            .peers
                            .values()
                            .filter(|p| p.last_handshake.map_or(
                                false,
                                |lhs| lhs != SystemTime::UNIX_EPOCH)
                            ) {
                            yield peer.into();
                        }
                    },
                    Err(err) => error!("Failed to retrieve WireGuard interface stats {}", err),
                }
                sleep(period).await;
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
        if let Some(current_configuration) = self.interface_configuration.clone() {
            if current_configuration == new_configuration {
                debug!("Received configuration is identical to current one. Skipping interface reconfiguration");
                return Ok(());
            }
        }

        if !self.config.userspace {
            #[cfg(target_os = "linux")]
            let _ = delete_interface(&self.config.ifname);
        }
        setup_interface(
            &self.config.ifname,
            self.config.userspace,
            &new_configuration,
        )?;
        info!(
            "Reconfigured WireGuard interface: {:?}",
            mask!(new_configuration, prvkey)
        );

        // store new configuration
        self.interface_configuration = Some(new_configuration);

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
            let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca));
            endpoint.tls_config(tls)?
        } else {
            endpoint
        };
        let channel = endpoint.connect_lazy();

        let token = MetadataValue::try_from(&self.config.token)?;
        let hostname = MetadataValue::from_static(&HOSTNAME);
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
            "Starting Defguard gateway version {} with configuration: {:?}",
            VERSION,
            mask!(self.config, token)
        );

        let client = self.setup_client()?;

        let wgapi = WGApi::new(self.config.ifname.clone(), self.config.userspace);
        let mut updates_stream = self.connect(Arc::clone(&client)).await?;
        loop {
            match updates_stream.message().await {
                Ok(Some(update)) => {
                    debug!("Received update: {:?}", update);
                    match update.update {
                        Some(update::Update::Network(configuration)) => {
                            self.configure(configuration)?
                        }
                        Some(update::Update::Peer(peer_config)) => {
                            info!("Applying peer configuration: {:?}", peer_config);
                            match update.update_type {
                                // UpdateType::Delete
                                2 => wgapi.delete_peer(&peer_config.into()),
                                // UpdateType::Create, UpdateType::Modify
                                _ => wgapi.write_peer(&peer_config.into()),
                            }?
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
    use crate::proto::Configuration;

    #[test]
    fn test_configuration_comparison() {
        let old_config = Configuration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.1/24".to_string(),
            port: 50051,
            peers: vec![],
        };

        let new_config = Configuration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.1/24".to_string(),
            port: 50051,
            peers: vec![],
        };

        assert_eq!(old_config, new_config);

        let new_config = Configuration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.0.1/24".to_string(),
            port: 50051,
            peers: vec![],
        };

        assert_ne!(old_config, new_config);

        let new_config = Configuration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j40TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.1/24".to_string(),
            port: 50051,
            peers: vec![],
        };

        assert_ne!(old_config, new_config);

        let new_config = Configuration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.1/24".to_string(),
            port: 50052,
            peers: vec![],
        };

        assert_ne!(old_config, new_config);
    }
}
