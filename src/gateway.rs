#[cfg(target_os = "linux")]
use crate::wireguard::netlink::delete_interface;
use crate::{
    error::GatewayError,
    proto::{gateway_service_client::GatewayServiceClient, update, Configuration, Update},
    wireguard::{setup_interface, wgapi::WGApi},
    Config,
};
use std::{fs::File, io::Write, process, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::sleep};
use tonic::{
    codegen::InterceptedService,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig},
    Request, Status, Streaming,
};

/// Starts tokio thread collecting stats and sending them to backend service via gRPC.
fn spawn_stats_thread(
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
    period: Duration,
    ifname: String,
    userspace: bool,
) {
    // Create an async stream that periodically yields wireguard interface statistics.
    let stats_stream = async_stream::stream! {
        let api = WGApi::new(ifname, userspace);
        loop {
            match api.read_host() {
                Ok(host) => {
                    for peer in host.peers.values() {
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
fn configure(config: &Config, configuration: Configuration) -> Result<(), GatewayError> {
    debug!(
        "Received configuration, reconfiguring WireGuard interface: {:?}",
        configuration
    );
    if !config.userspace {
        #[cfg(target_os = "linux")]
        let _ = delete_interface(&config.ifname);
    }
    setup_interface(&config.ifname, config.userspace, &configuration)?;
    info!("Reconfigured WireGuard interface: {:?}", configuration);
    Ok(())
}

/// Continuously tries to connect to GRPC endpoint. Once the connection is established
/// configures the interface, starts the stats thread, connects and returns the updates stream
async fn connect(
    config: &Config,
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
        debug!("Connecting to DefGuard GRPC endpoint: {}", config.grpc_url);
        let (response, stream) = {
            let mut client = client.lock().await;
            let response = client.config(Request::new(())).await;
            let stream = client.updates(()).await;
            (response, stream)
        };
        if let (Ok(response), Ok(stream)) = (response, stream) {
            configure(config, response.into_inner())?;
            spawn_stats_thread(
                Arc::clone(&client),
                Duration::from_secs(config.stats_period),
                config.ifname.clone(),
                config.userspace,
            );
            info!("Connected to DefGuard GRPC endpoint: {}", config.grpc_url);
            break Ok(stream.into_inner());
        } else {
            error!("Couldn't connect to server, retrying");
        }
        sleep(Duration::from_secs(1)).await;
    }
}

/// Starts the gateway process.
/// * Retrieves configuration and configuration updates from Defguard GRPC server
/// * Manages the interface according to configuration and updates
/// * Sends interface statistics to Defguard server periodically
pub async fn start(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Gateway client starting");

    if let Some(pidfile) = &config.pidfile {
        let mut file = File::create(pidfile)?;
        file.write_all(process::id().to_string().as_bytes())?;
    }

    let channel = Channel::from_shared(config.grpc_url.to_owned())?;
    let channel = if let Some(ca) = &config.grpc_ca {
        let ca = std::fs::read_to_string(ca)?;
        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca));
        channel.tls_config(tls)?
    } else {
        channel
    };
    let channel = channel.connect_lazy();

    let token = MetadataValue::try_from(&config.token)
        .map_err(|_| Status::unknown("Token parsing error"))?;
    let jwt_auth_interceptor = move |mut req: Request<()>| -> Result<Request<()>, Status> {
        req.metadata_mut().insert("authorization", token.clone());
        Ok(req)
    };
    let client = Arc::new(Mutex::new(GatewayServiceClient::with_interceptor(
        channel,
        jwt_auth_interceptor,
    )));

    let wgapi = WGApi::new(config.ifname.clone(), config.userspace);
    let mut updates_stream = connect(config, Arc::clone(&client)).await?;
    loop {
        match updates_stream.message().await {
            Ok(Some(update)) => match update.update {
                Some(update::Update::Network(configuration)) => configure(config, configuration)?,
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
            },
            _ => {
                error!("Server connection lost, reconnecting");
                updates_stream = connect(config, Arc::clone(&client)).await?;
            }
        }
    }
}
