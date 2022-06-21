#[cfg(target_os = "linux")]
use crate::wireguard::netlink::delete_interface;
use crate::{
    error::GatewayError,
    proto::{gateway_service_client::GatewayServiceClient, update::Update, Configuration},
    wireguard::{setup_interface, wgapi::WGApi},
    Config,
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::sleep};
use tonic::{
    codegen::InterceptedService, metadata::MetadataValue, transport::Channel, Request, Status,
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
                    for peer in host.peers {
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

fn new_configuration(config: &Config, configuration: Configuration) -> Result<(), GatewayError> {
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

/// Connect to DefGuard GRPC endpoint, retrieve configuration and set up WireGuard interface.
/// Sends wireguard interface statistics periodically.
pub async fn run_gateway_client(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Connecting to DefGuard GRPC endpoint: {}", config.grpc_url);
    let channel = Channel::from_shared(config.grpc_url.to_owned())?.connect_lazy();

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

    let stats_period = Duration::from_secs(config.stats_period);

    let response = client.lock().await.config(Request::new(())).await?;
    new_configuration(config, response.into_inner())?;

    let mut updates_stream = loop {
        if let Ok(stream) = client.lock().await.updates(()).await {
            spawn_stats_thread(
                Arc::clone(&client),
                stats_period,
                config.ifname.clone(),
                config.userspace,
            );
            break stream.into_inner();
        } else {
            error!("Couldn't connect to server, retrying");
        }
        sleep(Duration::from_secs(1)).await;
    };

    let wgapi = WGApi::new(config.ifname.clone(), config.userspace);
    loop {
        match updates_stream.message().await {
            Ok(Some(update)) => match update.update {
                Some(Update::Network(configuration)) => new_configuration(config, configuration)?,
                Some(Update::Peer(peer_config)) => {
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
            Ok(None) => {
                if let Ok(response) = client.lock().await.updates(()).await {
                    // Server is back online, get new config stream...
                    updates_stream = response.into_inner();
                    // ...and restart stats stream
                    spawn_stats_thread(
                        Arc::clone(&client),
                        stats_period,
                        config.ifname.clone(),
                        config.userspace,
                    );
                    info!("Reconnection successful");
                }
                sleep(Duration::from_secs(1)).await;
            }
            Err(err) => {
                error!("Server connection lost, reconnecting: {}", err);
            }
        }
    }
}
