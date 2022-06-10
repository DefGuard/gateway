tonic::include_proto!("gateway");

use crate::{
    utils::parse_wg_stats,
    wireguard::{delete_interface, interface_stats, setup_interface},
    Config,
};
use gateway_service_client::GatewayServiceClient;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::sleep};
use tonic::{
    codegen::InterceptedService, metadata::MetadataValue, transport::Channel, Request, Status,
};

/// Starts tokio thread collecting stats and sending them to backend service via GRPC
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
    if_name: String,
) {
    // Create an async stream that periodically yields wireguard interface statistics.
    let stats_stream = async_stream::stream! {
        loop {
            let stats = interface_stats(&if_name);
            match stats {
                Ok(stats) => {
                    for s in parse_wg_stats(&stats) {
                        yield s;
                    }
                },
                Err(err) => error!("Failed to retrieve wireguard interface stats {}", err),
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

/// Connects to DefGuard GRPC endpoint, retrieves configuration and sets up wireguard interface.
/// Reconfigures the interface whenever new configuration is sent via grpc stream.
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
    let mut config_stream = loop {
        if let Ok(stream) = client.lock().await.config(()).await {
            spawn_stats_thread(Arc::clone(&client), stats_period, config.if_name.clone());
            break stream.into_inner();
        } else {
            error!("Couldn't connect to server, retrying");
        }
        sleep(Duration::from_secs(1)).await;
    };
    loop {
        match config_stream.message().await {
            Ok(Some(configuration)) => {
                debug!(
                    "Received configuration, reconfiguring wireguard interface: {:?}",
                    configuration
                );
                if !config.userspace {
                    let _ = delete_interface(&config.if_name);
                }
                setup_interface(&config.if_name, config.userspace, &configuration)?;
                info!("Reconfigured wireguard interface: {:?}", configuration);
            }
            Ok(None) => {
                if let Ok(config_response) = client.lock().await.config(()).await {
                    // Server is back online, get new config stream...
                    config_stream = config_response.into_inner();
                    // ...and restart stats stream
                    spawn_stats_thread(Arc::clone(&client), stats_period, config.if_name.clone());
                    info!("Reconnect successful");
                }
                sleep(Duration::from_secs(1)).await;
            }
            Err(err) => {
                error!("Server connection lost, reconnecting: {}", err);
            }
        }
    }
}
