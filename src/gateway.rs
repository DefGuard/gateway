tonic::include_proto!("gateway");

use crate::{
    utils::parse_wg_stats,
    wireguard::{delete_interface, interface_stats, setup_interface},
    Config,
};
use futures::Future;
use gateway_service_client::GatewayServiceClient;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::delay_for};
use tonic::transport::Channel;
use tonic::{Request, Status};

/// Creates an async stream that periodically yields wireguard interface statistics.
fn stats_stream(
    period: Duration,
) -> async_stream::AsyncStream<PeerStats, impl Future<Output = ()>> {
    async_stream::stream! {
        loop {
            let stats = interface_stats("defguard");
            match stats {
                Ok(stats) => {
                    for s in parse_wg_stats(&stats) {
                        yield s;
                    }
                },
                Err(err) => log::error!("Failed to retrieve wireguard interface stats {}", err),
            }
            delay_for(period).await;
        }
    }
}

/// Connects to DefGuard GRPC endpoint, retrieves configuration and sets up wireguard interface.
/// Reconfigures the interface whenever new configuration is sent via grpc stream.
/// Sends wireguard interface statistics periodically.
pub async fn run_gateway_client(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!("Connecting to DefGuard GRPC endpoint: {}", config.grpc_url);
    let channel = Channel::from_shared(config.grpc_url.to_owned())?
        .connect()
        .await?;
    let token = config.token.clone();

    let jwt_auth_interceptor = move |mut req: Request<()>| -> Result<Request<()>, Status> {
        req.metadata_mut().insert(
            "authorization",
            token
                .parse()
                .map_err(|_| Status::unknown("Token parsing error"))?,
        );
        Ok(req)
    };

    let client = Arc::new(Mutex::new(GatewayServiceClient::with_interceptor(
        channel,
        jwt_auth_interceptor,
    )));
    let moved_client = Arc::clone(&client);
    let stats_period = config.stats_period;
    tokio::spawn(async move {
        let mut client = moved_client.lock().await;
        let _r = client
            .stats(tonic::Request::new(stats_stream(Duration::from_secs(
                stats_period,
            ))))
            .await;
    });
    let mut config_stream = client.lock().await.config(()).await?.into_inner();
    while let Some(configuration) = config_stream.message().await? {
        log::debug!(
            "Received configuration, reconfiguring wireguard interface: {:?}",
            configuration
        );
        let _r = delete_interface("defguard");
        setup_interface("defguard", config.userspace, &configuration)?;
        log::info!("Reconfigured wireguard interface: {:?}", configuration);
    }

    Ok(())
}
