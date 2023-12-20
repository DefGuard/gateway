use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use axum::{extract::Extension, http::StatusCode, routing::get, Router};
use tokio::sync::Mutex;

use crate::{error::GatewayError, gateway::GatewayState};

async fn healthcheck(
    Extension(gateway_state): Extension<Arc<Mutex<GatewayState>>>,
) -> (axum::http::StatusCode, String) {
    let gateway = gateway_state.lock().await;
    if gateway.connected {
        (StatusCode::OK, "Alive".to_string())
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Not connected to core".to_string(),
        )
    }
}
pub async fn run_server(
    http_port: Option<u16>,
    gateway_state: Arc<Mutex<GatewayState>>,
) -> Result<(), GatewayError> {
    let app = Router::new()
        .route("/health", get(healthcheck))
        .layer(Extension(gateway_state));

    // run server
    if let Some(port) = http_port {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        info!("Health check listening on {addr}");
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .map_err(|err| GatewayError::HttpServer(err.to_string()))
    } else {
        Ok(())
    }
}
