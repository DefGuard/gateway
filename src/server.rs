use crate::{error::GatewayError, gateway::GatewayState};
use axum::{extract::Extension, http::StatusCode, routing::get, Router};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;

async fn healthcheck(
    Extension(gateway_state): Extension<Arc<Mutex<GatewayState>>>,
) -> (axum::http::StatusCode, String) {
    let gateway = gateway_state.lock().await;
    match gateway.connected {
        true => (StatusCode::OK, "Alive".to_string()),
        false => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Not connected to core".to_string(),
        ),
    }
}
pub async fn run_server(
    http_port: u16,
    gateway_state: Arc<Mutex<GatewayState>>,
) -> Result<(), GatewayError> {
    let app = Router::new()
        .route("/health", get(healthcheck))
        .layer(Extension(gateway_state));

    // run server
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), http_port);
    info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .map_err(|err| GatewayError::HttpServer(err.to_string()))
}
