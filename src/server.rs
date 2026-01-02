use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{Router, extract::Extension, http::StatusCode, routing::get, serve};
use tokio::net::TcpListener;

use crate::error::GatewayError;

async fn healthcheck<'a>(
    Extension(connected): Extension<Arc<AtomicBool>>,
) -> (StatusCode, &'a str) {
    if connected.load(Ordering::Relaxed) {
        (StatusCode::OK, "alive")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Not connected to core")
    }
}

pub async fn run_server(
    http_port: u16,
    http_bind_address: Option<IpAddr>,
    connected: Arc<AtomicBool>,
) -> Result<(), GatewayError> {
    let app = Router::new()
        .route("/health", get(healthcheck))
        .layer(Extension(connected));

    // run server
    let addr = SocketAddr::new(
        http_bind_address.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        http_port,
    );
    let listener = TcpListener::bind(&addr).await?;
    info!("Health check listening on {addr}");
    serve(listener, app.into_make_service())
        .await
        .map_err(|err| GatewayError::HttpServer(err.to_string()))
}
