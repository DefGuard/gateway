use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{Router, extract::Extension, http::StatusCode, routing::get, serve};
use tokio::net::TcpListener;

async fn healthcheck<'a>(
    Extension(connected): Extension<Arc<AtomicBool>>,
) -> (StatusCode, &'a str) {
    if connected.load(Ordering::Relaxed) {
        (StatusCode::OK, "alive")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Not connected to core")
    }
}

/// Launch HTTP server with the health check.
pub async fn run_http_server(
    http_port: u16,
    http_bind_address: Option<IpAddr>,
    connected: Arc<AtomicBool>,
) {
    let app = Router::new()
        .route("/health", get(healthcheck))
        .layer(Extension(connected));

    // run server
    let addr = SocketAddr::new(
        http_bind_address.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        http_port,
    );
    let listener = match TcpListener::bind(&addr).await {
        Ok(socket) => socket,
        Err(err) => {
            error!("Failed to bind to {addr}: {err}");
            return;
        }
    };
    info!("Health check listening on {addr}");

    // From axum docs: this future will never actually complete or return an error.
    let _ = serve(listener, app.into_make_service()).await;
}
