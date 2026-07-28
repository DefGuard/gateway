use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use defguard_certs::{CertificateError, CertificateInfo};
use defguard_grpc_tls::{certs::server_tls_config, server::certificate_serial_interceptor};
use defguard_version::{
    ComponentInfo, DefguardComponent, Version, get_tracing_variables, server::DefguardVersionLayer,
};
use tokio::{
    fs::remove_file,
    sync::{mpsc, oneshot},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status, Streaming, service::InterceptorLayer, transport::Server};
use tower::ServiceBuilder;
use tracing::instrument;

use crate::{
    CORE_CLIENT_CERT_NAME, GRPC_CA_CERT_NAME, GRPC_CERT_NAME, GRPC_KEY_NAME, VERSION,
    config::Config,
    error::GatewayError,
    execute_command,
    gateway::{Gateway, TlsConfig},
    proto::gateway::{CoreRequest, CoreResponse, core_request, core_response, gateway_server},
    version::is_core_version_supported,
};

pub(crate) struct GatewayServer {
    message_id: AtomicU64,
    gateway: Arc<Mutex<Gateway>>,
    cert_dir: PathBuf,
    reset_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<()>>>>,
}

impl GatewayServer {
    #[must_use]
    pub(crate) fn new(
        gateway: Arc<Mutex<Gateway>>,
        cert_dir: PathBuf,
        reset_tx: oneshot::Sender<()>,
    ) -> Self {
        Self {
            message_id: AtomicU64::new(0),
            gateway,
            cert_dir,
            reset_tx: Arc::new(tokio::sync::Mutex::new(Some(reset_tx))),
        }
    }

    /// Starts the gateway process.
    /// * Requires a valid mTLS configuration to be set (via `set_tls_config`) before starting;
    ///   returns an error if TLS configuration is absent - the gRPC server never starts in plain-text mode
    /// * Retrieves configuration and configuration updates from Defguard core via a mTLS-secured gRPC server
    /// * Manages the WireGuard interface according to configuration and updates
    /// * Sends interface statistics to Defguard core periodically
    pub(crate) async fn start(self, config: Config) -> Result<(), GatewayError> {
        info!("Starting Defguard Gateway version {VERSION} with configuration: {config:?}");

        if let Some(post_up) = &config.post_up {
            debug!("Executing specified POST_UP command: {post_up}");
            execute_command(post_up)?;
        }

        let tls_config = self
            .gateway
            .lock()
            .expect("gateway mutex poison")
            .tls_config
            .clone();

        // Build gRPC server.
        let addr = config.grpc_socket();
        info!("gRPC server is listening on {addr}");

        let tls = tls_config.ok_or_else(|| {
            GatewayError::SetupError(
                "TLS configuration is required; gateway gRPC server cannot start without mTLS"
                    .into(),
            )
        })?;

        let tls_config =
            server_tls_config(&tls.grpc_cert_pem, &tls.grpc_key_pem, &tls.grpc_ca_cert_pem)
                .map_err(|e| GatewayError::SetupError(e.to_string()))?;
        let mut builder = Server::builder().tls_config(tls_config)?;

        // Extract Core client cert serial for pinning.
        let expected_serial = CertificateInfo::from_der(&tls.core_client_cert_der)
            .map_err(|e: CertificateError| GatewayError::SetupError(e.to_string()))?
            .serial;

        // Start gRPC server. This should run indefinitely.
        debug!("Serving gRPC");
        builder
            .add_service(
                ServiceBuilder::new()
                    .layer(InterceptorLayer::new(certificate_serial_interceptor(
                        expected_serial,
                    )))
                    .layer(DefguardVersionLayer::new(Version::parse(VERSION)?))
                    .service(gateway_server::GatewayServer::new(self)),
            )
            .serve(addr)
            .await?;

        Ok(())
    }

    pub(crate) fn set_tls_config(&mut self, tls_config: TlsConfig) {
        if let Ok(mut gateway) = self.gateway.lock() {
            gateway.tls_config = Some(tls_config);
        }
    }
}

#[tonic::async_trait]
impl gateway_server::Gateway for GatewayServer {
    type BidiStream = UnboundedReceiverStream<Result<CoreRequest, Status>>;

    /// Handle bidirectional communication with Defguard Core.
    async fn bidi(
        &self,
        request: Request<Streaming<CoreResponse>>,
    ) -> Result<Response<Self::BidiStream>, Status> {
        let Some(address) = request.remote_addr() else {
            error!("Failed to determine Defguard Core's address for request: {request:?}");
            return Err(Status::internal(
                "Failed to determine Defguard Core's address",
            ));
        };
        info!("Defguard Core gRPC client connected from {address}");

        let core_info = ComponentInfo::from_metadata(request.metadata());
        let (version, info) = get_tracing_variables(&core_info);

        // Tracing span.
        let span = tracing::info_span!(
            "core_communication",
            component = %DefguardComponent::Core,
            version = version.to_string(),
            info
        );
        let _guard = span.enter();

        // Check Defguard Core's version and exit if it's not supported.
        let version = core_info.as_ref().map(|info| &info.version);
        if !is_core_version_supported(version) {
            return Err(Status::internal("Unsupported Defguard Core version"));
        }

        // Drop new connections if another Core has already been connected.
        if self
            .gateway
            .lock()
            .expect("Gateway lock poison")
            .client_tx
            .is_some()
        {
            error!("Only one client connection is allowed.");
            return Err(Status::internal("Client already connected"));
        }

        let (tx, rx) = mpsc::unbounded_channel();

        // First, send configuration request.
        let req = CoreRequest {
            id: self.message_id.fetch_add(1, Ordering::Relaxed),
            payload: Some(core_request::Payload::ConfigRequest(())),
        };

        match tx.send(Ok(req)) {
            Ok(()) => info!("Requesting network configuration from {address}"),
            Err(err) => {
                error!("Unable to send network configuration request to {address}: {err}");
                return Err(Status::internal("failed to send configuration request"));
            }
        }

        self.gateway.lock().expect("Gateway lock poison").client_tx = Some(tx);

        let gateway = Arc::clone(&self.gateway);
        let mut stream = request.into_inner();
        tokio::spawn(async move {
            loop {
                match stream.message().await {
                    Ok(Some(response)) => {
                        debug!("Received message from Defguard Core: {response:?}");
                        // Discard empty payloads.
                        if let Some(payload) = response.payload {
                            match payload {
                                core_response::Payload::Config(configuration) => {
                                    match gateway.lock() {
                                        Ok(mut gw) => {
                                            gw.connected.store(true, Ordering::Relaxed);
                                            if let Err(err) = gw.configure(configuration) {
                                                error!("Failed to configure: {err}");
                                            }
                                        }
                                        Err(err) => error!("Lock failed: {err}"),
                                    }
                                }
                                core_response::Payload::Update(update) => match gateway.lock() {
                                    Ok(mut gw) => {
                                        gw.handle_updates(update);
                                    }
                                    Err(err) => error!("Lock failed: {err}"),
                                },
                                core_response::Payload::Empty(()) => (),
                            }
                        }
                    }
                    Ok(None) => {
                        info!("gRPC stream from Defguard Core has been closed");
                        break;
                    }
                    Err(err) => {
                        error!("gRPC stream from Defguard Core failed with error: {err}");
                        break;
                    }
                }
            }
            info!("Defguard Core gRPC stream has been disconnected: {address}");
            if let Ok(mut gateway) = gateway.lock() {
                gateway.disconnect_cleanup();
            }
        });

        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }

    #[instrument(skip(self, _request))]
    async fn purge(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        debug!("Received purge request, removing gRPC certificate files");
        let cert_path = self.cert_dir.join(GRPC_CERT_NAME);
        let key_path = self.cert_dir.join(GRPC_KEY_NAME);
        let ca_cert_path = self.cert_dir.join(GRPC_CA_CERT_NAME);
        let core_client_cert_path = self.cert_dir.join(CORE_CLIENT_CERT_NAME);

        let remove_cert_file = async |path: &std::path::Path, label: &str| -> Result<(), Status> {
            match remove_file(path).await {
                Ok(()) => {
                    info!("Removed {label} at {}", path.display());
                    Ok(())
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    debug!("{label} not found at {}, skipping removal", path.display());
                    Ok(())
                }
                Err(err) => {
                    error!("Failed to remove {label} at {}: {err}", path.display());
                    Err(Status::internal(format!("Failed to remove {label}")))
                }
            }
        };

        remove_cert_file(&cert_path, "gRPC certificate").await?;
        remove_cert_file(&key_path, "gRPC key").await?;
        remove_cert_file(&ca_cert_path, "CA certificate").await?;
        remove_cert_file(&core_client_cert_path, "Core client certificate").await?;

        // Prepare underlying `Gateway` to enter setup mode.
        self.gateway
            .lock()
            .expect("Failed to lock GatewayServer::gateway")
            .purge();

        let Some(sender) = self.reset_tx.lock().await.take() else {
            error!("Reset channel sender not found");
            return Err(Status::internal("Failed to enter setup mode"));
        };

        if sender.send(()).is_err() {
            error!("Failed to notify setup handler");
            return Err(Status::internal("Failed to enter setup mode"));
        }

        info!("Removed gRPC certificate files; entering setup mode");
        Ok(Response::new(()))
    }
}
