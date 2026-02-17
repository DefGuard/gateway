use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use defguard_version::{Version, server::DefguardVersionLayer};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status, transport::Server};
use tower::ServiceBuilder;
use tracing::instrument;

use crate::{
    GRPC_CERT_NAME, GRPC_KEY_NAME, VERSION,
    config::Config,
    error::GatewayError,
    gateway::TlsConfig,
    proto::gateway::{CertificateInfo, DerPayload, LogEntry, gateway_setup_server},
};

const AUTH_HEADER: &str = "authorization";
type LogsReceiver = Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>;

pub async fn run_setup(
    config: &Config,
    cert_dir: &std::path::Path,
    logs_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>,
) -> Result<TlsConfig, GatewayError> {
    let setup_server = GatewaySetupServer::new(logs_rx);
    let tls_config = setup_server.await_setup(config.clone()).await?;

    let cert_path = cert_dir.join(GRPC_CERT_NAME);
    let key_path = cert_dir.join(GRPC_KEY_NAME);
    tokio::fs::write(cert_path, &tls_config.grpc_cert_pem).await?;
    tokio::fs::write(key_path, &tls_config.grpc_key_pem).await?;
    log::info!(
        "Generated gRPC TLS certificates have been saved to {}",
        cert_dir.display()
    );

    Ok(tls_config)
}

pub struct GatewaySetupServer {
    key_pair: Arc<Mutex<Option<defguard_certs::RcGenKeyPair>>>,
    logs_rx: LogsReceiver,
    current_session_token: Arc<Mutex<Option<String>>>,
    setup_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<TlsConfig>>>>,
    setup_rx: Arc<tokio::sync::Mutex<oneshot::Receiver<TlsConfig>>>,
}

impl Clone for GatewaySetupServer {
    fn clone(&self) -> Self {
        Self {
            key_pair: Arc::clone(&self.key_pair),
            logs_rx: Arc::clone(&self.logs_rx),
            current_session_token: Arc::clone(&self.current_session_token),
            setup_tx: Arc::clone(&self.setup_tx),
            setup_rx: Arc::clone(&self.setup_rx),
        }
    }
}

impl GatewaySetupServer {
    #[must_use]
    pub fn new(logs_rx: LogsReceiver) -> Self {
        let (setup_tx, setup_rx) = oneshot::channel();
        Self {
            key_pair: Arc::new(Mutex::new(None)),
            logs_rx,
            current_session_token: Arc::new(Mutex::new(None)),
            setup_tx: Arc::new(tokio::sync::Mutex::new(Some(setup_tx))),
            setup_rx: Arc::new(tokio::sync::Mutex::new(setup_rx)),
        }
    }

    pub async fn await_setup(&self, config: Config) -> Result<TlsConfig, GatewayError> {
        let mut server_builder = Server::builder();
        let mut server_config = None;
        let setup_rx = Arc::clone(&self.setup_rx);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.grpc_port);

        info!("Starting Gateway setup server on {addr} and awaiting configuration from Core");

        server_builder
            .add_service(
                ServiceBuilder::new()
                    // .layer(InterceptorLayer::new(CoreVersionInterceptor::new(
                    //     MIN_CORE_VERSION,
                    //     incompatible_components,
                    // )))
                    .layer(DefguardVersionLayer::new(Version::parse(VERSION)?))
                    .service(gateway_setup_server::GatewaySetupServer::new(self.clone())),
            )
            .serve_with_shutdown(addr, async {
                let mut rx_guard = setup_rx.lock().await;
                match (&mut *rx_guard).await {
                    Ok(cfg) => {
                        info!("Received Gateway setup configuration from Core");
                        server_config = Some(cfg);
                    }
                    Err(err) => {
                        error!("Setup communication channel closed unexpectedly: {err}");
                    }
                }
            })
            .await?;

        server_config.ok_or_else(|| {
            GatewayError::SetupError("Failed to receive setup configuration from Core".into())
        })
    }

    fn is_setup_in_progress(&self) -> bool {
        let in_progress = self
            .current_session_token
            .lock()
            .expect("Failed to acquire lock on current session token during gateway setup")
            .is_some();
        debug!("Setup in progress check: {in_progress}");
        in_progress
    }

    fn clear_setup_session(&self) {
        debug!("Terminating setup session");
        self.current_session_token
            .lock()
            .expect("Failed to acquire lock on current session token during gateway setup")
            .take();
        debug!("Setup session terminated");
    }

    fn initialize_setup_session(&self, token: String) {
        debug!("Establishing new setup session with Core");
        self.current_session_token
            .lock()
            .expect("Failed to acquire lock on current session token during gateway setup")
            .replace(token);
        debug!("Setup session established");
    }

    fn verify_session_token(&self, token: &str) -> bool {
        debug!("Validating setup session authorization");
        let is_valid = (*self
            .current_session_token
            .lock()
            .expect("Failed to acquire lock on current session token during gateway setup"))
        .as_ref()
        .is_some_and(|t| t == token);
        debug!("Authorization validation result: {is_valid}");
        is_valid
    }
}

#[tonic::async_trait]
impl gateway_setup_server::GatewaySetup for GatewaySetupServer {
    type StartStream = UnboundedReceiverStream<Result<LogEntry, Status>>;

    #[instrument(skip(self, request))]
    async fn start(&self, request: Request<()>) -> Result<Response<Self::StartStream>, Status> {
        debug!("Core initiated setup process, preparing to stream logs");
        if self.is_setup_in_progress() {
            error!("Setup already in progress, rejecting new setup request");
            return Err(Status::resource_exhausted("Setup already in progress"));
        }

        debug!("Authenticating setup session with Core");
        let token = request
            .metadata()
            .get(AUTH_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization token"))?;

        debug!("Setup session authenticated successfully");
        self.initialize_setup_session(token.to_string());

        debug!("Preparing to forward Gateway logs to Core in real-time");
        let logs_rx = self.logs_rx.clone();

        let (tx, rx) = mpsc::unbounded_channel();
        let self_clone = self.clone();

        debug!("Starting log streaming to Core");
        tokio::spawn(async move {
            loop {
                let maybe_log_entry = logs_rx.lock().await.try_recv();
                match maybe_log_entry {
                    Ok(log_entry) => {
                        if tx.send(Ok(log_entry)).is_err() {
                            debug!(
                                "Failed to send log entry to gRPC stream: receiver disconnected"
                            );
                            break;
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                        if tx.is_closed() {
                            debug!("gRPC stream receiver disconnected");
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        debug!("Logs receiver disconnected");
                        break;
                    }
                }
            }
            self_clone.clear_setup_session();
        });

        debug!("Log stream established, Core will now receive real-time Gateway logs");
        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }

    #[instrument(skip(self, request))]
    async fn get_csr(
        &self,
        request: Request<CertificateInfo>,
    ) -> Result<Response<DerPayload>, Status> {
        debug!("Core requested Certificate Signing Request (CSR) generation");
        let token = request
            .metadata()
            .get(AUTH_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization token"))?;

        debug!("Validating Core's authorization for this setup step");
        if !self.verify_session_token(token) {
            error!("Invalid session token in get_csr request");
            return Err(Status::unauthenticated("Invalid session token"));
        }

        let setup_info = request.into_inner();
        debug!(
            "Will generate certificate for hostname: {}",
            setup_info.cert_hostname
        );

        debug!("Generating key pair");
        let key_pair = match defguard_certs::generate_key_pair() {
            Ok(kp) => kp,
            Err(err) => {
                error!("Failed to generate key pair: {err}");
                self.clear_setup_session();
                return Err(Status::internal("Failed to generate key pair"));
            }
        };
        debug!("Key pair created");

        let subject_alt_names = vec![setup_info.cert_hostname];
        debug!("Preparing Certificate Signing Request for hostname: {subject_alt_names:?}",);

        let csr = match defguard_certs::Csr::new(
            &key_pair,
            &subject_alt_names,
            vec![
                // TODO: Change it?
                (defguard_certs::DnType::CommonName, "Defguard Gateway"),
                (defguard_certs::DnType::OrganizationName, "Defguard"),
            ],
        ) {
            Ok(csr) => csr,
            Err(err) => {
                error!("Failed to generate CSR: {err}");
                self.clear_setup_session();
                return Err(Status::internal(format!("Failed to generate CSR: {err}")));
            }
        };
        debug!("Certificate Signing Request prepared");

        self.key_pair
            .lock()
            .expect("Failed to acquire lock on key pair during gateway setup when trying to store generated key pair")
            .replace(key_pair);

        debug!("Encoding Certificate Signing Request for transmission");
        let csr_der = csr.to_der();
        let csr_request = DerPayload {
            der_data: csr_der.to_vec(),
        };
        debug!(
            "Sending Certificate Signing Request to Core for signing ({} bytes)",
            csr_request.der_data.len()
        );

        Ok(Response::new(csr_request))
    }

    #[instrument(skip(self, request))]
    async fn send_cert(&self, request: Request<DerPayload>) -> Result<Response<()>, Status> {
        debug!("Core sending back signed certificate for installation");
        let token = request
            .metadata()
            .get(AUTH_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization token"))?;

        debug!("Validating Core's authorization to complete setup");
        if !self.verify_session_token(token) {
            error!("Invalid session token in send_cert request");
            return Err(Status::unauthenticated("Invalid session token"));
        }

        let der_payload = request.into_inner();
        let cert_der = der_payload.der_data;
        debug!(
            "Received signed certificate from Core ({} bytes)",
            cert_der.len()
        );

        debug!("Parsing received certificate DER data");
        let grpc_cert_pem =
            match defguard_certs::der_to_pem(&cert_der, defguard_certs::PemLabel::Certificate) {
                Ok(pem) => pem,
                Err(err) => {
                    error!("Failed to convert certificate DER to PEM: {err}");
                    self.clear_setup_session();
                    return Err(Status::internal(format!(
                        "Failed to convert certificate DER to PEM: {err}"
                    )));
                }
            };
        debug!("Certificate processed successfully");

        let key_pair = {
            let key_pair = self
                .key_pair
                .lock()
                .expect("Failed to acquire lock on key pair during gateway setup when trying to receive certificate")
                .take();
            if let Some(kp) = key_pair {
                kp
            } else {
                error!(
                    "Key pair not found during Gateway setup. Key pair generation step might have failed."
                );
                self.clear_setup_session();
                return Err(Status::internal(
                    "Key pair not found during Gateway setup. Key pair generation step might have failed.",
                ));
            }
        };

        let configuration = TlsConfig {
            grpc_key_pem: key_pair.serialize_pem(),
            grpc_cert_pem,
        };

        let Some(sender) = self.setup_tx.lock().await.take() else {
            error!("Setup channel sender not found");
            return Err(Status::internal("Setup channel sender not found"));
        };

        sender.send(configuration).map_err(|_| {
            error!("Failed to send setup configuration through channel");
            Status::internal("Failed to send setup configuration through channel")
        })?;

        debug!("Setup process completed successfully, cleaning up temporary session");
        self.clear_setup_session();

        debug!("Confirming successful setup to Core");
        Ok(Response::new(()))
    }
}
