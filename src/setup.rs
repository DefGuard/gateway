use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use defguard_version::{Version, server::DefguardVersionLayer};
use rustls_pki_types::{CertificateDer, UnixTime};
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status, transport::Server};
use tower::ServiceBuilder;
use tracing::instrument;
use webpki::{KeyUsage, anchor_from_trusted_cert};

use crate::{
    CORE_CLIENT_CERT_NAME, GRPC_CA_CERT_NAME, GRPC_CERT_NAME, GRPC_KEY_NAME, VERSION,
    config::Config,
    error::GatewayError,
    gateway::TlsConfig,
    proto::{
        common::{CertBundle, CertificateInfo, DerPayload, LogEntry},
        gateway::gateway_setup_server,
    },
};

const AUTH_HEADER: &str = "authorization";
type LogsReceiver = Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>;

/// Verify that both `component_der` and `core_client_der` are signed by `ca_der`.
///
/// Uses ECDSA P-256 / SHA-256 via ring (FreeBSD-compatible). Returns an error
/// message string on any failure so the caller can forward it as a gRPC status.
fn validate_cert_bundle(
    ca_der: &[u8],
    component_der: &[u8],
    core_client_der: &[u8],
) -> Result<(), String> {
    let sig_algs: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P256_SHA384,
    ];

    let ca_cert_der = CertificateDer::from(ca_der);
    let trust_anchor = anchor_from_trusted_cert(&ca_cert_der)
        .map_err(|e| format!("Failed to parse CA certificate as trust anchor: {e}"))?;
    let trust_anchors = [trust_anchor];

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let time = UnixTime::since_unix_epoch(now);

    // Verify component (server) certificate.
    let component_cert_der = CertificateDer::from(component_der);
    let component_ee = webpki::EndEntityCert::try_from(&component_cert_der)
        .map_err(|e| format!("Failed to parse component certificate: {e}"))?;
    component_ee
        .verify_for_usage(
            sig_algs,
            &trust_anchors,
            &[],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| format!("Component certificate failed chain validation: {e}"))?;

    // Verify Core client certificate.
    let core_client_cert_der = CertificateDer::from(core_client_der);
    let core_client_ee = webpki::EndEntityCert::try_from(&core_client_cert_der)
        .map_err(|e| format!("Failed to parse Core client certificate: {e}"))?;
    core_client_ee
        .verify_for_usage(
            sig_algs,
            &trust_anchors,
            &[],
            time,
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|e| format!("Core client certificate failed chain validation: {e}"))?;

    Ok(())
}

pub async fn run_setup(
    config: &Config,
    logs_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>,
) -> Result<TlsConfig, GatewayError> {
    let cert_dir = &config.cert_dir;
    let setup_server = GatewaySetupServer::new(logs_rx);
    let tls_config = setup_server.await_setup(config).await?;

    let cert_path = cert_dir.join(GRPC_CERT_NAME);
    let key_path = cert_dir.join(GRPC_KEY_NAME);
    // Certificate and its key will be accessed only to this process's user.
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600); // rw-------
    // Write certificate to a file.
    options
        .clone()
        .open(cert_path)
        .await?
        .write_all(tls_config.grpc_cert_pem.as_bytes())
        .await?;
    // Write key to a file.
    options
        .clone()
        .open(key_path)
        .await?
        .write_all(tls_config.grpc_key_pem.as_bytes())
        .await?;
    // Write CA certificate to a file.
    options
        .clone()
        .open(cert_dir.join(GRPC_CA_CERT_NAME))
        .await?
        .write_all(tls_config.grpc_ca_cert_pem.as_bytes())
        .await?;
    // Write Core client certificate (PEM-encoded) to a file for serial pinning on restart.
    let core_client_cert_pem = defguard_certs::der_to_pem(
        &tls_config.core_client_cert_der,
        defguard_certs::PemLabel::Certificate,
    )
    .map_err(|err| {
        GatewayError::SetupError(format!(
            "Failed to PEM-encode Core client certificate: {err}"
        ))
    })?;
    options
        .open(cert_dir.join(CORE_CLIENT_CERT_NAME))
        .await?
        .write_all(core_client_cert_pem.as_bytes())
        .await?;
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

    pub async fn await_setup(&self, config: &Config) -> Result<TlsConfig, GatewayError> {
        let mut server_builder = Server::builder();
        let mut server_config = None;
        let setup_rx = Arc::clone(&self.setup_rx);

        let addr = config.grpc_socket();
        info!("Starting Gateway setup server on {addr} and awaiting configuration from Core");

        server_builder
            .add_service(
                ServiceBuilder::new()
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

        let subject_alt_names = [setup_info.cert_hostname];
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
            .expect(
                "Failed to acquire lock on key pair during gateway setup when trying to store \
                generated key pair",
            )
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
    async fn send_cert(&self, request: Request<CertBundle>) -> Result<Response<()>, Status> {
        debug!("Core sending back signed certificate bundle for installation");
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

        let bundle = request.into_inner();

        debug!("Validating certificate bundle received from Core");
        if let Err(reason) = validate_cert_bundle(
            &bundle.ca_cert_der,
            &bundle.component_cert_der,
            &bundle.core_client_cert_der,
        ) {
            error!("Certificate bundle validation failed: {reason}");
            self.clear_setup_session();
            return Err(Status::invalid_argument(reason));
        }
        debug!("Certificate bundle validated successfully against CA");

        debug!(
            "Received component certificate from Core ({} bytes)",
            bundle.component_cert_der.len()
        );
        debug!("Parsing component certificate DER data");
        let grpc_cert_pem = match defguard_certs::der_to_pem(
            &bundle.component_cert_der,
            defguard_certs::PemLabel::Certificate,
        ) {
            Ok(pem) => pem,
            Err(err) => {
                let msg = format!("Failed to convert component certificate DER to PEM: {err}");
                error!("{msg}");
                self.clear_setup_session();
                return Err(Status::internal(msg));
            }
        };

        debug!(
            "Received CA certificate from Core ({} bytes)",
            bundle.ca_cert_der.len()
        );
        debug!("Parsing CA certificate DER data");
        let grpc_ca_cert_pem = match defguard_certs::der_to_pem(
            &bundle.ca_cert_der,
            defguard_certs::PemLabel::Certificate,
        ) {
            Ok(pem) => pem,
            Err(err) => {
                let msg = format!("Failed to convert CA certificate DER to PEM: {err}");
                error!("{msg}");
                self.clear_setup_session();
                return Err(Status::internal(msg));
            }
        };

        debug!(
            "Received Core client certificate ({} bytes); will pin serial for mTLS",
            bundle.core_client_cert_der.len()
        );

        let key_pair = {
            let key_pair = self
                .key_pair
                .lock()
                .expect(
                    "Failed to acquire lock on key pair during gateway setup when trying to \
                    receive certificate",
                )
                .take();
            if let Some(kp) = key_pair {
                kp
            } else {
                let msg = "Key pair not found during Gateway setup. Key pair generation step might \
                    have failed.";
                error!("{msg}");
                self.clear_setup_session();
                return Err(Status::internal(msg));
            }
        };

        let configuration = TlsConfig {
            grpc_key_pem: key_pair.serialize_pem(),
            grpc_cert_pem,
            grpc_ca_cert_pem,
            core_client_cert_der: bundle.core_client_cert_der,
        };

        let Some(sender) = self.setup_tx.lock().await.take() else {
            error!("Setup channel sender not found");
            return Err(Status::internal("Setup channel sender not found"));
        };

        sender.send(configuration).map_err(|_| {
            let msg = "Failed to send setup configuration through channel";
            error!("{msg}");
            Status::internal(msg)
        })?;

        debug!("Setup process completed successfully, cleaning up temporary session");
        self.clear_setup_session();

        debug!("Confirming successful setup to Core");
        Ok(Response::new(()))
    }
}
