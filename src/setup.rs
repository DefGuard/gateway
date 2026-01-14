use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use defguard_version::{Version, server::DefguardVersionLayer};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, transport::Server};
use tower::ServiceBuilder;
use tracing::instrument;

use crate::{
    CommsChannel, VERSION,
    config::Config,
    error::GatewayError,
    gateway::TlsConfig,
    proto::gateway::{DerPayload, InitialSetupInfo, gateway_setup_server},
};

static SETUP_CHANNEL: LazyLock<CommsChannel<Option<TlsConfig>>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel(10);
    (
        Arc::new(tokio::sync::Mutex::new(tx)),
        Arc::new(tokio::sync::Mutex::new(rx)),
    )
});

pub struct GatewaySetupServer {
    key_pair: Arc<Mutex<Option<defguard_certs::RcGenKeyPair>>>,
    setup_in_progress: Arc<AtomicBool>,
}

impl Clone for GatewaySetupServer {
    fn clone(&self) -> Self {
        Self {
            key_pair: Arc::clone(&self.key_pair),
            setup_in_progress: Arc::clone(&self.setup_in_progress),
        }
    }
}

impl GatewaySetupServer {
    pub fn new() -> Self {
        Self {
            key_pair: Arc::new(Mutex::new(None)),
            setup_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub async fn await_setup(&self, config: Config) -> Result<TlsConfig, GatewayError> {
        let mut server_builder = Server::builder();
        let mut server_config = None;

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
                let config = SETUP_CHANNEL.1.lock().await.recv().await;
                if let Some(cfg) = config {
                    info!("Received Gateway setup configuration from Core");
                    server_config = cfg;
                } else {
                    error!("Setup communication channel closed unexpectedly");
                }
            })
            .await?;

        server_config.ok_or_else(|| {
            GatewayError::SetupError("Failed to receive setup configuration from Core".into())
        })
    }
}

#[tonic::async_trait]
impl gateway_setup_server::GatewaySetup for GatewaySetupServer {
    #[instrument(skip(self, request))]
    async fn start(
        &self,
        request: Request<InitialSetupInfo>,
    ) -> Result<Response<DerPayload>, Status> {
        if self.setup_in_progress.load(Ordering::SeqCst) {
            return Err(Status::already_exists("Setup is already in progress"));
        }

        self.setup_in_progress.store(true, Ordering::SeqCst);
        let initial_info = request.into_inner();

        let new_key_pair = match defguard_certs::generate_key_pair() {
            Ok(kp) => kp,
            Err(err) => {
                error!("Failed to generate key pair: {err}");
                self.setup_in_progress.store(false, Ordering::SeqCst);
                return Err(Status::internal(format!(
                    "Failed to generate key pair: {err}"
                )));
            }
        };

        let subject_alt_names = vec![initial_info.cert_hostname];

        let csr = match defguard_certs::Csr::new(
            &new_key_pair,
            &subject_alt_names,
            vec![
                (defguard_certs::DnType::CommonName, "Defguard Gateway"),
                (defguard_certs::DnType::OrganizationName, "Defguard"),
            ],
        ) {
            Ok(csr) => csr,
            Err(err) => {
                error!("Failed to generate CSR: {err}");
                self.setup_in_progress.store(false, Ordering::SeqCst);
                return Err(Status::internal(format!("Failed to generate CSR: {err}")));
            }
        };

        let response = DerPayload {
            der_data: csr.to_der().to_vec(),
        };

        {
            let mut key_pair_lock = self.key_pair.lock().expect("Failed to lock key_pair mutex");
            *key_pair_lock = Some(new_key_pair);
        }

        Ok(Response::new(response))
    }

    #[instrument(skip(self, request))]
    async fn send_cert(&self, request: Request<DerPayload>) -> Result<Response<()>, Status> {
        let der_payload = request.into_inner();

        let key_pair = {
            let key_pair = self
                .key_pair
                .lock()
                .expect("Failed to lock key_pair mutex")
                .take();
            if let Some(kp) = key_pair {
                kp
            } else {
                error!("Key pair not found. The setup session may not have been started properly.");
                self.setup_in_progress.store(false, Ordering::SeqCst);
                return Err(Status::internal(
                    "Key pair not found. The setup session may not have been started properly.",
                ));
            }
        };

        info!(
            "Received certificate of length: {}",
            der_payload.der_data.len()
        );

        let cert_pem = match defguard_certs::der_to_pem(
            &der_payload.der_data,
            defguard_certs::PemLabel::Certificate,
        ) {
            Ok(pem) => pem,
            Err(err) => {
                error!("Failed to convert certificate DER format to PEM: {err}");
                self.setup_in_progress.store(false, Ordering::SeqCst);
                return Err(Status::internal(format!(
                    "Failed to convert certificate DER format to PEM: {err}"
                )));
            }
        };

        let config = TlsConfig {
            grpc_key_pem: key_pair.serialize_pem(),
            grpc_cert_pem: cert_pem,
        };

        SETUP_CHANNEL
            .0
            .lock()
            .await
            .send(Some(config))
            .await
            .map_err(|err| {
                error!("Failed to send setup configuration through channel: {err}");
                Status::internal(format!(
                    "Failed to send setup configuration through channel: {err}"
                ))
            })?;

        self.setup_in_progress.store(false, Ordering::SeqCst);

        Ok(Response::new(()))
    }
}
