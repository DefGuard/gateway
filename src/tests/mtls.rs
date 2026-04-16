use std::{
    env::temp_dir,
    net::TcpListener,
    sync::{Arc, Mutex},
    time::Duration,
};

use defguard_certs::{
    CertificateAuthority, Csr, PemLabel, cert_der_to_pem, der_to_pem, generate_key_pair,
};
use rustls::crypto::ring;
use tokio::{select, spawn, sync::oneshot, time::sleep};
use tokio_stream::iter as stream_iter;
use tonic::{
    Code, Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

use super::mock_wgapi::NullWgApi;
use crate::{
    config::Config,
    gateway::{Gateway, GatewayServer, TlsConfig},
    proto::gateway::CoreResponse,
    proto::gateway::gateway_client::GatewayClient,
};

struct TestCerts {
    ca_cert_pem: String,
    gateway_cert_pem: String,
    gateway_key_pem: String,
    core_client_cert_der: Vec<u8>,
    core_client_cert_pem: String,
    core_client_key_pem: String,
    wrong_serial_cert_pem: String,
    wrong_serial_key_pem: String,
    rogue_client_cert_pem: String,
    rogue_client_key_pem: String,
}

impl TestCerts {
    fn generate() -> Self {
        let ca = CertificateAuthority::new("Test CA", "test@test.local", 365).unwrap();
        let ca_cert_pem = ca.cert_pem().unwrap();

        // Gateway server cert: ServerAuth EKU, IP SAN 127.0.0.1
        let gw_key = generate_key_pair().unwrap();
        let gw_csr = Csr::new(&gw_key, &["127.0.0.1".to_string()], vec![]).unwrap();
        let gw_server_cert = ca.sign_server_cert(&gw_csr).unwrap();
        let gateway_cert_pem = cert_der_to_pem(gw_server_cert.der()).unwrap();
        let gateway_key_pem = der_to_pem(gw_key.serialized_der(), PemLabel::PrivateKey).unwrap();

        // Core client cert A — pinned serial
        let client_a = ca.issue_core_client_cert("core-client-a").unwrap();
        let core_client_cert_der = client_a.cert_der.clone();
        let core_client_cert_pem = cert_der_to_pem(&client_a.cert_der).unwrap();
        let core_client_key_pem = der_to_pem(&client_a.key_der, PemLabel::PrivateKey).unwrap();

        // Core client cert B — different serial, same CA
        let client_b = ca.issue_core_client_cert("core-client-b").unwrap();
        let wrong_serial_cert_pem = cert_der_to_pem(&client_b.cert_der).unwrap();
        let wrong_serial_key_pem = der_to_pem(&client_b.key_der, PemLabel::PrivateKey).unwrap();

        // Rogue CA + client cert
        let rogue_ca = CertificateAuthority::new("Rogue CA", "rogue@rogue.local", 365).unwrap();
        let rogue_client = rogue_ca.issue_core_client_cert("rogue-core").unwrap();
        let rogue_client_cert_pem = cert_der_to_pem(&rogue_client.cert_der).unwrap();
        let rogue_client_key_pem = der_to_pem(&rogue_client.key_der, PemLabel::PrivateKey).unwrap();

        Self {
            ca_cert_pem,
            gateway_cert_pem,
            gateway_key_pem,
            core_client_cert_der,
            core_client_cert_pem,
            core_client_key_pem,
            wrong_serial_cert_pem,
            wrong_serial_key_pem,
            rogue_client_cert_pem,
            rogue_client_key_pem,
        }
    }
}

fn make_tls_config(certs: &TestCerts) -> TlsConfig {
    TlsConfig {
        grpc_key_pem: certs.gateway_key_pem.clone(),
        grpc_cert_pem: certs.gateway_cert_pem.clone(),
        grpc_ca_cert_pem: certs.ca_cert_pem.clone(),
        core_client_cert_der: certs.core_client_cert_der.clone(),
    }
}

fn build_gateway(config: &Config) -> Gateway {
    Gateway::new(config.clone(), NullWgApi).unwrap()
}

/// Install the rustls AWS-LC crypto provider for the process.
///
/// Must be called before any TLS code runs. Safe to call from multiple tests —
/// subsequent calls after the first are silently ignored.
fn init_crypto() {
    let _ = ring::default_provider().install_default();
}

/// Spawn a configured `GatewayServer` on a free port.
/// Returns `(bound_port, shutdown_tx)`.
async fn spawn_test_gateway(certs: &TestCerts) -> (u16, oneshot::Sender<()>) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let mut config = Config::default();
    config.grpc_port = port;

    let gateway = build_gateway(&config);
    let gateway = Arc::new(Mutex::new(gateway));

    let (reset_tx, _reset_rx) = oneshot::channel();
    let mut server = GatewayServer::new(Arc::clone(&gateway), temp_dir(), reset_tx);
    server.set_tls_config(make_tls_config(certs));

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    spawn(async move {
        select! {
            _ = server.start(config) => {}
            _ = shutdown_rx => {}
        }
    });

    sleep(Duration::from_millis(150)).await;

    (port, shutdown_tx)
}

/// Build a tonic `GatewayClient` with optional mTLS client identity.
async fn connect(
    port: u16,
    ca_cert_pem: &str,
    client_identity: Option<(&str, &str)>,
) -> Result<GatewayClient<Channel>, tonic::transport::Error> {
    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_cert_pem));

    if let Some((cert_pem, key_pem)) = client_identity {
        tls = tls.identity(Identity::from_pem(cert_pem, key_pem));
    }

    let channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .tls_config(tls)?
        .connect()
        .await?;

    Ok(GatewayClient::new(channel))
}

/// Open a `bidi` streaming call with an empty request stream and return the status.
///
/// The stream body is irrelevant — we only care whether the mTLS + serial-pin
/// interceptors accept or reject the connection.
async fn call_bidi(client: &mut GatewayClient<Channel>) -> tonic::Status {
    let empty: Vec<CoreResponse> = vec![];
    match client.bidi(Request::new(stream_iter(empty))).await {
        Ok(_) => tonic::Status::ok("accepted"),
        Err(status) => status,
    }
}

/// `start()` must return `Err` immediately when no `TlsConfig` has been set.
#[tokio::test]
async fn start_errors_without_tls_config() {
    let config = Config::default();
    let gateway = build_gateway(&config);
    let gateway = Arc::new(Mutex::new(gateway));
    let (reset_tx, _) = oneshot::channel();
    let server = GatewayServer::new(Arc::clone(&gateway), temp_dir(), reset_tx);
    // TLS config intentionally not set.
    let result = server.start(config).await;
    assert!(result.is_err(), "expected Err, got Ok");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("TLS configuration is required"),
        "unexpected error message",
    );
}

/// A client presenting the correct CA-signed cert with the expected serial must be accepted.
///
/// The `bidi` call may be rejected by the version interceptor (no version headers are sent),
/// but it must NOT be rejected with `Unauthenticated` — that would indicate the mTLS layer
/// or serial-pin interceptor wrongly rejected the cert.
#[tokio::test]
async fn valid_mtls_client_accepted() {
    init_crypto();
    let certs = TestCerts::generate();
    let (port, shutdown_tx) = spawn_test_gateway(&certs).await;

    let mut client = connect(
        port,
        &certs.ca_cert_pem,
        Some((&certs.core_client_cert_pem, &certs.core_client_key_pem)),
    )
    .await
    .expect("TLS handshake should succeed with valid client cert");

    let status = call_bidi(&mut client).await;

    assert_ne!(
        status.code(),
        Code::Unauthenticated,
        "valid client cert should not be rejected; got: {status}",
    );

    let _ = shutdown_tx.send(());
}

/// A client that presents no certificate must be rejected at the TLS layer.
#[tokio::test]
async fn no_client_cert_rejected() {
    init_crypto();
    let certs = TestCerts::generate();
    let (port, shutdown_tx) = spawn_test_gateway(&certs).await;

    // connect() is lazy in tonic — the TLS handshake happens on the first RPC.
    let Ok(mut client) = connect(port, &certs.ca_cert_pem, None).await else {
        let _ = shutdown_tx.send(());
        return;
    };

    let empty: Vec<CoreResponse> = vec![];
    let result = client.bidi(Request::new(stream_iter(empty))).await;

    assert!(
        result.is_err(),
        "connecting without a client cert should be rejected",
    );

    let _ = shutdown_tx.send(());
}

/// A client presenting a cert from the correct CA but with the wrong serial must be rejected
/// by the serial-pin interceptor with `Unauthenticated`.
#[tokio::test]
async fn wrong_serial_rejected() {
    init_crypto();
    let certs = TestCerts::generate();
    let (port, shutdown_tx) = spawn_test_gateway(&certs).await;

    // This cert is valid (signed by the CA the server trusts) but has a different serial.
    let mut client = connect(
        port,
        &certs.ca_cert_pem,
        Some((&certs.wrong_serial_cert_pem, &certs.wrong_serial_key_pem)),
    )
    .await
    .expect("TLS handshake should succeed; the serial check runs as a gRPC interceptor");

    let status = call_bidi(&mut client).await;

    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "wrong-serial cert must be rejected with Unauthenticated; got: {status}",
    );

    let _ = shutdown_tx.send(());
}

/// A client presenting a cert signed by a rogue CA must be rejected at the TLS layer
/// because the server does not trust that CA.
#[tokio::test]
async fn rogue_ca_client_rejected() {
    init_crypto();
    let certs = TestCerts::generate();
    let (port, shutdown_tx) = spawn_test_gateway(&certs).await;

    // connect() is lazy in tonic — the TLS handshake happens on the first RPC.
    let Ok(mut client) = connect(
        port,
        &certs.ca_cert_pem,
        Some((&certs.rogue_client_cert_pem, &certs.rogue_client_key_pem)),
    )
    .await
    else {
        let _ = shutdown_tx.send(());
        return;
    };

    let empty: Vec<CoreResponse> = vec![];
    let result = client.bidi(Request::new(stream_iter(empty))).await;

    assert!(
        result.is_err(),
        "rogue-CA client cert must be rejected; got Ok",
    );
    // Must NOT be FailedPrecondition — that would mean the cert was accepted by the
    // TLS layer and reached the gRPC handler.
    if let Err(ref status) = result {
        assert_ne!(
            status.code(),
            Code::FailedPrecondition,
            "rogue-CA cert reached the gRPC handler — server-side CA verification is missing; \
             got: {status}",
        );
    }

    let _ = shutdown_tx.send(());
}
