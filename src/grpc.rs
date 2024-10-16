use std::{
    collections::HashMap,
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use gethostname::gethostname;
use tokio::{
    sync::mpsc,
    task::{spawn, JoinHandle, JoinSet},
    time::{interval, sleep},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{
    codegen::InterceptedService,
    metadata::{Ascii, MetadataValue},
    service::Interceptor,
    transport::{
        Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
    },
    Request, Response, Status, Streaming,
};

use crate::{
    config::Config,
    error::GatewayError,
    execute_command, mask,
    proto::{core_request, core_response, gateway_server, CoreRequest, CoreResponse, Peer, Update},
    VERSION,
};

// connected clients
type ClientMap = HashMap<SocketAddr, mpsc::UnboundedSender<Result<CoreRequest, Status>>>;

pub struct GatewayServer {
    clients: Arc<Mutex<ClientMap>>,
}

impl GatewayServer {
    fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(ClientMap::new())),
        }
    }
}

pub async fn run_grpc(config: Config) -> Result<(), GatewayError> {
    // read gRPC TLS cert and key
    debug!("Configuring certificates for gRPC");
    let grpc_cert = config
        .grpc_cert
        .as_ref()
        .and_then(|path| read_to_string(path).ok());
    let grpc_key = config
        .grpc_key
        .as_ref()
        .and_then(|path| read_to_string(path).ok());
    debug!("Configured certificates for gRPC, cert: {grpc_cert:?}");

    let grpc_server = GatewayServer::new();

    // Start gRPC server.
    debug!("Spawning gRPC server");
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.grpc_port);
    info!("gRPC server is listening on {addr}");
    let mut builder = if let (Some(cert), Some(key)) = (grpc_cert, grpc_key) {
        let identity = Identity::from_pem(cert, key);
        Server::builder().tls_config(ServerTlsConfig::new().identity(identity))?
    } else {
        Server::builder()
    };
    builder
        .add_service(gateway_server::GatewayServer::new(grpc_server))
        .serve(addr)
        .await?;

    Ok(())
}

#[tonic::async_trait]
impl gateway_server::Gateway for GatewayServer {
    type BidiStream = UnboundedReceiverStream<Result<CoreRequest, Status>>;

    /// Handle bidirectional communication with Defguard core.
    async fn bidi(
        &self,
        request: Request<Streaming<CoreResponse>>,
    ) -> Result<Response<Self::BidiStream>, Status> {
        let Some(address) = request.remote_addr() else {
            error!("Failed to determine client address for request: {request:?}");
            return Err(Status::internal("Failed to determine client address"));
        };
        info!("Defguard core RPC client connected from: {address}");

        let (tx, rx) = mpsc::unbounded_channel();
        self.clients.lock().unwrap().insert(address, tx);
        // self.connected.store(true, Ordering::Relaxed);

        let clients = Arc::clone(&self.clients);
        // let results = Arc::clone(&self.results);
        // let connected = Arc::clone(&self.connected);
        let mut stream = request.into_inner();
        tokio::spawn(async move {
            loop {
                match stream.message().await {
                    Ok(Some(response)) => {
                        debug!("Received message from Defguard core: {response:?}");
                        // connected.store(true, Ordering::Relaxed);
                        // // Discard empty payloads.
                        // if let Some(payload) = response.payload {
                        //     if let Some(rx) = results.lock().unwrap().remove(&response.id) {
                        //         if let Err(err) = rx.send(payload) {
                        //             error!("Failed to send message to rx: {err:?}");
                        //         }
                        //     } else {
                        //         error!("Missing receiver for response #{}", response.id);
                        //     }
                        // }
                    }
                    Ok(None) => {
                        info!("gRPC stream has been closed");
                        break;
                    }
                    Err(err) => {
                        error!("gRPC client error: {err}");
                        break;
                    }
                }
            }
            info!("Defguard core client disconnected: {address}");
            // connected.store(false, Ordering::Relaxed);
            clients.lock().unwrap().remove(&address);
        });

        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}
