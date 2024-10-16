use std::{
    borrow::Borrow,
    collections::HashMap,
    io::{stdout, Write},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use defguard_gateway::proto;
use defguard_wireguard_rs::{
    host::{Host, Peer},
    key::Key,
    net::IpAddrMask,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{
        mpsc::{self, UnboundedSender},
        watch::{self, Receiver, Sender},
    },
    time::sleep,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{transport::Endpoint, Request, Response, Status, Streaming};

struct HostConfig {
    name: String,
    address: IpAddrMask,
    host: Host,
}

// struct GatewayServer {
//     config_rx: Receiver<HostConfig>,
//     clients: Arc<Mutex<ClientMap>>,
// }

// impl GatewayServer {
//     pub fn new(config_rx: Receiver<HostConfig>, clients: Arc<Mutex<ClientMap>>) -> Self {
//         // watch for changes in host configuration
//         let task_clients = clients.clone();
//         let mut task_config_rx = config_rx.clone();
//         tokio::spawn(async move {
//             while task_config_rx.changed().await.is_ok() {
//                 let config = (&*task_config_rx.borrow()).into();
//                 let update = proto::Update {
//                     update_type: proto::UpdateType::Modify as i32,
//                     update: Some(proto::update::Update::Network(config)),
//                 };
//                 task_clients.lock().unwrap().retain(
//                     move |_addr, tx: &mut UnboundedSender<Result<proto::Update, Status>>| {
//                         tx.send(Ok(update.clone())).is_ok()
//                     },
//                 );
//             }
//         });

//         Self { config_rx, clients }
//     }
// }

impl From<&HostConfig> for proto::Configuration {
    fn from(host_config: &HostConfig) -> Self {
        Self {
            name: host_config.name.clone(),
            prvkey: host_config
                .host
                .private_key
                .as_ref()
                .map(|key| key.to_string())
                .unwrap_or_default(),
            address: host_config.address.to_string(),
            port: u32::from(host_config.host.listen_port),
            peers: host_config
                .host
                .peers
                .values()
                .map(|peer| peer.into())
                .collect(),
        }
    }
}

// #[tonic::async_trait]
// impl proto::gateway_service_server::GatewayService for GatewayServer {
//     type UpdatesStream = UnboundedReceiverStream<Result<proto::Update, Status>>;

//     async fn config(
//         &self,
//         request: Request<proto::ConfigurationRequest>,
//     ) -> Result<Response<proto::Configuration>, Status> {
//         let address = request.remote_addr().unwrap();
//         eprintln!("CONFIG connected from: {address}");
//         Ok(Response::new((&*self.config_rx.borrow()).into()))
//     }

//     async fn stats(
//         &self,
//         request: Request<Streaming<proto::StatsUpdate>>,
//     ) -> Result<Response<()>, Status> {
//         let address = request.remote_addr().unwrap();
//         eprintln!("STATS connected from: {address}");

//         let mut stream = request.into_inner();
//         while let Some(peer_stats) = stream.message().await? {
//             eprintln!("STATS {:?}", peer_stats);
//         }
//         Ok(Response::new(()))
//     }

//     async fn updates(&self, request: Request<()>) -> Result<Response<Self::UpdatesStream>, Status> {
//         let address = request.remote_addr().unwrap();
//         eprintln!("UPDATES connected from: {address}");

//         let (tx, rx) = mpsc::unbounded_channel();
//         self.clients.lock().unwrap().insert(address, tx);

//         Ok(Response::new(UnboundedReceiverStream::new(rx)))
//     }
// }

async fn cli(tx: Sender<HostConfig>) {
    let mut stdin = BufReader::new(tokio::io::stdin());
    println!(
        "a|addr address - set host address\n\
        c|peer key - create peer with public key\n\
        d|del key - delete peer with public key\n\
        k|key key - set private key\n\
        p|port port - set listening port\n\
        q|quit - quit\n\
        "
    );
    loop {
        print!("> ");
        stdout().flush().unwrap();
        let mut line = String::new();
        let _count = stdin.read_line(&mut line).await.unwrap();
        let mut token_iter = line.split_whitespace();
        if let Some(keyword) = token_iter.next() {
            match keyword {
                "a" | "addr" => {
                    if let Some(address) = token_iter.next() {
                        if let Ok(ipaddr) = address.parse() {
                            tx.send_modify(|config| config.address = ipaddr);
                        } else {
                            eprintln!("Parse error");
                        }
                    }
                }
                "c" | "peer" => {
                    if let Some(key) = token_iter.next() {
                        if let Ok(key) = Key::try_from(key) {
                            let peer = Peer::new(key.clone());

                            let update = proto::Update {
                                update_type: proto::UpdateType::Create as i32,
                                update: Some(proto::update::Update::Peer((&peer).into())),
                            };
                            // clients.lock().unwrap().retain(
                            //     move |addr, tx: &mut UnboundedSender<Result<proto::Update, Status>>| {
                            //         eprintln!("Sending peer update to {addr}");
                            //         tx.send(Ok(update.clone())).is_ok()
                            //     },
                            // );

                            // modify HostConfig, but do not notify the receiver
                            tx.send_if_modified(|config| {
                                config.host.peers.insert(key, peer);
                                false
                            });
                        } else {
                            eprintln!("Parse error");
                        }
                    }
                }
                "d" | "del" => {
                    if let Some(key) = token_iter.next() {
                        if let Ok(key) = Key::try_from(key) {
                            let peer = Peer::new(key);

                            let update = proto::Update {
                                update_type: proto::UpdateType::Delete as i32,
                                update: Some(proto::update::Update::Peer((&peer).into())),
                            };
                            // clients.lock().unwrap().retain(
                            //     move |addr, tx: &mut UnboundedSender<Result<proto::Update, Status>>| {
                            //         eprintln!("Sending peer update to {addr}");
                            //         tx.send(Ok(update.clone())).is_ok()
                            //     },
                            // );

                            // modify HostConfig, but do not notify the receiver
                            // tx.send_if_modified(|config| {
                            //     config.host.peers.retain(|entry| entry.public_key != peer.public_key);
                            //     false
                            // });
                        } else {
                            eprintln!("Parse error");
                        }
                    }
                }
                "k" | "key" => {
                    if let Some(key) = token_iter.next() {
                        if let Ok(key) = Key::try_from(key) {
                            tx.send_modify(|config| config.host.private_key = Some(key));
                        } else {
                            eprintln!("Parse error");
                        }
                    }
                }
                "p" | "port" => {
                    if let Some(port) = token_iter.next() {
                        if let Ok(port) = port.parse() {
                            tx.send_modify(|config| config.host.listen_port = port);
                        } else {
                            eprintln!("Parse error");
                        }
                    }
                }
                "q" | "quit" => break,
                _ => eprintln!("Unknown command"),
            }
        }
    }
}

async fn grpc_client(config_rx: Receiver<HostConfig>) -> Result<(), tonic::transport::Error> {
    let endpoint = Endpoint::from_static("http://localhost:50066");
    let endpoint = endpoint
        .http2_keep_alive_interval(TEN_SECS)
        .tcp_keepalive(Some(TEN_SECS))
        .keep_alive_while_idle(true);
    let uri = endpoint.uri();
    loop {
        let mut client = proto::gateway_client::GatewayClient::new(endpoint.connect_lazy());
        let (tx, rx) = mpsc::unbounded_channel();
        let Ok(response) = client.bidi(UnboundedReceiverStream::new(rx)).await else {
            eprintln!("Failed to connect to gateway, retrying in 10s",);
            sleep(TEN_SECS).await;
            continue;
        };
        eprintln!("Connected to proxy at {uri}");
        let mut resp_stream = response.into_inner();
        'message: loop {
            match resp_stream.message().await {
                Ok(None) => {
                    eprintln!("stream was closed by the sender");
                    break 'message;
                }
                Ok(Some(received)) => {
                    eprintln!("Received the following message from gateway: {received:?}");
                    let payload = match received.payload {
                        Some(proto::core_request::Payload::ConfigRequest(config_request)) => {
                            eprintln!("*** ConfigurationRequest {config_request:?}");
                            let config = (&*config_rx.borrow()).into();
                            Some(proto::core_response::Payload::Config(config))
                        }
                        Some(proto::core_request::Payload::PeerStats(peer_stats)) => {
                            eprintln!("*** PeerStats {peer_stats:?}");
                            None
                        }
                        // Reply without payload.
                        None => None,
                    };
                    let req = proto::CoreResponse {
                        id: received.id,
                        payload,
                    };
                    tx.send(req).unwrap();
                }
                Err(err) => {
                    eprintln!("Disconnected from gateway at {uri}");
                    eprintln!("stream error: {err}");
                    eprintln!("waiting 10s to re-establish the connection");
                    sleep(TEN_SECS).await;
                    break 'message;
                }
            }
        }
    }
}

const TEN_SECS: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let configuration = HostConfig {
        name: "demo".into(),
        host: Host::new(
            50505,
            Key::try_from("JPcD7xOfOAULx+cTdgzB3dIv6nvqqbmlACYzxrfJ4Dw=").unwrap(),
        ),
        address: "192.168.68.68".parse().unwrap(),
    };
    let (config_tx, config_rx) = watch::channel(configuration);
    tokio::select! {
        _ = grpc_client(config_rx) => eprintln!("gRPC client completed"),
        _ = cli(config_tx) => eprintln!("CLI completed")
    };

    Ok(())
}
