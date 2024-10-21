use std::{
    io::{stdout, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
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
use tonic::transport::Endpoint;

struct HostConfig {
    name: String,
    address: IpAddrMask,
    host: Host,
}

/// Shared trasmission channel for both CLI and gRPC client to communicate with gateway.
static STREAM_TX: Mutex<Option<UnboundedSender<proto::CoreResponse>>> = Mutex::new(None);
static MESSAGE_ID: AtomicU64 = AtomicU64::new(0);

/// Watcher for config changes, which sends changes over gRPC.
async fn handle_changes(mut config_rx: Receiver<HostConfig>) {
    while config_rx.changed().await.is_ok() {
        eprintln!("Sending changes");
        if let Some(tx) = &*STREAM_TX.lock().unwrap() {
            let config = (&*config_rx.borrow()).into();
            let update = proto::Update {
                update_type: proto::UpdateType::Modify as i32,
                update: Some(proto::update::Update::Network(config)),
            };

            let payload = Some(proto::core_response::Payload::Update(update));
            let id = MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
            let req = proto::CoreResponse { id, payload };
            tx.send(req).unwrap();
        } else {
            eprintln!("Failed to obtain a lock for mutex/sender");
        }
    }
}

impl From<&HostConfig> for proto::Configuration {
    fn from(host_config: &HostConfig) -> Self {
        Self {
            name: host_config.name.clone(),
            prvkey: host_config
                .host
                .private_key
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            address: host_config.address.to_string(),
            port: u32::from(host_config.host.listen_port),
            peers: host_config.host.peers.values().map(Into::into).collect(),
        }
    }
}

fn print_help() {
    println!(
        "?|help - print this help\n\
        a|addr address - set host address\n\
        c|peer key - create peer with public key\n\
        d|del key - delete peer with public key\n\
        k|key key - set private key\n\
        p|port port - set listening port\n\
        q|quit - quit\n\
        "
    );
}

/// Command line command handler.
async fn cli(config_tx: Sender<HostConfig>) {
    let mut stdin = BufReader::new(tokio::io::stdin());
    print_help();
    loop {
        print!("> ");
        stdout().flush().unwrap();
        let mut line = String::new();
        let _count = stdin.read_line(&mut line).await.unwrap();
        let mut token_iter = line.split_whitespace();
        if let Some(keyword) = token_iter.next() {
            match keyword {
                "?" | "help" => print_help(),
                "a" | "addr" => {
                    let Some(arg) = token_iter.next() else {
                        eprintln!("missing argument");
                        continue;
                    };
                    if let Ok(ipaddr) = arg.parse() {
                        config_tx.send_modify(|config| config.address = ipaddr);
                    } else {
                        eprintln!("Parse error");
                    }
                }
                "c" | "peer" => {
                    let Some(arg) = token_iter.next() else {
                        eprintln!("missing argument");
                        continue;
                    };
                    if let Ok(key) = Key::try_from(arg) {
                        let peer = Peer::new(key.clone());
                        // Try to send
                        if let Some(tx) = &*STREAM_TX.lock().unwrap() {
                            let update = proto::Update {
                                update_type: proto::UpdateType::Create as i32,
                                update: Some(proto::update::Update::Peer((&peer).into())),
                            };
                            let payload = Some(proto::core_response::Payload::Update(update));
                            let id = MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
                            let req = proto::CoreResponse { id, payload };
                            tx.send(req).unwrap();
                        }
                        // modify HostConfig, but do not notify the receiver
                        config_tx.send_if_modified(|config| {
                            config.host.peers.insert(key, peer);
                            false
                        });
                    } else {
                        eprintln!("Parse error");
                    }
                }
                "d" | "del" => {
                    let Some(arg) = token_iter.next() else {
                        eprintln!("missing argument");
                        continue;
                    };
                    if let Ok(key) = Key::try_from(arg) {
                        let peer = Peer::new(key);
                        // Try to send
                        if let Some(tx) = &*STREAM_TX.lock().unwrap() {
                            let update = proto::Update {
                                update_type: proto::UpdateType::Delete as i32,
                                update: Some(proto::update::Update::Peer((&peer).into())),
                            };
                            let payload = Some(proto::core_response::Payload::Update(update));
                            let id = MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
                            let req = proto::CoreResponse { id, payload };
                            tx.send(req).unwrap();
                        }
                        // modify HostConfig, but do not notify the receiver
                        config_tx.send_if_modified(|config| {
                            config
                                .host
                                .peers
                                .retain(|public_key, _| public_key != &peer.public_key);
                            false
                        });
                    } else {
                        eprintln!("Parse error");
                    }
                }
                "k" | "key" => {
                    let Some(arg) = token_iter.next() else {
                        eprintln!("missing argument");
                        continue;
                    };
                    if let Ok(key) = Key::try_from(arg) {
                        config_tx.send_modify(|config| config.host.private_key = Some(key));
                    } else {
                        eprintln!("Parse error");
                    }
                }
                "p" | "port" => {
                    let Some(arg) = token_iter.next() else {
                        eprintln!("missing argument");
                        continue;
                    };
                    if let Ok(port) = arg.parse() {
                        config_tx.send_modify(|config| config.host.listen_port = port);
                    } else {
                        eprintln!("Parse error");
                    }
                }
                "q" | "quit" => break,
                _ => eprintln!("Unknown command"),
            }
        }
    }
}

const TEN_SECS: Duration = Duration::from_secs(10);

/// Client side for gRPC communication.
async fn grpc_client(config_rx: Receiver<HostConfig>) -> Result<(), tonic::transport::Error> {
    let endpoint = Endpoint::from_static("http://localhost:50066");
    let endpoint = endpoint
        .http2_keep_alive_interval(TEN_SECS)
        .tcp_keepalive(Some(TEN_SECS))
        .keep_alive_while_idle(true);
    let uri = endpoint.uri();
    loop {
        *STREAM_TX.lock().unwrap() = None;
        let mut client = proto::gateway_client::GatewayClient::new(endpoint.connect_lazy());
        let (tx, rx) = mpsc::unbounded_channel();
        *STREAM_TX.lock().unwrap() = Some(tx.clone());

        let Ok(response) = client.bidi(UnboundedReceiverStream::new(rx)).await else {
            eprintln!("Failed to connect to gateway, retrying in 10s",);
            sleep(TEN_SECS).await;
            continue;
        };
        eprintln!("Connected to gateway at {uri}");
        let mut resp_stream = response.into_inner();

        eprintln!("Sending configuration");
        let config = (&*config_rx.borrow()).into();
        let payload = Some(proto::core_response::Payload::Config(config));
        let id = MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
        let req = proto::CoreResponse { id, payload };
        tx.send(req).unwrap();

        'message: loop {
            match resp_stream.message().await {
                Ok(None) => {
                    eprintln!("stream was closed by the sender");
                    break 'message;
                }
                Ok(Some(received)) => {
                    eprintln!("Received message from gateway: {received:?}");
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
        _ = grpc_client(config_rx.clone()) => eprintln!("gRPC client completed"),
        () = cli(config_tx) => eprintln!("CLI completed"),
        () = handle_changes(config_rx) => eprintln!("Changes handler completed"),
    };

    Ok(())
}
