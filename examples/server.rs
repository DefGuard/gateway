use std::{
    io::{stdout, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{
        mpsc,
        watch::{self, Receiver, Sender},
    },
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status, Streaming};

tonic::include_proto!("gateway");

pub struct GatewayServer {
    rx: Receiver<Configuration>,
}

impl GatewayServer {
    pub fn new(rx: Receiver<Configuration>) -> Self {
        Self { rx }
    }
}

#[tonic::async_trait]
impl gateway_service_server::GatewayService for GatewayServer {
    type ConfigStream = ReceiverStream<Result<Configuration, Status>>;

    async fn stats(&self, request: Request<Streaming<PeerStats>>) -> Result<Response<()>, Status> {
        let address = request.remote_addr().unwrap();
        eprintln!("STATS connected from: {}", address);

        let mut stream = request.into_inner();
        while let Some(peer_stats) = stream.message().await? {
            eprintln!("STATS {:?}", peer_stats);
        }
        Ok(Response::new(()))
    }

    async fn config(&self, request: Request<()>) -> Result<Response<Self::ConfigStream>, Status> {
        let address = request.remote_addr().unwrap();
        eprintln!("CONFIG connected from: {}", address);

        let (tx, rx) = mpsc::channel(16);
        let mut config_rx = self.rx.clone();
        tokio::spawn(async move {
            while !tx.is_closed() {
                // loop {
                let config = config_rx.borrow().clone();
                eprintln!("Sending config {:?}", config);
                if tx.send(Ok(config)).await.is_err() {
                    break;
                }

                if let Err(err) = config_rx.changed().await {
                    eprintln!("Watcher error {}", err);
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub async fn cli(tx: Sender<Configuration>) {
    let mut stdin = BufReader::new(tokio::io::stdin());
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
                        tx.send_modify(|config| config.address = address.into());
                    }
                }
                "k" | "key" | "prvkey" => {
                    if let Some(key) = token_iter.next() {
                        tx.send_modify(|config| config.prvkey = key.into());
                    }
                }
                "p" | "port" => {
                    if let Some(port) = token_iter.next() {
                        tx.send_modify(|config| config.port = port.parse().unwrap_or_default());
                    }
                }
                "q" | "quit" => break,
                _ => eprintln!("Unknown command"),
            }
        }
    }
}

pub async fn grpc(rx: Receiver<Configuration>) -> Result<(), tonic::transport::Error> {
    let gateway_service = gateway_service_server::GatewayServiceServer::new(GatewayServer::new(rx));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50055); // TODO: port as an option
    Server::builder()
        .add_service(gateway_service)
        .serve(addr)
        .await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let configuration = Configuration {
        prvkey: "JPcD7xOfOAULx+cTdgzB3dIv6nvqqbmlACYzxrfJ4Dw=".into(),
        address: "192.168.68.68".into(),
        port: 50505,
        peers: Vec::new(),
    };
    let (tx, rx) = watch::channel(configuration);
    tokio::select! {
        _ = grpc(rx) => eprintln!("grpc completed"),
        _ = cli(tx) => eprintln!("cli completed")
    };

    Ok(())
}
