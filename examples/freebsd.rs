use std::{
    collections::HashMap,
    io::{stdout, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use defguard_gateway::{
    enterprise::firewall::api::{FirewallApi, FirewallManagementApi},
    proto,
};
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
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{transport::Server, Request, Response, Status, Streaming};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut firewall_api = FirewallApi::new("wg0");
    firewall_api.begin()?;
    firewall_api
        .setup(
            Some(defguard_gateway::enterprise::firewall::Policy::Allow),
            None,
        )
        .unwrap();

    firewall_api.commit()?;

    Ok(())
}
