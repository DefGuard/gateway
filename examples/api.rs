#[cfg(target_os = "linux")]
use defguard_gateway::wireguard::netlink::{address_interface, create_interface};
use defguard_gateway::wireguard::{wgapi::WGApi, Host, IpAddrMask, Key, Peer};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        eprintln!("create interface");
        create_interface("wg0")?;
        eprintln!("address interface");
        let addr = IpAddrMask::from_str("10.20.30.40/24").unwrap();
        address_interface("wg0", &addr)?;
    }
    let api = if cfg!(target_os = "linux") {
        WGApi::new("wg0".into(), false)
    } else {
        WGApi::new("utun3".into(), true)
    };
    let host = api.read_host()?;
    println!("{host:#?}");

    let mut host = Host::new(
        12345,
        "EF/BvkM0TVmpggGhMJ/QHXZARCZSnKchozvf8AOIjlM="
            .try_into()
            .unwrap(),
    );
    let peer_key: Key = "Chtg9UAkTUOlH7Z6mT//c43kRTjejo7IlX1PCA9AaEs="
        .try_into()
        .unwrap();
    let mut peer = Peer::new(peer_key.clone());
    let addr = IpAddrMask::from_str("10.20.30.40/24").unwrap();
    peer.allowed_ips.push(addr);
    host.peers.insert(peer_key, peer);

    api.write_host(&host)?;

    let peer = Peer::new(
        "hTZX/2a0CVyoqhP60eiXYRTXuDbWXCrrhAvd/8ublE0="
            .try_into()
            .unwrap(),
    );
    api.write_peer(&peer)?;

    api.delete_peer(&peer)?;

    Ok(())
}
