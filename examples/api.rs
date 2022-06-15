use std::str::FromStr;
#[cfg(target_os = "linux")]
use wireguard_gateway::wireguard::netlink::{address_interface, create_interface};
use wireguard_gateway::wireguard::{wgapi::WGApi, Host, IpAddrMask, Peer};

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
    let host = api.read_configuration()?;
    println!("{host:#?}");

    let mut host = Host::new(
        12345,
        "EF/BvkM0TVmpggGhMJ/QHXZARCZSnKchozvf8AOIjlM="
            .try_into()
            .unwrap(),
    );
    let mut peer = Peer::new(
        "Chtg9UAkTUOlH7Z6mT//c43kRTjejo7IlX1PCA9AaEs="
            .try_into()
            .unwrap(),
    );
    let addr = IpAddrMask::from_str("10.20.30.40/24").unwrap();
    peer.allowed_ips.push(addr);
    host.peers.push(peer);

    api.write_configuration(&host)?;

    Ok(())
}
