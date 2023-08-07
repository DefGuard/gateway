mod nvlist;
mod wgio;

use std::{
    collections::HashMap,
    net::IpAddr,
    // time::{Duration, SystemTime},
    os::fd::RawFd,
};

use nix::{errno, ioctl_readwrite, sys::socket};

use super::{Host, IpAddrMask, Peer};
use nvlist::{NvList, NvValue};
use wgio::{WgDataIo, WgIoError};

// FIXME: `WgDataIo` has to be declared as public
ioctl_readwrite!(write_wireguard_data, b'i', 210, WgDataIo);
ioctl_readwrite!(read_wireguard_data, b'i', 211, WgDataIo);

/// Create socket for ioctl communication.
fn get_dgram_socket() -> Result<RawFd, errno::Errno> {
    socket::socket(
        socket::AddressFamily::Inet,
        socket::SockType::Datagram,
        socket::SockFlag::empty(),
        None,
    )
}

impl IpAddrMask {
    #[must_use]
    fn try_from_nvlist(nvlist: &NvList) -> Option<Self> {
        // cidr is mendatory
        nvlist.get_number("cidr").and_then(|cidr| {
            match nvlist.get_binary("ipv4") {
                Some(ipv4) => <[u8; 4]>::try_from(ipv4).ok().map(IpAddr::from),
                None => nvlist
                    .get_binary("ipv6")
                    .and_then(|ipv6| <[u8; 16]>::try_from(ipv6).ok().map(IpAddr::from)),
            }
            .map(|ip| Self {
                ip,
                cidr: cidr as u8,
            })
        })
    }
}

impl Host {
    #[must_use]
    fn from_nvlist(nvlist: &NvList) -> Self {
        let listen_port = nvlist.get_number("listen-port").unwrap_or_default();
        let private_key = nvlist
            .get_binary("private-key")
            .and_then(|value| (*value).try_into().ok());

        let mut peers = HashMap::new();
        if let Some(peer_array) = nvlist.get_nvlist_array("peers") {
            for peer_list in peer_array {
                if let Some(peer) = Peer::try_from_nvlist(peer_list) {
                    peers.insert(peer.public_key.clone(), peer);
                }
            }
        }

        Self {
            listen_port: listen_port as u16,
            private_key,
            fwmark: nvlist.get_number("user-cookie").map(|num| num as u32),
            peers,
        }
    }
}

impl Peer {
    #[must_use]
    fn try_from_nvlist(nvlist: &NvList) -> Option<Self> {
        if let Some(public_key) = nvlist
            .get_binary("public-key")
            .and_then(|value| (*value).try_into().ok())
        {
            let preshared_key = nvlist
                .get_binary("preshared-key")
                .and_then(|value| (*value).try_into().ok());
            // TODO: check if is it seconds
            let last_handshake = None; //nvlist
                                       // .get_binary("last-handshake-time")
                                       // .map(|value| SystemTime::UNIX_EPOCH + Duration::from_secs(value));
            let mut allowed_ips = Vec::new();
            if let Some(ip_array) = nvlist.get_nvlist_array("allowed-ips") {
                for ip_list in ip_array {
                    if let Some(ip) = IpAddrMask::try_from_nvlist(ip_list) {
                        allowed_ips.push(ip);
                    }
                }
            }

            Some(Self {
                public_key,
                preshared_key,
                protocol_version: None,
                endpoint: None,
                last_handshake,
                tx_bytes: nvlist.get_number("tx-bytes").unwrap_or_default(),
                rx_bytes: nvlist.get_number("rx-bytes").unwrap_or_default(),
                persistent_keepalive_interval: nvlist
                    .get_number("persistent-keepalive-interval")
                    .map(|value| value as u16),
                allowed_ips,
            })
        } else {
            None
        }
    }
}

pub fn kernel_get_device(if_name: &str) -> Result<Host, WgIoError> {
    let s = get_dgram_socket().unwrap();
    let mut wg_data = WgDataIo::new(if_name);
    unsafe {
        // First do ioctl with empty `wg_data` to obtain buffer size.
        let x = read_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
        println!("{}", wg_data.wgd_size);

        wg_data.alloc_data()?;

        // Second call to ioctl with allocated buffer.
        let x = read_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
    }

    println!("{:?}", wg_data.as_buf());

    let mut nvlist = NvList::new();
    nvlist.unpack(wg_data.as_buf()).unwrap();
    nvlist.debug();

    let host = Host::from_nvlist(&nvlist);

    Ok(host)
}

pub fn kernel_set_device(if_name: &str) {
    let s = get_dgram_socket().unwrap();
    let mut wg_data = WgDataIo::new(if_name);

    let mut nvlist = NvList::new();
    nvlist.append("listen-port", NvValue::Number(12345));

    let mut ip1 = NvList::new();
    ip1.append("ipv4", NvValue::Binary(&[10, 6, 0, 0]));
    ip1.append("cidr", NvValue::Number(24));
    ip1.append("", NvValue::NvListArrayNext);

    let mut ip2 = NvList::new();
    ip2.append("ipv4", NvValue::Binary(&[10, 7, 0, 0]));
    ip2.append("cidr", NvValue::Number(24));
    ip2.append("", NvValue::NvListArrayNext);

    let mut ip3 = NvList::new();
    ip3.append("ipv4", NvValue::Binary(&[10, 7, 0, 0]));
    ip3.append("cidr", NvValue::Number(24));
    ip3.append("", NvValue::NvListArrayNext);

    let mut peer1 = NvList::new();
    peer1.append(
        "public-key",
        NvValue::Binary(&[
            220, 98, 132, 114, 211, 195, 157, 56, 63, 135, 95, 253, 123, 132, 59, 218, 35, 120, 55,
            169, 156, 165, 223, 184, 140, 111, 142, 164, 145, 107, 167, 17,
        ]),
    );
    peer1.append("allowed-ips", NvValue::NvListArray(vec![ip1, ip2, ip3]));
    peer1.append("", NvValue::NvListArrayNext);

    let mut peer2 = NvList::new();
    peer2.append(
        "public-key",
        NvValue::Binary(&[
            60, 195, 52, 243, 24, 229, 218, 5, 142, 193, 30, 194, 241, 176, 169, 221, 121, 39, 172,
            116, 158, 67, 46, 115, 119, 155, 107, 159, 128, 201, 79, 54,
        ]),
    );
    peer2.append("", NvValue::NvListArrayNext);

    nvlist.append("peers", NvValue::NvListArray(vec![peer1, peer2]));
    nvlist.debug();

    let mut buf = nvlist.pack().unwrap();
    wg_data.wgd_data = buf.as_mut_ptr();
    wg_data.wgd_size = buf.len();

    unsafe {
        let x = write_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
    }
}
