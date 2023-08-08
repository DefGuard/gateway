mod nvlist;
mod sockaddr;
mod timespec;
mod wgio;

use std::{collections::HashMap, net::IpAddr};

use self::{
    nvlist::{NvList, NvValue},
    sockaddr::unpack_sockaddr,
    timespec::unpack_timespec,
    wgio::{WgDataIo, WgIoError},
};
use super::{Host, IpAddrMask, Peer};

// nvlist key names
static NV_LISTEN_PORT: &str = "listen-port";
static NV_FWMARK: &str = "user-cookie";
static NV_PUBLIC_KEY: &str = "public-key";
static NV_PRIVATE_KEY: &str = "private-key";
static NV_PEERS: &str = "peers";
// static NV_REPLACE_PEERS: &str = "replace-peers";

static NV_PRESHARED_KEY: &str = "preshared-key";
static NV_KEEPALIVE_INTERVAL: &str = "persistent-keepalive-interval";
static NV_ENDPOINT: &str = "endpoint";
static NV_RX_BYTES: &str = "rx-bytes";
static NV_TX_BYTES: &str = "tx-bytes";
static NV_LAST_HANDSHAKE: &str = "last-handshake-time";
static NV_ALLOWED_IPS: &str = "allowed-ips";
// static NV_REPLACE_ALLOWED_IPS: &str = "replace-allowed-ips";
// static NV_REMOVE: &str = "remove";

static NV_CIDR: &str = "cidr";
static NV_IPV4: &str = "ipv4";
static NV_IPV6: &str = "ipv6";

/// Cast bytes to `T`.
unsafe fn cast_ref<T>(bytes: &[u8]) -> &T {
    let ptr: *const u8 = bytes.as_ptr();
    ptr.cast::<T>().as_ref().unwrap()
}

impl IpAddrMask {
    #[must_use]
    fn try_from_nvlist(nvlist: &NvList) -> Option<Self> {
        // cidr is mendatory
        nvlist.get_number(NV_CIDR).and_then(|cidr| {
            match nvlist.get_binary(NV_IPV4) {
                Some(ipv4) => <[u8; 4]>::try_from(ipv4).ok().map(IpAddr::from),
                None => nvlist
                    .get_binary(NV_IPV6)
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
        let listen_port = nvlist.get_number(NV_LISTEN_PORT).unwrap_or_default();
        let private_key = nvlist
            .get_binary(NV_PRIVATE_KEY)
            .and_then(|value| (*value).try_into().ok());

        let mut peers = HashMap::new();
        if let Some(peer_array) = nvlist.get_nvlist_array(NV_PEERS) {
            for peer_list in peer_array {
                if let Some(peer) = Peer::try_from_nvlist(peer_list) {
                    peers.insert(peer.public_key.clone(), peer);
                }
            }
        }

        Self {
            listen_port: listen_port as u16,
            private_key,
            fwmark: nvlist.get_number(NV_FWMARK).map(|num| num as u32),
            peers,
        }
    }
}

impl<'a> Host {
    #[must_use]
    fn to_nvlist(&'a self) -> NvList<'a> {
        let mut nvlist = NvList::new();

        nvlist.append_number(NV_LISTEN_PORT, self.listen_port as u64);
        if let Some(ref private_key) = self.private_key {
            nvlist.append_binary(NV_PRIVATE_KEY, private_key.as_slice());
        }
        if let Some(fwmark) = self.fwmark {
            nvlist.append_number(NV_FWMARK, fwmark as u64);
        }

        nvlist
    }
}

impl Peer {
    #[must_use]
    fn try_from_nvlist(nvlist: &NvList) -> Option<Self> {
        if let Some(public_key) = nvlist
            .get_binary(NV_PUBLIC_KEY)
            .and_then(|value| (*value).try_into().ok())
        {
            let preshared_key = nvlist
                .get_binary(NV_PRESHARED_KEY)
                .and_then(|value| (*value).try_into().ok());
            let mut allowed_ips = Vec::new();
            if let Some(ip_array) = nvlist.get_nvlist_array(NV_ALLOWED_IPS) {
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
                endpoint: nvlist.get_binary(NV_ENDPOINT).and_then(unpack_sockaddr),
                last_handshake: nvlist
                    .get_binary(NV_LAST_HANDSHAKE)
                    .and_then(unpack_timespec),
                tx_bytes: nvlist.get_number(NV_TX_BYTES).unwrap_or_default(),
                rx_bytes: nvlist.get_number(NV_RX_BYTES).unwrap_or_default(),
                persistent_keepalive_interval: nvlist
                    .get_number(NV_KEEPALIVE_INTERVAL)
                    .map(|value| value as u16),
                allowed_ips,
            })
        } else {
            None
        }
    }
}

impl<'a> Peer {
    #[must_use]
    fn to_nvlist(&'a self) -> NvList<'a> {
        let mut nvlist = NvList::new();

        nvlist.append_binary(NV_PUBLIC_KEY, self.public_key.as_slice());

        nvlist
    }
}

pub fn kernel_get_device(if_name: &str) -> Result<Host, WgIoError> {
    let mut wg_data = WgDataIo::new(if_name);
    wg_data.read_data()?;

    let mut nvlist = NvList::new();
    nvlist.unpack(wg_data.as_slice()).unwrap(); // FIXME

    Ok(Host::from_nvlist(&nvlist))
}

pub fn kernel_set_device(if_name: &str) {
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

    let mut buf = nvlist.pack().unwrap();
    wg_data.wgd_data = buf.as_mut_ptr();
    wg_data.wgd_size = buf.len();
    wg_data.write_data().unwrap();
}
