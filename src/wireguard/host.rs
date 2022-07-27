use super::{IpAddrMask, Key};
use crate::proto;
#[cfg(target_os = "linux")]
use netlink_packet_wireguard::{
    constants::{WGDEVICE_F_REPLACE_PEERS, WGPEER_F_REMOVE_ME, WGPEER_F_REPLACE_ALLOWEDIPS},
    nlas::{WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    str::{from_utf8, FromStr},
    time::{Duration, SystemTime},
};

#[derive(Debug, Default)]
pub struct Peer {
    public_key: Key,
    preshared_key: Option<Key>,
    protocol_version: Option<u32>,
    endpoint: Option<SocketAddr>,
    last_handshake: Option<SystemTime>,
    tx_bytes: u64,
    rx_bytes: u64,
    persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Vec<IpAddrMask>,
}

impl Peer {
    pub fn new(public_key: Key) -> Self {
        Self {
            public_key,
            preshared_key: None,
            protocol_version: None,
            endpoint: None,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            persistent_keepalive_interval: None,
            allowed_ips: Vec::new(),
        }
    }

    pub fn set_allowed_ips(&mut self, allowed_ips: Vec<IpAddrMask>) {
        self.allowed_ips = allowed_ips;
    }

    pub fn as_uapi_update(&self) -> String {
        let mut output = format!("public_key={}\n", self.public_key.to_lower_hex());
        if let Some(key) = &self.preshared_key {
            output.push_str("preshared_key=");
            output.push_str(&key.to_lower_hex());
            output.push('\n');
        }
        if let Some(endpoint) = &self.endpoint {
            output.push_str("endpoint=");
            output.push_str(&endpoint.to_string());
            output.push('\n');
        }
        if let Some(interval) = &self.persistent_keepalive_interval {
            output.push_str("persistent_keepalive_interval=");
            output.push_str(&interval.to_string());
            output.push('\n');
        }
        output.push_str("replace_allowed_ips=true\n");
        for allowed_ip in &self.allowed_ips {
            output.push_str("allowed_ip=");
            output.push_str(&allowed_ip.to_string());
            output.push('\n');
        }

        output
    }

    pub fn as_uapi_remove(&self) -> String {
        format!(
            "public_key={}\nremove=true\n",
            self.public_key.to_lower_hex()
        )
    }

    #[cfg(target_os = "linux")]
    pub fn from_nlas(nlas: &[WgPeerAttrs]) -> Self {
        let mut peer = Self::default();

        for nla in nlas {
            match nla {
                WgPeerAttrs::PublicKey(value) => peer.public_key = Key::new(*value),
                WgPeerAttrs::PresharedKey(value) => peer.preshared_key = Some(Key::new(*value)),
                WgPeerAttrs::Endpoint(value) => peer.endpoint = Some(*value),
                WgPeerAttrs::PersistentKeepalive(value) => {
                    peer.persistent_keepalive_interval = Some(*value)
                }
                WgPeerAttrs::LastHandshake(value) => peer.last_handshake = Some(*value),
                WgPeerAttrs::RxBytes(value) => peer.rx_bytes = *value,
                WgPeerAttrs::TxBytes(value) => peer.tx_bytes = *value,
                WgPeerAttrs::AllowedIps(nlas) => {
                    for nla in nlas {
                        let ip = nla.iter().find_map(|nla| match nla {
                            WgAllowedIpAttrs::IpAddr(ip) => Some(*ip),
                            _ => None,
                        });
                        let cidr = nla.iter().find_map(|nla| match nla {
                            WgAllowedIpAttrs::Cidr(cidr) => Some(*cidr),
                            _ => None,
                        });
                        if let (Some(ip), Some(cidr)) = (ip, cidr) {
                            peer.allowed_ips.push(IpAddrMask::new(ip, cidr));
                        }
                    }
                }
                _ => (),
            }
        }

        peer
    }

    #[cfg(target_os = "linux")]
    pub fn as_nlas(&self, ifname: &str) -> Vec<WgDeviceAttrs> {
        vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::Peers(vec![self.as_nlas_peer()]),
        ]
    }

    #[cfg(target_os = "linux")]
    pub fn as_nlas_remove(&self, ifname: &str) -> Vec<WgDeviceAttrs> {
        vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::Peers(vec![WgPeer(vec![
                WgPeerAttrs::PublicKey(self.public_key.as_array()),
                WgPeerAttrs::Flags(WGPEER_F_REMOVE_ME),
            ])]),
        ]
    }

    #[cfg(target_os = "linux")]
    pub fn as_nlas_peer(&self) -> WgPeer {
        let mut attrs = vec![WgPeerAttrs::PublicKey(self.public_key.as_array())];
        if let Some(keepalive) = self.persistent_keepalive_interval {
            attrs.push(WgPeerAttrs::PersistentKeepalive(keepalive));
        }
        attrs.push(WgPeerAttrs::Flags(WGPEER_F_REPLACE_ALLOWEDIPS));
        let allowed_ips = self
            .allowed_ips
            .iter()
            .map(|ipaddr| ipaddr.to_nlas_allowed_ip())
            .collect();
        attrs.push(WgPeerAttrs::AllowedIps(allowed_ips));

        WgPeer(attrs)
    }
}

impl From<proto::Peer> for Peer {
    fn from(proto_peer: proto::Peer) -> Self {
        let mut peer = Self::new(proto_peer.pubkey.as_str().try_into().unwrap_or_default());
        peer.allowed_ips = proto_peer
            .allowed_ips
            .iter()
            .filter_map(|entry| IpAddrMask::from_str(entry).ok())
            .collect();
        peer
    }
}

impl From<&Peer> for proto::Peer {
    fn from(peer: &Peer) -> Self {
        Self {
            pubkey: peer.public_key.to_string(),
            allowed_ips: peer
                .allowed_ips
                .iter()
                .map(|ipmask| ipmask.to_string())
                .collect(),
        }
    }
}

impl From<&Peer> for proto::PeerStats {
    fn from(peer: &Peer) -> Self {
        Self {
            public_key: peer.public_key.to_string(),
            endpoint: peer
                .endpoint
                .map_or(String::new(), |endpoint| endpoint.to_string()),
            allowed_ips: peer.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
            latest_handshake: peer.last_handshake.map_or(0, |ts| {
                ts.duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs() as i64)
            }),
            download: peer.rx_bytes as i64,
            upload: peer.tx_bytes as i64,
            keepalive_interval: peer.persistent_keepalive_interval.unwrap_or_default() as i64,
        }
    }
}

#[derive(Debug, Default)]
pub struct Host {
    pub listen_port: u16,
    pub private_key: Option<Key>,
    fwmark: Option<u32>,
    pub peers: HashMap<Key, Peer>,
}

impl Host {
    pub fn new(listen_port: u16, private_key: Key) -> Self {
        Self {
            listen_port,
            private_key: Some(private_key),
            fwmark: None,
            peers: HashMap::new(),
        }
    }

    pub fn as_uapi(&self) -> String {
        let mut output = format!("listen_port={}\n", self.listen_port);
        if let Some(key) = &self.private_key {
            output.push_str("private_key=");
            output.push_str(&key.to_lower_hex());
            output.push('\n');
        }
        if let Some(fwmark) = &self.fwmark {
            output.push_str("fwmark=");
            output.push_str(&fwmark.to_string());
            output.push('\n');
        }
        output.push_str("replace_peers=true\n");
        for peer in self.peers.values() {
            output.push_str(peer.as_uapi_update().as_ref());
        }

        output
    }

    // TODO: handle errors
    pub fn parse_from(buf: &[u8]) -> Self {
        let mut host = Self::default();
        let mut current_peer_key = None;

        for line in buf.split(|&char| char == b'\n') {
            if let Some(index) = line.iter().position(|&char| char == b'=') {
                let keyword = from_utf8(&line[..index]).unwrap();
                let value = from_utf8(&line[index + 1..]).unwrap();
                match keyword {
                    "listen_port" => host.listen_port = value.parse().unwrap_or_default(),
                    "fwmark" => host.fwmark = Some(value.parse().unwrap_or_default()),
                    "private_key" => host.private_key = Some(Key::decode(value).unwrap()),
                    // "public_key" starts new peer definition
                    "public_key" => {
                        current_peer_key = Key::decode(value).ok();
                        if let Some(ref key) = current_peer_key {
                            let peer = Peer::new(key.clone());
                            host.peers.insert(key.clone(), peer);
                        }
                    }
                    "preshared_key" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                peer.preshared_key = Key::decode(value).ok();
                            }
                        }
                    }
                    "protocol_version" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                peer.protocol_version = value.parse().ok();
                            }
                        }
                    }
                    "endpoint" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                if let Ok(addr) = SocketAddr::from_str(value) {
                                    peer.endpoint = Some(addr);
                                }
                            }
                        }
                    }
                    "persistent_keepalive_interval" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                peer.persistent_keepalive_interval = value.parse().ok();
                            }
                        }
                    }
                    "allowed_ip" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                peer.allowed_ips.push(value.parse().unwrap());
                            }
                        }
                    }
                    "last_handshake_time_sec" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                let handshake =
                                    peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
                                *handshake +=
                                    Duration::from_secs(value.parse().unwrap_or_default());
                            }
                        }
                    }
                    "last_handshake_time_nsec" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                let handshake =
                                    peer.last_handshake.get_or_insert(SystemTime::UNIX_EPOCH);
                                *handshake +=
                                    Duration::from_nanos(value.parse().unwrap_or_default());
                            }
                        }
                    }
                    "rx_bytes" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                peer.rx_bytes = value.parse().unwrap_or_default();
                            }
                        }
                    }
                    "tx_bytes" => {
                        if let Some(ref key) = current_peer_key {
                            if let Some(peer) = host.peers.get_mut(key) {
                                peer.tx_bytes = value.parse().unwrap_or_default();
                            }
                        }
                    }
                    // "errno" ends config
                    "errno" => {
                        let _errno: u32 = value.parse().unwrap();
                        // if errno != 0
                    }
                    _ => eprintln!("Unknown keyword {}", keyword),
                }
            }
        }

        host
    }

    #[cfg(target_os = "linux")]
    pub fn from_nlas(nlas: &[WgDeviceAttrs]) -> Self {
        let mut host = Self::default();

        for nla in nlas {
            match nla {
                WgDeviceAttrs::PrivateKey(value) => host.private_key = Some(Key::new(*value)),
                WgDeviceAttrs::ListenPort(value) => host.listen_port = *value,
                WgDeviceAttrs::Fwmark(value) => host.fwmark = Some(*value),
                WgDeviceAttrs::Peers(nlas) => {
                    for nla in nlas {
                        let peer = Peer::from_nlas(nla);
                        host.peers.insert(peer.public_key.clone(), peer);
                    }
                }
                _ => (),
            }
        }

        host
    }

    #[cfg(target_os = "linux")]
    pub fn as_nlas(&self, ifname: &str) -> Vec<WgDeviceAttrs> {
        let mut nlas = vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::ListenPort(self.listen_port),
        ];
        if let Some(key) = &self.private_key {
            nlas.push(WgDeviceAttrs::PrivateKey(key.as_array()));
        }
        if let Some(fwmark) = &self.fwmark {
            nlas.push(WgDeviceAttrs::Fwmark(*fwmark));
        }
        nlas.push(WgDeviceAttrs::Flags(WGDEVICE_F_REPLACE_PEERS));
        let peers = self
            .peers
            .values()
            .map(|peer| peer.as_nlas_peer())
            .collect();
        nlas.push(WgDeviceAttrs::Peers(peers));
        nlas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let uapi_output =
            b"private_key=000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            listen_port=7301\n\
            public_key=100102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            protocol_version=1\n\
            last_handshake_time_sec=0\n\
            last_handshake_time_nsec=0\n\
            tx_bytes=0\n\
            rx_bytes=0\n\
            persistent_keepalive_interval=0\n\
            allowed_ip=10.6.0.12/32\n\
            public_key=200102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            protocol_version=1\n\
            endpoint=83.11.218.160:51421\n\
            last_handshake_time_sec=1654631933\n\
            last_handshake_time_nsec=862977251\n\
            tx_bytes=52759980\n\
            rx_bytes=3683056\n\
            persistent_keepalive_interval=0\n\
            allowed_ip=10.6.0.25/32\n\
            public_key=300102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            protocol_version=1\n\
            endpoint=31.135.163.194:37712\n\
            last_handshake_time_sec=1654776419\n\
            last_handshake_time_nsec=732507856\n\
            tx_bytes=1009094476\n\
            rx_bytes=76734328\n\
            persistent_keepalive_interval=0\n\
            allowed_ip=10.6.0.23/32\n\
            errno=0\n";
        let host = Host::parse_from(uapi_output);
        assert_eq!(host.listen_port, 7301);
        assert_eq!(host.peers.len(), 3);

        let key = Key::decode("200102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f")
            .unwrap();
        let stats = proto::PeerStats::from(&host.peers[&key]);
        assert_eq!(stats.download, 3683056);
        assert_eq!(stats.upload, 52759980);
        assert_eq!(stats.latest_handshake, 1654631933);
    }

    #[test]
    fn test_host_uapi() {
        let key_str = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::decode(key_str).unwrap();

        let host = Host::new(12345, key);
        assert_eq!(
            "listen_port=12345\n\
            private_key=000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            replace_peers=true\n",
            host.as_uapi()
        );
    }

    #[test]
    fn test_peer_uapi() {
        let key_str = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::decode(key_str).unwrap();

        let peer = Peer::new(key);
        assert_eq!(
            "public_key=000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            replace_allowed_ips=true\n",
            peer.as_uapi_update()
        );

        let key_str = "00112233445566778899aaabbcbddeeff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::decode(key_str).unwrap();
        let peer = Peer::new(key);
        assert_eq!(
            "public_key=00112233445566778899aaabbcbddeeff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            remove=true\n",
            peer.as_uapi_remove()
        );
    }
}
