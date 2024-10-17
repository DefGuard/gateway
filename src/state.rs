use std::collections::HashMap;

use crate::proto::{Configuration, Peer};

type PubKey = String;

/// Helper struct which stores interface configuration.
#[derive(Clone)]
pub(crate) struct InterfaceConfiguration {
    name: String,
    prvkey: String,
    address: String,
    port: u32,
    peers: HashMap<PubKey, Peer>,
}

impl InterfaceConfiguration {
    /// Check if the configuraion stored in this struct is different from `Configuration` from protos.
    pub(crate) fn same_as(&self, other: &Configuration) -> bool {
        self.name == other.name
            && self.prvkey == other.prvkey
            && self.address == other.address
            && self.port == other.port
            && !self.is_peer_list_changed(&other.peers)
    }

    /// Check if new peers are the same as the ones stored in this struct.
    fn is_peer_list_changed(&self, new_peers: &[Peer]) -> bool {
        // check if number of peers is different
        // FIXME: this assumes there aren't any duplicates
        if self.peers.len() != new_peers.len() {
            return true;
        }

        // check if all public keys are equal
        if !new_peers
            .iter()
            .map(|peer| &peer.pubkey)
            .all(|k| self.peers.contains_key(k))
        {
            return true;
        }

        // check if all IP addresses are equal
        !new_peers
            .iter()
            .all(|peer| match self.peers.get(&peer.pubkey) {
                Some(p) => peer.allowed_ips == p.allowed_ips,
                None => false,
            })
    }
}

impl From<Configuration> for InterfaceConfiguration {
    fn from(config: Configuration) -> Self {
        Self {
            name: config.name,
            prvkey: config.prvkey,
            address: config.address,
            port: config.port,
            peers: config
                .peers
                .into_iter()
                .map(|peer| (peer.pubkey.clone(), peer))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_configuration_comparison() {
        let peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.3/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];
        let config = Configuration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.1/24".to_string(),
            port: 50051,
            peers: peers.clone(),
        };

        // new config is the same
        let old_config: InterfaceConfiguration = config.clone().into();
        assert!(old_config.same_as(&config));

        // only interface config is different
        let new_config = Configuration {
            name: "gateway".to_string(),
            prvkey: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
            address: "10.6.1.2/24".to_string(),
            port: 50051,
            peers,
        };
        assert!(!old_config.same_as(&new_config));

        // remove one peer
        let mut new_config = config.clone();
        new_config.peers.pop();
        assert!(!old_config.same_as(&new_config));

        // peer was added
        let mut new_config = config.clone();
        new_config.peers.push(Peer {
            pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
            allowed_ips: vec!["10.6.1.4/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        });
        assert!(!old_config.same_as(&new_config));

        // peer pubkey changed
        let mut new_config = config.clone();
        new_config.peers = vec![
            Peer {
                pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.3/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];
        assert!(!old_config.same_as(&new_config));

        // peer IP address changed
        let mut new_config = config.clone();
        new_config.peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.4/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];
        assert!(!old_config.same_as(&new_config));

        // peer preshared key changed
        let mut new_config = config.clone();
        new_config.peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: Some("VGhpc2lzdGhlcGFzc3dvcmQzMWNoYXJhY3RlcnNsbwo=".into()),
                keepalive_interval: None,
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.4/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];
        assert!(!old_config.same_as(&new_config));

        // peer keepalive interval changed
        let mut new_config = config.clone();
        new_config.peers = vec![
            Peer {
                pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
                allowed_ips: vec!["10.6.1.2/24".to_string()],
                preshared_key: Some("VGhpc2lzdGhlcGFzc3dvcmQzMWNoYXJhY3RlcnNsbwo=".into()),
                keepalive_interval: Some(15),
            },
            Peer {
                pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
                allowed_ips: vec!["10.6.1.4/24".to_string()],
                preshared_key: None,
                keepalive_interval: None,
            },
        ];

        assert!(!old_config.same_as(&new_config));
    }
}
