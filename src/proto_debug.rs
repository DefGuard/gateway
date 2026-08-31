//! Manual `Debug` implementations for protos.
//!
//! `Debug` derivation for these types is disabled in `build.rs` (`skip_debug`),
//! so sensitive fields can be redacted here instead of leaking into logs.

use std::fmt;

use crate::proto::gateway::{Configuration, CoreResponse, Peer, Update, core_response, update};

const REDACTED: &str = "***";

impl fmt::Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Configuration")
            .field("name", &self.name)
            .field("private_key", &REDACTED)
            .field("port", &self.port)
            .field("peers", &self.peers)
            .field("addresses", &self.addresses)
            .field("firewall_config", &self.firewall_config)
            .field("mtu", &self.mtu)
            .field("fwmark", &self.fwmark)
            .finish()
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("pubkey", &self.pubkey)
            .field("allowed_ips", &self.allowed_ips)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| REDACTED),
            )
            .field("keepalive_interval", &self.keepalive_interval)
            .finish()
    }
}

impl fmt::Debug for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Update")
            .field("update_type", &self.update_type)
            .field("update", &self.update)
            .finish()
    }
}

impl fmt::Debug for update::Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer(peer) => f.debug_tuple("Peer").field(peer).finish(),
            Self::Network(config) => f.debug_tuple("Network").field(config).finish(),
            Self::FirewallConfig(config) => f.debug_tuple("FirewallConfig").field(config).finish(),
            Self::DisableFirewall(empty) => f.debug_tuple("DisableFirewall").field(empty).finish(),
        }
    }
}

impl fmt::Debug for CoreResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreResponse")
            .field("id", &self.id)
            .field("payload", &self.payload)
            .finish()
    }
}

impl fmt::Debug for core_response::Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(empty) => f.debug_tuple("Empty").field(empty).finish(),
            Self::Config(config) => f.debug_tuple("Config").field(config).finish(),
            Self::Update(update) => f.debug_tuple("Update").field(update).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_is_not_printed() {
        let config = Configuration {
            name: "wg0".into(),
            private_key: "SUPER_SECRET".into(),
            peers: vec![Peer {
                pubkey: "PUBLIC".into(),
                preshared_key: Some("ALSO_SECRET".into()),
                ..Peer::default()
            }],
            ..Configuration::default()
        };
        let printed = format!("{config:?}");
        assert!(!printed.contains("SUPER_SECRET"));
        assert!(!printed.contains("ALSO_SECRET"));
        assert!(printed.contains("wg0"));
        assert!(printed.contains("PUBLIC"));
    }
}
