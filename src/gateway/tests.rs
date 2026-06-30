use std::{
    net::{IpAddr, Ipv4Addr},
    slice::from_ref,
};

#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
use defguard_wireguard_rs::Kernel;
#[cfg(any(target_os = "macos", target_os = "netbsd"))]
use defguard_wireguard_rs::Userspace;
use defguard_wireguard_rs::WGApi;
use ipnetwork::IpNetwork;

use super::*;
use crate::enterprise::firewall::{Address, FirewallRule, Policy, Port, Protocol};

#[cfg(any(target_os = "macos", target_os = "netbsd"))]
type WG = WGApi<Userspace>;
#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
type WG = WGApi<Kernel>;

#[tokio::test]
async fn test_configuration_comparison() {
    let old_config = InterfaceConfiguration {
        name: "gateway".to_string(),
        private_key: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
        addresses: vec!["10.6.1.1/24".parse().unwrap()],
        port: 50051,
        mtu: 1420,
        fwmark: 0,
    };

    let old_peers = vec![
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
    let old_peers_map = old_peers
        .clone()
        .into_iter()
        .map(|peer| (peer.pubkey.clone(), peer))
        .collect();

    let wgapi = WG::new("wg0").unwrap();
    let config = Config::default();
    let gateway = Gateway {
        config,
        interface_configuration: Some(old_config.clone()),
        peers: old_peers_map,
        wgapi: Arc::new(Mutex::new(wgapi)),
        firewall_config: None,
        connected: Arc::new(AtomicBool::new(false)),
        client_tx: None,
        tls_config: None,
    };

    // new config is the same
    let new_config = old_config.clone();
    let new_peers = old_peers.clone();
    assert!(!gateway.is_interface_config_changed(&new_config, &new_peers));

    // only interface config is different
    let new_config = InterfaceConfiguration {
        name: "gateway".to_string(),
        private_key: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
        addresses: vec!["10.6.1.2/24".parse().unwrap()],
        port: 50051,
        mtu: 1420,
        fwmark: 0,
    };
    let new_peers = old_peers.clone();
    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer was removed
    let new_config = old_config.clone();
    let mut new_peers = old_peers.clone();
    new_peers.pop();

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer was added
    let new_config = old_config.clone();
    let mut new_peers = old_peers.clone();
    new_peers.push(Peer {
        pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
        allowed_ips: vec!["10.6.1.4/24".to_string()],
        preshared_key: None,
        keepalive_interval: None,
    });

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer pubkey changed
    let new_config = old_config.clone();
    let new_peers = vec![
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

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer IP changed
    let new_config = old_config.clone();
    let new_peers = vec![
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

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer preshared key changed
    let new_config = old_config.clone();
    let new_peers = vec![
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

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer keepalive interval changed
    let new_config = old_config.clone();
    let new_peers = vec![
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

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));
}

#[tokio::test]
async fn test_firewall_rules_comparison() {
    let rule1 = FirewallRule {
        comment: Some("Rule 1".to_string()),
        destination_addrs: vec![Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32).unwrap(),
        )],
        destination_ports: vec![Port::Single(80)],
        id: 1,
        verdict: Policy::Allow,
        protocols: vec![Protocol::Tcp],
        source_addrs: vec![Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 32).unwrap(),
        )],
        ipv4: true,
    };

    let rule2 = FirewallRule {
        comment: Some("Rule 2".to_string()),
        destination_addrs: vec![Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 32).unwrap(),
        )],
        destination_ports: vec![Port::Single(443)],
        id: 2,
        verdict: Policy::Allow,
        protocols: vec![Protocol::Tcp],
        source_addrs: vec![Address::Network(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 32).unwrap(),
        )],
        ipv4: true,
    };

    let rule3 = FirewallRule {
        comment: Some("Rule 3".to_string()),
        destination_addrs: vec![Address::Network(
            IpNetwork::from_str("10.0.1.0/24").unwrap(),
        )],
        destination_ports: vec![Port::Range(1000, 2000)],
        id: 3,
        verdict: Policy::Deny,
        protocols: vec![Protocol::Udp],
        source_addrs: vec![Address::Network(
            IpNetwork::from_str("192.168.0.0/16").unwrap(),
        )],
        ipv4: true,
    };

    let config1 = FirewallConfig {
        rules: vec![rule1.clone(), rule2.clone()],
        default_policy: Policy::Allow,
        snat_bindings: Vec::new(),
    };

    let config_empty = FirewallConfig {
        rules: Vec::new(),
        default_policy: Policy::Allow,
        snat_bindings: Vec::new(),
    };

    let wgapi = WG::new("wg0").unwrap();
    let config = Config::default();
    let mut gateway = Gateway {
        config,
        interface_configuration: None,
        peers: HashMap::new(),
        wgapi: Arc::new(Mutex::new(wgapi)),
        firewall_config: None,
        connected: Arc::new(AtomicBool::new(false)),
        client_tx: None,
        tls_config: None,
    };

    // Gateway has no firewall config, new rules are empty
    gateway.firewall_config = None;
    assert!(gateway.have_firewall_rules_changed(&[]));

    // Gateway has no firewall config, but new rules exist
    gateway.firewall_config = None;
    assert!(gateway.have_firewall_rules_changed(from_ref(&rule1)));

    // Gateway has firewall config, with empty rules list
    gateway.firewall_config = Some(config1.clone());
    assert!(gateway.have_firewall_rules_changed(&[]));

    // Gateway has firewall config, new rules have different length
    gateway.firewall_config = Some(config1.clone());
    assert!(gateway.have_firewall_rules_changed(from_ref(&rule1)));

    // Gateway has firewall config, new rules have different content
    gateway.firewall_config = Some(config1.clone());
    assert!(gateway.have_firewall_rules_changed(&[rule1.clone(), rule3.clone()]));

    // Gateway has firewall config, new rules are identical
    gateway.firewall_config = Some(config1.clone());
    assert!(!gateway.have_firewall_rules_changed(&[rule1.clone(), rule2.clone()]));

    // Gateway has empty firewall config, new rules exist
    gateway.firewall_config = Some(config_empty.clone());
    assert!(gateway.have_firewall_rules_changed(from_ref(&rule1)));

    // Both configs are empty
    gateway.firewall_config = Some(config_empty);
    assert!(!gateway.have_firewall_rules_changed(&[]));
}

#[tokio::test]
async fn test_firewall_config_comparison() {
    let config1 = FirewallConfig {
        rules: Vec::new(),
        default_policy: Policy::Allow,
        snat_bindings: Vec::new(),
    };

    let config2 = FirewallConfig {
        rules: Vec::new(),
        default_policy: Policy::Deny,
        snat_bindings: Vec::new(),
    };

    let config3 = FirewallConfig {
        rules: Vec::new(),
        default_policy: Policy::Allow,
        snat_bindings: Vec::new(),
    };

    let wgapi = WG::new("wg0").unwrap();
    let config = Config::default();
    let mut gateway = Gateway {
        config,
        interface_configuration: None,
        peers: HashMap::new(),
        wgapi: Arc::new(Mutex::new(wgapi)),
        firewall_config: None,
        connected: Arc::new(AtomicBool::new(false)),
        client_tx: None,
        tls_config: None,
    };
    // Gateway has no config
    gateway.firewall_config = None;
    assert!(gateway.has_firewall_config_changed(&config1));

    // Gateway has config, new config has different default_policy
    gateway.firewall_config = Some(config1.clone());
    assert!(gateway.has_firewall_config_changed(&config2));

    // Gateway has config, new config is identical
    gateway.firewall_config = Some(config1.clone());
    assert!(!gateway.has_firewall_config_changed(&config3));

    // Rules are not being ignored
    let config4 = FirewallConfig {
        rules: vec![FirewallRule {
            comment: None,
            destination_addrs: Vec::new(),
            destination_ports: Vec::new(),
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: true,
        }],
        default_policy: Policy::Allow,
        snat_bindings: Vec::new(),
    };
    gateway.firewall_config = Some(config1);
    assert!(gateway.has_firewall_config_changed(&config4));

    // Rule IP versions are not being ignored
    let config5 = FirewallConfig {
        rules: vec![FirewallRule {
            comment: None,
            destination_addrs: Vec::new(),
            destination_ports: Vec::new(),
            id: 0,
            verdict: Policy::Allow,
            protocols: Vec::new(),
            source_addrs: Vec::new(),
            ipv4: false,
        }],
        default_policy: Policy::Allow,
        snat_bindings: Vec::new(),
    };
    gateway.firewall_config = Some(config4);
    assert!(gateway.has_firewall_config_changed(&config5));
}
