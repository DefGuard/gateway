use super::mock_wgapi::StatefulMockWgApi;
use crate::{config::Config, gateway::Gateway, proto::gateway::Configuration};

/// Reproduction test for the interface recovery bug.
///
/// After a disconnect, `Gateway::purge()` calls `remove_interface()` which
/// deletes the kernel WireGuard link. On the next `configure()`, the gateway
/// tries to configure a non-existent device and fails with `NoDevice`.
///
/// This test proves the bug by:
/// 1. Building a Gateway with the stateful mock (interface starts as existing)
/// 2. Calling `purge()` which drives `remove_interface()` -> interface gone
/// 3. Calling `configure()` with a minimal config -> fails on current code
#[test]
fn purge_then_configure_recovers_interface() {
    let config = Config::default();
    let mut gateway = Gateway::new(config, StatefulMockWgApi::new()).unwrap();

    // Verify the interface exists before purge.
    assert!(
        gateway.wgapi.lock().unwrap().read_interface_data().is_ok(),
        "interface should exist initially"
    );

    // Simulate what happens on disconnect: purge removes the interface.
    gateway.purge();

    // After purge, the interface should be gone.
    assert!(
        gateway.wgapi.lock().unwrap().read_interface_data().is_err(),
        "interface should not exist after purge"
    );

    // Simulate reconnect: Core pushes a new configuration.
    let new_config = Configuration {
        name: "wg0".into(),
        private_key: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abC=".into(),
        port: 51820,
        peers: vec![],
        addresses: vec!["10.0.0.1/24".into()],
        firewall_config: None,
        mtu: 1420,
        fwmark: 0,
    };

    let result = gateway.configure(new_config);
    assert!(
        result.is_ok(),
        "configure should succeed (but fails on current code): {result:?}",
    );
}
