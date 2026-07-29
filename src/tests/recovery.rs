use super::mock_wgapi::StatefulMockWgApi;
use crate::{config::Config, gateway::Gateway, proto::gateway::Configuration};

/// Regression test for the interface recovery bug (#354).
///
/// After a disconnect, `Gateway::purge()` calls `remove_interface()` which
/// deletes the kernel WireGuard link. Before the fix, the next `configure()`
/// tried to configure a non-existent device and failed; `configure()` now
/// recreates the interface when it is missing, so recovery succeeds.
///
/// The test:
/// 1. Builds a Gateway with the stateful mock (interface starts as existing)
/// 2. Calls `purge()`, which drives `remove_interface()` -> interface gone
/// 3. Calls `configure()` and asserts it recreates the interface and succeeds
#[test]
fn test_purge_then_configure_recovers_interface() {
    let mut config = Config::default();
    config.disable_firewall_management = true;
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
        "configure should recover the interface and succeed: {result:?}",
    );
}
