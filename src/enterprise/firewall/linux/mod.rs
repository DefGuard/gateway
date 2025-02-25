pub mod netfilter;

use std::sync::atomic::{AtomicU32, Ordering};

use netfilter::{
    allow_established_traffic, apply_filter_rules, clear_chains, init_firewall, masq_interface,
    set_default_policy,
};

use super::{
    api::{FirewallApi, FirewallManagementApi},
    proto, Address, FirewallError, FirewallRule, Policy, Port, Protocol,
};

static SET_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn get_set_id() -> u32 {
    SET_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug, Default)]
pub enum State {
    #[default]
    Established,
    Invalid,
    New,
    Related,
}

#[derive(Debug, Default)]
pub struct FilterRule {
    pub src_ips: Vec<Address>,
    pub dest_ips: Vec<Address>,
    pub src_ports: Vec<Port>,
    pub dest_ports: Vec<Port>,
    pub protocols: Vec<Protocol>,
    pub oifname: Option<String>,
    pub iifname: Option<String>,
    pub action: Policy,
    pub states: Vec<State>,
    pub counter: bool,
    // The ID of the associated Defguard rule.
    // The filter rules may not always be a 1:1 representation of the Defguard rules, so
    // this value helps to keep track of them.
    pub defguard_rule_id: i64,
    pub v4: bool,
}

impl FirewallManagementApi for FirewallApi {
    fn setup(&self) -> Result<(), FirewallError> {
        debug!("Initializing firewall, VPN interface: {}", self.ifname);
        init_firewall().expect("Failed to setup chains");
        masq_interface(&self.ifname).expect("Failed to masquerade interface");
        allow_established_traffic(&self.ifname)?;
        info!("Firewall initialized");
        Ok(())
    }

    fn clear(&self) -> Result<(), FirewallError> {
        debug!("Removing all firewall rules");
        clear_chains()?;
        info!("Removed all firewall rules");
        Ok(())
    }

    fn set_default_policy(&self, policy: Policy) -> Result<(), FirewallError> {
        debug!("Setting default firewall policy to: {:?}", policy);
        set_default_policy(policy)?;
        info!("Set firewall default policy to {:?}", policy);
        Ok(())
    }

    fn apply_rule(&self, rule: FirewallRule) -> Result<(), FirewallError> {
        let mut rules = vec![];

        if rule.destination_ports.is_empty() {
            let rule = FilterRule {
                src_ips: rule.source_addrs,
                dest_ips: rule.destination_addrs,
                protocols: rule.protocols,
                action: rule.verdict,
                counter: true,
                defguard_rule_id: rule.id,
                v4: rule.v4,
                ..Default::default()
            };
            rules.push(rule);
        } else {
            for protocol in rule.protocols {
                if protocol.supports_ports() {
                    let rule = FilterRule {
                        src_ips: rule.source_addrs.clone(),
                        dest_ips: rule.destination_addrs.clone(),
                        dest_ports: rule.destination_ports.clone(),
                        protocols: vec![protocol],
                        action: rule.verdict,
                        counter: true,
                        defguard_rule_id: rule.id,
                        v4: rule.v4,
                        ..Default::default()
                    };
                    rules.push(rule);
                } else {
                    let rule = FilterRule {
                        src_ips: rule.source_addrs.clone(),
                        dest_ips: rule.destination_addrs.clone(),
                        protocols: vec![protocol],
                        action: rule.verdict,
                        counter: true,
                        defguard_rule_id: rule.id,
                        v4: rule.v4,
                        ..Default::default()
                    };
                    rules.push(rule);
                }
            }
        }

        apply_filter_rules(rules)?;

        Ok(())
    }
}
