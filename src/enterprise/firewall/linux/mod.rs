pub mod netfilter;

use std::sync::atomic::{AtomicU32, Ordering};

use mnl::mnl_sys::libc::c_char;
use netfilter::{
    allow_established_traffic, apply_filter_rules, clear_chains, init_firewall, masq_interface,
    set_default_action,
};
use nftnl::{expr::Expression, nftnl_sys, Rule};

use super::{
    api::{FirewallApi, FirewallManagementApi},
    proto, Address, FirewallRule, Port, Protocol,
};

static SET_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn get_set_id() -> u32 {
    println!("SET_ID_COUNTER: {:?}", SET_ID_COUNTER);
    SET_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug, Default)]
pub enum Action {
    Accept,
    Drop,
    #[default]
    None,
}

impl From<bool> for Action {
    fn from(allow: bool) -> Self {
        if allow {
            Self::Accept
        } else {
            Self::Drop
        }
    }
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
    pub action: Action,
    pub states: Vec<State>,
    pub counter: bool,
    pub id: u32,
    pub v4: bool,
}

impl FirewallManagementApi for FirewallApi {
    fn setup(&self) {
        println!("Initializing firewall for interface {}", self.ifname);
        init_firewall().expect("Failed to setup chains");
        masq_interface(&self.ifname).expect("Failed to masquerade interface");
        allow_established_traffic(&self.ifname);
    }

    fn clear(&self) {
        println!("Cleaning up firewall for interface {}", self.ifname);
        clear_chains();
    }

    fn set_default_action(&self, allow: bool) {
        println!(
            "Setting default action to {} for interface {}",
            if allow { "allow" } else { "drop" },
            self.ifname
        );

        set_default_action(allow);
    }

    fn apply_rule(&self, rule: FirewallRule) {
        let mut rules = vec![];

        if rule.destination_ports.is_empty() {
            let rule = FilterRule {
                src_ips: rule.source_addrs,
                dest_ips: rule.destination_addrs,
                protocols: rule.protocols,
                action: rule.allow.into(),
                counter: true,
                id: rule.id,
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
                        action: rule.allow.into(),
                        counter: true,
                        id: rule.id,
                        ..Default::default()
                    };
                    rules.push(rule);
                } else {
                    let rule = FilterRule {
                        src_ips: rule.source_addrs.clone(),
                        dest_ips: rule.destination_addrs.clone(),
                        protocols: vec![protocol],
                        action: rule.allow.into(),
                        counter: true,
                        id: rule.id,
                        ..Default::default()
                    };
                    rules.push(rule);
                }
            }
        }

        apply_filter_rules(rules);
    }
}
