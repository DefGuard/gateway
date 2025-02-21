mod netfilter;

use netfilter::{apply_filter_rules, clear_chains, init_firewall, masq_interface};

use super::{
    api::{FirewallApi, FirewallManagementApi},
    proto, Address, Port, Protocol,
};

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
}

impl FirewallManagementApi for FirewallApi {
    fn setup(&self) {
        println!("Initializing firewall for interface {}", self.ifname);
        init_firewall().expect("Failed to setup chains");
        masq_interface(&self.ifname).expect("Failed to masquerade interface");
    }

    fn clear(&self) {
        println!("Cleaning up firewall for interface {}", self.ifname);
        clear_chains();
    }

    fn set_access(
        &self,
        sources: Vec<Address>,
        destinations: Vec<Address>,
        destination_ports: Vec<Port>,
        protocols: Vec<Protocol>,
        allow: bool,
        id: u32,
    ) {
        let mut rules = vec![];

        if destination_ports.is_empty() {
            let rule = FilterRule {
                src_ips: sources,
                dest_ips: destinations,
                protocols,
                action: allow.into(),
                counter: true,
                id,
                ..Default::default()
            };
            rules.push(rule);
        } else {
            let mut id_counter = id;
            for protocol in protocols {
                let rule = FilterRule {
                    src_ips: sources.clone(),
                    dest_ips: destinations.clone(),
                    dest_ports: destination_ports.clone(),
                    protocols: vec![protocol],
                    action: allow.into(),
                    counter: true,
                    id: id_counter,
                    ..Default::default()
                };
                rules.push(rule);
                id_counter += 1;
            }
        }

        apply_filter_rules(rules);
    }
}
