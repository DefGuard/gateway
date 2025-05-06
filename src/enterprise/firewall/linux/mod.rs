pub mod netfilter;

use std::sync::atomic::{AtomicU32, Ordering};

use mnl::mnl_sys::libc;
use netfilter::{
    allow_established_traffic, apply_filter_rules, drop_table, ignore_unrelated_traffic,
    init_firewall, send_batch, set_default_policy, set_masq,
};
use nftnl::Batch;

use super::{
    api::{FirewallApi, FirewallManagementApi},
    Address, FirewallError, FirewallRule, Policy, Port, Protocol, PORT_PROTOCOLS,
};
use crate::proto;

static SET_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn get_set_id() -> u32 {
    SET_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

impl Protocol {
    pub const fn from_proto(
        proto: proto::enterprise::firewall::Protocol,
    ) -> Result<Self, FirewallError> {
        match proto {
            proto::enterprise::firewall::Protocol::Tcp => Ok(Self(libc::IPPROTO_TCP as u8)),
            proto::enterprise::firewall::Protocol::Udp => Ok(Self(libc::IPPROTO_UDP as u8)),
            proto::enterprise::firewall::Protocol::Icmp => Ok(Self(libc::IPPROTO_ICMP as u8)),
            proto::enterprise::firewall::Protocol::Invalid => {
                Err(FirewallError::UnsupportedProtocol(proto as u8))
            }
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
pub struct FilterRule<'a> {
    pub src_ips: &'a [Address],
    pub dest_ips: &'a [Address],
    pub src_ports: &'a [Port],
    pub dest_ports: &'a [Port],
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
    pub comment: Option<String>,
    pub negated_oifname: bool,
    pub negated_iifname: bool,
}

impl FirewallManagementApi for FirewallApi {
    /// Sets up the firewall with the given default policy and priority. Drops the previous table.
    ///
    /// This function also begins a batch of operations which can be applied later using the [`apply`] method.
    /// This allows for making atomic changes to the firewall rules.
    fn setup(
        &mut self,
        default_policy: Option<Policy>,
        priority: Option<i32>,
    ) -> Result<(), FirewallError> {
        debug!("Initializing firewall, VPN interface: {}", self.ifname);
        if let Some(batch) = &mut self.batch {
            drop_table(batch, &self.ifname)?;
            init_firewall(default_policy, priority, batch, &self.ifname)
                .expect("Failed to setup chains");
            debug!("Allowing all established traffic");
            ignore_unrelated_traffic(batch, &self.ifname)?;
            allow_established_traffic(batch, &self.ifname)?;
            debug!("Allowed all established traffic");
            debug!("Initialized firewall");
            Ok(())
        } else {
            Err(FirewallError::TransactionNotStarted)
        }
    }

    /// Cleans up the whole Defguard table.
    fn cleanup(&mut self) -> Result<(), FirewallError> {
        debug!("Cleaning up all previous firewall rules, if any");
        if let Some(batch) = &mut self.batch {
            drop_table(batch, &self.ifname)?;
        } else {
            return Err(FirewallError::TransactionNotStarted);
        }
        debug!("Cleaned up all previous firewall rules");
        Ok(())
    }

    /// Allows for changing the default policy of the firewall.
    fn set_firewall_default_policy(&mut self, policy: Policy) -> Result<(), FirewallError> {
        debug!("Setting default firewall policy to: {policy:?}");
        if let Some(batch) = &mut self.batch {
            set_default_policy(policy, batch, &self.ifname)?;
        } else {
            return Err(FirewallError::TransactionNotStarted);
        }
        debug!("Set firewall default policy to {policy:?}");
        Ok(())
    }

    /// Allows for changing the masquerade status of the firewall.
    fn set_masquerade_status(&mut self, enabled: bool) -> Result<(), FirewallError> {
        debug!("Setting masquerade status to: {enabled:?}");
        if let Some(batch) = &mut self.batch {
            set_masq(&self.ifname, enabled, batch)?;
        } else {
            return Err(FirewallError::TransactionNotStarted);
        }
        debug!("Set masquerade status to: {enabled:?}");
        Ok(())
    }

    fn add_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), FirewallError> {
        debug!("Applying the following Defguard ACL rules: {:?}", rules);
        for rule in rules {
            self.add_rule(rule)?;
        }
        debug!("Applied all Defguard ACL rules");
        Ok(())
    }

    fn add_rule(&mut self, rule: FirewallRule) -> Result<(), FirewallError> {
        debug!("Applying the following Defguard ACL rule: {:?}", rule);
        let mut rules = Vec::new();
        let batch = if let Some(ref mut batch) = self.batch {
            batch
        } else {
            return Err(FirewallError::TransactionNotStarted);
        };

        debug!("The rule will be split into multiple nftables rules based on the specified destination ports and protocols.");
        if rule.destination_ports.is_empty() {
            debug!("No destination ports specified, applying single aggregate nftables rule for every protocol.");
            let rule = FilterRule {
                src_ips: &rule.source_addrs,
                dest_ips: &rule.destination_addrs,
                protocols: rule.protocols,
                action: rule.verdict,
                counter: true,
                defguard_rule_id: rule.id,
                v4: rule.ipv4,
                comment: rule.comment.clone(),
                ..Default::default()
            };
            rules.push(rule);
        } else if !rule.protocols.is_empty() {
            debug!("Destination ports and protocols specified, applying individual nftables rules for each protocol.");
            for protocol in rule.protocols {
                debug!("Applying rule for protocol: {:?}", protocol);
                if protocol.supports_ports() {
                    debug!("Protocol supports ports, rule.");
                    let rule = FilterRule {
                        src_ips: &rule.source_addrs,
                        dest_ips: &rule.destination_addrs,
                        dest_ports: &rule.destination_ports,
                        protocols: vec![protocol],
                        action: rule.verdict,
                        counter: true,
                        defguard_rule_id: rule.id,
                        v4: rule.ipv4,
                        comment: rule.comment.clone(),
                        ..Default::default()
                    };
                    rules.push(rule);
                } else {
                    debug!("Protocol does not support ports, applying nftables rule and ignoring destination ports.");
                    let rule = FilterRule {
                        src_ips: &rule.source_addrs,
                        dest_ips: &rule.destination_addrs,
                        protocols: vec![protocol],
                        action: rule.verdict,
                        counter: true,
                        defguard_rule_id: rule.id,
                        v4: rule.ipv4,
                        comment: rule.comment.clone(),
                        ..Default::default()
                    };
                    rules.push(rule);
                }
            }
        } else {
            debug!(
                "Destination ports specified, but no protocols specified, applying nftables rules for each protocol that support ports."
            );
            for protocol in PORT_PROTOCOLS {
                debug!("Applying nftables rule for protocol: {:?}", protocol);
                let rule = FilterRule {
                    src_ips: &rule.source_addrs,
                    dest_ips: &rule.destination_addrs,
                    dest_ports: &rule.destination_ports,
                    protocols: vec![protocol],
                    action: rule.verdict,
                    counter: true,
                    defguard_rule_id: rule.id,
                    v4: rule.ipv4,
                    comment: rule.comment.clone(),
                    ..Default::default()
                };
                rules.push(rule);
            }
        }

        apply_filter_rules(rules, batch, &self.ifname)?;

        debug!(
            "Applied firewall rules for Defguard ACL rule ID: {}",
            rule.id
        );
        Ok(())
    }

    fn begin(&mut self) -> Result<(), FirewallError> {
        if self.batch.is_none() {
            debug!("Starting new firewall transaction");
            let batch = Batch::new();
            self.batch = Some(batch);
            debug!("Firewall transaction successfully started");
            Ok(())
        } else {
            Err(FirewallError::TransactionFailed(
                    "There is another firewall transaction already in progress. Commit or rollback it before starting a new one.".to_string()
                ))
        }
    }

    fn rollback(&mut self) {
        self.batch = None;
        debug!("Firewall transaction has been rolled back.")
    }

    /// Apply whole firewall configuration and send it in one go to the kernel.
    fn commit(&mut self) -> Result<(), FirewallError> {
        if let Some(batch) = self.batch.take() {
            debug!("Committing firewall transaction");
            let finalized = batch.finalize();
            debug!("Firewall batch finalized, sending to kernel");
            send_batch(&finalized)?;
            debug!("Firewall transaction successfully committed to kernel");
            Ok(())
        } else {
            Err(FirewallError::TransactionNotStarted)
        }
    }
}
