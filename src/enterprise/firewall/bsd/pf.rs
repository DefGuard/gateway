use pfctl::{AnchorChange, FilterRuleAction, FilterRuleBuilder, StatePolicy, Transaction};

use super::PfRules;
use crate::enterprise::firewall::{FirewallError, Policy};

pub(crate) const DEFGUARD_ANCHOR: &str = "defguard";

pub(crate) fn init_firewall(
    transaction: &mut PfRules,
    ifname: &str,
    default_policy: Option<Policy>,
) -> Result<(), FirewallError> {
    // Initialize the firewall here
    // This is a placeholder implementation

    let mut pf = pfctl::PfCtl::new()?;
    pf.try_add_anchor(DEFGUARD_ANCHOR, pfctl::AnchorKind::Filter)?;

    Ok(())
}

pub(crate) fn allow_established_traffic(
    transaction: &mut Transaction,
) -> Result<(), FirewallError> {
    // Allow established traffic here
    // This is a placeholder implementation

    Ok(())
}

impl Policy {
    fn into_action(self) -> pfctl::FilterRuleAction {
        match self {
            Policy::Allow => pfctl::FilterRuleAction::Pass,
            Policy::Deny => pfctl::FilterRuleAction::Drop(pfctl::DropAction::Drop),
        }
    }
}

pub(crate) fn set_default_policy(
    batch: &mut PfRules,
    ifname: &str,
    policy: Policy,
) -> Result<(), FirewallError> {
    let rule = FilterRuleBuilder::default()
        .label(format!("defguard:default_policy_{:?}", policy))
        .action(policy.into_action())
        .interface(ifname)
        .keep_state(StatePolicy::Keep)
        .build()?;

    batch.add_filter_rule(rule);

    Ok(())
}
