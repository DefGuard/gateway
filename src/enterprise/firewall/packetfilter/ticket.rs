use std::os::fd::RawFd;

use ipnetwork::IpNetwork;

use super::{
    calls::{pf_add_addr, pf_begin_addrs, pf_change_rule, Change, IocPoolAddr, IocRule, PoolAddr},
    rule::Action,
};

pub(super) fn get_ticket(fd: RawFd, anchor: &str, kind: Action) -> u32 {
    let mut pfioc_rule = IocRule::new(anchor);

    pfioc_rule.action = Change::GetTicket;
    pfioc_rule.rule.action = kind;

    // pfioc_rule.action is ignored on FreeBSD, NetBSD, and OpenBSD. --- REALLY? [adam]
    // #[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
    // {
    //     pfioc_rule.action = Change::GetTicket;
    //     pfioc_rule.rule.action = Change::GetTicket as u8;
    // }

    unsafe {
        pf_change_rule(fd, &mut pfioc_rule).unwrap();
    }

    pfioc_rule.ticket
}

pub(super) fn get_pool_ticket(fd: RawFd, anchor: &str) -> u32 {
    let mut ioc = IocPoolAddr::new(anchor);

    unsafe {
        pf_begin_addrs(fd, &mut ioc).unwrap();
    }

    ioc.ticket
}

// Add pool address using the pool ticket previously obtained via `get_pool_ticket()`.
pub(super) fn add_pool_address(fd: RawFd, pool_addr: IpNetwork, pool_ticket: u32) {
    let mut pfioc_pooladdr = unsafe { std::mem::zeroed::<IocPoolAddr>() };
    pfioc_pooladdr.ticket = pool_ticket;
    pfioc_pooladdr.addr = PoolAddr::new(pool_addr, ""); // XXX: ifname
    unsafe {
        pf_add_addr(fd, &mut pfioc_pooladdr).unwrap();
    }
}
