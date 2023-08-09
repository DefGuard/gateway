use std::str::FromStr;

use defguard_gateway::wireguard::{
    bsd::{delete_peer, get_host, set_host, set_peer},
    Host, IpAddrMask, Key, Peer,
};

/*
static int kernel_get_wireguard_interfaces(struct string_list *list)
{
    struct ifgroupreq ifgr = { .ifgr_name = "wg" };
    struct ifg_req *ifg;
    int s = get_dgram_socket(), ret = 0;

    if (s < 0)
        return -errno;

    if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0)
        return errno == ENOENT ? 0 : -errno;

    ifgr.ifgr_groups = calloc(1, ifgr.ifgr_len);
    if (!ifgr.ifgr_groups)
        return -errno;
    if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0) {
        ret = -errno;
        goto out;
    }

    for (ifg = ifgr.ifgr_groups; ifg && ifgr.ifgr_len > 0; ++ifg) {
        if ((ret = string_list_add(list, ifg->ifgrq_member)) < 0)
            goto out;
        ifgr.ifgr_len -= sizeof(struct ifg_req);
    }

out:
    free(ifgr.ifgr_groups);
    return ret;
}
*/

fn main() {
    // test setting host
    let mut host = Host::new(
        7301,
        Key::decode("08817a6c496934607d3dcb7f56032711dc738597c7327b56be02cf9310140143").unwrap(),
    );
    let mut peer = Peer::new(
        Key::decode("8fe75ceaf7067463da2b08b7c5f8fde3ee4c0eb7d6090bfd69ba40e61daedd2a").unwrap(),
    );
    peer.allowed_ips
        .push(IpAddrMask::from_str("10.6.0.25/32").unwrap());
    host.peers.insert(peer.public_key.clone(), peer);
    let mut peer = Peer::new(
        Key::decode("d34293cee884e5350b1f1683f205399c9fa0087e41bfc3e08222a1c84f4d1207").unwrap(),
    );
    peer.allowed_ips
        .push(IpAddrMask::from_str("10.6.0.30/32").unwrap());
    host.peers.insert(peer.public_key.clone(), peer);
    set_host("wg0", &host).unwrap();

    // test setting peer
    let mut peer = Peer::new(
        Key::decode("b6e788853c39cd8143ab5fadcd128e9f7035d552d20c93e736e2c11f26195f72").unwrap(),
    );
    peer.allowed_ips
        .push(IpAddrMask::from_str("10.6.0.12/32").unwrap());
    set_peer("wg0", &peer).unwrap();

    // test getting host
    println!("{:#?}", get_host("wg0").unwrap());

    // test deletting peer
    delete_peer("wg0", &peer).unwrap();
}
