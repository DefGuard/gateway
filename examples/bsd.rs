// TEST:
// ifconfig wg create name wg0
// wg set wg0 listen-port 7301
// wg genpsk > priv.key # vkaCi/Csc9Iq/ZEQVKPZztvPwh36YTDouE4TPsIthY0=
// wg set wg0 private-key priv.key
// wg genkey | wg pubkey # 3GKEctPDnTg/h1/9e4Q72iN4N6mcpd+4jG+OpJFrpxE=
// wg set wg0 peer 3GKEctPDnTg/h1/9e4Q72iN4N6mcpd+4jG+OpJFrpxE=
use std::{
    alloc::{alloc, dealloc, Layout},
    os::fd::RawFd,
    ptr::null_mut,
    slice::from_raw_parts,
};

use nix::{errno, ioctl_readwrite, sys::socket};

use defguard_gateway::nvlist::NvList;

/// Create socket for ioctl communication.
fn get_dgram_socket() -> Result<RawFd, errno::Errno> {
    socket::socket(
        socket::AddressFamily::Inet,
        socket::SockType::Datagram,
        socket::SockFlag::empty(),
        None,
    )
}

// #define WG_KEY_SIZE	32
// #define SIOCSWG _IOWR('i', 210, struct wg_data_io)
// #define SIOCGWG _IOWR('i', 211, struct wg_data_io)
ioctl_readwrite!(write_wireguard_data, b'i', 210, WgDataIo);
ioctl_readwrite!(read_wireguard_data, b'i', 211, WgDataIo);

/// Represent `struct wg_data_io` defined in
/// https://github.com/freebsd/freebsd-src/blob/main/sys/dev/wg/if_wg.h
#[repr(C)]
pub struct WgDataIo {
    wgd_name: [u8; 16],
    wgd_data: *mut u8, // *void
    wgd_size: usize,
}

impl WgDataIo {
    /// Create empty `WgDataIo`
    #[must_use]
    pub fn new(if_name: &str) -> Self {
        let mut wgd_name = [0u8; 16];
        if_name
            .bytes()
            .take(15)
            .enumerate()
            .for_each(|(i, b)| wgd_name[i] = b);
        Self {
            wgd_name,
            wgd_data: null_mut(),
            wgd_size: 0,
        }
    }

    pub fn alloc_data(&mut self) {
        // TODO: if self.wgd_size != 0 {}
        let layout = Layout::array::<u8>(self.wgd_size).expect("Bad layout");
        unsafe {
            self.wgd_data = alloc(layout);
        }
    }

    pub fn as_buf<'a>(&self) -> &'a [u8] {
        unsafe { from_raw_parts(self.wgd_data, self.wgd_size) }
    }
}

impl Drop for WgDataIo {
    fn drop(&mut self) {
        eprintln!("Dropping WgDataIo");
        if self.wgd_size != 0 {
            let layout = Layout::array::<u8>(self.wgd_size).expect("Bad layout");
            unsafe {
                dealloc(self.wgd_data, layout);
            }
        }
    }
}

fn kernel_get_device() {
    let s = get_dgram_socket().unwrap();
    let mut wg_data = WgDataIo::new("wg0");
    unsafe {
        // First do ioctl with empty `wg_data` to obtain buffer size.
        let x = read_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
        println!("{}", wg_data.wgd_size);

        wg_data.alloc_data();

        // Second call to ioctl with allocated buffer.
        let x = read_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
        println!("{:?}", wg_data.as_buf());

        let mut nvlist = NvList::new();
        nvlist.unpack(wg_data.as_buf()).unwrap();
    }
}

/*
#include <sys/nv.h>
#include <dev/if_wg/if_wg.h>

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

static int kernel_get_device(struct wgdevice **device, const char *ifname)
{
    struct wg_data_io wgd = { 0 };
    nvlist_t *nvl_device = NULL;
    const nvlist_t *const *nvl_peers;
    struct wgdevice *dev = NULL;
    size_t size, peer_count, i;
    uint64_t number;
    const void *binary;
    int ret = 0, s;

    *device = NULL;
    s = get_dgram_socket();
    if (s < 0)
        goto err;

    strlcpy(wgd.wgd_name, ifname, sizeof(wgd.wgd_name));
    if (ioctl(s, SIOCGWG, &wgd) < 0)
        goto err;

    wgd.wgd_data = malloc(wgd.wgd_size);
    if (!wgd.wgd_data)
        goto err;
    if (ioctl(s, SIOCGWG, &wgd) < 0)
        goto err;

    dev = calloc(1, sizeof(*dev));
    if (!dev)
        goto err;
    strlcpy(dev->name, ifname, sizeof(dev->name));
    nvl_device = nvlist_unpack(wgd.wgd_data, wgd.wgd_size, 0);
    if (!nvl_device)
        goto err;

    if (nvlist_exists_number(nvl_device, "listen-port")) {
        number = nvlist_get_number(nvl_device, "listen-port");
        if (number <= UINT16_MAX) {
            dev->listen_port = number;
            dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
        }
    }
    if (nvlist_exists_number(nvl_device, "user-cookie")) {
        number = nvlist_get_number(nvl_device, "user-cookie");
        if (number <= UINT32_MAX) {
            dev->fwmark = number;
            dev->flags |= WGDEVICE_HAS_FWMARK;
        }
    }
    if (nvlist_exists_binary(nvl_device, "public-key")) {
        binary = nvlist_get_binary(nvl_device, "public-key", &size);
        if (binary && size == sizeof(dev->public_key)) {
            memcpy(dev->public_key, binary, sizeof(dev->public_key));
            dev->flags |= WGDEVICE_HAS_PUBLIC_KEY;
        }
    }
    if (nvlist_exists_binary(nvl_device, "private-key")) {
        binary = nvlist_get_binary(nvl_device, "private-key", &size);
        if (binary && size == sizeof(dev->private_key)) {
            memcpy(dev->private_key, binary, sizeof(dev->private_key));
            dev->flags |= WGDEVICE_HAS_PRIVATE_KEY;
        }
    }
    if (!nvlist_exists_nvlist_array(nvl_device, "peers"))
        goto skip_peers;
    nvl_peers = nvlist_get_nvlist_array(nvl_device, "peers", &peer_count);
    if (!nvl_peers)
        goto skip_peers;
    for (i = 0; i < peer_count; ++i) {
        struct wgpeer *peer;
        struct wgallowedip *aip;
        const nvlist_t *const *nvl_aips;
        size_t aip_count, j;

        peer = calloc(1, sizeof(*peer));
        if (!peer)
            goto err_peer;
        if (nvlist_exists_binary(nvl_peers[i], "public-key")) {
            binary = nvlist_get_binary(nvl_peers[i], "public-key", &size);
            if (binary && size == sizeof(peer->public_key)) {
                memcpy(peer->public_key, binary, sizeof(peer->public_key));
                peer->flags |= WGPEER_HAS_PUBLIC_KEY;
            }
        }
        if (nvlist_exists_binary(nvl_peers[i], "preshared-key")) {
            binary = nvlist_get_binary(nvl_peers[i], "preshared-key", &size);
            if (binary && size == sizeof(peer->preshared_key)) {
                memcpy(peer->preshared_key, binary, sizeof(peer->preshared_key));
                if (!key_is_zero(peer->preshared_key))
                    peer->flags |= WGPEER_HAS_PRESHARED_KEY;
            }
        }
        if (nvlist_exists_number(nvl_peers[i], "persistent-keepalive-interval")) {
            number = nvlist_get_number(nvl_peers[i], "persistent-keepalive-interval");
            if (number <= UINT16_MAX) {
                peer->persistent_keepalive_interval = number;
                peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
            }
        }
        if (nvlist_exists_binary(nvl_peers[i], "endpoint")) {
            const struct sockaddr *endpoint = nvlist_get_binary(nvl_peers[i], "endpoint", &size);
            if (endpoint && size <= sizeof(peer->endpoint) && size >= sizeof(peer->endpoint.addr) &&
                (endpoint->sa_family == AF_INET || endpoint->sa_family == AF_INET6))
                memcpy(&peer->endpoint.addr, endpoint, size);
        }
        if (nvlist_exists_number(nvl_peers[i], "rx-bytes"))
            peer->rx_bytes = nvlist_get_number(nvl_peers[i], "rx-bytes");
        if (nvlist_exists_number(nvl_peers[i], "tx-bytes"))
            peer->tx_bytes = nvlist_get_number(nvl_peers[i], "tx-bytes");
        if (nvlist_exists_binary(nvl_peers[i], "last-handshake-time")) {
            binary = nvlist_get_binary(nvl_peers[i], "last-handshake-time", &size);
            if (binary && size == sizeof(peer->last_handshake_time))
                memcpy(&peer->last_handshake_time, binary, sizeof(peer->last_handshake_time));
        }

        if (!nvlist_exists_nvlist_array(nvl_peers[i], "allowed-ips"))
            goto skip_allowed_ips;
        nvl_aips = nvlist_get_nvlist_array(nvl_peers[i], "allowed-ips", &aip_count);
        if (!aip_count || !nvl_aips)
            goto skip_allowed_ips;
        for (j = 0; j < aip_count; ++j) {
            aip = calloc(1, sizeof(*aip));
            if (!aip)
                goto err_allowed_ips;
            if (!nvlist_exists_number(nvl_aips[j], "cidr"))
                continue;
            number = nvlist_get_number(nvl_aips[j], "cidr");
            if (nvlist_exists_binary(nvl_aips[j], "ipv4")) {
                binary = nvlist_get_binary(nvl_aips[j], "ipv4", &size);
                if (!binary || number > 32) {
                    ret = EINVAL;
                    goto err_allowed_ips;
                }
                aip->family = AF_INET;
                aip->cidr = number;
                memcpy(&aip->ip4, binary, sizeof(aip->ip4));
            } else if (nvlist_exists_binary(nvl_aips[j], "ipv6")) {
                binary = nvlist_get_binary(nvl_aips[j], "ipv6", &size);
                if (!binary || number > 128) {
                    ret = EINVAL;
                    goto err_allowed_ips;
                }
                aip->family = AF_INET6;
                aip->cidr = number;
                memcpy(&aip->ip6, binary, sizeof(aip->ip6));
            } else
                continue;

            if (!peer->first_allowedip)
                peer->first_allowedip = aip;
            else
                peer->last_allowedip->next_allowedip = aip;
            peer->last_allowedip = aip;
            continue;

        err_allowed_ips:
            if (!ret)
                ret = -errno;
            free(aip);
            goto err_peer;
        }
    skip_allowed_ips:
        if (!dev->first_peer)
            dev->first_peer = peer;
        else
            dev->last_peer->next_peer = peer;
        dev->last_peer = peer;
        continue;

    err_peer:
        if (!ret)
            ret = -errno;
        free(peer);
        goto err;
    }

skip_peers:
    free(wgd.wgd_data);
    nvlist_destroy(nvl_device);
    *device = dev;
    return 0;

err:
    if (!ret)
        ret = -errno;
    free(wgd.wgd_data);
    nvlist_destroy(nvl_device);
    free(dev);
    return ret;
}


static int kernel_set_device(struct wgdevice *dev)
{
    struct wg_data_io wgd = { 0 };
    nvlist_t *nvl_device = NULL, **nvl_peers = NULL;
    size_t peer_count = 0, i = 0;
    struct wgpeer *peer;
    int ret = 0, s;

    strlcpy(wgd.wgd_name, dev->name, sizeof(wgd.wgd_name));

    nvl_device = nvlist_create(0);
    if (!nvl_device)
        goto err;

    for_each_wgpeer(dev, peer)
        ++peer_count;
    if (peer_count) {
        nvl_peers = calloc(peer_count, sizeof(*nvl_peers));
        if (!nvl_peers)
            goto err;
    }
    if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY)
        nvlist_add_binary(nvl_device, "private-key", dev->private_key, sizeof(dev->private_key));
    if (dev->flags & WGDEVICE_HAS_LISTEN_PORT)
        nvlist_add_number(nvl_device, "listen-port", dev->listen_port);
    if (dev->flags & WGDEVICE_HAS_FWMARK)
        nvlist_add_number(nvl_device, "user-cookie", dev->fwmark);
    if (dev->flags & WGDEVICE_REPLACE_PEERS)
        nvlist_add_bool(nvl_device, "replace-peers", true);

    for_each_wgpeer(dev, peer) {
        size_t aip_count = 0, j = 0;
        nvlist_t **nvl_aips = NULL;
        struct wgallowedip *aip;

        nvl_peers[i]  = nvlist_create(0);
        if (!nvl_peers[i])
            goto err_peer;
        for_each_wgallowedip(peer, aip)
            ++aip_count;
        if (aip_count) {
            nvl_aips = calloc(aip_count, sizeof(*nvl_aips));
            if (!nvl_aips)
                goto err_peer;
        }
        nvlist_add_binary(nvl_peers[i], "public-key", peer->public_key, sizeof(peer->public_key));
        if (peer->flags & WGPEER_HAS_PRESHARED_KEY)
            nvlist_add_binary(nvl_peers[i], "preshared-key", peer->preshared_key, sizeof(peer->preshared_key));
        if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
            nvlist_add_number(nvl_peers[i], "persistent-keepalive-interval", peer->persistent_keepalive_interval);
        if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
            nvlist_add_binary(nvl_peers[i], "endpoint", &peer->endpoint.addr, peer->endpoint.addr.sa_len);
        if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS)
            nvlist_add_bool(nvl_peers[i], "replace-allowedips", true);
        if (peer->flags & WGPEER_REMOVE_ME)
            nvlist_add_bool(nvl_peers[i], "remove", true);
        for_each_wgallowedip(peer, aip) {
            nvl_aips[j] = nvlist_create(0);
            if (!nvl_aips[j])
                goto err_peer;
            nvlist_add_number(nvl_aips[j], "cidr", aip->cidr);
            if (aip->family == AF_INET)
                nvlist_add_binary(nvl_aips[j], "ipv4", &aip->ip4, sizeof(aip->ip4));
            else if (aip->family == AF_INET6)
                nvlist_add_binary(nvl_aips[j], "ipv6", &aip->ip6, sizeof(aip->ip6));
            ++j;
        }
        if (j) {
            nvlist_add_nvlist_array(nvl_peers[i], "allowed-ips", (const nvlist_t *const *)nvl_aips, j);
            for (j = 0; j < aip_count; ++j)
                nvlist_destroy(nvl_aips[j]);
            free(nvl_aips);
        }
        ++i;
        continue;

    err_peer:
        ret = -errno;
        for (j = 0; j < aip_count && nvl_aips; ++j)
            nvlist_destroy(nvl_aips[j]);
        free(nvl_aips);
        nvlist_destroy(nvl_peers[i]);
        goto err;
    }
    if (i) {
        nvlist_add_nvlist_array(nvl_device, "peers", (const nvlist_t *const *)nvl_peers, i);
        for (i = 0; i < peer_count; ++i)
            nvlist_destroy(nvl_peers[i]);
        free(nvl_peers);
    }
    wgd.wgd_data = nvlist_pack(nvl_device, &wgd.wgd_size);
    nvlist_destroy(nvl_device);
    if (!wgd.wgd_data)
        goto err;
    s = get_dgram_socket();
    if (s < 0)
        return -errno;
    return ioctl(s, SIOCSWG, &wgd);

err:
    if (!ret)
        ret = -errno;
    for (i = 0; i < peer_count && nvl_peers; ++i)
        nvlist_destroy(nvl_peers[i]);
    free(nvl_peers);
    nvlist_destroy(nvl_device);
    return ret;
}

#define	NV_NAME_MAX	2048

#define	NV_TYPE_NONE			0
#define	NV_TYPE_NULL			1
#define	NV_TYPE_BOOL			2
#define	NV_TYPE_NUMBER			3
#define	NV_TYPE_STRING			4
#define	NV_TYPE_NVLIST			5
#define	NV_TYPE_DESCRIPTOR		6
#define	NV_TYPE_BINARY			7
#define	NV_TYPE_BOOL_ARRAY		8
#define	NV_TYPE_NUMBER_ARRAY		9
#define	NV_TYPE_STRING_ARRAY		10
// only in kernel
#define	NV_TYPE_NVLIST_ARRAY		11
#define	NV_TYPE_DESCRIPTOR_ARRAY	12

#define	NVLIST_HEADER_MAGIC	0x6c // 'l'
#define	NVLIST_HEADER_VERSION	0x00
struct nvlist_header {
    uint8_t		nvlh_magic;
    uint8_t		nvlh_version;
    uint8_t		nvlh_flags;
    uint64_t	nvlh_descriptors;
    uint64_t	nvlh_size;
} __packed;
struct nvpair_header {
    uint8_t		nvph_type;
    uint16_t	nvph_namesize;
    uint64_t	nvph_datasize;
    uint64_t	nvph_nitems;
} __packed;
*/

fn main() {
    kernel_get_device();

    // let data = [
    //     // *** nvlist_header (19 bytes)
    //     108, // nvlh_magic
    //     0, // nvlh_version
    //     0, // nvlh_flags
    //     0, 0, 0, 0, 0, 0, 0, 0, // nvlh_descriptors
    //     39, 0, 0, 0, 0, 0, 0, 0, // nvlh_size
    //     // *** data (nvlh_size bytes)
    //     // *** nvpair_header (19 bytes)
    //     3, // nvph_type = NV_TYPE_NUMBER
    //     12, 0, // nvph_namesize
    //     8, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
    //     0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
    //     108, 105, 115, 116, 101, 110, 45, 112, 111, 114, 116, 0, // "listen-port\0"
    //     57, 48, 0, 0, 0, 0, 0, 0, // 18519
    // ];
    // println!("len {}", data.len());
}
