mod nvlist;
mod wgio;

use std::os::fd::RawFd;

use nix::{errno, ioctl_readwrite, sys::socket};

use super::Host;
use nvlist::{NvList, NvValue};
use wgio::{WgDataIo, WgIoError};

// FIXME: `WgDataIo` has to be declared as public
ioctl_readwrite!(write_wireguard_data, b'i', 210, WgDataIo);
ioctl_readwrite!(read_wireguard_data, b'i', 211, WgDataIo);

/// Create socket for ioctl communication.
fn get_dgram_socket() -> Result<RawFd, errno::Errno> {
    socket::socket(
        socket::AddressFamily::Inet,
        socket::SockType::Datagram,
        socket::SockFlag::empty(),
        None,
    )
}

pub fn kernel_get_device(if_name: &str) -> Result<Host, WgIoError> {
    let s = get_dgram_socket().unwrap();
    let mut wg_data = WgDataIo::new(if_name);
    unsafe {
        // First do ioctl with empty `wg_data` to obtain buffer size.
        let x = read_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
        println!("{}", wg_data.wgd_size);

        wg_data.alloc_data()?;

        // Second call to ioctl with allocated buffer.
        let x = read_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
    }

    println!("{:?}", wg_data.as_buf());

    let mut nvlist = NvList::new();
    nvlist.unpack(wg_data.as_buf()).unwrap();
    nvlist.debug();

    // build `Host`
    let listen_port = match nvlist.get("listen-port").unwrap() {
        NvValue::Number(n) => *n,
        _ => 0,
    };
    let private_key = match nvlist.get("private-key").unwrap() {
        NvValue::Binary(b) => (*b).try_into().unwrap(),
        _ => unimplemented!(),
    };
    let host = Host::new(listen_port as u16, private_key);

    Ok(host)
}

pub fn kernel_set_device(if_name: &str) {
    let s = get_dgram_socket().unwrap();
    let mut wg_data = WgDataIo::new(if_name);

    let mut nvlist = NvList::new();
    nvlist.append("listen-port", NvValue::Number(12345));

    let mut ip1 = NvList::new();
    ip1.append("ipv4", NvValue::Binary(&[10, 6, 0, 0]));
    ip1.append("cidr", NvValue::Number(24));
    ip1.append("", NvValue::NvListArrayNext);

    let mut ip2 = NvList::new();
    ip2.append("ipv4", NvValue::Binary(&[10, 7, 0, 0]));
    ip2.append("cidr", NvValue::Number(24));
    ip2.append("", NvValue::NvListArrayNext);

    let mut ip3 = NvList::new();
    ip3.append("ipv4", NvValue::Binary(&[10, 7, 0, 0]));
    ip3.append("cidr", NvValue::Number(24));
    ip3.append("", NvValue::NvListArrayNext);

    let mut peer1 = NvList::new();
    peer1.append(
        "public-key",
        NvValue::Binary(&[
            220, 98, 132, 114, 211, 195, 157, 56, 63, 135, 95, 253, 123, 132, 59, 218, 35, 120, 55,
            169, 156, 165, 223, 184, 140, 111, 142, 164, 145, 107, 167, 17,
        ]),
    );
    peer1.append("allowed-ips", NvValue::NvListArray(vec![ip1, ip2, ip3]));
    peer1.append("", NvValue::NvListArrayNext);

    let mut peer2 = NvList::new();
    peer2.append(
        "public-key",
        NvValue::Binary(&[
            60, 195, 52, 243, 24, 229, 218, 5, 142, 193, 30, 194, 241, 176, 169, 221, 121, 39, 172,
            116, 158, 67, 46, 115, 119, 155, 107, 159, 128, 201, 79, 54,
        ]),
    );
    peer2.append("", NvValue::NvListArrayNext);

    nvlist.append("peers", NvValue::NvListArray(vec![peer1, peer2]));
    nvlist.debug();

    let mut buf = nvlist.pack().unwrap();
    wg_data.wgd_data = buf.as_mut_ptr();
    wg_data.wgd_size = buf.len();

    unsafe {
        let x = write_wireguard_data(s, &mut wg_data);
        println!("{x:?}");
    }
}
