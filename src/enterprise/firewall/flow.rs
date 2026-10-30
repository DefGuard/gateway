//! Identification of connections from raw packets, shared by firewall connection monitors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// IANA protocol numbers not exposed by `libc`.
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_UDPLITE: u8 = 136;

/// Uniquely identifies a connection, as seen in its original direction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FlowKey {
    pub(crate) protocol: u8,
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    /// Source port, or ICMP identifier.
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
}

pub(crate) fn protocol_has_ports(protocol: u8) -> bool {
    matches!(i32::from(protocol), libc::IPPROTO_TCP | libc::IPPROTO_UDP)
        || matches!(protocol, IPPROTO_DCCP | IPPROTO_SCTP | IPPROTO_UDPLITE)
}

pub(crate) fn be_u16(data: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(..2)?.try_into().ok()?))
}

pub(crate) fn ipv4(data: &[u8]) -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::from(
        <[u8; 4]>::try_from(data.get(..4)?).ok()?,
    )))
}

pub(crate) fn ipv6(data: &[u8]) -> Option<IpAddr> {
    Some(IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(data.get(..16)?).ok()?,
    )))
}

/// Extract connection details from a packet, starting at the network header.
pub(crate) fn parse_packet(packet: &[u8]) -> Option<FlowKey> {
    let (protocol, source, destination, transport) = match packet.first()? >> 4 {
        4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            (
                *packet.get(9)?,
                ipv4(packet.get(12..)?)?,
                ipv4(packet.get(16..)?)?,
                packet.get(header_len..)?,
            )
        }
        6 => {
            let mut next_header = *packet.get(6)?;
            let mut offset = 40;
            loop {
                match i32::from(next_header) {
                    libc::IPPROTO_HOPOPTS | libc::IPPROTO_ROUTING | libc::IPPROTO_DSTOPTS => {
                        let header = packet.get(offset..offset + 2)?;
                        next_header = header[0];
                        offset += (usize::from(header[1]) + 1) * 8;
                    }
                    libc::IPPROTO_FRAGMENT => {
                        next_header = *packet.get(offset)?;
                        offset += 8;
                    }
                    _ => break,
                }
            }
            (
                next_header,
                ipv6(packet.get(8..)?)?,
                ipv6(packet.get(24..)?)?,
                packet.get(offset..)?,
            )
        }
        _ => return None,
    };

    // Match the way conntrack identifies connections.
    let (source_port, destination_port) = match i32::from(protocol) {
        libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6 => (be_u16(transport.get(4..)?)?, 0),
        _ if protocol_has_ports(protocol) => (be_u16(transport)?, be_u16(transport.get(2..)?)?),
        _ => (0, 0),
    };

    Some(FlowKey {
        protocol,
        source,
        destination,
        source_port,
        destination_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = libc::IPPROTO_TCP as u8;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 168, 1, 1]);
        packet[20..22].copy_from_slice(&51000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet
    }

    #[test]
    fn test_parse_ipv4_tcp_packet() {
        assert_eq!(
            parse_packet(&tcp_packet()),
            Some(FlowKey {
                protocol: libc::IPPROTO_TCP as u8,
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                source_port: 51000,
                destination_port: 443,
            })
        );
    }

    #[test]
    fn test_parse_ipv6_udp_packet_with_extension_header() {
        let mut packet = vec![0u8; 56];
        packet[0] = 0x60;
        packet[6] = libc::IPPROTO_DSTOPTS as u8;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        // Destination options header, 8 bytes long.
        packet[40] = libc::IPPROTO_UDP as u8;
        packet[48..50].copy_from_slice(&5353u16.to_be_bytes());
        packet[50..52].copy_from_slice(&53u16.to_be_bytes());

        let key = parse_packet(&packet).unwrap();
        assert_eq!(key.protocol, libc::IPPROTO_UDP as u8);
        assert_eq!(key.source_port, 5353);
        assert_eq!(key.destination_port, 53);
    }
}
