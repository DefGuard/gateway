//! Platform-agnostic types describing connections observed by the firewall.

use std::{net::IpAddr, time::SystemTime};

use serde::{Deserialize, Serialize};

use crate::proto::enterprise::monitor as proto;

/// Direction of traffic, relative to the VPN interface.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Connection initiated from an external network towards a VPN device.
    Inbound,
    /// Connection initiated by a VPN device to an external network.
    Outbound,
}

#[cfg(target_os = "linux")]
impl Direction {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Inbound => "i",
            Self::Outbound => "o",
        }
    }
}

/// Firewall verdict for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Allowed,
    Blocked,
}

/// A single connection seen by the firewall on a VPN interface.
///
/// Blocked connections are reported as soon as the first packet is dropped.
/// Allowed connections are reported once the connection ends, so the traffic counters are final.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub timestamp: SystemTime,
    pub direction: Direction,
    pub status: Status,
    /// IANA protocol number (e.g. 6 for TCP, 17 for UDP).
    pub protocol: u8,
    /// Origin of the traffic.
    pub source: IpAddr,
    pub source_port: Option<u16>,
    /// Target of the traffic.
    pub destination: IpAddr,
    pub destination_port: Option<u16>,
    /// ID of the Defguard ACL rule that matched, or `None` if the default policy applied or the
    /// traffic is not subject to ACL rules.
    pub rule_id: Option<i64>,
    /// Bytes sent by the VPN device.
    pub upload_bytes: u64,
    /// Bytes received by the VPN device.
    pub download_bytes: u64,
}

impl ConnectionEvent {
    /// Data uploaded by the VPN device in KB.
    #[must_use]
    pub fn upload_kb(&self) -> u64 {
        self.upload_bytes.div_ceil(1024)
    }

    /// Data downloaded by the VPN device in KB.
    #[must_use]
    pub fn download_kb(&self) -> u64 {
        self.download_bytes.div_ceil(1024)
    }
}

impl From<Direction> for proto::Direction {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::Inbound => Self::Inbound,
            Direction::Outbound => Self::Outbound,
        }
    }
}

impl From<Status> for proto::Status {
    fn from(status: Status) -> Self {
        match status {
            Status::Allowed => Self::Allowed,
            Status::Blocked => Self::Blocked,
        }
    }
}

/// Convert an IP address to its network-order byte representation (4 or 16 bytes).
fn ip_to_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    }
}

impl From<&ConnectionEvent> for proto::ConnectionEvent {
    fn from(event: &ConnectionEvent) -> Self {
        Self {
            timestamp: Some(event.timestamp.into()),
            direction: proto::Direction::from(event.direction).into(),
            status: proto::Status::from(event.status).into(),
            protocol: event.protocol.into(),
            source_ip_addr: ip_to_bytes(event.source),
            source_port: event.source_port.map(Into::into),
            destination_ip_addr: ip_to_bytes(event.destination),
            destination_port: event.destination_port.map(Into::into),
            rule_id: event.rule_id,
            upload_bytes: event.upload_bytes,
            download_bytes: event.download_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        time::{Duration, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn test_connection_event_json() {
        let event = ConnectionEvent {
            timestamp: UNIX_EPOCH + Duration::from_micros(1_793_198_060_792_864),
            direction: Direction::Outbound,
            status: Status::Allowed,
            protocol: 6,
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: Some(51000),
            destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            destination_port: Some(443),
            rule_id: Some(7),
            upload_bytes: 3528,
            download_bytes: 33192,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            r#"{"timestamp":{"secs_since_epoch":1793198060,"nanos_since_epoch":792864000},"direction":"outbound","status":"allowed","protocol":6,"source":"10.0.0.2","source_port":51000,"destination":"192.168.1.1","destination_port":443,"rule_id":7,"upload_bytes":3528,"download_bytes":33192}"#
        );
        assert_eq!(
            serde_json::from_str::<ConnectionEvent>(&json).unwrap(),
            event
        );
    }

    #[test]
    fn test_connection_event_proto() {
        let event = ConnectionEvent {
            timestamp: UNIX_EPOCH + Duration::from_micros(1_793_198_060_792_864),
            direction: Direction::Inbound,
            status: Status::Blocked,
            protocol: 17,
            source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            source_port: Some(53),
            destination: "fd00::2".parse().unwrap(),
            destination_port: None,
            rule_id: None,
            upload_bytes: 0,
            download_bytes: 128,
        };
        let proto = proto::ConnectionEvent::from(&event);
        let timestamp = proto.timestamp.unwrap();
        assert_eq!(timestamp.seconds, 1_793_198_060);
        assert_eq!(timestamp.nanos, 792_864_000);
        assert_eq!(proto.direction(), proto::Direction::Inbound);
        assert_eq!(proto.status(), proto::Status::Blocked);
        assert_eq!(proto.protocol, 17);
        assert_eq!(proto.source_ip_addr, vec![192, 168, 1, 1]);
        assert_eq!(proto.source_port, Some(53));
        assert_eq!(proto.destination_ip_addr.len(), 16);
        assert_eq!(proto.destination_port, None);
        assert_eq!(proto.rule_id, None);
        assert_eq!(proto.download_bytes, 128);
    }
}
