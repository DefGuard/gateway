//! Platform-agnostic types describing connections observed by the firewall.

use std::{net::IpAddr, time::SystemTime};

use serde::{Deserialize, Serialize};

/// Direction of traffic, relative to the VPN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    /// Connection initiated by a VPN device to an external network (or another VPN device).
    Outbound,
    /// Connection initiated from an external network towards a VPN device.
    Inbound,
}

/// Firewall verdict for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Allowed,
    Blocked,
}

/// A single connection seen by the firewall on a VPN interface.
///
/// Blocked connections are reported as soon as the first packet is dropped.
/// Allowed connections are reported once the connection ends, so the traffic counters are final.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionEvent {
    /// When the first packet of the connection was seen.
    #[serde(with = "rfc3339")]
    pub timestamp: SystemTime,
    pub direction: TrafficDirection,
    pub status: ConnectionStatus,
    /// IANA protocol number (e.g. 6 for TCP, 17 for UDP).
    pub protocol: u8,
    /// Origin of the traffic.
    pub source: IpAddr,
    pub source_port: Option<u16>,
    /// Target of the traffic.
    pub destination: IpAddr,
    pub destination_port: Option<u16>,
    /// ID of the Defguard ACL rule that matched, or `None` if the default policy applied or the
    /// traffic is not subject to ACL rules (inbound traffic).
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

/// (De)serialize [`SystemTime`] as an RFC 3339 string.
mod rfc3339 {
    use std::time::SystemTime;

    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<S: Serializer>(
        time: &SystemTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(
            &DateTime::<Utc>::from(*time).to_rfc3339_opts(SecondsFormat::Micros, true),
        )
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SystemTime, D::Error> {
        let time = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&time)
            .map(SystemTime::from)
            .map_err(D::Error::custom)
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
            direction: TrafficDirection::Outbound,
            status: ConnectionStatus::Allowed,
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
            r#"{"timestamp":"2026-10-28T14:34:20.792864Z","direction":"outbound","status":"allowed","protocol":6,"source":"10.0.0.2","source_port":51000,"destination":"192.168.1.1","destination_port":443,"rule_id":7,"upload_bytes":3528,"download_bytes":33192}"#
        );
        assert_eq!(
            serde_json::from_str::<ConnectionEvent>(&json).unwrap(),
            event
        );
    }
}
