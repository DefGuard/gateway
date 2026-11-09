//! Platform-agnostic types describing connections observed by the firewall.

#[cfg(test)]
mod tests;

use std::{collections::HashMap, mem, net::IpAddr, time::SystemTime};

use serde::{Deserialize, Serialize};

use crate::proto::enterprise::monitor as proto;

/// Direction of traffic, relative to the VPN interface.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Connection initiated from an external network towards a VPN device.
    Inbound,
    /// Connection initiated by a VPN device.
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
    /// Number of packets of this kind (aggregation).
    pub count: u64,
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

/// Connection events which differ only in [`Merged`] fields are considered similar.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct AggregationKey {
    direction: Direction,
    status: Status,
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
    destination_port: Option<u16>,
    rule_id: Option<i64>,
}

/// Fields of similar connection events which are merged.
#[derive(Clone)]
struct Merged {
    timestamp: SystemTime,
    source_port: Option<u16>,
    upload_bytes: u64,
    download_bytes: u64,
    count: u64,
}

impl Merged {
    fn merge(&mut self, other: &Self) {
        self.timestamp = self.timestamp.min(other.timestamp);
        if self.source_port != other.source_port {
            self.source_port = None;
        }
        self.upload_bytes += other.upload_bytes;
        self.download_bytes += other.download_bytes;
        self.count += other.count;
    }
}

impl ConnectionEvent {
    /// Split into the aggregation key and the merged fields.
    fn split(self) -> (AggregationKey, Merged) {
        // Exhaustive, so new fields must be either part of the key or merged.
        let Self {
            timestamp,
            direction,
            status,
            protocol,
            source,
            source_port,
            destination,
            destination_port,
            rule_id,
            upload_bytes,
            download_bytes,
            count,
        } = self;
        (
            AggregationKey {
                direction,
                status,
                protocol,
                source,
                destination,
                destination_port,
                rule_id,
            },
            Merged {
                timestamp,
                source_port,
                upload_bytes,
                download_bytes,
                count,
            },
        )
    }

    fn join(key: AggregationKey, merged: Merged) -> Self {
        Self {
            timestamp: merged.timestamp,
            direction: key.direction,
            status: key.status,
            protocol: key.protocol,
            source: key.source,
            source_port: merged.source_port,
            destination: key.destination,
            destination_port: key.destination_port,
            rule_id: key.rule_id,
            upload_bytes: merged.upload_bytes,
            download_bytes: merged.download_bytes,
            count: merged.count,
        }
    }
}

/// Merges similar connection events (e.g. many short UDP exchanges) observed between reports to
/// Core into one event, with the earliest timestamp, summed traffic counters and `count`.
#[derive(Default)]
pub(crate) struct Aggregator {
    events: HashMap<AggregationKey, Merged>,
}

impl Aggregator {
    pub(crate) fn add(&mut self, event: ConnectionEvent) {
        let (key, merged) = event.split();
        self.events
            .entry(key)
            .and_modify(|existing| existing.merge(&merged))
            .or_insert(merged);
    }

    /// Take the merged events and start a new time window.
    pub(crate) fn take(&mut self) -> Vec<ConnectionEvent> {
        // Replace the map, so memory used during a burst is released.
        mem::take(&mut self.events)
            .into_iter()
            .map(|(key, merged)| ConnectionEvent::join(key, merged))
            .collect()
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
            count: event.count,
        }
    }
}
