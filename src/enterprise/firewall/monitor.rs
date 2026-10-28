//! Platform-agnostic types describing connections observed by the firewall.

use std::{net::IpAddr, time::SystemTime};

/// Direction of traffic, relative to the VPN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficDirection {
    /// Connection initiated by a VPN device to an external network (or another VPN device).
    Outbound,
    /// Connection initiated from an external network towards a VPN device.
    Inbound,
}

/// Firewall verdict for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    Allowed,
    Blocked,
}

/// A single connection seen by the firewall on a VPN interface.
///
/// Blocked connections are reported as soon as the first packet is dropped.
/// Allowed connections are reported once the connection ends, so the traffic counters are final.
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionEvent {
    /// When the first packet of the connection was seen.
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
