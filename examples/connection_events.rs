//! Prints connection monitoring events streamed by Defguard Gateway.
//!
//! Start the Gateway with `--connection-events-socket <PATH>`, then run:
//! `cargo run --example connection_events -- <PATH>`
//! The client must run as the same user as the Gateway, or as root.

use std::{env, os::unix::net::UnixStream, process::ExitCode};

use chrono::{DateTime, Local};
use defguard_gateway::enterprise::firewall::monitor::{
    ConnectionEvent, ConnectionStatus, TrafficDirection,
};
use serde_json::Deserializer;

fn protocol_name(protocol: u8) -> String {
    match protocol {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        58 => "ICMPv6".into(),
        other => format!("proto {other}"),
    }
}

fn endpoint(event: &ConnectionEvent, source: bool) -> String {
    let (ip, port) = if source {
        (event.source, event.source_port)
    } else {
        (event.destination, event.destination_port)
    };
    match (ip, port) {
        (ip, None) => ip.to_string(),
        (ip @ std::net::IpAddr::V4(_), Some(port)) => format!("{ip}:{port}"),
        (ip @ std::net::IpAddr::V6(_), Some(port)) => format!("[{ip}]:{port}"),
    }
}

fn print_event(event: &ConnectionEvent) {
    let timestamp = DateTime::<Local>::from(event.timestamp).format("%Y-%m-%d %H:%M:%S%.3f");
    let direction = match event.direction {
        TrafficDirection::Outbound => "outbound",
        TrafficDirection::Inbound => "inbound",
    };
    let status = match event.status {
        ConnectionStatus::Allowed => "ALLOWED",
        ConnectionStatus::Blocked => "BLOCKED",
    };
    let rule = event
        .rule_id
        .map_or_else(|| "default".to_string(), |id| format!("rule {id}"));
    println!(
        "{timestamp}  {status:7}  {direction:8}  {:6}  {} -> {}  [{rule}]  up {} KB, down {} KB",
        protocol_name(event.protocol),
        endpoint(event, true),
        endpoint(event, false),
        event.upload_kb(),
        event.download_kb(),
    );
}

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("Usage: connection_events <SOCKET PATH>");
        return ExitCode::FAILURE;
    };
    let stream = match UnixStream::connect(&path) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("Failed to connect to {path}: {err}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("Listening for connection events on {path}");

    // Events are newline-delimited JSON objects.
    for event in Deserializer::from_reader(stream).into_iter::<ConnectionEvent>() {
        match event {
            Ok(event) => print_event(&event),
            Err(err) => {
                eprintln!("Connection to Gateway lost: {err}");
                return ExitCode::FAILURE;
            }
        }
    }
    eprintln!("Gateway closed the connection");
    ExitCode::SUCCESS
}
