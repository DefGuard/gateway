use crate::wgservice::PeerStats;
use std::process::{Command, Output};
use std::{io, str};

pub fn run_command(command: &str, args: &[&str]) -> Result<Output, io::Error> {
    let mut command = Command::new(command);
    command.args(args);
    log::debug!("Running command: {:?}", command);
    let output = command.output();
    log::info!("Ran command {:?}", command);
    output
}

fn parse_peer_stats(line: &str) -> PeerStats {
    let mut split = line.split("\t");
    let peer = String::from(split.next().unwrap_or(""));
    let received = split.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
    let sent = split.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
    PeerStats {peer, received, sent}
}

pub fn parse_wg_stats(stdout: &str) -> Vec<PeerStats> {
    stdout.lines().map(parse_peer_stats).collect()
}

pub fn bytes_to_string(bytes: &Vec<u8>) -> String {
    String::from(std::str::from_utf8(bytes).unwrap_or(""))
}