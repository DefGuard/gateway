use crate::gateway::PeerStats;
use std::process::{Command, Output};
use std::{io, str};

/// Runs specified command.
///
/// # Arguments
///
/// * `command` - Command to run
/// * `args` - Command arguments
pub fn run_command(command: &str, args: &[&str]) -> Result<Output, io::Error> {
    let mut command = Command::new(command);
    command.args(args);
    log::debug!("Running command: {:?}", command);
    let output = command.output();
    log::info!("Ran command {:?}", command);
    output
}

/// Parses peer statistics from a line of `wg show INTERFACE dump` command.
fn parse_peer_stats(line: &str) -> PeerStats {
    let mut split = line.split('\t');
    let public_key = split.next().unwrap_or("").to_owned();
    split.next(); // private key, equals (none) for peers
    let endpoint = split.next().unwrap_or("").to_owned();
    let allowed_ips = split.next().unwrap_or("").to_owned();
    let latest_handshake = split.next().unwrap_or("0").parse::<i64>().unwrap_or(0);
    let download = split.next().unwrap_or("0").parse::<i64>().unwrap_or(0);
    let upload = split.next().unwrap_or("0").parse::<i64>().unwrap_or(0);
    let keepalive_interval = split.next().unwrap_or("0").parse::<i64>().unwrap_or(0);

    PeerStats {
        public_key,
        endpoint,
        allowed_ips,
        latest_handshake,
        download,
        upload,
        keepalive_interval,
    }
}

/// Parses peer statistics from `wg show INTERFACE dump` command output.
pub fn parse_wg_stats(stdout: &str) -> Vec<PeerStats> {
    stdout.lines().skip(1).map(parse_peer_stats).collect()
}

/// Transforms vector of bytes to String.
pub fn bytes_to_string(bytes: &[u8]) -> String {
    String::from(std::str::from_utf8(bytes).unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wg_stats_no_peers() {
        let dump = String::from("cBp30oYe0GzbVxHyQa1j8HmUVVhE655kKFdTQ8Lj90c=\trcUoOlw8ExqQo3oJpd20bJca3GJsIKK2IN4UVEn4uFc=\t41824\toff\n");
        let parsed = parse_wg_stats(&dump);
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn test_parse_wg_stats_single_peer() {
        let mut dump = String::from("cBp30oYe0GzbVxHyQa1j8HmUVVhE655kKFdTQ8Lj90c=\trcUoOlw8ExqQo3oJpd20bJca3GJsIKK2IN4UVEn4uFc=\t41824\toff\n");
        dump += "sIhx53MsX+iLk83sssybHrD7M+5m+CmpLzWL/zo8C38=\t(none)\t10.10.10.10:7300\t10.2.0.0/24,10.3.0.0/24\t1652248842\t1000\t2000\t60\n";
        let parsed = parse_wg_stats(&dump);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0],
            PeerStats {
                public_key: "sIhx53MsX+iLk83sssybHrD7M+5m+CmpLzWL/zo8C38=".to_owned(),
                endpoint: "10.10.10.10:7300".to_owned(),
                allowed_ips: "10.2.0.0/24,10.3.0.0/24".to_owned(),
                latest_handshake: 1652248842,
                download: 1000,
                upload: 2000,
                keepalive_interval: 60,
            }
        );
    }

    #[test]
    fn test_parse_wg_stats_multiple_peers() {
        let mut dump = String::from("cBp30oYe0GzbVxHyQa1j8HmUVVhE655kKFdTQ8Lj90c=\trcUoOlw8ExqQo3oJpd20bJca3GJsIKK2IN4UVEn4uFc=\t41824\toff\n");
        dump += "sIhx53MsX+iLk83sssybHrD7M+5m+CmpLzWL/zo8C38=\t(none)\t10.10.10.10:7300\t10.2.0.0/24,10.3.0.0/24\t1652248842\t1000\t2000\t60\n";
        dump += "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=\t(none)\t10.10.10.10:7301\t10.2.0.1/24,10.3.0.1/24\t1652248843\t3000\t4000\t70\n";
        let parsed = parse_wg_stats(&dump);
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed,
            vec![
                PeerStats {
                    public_key: "sIhx53MsX+iLk83sssybHrD7M+5m+CmpLzWL/zo8C38=".to_owned(),
                    endpoint: "10.10.10.10:7300".to_owned(),
                    allowed_ips: "10.2.0.0/24,10.3.0.0/24".to_owned(),
                    latest_handshake: 1652248842,
                    download: 1000,
                    upload: 2000,
                    keepalive_interval: 60,
                },
                PeerStats {
                    public_key: "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=".to_owned(),
                    endpoint: "10.10.10.10:7301".to_owned(),
                    allowed_ips: "10.2.0.1/24,10.3.0.1/24".to_owned(),
                    latest_handshake: 1652248843,
                    download: 3000,
                    upload: 4000,
                    keepalive_interval: 70,
                }
            ]
        );
    }
}
