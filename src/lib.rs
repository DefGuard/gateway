#![allow(clippy::derive_partial_eq_without_eq)]

pub mod config;
pub mod error;
pub mod gateway;
pub mod wireguard;

pub mod proto {
    tonic::include_proto!("gateway");
}

#[macro_use]
extern crate log;

use crate::{config::Config, error::GatewayError};
use std::str::FromStr;
use syslog::{BasicLogger, Facility, Formatter3164};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Masks object's field with "***" string.
/// Used to log sensitive/secret objects.
#[macro_export]
macro_rules! mask {
    ($object:expr, $field:ident) => {{
        let mut object = $object.clone();
        object.$field = String::from("***");
        object
    }};
}

/// Initialize logging to syslog.
pub fn init_syslog(config: &Config, pid: u32) -> Result<(), GatewayError> {
    let formatter = Formatter3164 {
        facility: Facility::from_str(&config.syslog_facility).unwrap_or_default(),
        hostname: None,
        process: "defguard-gateway".into(),
        pid,
    };
    let logger = syslog::unix_custom(formatter, &config.syslog_socket)?;
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))?;
    log::set_max_level(log::LevelFilter::Debug);
    Ok(())
}
