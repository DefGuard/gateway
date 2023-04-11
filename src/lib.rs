#![allow(clippy::derive_partial_eq_without_eq)]

pub mod config;
mod error;
pub mod gateway;
mod utils;
pub mod wireguard;

pub mod proto {
    tonic::include_proto!("gateway");
}

#[macro_use]
extern crate log;

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
