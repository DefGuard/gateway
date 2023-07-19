use defguard_gateway::{config::get_config, error::GatewayError, gateway::Gateway, init_syslog};
use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};
use std::{fs::File, io::Write, process};

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    // parse config
    let config = get_config()?;

    // setup pidfile
    let pid = process::id();

    if let Some(pidfile) = &config.pidfile {
        let mut file = File::create(pidfile)?;
        file.write_all(pid.to_string().as_bytes())?;
    }

    // setup logging
    println!("Initializing logging facilities");
    if config.use_syslog {
        if let Err(error) = init_syslog(&config, pid) {
            eprintln!("Unable to initialize syslog. Is the syslog daemon running?");
            return Err(error);
        };
    } else {
        init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    }

    // run gateway
    let mut gateway = Gateway::new(config)?;
    gateway.start().await?;
    Ok(())
}
