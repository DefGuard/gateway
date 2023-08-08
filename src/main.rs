use std::{fs::File, io::Write, process};

use defguard_gateway::{
    config::get_config, error::GatewayError, execute_command, gateway::Gateway, init_syslog,
};
use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};

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

    if let Some(pre_up) = &config.pre_up {
        log::info!("Executing specified PRE_UP command: {}", pre_up);
        execute_command(pre_up)?;
    }
    let mut gateway = Gateway::new(config.clone())?;
    gateway.start().await?;

    if let Some(post_down) = &config.post_down {
        log::info!("Executing specified POST_DOWN command: {}", post_down);
        execute_command(post_down)?;
    }

    Ok(())
}
