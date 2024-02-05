use std::{fs::File, io::Write, process, sync::Arc};

use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};
use tokio::task::JoinSet;

use defguard_gateway::{
    config::get_config, error::GatewayError, execute_command, gateway::Gateway, init_syslog,
    server::run_server,
};

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
    if config.use_syslog {
        if let Err(error) = init_syslog(&config, pid) {
            log::error!("Unable to initialize syslog. Is the syslog daemon running?");
            return Err(error);
        }
    } else {
        init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    }

    if let Some(pre_up) = &config.pre_up {
        log::info!("Executing specified PRE_UP command: {pre_up}");
        execute_command(pre_up)?;
    }

    let mut gateway = Gateway::new(config.clone())?;

    let mut tasks = JoinSet::new();
    if let Some(health_port) = config.health_port {
        tasks.spawn(run_server(health_port, Arc::clone(&gateway.connected)));
    }
    tasks.spawn(async move { gateway.start().await });
    while let Some(Ok(result)) = tasks.join_next().await {
        result?;
    }

    if let Some(post_down) = &config.post_down {
        log::info!("Executing specified POST_DOWN command: {post_down}");
        execute_command(post_down)?;
    }

    Ok(())
}
