use std::{
    fs::File,
    io::Write,
    process,
    sync::{Arc, Mutex},
};

#[cfg(not(target_os = "macos"))]
use defguard_wireguard_rs::Kernel;
use defguard_wireguard_rs::{Userspace, WGApi};
use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};
use tokio::task::JoinSet;

use defguard_gateway::{
    config::get_config,
    error::GatewayError,
    execute_command,
    gateway::{run_stats, Gateway, GatewayServer},
    init_syslog,
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
        log::info!("Executing specified pre-up command: {pre_up}");
        execute_command(pre_up)?;
    }

    let ifname = config.ifname.clone();
    let gateway = if config.userspace {
        let wgapi = WGApi::<Userspace>::new(ifname)?;
        Gateway::new(wgapi)?
    } else {
        #[cfg(not(target_os = "macos"))]
        {
            let wgapi = WGApi::<Kernel>::new(ifname)?;
            Gateway::new(wgapi)?
        }
        #[cfg(target_os = "macos")]
        {
            eprintln!("On macOS, gateway only supports userspace WireGuard");
            return Ok(());
        }
    };
    let mut tasks = JoinSet::new();
    if let Some(health_port) = config.health_port {
        tasks.spawn(run_server(health_port, Arc::clone(&gateway.connected)));
    }

    let gateway = Arc::new(Mutex::new(gateway));
    tasks.spawn(run_stats(Arc::clone(&gateway), config.stats_period()));

    let gateway_server = GatewayServer::new(gateway);
    tasks.spawn(gateway_server.start(config.clone()));

    // Await the tasks.
    while let Some(Ok(result)) = tasks.join_next().await {
        result?;
        log::debug!("Task ended");
    }

    if let Some(post_down) = &config.post_down {
        log::info!("Executing specified post-down command: {post_down}");
        execute_command(post_down)?;
    }

    Ok(())
}
