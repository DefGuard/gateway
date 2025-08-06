use std::{fs::File, io::Write, process, sync::Arc};

use defguard_gateway::{
    config::get_config, enterprise::firewall::api::FirewallApi, error::GatewayError,
    execute_command, gateway::Gateway, init_syslog, server::run_server,
};
#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
use defguard_wireguard_rs::Kernel;
use defguard_wireguard_rs::{Userspace, WGApi};
use env_logger::{init_from_env, Env, DEFAULT_FILTER_ENV};
use tokio::task::JoinSet;

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

    let ifname = config.ifname.clone();
    let firewall_api = FirewallApi::new(&ifname)?;

    let mut gateway = if config.userspace {
        let wgapi = WGApi::<Userspace>::new(ifname)?;
        Gateway::new(config.clone(), wgapi, firewall_api)?
    } else {
        #[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
        {
            let wgapi = WGApi::<Kernel>::new(ifname)?;
            Gateway::new(config.clone(), wgapi, firewall_api)?
        }
        #[cfg(any(target_os = "macos", target_os = "netbsd"))]
        {
            eprintln!("Gateway only supports userspace WireGuard for macOS");
            return Ok(());
        }
    };

    let mut tasks = JoinSet::new();
    if let Some(health_port) = config.health_port {
        tasks.spawn(run_server(
            health_port,
            config.http_bind_address,
            Arc::clone(&gateway.connected),
        ));
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
