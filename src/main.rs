use std::{
    fs::File,
    io::Write,
    process,
    sync::{Arc, Mutex},
};

use defguard_gateway::{
    VERSION,
    config::get_config,
    enterprise::firewall::api::FirewallApi,
    error::GatewayError,
    execute_command,
    gateway::{Gateway, GatewayServer, run_stats},
    init_syslog,
    server::run_server,
};
use defguard_version::Version;
#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
use defguard_wireguard_rs::Kernel;
use defguard_wireguard_rs::{Userspace, WGApi};
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
        let version = Version::parse(VERSION)?;
        defguard_version::tracing::init(version, &config.log_level)?;
    }

    if let Some(pre_up) = &config.pre_up {
        log::info!("Executing specified PRE_UP command: {pre_up}");
        execute_command(pre_up)?;
    }

    let ifname = config.ifname.clone();
    let firewall_api = FirewallApi::new(&ifname)?;

    let gateway = if config.userspace {
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

    // Keep track of spawned tasks.
    let mut tasks = JoinSet::new();

    // Optionally, launch HTTP server to report gateway's health.
    if let Some(health_port) = config.health_port {
        tasks.spawn(run_server(
            health_port,
            config.http_bind_address,
            Arc::clone(&gateway.connected),
        ));
    }

    // Launch statistics gathering task.
    let gateway = Arc::new(Mutex::new(gateway));
    tasks.spawn(run_stats(Arc::clone(&gateway), config.stats_period()));

    // Launch gRPC server.
    let gateway_server = GatewayServer::new(config.token.clone(), gateway);
    tasks.spawn(gateway_server.start(config.clone()));

    while let Some(Ok(result)) = tasks.join_next().await {
        result?;
    }

    if let Some(post_down) = &config.post_down {
        log::info!("Executing specified POST_DOWN command: {post_down}");
        execute_command(post_down)?;
    }

    Ok(())
}
