use std::{
    fs::{File, read_to_string},
    io::Write,
    process,
    sync::{Arc, Mutex},
};

use defguard_gateway::{
    GRPC_CERT_NAME, GRPC_KEY_NAME, VERSION,
    config::get_config,
    enterprise::firewall::api::FirewallApi,
    error::GatewayError,
    execute_command,
    gateway::{Gateway, GatewayServer, TlsConfig, run_stats},
    init_syslog,
    server::run_server,
    setup::GatewaySetupServer,
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

    let cert_dir = &config.cert_dir;
    if !cert_dir.exists() {
        tokio::fs::create_dir_all(cert_dir).await?;
    }
    let tls_config = if let (Some(cert), Some(key)) = (
        read_to_string(cert_dir.join(GRPC_CERT_NAME)).ok(),
        read_to_string(cert_dir.join(GRPC_KEY_NAME)).ok(),
    ) {
        log::info!(
            "Using existing gRPC TLS certificates from {}",
            cert_dir.display()
        );
        TlsConfig {
            grpc_cert_pem: cert,
            grpc_key_pem: key,
        }
    } else {
        log::info!(
            "gRPC TLS certificates not found in {}. They will be generated during setup.",
            cert_dir.display()
        );
        let setup_server = GatewaySetupServer::new();
        let tls_config = setup_server.await_setup(config.clone()).await?;

        let cert_path = cert_dir.join(GRPC_CERT_NAME);
        let key_path = cert_dir.join(GRPC_KEY_NAME);
        tokio::fs::write(cert_path, &tls_config.grpc_cert_pem).await?;
        tokio::fs::write(key_path, &tls_config.grpc_key_pem).await?;
        log::info!(
            "Generated gRPC TLS certificates have been saved to {}",
            cert_dir.display()
        );

        tls_config
    };

    // Launch gRPC server.
    let mut gateway_server = GatewayServer::new(gateway);
    gateway_server.set_tls_config(tls_config);
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
