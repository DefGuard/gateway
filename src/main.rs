use std::{
    fs::{File, Permissions, read_to_string},
    io::Write,
    os::unix::fs::PermissionsExt,
    process,
    sync::{Arc, Mutex},
};

use defguard_gateway::{
    GRPC_CERT_NAME, GRPC_KEY_NAME, VERSION,
    config::get_config,
    enterprise::firewall::api::FirewallApi,
    error::GatewayError,
    execute_command,
    gateway::{Gateway, TlsConfig, run_gateway_loop, run_stats},
    init_syslog,
    logging::init_tracing,
    server::run_server,
    setup::run_setup,
};
use defguard_version::Version;
#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
use defguard_wireguard_rs::Kernel;
use defguard_wireguard_rs::{Userspace, WGApi};
use tokio::{sync::mpsc, task::JoinSet};

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

    let cert_dir = &config.cert_dir;
    if !cert_dir.exists() {
        tokio::fs::create_dir_all(cert_dir).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(cert_dir, Permissions::from_mode(0o700)).await?;
    }

    let (grpc_cert, grpc_key) = (
        read_to_string(cert_dir.join(GRPC_CERT_NAME)).ok(),
        read_to_string(cert_dir.join(GRPC_KEY_NAME)).ok(),
    );

    let needs_setup = grpc_cert.is_none() || grpc_key.is_none();

    // TODO: The channel size may need to be adjusted or some other approach should be used
    // to avoid dropping log messages.
    let (logs_tx, logs_rx) = mpsc::channel(200);
    let logs_rx = Arc::new(tokio::sync::Mutex::new(logs_rx));

    // setup logging
    if config.use_syslog {
        if let Err(error) = init_syslog(&config, pid) {
            log::error!("Unable to initialize syslog. Is the syslog daemon running?");
            return Err(error);
        }
    } else {
        init_tracing(&Version::parse(VERSION)?, &config.log_level, Some(logs_tx));
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

    let tls_config = if needs_setup {
        log::info!(
            "gRPC TLS certificates not found in {}. They will be generated during setup.",
            cert_dir.display()
        );
        run_setup(&config, cert_dir, Arc::clone(&logs_rx)).await?
    } else if let (Some(cert), Some(key)) = (grpc_cert, grpc_key) {
        log::info!(
            "Using existing gRPC TLS certificates from {}",
            cert_dir.display()
        );
        TlsConfig {
            grpc_cert_pem: cert,
            grpc_key_pem: key,
        }
    } else {
        return Err(GatewayError::SetupError(
            "gRPC TLS certificates are missing after setup".to_string(),
        ));
    };

    // Launch gRPC server (with purge-triggered setup loop).
    tasks.spawn(run_gateway_loop(
        config.clone(),
        cert_dir.clone(),
        gateway,
        Arc::clone(&logs_rx),
        tls_config,
    ));

    while let Some(Ok(result)) = tasks.join_next().await {
        result?;
    }

    if let Some(post_down) = &config.post_down {
        log::info!("Executing specified POST_DOWN command: {post_down}");
        execute_command(post_down)?;
    }

    Ok(())
}
