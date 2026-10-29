#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};
use std::{
    fs::{File, read_to_string},
    io::Write,
    path::Path,
    process,
    sync::{Arc, Mutex},
};
#[cfg(not(unix))]
use tokio::signal;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal as unix_signal};

#[cfg(unix)]
use defguard_gateway::connection_events::run_connection_events_server;
use defguard_gateway::{
    CORE_CLIENT_CERT_NAME, GRPC_CA_CERT_NAME, GRPC_CERT_NAME, GRPC_KEY_NAME, VERSION,
    config::get_config,
    error::GatewayError,
    execute_command,
    gateway::{Gateway, TlsConfig, run_gateway_loop, run_stats},
    init_syslog,
    logging::init_tracing,
    server::run_http_server,
};
use defguard_version::Version;
#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
use defguard_wireguard_rs::Kernel;
use defguard_wireguard_rs::{Userspace, WGApi};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};

#[cfg(unix)]
fn install_shutdown_signal()
-> Result<impl std::future::Future<Output = std::io::Result<()>>, std::io::Error> {
    let mut terminate = unix_signal(SignalKind::terminate())?;
    let mut interrupt = unix_signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => Ok(()),
            _ = interrupt.recv() => Ok(()),
        }
    })
}

#[cfg(not(unix))]
fn install_shutdown_signal()
-> Result<impl std::future::Future<Output = std::io::Result<()>>, std::io::Error> {
    Ok(signal::ctrl_c())
}

fn load_tls_config(cert_dir: &Path) -> Result<Option<TlsConfig>, GatewayError> {
    let grpc_cert = read_to_string(cert_dir.join(GRPC_CERT_NAME)).ok();
    let grpc_key = read_to_string(cert_dir.join(GRPC_KEY_NAME)).ok();
    let grpc_ca_cert = read_to_string(cert_dir.join(GRPC_CA_CERT_NAME)).ok();
    let core_client_cert_pem = read_to_string(cert_dir.join(CORE_CLIENT_CERT_NAME)).ok();

    match (grpc_cert, grpc_key, grpc_ca_cert, core_client_cert_pem) {
        (Some(cert), Some(key), Some(ca_cert), Some(client_cert_pem)) => {
            let core_client_cert_der = defguard_certs::parse_pem_certificate(&client_cert_pem)
                .map_err(|e| {
                    GatewayError::SetupError(format!("Failed to parse Core client cert: {e}"))
                })?
                .to_vec();
            Ok(Some(TlsConfig {
                grpc_cert_pem: cert,
                grpc_key_pem: key,
                grpc_ca_cert_pem: ca_cert,
                core_client_cert_der,
            }))
        }
        _ => Ok(None),
    }
}

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    // Install the ring CryptoProvider as the process-wide default for rustls.
    // Both ring and aws-lc-rs may be pulled in transitively; without an explicit
    // selection rustls panics at runtime when it cannot determine which to use.
    defguard_gateway::init_crypto_provider();

    // parse config and install signal handlers before starting setup or server tasks.
    let config = get_config()?;
    let shutdown_signal = install_shutdown_signal()?;
    tokio::pin!(shutdown_signal);

    // setup pidfile
    let pid = process::id();

    if let Some(pidfile) = &config.pidfile {
        let mut file = File::create(pidfile)?;
        file.write_all(pid.to_string().as_bytes())?;
    }

    let cert_dir = &config.cert_dir;
    if cert_dir.exists() {
        // Probe write access
        let probe = cert_dir.join(".write_test");
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&probe)
            .await
        {
            Ok(_) => {
                let _ = tokio::fs::remove_file(&probe).await;
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(GatewayError::SetupError(format!(
                    "Certificate directory '{}' exists but is not writable. \
                     Please check directory permissions.",
                    cert_dir.display()
                )));
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        tokio::fs::create_dir_all(cert_dir).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(cert_dir, Permissions::from_mode(0o700)).await?;
    }

    let maybe_tls_config = load_tls_config(cert_dir)?;

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
    let gateway = if config.userspace {
        let wgapi = WGApi::<Userspace>::new(ifname)?;
        Gateway::new(config.clone(), wgapi)?
    } else {
        #[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
        {
            let wgapi = WGApi::<Kernel>::new(ifname)?;
            Gateway::new(config.clone(), wgapi)?
        }
        #[cfg(any(target_os = "macos", target_os = "netbsd"))]
        {
            eprintln!("Gateway only supports userspace WireGuard for macOS");
            return Ok(());
        }
    };

    // Keep track of background tasks.
    let mut tasks = JoinSet::new();

    // Optionally, launch HTTP server to report gateway's health.
    if let Some(health_port) = config.health_port {
        tasks.spawn(run_http_server(
            health_port,
            config.http_bind_address,
            Arc::clone(&gateway.connected),
        ));
    }

    // Optionally, stream connection monitoring events to local clients.
    #[cfg(unix)]
    if let Some(path) = &config.connection_events_socket {
        #[cfg(not(target_os = "linux"))]
        log::warn!("Connection monitoring is only supported on Linux, no events will be sent");
        tasks.spawn(run_connection_events_server(
            path.clone(),
            gateway.connection_events(),
        ));
    }

    // Launch statistics gathering task.
    let gateway = Arc::new(Mutex::new(gateway));
    tasks.spawn(run_stats(Arc::clone(&gateway), config.stats_period()));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut gateway_task = tokio::spawn(run_gateway_loop(
        config.clone(),
        gateway,
        Arc::clone(&logs_rx),
        maybe_tls_config,
        shutdown_rx,
    ));
    let mut shutdown_error = None;

    tokio::select! {
        biased;
        result = &mut shutdown_signal => {
            if let Err(err) = result {
                log::error!("Failed to listen for shutdown signal: {err}");
                shutdown_error = Some(err);
            }
            let _ = shutdown_tx.send(true);
            if let Err(err) = (&mut gateway_task).await {
                log::error!("Gateway task failed: {err}");
            }
        }
        result = &mut gateway_task => {
            if let Err(err) = result {
                log::error!("Gateway task failed: {err}");
            }
        }
        result = tasks.join_next() => {
            if let Some(Err(err)) = result {
                log::error!("Background task failed: {err}");
            }
            let _ = shutdown_tx.send(true);
            if let Err(err) = (&mut gateway_task).await {
                log::error!("Gateway task failed: {err}");
            }
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}

    if let Some(post_down) = &config.post_down {
        log::info!("Executing specified POST_DOWN command: {post_down}");
        execute_command(post_down)?;
    }

    if let Some(err) = shutdown_error {
        return Err(err.into());
    }

    Ok(())
}
