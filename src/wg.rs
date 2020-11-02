use boringtun::device::drop_privileges::*;
use boringtun::device::*;
use boringtun::noise::Verbosity;
use daemonize::Daemonize; // FIXME: remove
use std::fs::File;
use std::os::unix::net::UnixDatagram;
use std::process::exit;

pub fn create_interface(name: &String) {
    let background = false;
    let tun_name = name;
    let n_threads = 4;
    let log_level = Verbosity::None; // "silent" / "info" / "debug"
    let log = "/tmp/boringtun.log";
    let err_log = "/tmp/boringtun_err.log";
    let use_connected_socket = true;
    let use_multi_queue = true;
    let enable_drop_privileges = true;

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    if background {
        let stdout =
            File::create(&log).unwrap_or_else(|_| panic!("Could not create log file {}", log));
        let stderr = File::create(&err_log)
            .unwrap_or_else(|_| panic!("Could not create error log file {}", err_log));

        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .stdout(stdout)
            .stderr(stderr)
            .exit_action(move || {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("BoringTun started successfully");
                } else {
                    eprintln!("BoringTun failed to start");
                    exit(1);
                };
            });

        match daemonize.start() {
            Ok(_) => println!("Success, daemonized"),
            Err(e) => {
                eprintln!("Error, {}", e);
                exit(1);
            }
        }
    }

    let config = DeviceConfig {
        n_threads,
        log_level,
        use_connected_socket,
        #[cfg(target_os = "linux")]
        use_multi_queue,
    };

    let mut device_handle = match DeviceHandle::new(&tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            eprintln!("Failed to initialize tunnel: {:?}", e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if enable_drop_privileges {
        if let Err(e) = drop_privileges() {
            eprintln!("Failed to drop privileges: {:?}", e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    device_handle.wait();
}
