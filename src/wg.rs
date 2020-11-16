use boringtun::device::drop_privileges::*;
use boringtun::device::*;
use boringtun::noise::Verbosity;
use std::os::unix::net::UnixDatagram;
use std::process::exit;

pub fn create_interface(name: &str) {
    let tun_name = name;
    let n_threads = 4;
    let log_level = Verbosity::None; // "silent" / "info" / "debug"
    let use_connected_socket = true;
    let use_multi_queue = true;
    let enable_drop_privileges = true;

    // Create a socketpair to communicate between forked processes
    let (sock, _) = UnixDatagram::pair().unwrap();
    let _ = sock.set_nonblocking(true);

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
            sock.send(&[0]).unwrap();
            exit(1);
        }
    };

    if enable_drop_privileges {
        if let Err(e) = drop_privileges() {
            eprintln!("Failed to drop privileges: {:?}", e);
            sock.send(&[0]).unwrap();
            exit(1);
        }
    }

    drop(sock);
    device_handle.wait();
}
