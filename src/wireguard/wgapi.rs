use super::{Host, SOCKET_BUFFER_LENGTH};
#[cfg(target_os = "linux")]
use crate::wireguard::netlink::{get_host, set_host};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    str::from_utf8,
    string::ToString,
    time::Duration,
};

pub struct WGApi {
    ifname: String,
    userspace: bool,
}

impl WGApi {
    pub fn new(ifname: String, userspace: bool) -> Self {
        Self { ifname, userspace }
    }

    fn socket(&self) -> io::Result<UnixStream> {
        let path = format!("/var/run/wireguard/{}.sock", self.ifname);
        let socket = UnixStream::connect(&path)?;
        socket.set_read_timeout(Some(Duration::new(3, 0)))?;
        Ok(socket)
    }

    // FIXME: currenty other errors are ignored and result in 0 being returned.
    fn parse_errno(buf: &[u8]) -> u32 {
        for line in buf.split(|&char| char == b'\n') {
            if let Some(index) = line.iter().position(|&char| char == b'=') {
                let key = from_utf8(&line[..index]).unwrap();
                let value = from_utf8(&line[index + 1..]).unwrap();
                if key == "errno" {
                    return value.parse().unwrap_or_default();
                }
            }
        }
        0
    }

    pub fn read_configuration(&self) -> io::Result<Host> {
        if self.userspace {
            let mut socket = self.socket()?;
            socket.write_all(b"get=1\n\n")?;

            let mut buf = [0u8; SOCKET_BUFFER_LENGTH];
            let count = socket.read(&mut buf)?;
            Ok(Host::parse_from(&buf[..count]))
        } else {
            #[cfg(target_os = "linux")]
            {
                get_host(&self.ifname)
            }
            #[cfg(not(target_os = "linux"))]
            Err(io::Error::new(
                io::ErrorKind::Other,
                "kernel support is not available on this platform",
            ))
        }
    }

    pub fn write_configuration(&self, host: &Host) -> io::Result<()> {
        if self.userspace {
            let mut socket = self.socket()?;
            socket.write_all(b"set=1\n")?;
            socket.write_all(host.to_string().as_bytes())?;
            socket.write_all(b"\n")?;

            let mut buf = [0u8; SOCKET_BUFFER_LENGTH];
            let count = socket.read(&mut buf)?;
            if Self::parse_errno(&buf[..count]) != 0 {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "write configuration error",
                ))
            } else {
                Ok(())
            }
        } else {
            #[cfg(target_os = "linux")]
            {
                set_host(&self.ifname, host)
            }
            #[cfg(not(target_os = "linux"))]
            Err(io::Error::new(
                io::ErrorKind::Other,
                "kernel support is not available on this platform",
            ))
        }
    }
}
