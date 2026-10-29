//! Streams connection monitoring events to local clients over a Unix socket.
//!
//! Each event is sent as a single line of JSON (see [`ConnectionEvent`]).

use std::{
    fs::{self, Permissions},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::broadcast::{self, error::RecvError},
    task::JoinSet,
};

use crate::enterprise::firewall::monitor::ConnectionEvent;

/// Removes the socket file when the server stops, including when its task is aborted on quit.
struct SocketFile<'a>(&'a Path);

impl Drop for SocketFile<'_> {
    fn drop(&mut self) {
        match fs::remove_file(self.0) {
            Ok(()) => debug!("Removed {}", self.0.display()),
            Err(err) => warn!("Failed to remove {}: {err}", self.0.display()),
        }
    }
}

/// Accept clients on Unix socket `path` and stream `events` to each of them.
/// The socket file is removed when the server stops.
pub async fn run_connection_events_server(
    path: PathBuf,
    events: broadcast::Sender<ConnectionEvent>,
) {
    // Remove a socket left over by a previous run.
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            error!("Failed to remove {}: {err}", path.display());
            return;
        }
    }
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            error!("Failed to bind to {}: {err}", path.display());
            return;
        }
    };
    let _socket_file = SocketFile(&path);
    if let Err(err) = fs::set_permissions(&path, Permissions::from_mode(0o600)) {
        error!("Failed to set permissions of {}: {err}", path.display());
        return;
    }
    info!("Connection events available on {}", path.display());

    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, _)) => {
                    if is_authorized(&stream) {
                        clients.spawn(stream_events(stream, events.subscribe()));
                    }
                }
                Err(err) => warn!("Failed to accept connection events client: {err}"),
            },
            Some(_) = clients.join_next() => {}
        }
    }
}

/// Only allow clients running as the same user as the Gateway, or root. This also covers clients
/// which connected before the socket permissions were restricted.
fn is_authorized(stream: &UnixStream) -> bool {
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == 0 || cred.uid() == unsafe { libc::geteuid() } => true,
        Ok(cred) => {
            warn!(
                "Rejected connection events client running as user {}",
                cred.uid()
            );
            false
        }
        Err(err) => {
            warn!("Failed to get connection events client credentials: {err}");
            false
        }
    }
}

async fn stream_events(stream: UnixStream, mut events: broadcast::Receiver<ConnectionEvent>) {
    debug!("Connection events client connected");
    let (mut reader, mut writer) = stream.into_split();
    let mut buf = [0; 64];
    loop {
        let event = tokio::select! {
            // Clients aren't expected to send anything; this detects disconnection.
            result = reader.read(&mut buf) => match result {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            },
            result = events.recv() => match result {
                Ok(event) => event,
                Err(RecvError::Lagged(count)) => {
                    warn!("Connection events client is too slow, dropped {count} events");
                    continue;
                }
                Err(RecvError::Closed) => break,
            },
        };
        let mut line = match serde_json::to_vec(&event) {
            Ok(line) => line,
            Err(err) => {
                error!("Failed to serialize connection event {event:?}: {err}");
                continue;
            }
        };
        line.push(b'\n');
        if writer.write_all(&line).await.is_err() {
            break;
        }
    }
    debug!("Connection events client disconnected");
}
