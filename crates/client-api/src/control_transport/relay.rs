use super::{Dialer, Origin};
use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{oneshot, Semaphore},
};

pub(super) type Observer = Arc<dyn Fn(&'static str, u64) + Send + Sync>;

// Emit only allowlisted stage codes, never arbitrary IO strings, URLs or addresses.
pub(super) fn failure_code(error: &io::Error) -> &'static str {
    match error.to_string().as_str() {
        "physical_dns_timeout" => "physical_dns_timeout",
        "physical_dns_failed" => "physical_dns_failed",
        "physical_network_changed" => "physical_network_changed",
        "physical_discovery_failed" => "physical_discovery_failed",
        "physical_bind_failed" => "physical_bind_failed",
        _ => match error.kind() {
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                "physical_route_unavailable"
            }
            io::ErrorKind::TimedOut => "physical_connect_timeout",
            _ => "physical_connect_failed",
        },
    }
}

pub(super) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(super) type BoxIo = Box<dyn Io>;

struct Local {
    io: BoxIo,
    closed: Pin<Box<dyn Future<Output = io::Result<()>> + Send>>,
}

#[cfg(unix)]
impl Local {
    fn unix(socket: tokio::net::UnixStream) -> io::Result<Self> {
        let closed = super::local_close::watch(&socket)?;
        Ok(Self {
            io: Box::new(socket),
            closed,
        })
    }
}

#[cfg(windows)]
use super::windows_local;

#[cfg(windows)]
pub(super) struct Listener(windows_local::Listener);
#[cfg(windows)]
impl Listener {
    pub fn bind() -> io::Result<Self> {
        windows_local::bind().map(Self)
    }
    pub fn configure(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        self.0.configure(builder)
    }
    async fn accept(&mut self) -> io::Result<Local> {
        Ok(Local {
            io: self.0.accept().await?,
            closed: Box::pin(std::future::pending()),
        })
    }
}

#[cfg(unix)]
pub(super) struct Listener {
    socket: tokio::net::UnixListener,
    path: std::path::PathBuf,
    directory: std::path::PathBuf,
    inode: u64,
}

#[cfg(unix)]
impl Listener {
    pub fn bind() -> io::Result<Self> {
        use std::os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt},
        };
        let directory = std::env::temp_dir().join(format!("nc-{}", uuid::Uuid::new_v4().simple()));
        let path = directory.join("s");
        // Do not silently move private IPC to another disk or use a TCP fallback.
        if path.as_os_str().as_bytes().len() >= 104 {
            return Err(io::Error::other("control_socket_path_too_long"));
        }
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let socket = match tokio::net::UnixListener::bind(&path) {
            Ok(socket) => socket,
            Err(error) => {
                let _ = std::fs::remove_dir(&directory);
                return Err(error);
            }
        };
        let inode = std::fs::symlink_metadata(&path)?.ino();
        Ok(Self {
            socket,
            path,
            directory,
            inode,
        })
    }

    pub fn configure(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder.unix_socket(self.path.clone())
    }

    async fn accept(&mut self) -> io::Result<Local> {
        let (socket, _) = self.socket.accept().await?;
        Local::unix(socket)
    }
}

#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.ino() == self.inode && m.file_type().is_socket())
        {
            let _ = std::fs::remove_file(&self.path);
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

pub(super) struct Relay {
    stop: Option<oneshot::Sender<()>>,
    observer: Arc<std::sync::RwLock<Option<Observer>>>,
}
impl Relay {
    pub fn set_observer(&self, observer: Option<Observer>) {
        *self
            .observer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = observer;
    }
    pub fn is_running(&self) -> bool {
        self.stop.as_ref().is_some_and(|stop| !stop.is_closed())
    }

    pub fn start(mut listener: Listener, dialer: Arc<dyn Dialer>, origin: Origin) -> Self {
        let (stop, mut cancelled) = oneshot::channel();
        let observer = Arc::new(std::sync::RwLock::<Option<Observer>>::new(None));
        let observe = observer.clone();
        tokio::spawn(async move {
            static CONNECTIONS: Semaphore = Semaphore::const_new(16);
            // A slow journal must never occupy async workers or connection
            // capacity, nor create an unbounded queue of blocking log jobs.
            static DIAGNOSTICS: Semaphore = Semaphore::const_new(16);
            loop {
                let mut accepted = tokio::select! {
                    biased;
                    _ = &mut cancelled => break,
                    result = listener.accept() => match result { Ok(socket) => socket, Err(_) => break },
                };
                let Ok(permit) = CONNECTIONS.try_acquire() else {
                    drop(accepted);
                    continue;
                };
                let dialer = dialer.clone();
                let origin = origin.clone();
                let observe = observe.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let started = std::time::Instant::now();
                    let connected = tokio::select! {
                        _ = &mut accepted.closed => return,
                        result = tokio::time::timeout(
                            super::super::HTTP_CONNECT_TIMEOUT,
                            dialer.connect(origin),
                        ) => result,
                    };
                    match connected {
                        Ok(Ok(remote)) => {
                            let _ = bridge(accepted, remote).await;
                        }
                        failed => {
                            // Release both resources before best-effort log IO.
                            drop(accepted);
                            drop(_permit);
                            let code = match &failed {
                                Ok(Err(error)) => failure_code(error),
                                _ => "physical_connect_timeout",
                            };
                            let callback = observe
                                .read()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .clone();
                            if let Some(callback) = callback {
                                let ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                                let Ok(log_permit) = DIAGNOSTICS.try_acquire() else {
                                    return;
                                };
                                tokio::task::spawn_blocking(move || {
                                    let _permit = log_permit;
                                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                        || callback(code, ms),
                                    ));
                                });
                            }
                        }
                    }
                });
            }
        });
        Self {
            stop: Some(stop),
            observer,
        }
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        // Retire the listening endpoint. Accepted streams finish independently,
        // including response bodies whose reqwest client was just reset.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn bridge(local: Local, remote: tokio::net::TcpStream) -> io::Result<()> {
    let Local { io, mut closed } = local;
    let (mut local_read, mut local_write) = tokio::io::split(io);
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload_finished = {
        let upload = pump(&mut local_read, &mut remote_write);
        let download = pump(&mut remote_read, &mut local_write);
        tokio::pin!(upload, download);
        tokio::select! {
            result = &mut upload => {
                result?;
                // Named pipes have no directional shutdown; EOF is disconnect.
                #[cfg(windows)]
                return Ok(());
                #[cfg(unix)]
                {
                    // A Unix peer can close only its write half and still read.
                    tokio::select! {
                        result = &mut download => result?,
                        result = &mut closed => return result,
                    }
                    true
                }
            }
            result = &mut download => { result?; false }
            result = &mut closed => return result,
        }
    };
    // Once the response is complete, its shutdown also marks our own write
    // side closed. Stop watching it and drain any abandoned request bytes:
    // closing IPC with unread upload data would reset the valid response.
    drop(closed);
    if !upload_finished {
        let _ = remote_write.shutdown().await;
        pump(&mut local_read, tokio::io::sink()).await?;
    }
    Ok(())
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
) -> io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(120), read.read(&mut buffer))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        if n == 0 {
            return write.shutdown().await;
        }
        tokio::time::timeout(Duration::from_secs(120), write.write_all(&buffer[..n]))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_disconnect_does_not_wait_for_a_silent_remote_half() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        #[cfg(unix)]
        let (client, local) = {
            let (client, socket) = tokio::net::UnixStream::pair().unwrap();
            (client, Local::unix(socket).unwrap())
        };
        #[cfg(windows)]
        let (client, local) = {
            let (client, socket) = tokio::io::duplex(128);
            (
                client,
                Local {
                    io: Box::new(socket),
                    closed: Box::pin(std::future::pending()),
                },
            )
        };
        let forwarding = tokio::spawn(bridge(local, remote));
        drop(client);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        // Keep the peer's write half open: local cancellation must suffice.
        tokio::time::timeout(Duration::from_secs(1), forwarding)
            .await
            .expect("cancelled local transport retained the remote relay")
            .unwrap()
            .unwrap();
        drop(peer);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_endpoint_is_user_private_and_owned_paths_are_removed() {
        use std::os::unix::fs::PermissionsExt;
        let listener = Listener::bind().unwrap();
        let path = listener.path.clone();
        let directory = listener.directory.clone();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(path.exists());
        drop(listener);
        assert!(!path.exists());
        assert!(!directory.exists());
    }
}
