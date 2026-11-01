use reqwest::{Client, Url};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, RwLock},
};
use tokio::net::TcpStream;

#[cfg(any(target_os = "linux", test))]
mod linux_wire;
#[cfg(unix)]
mod local_close;
mod physical;
mod relay;
#[cfg(windows)]
mod windows_local;

#[derive(Clone)]
pub(super) struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

pub(super) type DialFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
pub(super) trait Dialer: Send + Sync {
    fn connect(&self, origin: Origin) -> DialFuture;
}

pub(super) struct SystemDialer;

async fn race_connections(attempts: Vec<DialFuture>) -> io::Result<TcpStream> {
    use futures_util::{stream::FuturesUnordered, StreamExt};
    // Native resolvers bound their answers to at most 256 records. Admission
    // to actual TCP sockets is separately limited by CONNECTING below.
    if attempts.is_empty() || attempts.len() > 256 {
        return Err(io::Error::other("physical_connect_failed"));
    }
    let mut running = FuturesUnordered::new();
    for (index, attempt) in attempts.into_iter().enumerate() {
        running.push(async move {
            tokio::time::sleep(std::time::Duration::from_millis(index as u64 * 250)).await;
            attempt.await
        });
    }
    while let Some(result) = running.next().await {
        if let Ok(stream) = result {
            return Ok(stream);
        }
    }
    Err(io::Error::other("physical_connect_failed"))
}

async fn snapshot() -> io::Result<physical::Snapshot> {
    native_read(physical::snapshot).await
}

async fn native_read<T: Send + 'static>(
    read: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    // Keep permits inside blocking work: cancelling an HTTP future cannot
    // otherwise bound the number of still-running OS metadata subprocesses.
    static READERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
    let permit = READERS
        .acquire()
        .await
        .map_err(|_| io::Error::other("physical_discovery_failed"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read()
    })
    .await
    .map_err(|_| io::Error::other("physical_discovery_failed"))?
}

impl Dialer for SystemDialer {
    fn connect(&self, origin: Origin) -> DialFuture {
        Box::pin(async move {
            let before = snapshot().await?;
            let mut families: Vec<DialFuture> = Vec::new();
            for ipv6 in [true, false] {
                if if ipv6 {
                    before.ipv6.is_none()
                } else {
                    before.ipv4.is_none()
                } {
                    continue;
                }
                let network = before.clone();
                let target = origin.clone();
                families.push(Box::pin(async move {
                    connect_family(network, target, ipv6).await
                }));
            }
            // DNS and TCP for both families share the caller's original dial
            // deadline. A silent DNS family/address cannot starve the other.
            race_connections(families).await
        })
    }
}

async fn connect_family(
    before: physical::Snapshot,
    origin: Origin,
    ipv6: bool,
) -> io::Result<TcpStream> {
    let mut family = before.clone();
    if ipv6 {
        family.ipv4 = None;
    } else {
        family.ipv6 = None;
    }
    let host = origin.host.clone();
    let addresses = if let Ok(address) = host.parse::<std::net::IpAddr>() {
        family.interface(address)?;
        vec![address]
    } else {
        resolve_host(host, family).await?
    };
    if snapshot().await? != before {
        return Err(io::Error::other("physical_network_changed"));
    }
    let attempts = addresses
        .into_iter()
        .map(|address| {
            let network = before.clone();
            Box::pin(async move { connect_address(network, address, origin.port).await })
                as DialFuture
        })
        .collect();
    race_connections(attempts).await
}

#[cfg(not(target_os = "linux"))]
async fn resolve_host(
    host: String,
    family: physical::Snapshot,
) -> io::Result<Vec<std::net::IpAddr>> {
    native_read(move || physical::resolve(&host, &family)).await
}

#[cfg(target_os = "linux")]
async fn resolve_host(
    host: String,
    family: physical::Snapshot,
) -> io::Result<Vec<std::net::IpAddr>> {
    let selected = family.clone();
    let servers = native_read(move || physical::dns_servers(&selected)).await?;
    linux_wire::resolve(&host, &family, &servers, physical::bind_socket).await
}

async fn connect_address(
    before: physical::Snapshot,
    address: std::net::IpAddr,
    port: u16,
) -> io::Result<TcpStream> {
    static CONNECTING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
    let _permit = CONNECTING
        .acquire()
        .await
        .map_err(|_| io::Error::other("physical_connect_failed"))?;
    let interface = before.interface(address)?;
    let remote = std::net::SocketAddr::new(address, port);
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(remote),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    physical::bind_socket(&socket, interface, remote)?;
    let stream: std::net::TcpStream = socket.into();
    let stream = tokio::net::TcpSocket::from_std_stream(stream)
        .connect(remote)
        .await?;
    // Never forward TLS bytes after a NIC disappears or its index is reused.
    if snapshot().await?.interface(address)? != interface
        || !interface.addresses.contains(&stream.local_addr()?.ip())
    {
        return Err(io::Error::other("physical_network_changed"));
    }
    Ok(stream)
}

pub(super) struct ControlClient {
    pub client: Client,
    origin: Origin,
    _relay: relay::Relay,
}

impl ControlClient {
    pub fn new(url: &Url, dialer: Arc<dyn Dialer>) -> io::Result<Self> {
        Self::build(url, dialer, Client::builder())
    }

    fn build(
        url: &Url,
        dialer: Arc<dyn Dialer>,
        builder: reqwest::ClientBuilder,
    ) -> io::Result<Self> {
        let origin = Origin {
            scheme: url.scheme().to_owned(),
            host: url
                .host_str()
                .ok_or_else(|| io::Error::other("control_origin_invalid"))?
                .trim_matches(['[', ']'])
                .to_owned(),
            port: url
                .port_or_known_default()
                .ok_or_else(|| io::Error::other("control_origin_invalid"))?,
        };
        let listener = relay::Listener::bind()?;
        let expected = origin.clone();
        let scheme = url.scheme().to_owned();
        let builder = builder
            .no_proxy()
            .connect_timeout(super::HTTP_CONNECT_TIMEOUT)
            .timeout(super::HTTP_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                let url = attempt.url();
                if url.scheme() != scheme
                    || url.host_str().map(|s| s.trim_matches(['[', ']']))
                        != Some(expected.host.as_str())
                    || url.port_or_known_default() != Some(expected.port)
                {
                    attempt.stop()
                } else if attempt.previous().len() >= 10 {
                    attempt.error("control_redirect_limit")
                } else {
                    attempt.follow()
                }
            }));
        let client = listener
            .configure(builder)
            .build()
            .map_err(|_| io::Error::other("control_client_unavailable"))?;
        let relay = relay::Relay::start(listener, dialer, origin.clone());
        Ok(Self {
            client,
            origin,
            _relay: relay,
        })
    }

    pub async fn execute(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, super::ClientApiError> {
        let url = request.url();
        if url.scheme() != self.origin.scheme
            || url.host_str().map(|s| s.trim_matches(['[', ']'])) != Some(self.origin.host.as_str())
            || url.port_or_known_default() != Some(self.origin.port)
        {
            return Err(super::ClientApiError::InvalidPayload {
                code: "control_origin_mismatch",
            });
        }
        Ok(self.client.execute(request).await?)
    }
}

pub(super) struct Slot {
    origin: Url,
    dialer: Arc<dyn Dialer>,
    current: RwLock<Option<Arc<ControlClient>>>,
}

impl Slot {
    pub fn new(origin: Url, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            origin,
            dialer,
            current: RwLock::new(None),
        }
    }

    pub fn reset(&self) {
        self.current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    pub async fn execute(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, super::ClientApiError> {
        let client = {
            let mut current = self
                .current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A stopped accept task drops its cancellation receiver. Retire
            // that client before a NEW request; never replay one already sent.
            if current
                .as_ref()
                .is_none_or(|client| !client._relay.is_running())
            {
                *current = Some(Arc::new(
                    ControlClient::new(&self.origin, self.dialer.clone())
                        .map_err(|_| super::ClientApiError::ControlTransportUnavailable)?,
                ));
            }
            current.as_ref().unwrap().clone()
        };
        client.execute(request).await
    }
}

#[cfg(test)]
mod tests;
