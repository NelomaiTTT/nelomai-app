use reqwest::{Client, Url};
use std::{
    future::Future,
    io,
    net::IpAddr,
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
use relay::Observer;

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
    let mut last_error = io::Error::other("physical_connect_failed");
    while let Some(result) = running.next().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

async fn snapshot() -> io::Result<physical::Snapshot> {
    #[cfg(test)]
    if let Some(before) = tests::fixture_snapshot() {
        return Ok(before);
    }
    native_read(physical::snapshot)
        .await
        .map_err(|e| io::Error::new(e.kind(), "physical_discovery_failed"))
}

async fn native_read<T: Send + 'static>(
    read: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    static READERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
    native_read_in(&READERS, read).await
}

// Uncancellable scoped DNS calls must not occupy snapshot/NIC revalidation
// capacity after the async DNS budget expires and the static route is selected.
async fn native_dns_read<T: Send + 'static>(
    read: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    static READERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
    native_read_in(&READERS, read).await
}

async fn native_read_in<T: Send + 'static>(
    readers: &'static tokio::sync::Semaphore,
    read: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    // Keep permits inside blocking work. Cancelling a caller releases neither
    // a live OS worker's admission nor a cancelled queued closure into it.
    let permit = readers
        .acquire()
        .await
        .map_err(|_| io::Error::other("physical_discovery_failed"))?;
    crate::blocking::read(move || {
        let _permit = permit;
        read()
    })
    .await
}

impl Dialer for SystemDialer {
    fn connect(&self, origin: Origin) -> DialFuture {
        Box::pin(async move {
            let before = snapshot().await?;
            let port = origin.port;
            if let Ok(ip) = origin.host.parse::<IpAddr>() {
                before.interface(ip)?;
                return connect_batch(before, port, vec![ip]).await;
            }
            let attempts = physical_dials(before, port, &origin.host).await?;
            futures_util::future::select_ok(attempts)
                .await
                .map(|(stream, _)| stream)
        })
    }
}

type FamilyQuery = futures_util::future::BoxFuture<'static, io::Result<DialFuture>>;
type Queries = futures_util::stream::FuturesUnordered<FamilyQuery>;

// Poll every available family of both names under one DNS deadline. Hold
// secondary answers without opening sockets until all primary DNS has failed.
async fn physical_dials(
    before: physical::Snapshot,
    port: u16,
    host: &str,
) -> io::Result<Vec<DialFuture>> {
    use futures_util::StreamExt;
    let policy = crate::panel_dns::PanelDnsFallback::for_host(host);
    let deadline = policy.as_ref().map(|p| p.deadline);
    let mut primary = family_queries(&before, port, host, deadline);
    let mut secondary = policy
        .as_ref()
        .and_then(|p| p.secondary)
        .map(|name| family_queries(&before, port, name, deadline))
        .unwrap_or_default();
    let mut held = Vec::new();
    let mut last_error = io::Error::other("physical_egress_unavailable");
    while !primary.is_empty() {
        tokio::select! {
            biased;
            Some(answer) = primary.next() => match answer {
                Ok(dial) => return Ok(selected_dials(vec![dial], primary)),
                Err(error) => last_error = error,
            },
            Some(answer) = secondary.next(), if !secondary.is_empty() => {
                if let Ok(dial) = answer { held.push(dial); }
            }
        }
    }
    while held.is_empty() {
        match secondary.next().await {
            Some(Ok(dial)) => held.push(dial),
            Some(Err(_)) => continue,
            None => break,
        }
    }
    if !held.is_empty() {
        return Ok(selected_dials(held, secondary));
    }
    let policy = policy.ok_or(last_error)?;
    before.interface(policy.address.ip())?;
    Ok(vec![connect_batch(before, port, vec![policy.address.ip()])])
}

// The caller can dial the first usable answer immediately. A later answer
// from this same name still races its TCP sibling, subject to the DNS deadline.
fn selected_dials(mut ready: Vec<DialFuture>, remaining: Queries) -> Vec<DialFuture> {
    for query in remaining {
        ready.push(Box::pin(async move { query.await?.await }));
    }
    ready
}

fn family_queries(
    before: &physical::Snapshot,
    port: u16,
    name: &str,
    deadline: Option<tokio::time::Instant>,
) -> Queries {
    let queries = Queries::new();
    for ipv6 in [true, false] {
        let mut family = before.clone();
        if ipv6 {
            family.ipv4 = None;
        } else {
            family.ipv6 = None;
        }
        if family.ipv4.is_none() && family.ipv6.is_none() {
            continue;
        }
        let delay_v4 = !ipv6 && before.ipv6.is_some();
        let network = before.clone();
        let name = name.to_owned();
        queries.push(Box::pin(async move {
            let query = async {
                if delay_v4 {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                let mut ips = resolve_host(name, family.clone()).await?;
                ips.retain(|ip| family.interface(*ip).is_ok());
                if ips.is_empty() {
                    return Err(io::Error::from(io::ErrorKind::NotFound));
                }
                Ok(connect_batch(network, port, ips))
            };
            let result = match deadline {
                Some(end) => tokio::time::timeout_at(end, query)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "physical_dns_timeout"))?,
                None => query.await,
            };
            result.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    if e.kind() == io::ErrorKind::TimedOut {
                        "physical_dns_timeout"
                    } else {
                        "physical_dns_failed"
                    },
                )
            })
        }));
    }
    queries
}

fn connect_batch(before: physical::Snapshot, port: u16, addresses: Vec<IpAddr>) -> DialFuture {
    Box::pin(async move {
        if snapshot().await? != before {
            return Err(io::Error::other("physical_network_changed"));
        }
        let attempts = addresses
            .into_iter()
            .map(|address| Box::pin(connect_address(before.clone(), address, port)) as DialFuture)
            .collect();
        race_connections(attempts).await
    })
}

#[cfg(not(target_os = "linux"))]
async fn resolve_host(
    host: String,
    family: physical::Snapshot,
) -> io::Result<Vec<std::net::IpAddr>> {
    #[cfg(test)]
    if let Some(result) = tests::fixture_resolve(host.clone(), family.clone()) {
        return result.await;
    }
    native_dns_read(move || physical::resolve(&host, &family)).await
}

#[cfg(target_os = "linux")]
async fn resolve_host(
    host: String,
    family: physical::Snapshot,
) -> io::Result<Vec<std::net::IpAddr>> {
    #[cfg(test)]
    if let Some(result) = tests::fixture_resolve(host.clone(), family.clone()) {
        return result.await;
    }
    resolve_linux_host(
        host,
        family,
        |selected| physical::dns_servers(&selected),
        physical::bind_socket,
    )
    .await
}

async fn connect_address(
    before: physical::Snapshot,
    address: std::net::IpAddr,
    port: u16,
) -> io::Result<TcpStream> {
    #[cfg(test)]
    if let Some(dial) = tests::fixture_dial(address) {
        return dial.await;
    }
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
    physical::bind_socket(&socket, interface, remote)
        .map_err(|e| io::Error::new(e.kind(), "physical_bind_failed"))?;
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
    #[cfg(unix)]
    local_name: std::path::PathBuf,
    #[cfg(windows)]
    local_name: String,
}

impl ControlClient {
    pub fn new(url: &Url, dialer: Arc<dyn Dialer>) -> io::Result<Self> {
        let builder = Client::builder();
        #[cfg(test)]
        let builder = crate::panel_dns::https_tests::configure_client(builder);
        Self::build(url, dialer, builder)
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
        let builder = builder
            .no_proxy()
            .connect_timeout(super::HTTP_CONNECT_TIMEOUT)
            .timeout(super::HTTP_REQUEST_TIMEOUT)
            // A later redirect connect error cannot prove the initial POST
            // was unsent. Surface redirects without replaying any HTTP bytes.
            .redirect(reqwest::redirect::Policy::none());
        let client = listener
            .configure(builder)
            .build()
            .map_err(|_| io::Error::other("control_client_unavailable"))?;
        let local_name = listener.local_name();
        let relay = relay::Relay::start(listener, dialer, origin.clone());
        Ok(Self {
            client,
            origin,
            _relay: relay,
            local_name,
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

/// Lifetime guard for the existing user-private physical transport. Allows the
/// pinned updater HTTP library to use its native Unix/named-pipe connector;
/// neither a new TCP proxy nor an ordinary-network fallback is introduced.
#[derive(Clone)]
pub struct UpdateTransport(Arc<ControlClient>);
impl UpdateTransport {
    #[cfg(unix)]
    pub fn unix_socket(&self) -> std::path::PathBuf {
        self.0.local_name.clone()
    }
    #[cfg(windows)]
    pub fn windows_named_pipe(&self) -> String {
        self.0.local_name.clone()
    }
}

pub(super) struct Slot {
    origin: Url,
    dialer: Arc<dyn Dialer>,
    current: RwLock<Option<Arc<ControlClient>>>,
    backup: RwLock<Option<Arc<ControlClient>>>,
    observer: RwLock<Option<Observer>>,
}

impl Slot {
    pub fn set_observer(&self, observe: Observer) {
        *self
            .observer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observe.clone());
        for slot in [&self.current, &self.backup] {
            if let Some(current) = slot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                current._relay.set_observer(Some(observe.clone()));
            }
        }
    }

    pub fn new(origin: Url, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            origin,
            dialer,
            current: RwLock::new(None),
            backup: RwLock::new(None),
            observer: RwLock::new(None),
        }
    }

    pub fn update_transport(&self, url: &Url) -> Result<UpdateTransport, super::ClientApiError> {
        if url.origin() == self.origin.origin() {
            return self
                .client_for(&self.current, &self.origin)
                .map(UpdateTransport);
        }
        if let Some(backup) = crate::panel_backup_url(&self.origin) {
            if url.origin() == backup.origin() {
                return self.client_for(&self.backup, &backup).map(UpdateTransport);
            }
        }
        Err(super::ClientApiError::InvalidPayload {
            code: "control_origin_mismatch",
        })
    }

    pub fn reset(&self) {
        for slot in [&self.current, &self.backup] {
            slot.write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    fn client_for(
        &self,
        slot: &RwLock<Option<Arc<ControlClient>>>,
        origin: &Url,
    ) -> Result<Arc<ControlClient>, super::ClientApiError> {
        let mut current = slot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Retire stopped relays only before a new request.
        if current
            .as_ref()
            .is_none_or(|client| !client._relay.is_running())
        {
            *current = Some(Arc::new(
                ControlClient::new(origin, self.dialer.clone())
                    .map_err(|_| super::ClientApiError::ControlTransportUnavailable)?,
            ));
        }
        let client = current.as_ref().unwrap().clone();
        client._relay.set_observer(
            self.observer
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        );
        Ok(client)
    }

    #[cfg(test)]
    pub async fn execute(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, super::ClientApiError> {
        self.execute_with_primary(request, None).await
    }

    pub(super) async fn execute_with_primary(
        &self,
        request: reqwest::Request,
        primary_temporary: Option<&mut bool>,
    ) -> Result<reqwest::Response, super::ClientApiError> {
        let mut request = request;
        let budget = request
            .timeout()
            .copied()
            .unwrap_or(super::HTTP_REQUEST_TIMEOUT);
        *request.timeout_mut() = Some(budget);
        let original = request.url().clone();
        let backup = crate::panel_backup_url(&original).and_then(|url| {
            let mut alternate = request.try_clone()?;
            *alternate.url_mut() = url;
            alternate.headers_mut().remove(reqwest::header::HOST);
            Some(alternate)
        });
        let started = std::time::Instant::now();
        let client = self.client_for(&self.current, &self.origin)?;
        *request.timeout_mut() = Some(budget.saturating_sub(started.elapsed()));
        match client.execute(request).await {
            Err(super::ClientApiError::Transport(error))
                if error.is_connect() && error.url() == Some(&original) =>
            {
                let remaining = budget.saturating_sub(started.elapsed());
                match backup {
                    Some(mut alternate) if !remaining.is_zero() => {
                        if let Some(temporary) = primary_temporary {
                            // Keep the primary failure classification for the update
                            // check even if the backup fails at a different layer.
                            *temporary =
                                error.is_timeout() || super::is_transient_http_io_failure(&error);
                        }
                        let client = self.client_for(&self.backup, alternate.url())?;
                        let remaining = budget.saturating_sub(started.elapsed());
                        if remaining.is_zero() {
                            return Err(super::ClientApiError::Transport(error));
                        }
                        *alternate.timeout_mut() = Some(remaining);
                        client.execute(alternate).await
                    }
                    _ => Err(super::ClientApiError::Transport(error)),
                }
            }
            result => result,
        }
    }
}

#[cfg(test)]
mod tests;

// Keep actual Linux discovery on the DNS admission path. The injected OS
// discovery/bind functions also permit host-independent tests of this adapter.
#[cfg(any(target_os = "linux", test))]
async fn resolve_linux_host(
    host: String,
    family: physical::Snapshot,
    discover: impl FnOnce(physical::Snapshot) -> io::Result<Vec<physical::DnsServer>> + Send + 'static,
    bind: linux_wire::BindSocket,
) -> io::Result<Vec<std::net::IpAddr>> {
    let selected = family.clone();
    let servers = native_dns_read(move || discover(selected)).await?;
    linux_wire::resolve(&host, &family, &servers, bind).await
}
