use futures_util::{
    future::{select, Either},
    pin_mut,
};
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    Client, ClientBuilder,
};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

const PANEL_HOST: &str = "nelomai.ru";
const PANEL_BACKUP_HOST: &str = "nelomai.top";
const PANEL_DNS_TIMEOUT: Duration = Duration::from_secs(1);
const PANEL_BACKUP: Ipv4Addr = Ipv4Addr::new(45, 144, 221, 68);

#[cfg(test)]
#[path = "panel_dns_https_tests.rs"]
pub(crate) mod https_tests;

/// Keep the URL, TLS server name and certificate validation unchanged. Only
/// failed OS DNS resolution of the exact panel hostname uses the independent
/// backup DNS name, then the static address, within one shared DNS budget.
pub fn panel_http_client_builder() -> ClientBuilder {
    // Redirects could turn a later connect error into replay of an already sent POST.
    let builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(PanelDns));
    #[cfg(test)]
    let builder = https_tests::configure_client(builder);
    builder
}

/// Also used by the desktop updater, whose HTTP client is a different reqwest
/// version. Zero ports let each HTTP client preserve the port in its URL.
pub async fn resolve_panel_addresses(host: &str) -> io::Result<Vec<SocketAddr>> {
    with_panel_fallback(host, os_lookup(host), os_lookup).await
}

// Both ordinary and scoped resolvers use exactly this allowlist, secondary
// name and absolute DNS budget. The numeric address never changes URL identity.
pub(crate) struct PanelDnsFallback {
    pub secondary: Option<&'static str>,
    pub deadline: tokio::time::Instant,
    pub address: SocketAddr,
}

impl PanelDnsFallback {
    pub fn for_host(host: &str) -> Option<Self> {
        let secondary = if host.eq_ignore_ascii_case(PANEL_HOST) {
            Some(PANEL_BACKUP_HOST)
        } else if host.eq_ignore_ascii_case(PANEL_BACKUP_HOST) {
            None
        } else {
            return None;
        };
        let address = SocketAddr::from((PANEL_BACKUP, 0));
        #[cfg(test)]
        let address = https_tests::backup_address().unwrap_or(address);
        Some(Self {
            secondary,
            deadline: tokio::time::Instant::now() + PANEL_DNS_TIMEOUT,
            address,
        })
    }
}

/// The only approved alternate HTTPS origin. Paths and query strings stay intact.
pub fn panel_backup_url(url: &reqwest::Url) -> Option<reqwest::Url> {
    if url.scheme() != "https"
        || !matches!(url.host_str(), Some(PANEL_HOST | PANEL_BACKUP_HOST))
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    if url.port_or_known_default() != Some(443) {
        return None;
    }
    let mut backup = url.clone();
    backup
        .set_host(Some(if url.host_str() == Some(PANEL_HOST) {
            PANEL_BACKUP_HOST
        } else {
            PANEL_HOST
        }))
        .ok()?;
    Some(backup)
}

/// Use with panel_http_client_builder: at most one retry, only before HTTP was sent.
pub async fn execute_panel_request(
    client: &Client,
    mut request: reqwest::Request,
    default_timeout: Duration,
) -> Result<reqwest::Response, reqwest::Error> {
    let budget = request.timeout().copied().unwrap_or(default_timeout);
    *request.timeout_mut() = Some(budget);
    let original_url = request.url().clone();
    let backup = panel_backup_url(&original_url).and_then(|url| {
        let mut backup = request.try_clone()?;
        *backup.url_mut() = url;
        backup.headers_mut().remove(reqwest::header::HOST);
        Some(backup)
    });
    let started = std::time::Instant::now();
    match client.execute(request).await {
        Err(error) if error.is_connect() && error.url() == Some(&original_url) => {
            let remaining = budget.saturating_sub(started.elapsed());
            match backup {
                Some(mut backup) if !remaining.is_zero() => {
                    *backup.timeout_mut() = Some(remaining);
                    client.execute(backup).await
                }
                _ => Err(error),
            }
        }
        result => result,
    }
}

async fn os_lookup(host: &str) -> io::Result<Vec<SocketAddr>> {
    #[cfg(test)]
    if let Some(lookup) = https_tests::system_lookup(host) {
        return lookup.await;
    }
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(address, 0)]);
    }
    let host = host.to_owned();
    #[cfg(test)]
    let lookup = BLOCKING_LOOKUP.with(|slot| slot.borrow().clone());
    crate::blocking::read(move || {
        #[cfg(test)]
        if let Some(lookup) = lookup {
            return lookup(&host);
        }
        std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0))
            .map(|addresses| addresses.collect())
    })
    .await
}

struct PanelDns;

impl Resolve for PanelDns {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = resolve_panel_addresses(name.as_str()).await?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

async fn with_panel_fallback<Fut>(
    host: &str,
    lookup: impl Future<Output = io::Result<Vec<SocketAddr>>>,
    secondary_lookup: impl FnOnce(&'static str) -> Fut,
) -> io::Result<Vec<SocketAddr>>
where
    Fut: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let Some(policy) = PanelDnsFallback::for_host(host) else {
        return lookup.await;
    };
    let primary = tokio::time::timeout_at(policy.deadline, lookup);
    let secondary = tokio::time::timeout_at(policy.deadline, async {
        let name = policy.secondary.ok_or(io::ErrorKind::NotFound)?;
        secondary_lookup(name).await
    });
    pin_mut!(primary, secondary);
    let secondary_result = match select(primary, secondary).await {
        Either::Left((result, secondary)) => match result {
            Ok(Ok(addresses)) if !addresses.is_empty() => return Ok(addresses),
            _ => secondary.await,
        },
        Either::Right((result, primary)) => match primary.await {
            Ok(Ok(addresses)) if !addresses.is_empty() => return Ok(addresses),
            _ => result,
        },
    };
    if let Ok(Ok(addresses)) = secondary_result {
        if !addresses.is_empty() {
            return Ok(addresses);
        }
    }
    Ok(vec![policy.address])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};

    fn dns_error() -> io::Error {
        io::Error::new(io::ErrorKind::NotFound, "synthetic DNS failure")
    }

    #[test]
    fn https_alternate_is_scoped_and_preserves_request_target() {
        let source = reqwest::Url::parse(
            "https://nelomai.ru/api/client/v1/server-candidates?layer=tic&x=a%2Fb",
        )
        .unwrap();
        assert_eq!(
            panel_backup_url(&source).unwrap().as_str(),
            "https://nelomai.top/api/client/v1/server-candidates?layer=tic&x=a%2Fb"
        );
        assert_eq!(
            panel_backup_url(&panel_backup_url(&source).unwrap()).unwrap(),
            source
        );
        for value in [
            "http://nelomai.ru/x",
            "https://nelomai.ru:8443/x",
            "https://x.nelomai.ru/x",
            "https://nelomai.ru.evil.test/x",
            "https://user@nelomai.ru/x",
            "https://45.144.221.68/x",
            "https://example.test/x",
        ] {
            assert!(
                panel_backup_url(&reqwest::Url::parse(value).unwrap()).is_none(),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn backup_hostname_has_its_own_static_dns_recovery() {
        assert_eq!(
            with_failed_secondary(PANEL_BACKUP_HOST, ready(Err(dns_error())))
                .await
                .unwrap(),
            vec!["45.144.221.68:0".parse::<SocketAddr>().unwrap()]
        );
    }

    async fn with_failed_secondary(
        host: &str,
        lookup: impl Future<Output = io::Result<Vec<SocketAddr>>>,
    ) -> io::Result<Vec<SocketAddr>> {
        with_panel_fallback(host, lookup, |_| ready(Err(dns_error()))).await
    }

    #[tokio::test]
    async fn healthy_dns_precedes_backup_and_preserves_both_address_families() {
        let expected = vec![
            "192.0.2.15:0".parse().unwrap(),
            "[2001:db8::15]:0".parse().unwrap(),
        ];
        assert_eq!(
            with_failed_secondary(PANEL_HOST, ready(Ok(expected.clone())))
                .await
                .unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn failed_panel_dns_uses_backup() {
        assert_eq!(
            with_failed_secondary(PANEL_HOST, ready(Err(dns_error())))
                .await
                .unwrap(),
            vec!["45.144.221.68:0".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn empty_panel_dns_uses_backup() {
        assert_eq!(
            with_failed_secondary(PANEL_HOST, ready(Ok(vec![])))
                .await
                .unwrap(),
            vec!["45.144.221.68:0".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_panel_dns_uses_backup_after_one_second() {
        let start = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            with_failed_secondary(PANEL_HOST, pending()),
        )
        .await
        .expect("DNS fallback exceeded its deadline")
        .unwrap();
        assert_eq!(
            result,
            vec!["45.144.221.68:0".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn unrelated_names_and_subdomains_do_not_receive_panel_backup() {
        for host in ["other.example", "x.nelomai.ru", "nelomai.ru.other.example"] {
            assert_eq!(
                with_failed_secondary(host, ready(Err(dns_error())))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert!(with_failed_secondary(host, ready(Ok(vec![])))
                .await
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn recovered_dns_replaces_backup_without_sticky_state() {
        with_failed_secondary(PANEL_HOST, ready(Err(dns_error())))
            .await
            .unwrap();
        let answer = vec!["192.0.2.20:0".parse().unwrap()];
        assert_eq!(
            with_failed_secondary(PANEL_HOST, ready(Ok(answer.clone())))
                .await
                .unwrap(),
            answer
        );
        assert_eq!(
            with_failed_secondary("NELOMAI.RU", ready(Err(dns_error())))
                .await
                .unwrap(),
            vec!["45.144.221.68:0".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unrelated_dns_does_not_inherit_panel_timeout() {
        let start = tokio::time::Instant::now();
        let result = with_failed_secondary("other.example", async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Err(dns_error())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }
}

#[cfg(test)]
type BlockingLookup = Arc<dyn Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync>;
#[cfg(test)]
thread_local! { static BLOCKING_LOOKUP:std::cell::RefCell<Option<BlockingLookup>>=const{std::cell::RefCell::new(None)}; }
#[cfg(test)]
#[test]
fn cancelled_ordinary_dns_in_blocking_queue_never_starts() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (release, wait) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = wait.recv();
        });
        ready.await.unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let observed = ran.clone();
        BLOCKING_LOOKUP.with(|slot| {
            slot.replace(Some(Arc::new(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(vec!["127.0.0.1:0".parse().unwrap()])
            })))
        });
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            resolve_panel_addresses("foreign.invalid")
        )
        .await
        .is_err());
        BLOCKING_LOOKUP.with(|slot| slot.replace(None));
        release.send(()).unwrap();
        blocker.await.unwrap();
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "ordinary DNS began after its cancelled future was dropped"
        );
    });
}
