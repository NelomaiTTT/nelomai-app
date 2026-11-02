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
const PANEL_DNS_TIMEOUT: Duration = Duration::from_secs(1);
const PANEL_BACKUP: Ipv4Addr = Ipv4Addr::new(45, 144, 221, 68);

#[cfg(test)]
#[path = "panel_dns_https_tests.rs"]
mod https_tests;

/// Keep the URL, TLS server name and certificate validation unchanged. Only
/// failed OS DNS resolution of the panel's exact hostname has a backup address.
pub fn panel_http_client_builder() -> ClientBuilder {
    Client::builder().dns_resolver(Arc::new(PanelDns))
}

/// Also used by the desktop updater, whose HTTP client is a different reqwest
/// version. Zero ports let each HTTP client preserve the port in its URL.
pub async fn resolve_panel_addresses(host: &str) -> io::Result<Vec<SocketAddr>> {
    with_panel_fallback(host, async {
        #[cfg(test)]
        if let Some(lookup) = https_tests::system_lookup(host) {
            return lookup.await;
        }
        tokio::net::lookup_host((host, 0))
            .await
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

async fn with_panel_fallback(
    host: &str,
    lookup: impl Future<Output = io::Result<Vec<SocketAddr>>>,
) -> io::Result<Vec<SocketAddr>> {
    if !host.eq_ignore_ascii_case(PANEL_HOST) {
        return lookup.await;
    }
    match tokio::time::timeout(PANEL_DNS_TIMEOUT, lookup).await {
        Ok(Ok(addresses)) if !addresses.is_empty() => Ok(addresses),
        _ => {
            let address = SocketAddr::from((PANEL_BACKUP, 0));
            #[cfg(test)]
            let address = https_tests::backup_address().unwrap_or(address);
            Ok(vec![address])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};

    fn dns_error() -> io::Error {
        io::Error::new(io::ErrorKind::NotFound, "synthetic DNS failure")
    }

    #[tokio::test]
    async fn healthy_dns_precedes_backup_and_preserves_both_address_families() {
        let expected = vec![
            "192.0.2.15:0".parse().unwrap(),
            "[2001:db8::15]:0".parse().unwrap(),
        ];
        assert_eq!(
            with_panel_fallback(PANEL_HOST, ready(Ok(expected.clone())))
                .await
                .unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn failed_panel_dns_uses_backup() {
        assert_eq!(
            with_panel_fallback(PANEL_HOST, ready(Err(dns_error())))
                .await
                .unwrap(),
            vec!["45.144.221.68:0".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn empty_panel_dns_uses_backup() {
        assert_eq!(
            with_panel_fallback(PANEL_HOST, ready(Ok(vec![])))
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
            with_panel_fallback(PANEL_HOST, pending()),
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
                with_panel_fallback(host, ready(Err(dns_error())))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert!(with_panel_fallback(host, ready(Ok(vec![])))
                .await
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn recovered_dns_replaces_backup_without_sticky_state() {
        with_panel_fallback(PANEL_HOST, ready(Err(dns_error())))
            .await
            .unwrap();
        let answer = vec!["192.0.2.20:0".parse().unwrap()];
        assert_eq!(
            with_panel_fallback(PANEL_HOST, ready(Ok(answer.clone())))
                .await
                .unwrap(),
            answer
        );
        assert_eq!(
            with_panel_fallback("NELOMAI.RU", ready(Err(dns_error())))
                .await
                .unwrap(),
            vec!["45.144.221.68:0".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unrelated_dns_does_not_inherit_panel_timeout() {
        let start = tokio::time::Instant::now();
        let result = with_panel_fallback("other.example", async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Err(dns_error())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }
}
