//! The public factory and PanelDns are real. Only OS DNS and the backup's
//! destination are substituted with this thread's loopback fixture.
use super::*;
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use std::{
    cell::Cell,
    io::{Read, Write},
    marker::PhantomData,
    net::TcpListener,
    rc::Rc,
    thread,
};

#[derive(Clone, Copy)]
enum DnsAnswer {
    Success,
    Failure,
    Stall,
    Empty,
    DelayedSuccess(Duration),
    DelayedFailure(Duration),
}

#[derive(Clone, Copy)]
struct DnsFixture {
    answer: DnsAnswer,
    address: SocketAddr,
    secondary: Option<(DnsAnswer, SocketAddr)>,
    trust_roots: Option<bool>,
}

// Each #[tokio::test] below uses its own current-thread runtime. The scoped
// fixture therefore follows reqwest's connector tasks without shared state between tests or
// replacing the production resolver. It is absent from non-test builds.
thread_local! {
    static DNS_FIXTURE: Cell<Option<DnsFixture>> = const { Cell::new(None) };
}

struct DnsScope {
    previous: Option<DnsFixture>,
    _same_thread: PhantomData<Rc<()>>,
}

impl DnsScope {
    fn new(answer: DnsAnswer, address: SocketAddr) -> Self {
        let previous = DNS_FIXTURE.with(|slot| {
            slot.replace(Some(DnsFixture {
                answer,
                address,
                secondary: None,
                trust_roots: None,
            }))
        });
        Self {
            previous,
            _same_thread: PhantomData,
        }
    }

    fn with_secondary(self, answer: DnsAnswer, address: SocketAddr) -> Self {
        DNS_FIXTURE.with(|slot| {
            let mut fixture = slot.get().unwrap();
            fixture.secondary = Some((answer, address));
            slot.set(Some(fixture));
        });
        self
    }

    fn with_roots(self, trust_backup: bool) -> Self {
        DNS_FIXTURE.with(|slot| {
            let mut fixture = slot.get().unwrap();
            fixture.trust_roots = Some(trust_backup);
            slot.set(Some(fixture));
        });
        self
    }
}

pub(super) fn configure_client(builder: ClientBuilder) -> ClientBuilder {
    let trust = DNS_FIXTURE.with(|slot| slot.get().and_then(|f| f.trust_roots));
    let Some(trust_backup) = trust else {
        return builder;
    };
    let builder = builder
        .no_proxy()
        .local_address(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))
        .add_root_certificate(
            reqwest::Certificate::from_der(include_bytes!("panel_dns_testdata/ca.der")).unwrap(),
        );
    if trust_backup {
        builder.add_root_certificate(
            reqwest::Certificate::from_der(include_bytes!("panel_dns_testdata/backup-ca.der"))
                .unwrap(),
        )
    } else {
        builder
    }
}

impl Drop for DnsScope {
    fn drop(&mut self) {
        DNS_FIXTURE.with(|slot| slot.set(self.previous));
    }
}

pub(super) fn system_lookup(
    host: &str,
) -> Option<impl Future<Output = io::Result<Vec<SocketAddr>>> + Send> {
    DNS_FIXTURE.with(|slot| {
        let fixture = slot.get()?;
        assert!(
            matches!(host, "nelomai.ru" | "nelomai.top" | "other.example"),
            "unexpected fixture DNS host: {host}"
        );
        let (answer, address) = if host == "nelomai.top" {
            fixture
                .secondary
                .unwrap_or((DnsAnswer::Failure, fixture.address))
        } else {
            (fixture.answer, fixture.address)
        };
        // Preserve the controlled socket port for production URLs without an
        // explicit port. Hyper supports this through its real resolver hook.
        let address = if fixture.trust_roots.is_some() {
            address
        } else {
            SocketAddr::new(address.ip(), 0)
        };
        Some(async move {
            match answer {
                DnsAnswer::Success => Ok(vec![address]),
                DnsAnswer::Failure => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "synthetic DNS failure",
                )),
                DnsAnswer::Stall => std::future::pending().await,
                DnsAnswer::Empty => Ok(vec![]),
                DnsAnswer::DelayedSuccess(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(vec![address])
                }
                DnsAnswer::DelayedFailure(delay) => {
                    tokio::time::sleep(delay).await;
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "synthetic DNS failure",
                    ))
                }
            }
        })
    })
}

async fn secondary_answer_after(primary: DnsAnswer) {
    let _scope = DnsScope::new(primary, "192.0.2.10:0".parse().unwrap())
        .with_secondary(DnsAnswer::Success, "192.0.2.20:0".parse().unwrap());
    assert_eq!(
        resolve_panel_addresses("nelomai.ru").await.unwrap(),
        vec!["192.0.2.20:0".parse::<SocketAddr>().unwrap()]
    );
}

#[tokio::test]
async fn secondary_dns_replaces_static_ip_after_primary_error() {
    secondary_answer_after(DnsAnswer::Failure).await;
}

#[tokio::test]
async fn secondary_dns_replaces_static_ip_after_empty_primary() {
    secondary_answer_after(DnsAnswer::Empty).await;
}

#[tokio::test]
async fn empty_secondary_dns_keeps_the_static_backup() {
    let _scope = DnsScope::new(DnsAnswer::Failure, "192.0.2.10:0".parse().unwrap())
        .with_secondary(DnsAnswer::Empty, "192.0.2.20:0".parse().unwrap());
    assert_eq!(
        resolve_panel_addresses("nelomai.ru").await.unwrap(),
        vec!["192.0.2.10:0".parse::<SocketAddr>().unwrap()]
    );
}

#[tokio::test(start_paused = true)]
async fn secondary_dns_is_available_when_primary_uses_its_full_budget() {
    let start = tokio::time::Instant::now();
    secondary_answer_after(DnsAnswer::Stall).await;
    assert_eq!(start.elapsed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn healthy_primary_wins_even_if_secondary_resolves_first() {
    let _scope = DnsScope::new(
        DnsAnswer::DelayedSuccess(Duration::from_millis(800)),
        "192.0.2.10:0".parse().unwrap(),
    )
    .with_secondary(DnsAnswer::Success, "192.0.2.20:0".parse().unwrap());
    let start = tokio::time::Instant::now();
    assert_eq!(
        resolve_panel_addresses("nelomai.ru").await.unwrap(),
        vec!["192.0.2.10:0".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(start.elapsed(), Duration::from_millis(800));
}

#[tokio::test(start_paused = true)]
async fn healthy_primary_does_not_wait_for_stalled_secondary() {
    let _scope = DnsScope::new(DnsAnswer::Success, "192.0.2.10:0".parse().unwrap())
        .with_secondary(DnsAnswer::Stall, "192.0.2.20:0".parse().unwrap());
    let start = tokio::time::Instant::now();
    assert_eq!(
        resolve_panel_addresses("nelomai.ru").await.unwrap(),
        vec!["192.0.2.10:0".parse::<SocketAddr>().unwrap()]
    );
    assert!(start.elapsed().is_zero());
}

#[tokio::test(start_paused = true)]
async fn secondary_lookup_cannot_restart_the_one_second_deadline() {
    let _scope = DnsScope::new(
        DnsAnswer::DelayedFailure(Duration::from_millis(800)),
        "192.0.2.10:0".parse().unwrap(),
    )
    .with_secondary(
        DnsAnswer::DelayedSuccess(Duration::from_millis(1400)),
        "192.0.2.20:0".parse().unwrap(),
    );
    let start = tokio::time::Instant::now();
    assert_eq!(
        resolve_panel_addresses("nelomai.ru").await.unwrap(),
        vec!["192.0.2.10:0".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(start.elapsed(), Duration::from_secs(1));
}

#[tokio::test]
async fn secondary_dns_is_not_used_for_unrelated_hosts() {
    let _scope = DnsScope::new(DnsAnswer::Failure, "192.0.2.10:0".parse().unwrap())
        .with_secondary(DnsAnswer::Success, "192.0.2.20:0".parse().unwrap());
    assert_eq!(
        resolve_panel_addresses("other.example")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

pub(super) fn backup_address() -> Option<SocketAddr> {
    DNS_FIXTURE.with(|slot| {
        slot.get().map(|fixture| {
            if fixture.trust_roots.is_some() {
                fixture.address
            } else {
                SocketAddr::new(fixture.address.ip(), 0)
            }
        })
    })
}

struct HttpsFixture {
    address: SocketAddr,
    server: thread::JoinHandle<(Option<String>, Option<String>)>,
}

enum Reply {
    Status(u16),
    Eof,
    Redirect(String),
    HandshakeStall,
    Delayed(Duration),
}

impl HttpsFixture {
    fn start(status: u16) -> Self {
        Self::start_with(false, Reply::Status(status))
    }

    fn start_with(backup_cert: bool, reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(if backup_cert {
                        include_bytes!("panel_dns_testdata/backup-server.der").to_vec()
                    } else {
                        include_bytes!("panel_dns_testdata/server.der").to_vec()
                    })],
                    PrivatePkcs8KeyDer::from(if backup_cert {
                        include_bytes!("panel_dns_testdata/backup-server-key.der").to_vec()
                    } else {
                        include_bytes!("panel_dns_testdata/server-key.der").to_vec()
                    })
                    .into(),
                )
                .unwrap();
        let server = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    error => panic!("local HTTPS connection missing: {error:?}"),
                }
            };
            // Accepted sockets can inherit the listener's nonblocking mode on
            // macOS. The blocking rustls fixture must wait for TLS records.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            if matches!(reply, Reply::HandshakeStall) {
                thread::sleep(Duration::from_millis(1500));
                return (None, None);
            }
            let mut stream =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => return (None, stream.conn.server_name().map(str::to_owned)),
                    Ok(n) => request.extend_from_slice(&buffer[..n]),
                }
                assert!(request.len() <= 16384);
                if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length: usize = header
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap_or("0")
                        .parse()
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let delayed = matches!(reply, Reply::Delayed(_));
            let (status, extra) = match reply {
                Reply::Status(status) => (status, String::new()),
                Reply::Redirect(url) => (307, format!("Location: {url}\r\n")),
                Reply::Eof => {
                    return (
                        Some(String::from_utf8(request).unwrap()),
                        stream.conn.server_name().map(str::to_owned),
                    )
                }
                Reply::Delayed(delay) => {
                    thread::sleep(delay);
                    (200, String::new())
                }
                Reply::HandshakeStall => unreachable!(),
            };
            let sent = write!(
                stream,
                "HTTP/1.1 {status} Test\r\n{extra}Content-Length: 2\r\nConnection: close\r\n\r\nok"
            );
            if !delayed {
                sent.unwrap();
            }
            stream.flush().unwrap();
            (
                Some(String::from_utf8(request).unwrap()),
                stream.conn.server_name().map(str::to_owned),
            )
        });
        Self { address, server }
    }

    fn client(&self, trust_ca: bool) -> Client {
        let builder = panel_http_client_builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            // Even a mutation that removes PanelDns cannot connect to a public
            // endpoint with this client. Valid requests stay on loopback.
            .local_address(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        let builder = if trust_ca {
            builder.add_root_certificate(
                reqwest::Certificate::from_der(include_bytes!("panel_dns_testdata/ca.der"))
                    .unwrap(),
            )
        } else {
            builder
        };
        builder.build().unwrap()
    }

    fn url(&self, host: &str) -> String {
        format!(
            "https://{host}:{}/api/client/v1/auth/login",
            self.address.port()
        )
    }
}

#[tokio::test]
async fn api_switches_https_host_and_certificate_after_primary_tls_failure() {
    let primary = HttpsFixture::start_with(true, Reply::Status(200));
    let backup = HttpsFixture::start_with(true, Reply::Status(200));
    let _dns = DnsScope::new(DnsAnswer::Success, primary.address)
        .with_secondary(DnsAnswer::Success, backup.address)
        .with_roots(true);
    let api = crate::ClientApi::new("https://nelomai.ru").unwrap();
    let response = api
        .send_request(
            api.http
                .post(api.endpoint("auth/login").unwrap())
                .header(reqwest::header::HOST, "nelomai.ru")
                .bearer_auth("synthetic-test-token")
                .body("single-https-backup-post"),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.url().host_str(), Some("nelomai.top"));
    let (request, sni) = primary.server.join().unwrap();
    assert!(request.is_none());
    assert_eq!(sni.as_deref(), Some("nelomai.ru"));
    let (request, sni) = backup.server.join().unwrap();
    let request = request.unwrap();
    assert_eq!(sni.as_deref(), Some("nelomai.top"));
    assert!(request
        .to_ascii_lowercase()
        .contains("host: nelomai.top\r\n"));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer synthetic-test-token\r\n"));
    assert!(request.ends_with("\r\n\r\nsingle-https-backup-post"));
}

#[tokio::test]
async fn api_never_replays_post_after_eof_status_or_redirect() {
    for kind in [0, 1, 2] {
        let trap = TcpListener::bind("127.0.0.1:0").unwrap();
        trap.set_nonblocking(true).unwrap();
        let reply = match kind {
            0 => Reply::Eof,
            1 => Reply::Status(503),
            _ => Reply::Redirect(format!(
                "https://nelomai.top:{}/redirect",
                trap.local_addr().unwrap().port()
            )),
        };
        let primary = HttpsFixture::start_with(false, reply);
        let _dns = DnsScope::new(DnsAnswer::Success, primary.address)
            .with_secondary(DnsAnswer::Success, trap.local_addr().unwrap())
            .with_roots(true);
        let api = crate::ClientApi::new("https://nelomai.ru").unwrap();
        let result = api
            .send_request(
                api.http
                    .post(api.endpoint("auth/login").unwrap())
                    .body("one-post")
                    .timeout(Duration::from_millis(300)),
            )
            .await;
        match kind {
            0 => assert!(result.is_err()),
            1 => assert_eq!(result.unwrap().status(), 503),
            _ => assert_eq!(result.unwrap().status(), 307),
        }
        assert!(primary
            .server
            .join()
            .unwrap()
            .0
            .unwrap()
            .ends_with("\r\n\r\none-post"));
        assert_eq!(trap.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}

#[tokio::test]
async fn api_backup_rejects_wrong_hostname_before_credentials() {
    let primary = HttpsFixture::start_with(true, Reply::Status(200));
    let backup = HttpsFixture::start_with(false, Reply::Status(200));
    let _dns = DnsScope::new(DnsAnswer::Success, primary.address)
        .with_secondary(DnsAnswer::Success, backup.address)
        .with_roots(true);
    let api = crate::ClientApi::new("https://nelomai.ru").unwrap();
    assert!(api
        .send_request(
            api.http
                .post(api.endpoint("auth/login").unwrap())
                .bearer_auth("must-not-be-sent")
        )
        .await
        .is_err());
    assert!(primary.server.join().unwrap().0.is_none());
    let (request, sni) = backup.server.join().unwrap();
    assert!(request.is_none());
    assert_eq!(sni.as_deref(), Some("nelomai.top"));
}

#[tokio::test]
async fn api_backup_rejects_untrusted_certificate_before_credentials() {
    let primary = HttpsFixture::start_with(true, Reply::Status(200));
    let backup = HttpsFixture::start_with(true, Reply::Status(200));
    let _dns = DnsScope::new(DnsAnswer::Success, primary.address)
        .with_secondary(DnsAnswer::Success, backup.address)
        .with_roots(false);
    let api = crate::ClientApi::new("https://nelomai.ru").unwrap();
    assert!(api
        .send_request(
            api.http
                .post(api.endpoint("auth/login").unwrap())
                .bearer_auth("must-not-be-sent")
        )
        .await
        .is_err());
    assert!(primary.server.join().unwrap().0.is_none());
    assert!(backup.server.join().unwrap().0.is_none());
}

#[tokio::test]
async fn https_backup_does_not_restart_the_request_deadline() {
    let primary = HttpsFixture::start_with(false, Reply::HandshakeStall);
    let backup = HttpsFixture::start_with(true, Reply::Delayed(Duration::from_millis(600)));
    let _dns = DnsScope::new(DnsAnswer::Success, primary.address)
        .with_secondary(DnsAnswer::Success, backup.address)
        .with_roots(true);
    let api = crate::ClientApi::new("https://nelomai.ru").unwrap();
    *api.http.current.write().unwrap() = panel_http_client_builder()
        .connect_timeout(Duration::from_millis(700))
        .build()
        .unwrap();
    let result = api
        .send_request(
            api.http
                .post(api.endpoint("auth/login").unwrap())
                .body("deadline-post")
                .timeout(Duration::from_secs(1)),
        )
        .await;
    assert!(matches!(result, Err(crate::ClientApiError::Transport(error)) if error.is_timeout()));
    assert!(primary.server.join().unwrap().0.is_none());
    let (request, sni) = backup.server.join().unwrap();
    assert!(request.unwrap().ends_with("\r\n\r\ndeadline-post"));
    assert_eq!(sni.as_deref(), Some("nelomai.top"));
}

#[tokio::test]
async fn dns_failure_stall_and_success_preserve_https_identity_and_single_post() {
    for answer in [DnsAnswer::Failure, DnsAnswer::Stall, DnsAnswer::Success] {
        let fixture = HttpsFixture::start(200);
        let _dns = DnsScope::new(answer, fixture.address);
        let response = fixture
            .client(true)
            .post(fixture.url(PANEL_HOST))
            .bearer_auth("synthetic-test-token")
            .body("synthetic-login-body")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let (request, sni) = fixture.server.join().unwrap();
        let request = request.unwrap();
        assert_eq!(sni.as_deref(), Some("nelomai.ru"));
        assert!(request.starts_with("POST /api/client/v1/auth/login HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("host: nelomai.ru:{}\r\n", fixture.address.port())));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer synthetic-test-token\r\n"));
        assert!(request.ends_with("\r\n\r\nsynthetic-login-body"));
    }
}

#[tokio::test]
async fn fallback_does_not_replay_a_post_after_http_failure() {
    let fixture = HttpsFixture::start(503);
    let _dns = DnsScope::new(DnsAnswer::Failure, fixture.address);
    let response = fixture
        .client(true)
        .post(fixture.url(PANEL_HOST))
        .body("one-attempt")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let (request, _) = fixture.server.join().unwrap();
    assert!(request.unwrap().ends_with("\r\n\r\none-attempt"));
}

#[tokio::test]
async fn secondary_dns_preserves_https_identity_and_never_replays_post() {
    for status in [200, 503] {
        let fixture = HttpsFixture::start(status);
        // The static-IP branch cannot reach the server; only the secondary DNS can.
        let _dns = DnsScope::new(DnsAnswer::Failure, "127.0.0.2:0".parse().unwrap())
            .with_secondary(DnsAnswer::Success, fixture.address);
        let response = fixture
            .client(true)
            .post(fixture.url("nelomai.ru"))
            .bearer_auth("synthetic-test-token")
            .body("single-secondary-dns-post")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let (request, sni) = fixture.server.join().unwrap();
        let request = request.unwrap();
        assert_eq!(sni.as_deref(), Some("nelomai.ru"));
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("host: nelomai.ru:{}\r\n", fixture.address.port())));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer synthetic-test-token\r\n"));
        assert!(request.ends_with("\r\n\r\nsingle-secondary-dns-post"));
    }
}

#[tokio::test]
async fn secondary_dns_cannot_bypass_certificate_validation() {
    let fixture = HttpsFixture::start(200);
    let _dns = DnsScope::new(DnsAnswer::Failure, "127.0.0.2:0".parse().unwrap())
        .with_secondary(DnsAnswer::Success, fixture.address);
    assert!(fixture
        .client(false)
        .post(fixture.url("nelomai.ru"))
        .bearer_auth("must-not-be-sent")
        .send()
        .await
        .is_err());
    let (request, sni) = fixture.server.join().unwrap();
    assert!(request.is_none());
    assert_eq!(sni.as_deref(), Some("nelomai.ru"));
}

#[tokio::test]
async fn fallback_rejects_an_untrusted_certificate_before_sending_credentials() {
    let fixture = HttpsFixture::start(200);
    let _dns = DnsScope::new(DnsAnswer::Failure, fixture.address);
    assert!(fixture
        .client(false)
        .post(fixture.url(PANEL_HOST))
        .bearer_auth("must-not-be-sent")
        .send()
        .await
        .is_err());
    let (request, sni) = fixture.server.join().unwrap();
    assert!(request.is_none());
    assert_eq!(sni.as_deref(), Some("nelomai.ru"));
}

#[tokio::test]
async fn resolver_does_not_disable_certificate_hostname_validation() {
    let fixture = HttpsFixture::start(200);
    let _dns = DnsScope::new(DnsAnswer::Success, fixture.address);
    assert!(fixture
        .client(true)
        .post(fixture.url("other.example"))
        .bearer_auth("must-not-be-sent")
        .send()
        .await
        .is_err());
    let (request, sni) = fixture.server.join().unwrap();
    assert!(request.is_none());
    assert_eq!(sni.as_deref(), Some("other.example"));
}
