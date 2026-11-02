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
}

#[derive(Clone, Copy)]
struct DnsFixture {
    answer: DnsAnswer,
    address: SocketAddr,
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
        let previous = DNS_FIXTURE.with(|slot| slot.replace(Some(DnsFixture { answer, address })));
        Self {
            previous,
            _same_thread: PhantomData,
        }
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
            matches!(host, "nelomai.ru" | "other.example"),
            "unexpected fixture DNS host: {host}"
        );
        Some(async move {
            match fixture.answer {
                DnsAnswer::Success => Ok(vec![SocketAddr::new(fixture.address.ip(), 0)]),
                DnsAnswer::Failure => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "synthetic DNS failure",
                )),
                DnsAnswer::Stall => std::future::pending().await,
            }
        })
    })
}

pub(super) fn backup_address() -> Option<SocketAddr> {
    DNS_FIXTURE.with(|slot| {
        slot.get()
            .map(|fixture| SocketAddr::new(fixture.address.ip(), 0))
    })
}

struct HttpsFixture {
    address: SocketAddr,
    server: thread::JoinHandle<(Option<String>, Option<String>)>,
}

impl HttpsFixture {
    fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("panel_dns_testdata/server.der").to_vec(),
                    )],
                    PrivatePkcs8KeyDer::from(
                        include_bytes!("panel_dns_testdata/server-key.der").to_vec(),
                    )
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
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .unwrap();
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
