use super::*;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn server(body: &'static str) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let _ = socket.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (address, hits, task)
}

struct Route {
    target: Option<SocketAddr>,
}
impl Dialer for Route {
    fn connect(&self, _origin: Origin) -> DialFuture {
        let target = self.target;
        Box::pin(async move {
            TcpStream::connect(target.ok_or_else(|| io::Error::other("physical_path_unavailable"))?)
                .await
        })
    }
}

// Omitting the private transport makes this reach the ordinary/VPN origin.
// The OS discovery seam is replaced; HTTP and the relay use real sockets.
#[tokio::test]
async fn control_http_uses_the_physical_dialer_instead_of_the_ordinary_route() {
    let (ordinary, ordinary_hits, first) = server("vpn").await;
    let (physical, physical_hits, second) = server("physical").await;
    let origin = Url::parse(&format!("http://{ordinary}")).unwrap();
    let control = ControlClient::new(
        &origin,
        Arc::new(Route {
            target: Some(physical),
        }),
    )
    .unwrap();
    let response = control
        .client
        .get(origin)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    first.abort();
    second.abort();
    assert_eq!(response, "physical");
    assert_eq!(ordinary_hits.load(Ordering::SeqCst), 0);
    assert_eq!(physical_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_physical_path_never_falls_back_to_the_ordinary_route() {
    let (ordinary, hits, server) = server("vpn").await;
    let origin = Url::parse(&format!("http://{ordinary}")).unwrap();
    let control = ControlClient::new(&origin, Arc::new(Route { target: None })).unwrap();
    let result = control.client.get(origin).send().await;
    server.abort();
    assert!(
        result.is_err(),
        "control HTTP silently used the ordinary route"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn api_requests_use_control_transport_but_tunnel_probes_keep_the_ordinary_path() {
    let (ordinary, ordinary_hits, first) =
        server(r#"{"api_version":"1","platform":"macos","entries":[{"version":"vpn","notes":"ordinary"}]}"#).await;
    let (physical, physical_hits, second) =
        server(r#"{"api_version":"1","platform":"macos","entries":[{"version":"direct","notes":"physical"}]}"#).await;
    let origin = Url::parse(&format!("http://{ordinary}")).unwrap();
    let mut api = crate::ClientApi::new(origin.as_str()).unwrap();
    api.http.control = Some(Arc::new(Slot::new(
        origin.clone(),
        Arc::new(Route {
            target: Some(physical),
        }),
    )));
    let history = api
        .release_history(nelomai_contracts::Platform::Macos)
        .await
        .unwrap();
    assert_eq!(history.entries[0].version, "direct");
    assert_eq!(ordinary_hits.load(Ordering::SeqCst), 0);
    assert!(api
        .probe_candidate_latency_ms(origin.as_str())
        .await
        .is_ok());
    assert!(api.probe_fresh_latency_ms(origin.as_str()).await.is_some());
    assert_eq!(ordinary_hits.load(Ordering::SeqCst), 2);
    assert_eq!(physical_hits.load(Ordering::SeqCst), 1);
    first.abort();
    second.abort();
}

#[tokio::test]
async fn resetting_control_client_does_not_cut_an_accepted_response_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release, ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        ready.await.unwrap();
        socket.write_all(b"physical").await.unwrap();
    });
    let origin = Url::parse(&format!("http://{address}")).unwrap();
    let slot = Slot::new(
        origin.clone(),
        Arc::new(Route {
            target: Some(address),
        }),
    );
    let request = Client::new().get(origin).build().unwrap();
    let response = slot.execute(request).await.unwrap();
    slot.reset();
    tokio::task::yield_now().await;
    release.send(()).unwrap();
    assert_eq!(response.text().await.unwrap(), "physical");
    server.await.unwrap();
}

async fn tls_server(body: &'static str) -> (SocketAddr, tokio::task::JoinHandle<bool>) {
    use tokio_rustls::rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    };
    let chain = CertificateDer::pem_slice_iter(include_bytes!("testdata/chain.pem"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("testdata/end.key")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let Ok(mut tls) = acceptor.accept(socket).await else {
            return false;
        };
        let mut bytes = [0; 4096];
        let Ok(length) = tls.read(&mut bytes).await else {
            return false;
        };
        if length == 0 {
            return false;
        }
        let request = std::str::from_utf8(&bytes[..length]).unwrap();
        let identity_preserved = request.contains("authorization: Bearer synthetic-test-token\r\n")
            && request.contains("host: foobar.com:");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(response.as_bytes()).await.unwrap();
        identity_preserved
    });
    (address, server)
}

#[tokio::test]
async fn private_relay_preserves_tls_hostname_trust_and_authorization() {
    let (physical, server) = tls_server("physical").await;
    // Even a deliberately broken relay mutation can only dial loopback.
    let url = Url::parse("https://foobar.com:31991/api/client/v1/bootstrap").unwrap();
    let builder = Client::builder()
        .resolve("foobar.com", physical)
        .add_root_certificate(
            reqwest::Certificate::from_pem(include_bytes!("testdata/root.pem")).unwrap(),
        );
    let control = ControlClient::build(
        &url,
        Arc::new(Route {
            target: Some(physical),
        }),
        builder,
    )
    .unwrap();
    let response = control
        .client
        .get(url)
        .bearer_auth("synthetic-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "physical");
    assert!(server.await.unwrap());
}

#[tokio::test]
async fn private_relay_never_sends_authorization_to_an_untrusted_tls_peer() {
    let (physical, server) = tls_server("physical").await;
    let url = Url::parse("https://foobar.com:31992/api/client/v1/bootstrap").unwrap();
    let control = ControlClient::build(
        &url,
        Arc::new(Route {
            target: Some(physical),
        }),
        Client::builder().resolve("foobar.com", physical),
    )
    .unwrap();
    let result = control
        .client
        .get(url)
        .bearer_auth("synthetic-test-token")
        .send()
        .await;
    assert!(result.is_err());
    assert!(!server.await.unwrap());
}

#[tokio::test]
async fn control_rejects_another_initial_origin_and_cross_origin_redirects() {
    let (physical, hits, server) = server("physical").await;
    let origin = Url::parse("http://127.0.0.1:31993").unwrap();
    let control = ControlClient::new(
        &origin,
        Arc::new(Route {
            target: Some(physical),
        }),
    )
    .unwrap();
    let request = Client::new().get("http://127.0.0.1:31994").build().unwrap();
    assert!(matches!(
        control.execute(request).await,
        Err(crate::ClientApiError::InvalidPayload {
            code: "control_origin_mismatch"
        })
    ));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    server.abort();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:31995/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let control = ControlClient::new(
        &origin,
        Arc::new(Route {
            target: Some(address),
        }),
    )
    .unwrap();
    let response = control.client.get(origin).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    server.await.unwrap();
}

#[tokio::test]
async fn shipping_https_api_constructor_uses_private_control_transport() {
    let (ordinary, ordinary_server) = tls_server("vpn").await;
    let (physical, physical_server) = tls_server("physical").await;
    let origin = Url::parse("https://foobar.com:31996").unwrap();
    let root = reqwest::Certificate::from_pem(include_bytes!("testdata/root.pem")).unwrap();
    let mut api = crate::ClientApi::new(origin.as_str()).unwrap();
    *api.http.current.write().unwrap() = Client::builder()
        .resolve("foobar.com", ordinary)
        .add_root_certificate(root.clone())
        .build()
        .unwrap();
    // Replace only OS dialing and the test CA. The public constructor must
    // already have selected control mode, otherwise this assertion fails.
    let slot = Arc::get_mut(
        api.http
            .control
            .as_mut()
            .expect("HTTPS service transport was not installed"),
    )
    .unwrap();
    slot.dialer = Arc::new(Route {
        target: Some(physical),
    });
    *slot.current.write().unwrap() = Some(Arc::new(
        ControlClient::build(
            &origin,
            slot.dialer.clone(),
            Client::builder()
                .resolve("foobar.com", ordinary)
                .add_root_certificate(root),
        )
        .unwrap(),
    ));
    let response = api
        .send_request(
            api.http
                .get(api.endpoint("bootstrap").unwrap())
                .bearer_auth("synthetic-test-token"),
        )
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "physical");
    assert!(physical_server.await.unwrap());
    assert!(!ordinary_server.is_finished());
    ordinary_server.abort();
}

#[tokio::test]
async fn control_origin_cannot_be_downgraded_before_sending_headers() {
    let (physical, hits, server) = server("physical").await;
    let origin = Url::parse("https://127.0.0.1:31997").unwrap();
    let control = ControlClient::new(
        &origin,
        Arc::new(Route {
            target: Some(physical),
        }),
    )
    .unwrap();
    let request = Client::new()
        .get("http://127.0.0.1:31997")
        .bearer_auth("synthetic-test-token")
        .build()
        .unwrap();
    assert!(matches!(
        control.execute(request).await,
        Err(crate::ClientApiError::InvalidPayload {
            code: "control_origin_mismatch"
        })
    ));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn blackholed_first_physical_address_does_not_starve_a_healthy_alternative() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let blocked: DialFuture = Box::pin(std::future::pending());
    let healthy: DialFuture = Box::pin(async move { TcpStream::connect(address).await });
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        race_connections(vec![blocked, healthy]),
    )
    .await
    .expect("one blackholed address consumed the total connection budget")
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), address);
}

#[tokio::test]
async fn dns_answer_larger_than_socket_capacity_can_still_connect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let healthy: DialFuture = Box::pin(async move { TcpStream::connect(address).await });
    let mut attempts = vec![healthy];
    for _ in 0..16 {
        attempts.push(Box::pin(std::future::pending()));
    }
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        race_connections(attempts),
    )
    .await
    .unwrap()
    .expect("valid DNS answer rejected before trying its reachable address");
    assert_eq!(stream.peer_addr().unwrap(), address);
}

struct PendingRoute;
impl Dialer for PendingRoute {
    fn connect(&self, _: Origin) -> DialFuture {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn stalled_physical_dial_uses_the_connect_budget_without_fallback() {
    let (ordinary, hits, server) = server("vpn").await;
    let origin = Url::parse(&format!("http://{ordinary}")).unwrap();
    let control = ControlClient::new(&origin, Arc::new(PendingRoute)).unwrap();
    let start = std::time::Instant::now();
    let result = control.client.get(origin).send().await;
    let elapsed = start.elapsed();
    server.abort();
    assert!(result.is_err());
    assert!(elapsed >= super::super::HTTP_CONNECT_TIMEOUT);
    assert!(elapsed < std::time::Duration::from_secs(13));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_native_reads_retain_capacity_until_os_work_finishes() {
    let _serial = NATIVE_READER_CASES.lock().await;
    type Gate = Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;
    struct Release(Gate);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let gate: Gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Release(gate.clone());
    let started = Arc::new(AtomicUsize::new(0));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let gate = gate.clone();
        let started = started.clone();
        readers.push(tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_millis(500),
                native_read(move || {
                    started.fetch_add(1, Ordering::SeqCst);
                    let mut open = gate.0.lock().unwrap();
                    while !*open {
                        open = gate.1.wait(open).unwrap();
                    }
                    Ok(())
                }),
            )
            .await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while started.load(Ordering::SeqCst) < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for reader in readers {
        assert!(reader.await.unwrap().is_err());
    }
    let observed = started.clone();
    let queued = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        native_read(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    )
    .await;
    assert!(
        queued.is_err(),
        "cancelled callers released live OS work capacity"
    );
    assert_eq!(started.load(Ordering::SeqCst), 4);
    drop(release);
    tokio::time::timeout(std::time::Duration::from_secs(2), native_read(|| Ok(())))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        started.load(Ordering::SeqCst),
        4,
        "cancelled queued read started after capacity returned"
    );
}

// Descriptor exhaustion is process-wide: run this case alone in a child test
// process, with a private temp directory, so parallel tests cannot be affected.
#[cfg(unix)]
#[tokio::test]
async fn stopped_relay_is_rebuilt_without_replaying_or_cutting_an_active_body() {
    const CHILD: &str = "NELOMAI_RELAY_FD_RECOVERY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        use std::os::unix::fs::DirBuilderExt;
        let name = uuid::Uuid::new_v4().simple().to_string();
        let directory = std::env::temp_dir().join(format!("nr-{}", &name[..8]));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "control_transport::tests::stopped_relay_is_rebuilt_without_replaying_or_cutting_an_active_body", "--nocapture"])
            .env(CHILD,"1").env("TMPDIR",&directory).output();
        let _ = std::fs::remove_dir_all(&directory);
        let output = output.unwrap();
        assert!(
            output.status.success(),
            "isolated recovery test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    struct Limit(libc::rlimit);
    impl Drop for Limit {
        fn drop(&mut self) {
            let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) };
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let posts = Arc::new(AtomicUsize::new(0));
    let count = posts.clone();
    let (release, ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut slow, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        let length = slow.read(&mut bytes).await.unwrap();
        assert!(bytes[..length].starts_with(b"GET /slow "));
        slow.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let body = tokio::spawn(async move {
            ready.await.unwrap();
            slow.write_all(b"physical").await.unwrap();
        });
        let (mut fresh, _) = listener.accept().await.unwrap();
        let length = fresh.read(&mut bytes).await.unwrap();
        assert!(bytes[..length].starts_with(b"POST /once "));
        count.fetch_add(1, Ordering::SeqCst);
        fresh
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        body.await.unwrap();
    });
    let origin = Url::parse("http://control.test:31999/").unwrap();
    let slot = Slot::new(
        origin.clone(),
        Arc::new(Route {
            target: Some(address),
        }),
    );
    let active = slot
        .execute(
            Client::new()
                .get(origin.join("slow").unwrap())
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
    let mut entries = std::fs::read_dir(std::env::temp_dir()).unwrap();
    let endpoint = entries.next().unwrap().unwrap().path().join("s");
    assert!(entries.next().is_none());
    drop(entries);
    // Queue a client without yielding, then leave exactly one FD for accept.
    let client = std::os::unix::net::UnixStream::connect(&endpoint).unwrap();
    let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
        0
    );
    let original = unsafe { original.assume_init() };
    let limit = Limit(original);
    let small = libc::rlimit {
        rlim_cur: original.rlim_cur.min(64),
        rlim_max: original.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &small) }, 0);
    let mut pressure = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => pressure.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                break;
            }
        }
    }
    assert!(!pressure.is_empty());
    drop(pressure.pop());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while endpoint.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener did not stop after the injected resource failure");
    drop(pressure);
    drop(limit);
    drop(client);
    let request = Client::new()
        .post(origin.join("once").unwrap())
        .build()
        .unwrap();
    let recovered = slot.execute(request).await;
    assert!(
        recovered.is_ok(),
        "resource pressure ended but cached relay stayed dead: {recovered:?}"
    );
    assert_eq!(recovered.unwrap().text().await.unwrap(), "ok");
    release.send(()).unwrap();
    assert_eq!(active.text().await.unwrap(), "physical");
    server.await.unwrap();
    assert_eq!(
        posts.load(Ordering::SeqCst),
        1,
        "recovery replayed the POST"
    );
}

#[tokio::test]
async fn control_failure_observer_records_dns_reason_without_secret_error_text_or_fallback() {
    struct BrokenDns;
    impl Dialer for BrokenDns {
        fn connect(&self, _: Origin) -> DialFuture {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "physical_dns_timeout",
                ))
            })
        }
    }
    let (ordinary, hits, server) = server("must not reach VPN").await;
    let origin = Url::parse(&format!("http://{ordinary}")).unwrap();
    let slot = Slot::new(origin.clone(), Arc::new(BrokenDns));
    let (seen, mut events) = tokio::sync::mpsc::channel(1);
    slot.set_observer(Arc::new(move |code, ms| {
        let _ = seen.try_send((code, ms));
    }));
    let request = Client::new().get(origin).build().unwrap();
    assert!(slot.execute(request).await.is_err());
    server.abort();
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .map(|(code, _)| code),
        Some("physical_dns_timeout")
    );
}

#[tokio::test]
async fn last_native_dns_failure_survives_the_family_race_for_diagnostics() {
    let result = race_connections(vec![Box::pin(async {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "physical_dns_timeout",
        ))
    })])
    .await;
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "physical_dns_timeout");
}

#[tokio::test]
async fn control_failure_observer_never_discloses_private_native_error_strings() {
    struct Broken {
        kind: io::ErrorKind,
    }
    impl Dialer for Broken {
        fn connect(&self, _: Origin) -> DialFuture {
            let kind = self.kind;
            Box::pin(async move {
                Err(io::Error::new(
                    kind,
                    "https://user:secret@private bearer-token",
                ))
            })
        }
    }
    for (kind, expected) in [
        (
            io::ErrorKind::NetworkUnreachable,
            "physical_route_unavailable",
        ),
        (io::ErrorKind::Other, "physical_connect_failed"),
    ] {
        let slot = Slot::new(
            Url::parse("http://127.0.0.1:9").unwrap(),
            Arc::new(Broken { kind }),
        );
        let (seen, mut events) = tokio::sync::mpsc::channel(1);
        slot.set_observer(Arc::new(move |code, _| {
            let _ = seen.try_send(code);
        }));
        assert!(slot
            .execute(Client::new().get("http://127.0.0.1:9").build().unwrap())
            .await
            .is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap(),
            Some(expected)
        );
    }
}

// Native transport uses the same real TLS fixtures as the ordinary client;
// only OS discovery/NIC dialing is replaced with a loopback route.
struct PanelRoute {
    primary: SocketAddr,
    backup: SocketAddr,
    calls: Arc<AtomicUsize>,
}
impl Dialer for PanelRoute {
    fn connect(&self, origin: Origin) -> DialFuture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let target = match origin.host.as_str() {
            "nelomai.ru" => self.primary,
            "nelomai.top" => self.backup,
            _ => panic!("unexpected native panel origin"),
        };
        Box::pin(async move { TcpStream::connect(target).await })
    }
}

#[tokio::test]
async fn native_panel_uses_independent_backup_tls_identity_after_pre_http_failure() {
    use crate::panel_dns::https_tests::{DnsAnswer, DnsScope, HttpsFixture, Reply};
    let primary = HttpsFixture::start_with(true, Reply::Status(200));
    let backup = HttpsFixture::start_with(true, Reply::Status(200));
    let _roots = DnsScope::new(DnsAnswer::Success, primary.address).with_roots(true);
    let calls = Arc::new(AtomicUsize::new(0));
    let origin = Url::parse("https://nelomai.ru/api/client/v1/auth/login").unwrap();
    let slot = Slot::new(
        origin.clone(),
        Arc::new(PanelRoute {
            primary: primary.address,
            backup: backup.address,
            calls: calls.clone(),
        }),
    );
    let request = Client::new()
        .post(origin)
        .header(reqwest::header::HOST, "nelomai.ru")
        .bearer_auth("native-synthetic")
        .body("one-native-post")
        .build()
        .unwrap();
    let result = slot.execute(request).await;
    assert!(result.is_ok(), "native fallback failed: {result:?}");
    assert_eq!(result.unwrap().url().host_str(), Some("nelomai.top"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let (request, sni) = primary.server.join().unwrap();
    assert!(request.is_none());
    assert_eq!(sni.as_deref(), Some("nelomai.ru"));
    let (request, sni) = backup.server.join().unwrap();
    assert_eq!(sni.as_deref(), Some("nelomai.top"));
    let request = request.unwrap().to_ascii_lowercase();
    assert!(request.contains("host: nelomai.top\r\n"));
    assert!(request.contains("authorization: bearer native-synthetic\r\n"));
    assert!(request.ends_with("\r\n\r\none-native-post"));
}

#[tokio::test]
async fn native_panel_never_replays_after_eof_http_error_or_same_origin_redirect() {
    use crate::panel_dns::https_tests::{DnsAnswer, DnsScope, HttpsFixture, Reply};
    for mode in 0..3 {
        let trap = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reply = match mode {
            0 => Reply::Eof,
            1 => Reply::Status(503),
            _ => Reply::Redirect("https://nelomai.ru/later-connect-failure".into()),
        };
        let primary = HttpsFixture::start_with(false, reply);
        let _roots = DnsScope::new(DnsAnswer::Success, primary.address).with_roots(true);
        let calls = Arc::new(AtomicUsize::new(0));
        let origin = Url::parse("https://nelomai.ru/api/client/v1/auth/login").unwrap();
        let slot = Slot::new(
            origin.clone(),
            Arc::new(PanelRoute {
                primary: primary.address,
                backup: trap.local_addr().unwrap(),
                calls: calls.clone(),
            }),
        );
        let result = slot
            .execute(
                Client::new()
                    .post(origin)
                    .body("once")
                    .timeout(Duration::from_millis(300))
                    .build()
                    .unwrap(),
            )
            .await;
        match mode {
            0 => assert!(result.is_err()),
            1 => assert_eq!(result.unwrap().status(), 503),
            _ => assert_eq!(result.unwrap().status(), 307),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "HTTP outcome triggered another native dial"
        );
        assert!(primary
            .server
            .join()
            .unwrap()
            .0
            .unwrap()
            .ends_with("\r\n\r\nonce"));
    }
}

struct TimedPanelRoute {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    primary: Duration,
    backup: Duration,
}
impl Dialer for TimedPanelRoute {
    fn connect(&self, origin: Origin) -> DialFuture {
        let delay = if origin.host == "nelomai.ru" {
            self.primary
        } else {
            self.backup
        };
        let calls = self.calls.clone();
        let drops = self.drops.clone();
        Box::pin(async move {
            struct Dropped(Arc<AtomicUsize>);
            impl Drop for Dropped {
                fn drop(&mut self) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
            let _drop = Dropped(drops);
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "controlled pre-send failure",
            ))
        })
    }
}

#[tokio::test]
async fn native_backup_shares_total_deadline() {
    let calls = Arc::new(AtomicUsize::new(0));
    let slot = Slot::new(
        Url::parse("https://nelomai.ru").unwrap(),
        Arc::new(TimedPanelRoute {
            calls: calls.clone(),
            drops: Arc::default(),
            primary: Duration::from_millis(150),
            backup: Duration::from_millis(300),
        }),
    );
    let start = std::time::Instant::now();
    let result = slot
        .execute(
            Client::new()
                .post("https://nelomai.ru/x")
                .body("once")
                .timeout(Duration::from_millis(250))
                .build()
                .unwrap(),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "safe pre-send failure did not reach backup"
    );
    assert!(
        start.elapsed() < Duration::from_millis(380),
        "backup restarted operation budget"
    );
}

#[tokio::test]
async fn native_cancellation_drops_dial_and_never_starts_backup() {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let slot = Slot::new(
        Url::parse("https://nelomai.ru").unwrap(),
        Arc::new(TimedPanelRoute {
            calls: calls.clone(),
            drops: drops.clone(),
            primary: Duration::from_secs(60),
            backup: Duration::from_secs(60),
        }),
    );
    let request = Client::new()
        .post("https://nelomai.ru/x")
        .body("once")
        .build()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(60), slot.execute(request))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "cancelled native dial survived its operation"
    );
}

#[tokio::test]
async fn native_backup_rejects_wrong_or_untrusted_certificate_without_credentials() {
    use crate::panel_dns::https_tests::{DnsAnswer, DnsScope, HttpsFixture, Reply};
    for trust_backup in [true, false] {
        let primary = HttpsFixture::start_with(true, Reply::Status(200));
        let backup = HttpsFixture::start_with(!trust_backup, Reply::Status(200));
        let _roots = DnsScope::new(DnsAnswer::Success, primary.address).with_roots(trust_backup);
        let origin = Url::parse("https://nelomai.ru/x").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let slot = Slot::new(
            origin.clone(),
            Arc::new(PanelRoute {
                primary: primary.address,
                backup: backup.address,
                calls: calls.clone(),
            }),
        );
        let result = slot
            .execute(
                Client::new()
                    .post(origin)
                    .bearer_auth("must-not-send")
                    .build()
                    .unwrap(),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(primary.server.join().unwrap().0.is_none());
        let (request, sni) = backup.server.join().unwrap();
        assert!(request.is_none());
        assert_eq!(sni.as_deref(), Some("nelomai.top"));
    }
}

static NATIVE_READER_CASES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn blocked_dns_workers_do_not_starve_fallback_metadata_and_cancelled_dns_queue() {
    let _serial = NATIVE_READER_CASES.lock().await;
    type Gate = Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;
    struct Release(Gate);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let gate: Gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Release(gate.clone());
    let started = Arc::new(AtomicUsize::new(0));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let gate = gate.clone();
        let started = started.clone();
        readers.push(tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(100),
                native_dns_read(move || {
                    started.fetch_add(1, Ordering::SeqCst);
                    let mut open = gate.0.lock().unwrap();
                    while !*open {
                        open = gate.1.wait(open).unwrap();
                    }
                    Ok(())
                }),
            )
            .await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while started.load(Ordering::SeqCst) != 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for reader in readers {
        assert!(reader.await.unwrap().is_err());
    }
    // This is the same admission path used by snapshot() and post-DNS NIC
    // revalidation. It must finish while every uncancellable DNS slot is busy.
    let metadata = tokio::time::timeout(Duration::from_millis(150), native_read(|| Ok(()))).await;
    assert!(
        metadata.is_ok(),
        "static-IP fallback metadata waited behind stalled native DNS"
    );
    metadata.unwrap().unwrap();
    let observed = started.clone();
    assert!(tokio::time::timeout(
        Duration::from_millis(40),
        native_dns_read(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    )
    .await
    .is_err());
    assert_eq!(
        started.load(Ordering::SeqCst),
        4,
        "DNS admission grew beyond its bounded workers"
    );
    drop(release);
    tokio::time::timeout(Duration::from_secs(2), native_dns_read(|| Ok(())))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        started.load(Ordering::SeqCst),
        4,
        "cancelled queued DNS read started after capacity returned"
    );
}

type ResolverLookup = Arc<dyn Fn(String, physical::Snapshot) -> ResolveFuture + Send + Sync>;
thread_local! {
    static RESOLVER: std::cell::RefCell<Option<ResolverLookup>> = const { std::cell::RefCell::new(None) };
}
type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<std::net::IpAddr>>> + Send>>;
pub(super) fn fixture_resolve(host: String, family: physical::Snapshot) -> Option<ResolveFuture> {
    RESOLVER.with(|slot| slot.borrow().as_ref().map(|lookup| lookup(host, family)))
}
struct ResolverScope;
impl Drop for ResolverScope {
    fn drop(&mut self) {
        RESOLVER.with(|slot| slot.replace(None));
        FIXTURE_NETWORK.with(|slot| slot.replace(None));
    }
}
fn dual_stack() -> physical::Snapshot {
    let interface = physical::Interface {
        index: 1,
        name: "fixture".into(),
        identity: "fixture".into(),
        addresses: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
        gateway: None,
    };
    physical::Snapshot {
        ipv4: Some(interface.clone()),
        ipv6: Some(interface),
    }
}
// Scoped OS DNS and physical interfaces/bind are fixture boundaries. The
// SystemDialer selects candidates and opens real TCP sockets to two local peers.
type TestDial = Arc<dyn Fn(std::net::IpAddr) -> DialFuture + Send + Sync>;
thread_local! {
    static FIXTURE_NETWORK: std::cell::RefCell<Option<(physical::Snapshot, TestDial)>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn fixture_snapshot() -> Option<physical::Snapshot> {
    FIXTURE_NETWORK.with(|slot| slot.borrow().as_ref().map(|(before, _)| before.clone()))
}
pub(super) fn fixture_dial(ip: std::net::IpAddr) -> Option<DialFuture> {
    FIXTURE_NETWORK.with(|slot| slot.borrow().as_ref().map(|(_, dial)| dial(ip)))
}

const HEALTHY_A: &str = "192.0.2.15";
const HEALTHY_AAAA: &str = "2001:db8::15";
const REFUSED_AAAA: &str = "2001:db8::dead";
const STATIC_IP: &str = "45.144.221.68";

type Answer = Option<(u64, &'static str)>;
async fn dns_race(
    host: &str,
    before: physical::Snapshot,
    // primary AAAA, primary A, secondary AAAA, secondary A; empty = negative.
    answers: [Answer; 4],
    wanted: Option<&str>,
    budget_ms: u64,
) {
    let _scope = ResolverScope;
    let healthy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trap = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good = healthy.local_addr().unwrap();
    let bad = trap.local_addr().unwrap();
    let wanted = wanted.map(|ip| ip.parse::<std::net::IpAddr>().unwrap());
    let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = attempts.clone();
    FIXTURE_NETWORK.with(|slot| {
        slot.replace(Some((
            before,
            Arc::new(move |ip| {
                seen.lock().unwrap().push(ip);
                if ip == REFUSED_AAAA.parse::<std::net::IpAddr>().unwrap() {
                    return Box::pin(async { Err(io::ErrorKind::ConnectionRefused.into()) })
                        as DialFuture;
                }
                Box::pin(TcpStream::connect(if Some(ip) == wanted {
                    good
                } else {
                    bad
                }))
            }),
        )))
    });
    let primary = host.to_owned();
    RESOLVER.with(|slot| {
        slot.replace(Some(Arc::new(move |name, family| {
            let index = usize::from(name != primary) * 2 + usize::from(family.ipv4.is_some());
            let answer = answers[index];
            Box::pin(async move {
                let Some((ms, addr)) = answer else {
                    return std::future::pending().await;
                };
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Ok(addr.parse().ok().into_iter().collect())
            })
        })))
    });
    let stream = tokio::time::timeout(
        Duration::from_millis(budget_ms),
        SystemDialer.connect(Origin {
            scheme: "https".into(),
            host: host.into(),
            port: 443,
        }),
    )
    .await
    .expect("family DNS starved a usable answer or restarted its budget");
    if let Some(wanted) = wanted {
        assert_eq!(
            stream.unwrap().peer_addr().unwrap(),
            good,
            "a lower-priority TCP peer stole the dial"
        );
        let dialed: Vec<_> = attempts
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|ip| *ip != REFUSED_AAAA.parse::<std::net::IpAddr>().unwrap())
            .collect();
        assert_eq!(dialed, vec![wanted]);
    } else {
        assert!(stream.is_err());
        assert!(attempts.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn dns_race_primary_aaaa_beats_static_and_secondary_a() {
    for secondary in ["", "192.0.2.99"] {
        dns_race(
            "nelomai.ru",
            dual_stack(),
            [
                Some((650, HEALTHY_AAAA)),
                Some((0, "")),
                Some((0, "")),
                Some((0, secondary)),
            ],
            Some(HEALTHY_AAAA),
            1800,
        )
        .await;
    }
}

#[tokio::test]
async fn dns_race_primary_a_beats_failed_aaaa() {
    dns_race(
        "nelomai.ru",
        dual_stack(),
        [
            Some((0, "")),
            Some((400, HEALTHY_A)),
            Some((0, "")),
            Some((0, "")),
        ],
        Some(HEALTHY_A),
        1500,
    )
    .await;
}

#[tokio::test]
async fn dns_race_each_usable_family_starts_before_silent_sibling_times_out() {
    for (a6, a4, want) in [
        (Some((0, HEALTHY_AAAA)), None, HEALTHY_AAAA),
        (None, Some((0, HEALTHY_A)), HEALTHY_A),
    ] {
        dns_race(
            "nelomai.ru",
            dual_stack(),
            [a6, a4, None, None],
            Some(want),
            800,
        )
        .await;
    }
}

#[tokio::test]
async fn dns_race_secondary_aaaa_beats_static_after_primary_dns_fails() {
    dns_race(
        "nelomai.ru",
        dual_stack(),
        [
            Some((0, "")),
            Some((0, "")),
            Some((650, HEALTHY_AAAA)),
            Some((0, "")),
        ],
        Some(HEALTHY_AAAA),
        1800,
    )
    .await;
}

#[tokio::test]
async fn dns_race_both_secondary_answers_survive_silent_primary() {
    dns_race(
        "nelomai.ru",
        dual_stack(),
        [None, None, Some((5, REFUSED_AAAA)), Some((50, HEALTHY_A))],
        Some(HEALTHY_A),
        1600,
    )
    .await;
}

#[tokio::test]
async fn dns_race_static_once_only_with_ipv4_and_only_for_panel_hosts() {
    let empty = [Some((0, "")); 4];
    dns_race("nelomai.ru", dual_stack(), empty, Some(STATIC_IP), 1500).await;
    let mut v6 = dual_stack();
    v6.ipv4 = None;
    dns_race("nelomai.top", v6, empty, None, 1500).await;
    dns_race(
        "foreign.example",
        dual_stack(),
        [
            Some((0, "")),
            Some((0, "")),
            Some((0, HEALTHY_AAAA)),
            Some((0, HEALTHY_A)),
        ],
        None,
        1500,
    )
    .await;
}

// Drive the real dialer's DNS ownership/deadline using virtual time; for
// these timing tests every physical TCP attempt is recorded and refused.
fn pending_dns() -> (
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Vec<std::net::IpAddr>>>,
) {
    let started = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = attempts.clone();
    FIXTURE_NETWORK.with(|slot| {
        slot.replace(Some((
            dual_stack(),
            Arc::new(move |ip| {
                seen.lock().unwrap().push(ip);
                Box::pin(async { Err(io::ErrorKind::ConnectionRefused.into()) })
            }),
        )))
    });
    struct CountDrop(Arc<AtomicUsize>);
    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let starts = started.clone();
    let drops = dropped.clone();
    RESOLVER.with(|slot| {
        slot.replace(Some(Arc::new(move |_, _| {
            let guard = CountDrop(drops.clone());
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let _guard = guard;
                std::future::pending().await
            })
        })))
    });
    (started, dropped, attempts)
}

#[tokio::test(start_paused = true)]
async fn dns_race_all_four_queries_share_one_deadline_and_static_is_attempted_once() {
    let _scope = ResolverScope;
    let (started, dropped, attempts) = pending_dns();
    let start = tokio::time::Instant::now();
    assert!(SystemDialer
        .connect(Origin {
            scheme: "https".into(),
            host: "nelomai.ru".into(),
            port: 443
        })
        .await
        .is_err());
    assert_eq!(started.load(Ordering::SeqCst), 4);
    assert_eq!(dropped.load(Ordering::SeqCst), 4);
    assert_eq!(
        *attempts.lock().unwrap(),
        vec![STATIC_IP.parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(
        (Duration::from_millis(1000)..Duration::from_millis(1010)).contains(&start.elapsed()),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn dns_race_cancelling_dial_drops_all_live_queries_before_static() {
    let _scope = ResolverScope;
    let (started, dropped, attempts) = pending_dns();
    assert!(tokio::time::timeout(
        Duration::from_millis(400),
        SystemDialer.connect(Origin {
            scheme: "https".into(),
            host: "nelomai.ru".into(),
            port: 443,
        })
    )
    .await
    .is_err());
    assert_eq!(started.load(Ordering::SeqCst), 4);
    assert_eq!(dropped.load(Ordering::SeqCst), 4);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn linux_dns_discovery_cannot_occupy_fallback_metadata_admission() {
    let _serial = NATIVE_READER_CASES.lock().await;
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let _release = Release(gate.clone());
    let started = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let gate = gate.clone();
        let started = started.clone();
        tasks.push(tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(100),
                resolve_linux_host(
                    "nelomai.ru".into(),
                    dual_stack(),
                    move |_| {
                        started.fetch_add(1, Ordering::SeqCst);
                        let mut open = gate.0.lock().unwrap();
                        while !*open {
                            open = gate.1.wait(open).unwrap();
                        }
                        Ok(Vec::new())
                    },
                    physical::bind_socket,
                ),
            )
            .await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while started.load(Ordering::SeqCst) != 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for task in tasks {
        assert!(task.await.unwrap().is_err());
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), native_read(|| Ok(())))
            .await
            .is_ok(),
        "Linux discovery still occupied snapshot admission"
    );
}

#[test]
fn cancelled_native_job_waiting_for_a_blocking_thread_never_starts() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        static ADMISSION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
        let (release, wait) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = wait.recv();
        });
        ready.await.unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let observed = ran.clone();
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            native_read_in(&ADMISSION, move || {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        )
        .await
        .is_err());
        release.send(()).unwrap();
        blocker.await.unwrap();
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "cancelled admitted job began after timeout"
        );
        assert_eq!(ADMISSION.available_permits(), 4);
        let error = native_read_in(&ADMISSION, || Err::<(), _>(io::ErrorKind::TimedOut.into()))
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::TimedOut,
            "blocking owner changed the native IO error contract"
        );
    });
}

#[tokio::test]
async fn artifact_download_adapter_uses_physical_dialer_without_tunnel_fallback() {
    let (ordinary, ordinary_hits, first) = server("tunnel").await;
    let (physical, physical_hits, second) = server("signed-package").await;
    let origin = Url::parse(&format!("http://{ordinary}")).unwrap();
    let mut api = crate::ClientApi::new(origin.as_str()).unwrap();
    api.http.control = Some(Arc::new(Slot::new(
        origin.clone(),
        Arc::new(Route {
            target: Some(physical),
        }),
    )));
    let url = origin
        .join("/api/client/v1/updates/artifacts/test.bin")
        .unwrap();
    let transport = api.update_transport(&url).unwrap();
    let builder = reqwest::Client::builder().no_proxy();
    #[cfg(unix)]
    let builder = builder.unix_socket(transport.unix_socket());
    #[cfg(windows)]
    let builder = builder.windows_named_pipe(transport.windows_named_pipe());
    let response = builder
        .build()
        .unwrap()
        .get(url.clone())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(response, "signed-package");
    assert_eq!(ordinary_hits.load(Ordering::SeqCst), 0);
    assert_eq!(physical_hits.load(Ordering::SeqCst), 1);
    api.http.control = Some(Arc::new(Slot::new(
        origin.clone(),
        Arc::new(Route { target: None }),
    )));
    let failed = api.update_transport(&url).unwrap();
    let builder = reqwest::Client::builder().no_proxy();
    #[cfg(unix)]
    let builder = builder.unix_socket(failed.unix_socket());
    #[cfg(windows)]
    let builder = builder.windows_named_pipe(failed.windows_named_pipe());
    assert!(builder.build().unwrap().get(url).send().await.is_err());
    assert_eq!(ordinary_hits.load(Ordering::SeqCst), 0);
    assert!(api
        .update_transport(&origin.join("/api/client/v1/profile").unwrap())
        .is_err());
    assert!(api
        .update_transport(
            &Url::parse("https://foreign.example/api/client/v1/updates/artifacts/x").unwrap()
        )
        .is_err());
    first.abort();
    second.abort();
}
