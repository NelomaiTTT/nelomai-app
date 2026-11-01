use super::*;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
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
        server(r#"{"api_version":"1","entries":[{"version":"vpn","notes":"ordinary"}]}"#).await;
    let (physical, physical_hits, second) =
        server(r#"{"api_version":"1","entries":[{"version":"direct","notes":"physical"}]}"#).await;
    let origin = Url::parse(&format!("http://{ordinary}")).unwrap();
    let mut api = crate::ClientApi::new(origin.as_str()).unwrap();
    api.http.control = Some(Arc::new(Slot::new(
        origin.clone(),
        Arc::new(Route {
            target: Some(physical),
        }),
    )));
    let history = api.release_history().await.unwrap();
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
