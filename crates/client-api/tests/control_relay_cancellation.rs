//! Exercise the production relay in its own process, so filling its global
//! connection limit cannot interfere with parallel client-api unit tests.
#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::time::Duration;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

#[path = "../src/control_transport"]
mod control_transport {
    use std::{future::Future, io, pin::Pin, sync::Arc};
    use tokio::net::TcpStream;

    #[derive(Clone)]
    pub(super) struct Origin;
    pub(super) type DialFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
    pub(super) trait Dialer: Send + Sync {
        fn connect(&self, origin: Origin) -> DialFuture;
    }
    #[path = "local_close.rs"]
    mod local_close;
    mod relay {
        pub(super) async fn connect_test_client(listener: &Listener) -> tokio::net::UnixStream {
            tokio::net::UnixStream::connect(listener.local_name())
                .await
                .unwrap()
        }
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/control_transport/relay.rs"
        ));
    }

    #[cfg(test)]
    mod cancellation {
        use super::*;
        use crate::{Duration, HTTP_CONNECT_TIMEOUT};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        use tokio_rustls::rustls::{
            self,
            pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        };

        static CASES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        struct Route(std::net::SocketAddr);
        impl Dialer for Route {
            fn connect(&self, _: Origin) -> DialFuture {
                let address = self.0;
                Box::pin(async move { TcpStream::connect(address).await })
            }
        }
        fn acceptor() -> tokio_rustls::TlsAcceptor {
            let chain = CertificateDer::pem_slice_iter(include_bytes!(
                "../src/control_transport/testdata/chain.pem"
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let key = PrivateKeyDer::from_pem_slice(include_bytes!(
                "../src/control_transport/testdata/end.key"
            ))
            .unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        }
        fn client(address: std::net::SocketAddr) -> (reqwest::Client, relay::Relay) {
            let listener = relay::Listener::bind().unwrap();
            let root = reqwest::Certificate::from_pem(include_bytes!(
                "../src/control_transport/testdata/root.pem"
            ))
            .unwrap();
            let client = listener
                .configure(
                    reqwest::Client::builder()
                        .no_proxy()
                        .add_root_certificate(root)
                        .connect_timeout(HTTP_CONNECT_TIMEOUT)
                        .timeout(Duration::from_secs(20)),
                )
                .build()
                .unwrap();
            let relay = relay::Relay::start(listener, Arc::new(Route(address)), Origin);
            relay.set_observer(None);
            (client, relay)
        }

        #[tokio::test]
        async fn blocked_diagnostics_do_not_hold_runtime_or_connection_capacity() {
            let _serial = CASES.lock().await;
            struct Broken;
            impl Dialer for Broken {
                fn connect(&self, _: Origin) -> DialFuture {
                    Box::pin(async {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "physical_dns_timeout",
                        ))
                    })
                }
            }
            struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
            impl Drop for Release {
                fn drop(&mut self) {
                    let (done, wake) = &*self.0;
                    *done.lock().unwrap() = true;
                    wake.notify_all();
                }
            }
            let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
            let release = Release(gate.clone());
            let (entered, mut started) = tokio::sync::mpsc::channel(16);
            let endpoint = relay::Listener::bind().unwrap();
            let broken = endpoint
                .configure(reqwest::Client::builder().no_proxy())
                .build()
                .unwrap();
            let relay = relay::Relay::start(endpoint, Arc::new(Broken), Origin);
            relay.set_observer(Some(Arc::new(move |_, _| {
                let _ = entered.try_send(());
                // Bounded even if the test panics: a stuck disk must not occupy
                // the sole async worker or any of the 16 connection slots.
                let _ = gate.1.wait_timeout_while(
                    gate.0.lock().unwrap(),
                    Duration::from_secs(3),
                    |done| !*done,
                );
            })));
            for _ in 0..16 {
                let before = std::time::Instant::now();
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    broken.get("http://foobar.com/").send(),
                )
                .await;
                assert!(
                    matches!(result, Ok(Err(_))),
                    "diagnostic callback delayed the transport error: {result:?}"
                );
                assert!(
                    before.elapsed() < Duration::from_secs(1),
                    "diagnostic callback blocked the async worker"
                );
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), started.recv())
                        .await
                        .unwrap(),
                    Some(())
                );
            }
            // With all log jobs stuck, another failure still completes and a
            // healthy request can use the entire connection budget.
            assert!(tokio::time::timeout(
                Duration::from_secs(1),
                broken.get("http://foobar.com/").send(),
            )
            .await
            .unwrap()
            .is_err());
            let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (healthy, _relay) = client(server.local_addr().unwrap());
            let serve = tokio::spawn(async move {
                let (mut socket, _) = server.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
            });
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                healthy.get("http://foobar.com/").send(),
            )
            .await
            .unwrap()
            .expect("diagnostic callbacks retained connection permits");
            assert_eq!(response.text().await.unwrap(), "ok");
            serve.await.unwrap();
            drop(release);
        }

        #[tokio::test]
        async fn early_https_response_is_read_in_full_during_upload() {
            let _serial = CASES.lock().await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (release, ready) = tokio::sync::oneshot::channel();
            let origin = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor().accept(socket).await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 8192];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let n = socket.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                }
                assert!(request.len() < 1024 * 1024);
                socket.write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 16384\r\nConnection: close\r\n\r\n").await.unwrap();
                socket.write_all(&vec![b'x'; 16384]).await.unwrap();
                socket.shutdown().await.unwrap();
                // Keep the origin read half alive: its lifetime is not the cause.
                let _ = ready.await;
            });
            let (client, _relay) = client(address);
            let response = client
                .post("https://foobar.com:31999/")
                .body(vec![b'u'; 1024 * 1024])
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
            let result = response.bytes().await;
            let _ = release.send(());
            origin.await.unwrap();
            assert!(
                result.is_ok(),
                "relay truncated the early response: {result:?}"
            );
            assert_eq!(result.unwrap().as_ref(), vec![b'x'; 16384]);
        }

        #[tokio::test]
        async fn client_tls_write_half_close_still_allows_reading_the_response() {
            let _serial = CASES.lock().await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let origin = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor().accept(socket).await.unwrap();
                let mut request = Vec::new();
                socket.read_to_end(&mut request).await.unwrap();
                assert!(request.starts_with(b"GET / HTTP/1.1"));
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
                socket.shutdown().await.unwrap();
            });
            let endpoint = relay::Listener::bind().unwrap();
            let client = relay::connect_test_client(&endpoint).await;
            let _relay = relay::Relay::start(endpoint, Arc::new(Route(address)), Origin);
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(
                    CertificateDer::from_pem_slice(include_bytes!(
                        "../src/control_transport/testdata/root.pem"
                    ))
                    .unwrap(),
                )
                .unwrap();
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let mut client = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("foobar.com").unwrap(),
                    client,
                )
                .await
                .unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: foobar.com\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            let result = client.read_to_end(&mut response).await;
            assert!(
                result.is_ok(),
                "write half-close cancelled response: {result:?}"
            );
            assert!(response.ends_with(b"\r\n\r\nok"));
            origin.await.unwrap();
        }

        #[tokio::test]
        async fn timed_out_https_requests_release_capacity_before_remote_eof() {
            let _serial = CASES.lock().await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let eof_count = Arc::new(AtomicUsize::new(0));
            let peers = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let acceptor = acceptor();
            let origin = tokio::spawn({
                let eof_count = eof_count.clone();
                let peers = peers.clone();
                async move {
                    loop {
                        let (socket, _) = listener.accept().await.unwrap();
                        let mut socket = acceptor.accept(socket).await.unwrap();
                        let eof_count = eof_count.clone();
                        let peers = peers.clone();
                        tokio::spawn(async move {
                            let mut bytes = [0; 4096];
                            loop {
                                match socket.read(&mut bytes).await {
                                    Ok(0) => break,
                                    Ok(_) => {}
                                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                                        break
                                    }
                                    Err(error) => panic!("unexpected TLS read: {error}"),
                                }
                            }
                            // Retain the remote write half after observing local EOF.
                            peers.lock().await.push(socket);
                            eof_count.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                }
            });
            let (old, old_relay) = client(address);
            let mut requests = Vec::new();
            for _ in 0..16 {
                let old = old.clone();
                requests.push(tokio::spawn(async move {
                    old.get("https://foobar.com:31999/").send().await
                }));
            }
            for request in requests {
                assert!(request.await.unwrap().unwrap_err().is_timeout());
            }
            drop(old);
            assert!(
                old_relay.is_running(),
                "request cancellation stopped the acceptor"
            );
            drop(old_relay);
            tokio::time::timeout(Duration::from_secs(2), async {
                while eof_count.load(Ordering::SeqCst) != 16 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (fresh, _relay) = client(listener.local_addr().unwrap());
            let healthy = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = self::acceptor().accept(socket).await.unwrap();
                let mut bytes = [0; 4096];
                assert!(socket.read(&mut bytes).await.unwrap() > 0);
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            });
            let response = fresh.get("https://foobar.com:31999/").send().await;
            assert!(
                response.is_ok(),
                "cancelled requests exhausted capacity after reset: {response:?}"
            );
            assert_eq!(response.unwrap().text().await.unwrap(), "ok");
            healthy.await.unwrap();
            assert_eq!(peers.lock().await.len(), 16);
            origin.abort();
        }
    }
}
