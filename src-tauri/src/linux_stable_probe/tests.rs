use super::*;
use nelomai_client_tunnel::TunnelMetrics;
use nelomai_contracts::RuntimeSlot;
use nelomai_unix_service::ServiceTunnelState;

const STRAY: &str = "[Interface]\nHeaderProtectionKey = test\nContentPaddingAddition = test\n";

fn start(probe: &mut StableProbe, configuration: &str, response: Response) {
    let request = probe.before_exchange(&Request::start(configuration.to_owned()));
    assert_eq!(probe.after_exchange(request, &response), None);
}

fn metrics(probe: &mut StableProbe, handshake: u64) -> Option<(&'static str, u64)> {
    let request = probe.before_exchange(&Request::metrics(false));
    let mut response = Response::success(None);
    response.metrics = Some(TunnelMetrics {
        latest_handshake_epoch_millis: Some(handshake),
        ..Default::default()
    });
    probe.after_exchange(request, &response)
}

#[test]
fn legacy_stable_only() {
    let mut target = RuntimeTarget {
        container_version: "0.4.3".into(),
        runtime_version: "0.3.11".into(),
        runtime_contract_version: 1,
        runtime_slot: RuntimeSlot::Stable,
    };
    assert!(StableProbe::supports(&target));
    target.runtime_slot = RuntimeSlot::Latest;
    assert!(!StableProbe::supports(&target));
    target.runtime_slot = RuntimeSlot::Stable;
    target.runtime_version = "0.4.3".into();
    assert!(!StableProbe::supports(&target));
}

#[test]
fn first_handshake_issues_one_check_for_the_admitted_start() {
    let running = || Response::success(Some(ServiceTunnelState::Running));
    let mut probe = StableProbe::default();
    assert_eq!(metrics(&mut probe, 100), None);
    start(&mut probe, STRAY, running());
    assert_eq!(metrics(&mut probe, 0), None);
    assert_eq!(metrics(&mut probe, 100), Some(("nlm-awg0", 100)));
    assert_eq!(metrics(&mut probe, 101), None);

    start(&mut probe, "[Interface]\n", running());
    assert_eq!(metrics(&mut probe, 200), Some(("nlm-wg0", 200)));
    assert_eq!(metrics(&mut probe, 201), None);
}

#[test]
fn stale_work_is_cleared_on_stop_or_unsuccessful_start() {
    let running = || Response::success(Some(ServiceTunnelState::Running));
    let mut probe = StableProbe::default();
    start(&mut probe, STRAY, running());
    let stop = probe.before_exchange(&Request::stop());
    assert_eq!(probe.after_exchange(stop, &Response::failure("busy")), None);
    assert_eq!(metrics(&mut probe, 100), None);

    start(&mut probe, STRAY, running());
    start(&mut probe, STRAY, Response::failure("busy"));
    assert_eq!(metrics(&mut probe, 100), None);

    start(&mut probe, STRAY, running());
    probe.cancel();
    assert_eq!(metrics(&mut probe, 100), None);
}

#[test]
fn invalid_metrics_reply_does_not_consume_the_probe() {
    let mut probe = StableProbe::default();
    start(
        &mut probe,
        STRAY,
        Response::success(Some(ServiceTunnelState::Running)),
    );
    let mut invalid = Response::success(None);
    invalid.protocol_version += 1;
    invalid.metrics = Some(TunnelMetrics {
        latest_handshake_epoch_millis: Some(100),
        ..Default::default()
    });
    let request = probe.before_exchange(&Request::metrics(false));
    assert_eq!(probe.after_exchange(request, &invalid), None);
    assert_eq!(metrics(&mut probe, 100), Some(("nlm-awg0", 100)));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn fresh_probe_requires_the_selected_interface() {
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    // A loopback HTTP fixture exercises actual Linux binding without contacting
    // the panel. Production passes only the fixed panel HTTPS URL.
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://localhost:{}/health",
        server.local_addr().unwrap().port()
    );
    let serve = async {
        let (mut stream, _) = server.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() < 4096);
        }
        assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    };
    let (_, checked) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve, check("lo", &url))
    })
    .await
    .unwrap();
    assert_eq!(checked, ProbeOutcome::Succeeded);

    // Exercise the socket after route approval. The missing interface must
    // reject the connection even though loopback is reachable without a bind.
    let addresses = [server.local_addr().unwrap()];
    let attempt = probe_checked_addresses(
        "nlm-no-probe",
        url.parse().unwrap(),
        &addresses,
        tokio::time::Instant::now() + Duration::from_secs(1),
    );
    tokio::select! {
        biased;
        accepted = server.accept() => {
            let _ = accepted.unwrap();
            panic!("probe reached the server without the selected interface");
        }
        outcome = attempt => assert_eq!(outcome, ProbeOutcome::Failed),
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn stop_aborts_the_in_flight_probe() {
    let (begun, running) = tokio::sync::oneshot::channel();
    let (on_drop, dropped) = tokio::sync::oneshot::channel::<()>();
    let mut probe = StableProbe {
        pending_interface: None,
        task: Some(tokio::spawn(async move {
            let _on_drop = on_drop;
            begun.send(()).unwrap();
            std::future::pending::<()>().await
        })),
    };
    running.await.unwrap();
    probe.before_exchange(&Request::stop());
    // Sender destruction here proves that the suspended task has been dropped.
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped)
            .await
            .unwrap()
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn outside_route_is_a_skip_without_any_http_connection() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/health", server.local_addr().unwrap());
    assert_eq!(
        check("nlm-probe-absent", &url).await,
        ProbeOutcome::OutsideTunnel
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), server.accept())
            .await
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn completed_probes_survive_stop_start_without_entering_legacy_diagnostics() {
    struct Helper {
        handshake: u64,
    }
    #[async_trait::async_trait]
    impl ServiceTransport for Helper {
        async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
            match request {
                Request::Start { .. } => Ok(Response::success(Some(ServiceTunnelState::Running))),
                Request::Stop { .. } => Ok(Response::success(Some(ServiceTunnelState::Stopped))),
                Request::Metrics { .. } => {
                    let mut response = Response::success(None);
                    response.metrics = Some(TunnelMetrics {
                        latest_handshake_epoch_millis: Some(self.handshake),
                        ..Default::default()
                    });
                    Ok(response)
                }
                Request::Diagnostics { .. } => {
                    let mut response = Response::success(None);
                    response.diagnostics = Some("helper evidence".into());
                    Ok(response)
                }
                _ => panic!("unexpected native request"),
            }
        }
    }

    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("common");
    // Loopback is outside the AWG interface, so no request reaches the panel.
    let probe_base = "http://127.0.0.1";
    let mut probe = StableProbe::default();
    let mut replies = Vec::new();
    for handshake in [12345, 23456] {
        let helper = Helper { handshake };
        probe
            .exchange(
                &helper,
                Request::start(STRAY.into()),
                &directory,
                probe_base,
            )
            .await
            .unwrap();
        probe
            .exchange(&helper, Request::metrics(false), &directory, probe_base)
            .await
            .unwrap();
        let task = probe.task.as_mut().expect("Metrics must schedule a probe");
        tokio::time::timeout(std::time::Duration::from_secs(4), task)
            .await
            .expect("probe must finish")
            .unwrap();
        replies.push(
            probe
                .exchange(&helper, Request::diagnostics(), &directory, probe_base)
                .await
                .unwrap(),
        );
        probe
            .exchange(&helper, Request::stop(), &directory, probe_base)
            .await
            .unwrap();
    }

    // A runtime may hold either reply and upload it after an account change.
    for reply in replies {
        assert_eq!(reply.diagnostics.as_deref(), Some("helper evidence"));
    }
    let journal = std::fs::read_to_string(directory.join("tunnel-probe.jsonl")).unwrap();
    let handshakes: Vec<_> = journal
        .lines()
        .map(|line| {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(record["probe_outcome"], "skipped_outside_tunnel");
            record["latest_handshake_epoch_millis"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(handshakes, [12345, 23456]);
}
