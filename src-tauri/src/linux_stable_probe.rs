use nelomai_client_api::RuntimeTarget;
#[cfg(target_os = "linux")]
use nelomai_client_container::StableTunnelProbeOutcome as ProbeOutcome;
use nelomai_client_tunnel::{detect_configuration_transport, TunnelTransport};
use nelomai_contracts::RuntimeSlot;
use nelomai_unix_service::{Request, Response, ServiceTunnelState, PROTOCOL_VERSION};
#[cfg(target_os = "linux")]
use nelomai_unix_service::{ServiceError, ServiceTransport};

#[derive(Clone, Copy)]
enum Observation {
    Start(TunnelTransport),
    Metrics,
    Ignore,
}

#[derive(Default)]
pub(super) struct StableProbe {
    pending_interface: Option<&'static str>,
    #[cfg(target_os = "linux")]
    task: Option<tokio::task::JoinHandle<()>>,
}

impl StableProbe {
    pub(super) fn supports(target: &RuntimeTarget) -> bool {
        target.runtime_slot == RuntimeSlot::Stable && target.runtime_version == "0.3.11"
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn exchange(
        &mut self,
        transport: &impl ServiceTransport,
        request: Request,
        directory: &std::path::Path,
        probe_base: &str,
    ) -> Result<Response, ServiceError> {
        let observed = self.before_exchange(&request);
        // Stable can upload a Diagnostics reply under a later auth session.
        // Keep Common's probe results in the separate support journal.
        let response = transport.exchange(request).await?;
        if let Some((interface, handshake)) = self.after_exchange(observed, &response) {
            self.schedule(
                interface,
                handshake,
                directory.to_owned(),
                format!("{probe_base}/health"),
            );
        }
        Ok(response)
    }

    fn before_exchange(&mut self, request: &Request) -> Observation {
        match request {
            Request::Start { configuration, .. } => {
                self.cancel();
                Observation::Start(detect_configuration_transport(configuration))
            }
            Request::Stop { .. } | Request::StopIfUnowned { .. } => {
                self.cancel();
                Observation::Ignore
            }
            Request::Metrics { .. } => Observation::Metrics,
            _ => Observation::Ignore,
        }
    }

    fn after_exchange(
        &mut self,
        observed: Observation,
        response: &Response,
    ) -> Option<(&'static str, u64)> {
        if response.protocol_version != PROTOCOL_VERSION || !response.ok {
            return None;
        }
        match observed {
            Observation::Start(transport)
                if response.state == Some(ServiceTunnelState::Running) =>
            {
                // These are the single-tunnel names in the signed 0.3.11 engine.
                self.pending_interface = Some(match transport {
                    TunnelTransport::WireGuard => "nlm-wg0",
                    TunnelTransport::AmneziaWg3 => "nlm-awg0",
                });
                None
            }
            Observation::Metrics => {
                let handshake = response.metrics.as_ref()?.latest_handshake_epoch_millis?;
                if handshake == 0 {
                    return None;
                }
                self.pending_interface.take().map(|name| (name, handshake))
            }
            _ => None,
        }
    }

    pub(super) fn cancel(&mut self) {
        self.pending_interface = None;
        #[cfg(target_os = "linux")]
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }

    #[cfg(target_os = "linux")]
    fn schedule(
        &mut self,
        interface: &'static str,
        handshake: u64,
        directory: std::path::PathBuf,
        url: String,
    ) {
        self.task = Some(tokio::spawn(async move {
            let status = check(interface, &url).await;
            let _ =
                nelomai_client_container::record_stable_tunnel_probe(&directory, handshake, status);
        }));
    }
}

impl Drop for StableProbe {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(target_os = "linux")]
async fn check(interface: &str, url: &str) -> ProbeOutcome {
    use tokio::time::{timeout_at, Duration, Instant};

    let Ok(url) = reqwest_updater::Url::parse(url) else {
        return ProbeOutcome::RouteUnavailable;
    };
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return ProbeOutcome::RouteUnavailable;
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let addresses = match timeout_at(deadline, tunnel_addresses(interface, host, port)).await {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(outcome)) => return outcome,
        Err(_) => return ProbeOutcome::RouteUnavailable,
    };
    probe_checked_addresses(interface, url, &addresses, deadline).await
}

#[cfg(target_os = "linux")]
async fn probe_checked_addresses(
    interface: &str,
    url: reqwest_updater::Url,
    addresses: &[std::net::SocketAddr],
    deadline: tokio::time::Instant,
) -> ProbeOutcome {
    use tokio::time::{timeout_at, Instant};

    let Some(host) = url.host_str() else {
        return ProbeOutcome::RouteUnavailable;
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return ProbeOutcome::RouteUnavailable;
    }
    // Keep the exact route-checked addresses. A second DNS lookup could pick
    // an excluded address and the interface binding would force it through VPN.
    let Ok(client) = nelomai_client_api::panel_http_client_builder()
        .no_proxy()
        .resolve_to_addrs(host, addresses)
        .interface(interface)
        .http1_only()
        .pool_max_idle_per_host(0)
        .connect_timeout(remaining)
        .timeout(remaining)
        .build()
    else {
        return ProbeOutcome::Failed;
    };
    match timeout_at(deadline, client.get(url).send()).await {
        Ok(Ok(response)) if response.status().is_success() => ProbeOutcome::Succeeded,
        _ => ProbeOutcome::Failed,
    }
}

#[cfg(target_os = "linux")]
async fn tunnel_addresses(
    interface: &str,
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, ProbeOutcome> {
    let ip_command = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .ok_or(ProbeOutcome::RouteUnavailable)?;
    let addresses = nelomai_client_api::resolve_panel_addresses(host)
        .await
        .map_err(|_| ProbeOutcome::RouteUnavailable)?;
    let mut unavailable = addresses.is_empty();
    let mut eligible = Vec::new();
    for address in addresses {
        let address = std::net::SocketAddr::new(address.ip(), port);
        match route_device(ip_command, address).await {
            Some(device) if device == interface => eligible.push(address),
            Some(_) => {}
            None => unavailable = true,
        }
    }
    if eligible.is_empty() {
        return Err(if unavailable {
            ProbeOutcome::RouteUnavailable
        } else {
            ProbeOutcome::OutsideTunnel
        });
    }
    Ok(eligible)
}

#[cfg(target_os = "linux")]
async fn route_device(ip_command: &str, address: std::net::SocketAddr) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Route {
        dev: String,
    }

    let family = if address.is_ipv4() { "-4" } else { "-6" };
    // No oif/source constraint. Ask for the ordinary route of a TCP socket.
    let output = tokio::process::Command::new(ip_command)
        .args([
            "-j",
            family,
            "route",
            "get",
            &address.ip().to_string(),
            "ipproto",
            "tcp",
            "dport",
            &address.port().to_string(),
        ])
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut routes: Vec<Route> = serde_json::from_slice(&output.stdout).ok()?;
    if routes.len() != 1 {
        return None;
    }
    routes.pop().map(|route| route.dev)
}

#[cfg(test)]
mod tests;
