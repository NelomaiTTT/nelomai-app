//! Pin one endpoint before a desktop member reaches the literal-only owner.
use crate::CoreError;
use nelomai_client_tunnel::redundancy::protocol::Command;
use nelomai_client_tunnel::TunnelConfiguration;
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    ops::Range,
    time::Duration,
};
use zeroize::Zeroizing;

const DNS_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) async fn pin_command(command: Command) -> Result<Command, CoreError> {
    pin_command_with(command, |host, port| async move {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(|answers| answers.collect())
    })
    .await
}

async fn pin_command_with<F, R>(mut command: Command, resolve: F) -> Result<Command, CoreError>
where
    F: FnOnce(String, u16) -> R,
    R: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let member = match &mut command {
        Command::Start { primary, .. } => primary,
        Command::Attach { member, .. } | Command::StageCandidate { member, .. } => member,
        _ => return Ok(command),
    };
    pin_with(&mut member.configuration, resolve).await?;
    Ok(command)
}

async fn pin_with<F, R>(
    configuration: &mut TunnelConfiguration,
    resolve: F,
) -> Result<(), CoreError>
where
    F: FnOnce(String, u16) -> R,
    R: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let range = endpoint_range(configuration.expose())?;
    let value = &configuration.expose()[range.clone()];
    if let Ok(address) = value.parse::<SocketAddr>() {
        return usable(address).then_some(()).ok_or_else(invalid_endpoint);
    }
    let (host, port) = value.rsplit_once(':').ok_or_else(invalid_endpoint)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(invalid_endpoint)?;
    if !dns_name(host) {
        return Err(invalid_endpoint());
    }
    let answers = tokio::time::timeout(DNS_TIMEOUT, resolve(host.to_owned(), port))
        .await
        .map_err(|_| CoreError::Tunnel("endpoint_resolution_timeout".into()))?
        .map_err(|_| CoreError::Tunnel("endpoint_resolution_failed".into()))?;
    // Match the ordinary path's IPv4 preference. The exact same selected IP is
    // then consumed by the native tunnel, physical route and endpoint guard.
    let address = answers
        .into_iter()
        .filter(|a| a.port() == port && usable(*a))
        .min_by_key(|a| if a.is_ipv4() { 0 } else { 1 })
        .ok_or_else(|| CoreError::Tunnel("endpoint_resolution_failed".into()))?;
    // Preserve AWG parameters, keys, formatting and line endings byte-for-byte.
    // The temporary key-bearing copy is zeroized even if this function unwinds.
    let mut output = Zeroizing::new(String::with_capacity(configuration.as_bytes().len() + 64));
    output.push_str(&configuration.expose()[..range.start]);
    output.push_str(&address.to_string());
    output.push_str(&configuration.expose()[range.end..]);
    *configuration = TunnelConfiguration::new(std::mem::take(&mut *output));
    Ok(())
}

fn invalid_endpoint() -> CoreError {
    CoreError::Tunnel("endpoint_invalid".into())
}

fn usable(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    let ip = match address {
        SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0 => return false,
        SocketAddr::V6(a) => a
            .ip()
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(*a.ip())),
        _ => address.ip(),
    };
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(a) if a.is_broadcast())
}

fn dns_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && !host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Locate only the single peer's Endpoint. Native parsing still validates the
/// complete configuration; this is not a replacement for its security checks.
fn endpoint_range(input: &str) -> Result<Range<usize>, CoreError> {
    if input.len() > 512 * 1024 || input.contains('\0') {
        return Err(invalid_endpoint());
    }
    let mut in_peer = false;
    let mut peers = 0;
    let mut endpoint = None;
    let mut offset = 0;
    for raw in input.split_inclusive('\n') {
        // Match the Windows member parser's comment/case handling without
        // rewriting those bytes. Native parsing still validates its own syntax.
        let content = raw.split('#').next().unwrap_or_default();
        let line = content.trim();
        if line.starts_with('[') {
            in_peer = line.eq_ignore_ascii_case("[Peer]");
            if in_peer {
                peers += 1;
            }
        } else if let Some((key, value)) = content.split_once('=') {
            if key.trim().eq_ignore_ascii_case("Endpoint") {
                if !in_peer || endpoint.is_some() || value.trim().is_empty() {
                    return Err(invalid_endpoint());
                }
                let start = offset + key.len() + 1 + value.len() - value.trim_start().len();
                endpoint = Some(start..start + value.trim().len());
            }
        }
        offset += raw.len();
    }
    if peers != 1 {
        return Err(invalid_endpoint());
    }
    endpoint.ok_or_else(invalid_endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(endpoint: &str) -> TunnelConfiguration {
        TunnelConfiguration::new(format!(
            "[Interface]\r\nPrivateKey = secret\r\nJc = 4\r\n[Peer]\r\nPublicKey = public\r\n  Endpoint = {endpoint}  \r\nAllowedIPs = 0.0.0.0/0\r\n"
        ))
    }

    #[tokio::test]
    async fn windows_peer_section_case_is_preserved() {
        for section in ["[peer]", "[PEER]", "[pEeR]"] {
            let input = format!(
                "[Interface]\nPrivateKey = secret\n{section}\nEndpoint = 192.0.2.5:51820\n"
            );
            let mut value = TunnelConfiguration::new(input.clone());
            pin_with(&mut value, |_, _| async {
                panic!("numeric endpoint must not resolve")
            })
            .await
            .unwrap();
            assert_eq!(value.expose(), input);
        }
    }

    #[tokio::test]
    async fn windows_literal_endpoint_comments_are_preserved_without_dns() {
        for input in [
            "[Interface]\n[Peer]\nEndpoint = 192.0.2.5:51820 # server\n",
            "[Interface]\r\n[Peer] # резерв\r\n\tEndpoint = [2001:db8::5]:51820# IPv6\r\n",
        ] {
            let mut value = TunnelConfiguration::new(input.into());
            pin_with(&mut value, |_, _| async {
                panic!("numeric endpoint must not resolve")
            })
            .await
            .unwrap();
            assert_eq!(value.expose(), input);
        }
    }

    #[tokio::test]
    async fn windows_hostname_pinning_changes_only_value_before_comment() {
        let input = "# [Peer] и Endpoint = ignored:1\r\n[Interface]\r\nPrivateKey = secret\r\n[pEeR] # основной\r\n\tEndpoint = 1b.nelomai.ru:20004 \t# сохранить Endpoint = other:1\r\nAllowedIPs = 0.0.0.0/0";
        let expected = "# [Peer] и Endpoint = ignored:1\r\n[Interface]\r\nPrivateKey = secret\r\n[pEeR] # основной\r\n\tEndpoint = 192.0.2.4:20004 \t# сохранить Endpoint = other:1\r\nAllowedIPs = 0.0.0.0/0";
        let mut value = TunnelConfiguration::new(input.into());
        pin_with(&mut value, |host, port| async move {
            assert_eq!((host.as_str(), port), ("1b.nelomai.ru", 20004));
            Ok(vec!["192.0.2.4:20004".parse().unwrap()])
        })
        .await
        .unwrap();
        assert_eq!(value.expose(), expected);
    }

    #[tokio::test]
    async fn windows_comments_do_not_hide_duplicate_or_missing_endpoints() {
        for input in [
            "[Peer]\nEndpoint = 192.0.2.1:4 # first\neNdPoInT = 192.0.2.2:4 # second\n",
            "[Peer]\nEndpoint = 192.0.2.1:4\n[peer] # second\n",
            "[Peer]\nEndpoint = # missing\n",
            "[Peer]\n# Endpoint = 192.0.2.1:4\n",
            "[Interface]\nEndpoint = 192.0.2.1:4 # wrong section\n[Peer]\n",
        ] {
            let mut value = TunnelConfiguration::new(input.into());
            assert!(pin_with(&mut value, |_, _| async {
                panic!("invalid configuration must not resolve")
            })
            .await
            .is_err());
            assert_eq!(value.expose(), input);
        }
    }

    #[tokio::test]
    async fn domain_is_pinned_once_preferring_ipv4_without_changing_other_bytes() {
        let mut value = config("1b.nelomai.ru:20004");
        pin_with(&mut value, |host, port| async move {
            assert_eq!(host, "1b.nelomai.ru");
            assert_eq!(port, 20004);
            Ok(vec![
                "[2001:db8::1]:20004".parse().unwrap(),
                "192.0.2.4:20004".parse().unwrap(),
            ])
        })
        .await
        .unwrap();
        assert_eq!(value.expose(), config("192.0.2.4:20004").expose());
    }

    #[tokio::test]
    async fn ipv6_answer_is_bracketed_and_numeric_endpoints_never_resolve() {
        let mut value = config("5b.nelomai.ru:20006");
        pin_with(&mut value, |_, _| async {
            Ok(vec!["[2001:db8::5]:20006".parse().unwrap()])
        })
        .await
        .unwrap();
        assert_eq!(value.expose(), config("[2001:db8::5]:20006").expose());
        for endpoint in ["192.0.2.4:20004", "[2001:db8::5]:20006"] {
            let mut value = config(endpoint);
            pin_with(&mut value, |_, _| async {
                panic!("numeric endpoint must not resolve")
            })
            .await
            .unwrap();
            assert_eq!(value.expose(), config(endpoint).expose());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dns_timeout_is_bounded_and_does_not_mutate_configuration() {
        let mut value = config("1b.nelomai.ru:20004");
        let before = tokio::time::Instant::now();
        let result = pin_with(&mut value, |_, _| std::future::pending()).await;
        assert!(
            matches!(result, Err(CoreError::Tunnel(code)) if code == "endpoint_resolution_timeout")
        );
        assert!(before.elapsed() <= std::time::Duration::from_secs(3));
        assert_eq!(value.expose(), config("1b.nelomai.ru:20004").expose());
    }

    #[tokio::test]
    async fn dns_failure_is_safe_and_never_falls_back_to_unpinned_config() {
        let mut value = config("1b.nelomai.ru:20004");
        let result = pin_with(&mut value, |_, _| async {
            Err(io::Error::other("secret resolver diagnostics"))
        })
        .await;
        assert!(
            matches!(result, Err(CoreError::Tunnel(code)) if code == "endpoint_resolution_failed")
        );
        assert_eq!(value.expose(), config("1b.nelomai.ru:20004").expose());
    }

    #[tokio::test]
    async fn invalid_or_ambiguous_endpoints_are_rejected_without_dns() {
        for endpoint in [
            "127.0.0.1:4",
            "0.0.0.0:4",
            "224.0.0.1:4",
            "255.255.255.255:4",
            "[::1]:4",
            "[::]:4",
            "[ff02::1]:4",
            "[::ffff:127.0.0.1]:4",
            "[fe80::1%2]:4",
            "192.0.2.1:0",
            "host:0",
            "host:65536",
            "host",
            "host/path:4",
            "host\\path:4",
            "host name:4",
            "-host:4",
            "host..name:4",
            "999.999.999.999:4",
            ":4",
        ] {
            let mut value = config(endpoint);
            assert!(pin_with(&mut value, |_, _| async {
                panic!("invalid endpoint must not resolve")
            })
            .await
            .is_err());
        }
        for input in [
            "[Interface]\nEndpoint = host:4\n[Peer]\n",
            "[Peer]\nEndpoint = host:4\nEndpoint = host:5\n",
            "[Peer]\nEndpoint = host:4\n[Peer]\n",
            "[Peer]\n",
            "[Peer]\nEndpoint = host:4\0",
        ] {
            let mut value = TunnelConfiguration::new(input.into());
            assert!(pin_with(&mut value, |_, _| async {
                panic!("ambiguous config must not resolve")
            })
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn unusable_or_wrong_port_answers_do_not_reach_native() {
        for answers in [
            vec![],
            vec![
                "127.0.0.1:20004",
                "0.0.0.0:20004",
                "[::ffff:127.0.0.1]:20004",
            ],
            vec!["192.0.2.4:9999"],
        ] {
            let mut value = config("host:20004");
            let result = pin_with(&mut value, |_, _| async move {
                Ok(answers.into_iter().map(|a| a.parse().unwrap()).collect())
            })
            .await;
            assert!(
                matches!(result, Err(CoreError::Tunnel(code)) if code == "endpoint_resolution_failed")
            );
            assert_eq!(value.expose(), config("host:20004").expose());
        }
    }

    #[tokio::test]
    async fn cancelling_pending_resolution_leaves_configuration_unchanged() {
        let mut value = config("host:20004");
        {
            let pending = pin_with(&mut value, |_, _| std::future::pending());
            tokio::pin!(pending);
            assert!(matches!(
                futures::poll!(&mut pending),
                std::task::Poll::Pending
            ));
        }
        assert_eq!(value.expose(), config("host:20004").expose());
    }

    #[tokio::test]
    async fn all_three_member_commands_pin_without_changing_scope_or_generation() {
        use nelomai_client_tunnel::redundancy::{protocol::Member, SessionScope, Slot};
        let scope = SessionScope {
            runtime: nelomai_contracts::RuntimeSlot::Latest,
            runtime_generation: 7,
            connection_generation: 8,
            session_id: "20000000-0000-4000-8000-000000000001".into(),
        };
        for kind in 0..3 {
            let member = Member {
                slot: if kind == 0 { Slot::A } else { Slot::B },
                lease_id: "20000000-0000-4000-8000-000000000002".into(),
                configuration: config("1b.nelomai.ru:20004"),
                probe: serde_json::from_value(serde_json::json!({
                    "kind":"dns_a", "target_ipv4":"8.8.8.8", "query_name":"nelomai.ru", "timeout_ms":4000
                })).unwrap(),
            };
            let command = match kind {
                0 => Command::Start {
                    scope: scope.clone(),
                    primary: member,
                    role_generation: 2,
                    membership_generation: 3,
                    warm_stop_v1: true,
                    options: Default::default(),
                },
                1 => Command::Attach {
                    scope: scope.clone(),
                    member,
                    expected_revision: 4,
                    expected_network_epoch: 5,
                    expected_membership_generation: 3,
                    membership_generation: 6,
                },
                _ => Command::StageCandidate {
                    scope: scope.clone(),
                    member,
                    expected_revision: 4,
                    expected_network_epoch: 5,
                    expected_membership_generation: 3,
                },
            };
            let mut expected = serde_json::to_value(&command).unwrap();
            expected[if kind == 0 { "primary" } else { "member" }]["configuration"] =
                config("192.0.2.4:20004").expose().into();
            let result = pin_command_with(command, |_, _| async {
                Ok(vec!["192.0.2.4:20004".parse().unwrap()])
            })
            .await
            .unwrap();
            assert_eq!(serde_json::to_value(result).unwrap(), expected);
        }
        for command in [
            Command::Stop {
                scope: scope.clone(),
            },
            Command::Status { scope },
        ] {
            let expected = serde_json::to_value(&command).unwrap();
            let result = pin_command_with(command, |_, _| async {
                panic!("control commands must not resolve")
            })
            .await
            .unwrap();
            assert_eq!(serde_json::to_value(result).unwrap(), expected);
        }
    }
}
