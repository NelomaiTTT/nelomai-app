use super::*;
use std::collections::VecDeque;

#[derive(Default)]
struct Commands {
    replies: VecDeque<String>,
    calls: Vec<Vec<String>>,
    missing_b: bool,
    replaced_b: bool,
    reused_b_index: bool,
}
impl LinuxNetworkCommands for Commands {
    fn busctl(&mut self, args: &[String]) -> io::Result<String> {
        self.ip(args)
    }
    fn ip(&mut self, args: &[String]) -> io::Result<String> {
        self.calls.push(args.to_vec());
        let value = self.replies.pop_front().unwrap_or_default();
        if value == "command_failure" {
            return Err(io::Error::other("injected native failure"));
        }
        Ok(value)
    }
    fn interface_name(&self, index: u32) -> io::Result<String> {
        if index == 20 && self.reused_b_index {
            return Ok("foreign0".into());
        }
        if index == 20 && (self.missing_b || self.replaced_b) {
            return Err(io::ErrorKind::NotFound.into());
        }
        match index {
            10 => Ok("nlm-wga".into()),
            20 => Ok("nlm-wgb".into()),
            5 => Ok("eth0".into()),
            _ => Err(invalid()),
        }
    }
    fn interface_index(&self, name: &str) -> io::Result<u32> {
        if name == "nlm-wgb" && self.missing_b {
            return Err(io::ErrorKind::NotFound.into());
        }
        if name == "nlm-wgb" && self.replaced_b {
            return Ok(99);
        }
        match name {
            "nlm-wga" => Ok(10),
            "nlm-wgb" => Ok(20),
            "eth0" => Ok(5),
            _ => Err(invalid()),
        }
    }
}
fn adapter(replies: &[&str]) -> LinuxNetwork<Commands> {
    LinuxNetwork::new(
        Commands {
            replies: replies.iter().map(|r| r.to_string()).collect(),
            ..Default::default()
        },
        [
            MemberTable {
                interface: 10,
                name: "nlm-wga".into(),
                table: 52000,
                priority: 12000,
            },
            MemberTable {
                interface: 20,
                name: "nlm-wgb".into(),
                table: 52001,
                priority: 12001,
            },
        ],
    )
    .unwrap()
}
fn route(cidr: &str, scope: RouteScope, interface: u32) -> NetworkValue {
    NetworkValue::Route(RouteValue {
        destination: cidr.parse().unwrap(),
        scope,
        interface,
        gateway: None,
        metric: 42,
    })
}

fn dns_value(interface: u32) -> NetworkValue {
    NetworkValue::LinkDns(LinkDnsValue {
        interface,
        servers: vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()],
    })
}
const DNS: &str = r#"{"type":"a(iayqs)","data":[[2,[9,9,9,9],0,""],[10,[38,32,0,254,0,0,0,0,0,0,0,0,0,0,0,254],0,""]]}"#;
const NO_DNS: &str = r#"{"type":"a(iayqs)","data":[]}"#;
const DOMAIN: &str = r#"{"type":"a(sb)","data":[[".",true]]}"#;
const NO_DOMAIN: &str = r#"{"type":"a(sb)","data":[]}"#;

#[test]
fn link_dns_reads_exact_ipv4_ipv6_and_root_domain_on_owned_link() {
    let mut network = adapter(&[DNS, DOMAIN, NO_DNS, NO_DOMAIN]);
    assert_eq!(
        network.read(&ResourceKey::LinkDns(10)).unwrap(),
        Some(dns_value(10))
    );
    assert_eq!(
        network.read(&ResourceKey::LinkDnsRoute(10)).unwrap(),
        Some(NetworkValue::LinkDnsRoute(10))
    );
    assert_eq!(network.read(&ResourceKey::LinkDns(20)).unwrap(), None);
    assert_eq!(network.read(&ResourceKey::LinkDnsRoute(20)).unwrap(), None);
    // sd_bus_path_encode escapes the first digit by its ASCII hex code.
    assert!(network.commands.calls[0]
        .iter()
        .any(|s| s == "/org/freedesktop/resolve1/link/_310"));
    assert!(network.commands.calls[2]
        .iter()
        .any(|s| s == "/org/freedesktop/resolve1/link/_320"));
}

#[test]
fn link_dns_expansion_targets_owned_active_not_physical_service() {
    let network = adapter(&[]);
    let servers = vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()];
    assert_eq!(
        network.dns_resources(10, &servers, &[]).unwrap(),
        vec![dns_value(10), NetworkValue::LinkDnsRoute(10)]
    );
    assert!(network.dns_resources(5, &servers, &[]).is_err());
    assert!(network
        .dns_resources(10, &servers, &["eth0".into()])
        .is_err());
    assert!(network.commands.calls.is_empty());
}

#[test]
fn link_dns_rechecks_property_after_slow_resolver_preflight() {
    let foreign = r#"{"type":"a(iayqs)","data":[[2,[77,88,8,8],0,""]]}"#;
    let mut network = adapter(&[
        NO_DNS,
        r#"{"type":"s","data":"stub"}"#,
        r#"{"type":"s","data":"yes"}"#,
        foreign,
    ]);
    let value = dns_value(10);
    assert!(network
        .compare_exchange(&value.key(), None, Some(&value))
        .is_err());
    assert!(!network
        .commands
        .calls
        .iter()
        .flatten()
        .any(|s| s == "SetLinkDNS"));
}

#[test]
fn link_dns_rejects_foreign_domain_malformed_family_and_failed_query() {
    for reply in [
        r#"{"type":"a(iayqs)","data":[[2,[9,9,9,9],853,"dns.example"]]}"#,
        r#"{"type":"a(iayqs)","data":[[2,[9,9,9,9],0,"dns.example"]]}"#,
        r#"{"type":"a(iayqs)","data":[[2,[9,9,9,9],853,""]]}"#,
        r#"{"type":"a(iayqs)","data":[[2,[9,9,9],0,""]]}"#,
        r#"{"type":"a(iayqs)","data":[[2,[9,9,9,256],0,""]]}"#,
        r#"{"type":"a(iayqs)","data":[[99,[9,9,9,9],0,""]]}"#,
        r#"{"type":"a(iayqs)","data":[[2,[9,9,9,9],0,""],[2,[9,9,9,9],0,""]]}"#,
        r#"{"type":"a(iayqs)","data":[[2,[0,0,0,0],0,""]]}"#,
        r#"{"type":"a(sb)","data":[]}"#,
        "command_failure",
        "{}",
    ] {
        assert!(adapter(&[reply]).read(&ResourceKey::LinkDns(10)).is_err());
    }
    for reply in [
        r#"{"type":"a(sb)","data":[[".",false]]}"#,
        r#"{"type":"a(sb)","data":[["corp.example",true]]}"#,
        r#"{"type":"a(sb)","data":[[".",true],["corp.example",true]]}"#,
    ] {
        assert!(adapter(&[reply])
            .read(&ResourceKey::LinkDnsRoute(10))
            .is_err());
    }
}

#[test]
fn link_dns_missing_member_is_absent_but_replacement_or_physical_link_is_not() {
    let mut network = adapter(&[]);
    network.commands.missing_b = true;
    assert_eq!(network.read(&ResourceKey::LinkDns(20)).unwrap(), None);
    assert_eq!(network.read(&ResourceKey::LinkDnsRoute(20)).unwrap(), None);
    network.commands.reused_b_index = true;
    assert!(network.read(&ResourceKey::LinkDns(20)).is_err());
    network.commands.reused_b_index = false;
    network.commands.missing_b = false;
    network.commands.replaced_b = true;
    assert!(network.read(&ResourceKey::LinkDns(20)).is_err());
    assert!(network.read(&ResourceKey::LinkDns(5)).is_err());
    assert!(network.commands.calls.is_empty());
}

#[test]
fn link_dns_cas_sets_or_clears_only_one_property_and_never_reverts_link() {
    let value = dns_value(10);
    let mut network = adapter(&[
        NO_DNS,
        r#"{"type":"s","data":"stub"}"#,
        r#"{"type":"s","data":"yes"}"#,
        NO_DNS,
        "",
        DNS,
        "",
    ]);
    network
        .compare_exchange(&value.key(), None, Some(&value))
        .unwrap();
    network
        .compare_exchange(&value.key(), Some(&value), None)
        .unwrap();
    let calls = &network.commands.calls;
    let set = &calls[4];
    assert_eq!(
        &set[set.iter().position(|s| s == "SetLinkDNS").unwrap()..],
        [
            "SetLinkDNS",
            "ia(iay)",
            "10",
            "2",
            "2",
            "4",
            "9",
            "9",
            "9",
            "9",
            "10",
            "16",
            "38",
            "32",
            "0",
            "254",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "254"
        ]
    );
    let clear = calls.last().unwrap();
    assert_eq!(
        &clear[clear.len() - 4..],
        ["SetLinkDNS", "ia(iay)", "10", "0"]
    );
    assert!(!calls
        .iter()
        .flatten()
        .any(|s| s.contains("Revert") || s == "SetLinkDomains"));
}

#[test]
fn link_domain_cas_clears_only_exact_root_route_and_refuses_foreign_change() {
    let value = NetworkValue::LinkDnsRoute(10);
    let mut network = adapter(&[
        NO_DOMAIN,
        r#"{"type":"s","data":"static"}"#,
        r#"{"type":"s","data":"yes"}"#,
        NO_DOMAIN,
        "",
        DOMAIN,
        "",
    ]);
    network
        .compare_exchange(&value.key(), None, Some(&value))
        .unwrap();
    network
        .compare_exchange(&value.key(), Some(&value), None)
        .unwrap();
    let set = &network.commands.calls[4];
    assert_eq!(
        &set[set.len() - 6..],
        ["SetLinkDomains", "ia(sb)", "10", "1", ".", "true"]
    );
    let clear = network.commands.calls.last().unwrap();
    assert_eq!(
        &clear[clear.len() - 4..],
        ["SetLinkDomains", "ia(sb)", "10", "0"]
    );
    let mut network = adapter(&[r#"{"type":"a(sb)","data":[["corp.example",true]]}"#]);
    assert!(network
        .compare_exchange(&value.key(), Some(&value), None)
        .is_err());
    assert_eq!(network.commands.calls.len(), 1);
}

#[test]
fn link_dns_requires_stub_resolver_but_cleanup_does_not_depend_on_mode() {
    for mode in ["uplink", "foreign", "missing", "future"] {
        let reply = format!(r#"{{"type":"s","data":"{mode}"}}"#);
        let mut network = adapter(&[NO_DNS, &reply]);
        let value = dns_value(10);
        assert!(network
            .compare_exchange(&value.key(), None, Some(&value))
            .is_err());
        assert!(!network
            .commands
            .calls
            .iter()
            .flatten()
            .any(|s| s == "SetLinkDNS"));
    }
    for listener in ["no", "udp", "tcp"] {
        let reply = format!(r#"{{"type":"s","data":"{listener}"}}"#);
        let mut network = adapter(&[NO_DNS, r#"{"type":"s","data":"stub"}"#, &reply]);
        let value = dns_value(10);
        assert!(network
            .compare_exchange(&value.key(), None, Some(&value))
            .is_err());
    }
    let value = dns_value(10);
    let mut network = adapter(&[DNS, ""]);
    network
        .compare_exchange(&value.key(), Some(&value), None)
        .unwrap();
    assert_eq!(network.commands.calls.len(), 2);
}

#[test]
fn resolved_property_failure_flows_through_real_adapter_journal_and_recovery() {
    use nelomai_client_tunnel::redundancy::Slot;
    use std::collections::{HashMap, HashSet};
    #[derive(Default)]
    struct Resolved {
        dns: HashMap<u32, Vec<Value>>,
        domains: HashSet<u32>,
        failed: bool,
        partial_failure: bool,
    }
    impl LinuxNetworkCommands for Resolved {
        fn ip(&mut self, _: &[String]) -> io::Result<String> {
            panic!("DNS must not issue route commands")
        }
        fn interface_name(&self, i: u32) -> io::Result<String> {
            Commands::default().interface_name(i)
        }
        fn interface_index(&self, name: &str) -> io::Result<u32> {
            Commands::default().interface_index(name)
        }
        fn busctl(&mut self, args: &[String]) -> io::Result<String> {
            assert_eq!(args[1], "org.freedesktop.resolve1");
            if args[0] == "get-property" {
                let (signature, data) = match args[4].as_str() {
                    "ResolvConfMode" => ("s", serde_json::json!("stub")),
                    "DNSStubListener" => ("s", serde_json::json!("yes")),
                    property => {
                        let i = match args[2].as_str() {
                            "/org/freedesktop/resolve1/link/_310" => 10,
                            "/org/freedesktop/resolve1/link/_320" => 20,
                            _ => panic!("unexpected link path"),
                        };
                        match property {
                            "DNSEx" => (
                                "a(iayqs)",
                                serde_json::json!(self.dns.get(&i).cloned().unwrap_or_default()),
                            ),
                            "Domains" => (
                                "a(sb)",
                                if self.domains.contains(&i) {
                                    serde_json::json!([[".", true]])
                                } else {
                                    serde_json::json!([])
                                },
                            ),
                            _ => panic!("unexpected property"),
                        }
                    }
                };
                return Ok(serde_json::json!({"type":signature,"data":data}).to_string());
            }
            assert_eq!(args[0], "call");
            assert_eq!(args[2], "/org/freedesktop/resolve1");
            let i = args[6].parse::<u32>().unwrap();
            let count = args[7].parse::<usize>().unwrap();
            match args[4].as_str() {
                "SetLinkDNS" => {
                    assert_eq!(args[5], "ia(iay)");
                    let mut cursor = 8;
                    let mut values = Vec::new();
                    for _ in 0..count {
                        let family = args[cursor].parse::<u32>().unwrap();
                        let len = args[cursor + 1].parse::<usize>().unwrap();
                        let bytes = args[cursor + 2..cursor + 2 + len]
                            .iter()
                            .map(|s| s.parse::<u8>().unwrap())
                            .collect::<Vec<_>>();
                        values.push(serde_json::json!([family, bytes, 0, ""]));
                        cursor += 2 + len;
                    }
                    assert_eq!(cursor, args.len());
                    self.dns.insert(i, values);
                }
                "SetLinkDomains" => {
                    assert_eq!(args[5], "ia(sb)");
                    assert!(count <= 1);
                    if i == 20 && count == 1 && !self.failed {
                        self.failed = true;
                        // Test both failure-before-side-effect and lost ACK after
                        // the property actually changed; journal must inspect.
                        if self.partial_failure {
                            self.domains.insert(i);
                        }
                        return Err(io::Error::other("injected domain failure"));
                    }
                    if count == 0 {
                        self.domains.remove(&i);
                    } else {
                        assert_eq!(&args[8..], [".", "true"]);
                        self.domains.insert(i);
                    }
                }
                _ => panic!("unexpected mutation"),
            }
            Ok(String::new())
        }
    }
    #[derive(Default)]
    struct Journal(Option<NetworkJournal>);
    impl NetworkJournalStore for Journal {
        fn save(&mut self, value: &NetworkJournal) -> io::Result<()> {
            self.0 = Some(value.clone());
            Ok(())
        }
    }
    for partial_failure in [false, true] {
        let network = LinuxNetwork::new(
            Resolved {
                partial_failure,
                ..Default::default()
            },
            adapter(&[]).members,
        )
        .unwrap();
        let mut owner = NetworkOwner::fresh(network, Journal::default());
        owner
            .select(Slot::A, vec![dns_value(10), NetworkValue::LinkDnsRoute(10)])
            .unwrap();
        assert!(owner
            .select(Slot::B, vec![dns_value(20), NetworkValue::LinkDnsRoute(20)])
            .is_err());
        assert_eq!(owner.active(), Some(Slot::A));
        assert!(!owner.cleanup_pending());
        assert_eq!(
            owner.system_mut().read(&ResourceKey::LinkDns(10)).unwrap(),
            Some(dns_value(10))
        );
        assert_eq!(
            owner
                .system_mut()
                .read(&ResourceKey::LinkDnsRoute(10))
                .unwrap(),
            Some(NetworkValue::LinkDnsRoute(10))
        );
        assert_eq!(
            owner.system_mut().read(&ResourceKey::LinkDns(20)).unwrap(),
            None
        );
        assert_eq!(
            owner
                .system_mut()
                .read(&ResourceKey::LinkDnsRoute(20))
                .unwrap(),
            None
        );
        let (system, store) = owner.into_parts();
        let state = store.0.clone().unwrap();
        let mut recovered = NetworkOwner::recover(system, store, state).unwrap();
        recovered.cleanup().unwrap();
        assert!(recovered.system_mut().commands.domains.is_empty());
        assert!(recovered
            .system_mut()
            .commands
            .dns
            .values()
            .all(Vec::is_empty));
    }
}

const PHYSICAL_LINKS: &str = r#"[{"ifindex":5,"ifname":"eth0","flags":["UP","LOWER_UP"],"link_type":"ether"},{"ifindex":10,"ifname":"nlm-wga","flags":["UP"],"link_type":"none","linkinfo":{"info_kind":"wireguard"}}]"#;
const MAIN_RULES: &str = r#"[{"priority":0,"src":"all","table":"255"},{"priority":32766,"src":"all","table":"254"},{"priority":32767,"src":"all","table":"253"}]"#;
const PHYSICAL_V4: &str = r#"[{"dst":"default","dev":"nlm-wga","gateway":"10.0.0.1","protocol":"4","flags":[]},{"dst":"default","dev":"eth0","gateway":"192.168.1.1","protocol":"16","metric":100,"flags":[]},{"dst":"192.168.1.0/24","dev":"eth0","protocol":"2","scope":"link","prefsrc":"192.168.1.4","metric":100,"flags":[]}]"#;

#[test]
fn full_linux_policy_checks_stub_before_start_and_uses_no_physical_dns_override() {
    let mut network = adapter(&[
        r#"{"type":"s","data":"stub"}"#,
        r#"{"type":"s","data":"yes"}"#,
        PHYSICAL_LINKS,
        MAIN_RULES,
        PHYSICAL_V4,
    ]);
    let p = network
        .resolve_policy(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
        .unwrap();
    assert!(p.dns_services.is_empty());
    assert_eq!(p.metric, 42);
    assert_eq!(p.bypasses.len(), 1);
    assert_eq!(p.bypasses[0].interface, 5);
    assert!(network.commands.calls.iter().all(|c| !c
        .iter()
        .any(|s| matches!(s.as_str(), "add" | "del" | "call"))));
    let mut unsupported = adapter(&[r#"{"type":"s","data":"foreign"}"#]);
    assert!(unsupported
        .resolve_policy(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
        .is_err());
    assert_eq!(unsupported.commands.calls.len(), 1);
}

#[test]
fn physical_discovery_never_ignores_a_deviceless_policy_route() {
    for extra in [
        r#"{"dst":"198.51.100.0/24","type":"blackhole","protocol":4}"#,
        r#"{"dst":"default","protocol":4,"nexthops":[{"gateway":"192.168.1.2","dev":"eth0","weight":1}]}"#,
    ] {
        let routes = format!(
            r#"[{{"dst":"default","dev":"eth0","gateway":"192.168.1.1","protocol":16}},{extra}]"#
        );
        let mut network = adapter(&[PHYSICAL_LINKS, MAIN_RULES, &routes]);
        assert!(network
            .resolve_physical_routes(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
            .is_err());
    }
}

#[test]
fn physical_discovery_uses_onlink_prefix_and_rejects_equal_cost_gateway_guess() {
    let mut network = adapter(&[PHYSICAL_LINKS, MAIN_RULES, PHYSICAL_V4]);
    let result = network
        .resolve_physical_routes(&Default::default(), &["192.168.1.9".parse().unwrap()], &[])
        .unwrap();
    assert_eq!(result.bypasses[0].gateway, None);
    let routes = r#"[{"dst":"default","dev":"eth0","gateway":"192.168.1.1","protocol":16,"metric":100},{"dst":"default","dev":"eth0","gateway":"192.168.1.2","protocol":16,"metric":100}]"#;
    assert!(adapter(&[PHYSICAL_LINKS, MAIN_RULES, routes])
        .resolve_physical_routes(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
        .is_err());
}

#[test]
fn physical_discovery_rejects_down_or_tunnel_ethernet_and_stale_interface_index() {
    for links in [
        r#"[{"ifindex":5,"ifname":"eth0","flags":["UP"],"link_type":"ether"}]"#,
        r#"[{"ifindex":5,"ifname":"eth0","flags":["UP","LOWER_UP"],"link_type":"ether","linkinfo":{"info_kind":"tun"}}]"#,
        r#"[{"ifindex":10,"ifname":"eth0","flags":["UP","LOWER_UP"],"link_type":"ether"}]"#,
    ] {
        assert!(adapter(&[links, MAIN_RULES, PHYSICAL_V4])
            .resolve_physical_routes(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
            .is_err());
    }
}

#[test]
fn physical_discovery_accepts_only_exact_registered_probe_rules() {
    for name in ["nlm-wga", "eth0"] {
        let rules = format!(
            r#"[{{"priority":0,"src":"all","table":255}},{{"priority":12000,"src":"all","table":52000,"protocol":4,"oif":"{name}"}},{{"priority":32766,"src":"all","table":254}}]"#
        );
        let result = adapter(&[PHYSICAL_LINKS, &rules, PHYSICAL_V4]).resolve_physical_routes(
            &Default::default(),
            &["198.51.100.1".parse().unwrap()],
            &[],
        );
        assert_eq!(result.is_ok(), name == "nlm-wga");
    }
}

#[test]
fn physical_discovery_excludes_vpn_gateway_and_retains_kernel_lan_without_mutation() {
    let mut network = adapter(&[PHYSICAL_LINKS, MAIN_RULES, PHYSICAL_V4, MAIN_RULES, "[]"]);
    let result = network
        .resolve_physical_routes(
            &nelomai_client_tunnel::DesktopTunnelOptions {
                exclude_local_networks: true,
                ..Default::default()
            },
            &[
                "198.51.100.1".parse().unwrap(),
                "203.0.113.8".parse().unwrap(),
            ],
            &[],
        )
        .unwrap();
    assert_eq!(result.bypasses.len(), 2);
    assert!(result
        .bypasses
        .iter()
        .all(|r| r.interface == 5 && r.gateway == Some("192.168.1.1".parse().unwrap())));
    assert_eq!(
        result.retained_routes,
        vec![RouteValue {
            destination: "192.168.1.0/24".parse().unwrap(),
            scope: RouteScope::Global,
            interface: 5,
            gateway: None,
            metric: 100,
        }]
    );
    assert!(network
        .commands
        .calls
        .iter()
        .all(|c| c.iter().any(|a| a == "show")
            && !c
                .iter()
                .any(|a| ["add", "del", "replace"].contains(&a.as_str()))));
}

#[test]
fn retained_kernel_route_can_be_verified_but_never_mutated_as_owned_static_route() {
    let text = r#"[{"dst":"192.168.1.0/24","dev":"eth0","protocol":"2","scope":"link","prefsrc":"192.168.1.4","metric":100,"flags":[]}]"#;
    let mut network = adapter(&[text, text]);
    let value = RouteValue {
        destination: "192.168.1.0/24".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 5,
        gateway: None,
        metric: 100,
    };
    assert!(network.verify_retained_route(&value).unwrap());
    let owned = NetworkValue::Route(value);
    assert!(network
        .compare_exchange(&owned.key(), Some(&owned), None)
        .is_err());
    assert_eq!(network.commands.calls.len(), 2);
}

#[test]
fn retained_route_change_and_unsupported_forwarding_attributes_are_rejected() {
    let value = RouteValue {
        destination: "192.168.1.0/24".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 5,
        gateway: None,
        metric: 100,
    };
    for extra in [
        r#", "gateway":"192.168.1.2""#,
        r#", "metric":200"#,
        r#", "encap":{"type":"seg6"}"#,
        r#", "flags":["linkdown"]"#,
    ] {
        let text = format!(r#"[{{"dst":"192.168.1.0/24","dev":"eth0","protocol":"2"{extra}}}]"#);
        assert!(!adapter(&[&text])
            .verify_retained_route(&value)
            .unwrap_or(false));
    }
}

#[test]
fn physical_discovery_rejects_policy_routing_instead_of_guessing_main_table() {
    let rules = r#"[{"priority":100,"src":"all","table":100,"fwmark":"0x1"},{"priority":32766,"src":"all","table":254}]"#;
    let mut network = adapter(&[PHYSICAL_LINKS, rules, PHYSICAL_V4]);
    assert!(network
        .resolve_physical_routes(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
        .is_err());
}

#[test]
fn physical_discovery_keeps_existing_endpoint_unowned_unless_journal_owns_it() {
    let text = r#"[{"dst":"default","dev":"eth0","gateway":"192.168.1.1","protocol":16},{"dst":"198.51.100.1","dev":"eth0","gateway":"192.168.1.1","protocol":4,"metric":42}]"#;
    for owned in [false, true] {
        let mut network = adapter(&[PHYSICAL_LINKS, MAIN_RULES, text]);
        let journal = if owned {
            vec!["198.51.100.1/32".parse().unwrap()]
        } else {
            vec![]
        };
        let result = network
            .resolve_physical_routes(
                &Default::default(),
                &["198.51.100.1".parse().unwrap()],
                &journal,
            )
            .unwrap();
        assert_eq!(result.retained_routes.len(), usize::from(!owned));
        assert_eq!(result.bypasses.len(), usize::from(owned));
        if !owned {
            assert_eq!(result.retained_routes[0].metric, 42);
        }
    }
}

#[test]
fn physical_ipv6_endpoint_uses_link_local_gateway_on_exact_interface() {
    let routes = r#"[{"dst":"default","dev":"eth0","gateway":"fe80::1","protocol":"9","metric":1024,"expires":900,"pref":"medium","flags":[]}]"#;
    let mut network = adapter(&[PHYSICAL_LINKS, MAIN_RULES, routes]);
    let result = network
        .resolve_physical_routes(&Default::default(), &["2001:db8::9".parse().unwrap()], &[])
        .unwrap();
    assert_eq!(result.bypasses[0].interface, 5);
    assert_eq!(result.bypasses[0].gateway, Some("fe80::1".parse().unwrap()));
    assert_eq!(
        result.bypasses[0].destination,
        "2001:db8::9/128".parse().unwrap()
    );
    assert!(network.commands.calls[1].contains(&"-6".into()));
}

#[test]
fn primary_table_can_be_registered_without_waiting_for_reserve() {
    let mut network = LinuxNetwork::new(Commands::default(), []).unwrap();
    let a = MemberTable {
        interface: 10,
        name: "nlm-wga".into(),
        table: 52000,
        priority: 12000,
    };
    network.register_member(a.clone()).unwrap();
    let NetworkValue::Route(probe) = route("9.9.9.9/32", RouteScope::Member(10), 10) else {
        unreachable!()
    };
    assert_eq!(
        network.route_resources(probe.clone()).unwrap(),
        vec![
            NetworkValue::Route(probe),
            network.member_rule(10, false).unwrap()
        ]
    );
    assert!(network.member_rule(20, false).is_err());
    network
        .register_member(MemberTable {
            interface: 20,
            name: "nlm-wgb".into(),
            table: 52001,
            priority: 12001,
        })
        .unwrap();
    assert!(network.member_rule(20, false).is_ok());
    assert!(network.register_member(a).is_err());
    assert!(network.commands.calls.is_empty()); // planning/registration changes no host state
}

#[test]
fn registering_ambiguous_table_never_changes_existing_primary_binding() {
    for conflict in [
        MemberTable {
            interface: 20,
            name: "nlm-wgb".into(),
            table: 52000,
            priority: 12001,
        },
        MemberTable {
            interface: 20,
            name: "nlm-wgb".into(),
            table: 52001,
            priority: 12000,
        },
        MemberTable {
            interface: 10,
            name: "nlm-wgb".into(),
            table: 52001,
            priority: 12001,
        },
        MemberTable {
            interface: 20,
            name: "nlm-wga".into(),
            table: 52001,
            priority: 12001,
        },
    ] {
        let mut network = LinuxNetwork::new(
            Commands::default(),
            [MemberTable {
                interface: 10,
                name: "nlm-wga".into(),
                table: 52000,
                priority: 12000,
            }],
        )
        .unwrap();
        let before = network.member_rule(10, false).unwrap();
        assert!(network.register_member(conflict).is_err());
        assert_eq!(network.member_rule(10, false).unwrap(), before);
        assert_eq!(network.members.len(), 1);
    }
}

#[test]
fn route_resource_expansion_keeps_global_routes_global_and_ipv6_rules_distinct() {
    let network = adapter(&[]);
    let NetworkValue::Route(global) = route("0.0.0.0/1", RouteScope::Global, 10) else {
        unreachable!()
    };
    assert_eq!(
        network.route_resources(global.clone()).unwrap(),
        vec![NetworkValue::Route(global)]
    );
    let NetworkValue::Route(probe) = route("2001:db8::1/128", RouteScope::Member(20), 20) else {
        unreachable!()
    };
    let resources = network.route_resources(probe).unwrap();
    assert_eq!(resources[1], network.member_rule(20, true).unwrap());
}

#[test]
fn reserve_probe_route_is_in_private_table_not_main() {
    let mut network = adapter(&["[]", ""]);
    let probe = route("9.9.9.9/32", RouteScope::Member(20), 20);
    network
        .compare_exchange(&probe.key(), None, Some(&probe))
        .unwrap();
    assert_eq!(
        network.commands.calls[0],
        [
            "-j",
            "-N",
            "-4",
            "route",
            "show",
            "table",
            "all",
            "exact",
            "9.9.9.9/32"
        ]
    );
    assert_eq!(
        network.commands.calls[1],
        [
            "-4",
            "route",
            "add",
            "9.9.9.9/32",
            "table",
            "52001",
            "dev",
            "nlm-wgb",
            "metric",
            "42",
            "proto",
            "4",
            "scope",
            "link"
        ]
    );
}

#[test]
fn rule_requires_device_bound_socket_and_has_independent_ipv6_identity() {
    let mut network = adapter(&["[]", ""]);
    let rule = network.member_rule(20, true).unwrap();
    assert_eq!(
        rule,
        NetworkValue::BoundRule(BoundRuleValue {
            ipv6: true,
            priority: 12001,
            table: 52001,
            interface: 20
        })
    );
    network
        .compare_exchange(&rule.key(), None, Some(&rule))
        .unwrap();
    assert_eq!(
        network.commands.calls[1],
        [
            "-6", "rule", "add", "priority", "12001", "oif", "nlm-wgb", "lookup", "52001",
            "protocol", "4"
        ]
    );
}

#[test]
fn switch_changes_main_route_without_touching_standby_table() {
    let mut network = adapter(&[
        r#"[{"dst":"8000::/1","dev":"nlm-wga","protocol":4,"metric":42,"flags":[],"pref":"medium"}]"#,
        "",
        "",
    ]);
    let a = route("8000::/1", RouteScope::Global, 10);
    let b = route("8000::/1", RouteScope::Global, 20);
    network
        .compare_exchange(&a.key(), Some(&a), Some(&b))
        .unwrap();
    assert_eq!(
        network.commands.calls[1],
        [
            "-6", "route", "del", "8000::/1", "table", "254", "dev", "nlm-wga", "metric", "42",
            "proto", "4"
        ]
    );
    assert_eq!(
        network.commands.calls[2],
        [
            "-6", "route", "add", "8000::/1", "table", "254", "dev", "nlm-wgb", "metric", "42",
            "proto", "4"
        ]
    );
}

#[test]
fn foreign_rule_at_owned_priority_is_not_deleted() {
    let mut network = adapter(&[
        r#"[{"priority":12001,"src":"all","table":52001,"protocol":4,"oif":"nlm-wgb","fwmark":"0x42"}]"#,
    ]);
    let rule = network.member_rule(20, false).unwrap();
    assert!(network
        .compare_exchange(&rule.key(), Some(&rule), None)
        .is_err());
    assert_eq!(network.commands.calls.len(), 1);
}

#[test]
fn identical_duplicate_rules_are_ambiguous_and_never_deleted() {
    let mut network = adapter(&[
        r#"[{"priority":12001,"src":"all","table":52001,"protocol":4,"oif":"nlm-wgb"},{"priority":12001,"src":"all","table":52001,"protocol":4,"oif":"nlm-wgb"}]"#,
    ]);
    let rule = network.member_rule(20, false).unwrap();
    assert!(network
        .compare_exchange(&rule.key(), Some(&rule), None)
        .is_err());
    assert_eq!(network.commands.calls.len(), 1);
}

#[test]
fn modified_route_attributes_are_not_discarded_by_identity_comparison() {
    for extra in [
        r#", "mtu":1300"#,
        r#", "prefsrc":"10.1.0.9"#,
        r#", "flags":["onlink"]"#,
        r#", "multipath":[]"#,
    ] {
        let json = format!(
            r#"[{{"dst":"9.9.9.9","dev":"nlm-wgb","table":"52001","protocol":4,"metric":42{extra}}}]"#
        );
        let mut network = adapter(&[&json]);
        let probe = route("9.9.9.9/32", RouteScope::Member(20), 20);
        assert!(network
            .compare_exchange(&probe.key(), Some(&probe), None)
            .is_err());
        assert_eq!(network.commands.calls.len(), 1);
    }
}

#[test]
fn slot_configuration_cannot_alias_main_table_or_another_slot() {
    for (interface, table, priority) in [
        (20, 254, 12001),
        (20, 52000, 12001),
        (10, 52001, 12001),
        (20, 52001, 12000),
    ] {
        let second = MemberTable {
            interface,
            name: "nlm-wgb".into(),
            table,
            priority,
        };
        assert!(LinuxNetwork::new(
            Commands::default(),
            [
                MemberTable {
                    interface: 10,
                    name: "nlm-wga".into(),
                    table: 52000,
                    priority: 12000
                },
                second
            ]
        )
        .is_err());
    }
}

#[test]
fn unsupported_dns_cannot_silently_succeed() {
    let mut network = adapter(&[]);
    assert!(network.read(&ResourceKey::Dns("eth0".into())).is_err());
    assert!(network.commands.calls.is_empty());
}

#[test]
fn iproute2_numeric_json_uses_string_protocol_table_and_scope() {
    // iproute2 print_string(... rtnl_*_n2a) retains JSON strings with -N.
    let mut network = adapter(&[
        r#"[{"dst":"9.9.9.9","dev":"nlm-wgb","protocol":"4","scope":"253","metric":42,"flags":[],"table":"52001"}]"#,
        r#"[{"priority":0,"src":"all","table":"255"},{"priority":12001,"src":"all","table":"52001","protocol":"4","oif":"nlm-wgb"}]"#,
    ]);
    let probe = route("9.9.9.9/32", RouteScope::Member(20), 20);
    assert_eq!(network.read(&probe.key()).unwrap(), Some(probe));
    let rule = network.member_rule(20, false).unwrap();
    assert_eq!(network.read(&rule.key()).unwrap(), Some(rule));
}

#[test]
fn detached_rule_can_be_cleaned_after_native_tunnel_stop_but_not_recreated() {
    let mut network = adapter(&[
        r#"[{"priority":12001,"src":"all","table":"52001","protocol":"4","oif":"nlm-wgb","oif_detached":null}]"#,
        "",
    ]);
    let rule = network.member_rule(20, false).unwrap();
    network.commands.missing_b = true;
    network
        .compare_exchange(&rule.key(), Some(&rule), None)
        .unwrap();
    assert_eq!(
        network.commands.calls.last().unwrap(),
        &[
            "-4", "rule", "del", "priority", "12001", "oif", "nlm-wgb", "lookup", "52001",
            "protocol", "4"
        ]
    );
    let calls = network.commands.calls.len();
    assert!(network
        .compare_exchange(&rule.key(), None, Some(&rule))
        .is_err());
    assert_eq!(network.commands.calls.len(), calls);
}

#[test]
fn reused_native_name_blocks_old_rule_cleanup() {
    let mut network = adapter(&[
        r#"[{"priority":12001,"src":"all","table":"52001","protocol":"4","oif":"nlm-wgb"}]"#,
    ]);
    let rule = network.member_rule(20, false).unwrap();
    network.commands.replaced_b = true;
    assert!(network
        .compare_exchange(&rule.key(), Some(&rule), None)
        .is_err());
    assert!(network
        .commands
        .calls
        .iter()
        .all(|c| c.first().map(String::as_str) == Some("-j")));
}

#[test]
fn route_dump_filters_other_tables_without_requiring_private_table_to_exist() {
    let mut network = adapter(&[
        r#"[{"dst":"9.9.9.9","dev":"eth0","protocol":"2","scope":"253","table":"255","flags":[]},{"dst":"9.9.9.9","dev":"nlm-wga","protocol":"4","metric":42,"flags":[]}]"#,
    ]);
    let probe = route("9.9.9.9/32", RouteScope::Member(20), 20);
    assert_eq!(network.read(&probe.key()).unwrap(), None);
    assert_eq!(&network.commands.calls[0][5..8], &["table", "all", "exact"]);
}

#[test]
fn failed_rule_creation_rolls_back_its_route_through_the_real_owner() {
    struct Journal;
    impl NetworkJournalStore for Journal {
        fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
            Ok(())
        }
    }
    let present = r#"[{"dst":"9.9.9.9","dev":"nlm-wgb","table":"52001","protocol":"4","scope":"253","metric":42,"flags":[]}]"#;
    let network = adapter(&[
        "[]",
        "[]", // preflight
        "[]",
        "",
        present, // route CAS, mutation, readback
        "[]",
        "command_failure", // rule CAS + failed add
        "[]",              // absent rule needs no rollback
        present,
        present,
        "",
        "[]", // route rollback inspect/CAS/delete/readback
    ]);
    let rule = network.member_rule(20, false).unwrap();
    let mut owner = NetworkOwner::fresh(network, Journal);
    assert!(owner
        .prepare(vec![route("9.9.9.9/32", RouteScope::Member(20), 20), rule])
        .is_err());
    assert!(!owner.cleanup_pending());
    assert!(!owner.has_resources());
    let commands = &owner.system_mut().commands;
    assert!(commands.replies.is_empty());
    let writes = commands
        .calls
        .iter()
        .filter(|a| a.first().map(String::as_str) != Some("-j"))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 3);
    assert_eq!(&writes[0][0..4], &["-4", "route", "add", "9.9.9.9/32"]);
    assert_eq!(&writes[1][0..3], &["-4", "rule", "add"]);
    assert_eq!(&writes[2][0..4], &["-4", "route", "del", "9.9.9.9/32"]);
}
