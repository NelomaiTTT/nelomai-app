use super::*;
use std::collections::VecDeque;

#[derive(Default)]
struct Commands {
    replies: VecDeque<String>,
    calls: Vec<Vec<String>>,
    missing_b: bool,
    replaced_b: bool,
}
impl LinuxNetworkCommands for Commands {
    fn ip(&mut self, args: &[String]) -> io::Result<String> {
        self.calls.push(args.to_vec());
        let value = self.replies.pop_front().unwrap_or_default();
        if value == "command_failure" {
            return Err(io::Error::other("injected native failure"));
        }
        Ok(value)
    }
    fn interface_name(&self, index: u32) -> io::Result<String> {
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
        "[]", // originals
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
