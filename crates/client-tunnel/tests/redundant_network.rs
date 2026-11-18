use nelomai_client_tunnel::redundancy::Slot;
use nelomai_client_tunnel::redundancy::{driver::RouteRefreshError, network::*};
use std::{collections::BTreeMap, io};

#[derive(Default)]
struct System {
    values: BTreeMap<String, NetworkValue>,
    writes: usize,
    reads: Vec<ResourceKey>,
    fail_at: Vec<usize>,
    ignore_at: Vec<usize>,
    reject_interfaces: Vec<u32>,
    foreign_on_failure: Option<NetworkValue>,
    halt_after_write: Option<(usize, NetworkValue)>,
    covered_address: Option<std::net::IpAddr>,
    stage_global_routes: bool,
    fail_delete_readback: bool,
    reject_next_read: bool,
}
impl NetworkSystem for System {
    fn observe_routes_on_close(&self) -> bool {
        self.stage_global_routes
    }

    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        self.reads.push(key.clone());
        if std::mem::take(&mut self.reject_next_read) {
            return Err(io::Error::other("native readback failed"));
        }
        Ok(self.values.get(&format!("{key:?}")).cloned())
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        self.writes += 1;
        if matches!(after,Some(NetworkValue::Route(r)) if self.reject_interfaces.contains(&r.interface))
        {
            return Err(io::Error::other("interface vanished"));
        }
        if self.fail_at.contains(&self.writes) {
            if let Some(foreign) = self.foreign_on_failure.take() {
                self.values.insert(format!("{:?}", foreign.key()), foreign);
            }
            return Err(io::Error::other("injected"));
        }
        if self.ignore_at.contains(&self.writes) {
            return Ok(());
        }
        let key = format!("{key:?}");
        if self.values.get(&key) != before {
            return Err(io::Error::other("foreign"));
        }
        if let Some(value) = after {
            self.values.insert(key, value.clone());
        } else {
            self.values.remove(&key);
            self.reject_next_read = std::mem::take(&mut self.fail_delete_readback);
        }
        if let Some(address) = self.covered_address {
            assert!(self.values.values().any(|value| {
                matches!(value, NetworkValue::Route(route) if route.destination.contains(&address))
            }), "native write lost VPN coverage for {address}");
        }
        if self
            .halt_after_write
            .as_ref()
            .is_some_and(|(write, _)| *write == self.writes)
        {
            let (_, foreign) = self.halt_after_write.take().unwrap();
            self.values.insert(format!("{:?}", foreign.key()), foreign);
            panic!("injected interruption immediately after native write");
        }
        Ok(())
    }
}
#[derive(Default)]
struct Journal {
    saved: Option<NetworkJournal>,
    fail: bool,
    saves: usize,
    lose_ack_at: Option<usize>,
    reject_at: Option<usize>,
}
impl NetworkJournalStore for Journal {
    fn save(&mut self, value: &NetworkJournal) -> io::Result<()> {
        self.saves += 1;
        if self.fail || self.reject_at == Some(self.saves) {
            return Err(io::Error::other("disk"));
        }
        self.saved = Some(value.clone());
        if self.lose_ack_at == Some(self.saves) {
            return Err(io::Error::other("lost disk ACK"));
        }
        Ok(())
    }
}
fn route(destination: &str, interface: u32) -> NetworkValue {
    NetworkValue::Route(RouteValue {
        destination: destination.parse().unwrap(),
        scope: RouteScope::Global,
        interface,
        gateway: None,
        metric: 1,
    })
}

#[test]
fn mac_global_prefix_splits_and_merges_keep_coverage_through_every_write() {
    let parent = route("203.0.113.0/24", 10);
    let child = route("203.0.113.16/28", 10);
    let mut owner = NetworkOwner::fresh(
        System {
            stage_global_routes: true,
            ..Default::default()
        },
        Journal::default(),
    );
    owner.select(Slot::A, vec![parent.clone()]).unwrap();
    owner.system_mut().covered_address = Some("203.0.113.17".parse().unwrap());

    // Attach uses select; explicit refresh uses journaled native writes.
    owner.select(Slot::A, vec![child.clone()]).unwrap();
    owner
        .select_with_outcome(Slot::A, vec![parent.clone()])
        .unwrap();

    // Refuse a later DNS/route update after staging the broader replacement,
    // then check coverage after each compensating native mutation as well.
    let fail_at = owner.system_mut().writes + 3;
    owner.system_mut().fail_at.push(fail_at);
    let dns = NetworkValue::Dns(DnsValue {
        service: "Ethernet".into(),
        servers: vec!["192.0.2.53".parse().unwrap()],
    });
    assert!(owner
        .select_with_outcome(Slot::A, vec![child, dns])
        .is_err());
    assert_eq!(
        owner.system_mut().read(&parent.key()).unwrap(),
        Some(parent)
    );
    assert_eq!(owner.active(), Some(Slot::A));
}

#[test]
fn staged_coverage_survives_unconfirmed_retirement_or_failed_restore() {
    for fail_readback in [true, false] {
        let parent = route("203.0.113.0/24", 10);
        let child = route("203.0.113.16/28", 10);
        let mut owner = NetworkOwner::fresh(
            System {
                stage_global_routes: true,
                ..Default::default()
            },
            Journal::default(),
        );
        owner.select(Slot::A, vec![parent.clone()]).unwrap();
        let native = owner.system_mut();
        native.covered_address = Some("203.0.113.17".parse().unwrap());
        native.fail_delete_readback = fail_readback;
        if !fail_readback {
            // The forward DNS update and the attempted route restore fail.
            native.fail_at = vec![native.writes + 3, native.writes + 4];
        }
        let dns = NetworkValue::Dns(DnsValue {
            service: "Ethernet".into(),
            servers: vec!["192.0.2.53".parse().unwrap()],
        });
        assert!(owner
            .select_with_outcome(Slot::A, vec![child.clone(), dns])
            .is_err());
        assert!(owner.cleanup_pending());
        assert_eq!(
            owner.system_mut().read(&child.key()).unwrap(),
            Some(child.clone())
        );

        let (mut system, journal) = owner.into_parts();
        system.covered_address = None; // Stop is now intentional.
        let persisted = journal.saved.clone().unwrap();
        let mut recovered = NetworkOwner::recover(system, journal, persisted).unwrap();
        // macOS Stop first closes the owned interface and the kernel retires
        // its routes. The network owner must never delete by a retired index.
        recovered
            .system_mut()
            .values
            .remove(&format!("{:?}", child.key()));
        recovered.confirm_links_closed().unwrap();
        recovered.cleanup().unwrap();
        assert!(!recovered.cleanup_pending());
        assert_eq!(recovered.system_mut().read(&child.key()).unwrap(), None);
    }
}

#[test]
fn linux_priority_transition_keeps_coverage_through_every_write() {
    let main_route = |destination, interface| {
        let NetworkValue::Route(mut value) = route(destination, interface) else {
            unreachable!()
        };
        value.metric = 42 + interface;
        value.scope = RouteScope::LinuxMainPriority(value.metric);
        NetworkValue::Route(value)
    };
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner
        .select(Slot::A, vec![main_route("203.0.113.0/24", 10)])
        .unwrap();
    owner.system_mut().covered_address = Some("203.0.113.17".parse().unwrap());
    owner
        .select_with_outcome(Slot::A, vec![main_route("203.0.113.16/28", 10)])
        .unwrap();
    owner
        .select_with_outcome(Slot::B, vec![main_route("203.0.113.16/28", 20)])
        .unwrap();
    owner
        .select_with_outcome(Slot::B, vec![main_route("203.0.113.0/24", 20)])
        .unwrap();
}

#[test]
fn recovery_removes_confirmed_gateway_route_when_final_save_is_rejected() {
    #[derive(Default)]
    struct RejectCommit(Journal);
    impl NetworkJournalStore for RejectCommit {
        fn save(&mut self, value: &NetworkJournal) -> io::Result<()> {
            let view = value.read_view()?;
            if view.pending().is_none() && view.recorded_active().is_some() {
                return Err(io::Error::other("rejected final save"));
            }
            self.0.save(value)
        }
    }

    let mut bypass = route("192.0.2.1/32", 5);
    if let NetworkValue::Route(route) = &mut bypass {
        route.gateway = Some("198.51.100.1".parse().unwrap());
    }
    let mut owner = NetworkOwner::fresh(System::default(), RejectCommit::default());
    assert!(owner
        .select_with_outcome(Slot::A, vec![bypass.clone()])
        .is_err());
    let (system, store) = owner.into_parts();
    let persisted = store.0.saved.clone().unwrap();
    let mut recovered = NetworkOwner::recover(system, store, persisted).unwrap();
    recovered.cleanup().unwrap();
    assert_eq!(recovered.system_mut().read(&bypass.key()).unwrap(), None);
}

#[test]
fn recover_rejects_an_intent_without_a_route() {
    let mut journal = serde_json::to_value(NetworkJournal::default()).unwrap();
    journal["route_intents"] = serde_json::json!([{"before": null, "after": null}]);
    let journal = serde_json::from_value(journal).unwrap();
    let result = NetworkOwner::recover(System::default(), Journal::default(), journal);
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
}

#[test]
fn legacy_commit_save_failure_restores_original_routes() {
    for acknowledgement_is_lost in [false, true] {
        let old = route("192.0.2.1/32", 10);
        let new = route("192.0.2.1/32", 20);
        let mut owner = NetworkOwner::fresh(
            System::default(),
            Journal {
                reject_at: (!acknowledgement_is_lost).then_some(4),
                lose_ack_at: acknowledgement_is_lost.then_some(4),
                ..Default::default()
            },
        );
        owner.select(Slot::A, vec![old.clone()]).unwrap();
        assert!(owner.select(Slot::B, vec![new]).is_err());
        assert_eq!(owner.system_mut().read(&old.key()).unwrap(), Some(old));
        assert_eq!(owner.active(), Some(Slot::A));
        assert!(!owner.cleanup_pending());
        let (_, store) = owner.into_parts();
        assert_eq!(
            store.saved.unwrap().read_view().unwrap().recorded_active(),
            Some(Slot::A)
        );
    }
}

#[test]
fn factual_journal_read_view_keeps_pending_and_stopping_without_io_or_authority() {
    let a = route("9.9.9.9/32", 10);
    let b = route("9.9.9.9/32", 20);
    let journal: NetworkJournal = serde_json::from_value(serde_json::json!({
        "owned":[{"original":null,"current":a}],"active":"A","stopping":true,
        "pending":{"target":[{"original":null,"current":b}],"active":"B"}
    }))
    .unwrap();
    let view = journal.read_view().unwrap();
    assert_eq!(view.current().cloned().collect::<Vec<_>>(), vec![a]);
    assert_eq!(
        view.pending().unwrap().cloned().collect::<Vec<_>>(),
        vec![b]
    );
    assert_eq!(view.recorded_active(), Some(Slot::A));
    assert_eq!(view.pending_active(), Some(Slot::B));
    assert!(view.stopping());
    let empty = NetworkJournal::default();
    assert!(empty.read_view().unwrap().current().next().is_none());
    assert!(empty.read_view().unwrap().pending().is_none());
}

#[test]
fn factual_journal_view_validates_both_complete_lists_before_exporting() {
    for pending in [false, true] {
        for fault in 0..4 {
            let value = route("9.9.9.9/32", 10);
            let mut entries = serde_json::json!([{"original":null,"current":value}]);
            match fault {
                0 => {
                    let duplicate = entries[0].clone();
                    entries.as_array_mut().unwrap().push(duplicate);
                }
                1 => entries[0]["current"]["Route"]["interface"] = serde_json::json!(0),
                2 => entries[0]["original"] = serde_json::to_value(&value).unwrap(),
                _ => {
                    entries[0]["current"]["Route"]["destination"] = serde_json::json!("9.9.9.9/24")
                }
            }
            let valid = serde_json::json!([{"original":null,"current":value}]);
            let journal: NetworkJournal = serde_json::from_value(serde_json::json!({
                "owned":if pending {valid.clone()} else {entries.clone()},
                "active":"A","stopping":false,
                "pending":{"target":if pending {entries} else {valid},"active":"B"}
            }))
            .unwrap();
            assert!(
                journal.read_view().is_err(),
                "pending={pending}, fault={fault}"
            );
        }
    }
}

#[test]
fn excluded_routes_retains_exact_committed_and_pending_rows_without_io() {
    let mut a = route("203.0.113.7/32", 10);
    if let NetworkValue::Route(r) = &mut a {
        r.scope = RouteScope::WindowsInterface(10);
    }
    let mut b = a.clone();
    if let NetworkValue::Route(r) = &mut b {
        r.metric = 90;
        r.gateway = Some("192.0.2.1".parse().unwrap());
    }
    let mut other = route("203.0.113.7/32", 20);
    if let NetworkValue::Route(r) = &mut other {
        r.scope = RouteScope::WindowsInterface(20);
    }
    let journal: NetworkJournal = serde_json::from_value(serde_json::json!({
        "owned":[{"original":null,"current":a},{"original":null,"current":other}],
        "active":"A", "stopping":false,
        "pending":{"target":[{"original":null,"current":b},{"original":null,"current":other}],"active":"B"}
    })).unwrap();
    let mut owner = NetworkOwner::recover(System::default(), Journal::default(), journal).unwrap();
    let rows = owner.excluded_routes();
    assert_eq!(rows.len(), 3);
    for value in [a, b, other] {
        let NetworkValue::Route(row) = value else {
            unreachable!()
        };
        assert!(rows.contains(&row));
    }
    assert_eq!(owner.system_mut().writes, 0);
    assert!(owner.system_mut().values.is_empty());
}

#[test]
fn windows_interface_routes_remain_distinct_and_update_in_place_on_role_change() {
    let value = |interface, metric| {
        serde_json::from_value::<NetworkValue>(serde_json::json!({"Route":{
        "destination":"9.9.9.9/32", "scope":{"WindowsInterface":interface},"interface":interface,"gateway":null,"metric":metric
    }})).unwrap()
    };
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner
        .select(Slot::A, vec![value(10, 1), value(20, 100)])
        .unwrap();
    owner
        .select(Slot::B, vec![value(10, 100), value(20, 1)])
        .unwrap();
    assert_eq!(owner.system_mut().values.len(), 2);
    assert_eq!(owner.system_mut().writes, 4);
    let b = value(20, 1);
    assert_eq!(owner.system_mut().read(&b.key()).unwrap(), Some(b));
    owner.cleanup().unwrap();
    assert!(owner.system_mut().values.is_empty());
    let mut invalid = value(10, 1);
    if let NetworkValue::Route(route) = &mut invalid {
        route.interface = 20;
    }
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    assert!(owner.select(Slot::A, vec![invalid]).is_err());
    assert_eq!(owner.system_mut().writes, 0);
}

fn bound_rule() -> NetworkValue {
    NetworkValue::BoundRule(BoundRuleValue {
        ipv6: false,
        priority: 12001,
        table: 52001,
        interface: 20,
    })
}

fn link_dns(interface: u32) -> Vec<NetworkValue> {
    // Exercise the durable journal representation as well as ownership.
    vec![
        serde_json::from_value(serde_json::json!({"LinkDns": {
            "interface": interface, "servers": ["9.9.9.9", "2620:fe::fe"]
        }}))
        .unwrap(),
        serde_json::from_value(serde_json::json!({"LinkDnsRoute": interface})).unwrap(),
    ]
}

#[test]
fn link_dns_switch_failure_rolls_back_each_property_then_restart_can_clean() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, link_dns(10)).unwrap();
    // Removing A's two properties, adding B's DNS, then failure adding B's domain.
    owner.system_mut().fail_at = vec![6];
    assert!(owner.select(Slot::B, link_dns(20)).is_err());
    assert_eq!(owner.active(), Some(Slot::A));
    assert!(!owner.cleanup_pending());
    for value in link_dns(10) {
        assert_eq!(owner.system_mut().read(&value.key()).unwrap(), Some(value));
    }
    for value in link_dns(20) {
        assert_eq!(owner.system_mut().read(&value.key()).unwrap(), None);
    }
    let (system, store) = owner.into_parts();
    let journal =
        serde_json::from_str(&serde_json::to_string(store.saved.as_ref().unwrap()).unwrap())
            .unwrap();
    let mut recovered = NetworkOwner::recover(system, store, journal).unwrap();
    recovered.cleanup().unwrap();
    assert!(recovered.system_mut().values.is_empty());
}

#[test]
fn link_dns_never_adopts_existing_properties_or_deletes_foreign_replacement() {
    for value in link_dns(10) {
        let mut system = System::default();
        system
            .values
            .insert(format!("{:?}", value.key()), value.clone());
        let mut owner = NetworkOwner::fresh(system, Journal::default());
        assert!(owner.select(Slot::A, link_dns(10)).is_err());
        assert_eq!(owner.system_mut().writes, 0);
        owner.cleanup().unwrap();
        assert_eq!(owner.system_mut().read(&value.key()).unwrap(), Some(value));
    }
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, link_dns(10)).unwrap();
    let foreign: NetworkValue = serde_json::from_value(serde_json::json!({"LinkDns": {
        "interface": 10, "servers": ["77.88.8.8"]
    }}))
    .unwrap();
    owner
        .system_mut()
        .values
        .insert(format!("{:?}", foreign.key()), foreign.clone());
    assert!(owner.cleanup().is_err());
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
}

#[test]
fn link_dns_disappeared_with_native_member_does_not_prevent_cleanup() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, link_dns(10)).unwrap();
    owner.system_mut().values.clear();
    owner.cleanup().unwrap();
    assert!(!owner.cleanup_pending());
    assert_eq!(owner.system_mut().writes, 2);
}

#[test]
fn preexisting_bound_rule_is_not_adopted_even_when_identical() {
    let rule = bound_rule();
    let mut system = System::default();
    system
        .values
        .insert(format!("{:?}", rule.key()), rule.clone());
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    assert!(owner.prepare(vec![rule.clone()]).is_err());
    assert_eq!(owner.system_mut().writes, 0);
    owner.cleanup().unwrap();
    assert_eq!(owner.system_mut().read(&rule.key()).unwrap(), Some(rule));
}

#[test]
fn bound_rule_survives_journal_restart_and_is_removed_only_by_its_owner() {
    let rule = bound_rule();
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.prepare(vec![rule.clone()]).unwrap();
    let (system, store) = owner.into_parts();
    let persisted = store.saved.clone().unwrap();
    let mut recovered = NetworkOwner::recover(system, store, persisted).unwrap();
    recovered.cleanup().unwrap();
    assert_eq!(recovered.system_mut().read(&rule.key()).unwrap(), None);
}

#[test]
fn bound_rule_rejects_builtin_table_zero_interface_and_default_rule_priority() {
    for (table, interface, priority) in [
        (254, 20, 12001),
        (52001, 0, 12001),
        (52001, 20, 0),
        (52001, 20, 32766),
    ] {
        let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
        let value = NetworkValue::BoundRule(BoundRuleValue {
            ipv6: false,
            priority,
            table,
            interface,
        });
        assert!(owner.prepare(vec![value]).is_err());
        assert_eq!(owner.system_mut().writes, 0);
    }
}
fn pair(interface: u32) -> Vec<NetworkValue> {
    vec![
        route("0.0.0.0/1", interface),
        route("128.0.0.0/1", interface),
        route("::/1", interface),
        route("8000::/1", interface),
    ]
}

#[test]
fn failed_ipv6_switch_restores_both_families_and_does_not_publish_reserve() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    owner.system_mut().fail_at = vec![7]; // B IPv4 changed; first IPv6 change fails.
    assert!(owner.select(Slot::B, pair(20)).is_err());
    assert_eq!(owner.active(), Some(Slot::A));
    assert!(!owner.cleanup_pending());
    for value in pair(10) {
        assert_eq!(owner.system_mut().read(&value.key()).unwrap(), Some(value));
    }
}

#[test]
fn failed_rollback_keeps_durable_pending_state_and_recovery_restores_original() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    owner.system_mut().fail_at = vec![7, 8];
    assert!(owner.select(Slot::B, pair(20)).is_err());
    assert!(owner.cleanup_pending());
    assert_eq!(owner.active(), None); // Never claim A or B after incomplete rollback.
    let (mut system, store) = owner.into_parts();
    system.fail_at.clear();
    let state = store.saved.clone().unwrap();
    let mut recovered = NetworkOwner::recover(system, store, state).unwrap();
    recovered.cleanup().unwrap();
    assert!(recovered.system_mut().values.is_empty());
}

#[test]
fn existing_foreign_route_is_never_adopted_or_removed() {
    for foreign_index in 0..4 {
        let mut system = System::default();
        let foreign = pair(77)[foreign_index].clone();
        system
            .values
            .insert(format!("{:?}", foreign.key()), foreign.clone());
        let mut owner = NetworkOwner::fresh(system, Journal::default());
        assert!(owner.select(Slot::A, pair(10)).is_err());
        assert_eq!(owner.system_mut().writes, 0);
        assert_eq!(owner.active(), None);
        assert!(!owner.has_resources());
        owner.cleanup().unwrap();
        assert_eq!(
            owner.system_mut().read(&foreign.key()).unwrap(),
            Some(foreign)
        );
    }
}

#[test]
fn failed_journal_write_prevents_route_mutation() {
    let mut owner = NetworkOwner::fresh(
        System::default(),
        Journal {
            fail: true,
            ..Default::default()
        },
    );
    assert!(owner.select(Slot::A, pair(10)).is_err());
    assert_eq!(owner.system_mut().writes, 0);
}

#[test]
fn standby_scoped_probe_does_not_replace_active_routes_or_dns() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    let mut values = pair(10);
    owner.select(Slot::A, values.clone()).unwrap();
    let probe = NetworkValue::Route(RouteValue {
        destination: "9.9.9.9/32".parse().unwrap(),
        scope: RouteScope::Member(20),
        interface: 20,
        gateway: None,
        metric: 1,
    });
    values.push(probe.clone());
    owner.select(Slot::A, values).unwrap();
    assert_eq!(owner.system_mut().writes, 5);
    assert_eq!(owner.active(), Some(Slot::A));
    for value in pair(10) {
        assert_eq!(owner.system_mut().read(&value.key()).unwrap(), Some(value));
    }
    assert_eq!(owner.system_mut().read(&probe.key()).unwrap(), Some(probe));
}

#[test]
fn cleanup_does_not_overwrite_dns_changed_by_another_owner() {
    let dns = NetworkValue::Dns(DnsValue {
        service: "ethernet".into(),
        servers: vec!["9.9.9.9".parse().unwrap()],
    });
    let original = NetworkValue::Dns(DnsValue {
        service: "ethernet".into(),
        servers: vec!["192.168.1.1".parse().unwrap()],
    });
    let foreign = NetworkValue::Dns(DnsValue {
        service: "ethernet".into(),
        servers: vec!["77.88.8.8".parse().unwrap()],
    });
    let mut system = System::default();
    system
        .values
        .insert(format!("{:?}", dns.key()), original.clone());
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    owner.select(Slot::A, vec![dns.clone()]).unwrap();
    assert_eq!(owner.system_mut().reads, vec![dns.key(); 3]);
    owner
        .system_mut()
        .values
        .insert(format!("{:?}", dns.key()), foreign.clone());
    assert!(owner.cleanup().is_err());
    assert!(owner.cleanup_pending());
    assert_eq!(owner.system_mut().read(&dns.key()).unwrap(), Some(foreign));
    let (_, store) = owner.into_parts();
    let saved = serde_json::to_value(store.saved.unwrap()).unwrap();
    assert_eq!(
        saved["owned"][0]["original"],
        serde_json::to_value(original).unwrap()
    );
}

#[test]
fn unchanged_route_is_rechecked_before_publishing_or_adding_a_reserve() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    let foreign = route("0.0.0.0/1", 77);
    owner
        .system_mut()
        .values
        .insert(format!("{:?}", foreign.key()), foreign);
    assert!(owner.select(Slot::A, pair(10)).is_err());
    assert_eq!(owner.system_mut().writes, 4);
}

#[test]
fn successful_command_without_native_change_does_not_publish_active() {
    let mut owner = NetworkOwner::fresh(
        System {
            ignore_at: vec![1],
            ..Default::default()
        },
        Journal::default(),
    );
    assert!(owner.select(Slot::A, pair(10)).is_err());
    assert_eq!(owner.active(), None);
    assert!(owner.system_mut().values.is_empty());
}

#[test]
fn rollback_that_reports_success_without_reverting_stays_pending() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    owner.system_mut().fail_at = vec![7];
    owner.system_mut().ignore_at = vec![8];
    assert!(owner.select(Slot::B, pair(20)).is_err());
    assert!(owner.cleanup_pending());
    assert_eq!(owner.active(), None);
}

#[test]
fn successful_stop_clears_pending_but_cannot_resurrect_same_owner() {
    // Initial A consumes two saves. Lose the metadata pending or commit ACK,
    // retaining the SAME owner for Stop; neither permits another Switch.
    for lose_ack_at in [None, Some(3), Some(4)] {
        let mut owner = NetworkOwner::fresh(
            System::default(),
            Journal {
                lose_ack_at,
                ..Default::default()
            },
        );
        owner.select(Slot::A, pair(10)).unwrap();
        let writes = owner.system_mut().writes;
        let switched = std::cell::Cell::new(0);
        let result = owner.select_metadata(Slot::A, Slot::B, || {
            switched.set(switched.get() + 1);
            Ok(())
        });
        assert_eq!(result.is_err(), lose_ack_at.is_some());
        assert_eq!(switched.get(), usize::from(lose_ack_at != Some(3)));
        assert_eq!(owner.system_mut().writes, writes);
        assert_eq!(owner.cleanup_pending(), lose_ack_at.is_some());
        if lose_ack_at.is_some() {
            assert_eq!(owner.active(), None);
            assert!(owner
                .select_metadata(Slot::A, Slot::B, || panic!("ambiguous Switch retried"))
                .is_err());
        } else {
            assert_eq!(owner.active(), Some(Slot::B));
        }
        owner.cleanup().unwrap();
        assert!(!owner.cleanup_pending());
        assert_eq!(owner.active(), None);
        assert!(owner.select(Slot::B, pair(20)).is_err());
        assert!(owner.system_mut().values.is_empty());
        assert_eq!(owner.system_mut().writes, writes + 4); // Delete only.
    }
    for lose_ack_at in [None, Some(3), Some(4)] {
        let mut owner = NetworkOwner::fresh(
            System::default(),
            Journal {
                lose_ack_at,
                ..Default::default()
            },
        );
        owner.select(Slot::A, pair(10)).unwrap();
        let NetworkValue::Route(retired) = &pair(10)[0] else {
            panic!("route fixture")
        };
        let result = owner.retire_owned_route(Slot::A, Some(retired));
        assert_eq!(result.is_err(), lose_ack_at.is_some());
        assert_eq!(owner.cleanup_pending(), lose_ack_at.is_some());
        // A lost delete/commit ACK never rolls back by recreating the endpoint.
        assert_eq!(
            owner.system_mut().writes,
            if lose_ack_at == Some(3) { 4 } else { 5 }
        );
        assert_eq!(
            owner
                .system_mut()
                .read(&pair(10)[0].key())
                .unwrap()
                .is_some(),
            lose_ack_at == Some(3)
        );
        owner.cleanup().unwrap();
        assert!(owner.system_mut().values.is_empty());
        assert_eq!(owner.system_mut().writes, 8); // Each original route deleted once.
    }
}

#[test]
fn physical_bypasses_can_be_prepared_without_publishing_unstarted_primary() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.prepare(vec![route("192.0.2.1/32", 5)]).unwrap();
    assert_eq!(owner.active(), None);
    let bypass = route("192.0.2.1/32", 5);
    assert_eq!(owner.system_mut().reads, vec![bypass.key(); 2]);
    owner.system_mut().reads.clear();
    let mut routes = vec![route("192.0.2.1/32", 5)];
    routes.extend(pair(10));
    owner.select(Slot::A, routes).unwrap();
    assert_eq!(owner.active(), Some(Slot::A));
    // Existing bypass is reconciled; new routes need only preflight + postflight.
    assert_eq!(
        owner
            .system_mut()
            .reads
            .iter()
            .filter(|key| **key == bypass.key())
            .count(),
        1
    );
    for value in pair(10) {
        assert_eq!(
            owner
                .system_mut()
                .reads
                .iter()
                .filter(|key| **key == value.key())
                .count(),
            2
        );
    }
    assert!(owner.prepare(vec![]).is_err());
    assert_eq!(owner.active(), Some(Slot::A));
}

#[test]
fn routes_removed_with_dead_interface_do_not_block_promotion_or_cleanup() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    owner.system_mut().values.clear(); // Kernel removed routes with lost A.
    owner.select(Slot::B, pair(20)).unwrap();
    assert_eq!(owner.active(), Some(Slot::B));
    owner.system_mut().values.clear();
    owner.cleanup().unwrap();
    assert!(!owner.cleanup_pending());
}

#[test]
fn failed_promotion_after_primary_disappeared_does_not_restore_dead_primary_routes() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    owner.system_mut().values.clear();
    owner.system_mut().fail_at = vec![7];
    assert!(owner.select(Slot::B, pair(20)).is_err());
    assert_eq!(owner.active(), None);
    assert!(owner.system_mut().values.is_empty());
}

#[test]
fn restart_then_stop_cleans_partial_switch_without_recreating_a_dead_interface() {
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    owner.system_mut().fail_at = vec![7, 8];
    assert!(owner.select(Slot::B, pair(20)).is_err());
    let (mut system, store) = owner.into_parts();
    system
        .values
        .retain(|_, value| matches!(value,NetworkValue::Route(r) if r.interface==20));
    system.fail_at.clear();
    system.reject_interfaces = vec![10];
    let writes = system.writes;
    let saved = store.saved.clone().unwrap();
    let mut owner = NetworkOwner::recover(system, store, saved).unwrap();
    assert_eq!(owner.system_mut().writes, writes); // Recovery is not permission to resume or switch.
    owner.cleanup().unwrap();
    assert!(owner.system_mut().values.is_empty());
    assert!(!owner.cleanup_pending());
}

#[derive(Default)]
struct GroupedSystem {
    inner: System,
    batches: Vec<Vec<ResourceKey>>,
    truncate: bool,
    replace_after_batch: Option<NetworkValue>,
}
impl NetworkSystem for GroupedSystem {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        self.inner.read(key)
    }
    fn read_many(&mut self, keys: &[ResourceKey]) -> io::Result<Vec<Option<NetworkValue>>> {
        self.batches.push(keys.to_vec());
        let mut values: Vec<_> = keys
            .iter()
            .map(|key| self.inner.values.get(&format!("{key:?}")).cloned())
            .collect();
        if self.truncate {
            values.pop();
        }
        if self
            .replace_after_batch
            .as_ref()
            .is_some_and(|v| keys.contains(&v.key()))
        {
            let value = self.replace_after_batch.take().unwrap();
            self.inner
                .values
                .insert(format!("{:?}", value.key()), value);
        }
        Ok(values)
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        self.inner.compare_exchange(key, before, after)
    }
}

#[test]
fn grouped_owner_reads_only_preflight_and_reconciliation_together() {
    let a = route("9.9.9.9/32", 10);
    let b = route("8.8.8.8/32", 10);
    let keys = vec![a.key(), b.key()];
    let mut owner = NetworkOwner::fresh(GroupedSystem::default(), Journal::default());
    owner.prepare(vec![a.clone(), b.clone()]).unwrap();
    assert_eq!(owner.system_mut().batches, vec![keys.clone()]);
    // Each write still has its own immediate readback.
    assert_eq!(owner.system_mut().inner.reads, keys);
    owner.prepare(vec![a, b]).unwrap();
    assert_eq!(owner.system_mut().batches.len(), 2);
    assert_eq!(owner.system_mut().batches[1].len(), 2);
    assert_eq!(owner.system_mut().inner.reads.len(), 2);
    assert_eq!(owner.system_mut().inner.writes, 2);
}

#[test]
fn unix_recovery_checks_missing_tunnel_routes_in_one_snapshot_and_preserves_a_matching_row() {
    let mut owner = NetworkOwner::fresh(GroupedSystem::default(), Journal::default());
    let a = route("192.0.2.1/32", 10);
    let b = route("192.0.2.2/32", 10);
    owner.prepare(vec![a.clone(), b.clone()]).unwrap();
    let (mut sys, store) = owner.into_parts();
    let journal = store.saved.clone().unwrap().unix_recovery().unwrap();
    sys.batches.clear();
    sys.inner.reads.clear();
    sys.inner.values.remove(&format!("{:?}", b.key()));
    let mut recovered = NetworkOwner::recover(sys, store, journal).unwrap();
    assert_eq!(
        recovered.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    let sys = recovered.system_mut();
    assert!(sys.batches.iter().any(|keys| keys == &[a.key(), b.key()]));
    assert!(sys.inner.reads.is_empty());
    assert_eq!(sys.inner.writes, 2);
    sys.inner.values.clear();
    recovered.cleanup().unwrap();
    assert!(!recovered.has_resources());
}

#[test]
fn grouped_owner_refuses_incomplete_results_before_journaling_or_writing() {
    let system = GroupedSystem {
        truncate: true,
        ..Default::default()
    };
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    assert!(owner.prepare(vec![route("9.9.9.9/32", 10)]).is_err());
    assert_eq!(owner.system_mut().inner.writes, 0);
    assert!(!owner.has_resources());
    assert!(!owner.cleanup_pending());
}

#[test]
fn grouped_preflight_cannot_authorize_a_later_foreign_replacement() {
    let foreign = route("9.9.9.9/32", 99);
    let system = GroupedSystem {
        replace_after_batch: Some(foreign.clone()),
        ..Default::default()
    };
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    assert!(owner.prepare(vec![route("9.9.9.9/32", 10)]).is_err());
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
    assert_eq!(owner.system_mut().inner.writes, 1);
    assert!(owner.cleanup_pending());
}

#[test]
fn grouped_read_default_preserves_order_and_missing_values() {
    let a = route("9.9.9.9/32", 10);
    let b = route("8.8.8.8/32", 20);
    let missing = route("1.1.1.1/32", 10).key();
    let mut system = System::default();
    system.values.insert(format!("{:?}", a.key()), a.clone());
    system.values.insert(format!("{:?}", b.key()), b.clone());
    let keys = vec![b.key(), missing, a.key()];
    assert_eq!(
        system.read_many(&keys).unwrap(),
        vec![Some(b), None, Some(a)]
    );
    assert_eq!(system.reads, keys);
}

#[test]
fn partial_live_refresh_does_not_roll_back_an_unattempted_foreign_route() {
    let old = route("192.0.2.1/32", 10);
    let next = route("198.51.100.1/32", 5);
    let foreign = route("203.0.113.1/32", 5);
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, vec![old.clone()]).unwrap();
    owner.system_mut().fail_at.push(2);
    owner.system_mut().foreign_on_failure = Some(foreign.clone());
    assert!(owner
        .select_with_outcome(Slot::A, vec![old.clone(), next.clone(), foreign.clone()])
        .is_err());
    assert_eq!(owner.system_mut().read(&old.key()).unwrap(), Some(old));
    assert_eq!(owner.system_mut().read(&next.key()).unwrap(), None);
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign.clone()),
        "rollback removed a native route whose write was never attempted"
    );
    owner.cleanup().unwrap();
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
}

#[test]
fn interrupted_rollback_only_leaves_attempted_routes_for_recovery() {
    let old = route("192.0.2.1/32", 10);
    let applied = route("198.51.100.1/32", 5);
    let failed = route("198.51.100.2/32", 5);
    let foreign = route("203.0.113.1/32", 5);
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, vec![old.clone()]).unwrap();
    owner.system_mut().fail_at = vec![3, 4];
    owner.system_mut().foreign_on_failure = Some(foreign.clone());
    assert!(owner
        .select_with_outcome(
            Slot::A,
            vec![old.clone(), applied.clone(), failed, foreign.clone()]
        )
        .is_err());
    assert!(owner.cleanup_pending());
    let (system, store) = owner.into_parts();
    let persisted = store.saved.clone().unwrap();
    let mut recovered = NetworkOwner::recover(system, store, persisted).unwrap();
    assert_eq!(
        recovered.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert_eq!(recovered.system_mut().read(&old.key()).unwrap(), None);
    assert_eq!(
        recovered.system_mut().read(&applied.key()).unwrap(),
        Some(applied.clone())
    );
    recovered
        .system_mut()
        .values
        .remove(&format!("{:?}", applied.key()));
    recovered.cleanup().unwrap();
    assert_eq!(
        recovered.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
}

#[test]
fn live_rollback_reclaims_a_route_only_after_the_restore_returns() {
    for interrupted in [false, true] {
        let previous = route("192.0.2.1/32", 10);
        let replacement = route("192.0.2.1/32", 20);
        let failed = route("203.0.113.1/32", 5);
        let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
        owner.select(Slot::A, vec![previous.clone()]).unwrap();
        owner.system_mut().fail_at.push(3);
        if interrupted {
            owner.system_mut().halt_after_write = Some((4, previous.clone()));
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.select_with_outcome(Slot::A, vec![replacement, failed])
        }));
        if interrupted {
            assert!(outcome.is_err());
        } else {
            assert!(outcome.unwrap().is_err());
            assert_eq!(owner.active(), Some(Slot::A));
        }
        let (system, journal) = owner.into_parts();
        let persisted = journal.saved.clone().unwrap();
        let mut recovered = NetworkOwner::recover(system, journal, persisted).unwrap();
        if interrupted {
            assert_eq!(
                recovered.cleanup().unwrap_err().to_string(),
                "network_route_ownership_unconfirmed"
            );
            assert_eq!(
                recovered.system_mut().read(&previous.key()).unwrap(),
                Some(previous)
            );
        } else {
            recovered.cleanup().unwrap();
            assert_eq!(recovered.system_mut().read(&previous.key()).unwrap(), None);
        }
    }
}

#[test]
fn recovery_cleans_acknowledged_routes_and_fences_an_interrupted_add() {
    let previous = route("192.0.2.1/32", 10);
    let confirmed = route("198.51.100.1/32", 5);
    let unconfirmed = route("198.51.100.2/32", 5);
    let foreign = route("203.0.113.1/32", 5);
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, vec![previous.clone()]).unwrap();
    owner.system_mut().halt_after_write = Some((3, foreign.clone()));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.select_with_outcome(
            Slot::A,
            vec![
                previous.clone(),
                confirmed.clone(),
                unconfirmed.clone(),
                foreign.clone(),
            ],
        )
    }))
    .is_err());
    let (system, journal) = owner.into_parts();
    let persisted: NetworkJournal =
        serde_json::from_slice(&serde_json::to_vec(journal.saved.as_ref().unwrap()).unwrap())
            .unwrap();
    let mut recovered = NetworkOwner::recover(system, journal, persisted).unwrap();
    for _ in 0..2 {
        assert_eq!(
            recovered.cleanup().unwrap_err().to_string(),
            "network_route_ownership_unconfirmed"
        );
        assert!(recovered.cleanup_pending());
        assert_eq!(recovered.system_mut().read(&previous.key()).unwrap(), None);
        assert_eq!(recovered.system_mut().read(&confirmed.key()).unwrap(), None);
        assert_eq!(
            recovered.system_mut().read(&unconfirmed.key()).unwrap(),
            Some(unconfirmed.clone())
        );
        assert_eq!(
            recovered.system_mut().read(&foreign.key()).unwrap(),
            Some(foreign.clone())
        );
    }
    let (mut system, journal) = recovered.into_parts();
    system.values.remove(&format!("{:?}", unconfirmed.key()));
    let persisted = journal.saved.clone().unwrap();
    let mut recovered = NetworkOwner::recover(system, journal, persisted).unwrap();
    recovered.cleanup().unwrap();
    assert!(!recovered.cleanup_pending());
    assert_eq!(
        recovered.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
}

#[test]
fn cas_preflight_collision_keeps_foreign_route_equal_to_target() {
    let old = route("192.0.2.1/32", 10);
    let foreign = route("203.0.113.1/32", 5);
    let mut owner = NetworkOwner::fresh(GroupedSystem::default(), Journal::default());
    owner.select(Slot::A, vec![old.clone()]).unwrap();

    // Install after the new value is read in grouped preflight. The
    // preflight re-read that compares before the CAS must reject this
    // exact value without mutating native state.
    owner.system_mut().replace_after_batch = Some(foreign.clone());
    assert!(matches!(
        owner.select_with_outcome(Slot::A, vec![old.clone(), foreign.clone()]),
        Err(RouteRefreshError::Unchanged(_))
    ));
    assert_eq!(owner.active(), Some(Slot::A));
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign),
        "rollback deleted the native entry that made compare_exchange reject the write"
    );
}

#[test]
fn live_refresh_preserves_foreign_route_inserted_during_journal_save() {
    assert_foreign_route_survives_live_journal_save(false);
}

#[test]
fn recovery_preserves_foreign_route_inserted_before_native_write() {
    assert_foreign_route_survives_live_journal_save(true);
}

fn assert_foreign_route_survives_live_journal_save(interrupt: bool) {
    use std::{cell::RefCell, rc::Rc};

    struct SharedSystem(Rc<RefCell<System>>);
    impl NetworkSystem for SharedSystem {
        fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
            self.0.borrow_mut().read(key)
        }
        fn compare_exchange(
            &mut self,
            key: &ResourceKey,
            before: Option<&NetworkValue>,
            after: Option<&NetworkValue>,
        ) -> io::Result<()> {
            self.0.borrow_mut().compare_exchange(key, before, after)
        }
    }
    struct InsertOnSave {
        system: Rc<RefCell<System>>,
        journal: Journal,
        foreign: Option<NetworkValue>,
        interrupt: bool,
    }
    impl NetworkJournalStore for InsertOnSave {
        fn save(&mut self, journal: &NetworkJournal) -> io::Result<()> {
            self.journal.save(journal)?;
            if self.journal.saves == 4 {
                let value = self.foreign.take().expect("foreign route fixture");
                self.system
                    .borrow_mut()
                    .values
                    .insert(format!("{:?}", value.key()), value);
                if self.interrupt {
                    panic!("interruption during the live route intent save");
                }
            }
            Ok(())
        }
    }

    let system = Rc::new(RefCell::new(System::default()));
    let original = route("192.0.2.1/32", 10);
    let foreign = route("203.0.113.1/32", 5);
    let store = InsertOnSave {
        system: system.clone(),
        journal: Journal::default(),
        foreign: Some(foreign.clone()),
        interrupt,
    };
    let mut owner = NetworkOwner::fresh(SharedSystem(system), store);
    owner.select(Slot::A, vec![original.clone()]).unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.select_with_outcome(Slot::A, vec![original, foreign.clone()])
    }));
    assert_eq!(
        owner.system_mut().0.borrow().writes,
        1,
        "only setup may write"
    );
    if interrupt {
        assert!(outcome.is_err());
        let (system, store) = owner.into_parts();
        let persisted = store.journal.saved.clone().unwrap();
        owner = NetworkOwner::recover(system, store, persisted).unwrap();
        assert_eq!(
            owner.cleanup().unwrap_err().to_string(),
            "network_route_ownership_unconfirmed"
        );
        assert!(owner.cleanup_pending());
    } else {
        assert!(outcome.unwrap().is_err());
        owner.cleanup().unwrap();
    }
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign),
        "cleanup must preserve the route installed by another process"
    );
}

#[test]
fn live_refresh_can_clean_up_after_final_journal_ack_loss() {
    let old = route("192.0.2.1/32", 10);
    let new = route("192.0.2.1/32", 20);
    let mut owner = NetworkOwner::fresh(
        System::default(),
        Journal {
            lose_ack_at: Some(5),
            ..Default::default()
        },
    );
    owner.select(Slot::A, vec![old.clone()]).unwrap();
    owner.system_mut().halt_after_write = Some((3, old.clone()));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.select_with_outcome(Slot::A, vec![new])
    }));
    assert!(outcome
        .expect("ambiguous save must not start a rollback")
        .is_err());
    assert!(owner.cleanup_pending());
    let (mut system, journal) = owner.into_parts();
    system.halt_after_write = None;
    let persisted = journal.saved.clone().unwrap();
    let mut recovered = NetworkOwner::recover(system, journal, persisted).unwrap();
    recovered
        .cleanup()
        .expect("recovery should recognize the owned route");
    assert_eq!(recovered.system_mut().read(&old.key()).unwrap(), None);
}

struct ReinsertAfterNativeDelete {
    inner: System,
    foreign: Option<NetworkValue>,
    interrupt: bool,
    interrupt_at_readback: bool,
}
impl NetworkSystem for ReinsertAfterNativeDelete {
    fn journal_each_write(&self) -> bool {
        true
    }

    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        if std::mem::take(&mut self.interrupt_at_readback) {
            panic!("helper interrupted after successful delete, before persisting its result");
        }
        self.inner.read(key)
    }

    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        self.inner.compare_exchange(key, before, after)?;
        if after.is_none()
            && self
                .foreign
                .as_ref()
                .is_some_and(|route| Some(route) == before)
        {
            let foreign = self.foreign.take().unwrap();
            self.inner.values.insert(format!("{key:?}"), foreign);
            self.interrupt_at_readback = self.interrupt;
        }
        Ok(())
    }
}

#[test]
fn forward_delete_ack_survives_interruption_before_readback() {
    let old = route("192.0.2.1/32", 10);
    let mut owner = NetworkOwner::fresh(
        ReinsertAfterNativeDelete {
            inner: System::default(),
            foreign: Some(old.clone()),
            interrupt: true,
            interrupt_at_readback: false,
        },
        Journal::default(),
    );
    owner.select(Slot::A, vec![old.clone()]).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.select_with_outcome(Slot::A, Vec::new())
    }));
    assert!(result.is_err());
    assert_eq!(owner.system_mut().inner.writes, 2);
    assert!(owner.system_mut().foreign.is_none());

    let (system, store) = owner.into_parts();
    let persisted =
        serde_json::from_slice(&serde_json::to_vec(store.saved.as_ref().unwrap()).unwrap())
            .unwrap();
    let mut recovered = NetworkOwner::recover(system, store, persisted).unwrap();
    assert!(recovered.cleanup_pending());
    assert_eq!(
        recovered.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert_eq!(
        recovered.system_mut().read(&old.key()).unwrap(),
        Some(old),
        "recovery deleted the foreign route using pre-delete durable ownership"
    );
}

#[test]
fn stop_preserves_reinserted_route_after_compensating_delete() {
    let old = route("192.0.2.1/32", 10);
    let replacement = route("198.51.100.1/32", 5);
    let failed = route("203.0.113.1/32", 5);
    let mut owner = NetworkOwner::fresh(
        ReinsertAfterNativeDelete {
            inner: System {
                fail_at: vec![3],
                ..Default::default()
            },
            foreign: Some(replacement.clone()),
            interrupt: false,
            interrupt_at_readback: false,
        },
        Journal::default(),
    );
    owner.select(Slot::A, vec![old.clone()]).unwrap();
    assert!(owner
        .select_with_outcome(Slot::A, vec![old, replacement.clone(), failed])
        .is_err());
    assert_eq!(owner.system_mut().inner.writes, 4);
    assert!(owner.system_mut().foreign.is_none());
    assert_eq!(
        owner.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert_eq!(
        owner.system_mut().read(&replacement.key()).unwrap(),
        Some(replacement),
        "Stop deleted the foreign replacement after the acknowledged compensating delete"
    );
}

#[test]
fn repeated_guarded_stop_preserves_a_reinserted_route_and_cleans_the_rest() {
    let first = route("192.0.2.1/32", 10);
    let foreign = route("192.0.2.2/32", 10);
    let last = route("192.0.2.3/32", 10);
    let mut owner = NetworkOwner::fresh(
        ReinsertAfterNativeDelete {
            inner: System::default(),
            foreign: Some(foreign.clone()),
            interrupt: false,
            interrupt_at_readback: false,
        },
        Journal::default(),
    );
    owner
        .select(Slot::A, vec![first.clone(), foreign.clone(), last.clone()])
        .unwrap();
    assert_eq!(
        owner.cleanup().unwrap_err().to_string(),
        "network_change_not_applied"
    );
    let (system, store) = owner.into_parts();
    let persisted = store.saved.clone().unwrap();
    let mut recovered = NetworkOwner::recover(system, store, persisted).unwrap();
    assert_eq!(
        recovered.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert_eq!(recovered.system_mut().read(&first.key()).unwrap(), None);
    assert_eq!(recovered.system_mut().read(&last.key()).unwrap(), None);
    assert_eq!(
        recovered.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign.clone())
    );
    assert_eq!(
        recovered.system_mut().inner.writes,
        6,
        "Stop must not reinstall previously deleted routes"
    );
    recovered
        .system_mut()
        .inner
        .values
        .remove(&format!("{:?}", foreign.key()));
    recovered.cleanup().unwrap();
    assert!(!recovered.has_resources());
}

#[test]
fn interrupted_replacement_protects_either_exact_row_and_cleans_independent_routes() {
    let before = route("192.0.2.1/32", 10);
    let after = route("192.0.2.1/32", 20);
    let independent = route("198.51.100.1/32", 5);
    for possible in [before.clone(), after.clone()] {
        let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
        owner
            .select(Slot::A, vec![before.clone(), independent.clone()])
            .unwrap();
        owner.system_mut().halt_after_write = Some((3, possible.clone()));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.select_with_outcome(Slot::A, vec![after.clone(), independent.clone()])
        }))
        .is_err());
        let (system, store) = owner.into_parts();
        let persisted =
            serde_json::from_slice(&serde_json::to_vec(store.saved.as_ref().unwrap()).unwrap())
                .unwrap();
        let mut recovered = NetworkOwner::recover(system, store, persisted).unwrap();
        assert_eq!(
            recovered.cleanup().unwrap_err().to_string(),
            "network_route_ownership_unconfirmed"
        );
        assert_eq!(
            recovered.system_mut().read(&independent.key()).unwrap(),
            None
        );
        assert_eq!(
            recovered.system_mut().read(&possible.key()).unwrap(),
            Some(possible)
        );
    }
}

fn gateway_routes(count: usize) -> Vec<NetworkValue> {
    (0..count)
        .map(|i| {
            NetworkValue::Route(RouteValue {
                destination: format!("10.56.{}.{}/32", i / 256, i % 256).parse().unwrap(),
                scope: RouteScope::Global,
                gateway: Some("192.0.2.254".parse().unwrap()),
                interface: 5,
                metric: 1,
            })
        })
        .collect()
}

#[test]
fn large_route_apply_and_stop_use_bounded_journal_batches() {
    let routes = gateway_routes(512);
    let mut owner = NetworkOwner::fresh(
        ReinsertAfterNativeDelete {
            inner: System::default(),
            foreign: None,
            interrupt: false,
            interrupt_at_readback: false,
        },
        Journal::default(),
    );
    owner.select(Slot::A, routes.clone()).unwrap();
    assert_eq!(owner.system_mut().inner.writes, 512);
    assert_eq!(owner.system_mut().inner.values.len(), 512);
    owner.cleanup().unwrap();
    assert_eq!(owner.system_mut().inner.writes, 1024);
    assert!(owner.system_mut().inner.values.is_empty());
    let (_, journal) = owner.into_parts();
    assert!(
        journal.saves < 100,
        "{} saves for a 512-route add and remove",
        journal.saves
    );
}

#[test]
fn large_failed_refresh_leaves_an_unattempted_foreign_gateway_route_untouched() {
    let routes = gateway_routes(512);
    let foreign = routes[272].clone();
    let system = System {
        fail_at: vec![260],
        foreign_on_failure: Some(foreign.clone()),
        ..Default::default()
    };
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    assert!(owner.select_with_outcome(Slot::A, routes).is_err());
    owner.cleanup().unwrap();
    assert_eq!(owner.system_mut().values.len(), 1);
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
    let (_, journal) = owner.into_parts();
    assert!(
        journal.saves < 100,
        "{} writes for an interrupted 512-route transaction",
        journal.saves
    );
}

#[test]
fn interrupted_route_batch_never_claims_an_unattempted_foreign_gateway_route() {
    let routes = gateway_routes(512);
    let foreign = routes[265].clone();
    let system = System {
        halt_after_write: Some((260, foreign.clone())),
        ..Default::default()
    };
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.select_with_outcome(Slot::A, routes.clone())
    }))
    .is_err());
    let (system, store) = owner.into_parts();
    let saved = store.saved.clone().unwrap();
    let mut owner = NetworkOwner::recover(system, store, saved).unwrap();
    assert_eq!(
        owner.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert_eq!(owner.system_mut().read(&routes[0].key()).unwrap(), None);
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign.clone())
    );
    assert_eq!(
        owner.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
}
