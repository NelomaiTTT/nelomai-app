use nelomai_client_tunnel::redundancy::network::*;
use nelomai_client_tunnel::redundancy::Slot;
use std::{collections::BTreeMap, io};

#[derive(Default)]
struct System {
    values: BTreeMap<String, NetworkValue>,
    writes: usize,
    reads: Vec<ResourceKey>,
    fail_at: Vec<usize>,
    ignore_at: Vec<usize>,
    reject_interfaces: Vec<u32>,
}
impl NetworkSystem for System {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        self.reads.push(key.clone());
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
        }
        Ok(())
    }
}
#[derive(Default)]
struct Journal {
    saved: Option<NetworkJournal>,
    fail: bool,
}
impl NetworkJournalStore for Journal {
    fn save(&mut self, value: &NetworkJournal) -> io::Result<()> {
        if self.fail {
            return Err(io::Error::other("disk"));
        }
        self.saved = Some(value.clone());
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
    let mut owner = NetworkOwner::fresh(System::default(), Journal::default());
    owner.select(Slot::A, pair(10)).unwrap();
    owner.cleanup().unwrap();
    assert!(!owner.cleanup_pending());
    assert_eq!(owner.active(), None);
    assert!(owner.select(Slot::B, pair(20)).is_err());
    assert!(owner.system_mut().values.is_empty());
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
