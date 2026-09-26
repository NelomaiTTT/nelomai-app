use nelomai_client_tunnel::redundancy::network::*;
use nelomai_client_tunnel::redundancy::Slot;
use std::{collections::BTreeMap, io};

#[derive(Default)]
struct System {
    values: BTreeMap<String, NetworkValue>,
    writes: usize,
    fail_at: Vec<usize>,
    ignore_at: Vec<usize>,
    reject_interfaces: Vec<u32>,
}
impl NetworkSystem for System {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
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
    let mut system = System::default();
    let foreign = route("0.0.0.0/1", 77);
    system
        .values
        .insert(format!("{:?}", foreign.key()), foreign.clone());
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    assert!(owner.select(Slot::A, pair(10)).is_err());
    assert_eq!(owner.system_mut().writes, 0);
    owner.cleanup().unwrap();
    assert_eq!(
        owner.system_mut().read(&foreign.key()).unwrap(),
        Some(foreign)
    );
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
    system.values.insert(format!("{:?}", dns.key()), original);
    let mut owner = NetworkOwner::fresh(system, Journal::default());
    owner.select(Slot::A, vec![dns.clone()]).unwrap();
    owner
        .system_mut()
        .values
        .insert(format!("{:?}", dns.key()), foreign.clone());
    assert!(owner.cleanup().is_err());
    assert!(owner.cleanup_pending());
    assert_eq!(owner.system_mut().read(&dns.key()).unwrap(), Some(foreign));
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
    let mut routes = vec![route("192.0.2.1/32", 5)];
    routes.extend(pair(10));
    owner.select(Slot::A, routes).unwrap();
    assert_eq!(owner.active(), Some(Slot::A));
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
