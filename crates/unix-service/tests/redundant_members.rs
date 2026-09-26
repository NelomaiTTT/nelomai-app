use nelomai_client_tunnel::{
    redundancy::{SessionScope, Slot},
    DesktopTunnelOptions,
};
use nelomai_contracts::{HealthProbeKind, RedundantHealthProbe, RuntimeSlot};
use nelomai_unix_service::member_network::members::SessionMembers;
use nelomai_unix_service::{
    parse_configuration, ParsedConfiguration, ServiceError, ServiceTunnelBackend,
    ServiceTunnelState,
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Events {
    calls: Vec<String>,
    fail_b_start: bool,
    fail_a_stop: bool,
    index_override: Option<u32>,
    rebind_stopped: bool,
}
struct Backend {
    label: &'static str,
    index: u32,
    events: Arc<Mutex<Events>>,
}
impl ServiceTunnelBackend for Backend {
    fn member_slot(&self) -> Option<nelomai_contracts::dispatcher::TunnelSlot> {
        match self.label {
            "A" => Some(nelomai_contracts::dispatcher::TunnelSlot::A),
            "B" => Some(nelomai_contracts::dispatcher::TunnelSlot::B),
            _ => None,
        }
    }
    fn start(
        &mut self,
        _: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        assert_eq!(options, &DesktopTunnelOptions::default());
        let mut e = self.events.lock().unwrap();
        e.calls.push(format!("start {}", self.label));
        if self.label == "B" && e.fail_b_start {
            return Err(ServiceError::Backend("start_failed".into()));
        }
        Ok(ServiceTunnelState::Running)
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        let mut e = self.events.lock().unwrap();
        e.calls.push(format!("stop {}", self.label));
        if self.label == "A" && e.fail_a_stop {
            return Err(ServiceError::Backend("stop_failed".into()));
        }
        Ok(ServiceTunnelState::Stopped)
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Running)
    }
    fn member_interface_index(&self) -> Result<u32, ServiceError> {
        Ok(self
            .events
            .lock()
            .unwrap()
            .index_override
            .unwrap_or(self.index))
    }
    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        let mut events = self.events.lock().unwrap();
        events.calls.push(format!("rebind {}", self.label));
        Ok(if events.rebind_stopped {
            ServiceTunnelState::Stopped
        } else {
            ServiceTunnelState::Running
        })
    }
}
fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 5,
        session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
        connection_generation: 8,
    }
}
fn config() -> ParsedConfiguration {
    parse_configuration("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.1:51820\n").unwrap()
}
fn probe() -> RedundantHealthProbe {
    RedundantHealthProbe {
        kind: HealthProbeKind::DnsA,
        target_ipv4: "9.9.9.9".parse().unwrap(),
        query_name: "example.com".into(),
        timeout_ms: 4000,
    }
}
fn setup() -> (SessionMembers<Backend>, Arc<Mutex<Events>>) {
    let events = Arc::new(Mutex::new(Events::default()));
    let backends = [
        Backend {
            label: "A",
            index: 10,
            events: events.clone(),
        },
        Backend {
            label: "B",
            index: 20,
            events: events.clone(),
        },
    ];
    (SessionMembers::new(scope(), backends).unwrap(), events)
}

#[test]
fn reserve_start_cannot_stop_primary_or_reinstall_a_live_member() {
    let (mut members, events) = setup();
    let primary = members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    assert_eq!(primary.routes.interface, 10);
    let reserve = members
        .start(&scope(), Slot::B, &config(), probe())
        .unwrap();
    assert_eq!(reserve.routes.interface, 20);
    assert!(members
        .start(&scope(), Slot::A, &config(), probe())
        .is_err());
    assert_eq!(events.lock().unwrap().calls, ["start A", "start B"]);
}

#[test]
fn old_runtime_or_connection_generation_cannot_start_or_stop_current_members() {
    let (mut members, events) = setup();
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    let mut old = scope();
    old.connection_generation -= 1;
    assert!(members.stop(&old, Slot::A).is_err());
    assert!(members.start(&old, Slot::B, &config(), probe()).is_err());
    let mut other = scope();
    other.runtime = RuntimeSlot::Stable;
    assert!(members.close(&other).is_err());
    assert_eq!(events.lock().unwrap().calls, ["start A"]);
}

#[test]
fn partial_reserve_start_is_retained_for_cleanup_without_stopping_primary() {
    let (mut members, events) = setup();
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    events.lock().unwrap().fail_b_start = true;
    assert!(members
        .start(&scope(), Slot::B, &config(), probe())
        .is_err());
    assert!(members.cleanup_needed(Slot::B));
    members.stop(&scope(), Slot::B).unwrap();
    assert!(members.cleanup_needed(Slot::A));
    assert!(!members.cleanup_needed(Slot::B));
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "stop B"]
    );
}

#[test]
fn close_fences_late_standby_and_tries_both_members_despite_first_failure() {
    let (mut members, events) = setup();
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    members
        .start(&scope(), Slot::B, &config(), probe())
        .unwrap();
    events.lock().unwrap().fail_a_stop = true;
    assert!(members.close(&scope()).is_err());
    assert!(members
        .start(&scope(), Slot::B, &config(), probe())
        .is_err());
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "stop A", "stop B"]
    );
    events.lock().unwrap().fail_a_stop = false;
    members.close(&scope()).unwrap();
    assert_eq!(events.lock().unwrap().calls.last().unwrap(), "stop A");
    assert!(!members.cleanup_needed(Slot::A));
}

#[test]
fn constructor_rejects_single_or_misaddressed_backends_before_start() {
    let events = Arc::new(Mutex::new(Events::default()));
    for label in ["single", "B"] {
        let backends = [
            Backend {
                label,
                index: 10,
                events: events.clone(),
            },
            Backend {
                label: "B",
                index: 20,
                events: events.clone(),
            },
        ];
        assert!(SessionMembers::new(scope(), backends).is_err());
    }
    assert!(events.lock().unwrap().calls.is_empty());
}

#[test]
fn invalid_probe_and_different_reserve_vip_fail_before_native_start() {
    let (mut members, events) = setup();
    let mut invalid = probe();
    invalid.target_ipv4 = "0.0.0.0".parse().unwrap();
    assert!(members
        .start(&scope(), Slot::A, &config(), invalid)
        .is_err());
    assert!(events.lock().unwrap().calls.is_empty());
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    let mut other = config();
    other.addresses = vec!["10.8.0.3/32".parse().unwrap()];
    assert!(members.start(&scope(), Slot::B, &other, probe()).is_err());
    assert_eq!(events.lock().unwrap().calls, ["start A"]);
}

#[test]
fn subnet_addresses_cannot_add_unscoped_connected_routes_on_reserve() {
    let (mut members, events) = setup();
    for address in ["10.8.0.2/24", "2001:db8::2/64"] {
        let mut unsafe_config = config();
        unsafe_config.addresses.push(address.parse().unwrap());
        assert!(members
            .start(&scope(), Slot::A, &unsafe_config, probe())
            .is_err());
    }
    assert!(events.lock().unwrap().calls.is_empty());
}

#[test]
fn replaced_native_member_is_not_queried_or_rebound_as_the_previous_owner() {
    let (mut members, events) = setup();
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    events.lock().unwrap().index_override = Some(99);
    assert_eq!(
        members.metrics(&scope(), Slot::A).unwrap_err(),
        ServiceError::Backend("member_interface_changed".into())
    );
    assert!(members.open_probe(&scope(), Slot::A).is_err());
    assert_eq!(
        members.rebind(&scope()).unwrap_err(),
        ServiceError::Backend("member_interface_changed".into())
    );
}

#[test]
fn ipv6_source_must_also_survive_promotion_unchanged() {
    let (mut members, events) = setup();
    let mut primary = config();
    primary.addresses.push("2001:db8::2/128".parse().unwrap());
    members.start(&scope(), Slot::A, &primary, probe()).unwrap();
    let mut standby = config();
    standby.addresses.push("2001:db8::3/128".parse().unwrap());
    assert!(members.start(&scope(), Slot::B, &standby, probe()).is_err());
    assert_eq!(events.lock().unwrap().calls, ["start A"]);
}

use nelomai_client_tunnel::redundancy::network::*;
use nelomai_unix_service::member_network::session::{NetworkPolicy, SessionNetwork};
use std::{collections::HashMap, io};
#[derive(Default)]
struct NetworkState {
    values: HashMap<ResourceKey, NetworkValue>,
    writes: Vec<ResourceKey>,
    fail_interface: Option<u32>,
}
struct Network(Arc<Mutex<NetworkState>>);
impl NetworkSystem for Network {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        Ok(self.0.lock().unwrap().values.get(key).cloned())
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.values.get(key) != before {
            return Err(io::Error::other("foreign"));
        }
        if matches!(after,Some(NetworkValue::Route(r)) if Some(r.interface)==state.fail_interface) {
            return Err(io::Error::other("interface failed"));
        }
        state.writes.push(key.clone());
        match after {
            Some(v) => {
                state.values.insert(key.clone(), v.clone());
            }
            None => {
                state.values.remove(key);
            }
        }
        Ok(())
    }
}
struct Store;
impl NetworkJournalStore for Store {
    fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
        Ok(())
    }
}
fn physical() -> RouteValue {
    RouteValue {
        destination: "192.0.2.1/32".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 5,
        gateway: Some("192.0.2.254".parse().unwrap()),
        metric: 0,
    }
}
fn policy() -> NetworkPolicy {
    NetworkPolicy {
        bypasses: vec![physical()],
        retained_routes: vec![],
        dns_services: vec!["Wi-Fi".into()],
        metric: 0,
    }
}
type NetworkFixture = (
    SessionNetwork<Backend, Network, Store>,
    Arc<Mutex<Events>>,
    Arc<Mutex<NetworkState>>,
);
fn network_setup() -> NetworkFixture {
    let events = Arc::new(Mutex::new(Events::default()));
    let backends = [
        Backend {
            label: "A",
            index: 10,
            events: events.clone(),
        },
        Backend {
            label: "B",
            index: 20,
            events: events.clone(),
        },
    ];
    let state = Arc::new(Mutex::new(NetworkState::default()));
    state.lock().unwrap().values.insert(
        ResourceKey::Dns("Wi-Fi".into()),
        NetworkValue::Dns(DnsValue {
            service: "Wi-Fi".into(),
            servers: vec!["192.168.1.1".parse().unwrap()],
        }),
    );
    (
        SessionNetwork::new(scope(), backends, Network(state.clone()), Store).unwrap(),
        events,
        state,
    )
}
fn dns_config() -> ParsedConfiguration {
    let mut c = config();
    c.dns = vec!["9.9.9.9".parse().unwrap()];
    c
}

#[test]
fn primary_routes_are_ready_before_reserve_exists_and_reserve_only_adds_scoped_probe() {
    let (mut session, events, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    assert_eq!(session.active(), Some(Slot::A));
    let before = network.lock().unwrap().values.clone();
    let writes = network.lock().unwrap().writes.len();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    let current = network.lock().unwrap();
    for (key, value) in before {
        assert_eq!(current.values.get(&key), Some(&value));
    }
    assert_eq!(
        &current.writes[writes..],
        &[ResourceKey::Route(
            "9.9.9.9/32".parse().unwrap(),
            RouteScope::Member(20)
        )]
    );
    assert_eq!(events.lock().unwrap().calls, ["start A", "start B"]);
}

#[test]
fn promotion_switches_both_address_families_and_stop_restores_dns_without_resurrection() {
    let (mut session, events, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    session.select_active(&scope(), Slot::B).unwrap();
    assert_eq!(session.active(), Some(Slot::B));
    for cidr in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
        assert!(
            matches!(network.lock().unwrap().values.get(&ResourceKey::Route(cidr.parse().unwrap(),RouteScope::Global)),Some(NetworkValue::Route(r)) if r.interface==20)
        );
    }
    session.close(&scope()).unwrap();
    assert_eq!(session.active(), None);
    let values = &network.lock().unwrap().values;
    assert_eq!(values.len(), 1);
    assert_eq!(
        values.get(&ResourceKey::Dns("Wi-Fi".into())),
        Some(&NetworkValue::Dns(DnsValue {
            service: "Wi-Fi".into(),
            servers: vec!["192.168.1.1".parse().unwrap()]
        }))
    );
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "stop A", "stop B"]
    );
    assert!(session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .is_err());
    assert!(session.select_active(&scope(), Slot::B).is_err());
}

#[test]
fn route_failure_cannot_publish_reserve_and_stop_still_attempts_both_native_members() {
    let (mut session, events, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    network.lock().unwrap().fail_interface = Some(20);
    assert!(session.select_active(&scope(), Slot::B).is_err());
    assert_eq!(session.active(), Some(Slot::A));
    events.lock().unwrap().fail_a_stop = true;
    assert!(session.close(&scope()).is_err());
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "stop A", "stop B"]
    );
    assert!(session.cleanup_pending());
    events.lock().unwrap().fail_a_stop = false;
    session.close(&scope()).unwrap();
    assert!(!session.cleanup_pending());
}

#[test]
fn stale_scope_and_wrong_endpoint_bypass_cannot_mutate_network_or_start_backend() {
    let (mut session, events, network) = network_setup();
    let mut old = scope();
    old.connection_generation -= 1;
    assert!(session
        .start_primary(&old, Slot::A, &dns_config(), probe(), policy())
        .is_err());
    let mut wrong = policy();
    wrong.bypasses[0].destination = "192.0.2.2/32".parse().unwrap();
    assert!(session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), wrong)
        .is_err());
    assert!(events.lock().unwrap().calls.is_empty());
    assert!(network.lock().unwrap().writes.is_empty());
}

#[test]
fn changing_physical_network_rebinds_both_only_after_endpoint_bypasses_are_committed() {
    let (mut session, events, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    let mut next = policy();
    next.bypasses[0].interface = 6;
    next.bypasses[0].gateway = Some("192.0.2.253".parse().unwrap());
    network.lock().unwrap().fail_interface = Some(6);
    assert!(session.network_changed(&scope(), next.clone()).is_err());
    assert_eq!(events.lock().unwrap().calls, ["start A", "start B"]);
    assert_eq!(session.active(), Some(Slot::A));
    network.lock().unwrap().fail_interface = None;
    session.network_changed(&scope(), next).unwrap();
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "rebind A", "rebind B"]
    );
    assert!(
        matches!(network.lock().unwrap().values.get(&ResourceKey::Route("192.0.2.1/32".parse().unwrap(),RouteScope::Global)),Some(NetworkValue::Route(r)) if r.interface==6)
    );
    session.close(&scope()).unwrap();
    assert!(session.network_changed(&scope(), policy()).is_err());
}

#[test]
fn new_network_cannot_drop_any_live_members_physical_endpoint() {
    let (mut session, events, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    let other=parse_configuration("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\nDNS = 9.9.9.9\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.2:51820\n").unwrap();
    let mut bypass = physical();
    bypass.destination = "192.0.2.2/32".parse().unwrap();
    session
        .add_standby(&scope(), Slot::B, &other, probe(), bypass)
        .unwrap();
    let writes = network.lock().unwrap().writes.len();
    assert!(session.network_changed(&scope(), policy()).is_err());
    assert_eq!(network.lock().unwrap().writes.len(), writes);
    assert_eq!(events.lock().unwrap().calls, ["start A", "start B"]);
}

#[test]
fn non_running_rebind_result_is_not_reported_as_success() {
    let (mut members, events) = setup();
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    members
        .start(&scope(), Slot::B, &config(), probe())
        .unwrap();
    events.lock().unwrap().rebind_stopped = true;
    assert!(members.rebind(&scope()).is_err());
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "rebind A", "rebind B"]
    );
}

#[test]
fn existing_lan_route_is_verified_but_not_adopted_or_deleted_by_session() {
    let (mut session, _, network) = network_setup();
    let lan = RouteValue {
        destination: "192.168.1.0/24".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 5,
        gateway: None,
        metric: 0,
    };
    let value = NetworkValue::Route(lan.clone());
    network
        .lock()
        .unwrap()
        .values
        .insert(value.key(), value.clone());
    let mut p = policy();
    p.retained_routes.push(lan);
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    assert!(!network.lock().unwrap().writes.contains(&value.key()));
    session.close(&scope()).unwrap();
    assert_eq!(
        network.lock().unwrap().values.get(&value.key()),
        Some(&value)
    );
}

#[test]
fn vanished_retained_lan_route_cannot_be_used_to_claim_exclusion_is_installed() {
    let (mut session, events, network) = network_setup();
    let mut p = policy();
    p.retained_routes.push(RouteValue {
        destination: "192.168.1.0/24".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 5,
        gateway: None,
        metric: 0,
    });
    assert!(session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .is_err());
    assert!(events.lock().unwrap().calls.is_empty());
    assert!(network.lock().unwrap().writes.is_empty());
}

#[test]
fn preexisting_physical_endpoint_route_remains_foreign_through_start_and_stop() {
    let (mut session, _, network) = network_setup();
    let value = NetworkValue::Route(physical());
    network
        .lock()
        .unwrap()
        .values
        .insert(value.key(), value.clone());
    let mut p = policy();
    p.retained_routes = p.bypasses.clone();
    p.bypasses.clear();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    session.close(&scope()).unwrap();
    assert_eq!(
        network.lock().unwrap().values.get(&value.key()),
        Some(&value)
    );
    assert!(!network.lock().unwrap().writes.contains(&value.key()));
}
