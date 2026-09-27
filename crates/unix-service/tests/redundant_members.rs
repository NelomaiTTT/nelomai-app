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
    recovered_scope: Option<SessionScope>,
    recovered_pending: bool,
}
struct Backend {
    label: &'static str,
    index: u32,
    events: Arc<Mutex<Events>>,
}
impl ServiceTunnelBackend for Backend {
    fn member_recovery_scope(&self) -> Option<SessionScope> {
        self.events.lock().unwrap().recovered_scope.clone()
    }
    fn member_cleanup_pending(&self) -> bool {
        self.events.lock().unwrap().recovered_pending
    }
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

#[test]
fn restart_only_cleanup_recovers_exact_scope_and_never_pretends_to_be_fresh_start() {
    let events = Arc::new(Mutex::new(Events {
        recovered_scope: Some(scope()),
        recovered_pending: true,
        ..Default::default()
    }));
    let backends = || {
        [
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
        ]
    };
    assert!(SessionMembers::new(scope(), backends()).is_err());
    let mut old = scope();
    old.connection_generation += 1;
    assert!(SessionMembers::recover_for_cleanup(old, backends()).is_err());
    let mut recovered = SessionMembers::recover_for_cleanup(scope(), backends()).unwrap();
    assert!(recovered.view(Slot::A).is_none());
    assert!(recovered
        .start(&scope(), Slot::A, &config(), probe())
        .is_err());
    assert!(events.lock().unwrap().calls.is_empty());
    events.lock().unwrap().fail_a_stop = true;
    assert!(recovered.close(&scope()).is_err());
    assert!(recovered.cleanup_needed(Slot::A));
    assert!(!recovered.cleanup_needed(Slot::B));
    events.lock().unwrap().fail_a_stop = false;
    recovered.close(&scope()).unwrap();
    assert_eq!(events.lock().unwrap().calls, ["stop A", "stop B", "stop A"]);
    assert!(recovered
        .start(&scope(), Slot::B, &config(), probe())
        .is_err());
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
    registrations: Vec<(Slot, u32)>,
    fail_registration: bool,
    fail_close_binding: bool,
    values: HashMap<ResourceKey, NetworkValue>,
    read_only_routes: Vec<RouteValue>,
    writes: Vec<ResourceKey>,
    fail_interface: Option<u32>,
    require_local_stop: Option<Arc<Mutex<Events>>>,
    bound_rules: bool,
    link_dns: bool,
    fail_rule_interface: Option<u32>,
}
struct Network(Arc<Mutex<NetworkState>>);
impl NetworkSystem for Network {
    fn member_started(&mut self, slot: Slot, interface: u32) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.fail_registration {
            return Err(io::Error::other("binding write failed"));
        }
        state.registrations.push((slot, interface));
        Ok(())
    }
    fn session_closed(&mut self) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.fail_close_binding {
            return Err(io::Error::other("binding close failed"));
        }
        state.registrations.clear();
        Ok(())
    }
    fn member_stopped(&mut self, slot: Slot, interface: u32) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        assert!(!state
            .values
            .values()
            .any(|v| matches!(v,NetworkValue::Route(r) if r.interface==interface)));
        if state.fail_close_binding {
            return Err(io::Error::other("binding close failed"));
        }
        state.registrations.retain(|p| *p != (slot, interface));
        Ok(())
    }
    fn dns_resources(
        &self,
        interface: u32,
        servers: &[std::net::IpAddr],
        services: &[String],
    ) -> io::Result<Vec<NetworkValue>> {
        if self.0.lock().unwrap().link_dns {
            Ok(vec![
                NetworkValue::LinkDns(LinkDnsValue {
                    interface,
                    servers: servers.to_vec(),
                }),
                NetworkValue::LinkDnsRoute(interface),
            ])
        } else {
            Ok(services
                .iter()
                .map(|service| {
                    NetworkValue::Dns(DnsValue {
                        service: service.clone(),
                        servers: servers.to_vec(),
                    })
                })
                .collect())
        }
    }
    fn verify_retained_route(&mut self, route: &RouteValue) -> io::Result<bool> {
        let state = self.0.lock().unwrap();
        if state
            .read_only_routes
            .iter()
            .any(|r| r.destination == route.destination)
        {
            return Ok(state.read_only_routes.contains(route));
        }
        let value = NetworkValue::Route(route.clone());
        Ok(state.values.get(&value.key()) == Some(&value))
    }
    fn route_resources(&self, route: RouteValue) -> io::Result<Vec<NetworkValue>> {
        let mut values = vec![NetworkValue::Route(route.clone())];
        if self.0.lock().unwrap().bound_rules {
            if let RouteScope::Member(interface) = route.scope {
                values.push(NetworkValue::BoundRule(BoundRuleValue {
                    ipv6: route.destination.addr().is_ipv6(),
                    priority: 12000 + interface,
                    table: 52000 + interface,
                    interface,
                }));
            }
        }
        Ok(values)
    }
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        if self
            .0
            .lock()
            .unwrap()
            .read_only_routes
            .iter()
            .any(|r| NetworkValue::Route(r.clone()).key() == *key)
        {
            return Err(io::Error::other("not_an_owned_static_route"));
        }
        Ok(self.0.lock().unwrap().values.get(key).cloned())
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        if let Some(events) = &state.require_local_stop {
            if !events.lock().unwrap().calls.iter().any(|c| c == "stop A") {
                return Err(io::Error::other("local_vpn_still_running"));
            }
        }
        if state.values.get(key) != before {
            return Err(io::Error::other("foreign"));
        }
        if matches!(after,Some(NetworkValue::Route(r)) if Some(r.interface)==state.fail_interface) {
            return Err(io::Error::other("interface failed"));
        }
        if matches!(after,Some(NetworkValue::BoundRule(r)) if Some(r.interface)==state.fail_rule_interface)
        {
            return Err(io::Error::other("rule failed"));
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
fn bindings_are_sealed_before_routes_and_retained_until_cleanup_finishes() {
    let (mut session, _, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    assert_eq!(network.lock().unwrap().registrations, vec![(Slot::A, 10)]);
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    assert_eq!(
        network.lock().unwrap().registrations,
        vec![(Slot::A, 10), (Slot::B, 20)]
    );
    network.lock().unwrap().fail_close_binding = true;
    assert!(session.close(&scope()).is_err());
    assert!(session.cleanup_pending());
    network.lock().unwrap().fail_close_binding = false;
    session.close(&scope()).unwrap();
    assert!(!session.cleanup_pending());
    assert!(network.lock().unwrap().registrations.is_empty());
}

#[test]
fn failed_member_binding_does_not_publish_routes_but_keeps_native_cleanup() {
    let (mut session, events, network) = network_setup();
    network.lock().unwrap().fail_registration = true;
    assert!(session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .is_err());
    assert!(session.active().is_none());
    session.close(&scope()).unwrap();
    assert!(events.lock().unwrap().calls.contains(&"stop A".into()));
}

#[test]
fn removing_inactive_member_preserves_primary_routes_dns_and_native_lifetime() {
    let (mut s, e, n) = network_setup();
    s.start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    let original = n.lock().unwrap().values.clone();
    s.add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    assert!(s.remove_standby(&scope(), Slot::A).is_err());
    s.remove_standby(&scope(), Slot::B).unwrap();
    assert_eq!(s.active(), Some(Slot::A));
    assert_eq!(n.lock().unwrap().values, original);
    assert_eq!(e.lock().unwrap().calls, ["start A", "start B", "stop B"]);
    assert_eq!(n.lock().unwrap().registrations, [(Slot::A, 10)]);
    s.add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    assert_eq!(s.active(), Some(Slot::A));
}

#[test]
fn failed_reserve_start_can_be_cleaned_without_stopping_primary() {
    let (mut s, e, _) = network_setup();
    s.start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    e.lock().unwrap().fail_b_start = true;
    assert!(s
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .is_err());
    s.remove_standby(&scope(), Slot::B).unwrap();
    assert_eq!(s.active(), Some(Slot::A));
    assert_eq!(e.lock().unwrap().calls, ["start A", "start B", "stop B"]);
}

#[test]
fn failed_reserve_binding_release_is_retained_and_retried_without_second_native_stop() {
    let (mut s, e, n) = network_setup();
    s.start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    s.add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    n.lock().unwrap().fail_close_binding = true;
    assert!(s.remove_standby(&scope(), Slot::B).is_err());
    assert!(s.cleanup_pending());
    assert!(s
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .is_err());
    n.lock().unwrap().fail_close_binding = false;
    s.remove_standby(&scope(), Slot::B).unwrap();
    assert!(!s.cleanup_pending());
    assert_eq!(e.lock().unwrap().calls, ["start A", "start B", "stop B"]);
}

#[test]
fn session_link_dns_follows_active_member_not_standby_creation() {
    let (mut session, _, network) = network_setup();
    network.lock().unwrap().link_dns = true;
    let mut p = policy();
    p.dns_services.clear(); // Linux has no physical DNS-service overrides.
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    let mut b = dns_config();
    b.dns = vec!["77.88.8.8".parse().unwrap()];
    session
        .add_standby(&scope(), Slot::B, &b, probe(), physical())
        .unwrap();
    {
        let state = network.lock().unwrap();
        assert!(state.values.contains_key(&ResourceKey::LinkDnsRoute(10)));
        assert!(!state.values.contains_key(&ResourceKey::LinkDns(20)));
        assert!(!state.values.contains_key(&ResourceKey::LinkDnsRoute(20)));
    }
    session.select_active(&scope(), Slot::B).unwrap();
    {
        let state = network.lock().unwrap();
        assert!(!state.values.contains_key(&ResourceKey::LinkDns(10)));
        assert!(!state.values.contains_key(&ResourceKey::LinkDnsRoute(10)));
        assert_eq!(
            state.values.get(&ResourceKey::LinkDns(20)),
            Some(&NetworkValue::LinkDns(LinkDnsValue {
                interface: 20,
                servers: b.dns
            }))
        );
        assert!(state.values.contains_key(&ResourceKey::LinkDnsRoute(20)));
    }
    session.close(&scope()).unwrap();
    assert_eq!(network.lock().unwrap().values.len(), 1); // untouched physical DNS.
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
fn member_probe_rules_participate_in_session_switch_and_stop_transaction() {
    let (mut session, _, network) = network_setup();
    network.lock().unwrap().bound_rules = true;
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    let a = ResourceKey::BoundRule {
        ipv6: false,
        priority: 12010,
    };
    let b = ResourceKey::BoundRule {
        ipv6: false,
        priority: 12020,
    };
    assert!(network.lock().unwrap().values.contains_key(&a));
    assert!(!network.lock().unwrap().values.contains_key(&b));
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    session.select_active(&scope(), Slot::B).unwrap();
    assert!(network.lock().unwrap().values.contains_key(&a));
    assert!(network.lock().unwrap().values.contains_key(&b));
    session.close(&scope()).unwrap();
    let values = &network.lock().unwrap().values;
    assert!(!values.contains_key(&a));
    assert!(!values.contains_key(&b));
    assert_eq!(values.len(), 1); // original DNS only
}

#[test]
fn failed_standby_rule_rolls_back_probe_route_without_breaking_primary() {
    let (mut session, _, network) = network_setup();
    network.lock().unwrap().bound_rules = true;
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    let before = network.lock().unwrap().values.clone();
    network.lock().unwrap().fail_rule_interface = Some(20);
    assert!(session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .is_err());
    assert_eq!(session.active(), Some(Slot::A));
    assert_eq!(network.lock().unwrap().values, before);
    session.close(&scope()).unwrap();
    assert!(!session.cleanup_pending());
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
fn local_stop_precedes_potentially_slow_route_and_dns_cleanup() {
    let (mut session, events, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    network.lock().unwrap().require_local_stop = Some(events.clone());
    session.close(&scope()).unwrap();
    assert!(!session.cleanup_pending());
    assert_eq!(network.lock().unwrap().values.len(), 1);
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
fn session_uses_read_only_dependency_verification_without_claiming_kernel_routes() {
    let (mut session, _, network) = network_setup();
    let lan = RouteValue {
        destination: "192.168.1.0/24".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 5,
        gateway: None,
        metric: 100,
    };
    network.lock().unwrap().read_only_routes.push(lan.clone());
    let mut p = policy();
    p.retained_routes.push(lan.clone());
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    session.select_active(&scope(), Slot::B).unwrap();
    session.close(&scope()).unwrap();
    let state = network.lock().unwrap();
    assert_eq!(state.read_only_routes, vec![lan.clone()]);
    assert!(!state.writes.contains(&NetworkValue::Route(lan).key()));
}

#[test]
fn late_standby_can_borrow_its_existing_dhcp_endpoint_without_adopting_it() {
    let (mut session, _, network) = network_setup();
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    let other=parse_configuration("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\nDNS = 9.9.9.9\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.2:51820\n").unwrap();
    let mut bypass = physical();
    bypass.destination = "192.0.2.2/32".parse().unwrap();
    network
        .lock()
        .unwrap()
        .read_only_routes
        .push(bypass.clone());
    session
        .add_standby(&scope(), Slot::B, &other, probe(), bypass.clone())
        .unwrap();
    session.select_active(&scope(), Slot::B).unwrap();
    session.close(&scope()).unwrap();
    let state = network.lock().unwrap();
    assert_eq!(state.read_only_routes, vec![bypass.clone()]);
    assert!(!state.writes.contains(&NetworkValue::Route(bypass).key()));
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

#[test]
fn restart_cleanup_restores_network_and_stops_owned_pair_without_replaying_start() {
    #[derive(Clone, Default)]
    struct Durable(Arc<Mutex<NetworkJournal>>);
    impl NetworkJournalStore for Durable {
        fn save(&mut self, value: &NetworkJournal) -> io::Result<()> {
            *self.0.lock().unwrap() = value.clone();
            Ok(())
        }
    }
    let events = Arc::new(Mutex::new(Events::default()));
    let backends = || {
        [
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
        ]
    };
    let network = Arc::new(Mutex::new(NetworkState::default()));
    let baseline = NetworkValue::Dns(DnsValue {
        service: "Wi-Fi".into(),
        servers: vec!["192.168.1.1".parse().unwrap()],
    });
    network
        .lock()
        .unwrap()
        .values
        .insert(baseline.key(), baseline.clone());
    let durable = Durable::default();
    let mut original = SessionNetwork::new(
        scope(),
        backends(),
        Network(network.clone()),
        durable.clone(),
    )
    .unwrap();
    original
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    original
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), physical())
        .unwrap();
    original.select_active(&scope(), Slot::B).unwrap();
    drop(original); // helper process state disappears; native resources persist
    events.lock().unwrap().recovered_scope = Some(scope());
    events.lock().unwrap().recovered_pending = true;
    let journal = durable.0.lock().unwrap().clone();
    events.lock().unwrap().recovered_pending = false;
    let network_only = SessionNetwork::recover_for_cleanup(
        scope(),
        backends(),
        Network(network.clone()),
        durable.clone(),
        journal.clone(),
    )
    .unwrap();
    assert!(
        network_only.cleanup_pending(),
        "native members may already be gone while routes/DNS still need cleanup"
    );
    drop(network_only);
    events.lock().unwrap().recovered_pending = true;
    let writes = network.lock().unwrap().writes.len();
    let mut recovered = SessionNetwork::recover_for_cleanup(
        scope(),
        backends(),
        Network(network.clone()),
        durable,
        journal,
    )
    .unwrap();
    assert_eq!(network.lock().unwrap().writes.len(), writes);
    assert_eq!(recovered.active(), None);
    assert!(recovered.cleanup_pending());
    assert!(recovered.select_active(&scope(), Slot::B).is_err());
    recovered.close(&scope()).unwrap();
    assert!(!recovered.cleanup_pending());
    assert_eq!(
        network.lock().unwrap().values,
        HashMap::from([(baseline.key(), baseline)])
    );
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "stop A", "stop B"]
    );
}
