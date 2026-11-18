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
    unavailable_label: Option<&'static str>,
    fail_tick_label: Option<&'static str>,
    disappear_on_tick: Option<&'static str>,
}
struct Backend {
    label: &'static str,
    index: u32,
    events: Arc<Mutex<Events>>,
}
impl ServiceTunnelBackend for Backend {
    fn tick(&mut self, now: u64) -> Result<(), ServiceError> {
        let mut events = self.events.lock().unwrap();
        events.calls.push(format!("tick {} {now}", self.label));
        if events.disappear_on_tick == Some(self.label) {
            events.unavailable_label = Some(self.label);
        }
        if events.fail_tick_label == Some(self.label) {
            return Err(ServiceError::Backend("forward_nat_partial_mutation".into()));
        }
        Ok(())
    }
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
        let events = self.events.lock().unwrap();
        if events.unavailable_label == Some(self.label) {
            return Err(ServiceError::Backend("member_not_running".into()));
        }
        Ok(events.index_override.unwrap_or(self.index))
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
    config_for_endpoint("192.0.2.1")
}
fn config_for_endpoint(endpoint: &str) -> ParsedConfiguration {
    parse_configuration(&format!("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}:51820\n")).unwrap()
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

use nelomai_client_tunnel::redundancy::{driver::RouteRefreshError, network::*};
use nelomai_unix_service::member_network::session::{NetworkPolicy, SessionNetwork};
use std::{collections::HashMap, io};
#[derive(Default)]
struct NetworkState {
    registrations: Vec<(Slot, u32)>,
    fail_registration: bool,
    wrong_egress_after_commit: Option<std::net::IpAddr>,
    fail_close_binding: bool,
    values: HashMap<ResourceKey, NetworkValue>,
    read_only_routes: Vec<RouteValue>,
    writes: Vec<ResourceKey>,
    fail_interface: Option<u32>,
    require_local_stop: Option<Arc<Mutex<Events>>>,
    bound_rules: bool,
    observe_closed_links: bool,
    link_dns: bool,
    fail_rule_interface: Option<u32>,
}
struct Network(Arc<Mutex<NetworkState>>);
impl NetworkSystem for Network {
    fn observe_routes_on_close(&self) -> bool {
        self.0.lock().unwrap().observe_closed_links
    }
    fn verify_physical_endpoint(
        &mut self,
        endpoint: std::net::IpAddr,
        _: &[RouteValue],
    ) -> io::Result<()> {
        let state = self.0.lock().unwrap();
        if !state.registrations.is_empty() && state.wrong_egress_after_commit == Some(endpoint) {
            return Err(io::Error::other("physical_route_changed"));
        }
        Ok(())
    }
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
        if !state.observe_closed_links {
            assert!(!state
                .values
                .values()
                .any(|v| matches!(v,NetworkValue::Route(r) if r.interface==interface)));
        }
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

    fn compare_exchange_prepared(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
        prepare: Option<&mut dyn FnMut() -> io::Result<()>>,
    ) -> Result<(), RouteRefreshError> {
        self.prepare_exchange(key, before, prepare)?;
        // The fixture's injected failures happen before a native write.
        self.compare_exchange(key, before, after)
            .map_err(RouteRefreshError::Unchanged)
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
        exclusions: vec![physical().destination],
        existing: vec![],
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
    s.add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
        .unwrap();
    assert!(s.remove_standby(&scope(), Slot::A).is_err());
    s.remove_standby(&scope(), Slot::B).unwrap();
    assert_eq!(s.active(), Some(Slot::A));
    assert_eq!(n.lock().unwrap().values, original);
    assert_eq!(e.lock().unwrap().calls, ["start A", "start B", "stop B"]);
    assert_eq!(n.lock().unwrap().registrations, [(Slot::A, 10)]);
    s.add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
        .unwrap();
    assert_eq!(s.active(), Some(Slot::A));
}

#[test]
fn removing_inactive_member_keeps_a_foreign_route_on_the_reused_link() {
    let (mut session, events, network) = network_setup();
    network.lock().unwrap().observe_closed_links = true;
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
        .unwrap();
    // Model the foreign tunnel installing an indistinguishable scoped row
    // after the kernel removed the inactive member's original row.
    let original = network.lock().unwrap().values.clone();
    let foreign = original
        .values()
        .find(|value| matches!(value, NetworkValue::Route(route) if route.interface == 20))
        .unwrap()
        .clone();
    network.lock().unwrap().writes.clear();
    session.remove_standby(&scope(), Slot::B).unwrap();
    assert_eq!(session.active(), Some(Slot::A));
    assert_eq!(network.lock().unwrap().values, original);
    assert!(!network.lock().unwrap().writes.contains(&foreign.key()));
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "stop B"]
    );
}

#[test]
fn failed_reserve_start_can_be_cleaned_without_stopping_primary() {
    let (mut s, e, _) = network_setup();
    s.start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    e.lock().unwrap().fail_b_start = true;
    assert!(s
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
    s.add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
        .unwrap();
    n.lock().unwrap().fail_close_binding = true;
    assert!(s.remove_standby(&scope(), Slot::B).is_err());
    assert!(s.cleanup_pending());
    assert!(s
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
        .add_standby(&scope(), Slot::B, &b, probe(), policy())
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
        .unwrap();
    session.select_active(&scope(), Slot::B).unwrap();
    assert_eq!(session.active(), Some(Slot::B));
    for cidr in ["0.0.0.0/1", "128.0.0.0/2", "::/1", "8000::/1"] {
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
    wrong.exclusions[0] = "192.0.2.2/32".parse().unwrap();
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
        .unwrap();
    let mut next = policy();
    let uplink = RouteValue {
        interface: 6,
        gateway: Some("192.0.2.253".parse().unwrap()),
        destination: "0.0.0.0/0".parse().unwrap(),
        ..physical()
    };
    next.retained_routes.push(uplink.clone());
    assert!(session.network_changed(&scope(), next.clone()).is_err());
    assert_eq!(events.lock().unwrap().calls, ["start A", "start B"]);
    assert_eq!(session.active(), Some(Slot::A));
    network.lock().unwrap().read_only_routes.push(uplink);
    session.network_changed(&scope(), next).unwrap();
    assert_eq!(
        events.lock().unwrap().calls,
        ["start A", "start B", "rebind A", "rebind B"]
    );
    assert!(network
        .lock()
        .unwrap()
        .values
        .values()
        .all(|v| !matches!(v,NetworkValue::Route(r) if r.interface==6)));
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
        .add_standby(&scope(), Slot::B, &other, probe(), {
            let mut p = policy();
            p.exclusions.push(bypass.destination);
            p
        })
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
        .add_standby(&scope(), Slot::B, &other, probe(), {
            let mut p = policy();
            p.exclusions.push(bypass.destination);
            p.retained_routes.push(bypass.clone());
            p
        })
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
    p.retained_routes.push(physical());
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    session
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
        .add_standby(&scope(), Slot::B, &dns_config(), probe(), policy())
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
    // The fake Stop cannot destroy a kernel interface. While an exact
    // replacement still exists, restart cleanup may neither delete nor adopt it.
    let before_stop = network.lock().unwrap().writes.len();
    assert!(recovered.close(&scope()).is_err());
    assert!(recovered.cleanup_pending());
    assert!(network.lock().unwrap().writes[before_stop..]
        .iter()
        .all(|key| !matches!(key, ResourceKey::Route(..))));
    network
        .lock()
        .unwrap()
        .values
        .retain(|_, v| !matches!(v, NetworkValue::Route(r) if [10,20].contains(&r.interface)));
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

fn control_default() -> RouteValue {
    RouteValue {
        destination: "0.0.0.0/0".parse().unwrap(),
        scope: RouteScope::Member(5),
        interface: 5,
        gateway: Some("192.0.2.254".parse().unwrap()),
        metric: 0,
    }
}
#[test]
fn control_default_keeps_vpn_routes_through_refresh_and_retried_cleanup() {
    let (mut session, events, network) = network_setup();
    let mut p = policy();
    p.retained_routes.push(control_default());
    let os_default = NetworkValue::Route(control_default());
    network
        .lock()
        .unwrap()
        .values
        .insert(os_default.key(), os_default.clone());
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p.clone())
        .unwrap();
    let control = NetworkValue::Route(control_default());
    assert_eq!(
        network.lock().unwrap().values.get(&control.key()),
        Some(&control)
    );
    for destination in ["0.0.0.0/1", "128.0.0.0/2"] {
        assert!(network.lock().unwrap().values.values().any(|v|matches!(v,NetworkValue::Route(r) if r.destination==destination.parse().unwrap() && r.interface==10 && r.scope==RouteScope::Global)));
    }
    session.network_changed(&scope(), p.clone()).unwrap();
    assert_eq!(
        network.lock().unwrap().values.get(&control.key()),
        Some(&control)
    );
    events.lock().unwrap().fail_a_stop = true;
    assert!(session.close(&scope()).is_err());
    assert!(session.cleanup_pending());
    events.lock().unwrap().fail_a_stop = false;
    session.close(&scope()).unwrap();
    session.close(&scope()).unwrap();
    assert_eq!(
        network.lock().unwrap().values.get(&control.key()),
        Some(&control)
    );
    let backends = [
        Backend {
            label: "A",
            index: 10,
            events: events.clone(),
        },
        Backend {
            label: "B",
            index: 20,
            events,
        },
    ];
    let mut restarted =
        SessionNetwork::new(scope(), backends, Network(network.clone()), Store).unwrap();
    restarted
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    restarted.close(&scope()).unwrap();
    assert_eq!(
        network.lock().unwrap().values.get(&control.key()),
        Some(&control)
    );
}
#[test]
fn control_default_borrowed_from_os_is_never_removed_by_stop() {
    let (mut session, _, network) = network_setup();
    let control = NetworkValue::Route(control_default());
    network
        .lock()
        .unwrap()
        .values
        .insert(control.key(), control.clone());
    let mut p = policy();
    p.retained_routes.push(control_default());
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    assert!(network.lock().unwrap().values.values().any(|v|matches!(v,NetworkValue::Route(r) if r.destination=="0.0.0.0/1".parse().unwrap() && r.interface==10)));
    session.close(&scope()).unwrap();
    assert_eq!(
        network.lock().unwrap().values.get(&control.key()),
        Some(&control)
    );
}

#[test]
fn control_default_journal_survives_interrupted_session_and_cleans_after_reconstruction() {
    #[derive(Clone)]
    struct Saved(Arc<Mutex<Option<NetworkJournal>>>);
    impl NetworkJournalStore for Saved {
        fn save(&mut self, journal: &NetworkJournal) -> io::Result<()> {
            *self.0.lock().unwrap() = Some(journal.clone());
            Ok(())
        }
    }
    let (_, events, network) = network_setup();
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
    let saved = Saved(Arc::new(Mutex::new(None)));
    let mut session =
        SessionNetwork::new(scope(), backends(), Network(network.clone()), saved.clone()).unwrap();
    let mut p = policy();
    p.retained_routes.push(control_default());
    let os_default = NetworkValue::Route(control_default());
    network
        .lock()
        .unwrap()
        .values
        .insert(os_default.key(), os_default.clone());
    session
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), p)
        .unwrap();
    drop(session); // Reconstruct the owner from the last durable journal, without graceful Stop.
    events.lock().unwrap().recovered_scope = Some(scope());
    events.lock().unwrap().recovered_pending = true;
    let journal = saved.0.lock().unwrap().clone().unwrap();
    let mut recovered = SessionNetwork::recover_for_cleanup(
        scope(),
        backends(),
        Network(network.clone()),
        saved,
        journal,
    )
    .unwrap();
    assert!(recovered.cleanup_pending());
    // The fake Stop cannot destroy a kernel interface. While an exact
    // replacement still exists, restart cleanup may neither delete nor adopt it.
    let before_stop = network.lock().unwrap().writes.len();
    assert!(recovered.close(&scope()).is_err());
    assert!(recovered.cleanup_pending());
    assert!(network.lock().unwrap().writes[before_stop..]
        .iter()
        .all(|key| !matches!(key, ResourceKey::Route(..))));
    network
        .lock()
        .unwrap()
        .values
        .retain(|_, v| !matches!(v, NetworkValue::Route(r) if [10,20].contains(&r.interface)));
    recovered.close(&scope()).unwrap();
    let state = network.lock().unwrap();
    assert_eq!(state.values.get(&os_default.key()), Some(&os_default));
    assert!(!state.writes.contains(&os_default.key()));
    assert!(state
        .values
        .values()
        .all(|v| v == &os_default || matches!(v, NetworkValue::Dns(_))));
}

#[test]
fn live_member_ticks_refresh_virtual_networks_without_ticking_absent_or_closed_members() {
    let (mut members, events) = setup();
    members.tick_backends(&scope(), 1).unwrap();
    assert!(events.lock().unwrap().calls.is_empty());
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    members.tick_backends(&scope(), 2).unwrap();
    assert_eq!(events.lock().unwrap().calls, ["start A", "tick A 2"]);
    members
        .start(&scope(), Slot::B, &config(), probe())
        .unwrap();
    members.tick_backends(&scope(), 3).unwrap();
    assert_eq!(
        &events.lock().unwrap().calls[2..],
        ["start B", "tick A 3", "tick B 3"]
    );
    let mut stale = scope();
    stale.connection_generation -= 1;
    let count = events.lock().unwrap().calls.len();
    assert!(members.tick_backends(&stale, 4).is_err());
    assert_eq!(events.lock().unwrap().calls.len(), count);
    members.close(&scope()).unwrap();
    let count = events.lock().unwrap().calls.len();
    members.tick_backends(&scope(), 5).unwrap();
    assert_eq!(events.lock().unwrap().calls.len(), count);
}

#[test]
fn nat_ticks_leave_unavailable_active_or_retiring_standby_to_existing_health_recovery() {
    for (unavailable, survivor) in [("A", "B"), ("B", "A")] {
        let (mut members, events) = setup();
        members
            .start(&scope(), Slot::A, &config(), probe())
            .unwrap();
        members
            .start(&scope(), Slot::B, &config(), probe())
            .unwrap();
        {
            let mut e = events.lock().unwrap();
            e.calls.clear();
            e.unavailable_label = Some(unavailable);
        }
        members.tick_backends(&scope(), 9).unwrap();
        assert_eq!(events.lock().unwrap().calls, [format!("tick {survivor} 9")]);
        // The NAT maintenance pass neither retires membership nor erases its
        // cleanup obligation. The original health/Stop path still owns both.
        assert!(members.view(Slot::A).is_some());
        assert!(members.view(Slot::B).is_some());
        assert!(members.cleanup_needed(Slot::A));
        assert!(members.cleanup_needed(Slot::B));
    }
}

#[test]
fn member_disappearance_after_successful_nat_tick_does_not_stop_the_other_member() {
    let (mut members, events) = setup();
    members
        .start(&scope(), Slot::A, &config(), probe())
        .unwrap();
    members
        .start(&scope(), Slot::B, &config(), probe())
        .unwrap();
    {
        let mut e = events.lock().unwrap();
        e.calls.clear();
        e.disappear_on_tick = Some("A");
    }
    members.tick_backends(&scope(), 10).unwrap();
    assert_eq!(events.lock().unwrap().calls, ["tick A 10", "tick B 10"]);
}

#[test]
fn nat_partial_mutation_failure_remains_authoritative_even_if_member_also_disappears() {
    for disappear in [false, true] {
        let (mut members, events) = setup();
        members
            .start(&scope(), Slot::A, &config(), probe())
            .unwrap();
        members
            .start(&scope(), Slot::B, &config(), probe())
            .unwrap();
        {
            let mut e = events.lock().unwrap();
            e.calls.clear();
            e.fail_tick_label = Some("A");
            if disappear {
                e.disappear_on_tick = Some("A");
            }
        }
        let error = members.tick_backends(&scope(), 11).unwrap_err();
        assert!(
            matches!(error,ServiceError::Backend(message) if message=="forward_nat_partial_mutation")
        );
        assert_eq!(events.lock().unwrap().calls, ["tick A 11"]);
        assert!(members.cleanup_needed(Slot::A));
        assert!(members.cleanup_needed(Slot::B));
    }
}

#[test]
fn active_data_routes_leave_each_transport_endpoint_to_the_os() {
    let (mut pair, _, network) = network_setup();
    pair.start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    let endpoint = physical().destination.addr();
    let state = network.lock().unwrap();
    assert!(state
        .values
        .values()
        .all(|value| !matches!(value, NetworkValue::Route(r)
            if r.scope == RouteScope::Global && r.destination.contains(&endpoint))));
}

#[test]
fn failed_effective_egress_check_after_start_fences_active_routes_until_stop() {
    let (mut pair, _, network) = network_setup();
    network.lock().unwrap().wrong_egress_after_commit = Some(physical().destination.addr());
    assert!(pair
        .start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .is_err());
    assert!(pair.active().is_none());
    assert!(pair.cleanup_pending());
    pair.close(&scope()).unwrap();
    assert_eq!(network.lock().unwrap().values.len(), 1);
}

#[test]
fn candidate_with_unverified_egress_never_starts_and_primary_stays_live() {
    let (mut pair, events, network) = network_setup();
    pair.start_primary(&scope(), Slot::A, &dns_config(), probe(), policy())
        .unwrap();
    let other = parse_configuration("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.2:51820\n").unwrap();
    let endpoint: std::net::IpAddr = "192.0.2.2".parse().unwrap();
    let mut p = policy();
    p.exclusions.push(endpoint.into());
    network.lock().unwrap().wrong_egress_after_commit = Some(endpoint);
    assert!(pair
        .add_standby(&scope(), Slot::B, &other, probe(), p)
        .is_err());
    assert_eq!(events.lock().unwrap().calls, ["start A"]);
    assert_eq!(pair.active(), Some(Slot::A));
    assert!(!pair.cleanup_pending());
    pair.close(&scope()).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires the disposable macOS VM and its root-owned WG/AWG engines"]
fn native_mac_pair_routes_refresh_promote_and_stop() {
    use nelomai_client_tunnel::{
        redundancy::{control::PairControl, driver::NativePair, protocol::Member},
        TunnelConfiguration,
    };
    use nelomai_unix_service::member_network::driver::SessionNativePair;
    use nelomai_unix_service::member_network::macos::{MacNetworkCommands, NativeMacCommands};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    let model = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.model"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&model.stdout).contains("VirtualMac"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let path = |key| std::path::PathBuf::from(std::env::var_os(key).unwrap());
    let root = path("NELOMAI_OWNER_QA_ROOT");
    let wg = path("NELOMAI_OWNER_QA_WG");
    let awg = path("NELOMAI_OWNER_QA_AWG");
    let mut session =
        nelomai_unix_service::member_network::factory::open_mac_pair(&root, scope(), &wg, &awg)
            .unwrap();
    let stage = std::env::var("NELOMAI_OWNER_QA_STAGE").unwrap();
    if stage == "recover" {
        assert!(session.cleanup_pending());
        session.close(&scope()).unwrap();
        assert!(!session.cleanup_pending());
        return;
    }
    assert!(matches!(
        stage.as_str(),
        "live" | "crash" | "engine-exit" | "detaching"
    ));
    let member_name = |slot: &str| {
        std::fs::read_to_string(root.join(slot).join("interface-name"))
            .unwrap()
            .trim()
            .to_owned()
    };
    let engine_identity = |slot: &str| {
        let name = member_name(slot);
        let socket = format!("/var/run/wireguard/{name}.sock");
        let meta = std::fs::symlink_metadata(socket).unwrap();
        let index = NativeMacCommands.interface_index(&name).unwrap();
        assert_ne!(index, 0);
        (name, index, meta.dev(), meta.ino())
    };
    let full = std::env::var_os("NELOMAI_ROUTE_QA_FULL").is_some();
    let allowed = if full {
        "0.0.0.0/0, ::/0"
    } else {
        "198.19.237.0/24"
    };
    let ips = ["198.19.237.60", "198.19.237.61"];
    let options = |ip: &str| DesktopTunnelOptions {
        policy_hash: Some("sha256:test".into()),
        excluded_ipv4_cidrs: vec![format!("{ip}/32")],
        ..Default::default()
    };
    let lookup = |ip: &str| {
        let result = NativeMacCommands
            .run(
                "/sbin/route",
                &["-n".into(), "get".into(), "-inet".into(), ip.into()],
            )
            .unwrap();
        result
            .lines()
            .find_map(|s| s.trim().strip_prefix("interface: "))
            .unwrap()
            .to_owned()
    };
    let check_panel = |interface: &str, active: bool| {
        if full {
            let url = std::env::var("NELOMAI_ROUTE_QA_PANEL_URL").unwrap();
            let panel_ip = std::env::var("NELOMAI_ROUTE_QA_PANEL_IP").unwrap();
            if active {
                assert_ne!(lookup(&panel_ip), interface);
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let history = runtime.block_on(async {
                nelomai_client_api::ClientApi::new(&url).unwrap().release_history(nelomai_contracts::Platform::Macos).await
            }).expect("the app's bound TLS transport must reach the panel while the data route points into the test tunnel");
            assert_eq!(history.platform, nelomai_contracts::Platform::Macos);
            println!(
                "panel returned {} release history entries via the application transport",
                history.entries.len()
            );
        }
    };
    let old = "198.19.237.21";
    let new = "198.19.237.22";
    let physical = lookup(old);
    check_panel(&physical, false);
    let mut probe = probe();
    probe.target_ipv4 = "198.19.237.100".parse().unwrap();
    let member = |slot, endpoint, suffix| {
        Member {
        slot,
        lease_id: format!("c66d98eb-4b03-4bd3-9663-133f84760b9{suffix}"),
        configuration: TunnelConfiguration::new(format!(
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32, fd12:ca6e::2/128\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = {allowed}\nEndpoint = {endpoint}:51820\n"
        )),
        probe: probe.clone(),
    }
    };
    // A physical-interface tcpdump can distinguish each active transition
    // from the positive controls before Start and after Stop by UDP port.
    let sample = |port, operation: &mut dyn FnMut()| {
        if stage != "live" || std::env::var_os("NELOMAI_ROUTE_QA_SENTINELS").is_none() {
            operation();
            return;
        }
        use std::sync::atomic::{AtomicBool, Ordering};
        let finished = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
                loop {
                    for host in ["198.19.237.23", "198.19.237.62", "203.0.113.123"] {
                        let _ = socket.send_to(b"nelomai route sentinel", (host, port));
                    }
                    if finished.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_micros(250));
                }
            });
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
            finished.store(true, Ordering::Relaxed);
            if let Err(payload) = outcome {
                std::panic::resume_unwind(payload);
            }
        });
    };
    let control = || std::thread::sleep(std::time::Duration::from_millis(300));
    sample(45991, &mut || control());
    let mut pair = SessionNativePair::new(scope(), session).unwrap();
    pair.start_primary(&scope(), &member(Slot::A, ips[0], '1'), &options(old))
        .unwrap();
    assert_eq!(lookup(old), physical);
    assert_eq!(lookup(new), member_name("slot-a"));
    check_panel(&physical, true);
    sample(45992, &mut || {
        pair.attach(&scope(), &member(Slot::B, ips[1], '2'))
            .unwrap();
    });
    let primary = engine_identity("slot-a");
    let standby = engine_identity("slot-b");
    assert_ne!(primary.1, standby.1);
    sample(45993, &mut || {
        pair.refresh_split_tunnel(&scope(), &options(new)).unwrap();
    });
    assert_eq!(lookup(old), member_name("slot-a"));
    assert_eq!(lookup(new), physical);
    sample(45994, &mut || {
        pair.select_active(&scope(), Slot::B).unwrap();
    });
    assert_eq!(engine_identity("slot-a"), primary);
    assert_eq!(engine_identity("slot-b"), standby);
    assert_eq!(lookup(old), member_name("slot-b"));
    assert_eq!(lookup(new), physical);
    for ip in ips {
        assert_eq!(lookup(ip), physical);
    }
    check_panel(&physical, true);
    if matches!(stage.as_str(), "engine-exit" | "detaching") {
        let socket = format!("/var/run/wireguard/{}.sock", primary.0);
        let peer = UnixStream::connect(&socket).unwrap();
        let mut pid = 0i32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        peer.as_raw_fd(),
                        0,
                        libc::LOCAL_PEERPID,
                        (&mut pid as *mut i32).cast(),
                        &mut length,
                    )
                },
                0
            );
            assert_eq!(length as usize, std::mem::size_of_val(&pid));
            if pid > 1 && pid as u32 != std::process::id() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "engine did not accept UAPI probe"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if stage == "detaching" {
            struct ResumeEngine(libc::pid_t);
            impl Drop for ResumeEngine {
                fn drop(&mut self) {
                    unsafe { libc::kill(self.0, libc::SIGCONT) };
                }
            }
            assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
            let paused = ResumeEngine(pid);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                let status = std::process::Command::new("/bin/ps")
                    .args(["-p", &pid.to_string(), "-o", "stat="])
                    .output()
                    .unwrap();
                if String::from_utf8_lossy(&status.stdout)
                    .trim()
                    .starts_with('T')
                {
                    break;
                }
                assert!(std::time::Instant::now() < deadline, "engine did not pause");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            std::fs::remove_file(&socket).unwrap();
            assert_eq!(
                NativeMacCommands.interface_index(&primary.0).unwrap(),
                primary.1
            );
            drop(paused);
            drop(pair);
            let mut recovered = nelomai_unix_service::member_network::factory::open_mac_pair(
                &root,
                scope(),
                &wg,
                &awg,
            )
            .unwrap();
            assert!(recovered.cleanup_pending());
            recovered.close(&scope()).unwrap();
            assert!(!recovered.cleanup_pending());
            assert_eq!(lookup(old), physical);
            return;
        }
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while UnixStream::connect(&socket).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "engine did not close its UAPI listener"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            NativeMacCommands.interface_index(&primary.0).unwrap(),
            primary.1
        );
        assert!(
            std::path::Path::new(&socket).exists(),
            "expected the published socket to outlive the engine"
        );
        assert!(pair.select_active(&scope(), Slot::A).is_err());
        assert_eq!(lookup(old), standby.0);
    }
    if matches!(stage.as_str(), "crash" | "engine-exit") {
        std::process::exit(79);
    }
    pair.close(&scope()).unwrap();
    sample(45995, &mut || control());
    assert_eq!(lookup(old), physical);
    check_panel(&physical, false);
    assert!(!pair.cleanup_pending());
}
