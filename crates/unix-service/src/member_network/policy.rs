//! Read-only physical discovery behind the session's private ownership boundary.
use super::session::NetworkPolicy;
use ipnet::IpNet;
use nelomai_client_tunnel::{redundancy::network::NetworkSystem, DesktopTunnelOptions};
use std::{io, net::IpAddr};

pub trait PhysicalPolicyProvider: NetworkSystem {
    /// `owned` is supplied by SessionNetwork from its journal, never by IPC.
    fn resolve_policy(
        &mut self,
        options: &DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[IpNet],
    ) -> io::Result<NetworkPolicy>;
}

#[cfg(any(target_os = "macos", test))]
impl<C: super::macos::MacNetworkCommands> PhysicalPolicyProvider for super::macos::MacNetwork<C> {
    fn resolve_policy(
        &mut self,
        options: &DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[IpNet],
    ) -> io::Result<NetworkPolicy> {
        super::macos::MacNetwork::resolve_policy(self, options, endpoints, owned)
    }
}

#[cfg(any(target_os = "linux", test))]
impl<C: super::linux::LinuxNetworkCommands> PhysicalPolicyProvider
    for super::linux::LinuxNetwork<C>
{
    fn resolve_policy(
        &mut self,
        options: &DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[IpNet],
    ) -> io::Result<NetworkPolicy> {
        super::linux::LinuxNetwork::resolve_policy(self, options, endpoints, owned)
    }
}

#[cfg(test)]
mod tests {
    use super::super::session::SessionNetwork;
    use super::*;
    use crate::{
        parse_configuration, ParsedConfiguration, ServiceError, ServiceTunnelBackend,
        ServiceTunnelState,
    };
    use nelomai_client_tunnel::redundancy::{network::*, SessionScope, Slot};
    use nelomai_contracts::{
        dispatcher::TunnelSlot, HealthProbeKind, RedundantHealthProbe, RuntimeSlot,
    };
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    #[derive(Clone, Debug, PartialEq)]
    struct Query {
        options: DesktopTunnelOptions,
        endpoints: Vec<IpAddr>,
        owned: Vec<IpNet>,
    }
    #[derive(Default)]
    struct State {
        queries: Vec<Query>,
        native_calls: usize,
        fail_resolve: bool,
        values: HashMap<ResourceKey, NetworkValue>,
    }
    struct Backend {
        slot: TunnelSlot,
        state: Rc<RefCell<State>>,
    }
    impl ServiceTunnelBackend for Backend {
        fn member_slot(&self) -> Option<TunnelSlot> {
            Some(self.slot)
        }
        fn member_interface_index(&self) -> Result<u32, ServiceError> {
            self.state.borrow_mut().native_calls += 1;
            Ok(if self.slot == TunnelSlot::A { 10 } else { 20 })
        }
        fn start(
            &mut self,
            _: &ParsedConfiguration,
            _: &DesktopTunnelOptions,
        ) -> Result<ServiceTunnelState, ServiceError> {
            self.state.borrow_mut().native_calls += 1;
            Ok(ServiceTunnelState::Running)
        }
        fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            self.state.borrow_mut().native_calls += 1;
            Ok(ServiceTunnelState::Stopped)
        }
        fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
            Ok(ServiceTunnelState::Running)
        }
    }
    struct Resolver(Rc<RefCell<State>>);
    impl NetworkSystem for Resolver {
        fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
            let mut state = self.0.borrow_mut();
            state.native_calls += 1;
            Ok(state.values.get(key).cloned())
        }
        fn compare_exchange(
            &mut self,
            key: &ResourceKey,
            before: Option<&NetworkValue>,
            after: Option<&NetworkValue>,
        ) -> io::Result<()> {
            let mut state = self.0.borrow_mut();
            state.native_calls += 1;
            assert_eq!(state.values.get(key), before);
            match after {
                Some(value) => {
                    state.values.insert(key.clone(), value.clone());
                }
                None => {
                    state.values.remove(key);
                }
            }
            Ok(())
        }
    }
    impl PhysicalPolicyProvider for Resolver {
        fn resolve_policy(
            &mut self,
            options: &DesktopTunnelOptions,
            endpoints: &[IpAddr],
            owned: &[IpNet],
        ) -> io::Result<NetworkPolicy> {
            let mut state = self.0.borrow_mut();
            state.queries.push(Query {
                options: options.clone(),
                endpoints: endpoints.to_vec(),
                owned: owned.to_vec(),
            });
            if state.fail_resolve {
                return Err(io::Error::other("private resolver path/details"));
            }
            Ok(NetworkPolicy {
                bypasses: endpoints.iter().map(|endpoint| bypass(*endpoint)).collect(),
                retained_routes: vec![],
                dns_services: vec![],
                metric: 10,
            })
        }
    }
    struct Store;
    impl NetworkJournalStore for Store {
        fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
            Ok(())
        }
    }
    type Pair = SessionNetwork<Backend, Resolver, Store>;
    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 7,
            session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
            connection_generation: 3,
        }
    }
    fn options() -> DesktopTunnelOptions {
        DesktopTunnelOptions {
            excluded_ipv4_cidrs: vec!["203.0.113.0/24".into()],
            exclude_local_networks: true,
            policy_hash: Some("authenticated-policy".into()),
        }
    }
    fn endpoint_a() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }
    fn endpoint_b() -> IpAddr {
        "198.51.100.1".parse().unwrap()
    }
    fn bypass(endpoint: IpAddr) -> RouteValue {
        RouteValue {
            destination: IpNet::from(endpoint),
            scope: RouteScope::Global,
            interface: 5,
            gateway: Some("192.0.2.254".parse().unwrap()),
            metric: 0,
        }
    }
    fn config(endpoint: IpAddr) -> ParsedConfiguration {
        parse_configuration(&format!("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}:51820\n")).unwrap()
    }
    fn probe() -> RedundantHealthProbe {
        RedundantHealthProbe {
            kind: HealthProbeKind::DnsA,
            target_ipv4: "9.9.9.9".parse().unwrap(),
            query_name: "health.example.net".into(),
            timeout_ms: 2000,
        }
    }
    fn setup() -> (Pair, Rc<RefCell<State>>) {
        let state = Rc::new(RefCell::new(State::default()));
        let backends = [TunnelSlot::A, TunnelSlot::B].map(|slot| Backend {
            slot,
            state: state.clone(),
        });
        let pair = Pair::new(scope(), backends, Resolver(state.clone()), Store).unwrap();
        (pair, state)
    }
    fn start(pair: &mut Pair) {
        let policy = pair
            .resolve_primary_policy(&scope(), &options(), endpoint_a())
            .unwrap();
        pair.start_primary(&scope(), Slot::A, &config(endpoint_a()), probe(), policy)
            .unwrap();
    }
    fn expected_owned(two_endpoints: bool) -> Vec<IpNet> {
        let mut values: Vec<IpNet> = [
            "0.0.0.0/1",
            "128.0.0.0/1",
            "::/1",
            "8000::/1",
            "9.9.9.9/32",
            "192.0.2.1/32",
        ]
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect();
        if two_endpoints {
            values.push("198.51.100.1/32".parse().unwrap());
        }
        values.sort();
        values
    }

    #[test]
    fn primary_preflight_is_read_only_and_forwards_all_options_without_adopting_ui_exclusions() {
        let (mut pair, state) = setup();
        let policy = pair
            .resolve_primary_policy(&scope(), &options(), endpoint_a())
            .unwrap();
        assert_eq!(
            state.borrow().queries,
            [Query {
                options: options(),
                endpoints: vec![endpoint_a()],
                owned: vec![]
            }]
        );
        assert_eq!(state.borrow().native_calls, 0);
        assert!(pair.active().is_none());
        assert!(pair.members().view(Slot::A).is_none());
        assert_eq!(policy.bypasses, [bypass(endpoint_a())]);
    }

    #[test]
    fn updated_discovery_uses_journal_routes_and_both_saved_endpoints_plus_candidate() {
        let (mut pair, state) = setup();
        start(&mut pair);
        state.borrow_mut().queries.clear();
        let before = state.borrow().native_calls;
        let policy = pair
            .resolve_updated_policy(&scope(), &options(), Some(endpoint_b()))
            .unwrap();
        assert_eq!(
            state.borrow().queries,
            [Query {
                options: options(),
                endpoints: vec![endpoint_a(), endpoint_b()],
                owned: expected_owned(false)
            }]
        );
        assert_eq!(state.borrow().native_calls, before);
        assert!(pair.members().view(Slot::B).is_none());
        let bypass = policy
            .bypasses
            .into_iter()
            .find(|r| r.destination == IpNet::from(endpoint_b()))
            .unwrap();
        pair.add_standby(&scope(), Slot::B, &config(endpoint_b()), probe(), bypass)
            .unwrap();
        state.borrow_mut().queries.clear();
        let before = state.borrow().native_calls;
        pair.resolve_updated_policy(&scope(), &options(), None)
            .unwrap();
        assert_eq!(
            state.borrow().queries,
            [Query {
                options: options(),
                endpoints: vec![endpoint_a(), endpoint_b()],
                owned: expected_owned(true)
            }]
        );
        assert_eq!(state.borrow().native_calls, before);
        // UI exclusions are passed as options; they never become ownership proof.
        assert!(!state.borrow().queries[0]
            .owned
            .contains(&"203.0.113.0/24".parse().unwrap()));
    }

    #[test]
    fn repeated_endpoints_are_deduplicated_and_removed_standby_is_not_reused() {
        let (mut pair, state) = setup();
        start(&mut pair);
        pair.add_standby(
            &scope(),
            Slot::B,
            &config(endpoint_a()),
            probe(),
            bypass(endpoint_a()),
        )
        .unwrap();
        state.borrow_mut().queries.clear();
        pair.resolve_updated_policy(&scope(), &options(), Some(endpoint_a()))
            .unwrap();
        assert_eq!(state.borrow().queries[0].endpoints, [endpoint_a()]);
        pair.remove_standby(&scope(), Slot::B).unwrap();
        pair.add_standby(
            &scope(),
            Slot::B,
            &config(endpoint_b()),
            probe(),
            bypass(endpoint_b()),
        )
        .unwrap();
        pair.remove_standby(&scope(), Slot::B).unwrap();
        state.borrow_mut().queries.clear();
        pair.resolve_updated_policy(&scope(), &options(), None)
            .unwrap();
        assert_eq!(state.borrow().queries[0].endpoints, [endpoint_a()]);
    }

    #[test]
    fn wrong_scope_closed_session_and_wrong_phase_are_rejected_before_resolver_query() {
        let (mut pair, state) = setup();
        let mut wrong = scope();
        wrong.connection_generation += 1;
        assert!(pair
            .resolve_primary_policy(&wrong, &options(), endpoint_a())
            .is_err());
        assert!(pair
            .resolve_updated_policy(&wrong, &options(), Some(endpoint_a()))
            .is_err());
        assert!(pair
            .resolve_updated_policy(&scope(), &options(), Some(endpoint_a()))
            .is_err());
        assert!(state.borrow().queries.is_empty());
        assert_eq!(state.borrow().native_calls, 0);
        start(&mut pair);
        state.borrow_mut().queries.clear();
        assert!(pair
            .resolve_primary_policy(&scope(), &options(), endpoint_a())
            .is_err());
        assert!(state.borrow().queries.is_empty());
        pair.close(&scope()).unwrap();
        let before = state.borrow().native_calls;
        assert!(pair
            .resolve_primary_policy(&scope(), &options(), endpoint_a())
            .is_err());
        assert!(pair
            .resolve_updated_policy(&scope(), &options(), None)
            .is_err());
        assert!(state.borrow().queries.is_empty());
        assert_eq!(state.borrow().native_calls, before);
    }

    #[test]
    fn invalid_options_and_too_many_distinct_endpoints_fail_before_queries() {
        let (mut pair, state) = setup();
        let mut bad = options();
        bad.policy_hash = None;
        assert!(pair
            .resolve_primary_policy(&scope(), &bad, endpoint_a())
            .is_err());
        assert!(state.borrow().queries.is_empty());
        start(&mut pair);
        pair.add_standby(
            &scope(),
            Slot::B,
            &config(endpoint_b()),
            probe(),
            bypass(endpoint_b()),
        )
        .unwrap();
        state.borrow_mut().queries.clear();
        assert!(pair
            .resolve_updated_policy(&scope(), &options(), Some("203.0.113.1".parse().unwrap()))
            .is_err());
        assert!(state.borrow().queries.is_empty());
    }

    #[test]
    fn resolver_error_is_redacted_and_leaves_session_unstarted() {
        let (mut pair, state) = setup();
        state.borrow_mut().fail_resolve = true;
        let error = pair
            .resolve_primary_policy(&scope(), &options(), endpoint_a())
            .unwrap_err();
        assert!(!error.to_string().contains("private resolver"));
        assert_eq!(state.borrow().native_calls, 0);
        assert!(pair.active().is_none());
        assert!(pair.members().view(Slot::A).is_none());
    }
}
