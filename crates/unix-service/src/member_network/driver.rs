//! Scoped bridge from Unix member/network ownership to the shared helper driver.
use super::diagnostic::{context, PairFailure, Stage};
use super::journal::ScopedJournal;
use super::session::SessionNetwork;
use crate::ServiceTunnelBackend;
use nelomai_client_tunnel::redundancy::{
    driver::{NativePair, SessionStore},
    evidence::NativeHealthSample,
    network::{NetworkJournalStore, NetworkSystem},
    session::SessionSnapshot,
    NativeProbeSocket, SessionScope, Slot,
};
use std::{
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

// Same wall-clock predicate as Android RedundantProductionAdapters.
const HANDSHAKE_FRESH_MS: u64 = 180_000;

pub struct SessionNativePair<B, N, S> {
    scope: SessionScope,
    network: SessionNetwork<B, N, S>,
    options: Option<nelomai_client_tunnel::DesktopTunnelOptions>,
}

impl<B: ServiceTunnelBackend, N: NetworkSystem, S: NetworkJournalStore> SessionNativePair<B, N, S> {
    pub fn new(scope: SessionScope, network: SessionNetwork<B, N, S>) -> io::Result<Self> {
        let pair = Self {
            scope,
            network,
            options: None,
        };
        pair.check_scope(&pair.scope)?;
        Ok(pair)
    }
    /// The privileged actor uses this for primary/standby installation and
    /// physical-network changes; SessionNetwork keeps its own lifecycle fences.
    pub fn network_mut(
        &mut self,
        scope: &SessionScope,
    ) -> io::Result<&mut SessionNetwork<B, N, S>> {
        self.check_scope(scope)?;
        Ok(&mut self.network)
    }
    fn check_scope(&self, scope: &SessionScope) -> io::Result<()> {
        self.network.begin_operation();
        if !self.scope.validate()
            || scope != &self.scope
            || self.network.members().scope() != &self.scope
        {
            return Err(failed());
        }
        Ok(())
    }
    fn sample_at(&self, slot: Slot, epoch_ms: u64) -> Option<NativeHealthSample> {
        self.check_scope(&self.scope).ok()?;
        // Retiring a standby binding can require cleanup while the active
        // member remains usable. Only closing/unresolved data routing fences it.
        self.network.active()?;
        let members = self.network.members();
        members.check_live(&self.scope, slot).ok()?;
        let metrics = members.metrics(&self.scope, slot).ok()?;
        let counters = members.data_counters(&self.scope, slot).ok()?;
        let handshake_fresh = metrics
            .latest_handshake_epoch_millis
            .filter(|time| *time > 0)
            .and_then(|time| epoch_ms.checked_sub(time))
            .is_some_and(|age| age <= HANDSHAKE_FRESH_MS);
        Some(NativeHealthSample {
            admitted: true,
            closed: false,
            handshake_fresh,
            tx_packets: counters.sent_packets,
            rx_data_packets: counters.received_packets,
        })
    }
    fn open_probe_with<T>(
        &self,
        slot: Slot,
        open: impl FnOnce(
            &super::members::SessionMembers<B>,
            &SessionScope,
            Slot,
        ) -> Result<T, crate::ServiceError>,
    ) -> io::Result<(T, String)> {
        self.check_scope(&self.scope)?;
        if self.network.active().is_none() {
            return Err(failed());
        }
        let members = self.network.members();
        members
            .check_live(&self.scope, slot)
            .map_err(|e| self.network.operation_error(Stage::Probe, e))?;
        let query_name = members
            .view(slot)
            .ok_or_else(failed)?
            .probe
            .query_name
            .clone();
        let socket = open(members, &self.scope, slot)
            .map_err(|e| self.network.operation_error(Stage::Probe, e))?;
        members
            .check_live(&self.scope, slot)
            .map_err(|e| self.network.operation_error(Stage::Probe, e))?;
        Ok((socket, query_name))
    }
}

impl<B: ServiceTunnelBackend, N: super::policy::PhysicalPolicyProvider, S: NetworkJournalStore>
    nelomai_client_tunnel::redundancy::control::PairControl for SessionNativePair<B, N, S>
{
    fn metrics(&self, slot: Slot) -> io::Result<nelomai_client_tunnel::TunnelMetrics> {
        self.check_scope(&self.scope)?;
        if self.network.active() != Some(slot) {
            return Err(failed());
        }
        self.network
            .members()
            .metrics(&self.scope, slot)
            .map_err(|e| self.network.operation_error(Stage::Metrics, e))
    }
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        self.check_scope(&self.scope)?;
        let active = self.network.active().ok_or_else(failed)?;
        self.network
            .members()
            .physical_network_fingerprint(&self.scope, active)
            .map_err(|e| self.network.operation_error(Stage::Fingerprint, e))
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        member: &nelomai_client_tunnel::redundancy::protocol::Member,
        options: &nelomai_client_tunnel::DesktopTunnelOptions,
    ) -> io::Result<()> {
        self.check_scope(scope)?;
        member
            .validate()
            .map_err(|e| context(Stage::Configuration, e))?;
        options.validate().map_err(|_| {
            PairFailure::service(Stage::Configuration, &crate::ServiceError::InvalidRequest)
                .into_io(Stage::Start)
        })?;
        if self.options.is_some() {
            return Err(failed());
        }
        let config = crate::parse_configuration(member.configuration.expose()).map_err(|_| {
            PairFailure::service(
                Stage::Configuration,
                &crate::ServiceError::InvalidConfiguration,
            )
            .into_io(Stage::Start)
        })?;
        let endpoint = member_endpoint(&config)?;
        let policy = self
            .network
            .resolve_primary_policy(scope, options, endpoint)
            .map_err(|e| self.network.operation_error(Stage::Start, e))?;
        // Preserve the options on a partially failed native Start for cleanup;
        // the enclosing control owner must not retry Start over these resources.
        self.options = Some(options.clone());
        self.network
            .start_primary(scope, member.slot, &config, member.probe.clone(), policy)
            .map_err(|e| self.network.operation_error(Stage::Start, e))
    }
    fn attach(
        &mut self,
        scope: &SessionScope,
        member: &nelomai_client_tunnel::redundancy::protocol::Member,
    ) -> io::Result<()> {
        self.check_scope(scope)?;
        member
            .validate()
            .map_err(|e| context(Stage::Configuration, e))?;
        let options = self.options.as_ref().ok_or_else(failed)?;
        let config = crate::parse_configuration(member.configuration.expose()).map_err(|_| {
            PairFailure::service(
                Stage::Configuration,
                &crate::ServiceError::InvalidConfiguration,
            )
            .into_io(Stage::Attach)
        })?;
        let endpoint = member_endpoint(&config)?;
        let policy = self
            .network
            .resolve_updated_policy(scope, options, Some(endpoint))
            .map_err(|e| self.network.operation_error(Stage::Attach, e))?;
        let bypass = policy
            .bypasses
            .iter()
            .chain(&policy.retained_routes)
            .find(|r| r.destination == ipnet::IpNet::from(endpoint))
            .cloned()
            .ok_or_else(failed)?;
        self.network
            .add_standby(scope, member.slot, &config, member.probe.clone(), bypass)
            .map_err(|e| self.network.operation_error(Stage::Attach, e))
    }
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.check_scope(scope)?;
        self.network
            .remove_standby(scope, slot)
            .map_err(|e| self.network.operation_error(Stage::RemoveStandby, e))
    }
    fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
        self.check_scope(scope)?;
        let options = self.options.as_ref().ok_or_else(failed)?;
        let policy = self
            .network
            .resolve_updated_policy(scope, options, None)
            .map_err(|e| self.network.operation_error(Stage::NetworkChanged, e))?;
        self.network
            .network_changed(scope, policy)
            .map_err(|e| self.network.operation_error(Stage::NetworkChanged, e))?;
        for slot in [Slot::A, Slot::B] {
            if self.network.members().view(slot).is_some() {
                self.network
                    .members()
                    .check_live(scope, slot)
                    .map_err(|e| self.network.operation_error(Stage::NetworkChanged, e))?;
            }
        }
        Ok(self.network.active().is_some())
    }
    fn cleanup_pending(&self) -> bool {
        self.network.cleanup_pending()
    }
}

fn member_endpoint(config: &crate::ParsedConfiguration) -> io::Result<std::net::IpAddr> {
    if config.peers.len() != 1 {
        return Err(failed());
    }
    config.peers[0]
        .endpoint
        .host()
        .parse()
        .map_err(|_| failed())
}

impl<B: ServiceTunnelBackend, N: NetworkSystem, S: NetworkJournalStore> NativePair
    for SessionNativePair<B, N, S>
{
    type Socket = NativeProbeSocket;
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        let epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis();
        self.sample_at(slot, u64::try_from(epoch_ms).ok()?)
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Self::Socket, String)> {
        self.open_probe_with(slot, |members, scope, slot| members.open_probe(scope, slot))
    }
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.check_scope(scope)?;
        self.network
            .select_active(scope, slot)
            .map_err(|e| self.network.operation_error(Stage::Network, e))
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.check_scope(scope)?;
        self.network
            .close(scope)
            .map_err(|e| self.network.operation_error(Stage::Stop, e))
    }
}

fn failed() -> io::Error {
    io::Error::other("member_pair_operation_failed")
}

const SESSION_FILE: &str = "redundant-state.json";

/// Root chooses the directory and scope. Seed a missing journal only here,
/// before returning it to SessionDriver. Reopening preserves the old snapshot;
/// the caller must pass that snapshot through SessionState::recover_for_cleanup.
pub fn open_session_store(
    root: &Path,
    scope: SessionScope,
    initial: &SessionSnapshot,
) -> io::Result<ScopedJournal<SessionSnapshot>> {
    open_session_store_for_owner(root, scope, initial, 0)
}

fn open_session_store_for_owner(
    root: &Path,
    scope: SessionScope,
    initial: &SessionSnapshot,
    uid: u32,
) -> io::Result<ScopedJournal<SessionSnapshot>> {
    if !scope.validate() || initial.scope != scope {
        return Err(journal_failed());
    }
    let mut store =
        ScopedJournal::<SessionSnapshot>::open_named(root, scope.clone(), uid, SESSION_FILE)
            .map_err(|e| context(Stage::SessionJournal, e))?;
    match store
        .load()
        .map_err(|e| context(Stage::SessionJournal, e))?
    {
        Some(saved) if saved.scope != scope => return Err(journal_failed()),
        Some(_) => (),
        None => store
            .save_state(initial)
            .map_err(|e| context(Stage::SessionJournal, e))?,
    }
    Ok(store)
}

impl SessionStore for ScopedJournal<SessionSnapshot> {
    fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()> {
        // The root constructor validated the initial inner scope against the
        // journal envelope. Preserve that anchor: a driver cannot select a new
        // scope, nor recreate a missing journal from its supplied snapshot.
        let previous = self
            .load()
            .map_err(|e| context(Stage::SessionJournal, e))?
            .ok_or_else(journal_failed)?;
        if !snapshot.scope.validate() || snapshot.scope != previous.scope {
            return Err(journal_failed());
        }
        self.save_state(snapshot)
            .map_err(|e| context(Stage::SessionJournal, e))
    }
}

fn journal_failed() -> io::Error {
    context(
        Stage::SessionJournal,
        io::Error::new(io::ErrorKind::InvalidData, "journal_invalid"),
    )
}

#[cfg(test)]
mod tests {
    mod physical {
        include!("physical_tests.rs");
    }
    use super::super::{counters::DataCounters, session::NetworkPolicy};
    use super::*;
    use crate::{parse_configuration, ParsedConfiguration, ServiceError, ServiceTunnelState};
    use nelomai_client_tunnel::redundancy::{control::PairControl, protocol::Member};
    use nelomai_client_tunnel::{redundancy::network::*, DesktopTunnelOptions, TunnelMetrics};
    use nelomai_contracts::{
        dispatcher::TunnelSlot, HealthProbeKind, RedundantHealthProbe, RuntimeSlot,
    };
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    const NOW: u64 = 1_000_000;
    #[derive(Default)]
    struct State {
        failure: Option<&'static str>,
        stop_incomplete_a: bool,
        calls: Vec<&'static str>,
        bad_identity: bool,
        bad_identity_slot: Option<TunnelSlot>,
        absent_slot: Option<TunnelSlot>,
        probe_tx: [u64; 2],
        probe_rx: [u64; 2],
        stopped_slots: Vec<TunnelSlot>,
        metric_slots: Vec<TunnelSlot>,
        fingerprint_slots: Vec<TunnelSlot>,
        replace_on_fingerprint: bool,
        fail_fingerprint: bool,
        fingerprint_override: Option<String>,
        fail_metrics: bool,
        fail_counters: bool,
        replace_on_metrics: bool,
        replace_on_counters: bool,
        fail_binding_release: bool,
        handshake: Option<u64>,
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
            let mut s = self.state.borrow_mut();
            s.calls.push("identity");
            if s.bad_identity
                || s.bad_identity_slot == Some(self.slot)
                || s.absent_slot == Some(self.slot)
            {
                return Err(ServiceError::Backend("secret native details".into()));
            }
            Ok(if self.slot == TunnelSlot::A { 10 } else { 20 })
        }
        fn member_data_counters(&self) -> Result<DataCounters, ServiceError> {
            let mut s = self.state.borrow_mut();
            s.calls.push("counters");
            if s.fail_counters {
                return Err(ServiceError::Backend("secret counter details".into()));
            }
            if s.replace_on_counters {
                s.bad_identity = true;
            }
            Ok(DataCounters {
                sent_packets: 7 + s.probe_tx[usize::from(self.slot == TunnelSlot::B)],
                received_packets: 11 + s.probe_rx[usize::from(self.slot == TunnelSlot::B)],
            })
        }
        fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
            assert!(!probe);
            let mut s = self.state.borrow_mut();
            s.calls.push("metrics");
            s.metric_slots.push(self.slot);
            if s.fail_metrics {
                return Err(ServiceError::Backend("secret metrics details".into()));
            }
            if s.replace_on_metrics {
                s.bad_identity = true;
            }
            Ok(TunnelMetrics {
                received_bytes: if self.slot == TunnelSlot::A {
                    9_000_000
                } else {
                    19_000_000
                },
                sent_bytes: 8_000_000,
                latest_handshake_epoch_millis: s.handshake,
                probe_target: Some("UI must not choose probe".into()),
            })
        }
        fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
            let mut s = self.state.borrow_mut();
            s.calls.push("fingerprint");
            s.fingerprint_slots.push(self.slot);
            if s.fail_fingerprint {
                return Err(ServiceError::Backend("private fingerprint detail".into()));
            }
            if s.replace_on_fingerprint {
                s.bad_identity_slot = Some(TunnelSlot::B);
            }
            Ok(s.fingerprint_override
                .clone()
                .unwrap_or_else(|| "ab".repeat(32)))
        }
        fn start(
            &mut self,
            _: &ParsedConfiguration,
            _: &DesktopTunnelOptions,
        ) -> Result<ServiceTunnelState, ServiceError> {
            self.state.borrow_mut().calls.push("start");
            if self.state.borrow().failure == Some("native") {
                return Err(ServiceError::Backend("wireguard_go_start_timeout".into()));
            }
            Ok(ServiceTunnelState::Running)
        }
        fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            let mut s = self.state.borrow_mut();
            s.calls.push("stop");
            if s.stop_incomplete_a && self.slot == TunnelSlot::A {
                return Ok(ServiceTunnelState::Stopping);
            }
            // Model the backend's exact ownership fence, including safe cleanup
            // of an absent owned member, but never a replacement interface.
            if s.bad_identity || s.bad_identity_slot == Some(self.slot) {
                return Err(ServiceError::Backend("foreign member".into()));
            }
            s.stopped_slots.push(self.slot);
            if s.absent_slot == Some(self.slot) {
                s.absent_slot = None;
            }
            Ok(ServiceTunnelState::Stopped)
        }
        fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
            Ok(ServiceTunnelState::Running)
        }
    }
    struct Network(Rc<RefCell<State>>);
    impl NetworkSystem for Network {
        fn member_stopped(&mut self, slot: Slot, interface: u32) -> io::Result<()> {
            assert_eq!((slot, interface), (Slot::B, 20));
            let mut state = self.0.borrow_mut();
            state.calls.push("release B binding");
            if state.fail_binding_release {
                return Err(io::Error::other("binding release failed"));
            }
            Ok(())
        }
        fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
            let mut s = self.0.borrow_mut();
            s.calls.push("read network");
            Ok(s.values.get(key).cloned())
        }
        fn compare_exchange(
            &mut self,
            key: &ResourceKey,
            before: Option<&NetworkValue>,
            after: Option<&NetworkValue>,
        ) -> io::Result<()> {
            let mut s = self.0.borrow_mut();
            s.calls.push("write network");
            let origin = if matches!(key, ResourceKey::Dns(_)) {
                "dns"
            } else {
                "route"
            };
            if s.failure == Some(origin) {
                return Err(io::Error::from_raw_os_error(13));
            }
            if s.values.get(key) != before {
                return Err(io::Error::other("foreign route"));
            }
            if let Some(value) = after {
                s.values.insert(key.clone(), value.clone());
            } else {
                s.values.remove(key);
            }
            Ok(())
        }
    }
    impl super::super::policy::PhysicalPolicyProvider for Network {
        fn resolve_policy(
            &mut self,
            _: &DesktopTunnelOptions,
            endpoints: &[std::net::IpAddr],
            _: &[ipnet::IpNet],
        ) -> io::Result<NetworkPolicy> {
            self.0.borrow_mut().calls.push("resolve");
            if self.0.borrow().failure == Some("policy") {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "PrivateKey=secret /private/path 192.0.2.1",
                ));
            }
            Ok(NetworkPolicy {
                bypasses: endpoints
                    .iter()
                    .map(|e| RouteValue {
                        destination: (*e).into(),
                        ..bypass()
                    })
                    .collect(),
                retained_routes: vec![],
                dns_services: vec!["private service".into()],
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

    struct DiagnosticStore(Rc<RefCell<State>>);
    impl NetworkJournalStore for DiagnosticStore {
        fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
            if self.0.borrow().failure == Some("journal") {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "PrivateKey=secret /private/path",
                ));
            }
            Ok(())
        }
    }

    type DiagnosticPair = SessionNativePair<Backend, Network, DiagnosticStore>;
    fn diagnostic_pair(state: &Rc<RefCell<State>>) -> DiagnosticPair {
        let backends = [TunnelSlot::A, TunnelSlot::B].map(|slot| Backend {
            slot,
            state: state.clone(),
        });
        let network = SessionNetwork::new(
            scope(),
            backends,
            Network(state.clone()),
            DiagnosticStore(state.clone()),
        )
        .unwrap();
        SessionNativePair::new(scope(), network).unwrap()
    }
    struct DiagnosticFactory {
        pair: Option<DiagnosticPair>,
        store: Option<ScopedJournal<SessionSnapshot>>,
    }
    impl super::super::actor::PairFactory for DiagnosticFactory {
        type Native = DiagnosticPair;
        type Store = ScopedJournal<SessionSnapshot>;
        fn recover(&mut self) -> Result<(), ServiceError> {
            Ok(())
        }
        fn prepare(
            &mut self,
            command: &nelomai_client_tunnel::redundancy::protocol::Command,
            now: u64,
        ) -> io::Result<
            nelomai_client_tunnel::redundancy::control::SessionControl<Self::Native, Self::Store>,
        > {
            nelomai_client_tunnel::redundancy::control::SessionControl::prepare(
                RuntimeSlot::Latest,
                command,
                self.pair.take().unwrap(),
                self.store.take().unwrap(),
                now,
            )
        }
    }
    struct Idle;
    impl ServiceTunnelBackend for Idle {
        fn start(
            &mut self,
            _: &ParsedConfiguration,
            _: &DesktopTunnelOptions,
        ) -> Result<ServiceTunnelState, ServiceError> {
            panic!("pair must not start ordinary backend")
        }
        fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            panic!("pair must not stop ordinary backend")
        }
        fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
            Ok(ServiceTunnelState::Stopped)
        }
    }

    #[test]
    fn diagnostic_propagation_distinguishes_native_policy_route_dns_and_journal() {
        for (injected, origin, cause, kind) in [
            (
                "native",
                "native_start",
                "native_timeout",
                io::ErrorKind::TimedOut,
            ),
            (
                "policy",
                "policy",
                "unsupported",
                io::ErrorKind::Unsupported,
            ),
            (
                "route",
                "route_apply",
                "permission_denied",
                io::ErrorKind::PermissionDenied,
            ),
            (
                "dns",
                "dns_apply",
                "permission_denied",
                io::ErrorKind::PermissionDenied,
            ),
            (
                "journal",
                "network_journal",
                "write_zero",
                io::ErrorKind::WriteZero,
            ),
        ] {
            let state = Rc::new(RefCell::new(State {
                failure: Some(injected),
                ..Default::default()
            }));
            let mut pair = diagnostic_pair(&state);
            let member = Member {
                slot: Slot::A,
                lease_id: "aaaaaaaa-0000-4000-8000-000000000001".into(),
                configuration: nelomai_client_tunnel::TunnelConfiguration::new("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n".into()),
                probe: probe(),
            };
            let error = pair
                .start_primary(&scope(), &member, &DesktopTunnelOptions::default())
                .unwrap_err();
            assert_eq!(error.kind(), kind, "{injected}");
            let text = error.to_string();
            assert!(
                text.contains(&format!("origin={origin}")),
                "{injected}: {text}"
            );
            assert!(
                text.contains(&format!("cause={cause}")),
                "{injected}: {text}"
            );
            if matches!(injected, "route" | "dns") {
                assert!(text.contains("native_status=Some(13)"), "{text}");
            }
            for secret in [
                "PrivateKey",
                "secret",
                "/private",
                "192.0.2",
                "private service",
            ] {
                assert!(!text.contains(secret), "{text}");
            }
            // A new operation must not inherit policy/native/network context.
            let mut wrong = scope();
            wrong.connection_generation += 1;
            let error = pair.select_active(&wrong, Slot::A).unwrap_err();
            assert!(!error.to_string().contains(&format!("origin={origin}")));
            state.borrow_mut().failure = None;
            pair.close(&scope()).unwrap();
            assert!(!pair.cleanup_pending());
            assert!(state.borrow().values.is_empty());

            // Repeat through the real shared coordinator and public actor, so
            // automatic cleanup cannot replace the initiating typed failure.
            use nelomai_client_tunnel::redundancy::protocol::Command;
            let state = Rc::new(RefCell::new(State {
                failure: Some(injected),
                ..Default::default()
            }));
            let dir = directory();
            let store = open_session_store_for_owner(dir.path(), scope(), &snapshot(), unsafe {
                libc::geteuid()
            })
            .unwrap();
            let factory = DiagnosticFactory {
                pair: Some(diagnostic_pair(&state)),
                store: Some(store),
            };
            let mut actor =
                super::super::actor::CompositeBackend::new(RuntimeSlot::Latest, Idle, factory)
                    .unwrap();
            let command = Command::Start {
                scope: scope(),
                primary: member,
                options: DesktopTunnelOptions::default(),
                role_generation: 1,
                membership_generation: 1,
                warm_stop_v1: true,
            };
            let error = actor.redundant(command).unwrap_err();
            assert_eq!(
                error,
                ServiceError::Backend("redundant_actor_failed".into())
            );
            assert_eq!(error.code(), "service_unavailable");
            let report: serde_json::Value =
                serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
            assert_eq!(report["failure"]["stage"], "start");
            assert_eq!(report["failure"]["origin"], origin);
            assert_eq!(report["failure"]["cause"], cause);
            assert_eq!(report["scope"]["connection_generation"], 3);
            assert!(report.to_string().len() < 1024);
            state.borrow_mut().failure = None;
            actor.redundant(Command::Stop { scope: scope() }).unwrap();
            let report: serde_json::Value =
                serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
            assert!(report["failure"].is_null());
            assert!(state.borrow().values.is_empty());
        }
    }

    #[test]
    fn cleanup_diagnostic_uses_returned_failure_and_never_leaks_into_next_operation() {
        let (mut pair, state) = setup();
        pair.network_mut(&scope())
            .unwrap()
            .add_standby(&scope(), Slot::B, &config(), probe(), bypass())
            .unwrap();
        state.borrow_mut().stop_incomplete_a = true;
        state.borrow_mut().bad_identity_slot = Some(TunnelSlot::B);
        state.borrow_mut().failure = Some("route");
        let error = pair.close(&scope()).unwrap_err().to_string();
        assert!(error.contains("origin=native_stop"), "{error}");
        assert!(error.contains("cause=native_incomplete"), "{error}");
        // The secondary cleanup error must be discarded, not reused for retry.
        state.borrow_mut().stop_incomplete_a = false;
        state.borrow_mut().bad_identity_slot = None;
        state.borrow_mut().failure = Some("route");
        let error = pair.close(&scope()).unwrap_err().to_string();
        assert!(error.contains("origin=route_apply"), "{error}");
        assert!(error.contains("native_status=Some(13)"), "{error}");
        state.borrow_mut().failure = None;
        pair.close(&scope()).unwrap();
        assert!(!pair.cleanup_pending());
        let error = pair
            .select_active(&scope(), Slot::A)
            .unwrap_err()
            .to_string();
        assert!(
            !error.contains("route_apply") && !error.contains("native_stop"),
            "{error}"
        );
    }
    type Pair = SessionNativePair<Backend, Network, Store>;
    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 7,
            session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
            connection_generation: 3,
        }
    }
    fn config() -> ParsedConfiguration {
        parse_configuration("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.1:51820\n").unwrap()
    }
    fn probe() -> RedundantHealthProbe {
        RedundantHealthProbe {
            kind: HealthProbeKind::DnsA,
            target_ipv4: "9.9.9.9".parse().unwrap(),
            query_name: "health.example.net".into(),
            timeout_ms: 2000,
        }
    }
    fn bypass() -> RouteValue {
        RouteValue {
            destination: "192.0.2.1/32".parse().unwrap(),
            scope: RouteScope::Global,
            interface: 5,
            gateway: Some("192.0.2.254".parse().unwrap()),
            metric: 0,
        }
    }
    fn setup() -> (Pair, Rc<RefCell<State>>) {
        let state = Rc::new(RefCell::new(State {
            handshake: Some(NOW - 1000),
            ..Default::default()
        }));
        let backends = [TunnelSlot::A, TunnelSlot::B].map(|slot| Backend {
            slot,
            state: state.clone(),
        });
        let mut network =
            SessionNetwork::new(scope(), backends, Network(state.clone()), Store).unwrap();
        network
            .start_primary(
                &scope(),
                Slot::A,
                &config(),
                probe(),
                NetworkPolicy {
                    bypasses: vec![bypass()],
                    retained_routes: vec![],
                    dns_services: vec![],
                    metric: 10,
                },
            )
            .unwrap();
        let pair = Pair::new(scope(), network).unwrap();
        state.borrow_mut().calls.clear();
        (pair, state)
    }

    fn command_member(slot: Slot) -> Member {
        Member { slot, lease_id: if slot==Slot::A {"72cc17e2-0000-4000-8000-000000000002"}else{"72cc17e2-0000-4000-8000-000000000003"}.into(), configuration: nelomai_client_tunnel::TunnelConfiguration::new("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.1:51820\n".into()), probe:probe() }
    }
    fn unstarted() -> (Pair, Rc<RefCell<State>>) {
        let state = Rc::new(RefCell::new(State::default()));
        let backends = [TunnelSlot::A, TunnelSlot::B].map(|slot| Backend {
            slot,
            state: state.clone(),
        });
        let network =
            SessionNetwork::new(scope(), backends, Network(state.clone()), Store).unwrap();
        (Pair::new(scope(), network).unwrap(), state)
    }
    #[test]
    fn control_bridge_starts_primary_attaches_reserve_and_removes_only_reserve() {
        let (mut pair, state) = unstarted();
        let options = DesktopTunnelOptions {
            policy_hash: Some("policy".into()),
            ..Default::default()
        };
        PairControl::start_primary(&mut pair, &scope(), &command_member(Slot::A), &options)
            .unwrap();
        assert_eq!(pair.network.active(), Some(Slot::A));
        assert!(pair.network.members().view(Slot::B).is_none());
        assert_eq!(
            state
                .borrow()
                .calls
                .iter()
                .filter(|c| **c == "start")
                .count(),
            1
        );
        PairControl::attach(&mut pair, &scope(), &command_member(Slot::B)).unwrap();
        assert_eq!(pair.network.active(), Some(Slot::A));
        assert!(pair.network.members().view(Slot::B).is_some());
        PairControl::remove_standby(&mut pair, &scope(), Slot::B).unwrap();
        assert_eq!(pair.network.active(), Some(Slot::A));
        assert!(pair.network.members().view(Slot::B).is_none());
        assert!(!PairControl::cleanup_pending(&pair));
    }
    #[test]
    fn control_bridge_rejects_wrong_scope_before_discovery_or_member_effects() {
        let (mut pair, state) = unstarted();
        let mut wrong = scope();
        wrong.connection_generation += 1;
        assert!(PairControl::start_primary(
            &mut pair,
            &wrong,
            &command_member(Slot::A),
            &DesktopTunnelOptions::default()
        )
        .is_err());
        assert!(PairControl::attach(&mut pair, &wrong, &command_member(Slot::B)).is_err());
        assert!(PairControl::remove_standby(&mut pair, &wrong, Slot::B).is_err());
        assert!(PairControl::rebind_pair(&mut pair, &wrong).is_err());
        assert!(state.borrow().calls.is_empty());
    }

    #[test]
    fn readonly_diagnostics_follow_native_active_and_never_probe_or_mutate() {
        let (mut pair, state) = setup();
        pair.network
            .add_standby(&scope(), Slot::B, &config(), probe(), bypass())
            .unwrap();
        state.borrow_mut().calls.clear();
        assert_eq!(
            PairControl::metrics(&pair, Slot::A).unwrap().received_bytes,
            9_000_000
        );
        assert_eq!(
            PairControl::physical_network_fingerprint(&pair).unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(state.borrow().metric_slots, [TunnelSlot::A]);
        assert_eq!(state.borrow().fingerprint_slots, [TunnelSlot::A]);
        assert!(state
            .borrow()
            .calls
            .iter()
            .all(|c| matches!(*c, "identity" | "metrics" | "fingerprint")));
        NativePair::select_active(&mut pair, &scope(), Slot::B).unwrap();
        state.borrow_mut().calls.clear();
        assert!(PairControl::metrics(&pair, Slot::A).is_err());
        assert_eq!(
            PairControl::metrics(&pair, Slot::B).unwrap().received_bytes,
            19_000_000
        );
        assert_eq!(
            PairControl::physical_network_fingerprint(&pair).unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(state.borrow().metric_slots, [TunnelSlot::A, TunnelSlot::B]);
        assert_eq!(
            state.borrow().fingerprint_slots,
            [TunnelSlot::A, TunnelSlot::B]
        );
        assert!(state
            .borrow()
            .calls
            .iter()
            .all(|c| matches!(*c, "identity" | "metrics" | "fingerprint")));
        NativePair::close(&mut pair, &scope()).unwrap();
        state.borrow_mut().calls.clear();
        assert!(PairControl::metrics(&pair, Slot::B).is_err());
        assert!(PairControl::physical_network_fingerprint(&pair).is_err());
        assert!(state.borrow().calls.is_empty());
    }

    #[test]
    fn physical_discovery_is_independent_of_member_identity_but_metrics_remain_fenced() {
        let (mut pair, state) = setup();
        pair.network
            .add_standby(&scope(), Slot::B, &config(), probe(), bypass())
            .unwrap();
        let mut wrong = scope();
        wrong.connection_generation += 1;
        state.borrow_mut().calls.clear();
        assert!(pair.network.members().metrics(&wrong, Slot::A).is_err());
        assert!(pair
            .network
            .members()
            .physical_network_fingerprint(&wrong, Slot::A)
            .is_err());
        assert!(state.borrow().calls.is_empty());
        state.borrow_mut().replace_on_metrics = true;
        assert!(PairControl::metrics(&pair, Slot::A).is_err());
        state.borrow_mut().replace_on_metrics = false;
        state.borrow_mut().bad_identity = false;
        state.borrow_mut().bad_identity_slot = Some(TunnelSlot::B);
        assert_eq!(
            PairControl::physical_network_fingerprint(&pair).unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(state.borrow().fingerprint_slots, [TunnelSlot::A]);
        let before = state.borrow().values.clone();
        assert!(NativePair::select_active(&mut pair, &scope(), Slot::B).is_err());
        assert!(PairControl::remove_standby(&mut pair, &scope(), Slot::B).is_err());
        assert_eq!(state.borrow().values, before);
        assert!(state.borrow().stopped_slots.is_empty());
        assert_eq!(pair.sample_at(Slot::B, NOW), None);
        assert!(pair
            .open_probe_with(Slot::B, |_, _, _| -> Result<(), ServiceError> {
                panic!("foreign member must never be probed")
            })
            .is_err());
        state.borrow_mut().bad_identity_slot = None;
        state.borrow_mut().replace_on_fingerprint = true;
        assert_eq!(
            PairControl::physical_network_fingerprint(&pair).unwrap(),
            "ab".repeat(32)
        );
        assert!(NativePair::select_active(&mut pair, &scope(), Slot::B).is_err());
        state.borrow_mut().bad_identity_slot = None;
        state.borrow_mut().replace_on_fingerprint = false;
        state.borrow_mut().fail_fingerprint = true;
        assert!(PairControl::physical_network_fingerprint(&pair).is_err());
    }

    #[test]
    fn fingerprint_failure_or_invalid_payload_never_becomes_an_empty_success() {
        let (pair, state) = setup();
        for invalid in [
            String::new(),
            "a".repeat(63),
            "AB".repeat(32),
            "z".repeat(64),
        ] {
            state.borrow_mut().fingerprint_override = Some(invalid);
            assert!(PairControl::physical_network_fingerprint(&pair).is_err());
        }
        state.borrow_mut().fingerprint_override = None;
        state.borrow_mut().fail_fingerprint = true;
        assert!(PairControl::physical_network_fingerprint(&pair).is_err());
        assert!(state
            .borrow()
            .calls
            .iter()
            .all(|c| matches!(*c, "identity" | "fingerprint")));
    }

    #[test]
    fn sample_uses_plaintext_packet_counters_and_fresh_native_handshake() {
        let (pair, state) = setup();
        assert_eq!(
            pair.sample_at(Slot::A, NOW),
            Some(NativeHealthSample {
                admitted: true,
                closed: false,
                handshake_fresh: true,
                tx_packets: 7,
                rx_data_packets: 11,
            })
        );
        assert!(state.borrow().calls.contains(&"metrics"));
        assert!(state.borrow().calls.contains(&"counters"));
        assert_eq!(pair.sample_at(Slot::B, NOW), None);
    }
    #[test]
    fn unavailable_identity_metrics_or_counters_never_produce_a_health_sample() {
        for failure in 0..5 {
            let (pair, state) = setup();
            match failure {
                0 => state.borrow_mut().bad_identity = true,
                1 => state.borrow_mut().fail_metrics = true,
                2 => state.borrow_mut().fail_counters = true,
                3 => state.borrow_mut().replace_on_metrics = true,
                _ => state.borrow_mut().replace_on_counters = true,
            }
            assert_eq!(pair.sample_at(Slot::A, NOW), None);
            let calls = &state.borrow().calls;
            if failure == 0 {
                assert!(!calls.contains(&"metrics") && !calls.contains(&"counters"));
            }
            if failure == 1 || failure == 3 {
                assert!(!calls.contains(&"counters"));
            }
        }
    }
    #[test]
    fn members_counter_read_is_fenced_before_and_after_native_read() {
        let (pair, state) = setup();
        let mut wrong = scope();
        wrong.connection_generation += 1;
        assert!(pair
            .network
            .members()
            .data_counters(&wrong, Slot::A)
            .is_err());
        assert!(state.borrow().calls.is_empty());
        assert!(pair
            .network
            .members()
            .data_counters(&scope(), Slot::B)
            .is_err());
        assert!(!state.borrow().calls.contains(&"counters"));
        state.borrow_mut().replace_on_counters = true;
        assert!(pair
            .network
            .members()
            .data_counters(&scope(), Slot::A)
            .is_err());
        assert_eq!(state.borrow().calls, ["identity", "counters", "identity"]);
    }
    #[test]
    fn handshake_freshness_matches_android_and_rejects_future_or_missing_time() {
        let (pair, state) = setup();
        for (time, fresh) in [
            (None, false),
            (Some(0), false),
            (Some(NOW + 1), false),
            (Some(NOW - 180_000), true),
            (Some(NOW - 180_001), false),
        ] {
            state.borrow_mut().handshake = time;
            assert_eq!(pair.sample_at(Slot::A, NOW).unwrap().handshake_fresh, fresh);
        }
    }
    #[test]
    fn wrapper_scope_is_checked_before_selection_close_or_mutable_access() {
        let (mut pair, state) = setup();
        let mut wrong = scope();
        wrong.connection_generation += 1;
        assert!(pair.network_mut(&wrong).is_err());
        assert!(pair.select_active(&wrong, Slot::A).is_err());
        assert!(pair.close(&wrong).is_err());
        assert!(state.borrow().calls.is_empty());
        // Also guard against a mismatched inner SessionNetwork after replacement.
        pair.scope = wrong;
        assert!(pair.select_active(&scope(), Slot::A).is_err());
        assert!(pair.close(&scope()).is_err());
        assert!(pair.sample_at(Slot::A, NOW).is_none());
        assert!(state.borrow().calls.is_empty());
    }
    #[test]
    fn constructor_rejects_mismatched_scope_without_native_calls() {
        let (pair, state) = setup();
        let mut wrong = scope();
        wrong.runtime_generation += 1;
        assert!(Pair::new(wrong, pair.network).is_err());
        assert!(state.borrow().calls.is_empty());
    }
    #[test]
    fn selection_and_close_use_the_existing_network_owner() {
        let (mut pair, state) = setup();
        pair.network_mut(&scope())
            .unwrap()
            .add_standby(&scope(), Slot::B, &config(), probe(), bypass())
            .unwrap();
        pair.select_active(&scope(), Slot::B).unwrap();
        assert_eq!(pair.network.active(), Some(Slot::B));
        pair.close(&scope()).unwrap();
        assert!(state.borrow().values.is_empty());
        assert!(pair.sample_at(Slot::A, NOW).is_none());
        assert!(pair.sample_at(Slot::B, NOW).is_none());
    }

    #[test]
    fn failed_retired_b_binding_release_keeps_a_sample_and_probe_available() {
        let (mut pair, state) = setup();
        pair.network_mut(&scope())
            .unwrap()
            .add_standby(&scope(), Slot::B, &config(), probe(), bypass())
            .unwrap();
        state.borrow_mut().fail_binding_release = true;
        assert!(pair
            .network_mut(&scope())
            .unwrap()
            .remove_standby(&scope(), Slot::B)
            .is_err());
        assert!(pair.network.cleanup_pending());
        assert_eq!(pair.network.active(), Some(Slot::A));
        assert!(pair.network.members().view(Slot::B).is_none());
        assert_eq!(
            pair.sample_at(Slot::A, NOW),
            Some(NativeHealthSample {
                admitted: true,
                closed: false,
                handshake_fresh: true,
                tx_packets: 7,
                rx_data_packets: 11,
            })
        );
        let (_, name) = pair
            .open_probe_with(Slot::A, |members, selected, slot| {
                assert_eq!(selected, &scope());
                assert_eq!(slot, Slot::A);
                assert_eq!(members.view(slot).unwrap().routes.interface, 10);
                Ok(())
            })
            .unwrap();
        assert_eq!(name, "health.example.net");
        assert!(pair.sample_at(Slot::B, NOW).is_none());
        assert!(pair
            .open_probe_with::<()>(Slot::B, |_, _, _| panic!("retired B socket"))
            .is_err());
        state.borrow_mut().fail_binding_release = false;
        pair.network_mut(&scope())
            .unwrap()
            .remove_standby(&scope(), Slot::B)
            .unwrap();
        assert!(!pair.network.cleanup_pending());
        assert_eq!(pair.network.active(), Some(Slot::A));
    }
    #[test]
    fn probe_uses_contract_query_and_checks_ownership_around_socket_open() {
        let (pair, state) = setup();
        let ((), query) = pair
            .open_probe_with(Slot::A, |members, selected, slot| {
                assert_eq!(selected, &scope());
                assert_eq!(slot, Slot::A);
                assert_eq!(
                    members.view(slot).unwrap().probe.target_ipv4.to_string(),
                    "9.9.9.9"
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(query, "health.example.net");
        assert!(pair
            .open_probe_with(Slot::A, |_, _, _| {
                state.borrow_mut().bad_identity = true;
                Ok(())
            })
            .is_err());
        assert!(pair
            .open_probe_with::<()>(Slot::A, |_, _, _| panic!("foreign socket"))
            .is_err());
    }
    #[test]
    fn native_errors_are_generic_and_do_not_expose_details() {
        let (mut pair, state) = setup();
        state.borrow_mut().bad_identity = true;
        let error = pair.select_active(&scope(), Slot::A).unwrap_err();
        assert!(!error.to_string().contains("secret"));
        let error = pair
            .open_probe_with::<()>(Slot::A, |_, _, _| {
                Err(ServiceError::Backend("secret".into()))
            })
            .unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn probe_io_failure_keeps_errno_kind_and_existing_service_error() {
        let (pair, _) = setup();
        let error = pair
            .open_probe_with::<()>(Slot::A, |members, _, _| {
                let error = members.probe_error(io::Error::from_raw_os_error(13));
                assert_eq!(
                    error,
                    ServiceError::Backend("member_probe_socket_failed".into())
                );
                assert_eq!(error.code(), "service_unavailable");
                Err(error)
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let report = error.to_string();
        assert!(report.contains("origin=probe"), "{report}");
        assert!(report.contains("native_status=Some(13)"), "{report}");
    }

    fn snapshot() -> SessionSnapshot {
        use nelomai_client_tunnel::redundancy::session::{SessionPhase, SessionState};
        let mut state = SessionState::new(scope(), Slot::A, 1, 1).unwrap();
        state.primary_started(&scope()).unwrap();
        assert_eq!(state.snapshot().phase, SessionPhase::Running);
        state.snapshot()
    }
    fn directory() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn journal_scope_is_selected_before_first_write_and_mismatched_save_is_rejected() {
        let dir = directory();
        let uid = unsafe { libc::geteuid() };
        let mut wrong = snapshot();
        wrong.scope.connection_generation += 1;
        assert!(open_session_store_for_owner(dir.path(), scope(), &wrong, uid).is_err());
        assert!(!dir.path().join(SESSION_FILE).exists());
        let mut store =
            open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).unwrap();
        let original = std::fs::read(dir.path().join(SESSION_FILE)).unwrap();
        assert!(SessionStore::save(&mut store, &wrong).is_err());
        assert_eq!(
            std::fs::read(dir.path().join(SESSION_FILE)).unwrap(),
            original
        );
        assert_eq!(store.load().unwrap(), Some(snapshot()));
    }

    #[test]
    fn factory_boot_journal_and_driver_state_coexist_and_reopen_independently() {
        use super::super::factory::SessionDirectory;
        let dir = directory();
        let uid = unsafe { libc::geteuid() };
        let directory = SessionDirectory::open(dir.path(), scope(), "boot-one", uid).unwrap();
        assert!(!directory.recovering);
        let boot_before = std::fs::read(dir.path().join("redundant-session.json")).unwrap();
        let mut store =
            open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).unwrap();
        let mut stopped = snapshot();
        stopped.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped;
        stopped.installed = [false, false];
        SessionStore::save(&mut store, &stopped).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("redundant-session.json")).unwrap(),
            boot_before
        );
        assert!(dir.path().join("redundant-state.json").is_file());
        assert!(
            SessionDirectory::open(dir.path(), scope(), "boot-one", uid)
                .unwrap()
                .recovering
        );
        let reopened = open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).unwrap();
        assert_eq!(reopened.load().unwrap(), Some(stopped));
        assert!(SessionDirectory::open(dir.path(), scope(), "boot-two", uid).is_err());
    }
    #[test]
    fn session_journal_preserves_existing_snapshot_and_validates_root_and_inner_scope() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = directory();
        let uid = unsafe { libc::geteuid() };
        assert!(open_session_store_for_owner(
            dir.path(),
            scope(),
            &snapshot(),
            uid.wrapping_add(1)
        )
        .is_err());
        let mut store =
            open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).unwrap();
        let mut stopping = snapshot();
        stopping.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Stopping;
        SessionStore::save(&mut store, &stopping).unwrap();
        let reopened = open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).unwrap();
        assert_eq!(reopened.load().unwrap(), Some(stopping));
        assert_eq!(
            std::fs::metadata(dir.path().join(SESSION_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        if uid != 0 {
            assert!(open_session_store(dir.path(), scope(), &snapshot()).is_err());
        }
        let mut corrupt = snapshot();
        corrupt.scope.runtime_generation += 1;
        store.save_state(&corrupt).unwrap(); // Simulate an invalid old inner snapshot.
        assert!(open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).is_err());
    }
    #[test]
    fn missing_session_journal_cannot_be_reseeded_by_an_arbitrary_snapshot_save() {
        let dir = directory();
        let uid = unsafe { libc::geteuid() };
        let mut store =
            open_session_store_for_owner(dir.path(), scope(), &snapshot(), uid).unwrap();
        std::fs::rename(dir.path().join(SESSION_FILE), dir.path().join("saved.json")).unwrap();
        assert!(SessionStore::save(&mut store, &snapshot()).is_err());
        assert!(!dir.path().join(SESSION_FILE).exists());
        let raw =
            ScopedJournal::<SessionSnapshot>::open_named(dir.path(), scope(), uid, SESSION_FILE)
                .unwrap();
        let mut raw = raw;
        assert!(SessionStore::save(&mut raw, &snapshot()).is_err());
    }
    #[test]
    fn journal_failures_do_not_expose_paths_or_os_details() {
        let dir = directory();
        let error = match open_session_store_for_owner(
            &dir.path().join("secret-path"),
            scope(),
            &snapshot(),
            unsafe { libc::geteuid() },
        ) {
            Ok(_) => panic!("missing root accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let report = error.to_string();
        assert!(report.contains("origin=session_journal"));
        assert!(report.contains("cause=not_found"));
        assert!(
            !report.contains("secret-path") && !report.contains(&dir.path().display().to_string())
        );
    }
}
