//! Local serialized owner. Construction alone does not enable redundancy or
//! wire a native factory into the dispatcher.
use super::diagnostic::{context, PairFailure, Stage};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use nelomai_client_tunnel::{
    redundancy::{
        control::{PairControl, SessionControl},
        driver::SessionStore,
        protocol::{Command, Snapshot},
        session::SessionPhase,
    },
    DesktopTunnelOptions, TunnelMetrics,
};
use nelomai_contracts::RuntimeSlot;
use std::io;

#[derive(serde::Serialize)]
struct OperationDiagnostic {
    operation_id: u64,
    operation: Stage,
    scope: nelomai_client_tunnel::redundancy::SessionScope,
    failure: Option<PairFailure>,
}

fn record_tick_failure(
    report: &mut Option<OperationDiagnostic>,
    operation_id: &mut u64,
    scope: nelomai_client_tunnel::redundancy::SessionScope,
    error: io::Error,
) {
    *operation_id = operation_id.saturating_add(1);
    *report = Some(OperationDiagnostic {
        operation_id: *operation_id,
        operation: Stage::Tick,
        scope,
        failure: Some(PairFailure::io(Stage::Tick, error)),
    });
}

fn command_stage(command: &Command) -> Stage {
    match command {
        Command::Start { .. } => Stage::Start,
        Command::Stop { .. } => Stage::Stop,
        Command::Status { .. } => Stage::Status,
        Command::PrepareStop { .. } => Stage::PrepareStop,
        Command::PrepareRecoveryStop { .. } => Stage::PrepareRecoveryStop,
        Command::Attach { .. } => Stage::Attach,
        Command::StageCandidate { .. } => Stage::CandidateStaging,
        Command::RetireInactive { .. } => Stage::RetireInactive,
        Command::RemoveStandby { .. } => Stage::RemoveStandby,
        Command::CommitCandidate { .. } => Stage::CommitCandidate,
        Command::ConfirmRole { .. } => Stage::ConfirmRole,
        Command::NetworkChanged { .. } => Stage::NetworkChanged,
    }
}

const PHYSICAL_SAMPLE_MS: u64 = 2_000;

pub trait PairFactory {
    type Native: PairControl;
    type Store: SessionStore;

    /// Cleanup-only recovery of the factory's durable directory. Never resume
    /// old health or adopt foreign resources. Failure prevents actor creation.
    fn recover(&mut self) -> Result<(), ServiceError>;

    /// Seal Starting without launching a native member. On error, no native
    /// ownership may escape this call. Reject any reused durable scope. Runtime
    /// comes from the authenticated actor, not an untrusted request selection.
    fn prepare(
        &mut self,
        command: &Command,
        now: u64,
    ) -> io::Result<SessionControl<Self::Native, Self::Store>>;
}

pub struct CompositeBackend<B, F: PairFactory> {
    single: B,
    factory: F,
    runtime: RuntimeSlot,
    pair: Option<SessionControl<F::Native, F::Store>>,
    snapshot: Option<Snapshot>,
    now: u64,
    physical_fingerprint: Option<String>,
    next_physical_sample: u64,
    operation_id: u64,
    diagnostic: Option<OperationDiagnostic>,
}

impl<B: ServiceTunnelBackend, F: PairFactory> CompositeBackend<B, F> {
    pub fn new(runtime: RuntimeSlot, single: B, mut factory: F) -> Result<Self, ServiceError> {
        factory.recover().map_err(|_| failed())?;
        Ok(Self {
            single,
            factory,
            runtime,
            pair: None,
            snapshot: None,
            now: 0,
            physical_fingerprint: None,
            next_physical_sample: 0,
            operation_id: 0,
            diagnostic: None,
        })
    }

    fn refresh(&mut self) {
        self.snapshot = self.pair.as_mut().map(SessionControl::snapshot);
        if self
            .snapshot
            .as_ref()
            .is_none_or(|s| s.session.phase != SessionPhase::Running)
        {
            self.physical_fingerprint = None;
            self.next_physical_sample = self.now;
        }
    }

    fn pair_blocks_single(&mut self) -> bool {
        self.refresh();
        self.snapshot.as_ref().is_some_and(|s| !terminal(s))
    }

    /// Serialized with commands, before driver health polling. No additional
    /// debounce: NetworkChanged owns the existing four-second health grace.
    fn poll_physical(&mut self, now: u64) -> io::Result<()> {
        let Some(pair) = self.pair.as_mut() else {
            return Ok(());
        };
        let snapshot = pair.snapshot();
        if snapshot.session.phase != SessionPhase::Running {
            self.physical_fingerprint = None;
            self.next_physical_sample = now;
            return Ok(());
        }
        if now < self.next_physical_sample {
            return Ok(());
        }
        self.next_physical_sample = now.saturating_add(PHYSICAL_SAMPLE_MS);
        let fingerprint = pair.physical_network_fingerprint().and_then(|value| {
            if value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                Ok(value)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid_physical_fingerprint",
                ))
            }
        });
        match fingerprint {
            Err(error)
                if error.kind() == io::ErrorKind::Unsupported
                    && self.physical_fingerprint.is_none()
                    && pair.network_validated() =>
            {
                // Optional hook has never supplied evidence. Preserve existing
                // unsupported platform/fake behavior, not a lost working provider.
                Ok(())
            }
            Err(error) => {
                // Only discovery errors enter here, never DNS probe outcomes.
                // Repeated failures keep the same invalid epoch until retry.
                record_tick_failure(
                    &mut self.diagnostic,
                    &mut self.operation_id,
                    snapshot.session.scope.clone(),
                    context(Stage::Fingerprint, error),
                );
                if pair.network_validated() {
                    pair.invalidate_network(&snapshot.session.scope, now)?;
                }
                Ok(())
            }
            Ok(value) => {
                let changed = self
                    .physical_fingerprint
                    .as_ref()
                    .is_some_and(|old| old != &value);
                if changed || !pair.network_validated() {
                    let result = pair.execute(
                        Command::NetworkChanged {
                            scope: snapshot.session.scope.clone(),
                        },
                        now,
                    );
                    if let Err(error) = result {
                        // Native rebind failure leaves evidence suspended; do
                        // not make the engine loop shut down for one transient
                        // discovery/rebind error. Durable fencing/stop errors
                        // still propagate instead of pretending Running.
                        if pair.snapshot().session.phase != SessionPhase::Running
                            || pair.network_validated()
                        {
                            return Err(error);
                        }
                        record_tick_failure(
                            &mut self.diagnostic,
                            &mut self.operation_id,
                            snapshot.session.scope.clone(),
                            context(Stage::NetworkChanged, error),
                        );
                        return Ok(());
                    }
                    if !pair.network_validated() {
                        return Ok(());
                    }
                }
                self.physical_fingerprint = Some(value);
                Ok(())
            }
        }
    }
}

impl<B: ServiceTunnelBackend, F: PairFactory> ServiceTunnelBackend for CompositeBackend<B, F> {
    fn supports_redundancy(&self) -> bool {
        true
    }
    fn current_redundancy_snapshot(&self) -> Option<Snapshot> {
        self.snapshot.clone()
    }
    fn redundant(&mut self, command: Command) -> Result<Snapshot, ServiceError> {
        command
            .validate(self.runtime)
            .map_err(|_| ServiceError::InvalidRequest)?;
        let stage = command_stage(&command);
        let scope = command.scope().clone();
        // Read-only Status must not erase the failure it is observing.
        if stage != Stage::Status {
            self.operation_id = self.operation_id.saturating_add(1);
            self.diagnostic = Some(OperationDiagnostic {
                operation_id: self.operation_id,
                operation: stage,
                scope: scope.clone(),
                failure: None,
            });
        }
        self.refresh();
        let mut preflight_error = None;
        let result: io::Result<Snapshot> = (|| {
            if let Command::Start {
                primary, options, ..
            } = &command
            {
                if self
                    .snapshot
                    .as_ref()
                    .is_some_and(|s| !terminal(s) || &s.session.scope == command.scope())
                {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "start_fenced"));
                }
                if self.single.status().map_err(|e| {
                    let safe = PairFailure::service(Stage::Prepare, &e).into_io(stage);
                    preflight_error = Some(e);
                    safe
                })? != ServiceTunnelState::Stopped
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "single_running",
                    ));
                }
                let pair = self
                    .factory
                    .prepare(&command, self.now)
                    .map_err(|e| context(Stage::Prepare, e))?;
                // Retain ownership even if native Start fails after allocation.
                self.pair = Some(pair);
                self.physical_fingerprint = None;
                self.next_physical_sample = self.now;
                self.pair
                    .as_mut()
                    .expect("prepared pair")
                    .start_primary(primary, options)
            } else {
                self.pair
                    .as_mut()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing_pair"))?
                    .execute(command, self.now)
            }
        })();
        self.refresh();
        result.map_err(|error| {
            if stage != Stage::Status {
                self.diagnostic
                    .as_mut()
                    .expect("operation initialized")
                    .failure = Some(PairFailure::io(stage, error));
            }
            preflight_error.unwrap_or_else(failed)
        })
    }
    fn tick(&mut self, now: u64) -> Result<(), ServiceError> {
        let backwards = now < self.now;
        self.now = now;
        if self.pair.is_some() {
            // Let the driver enforce its existing backwards-clock fence before
            // doing any discovery/rebind against a regressed time.
            let result = (|| {
                if !backwards {
                    self.poll_physical(now)?;
                }
                self.pair
                    .as_mut()
                    .expect("pair retained during poll")
                    .tick(now)
            })();
            self.refresh();
            result.map(|_| ()).map_err(|error| {
                if let Some(snapshot) = &self.snapshot {
                    self.operation_id = self.operation_id.saturating_add(1);
                    self.diagnostic = Some(OperationDiagnostic {
                        operation_id: self.operation_id,
                        operation: Stage::Tick,
                        scope: snapshot.session.scope.clone(),
                        failure: Some(PairFailure::io(Stage::Tick, error)),
                    });
                }
                failed()
            })
        } else {
            self.single.tick(now)
        }
    }
    fn shutdown(&mut self) -> Result<(), ServiceError> {
        self.refresh();
        let Some(snapshot) = self.snapshot.as_ref() else {
            return self.single.shutdown();
        };
        let command = Command::Stop {
            scope: snapshot.session.scope.clone(),
        };
        let snapshot = self.redundant(command)?;
        if terminal(&snapshot) {
            Ok(())
        } else {
            Err(failed())
        }
    }
    fn start(
        &mut self,
        config: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        if self.pair_blocks_single() {
            return Err(failed());
        }
        // A clean terminal pair may yield to ordinary mode. Drop its cached
        // status before Start so a partial single Start is still single-owned.
        self.pair = None;
        self.snapshot = None;
        self.diagnostic = None;
        self.physical_fingerprint = None;
        self.next_physical_sample = self.now;
        self.single.start(config, options)
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        if self.pair_blocks_single() {
            return Err(failed());
        }
        if self.pair.is_some() {
            return Ok(ServiceTunnelState::Stopped);
        }
        self.single.stop()
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        if let Some(snapshot) = &self.snapshot {
            return Ok(if snapshot.cleanup_pending {
                ServiceTunnelState::Stopping
            } else {
                match snapshot.session.phase {
                    SessionPhase::Starting => ServiceTunnelState::Starting,
                    SessionPhase::Running if snapshot.primary_ready => ServiceTunnelState::Running,
                    SessionPhase::Running => ServiceTunnelState::Starting,
                    SessionPhase::Stopping => ServiceTunnelState::Stopping,
                    SessionPhase::Stopped => ServiceTunnelState::Stopped,
                }
            });
        }
        self.single.status()
    }
    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        if let Some(pair) = &self.pair {
            // Pair probes belong exclusively to the helper tick scheduler.
            return pair.metrics().map_err(|_| failed());
        }
        self.single.metrics(probe)
    }
    fn diagnostics(&self) -> Result<String, ServiceError> {
        if let Some(report) = &self.diagnostic {
            return serde_json::to_string(report).map_err(|_| failed());
        }
        self.single.diagnostics()
    }
    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        if let Some(pair) = &self.pair {
            return pair.physical_network_fingerprint().map_err(|_| failed());
        }
        self.single.physical_network_fingerprint()
    }
    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        if self.pair.is_some() {
            return Err(unsupported());
        }
        self.single.rebind_udp()
    }
}

fn terminal(snapshot: &Snapshot) -> bool {
    snapshot.session.phase == SessionPhase::Stopped && !snapshot.cleanup_pending
}

fn unsupported() -> ServiceError {
    ServiceError::Backend("redundant_operation_unsupported".into())
}

fn failed() -> ServiceError {
    ServiceError::Backend("redundant_actor_failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_configuration;
    use nelomai_client_tunnel::{
        redundancy::{
            driver::NativePair, evidence::NativeHealthSample, protocol::Member,
            session::SessionSnapshot, ProbeDatagram, SessionScope, Slot,
        },
        TunnelConfiguration,
    };
    use nelomai_contracts::{HealthProbeKind, RedundantHealthProbe};
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct World {
        events: Vec<String>,
        single: ServiceTunnelState,
        fail_status: bool,
        status_error: Option<ServiceError>,
        fail_prepare: bool,
        fail_recover: bool,
        fail_start: bool,
        fail_close: bool,
        residual_cleanup: bool,
        pending: bool,
        saved: Vec<SessionSnapshot>,
        closed_scopes: Vec<SessionScope>,
        prepared_at: Vec<u64>,
        fail_diagnostics: bool,
        fingerprint: Option<String>,
        fingerprint_unsupported: bool,
        fail_rebind: bool,
        unvalidated_rebind: bool,
        rebind_scopes: Vec<SessionScope>,
        fail_save: bool,
    }
    type Shared = Rc<RefCell<World>>;
    struct Single(Shared);
    impl ServiceTunnelBackend for Single {
        fn start(
            &mut self,
            _: &ParsedConfiguration,
            _: &DesktopTunnelOptions,
        ) -> Result<ServiceTunnelState, ServiceError> {
            let mut w = self.0.borrow_mut();
            w.events.push("single start".into());
            w.single = ServiceTunnelState::Running;
            Ok(w.single)
        }
        fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            let mut w = self.0.borrow_mut();
            w.events.push("single stop".into());
            w.single = ServiceTunnelState::Stopped;
            Ok(w.single)
        }
        fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
            let mut w = self.0.borrow_mut();
            w.events.push("single status".into());
            if let Some(error) = &w.status_error {
                return Err(error.clone());
            }
            if w.fail_status {
                Err(failed())
            } else {
                Ok(w.single)
            }
        }
        fn metrics(&self, _: bool) -> Result<TunnelMetrics, ServiceError> {
            self.0.borrow_mut().events.push("single metrics".into());
            Err(failed())
        }
        fn diagnostics(&self) -> Result<String, ServiceError> {
            self.0.borrow_mut().events.push("single diagnostics".into());
            Ok("single diagnostics".into())
        }
        fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
            self.0.borrow_mut().events.push("single fingerprint".into());
            Ok("physical".into())
        }
        fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            self.0.borrow_mut().events.push("single rebind".into());
            Ok(ServiceTunnelState::Running)
        }
        fn tick(&mut self, _: u64) -> Result<(), ServiceError> {
            self.0.borrow_mut().events.push("single tick".into());
            Ok(())
        }
        fn shutdown(&mut self) -> Result<(), ServiceError> {
            self.0.borrow_mut().events.push("single shutdown".into());
            self.stop().map(|_| ())
        }
    }
    struct Socket(Shared);
    impl Drop for Socket {
        fn drop(&mut self) {
            self.0.borrow_mut().events.push("cancel probe".into());
        }
    }
    impl ProbeDatagram for Socket {
        fn send(&mut self, p: &[u8]) -> io::Result<usize> {
            Ok(p.len())
        }
        fn receive(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.borrow_mut().events.push("receive probe".into());
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    struct Native(Shared);
    impl NativePair for Native {
        type Socket = Socket;
        fn sample(&mut self, _: Slot) -> Option<NativeHealthSample> {
            self.0.borrow_mut().events.push("sample".into());
            Some(NativeHealthSample {
                admitted: true,
                closed: false,
                handshake_fresh: true,
                tx_packets: 0,
                rx_data_packets: 0,
            })
        }
        fn open_probe(&mut self, _: Slot) -> io::Result<(Socket, String)> {
            self.0.borrow_mut().events.push("probe".into());
            Ok((Socket(self.0.clone()), "health.example.net".into()))
        }
        fn select_active(&mut self, _: &SessionScope, _: Slot) -> io::Result<()> {
            Ok(())
        }
        fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
            let mut w = self.0.borrow_mut();
            w.events.push("close".into());
            w.closed_scopes.push(scope.clone());
            if w.fail_close {
                return Err(io::Error::other("private close detail"));
            }
            w.pending = false;
            Ok(())
        }
    }
    impl PairControl for Native {
        fn complete_start(&mut self, scope: &SessionScope) -> io::Result<()> {
            assert_eq!(self.0.borrow().saved.last().unwrap().scope, *scope);
            self.check_integrity()
        }
        fn metrics(&self, slot: Slot) -> io::Result<TunnelMetrics> {
            let mut w = self.0.borrow_mut();
            w.events.push(format!("pair metrics {slot:?}"));
            if w.fail_diagnostics {
                return Err(io::Error::other("private metrics detail"));
            }
            Ok(TunnelMetrics {
                received_bytes: 123,
                sent_bytes: 456,
                latest_handshake_epoch_millis: None,
                probe_target: None,
            })
        }
        fn physical_network_fingerprint(&self) -> io::Result<String> {
            let mut w = self.0.borrow_mut();
            w.events.push("pair fingerprint".into());
            if w.fingerprint_unsupported {
                return Err(io::ErrorKind::Unsupported.into());
            }
            if w.fail_diagnostics {
                return Err(io::Error::other("private fingerprint detail"));
            }
            Ok(w.fingerprint.clone().unwrap_or_else(|| "ab".repeat(32)))
        }
        fn start_primary(
            &mut self,
            _: &SessionScope,
            _: &Member,
            _: &DesktopTunnelOptions,
        ) -> io::Result<()> {
            let mut w = self.0.borrow_mut();
            assert_eq!(w.saved.last().unwrap().phase, SessionPhase::Starting);
            w.events.push("primary".into());
            w.pending = true;
            if w.fail_start {
                Err(io::Error::other("secret start detail"))
            } else {
                Ok(())
            }
        }
        fn attach(&mut self, _: &SessionScope, _: &Member) -> io::Result<()> {
            self.0.borrow_mut().events.push("attach".into());
            Ok(())
        }
        fn remove_standby(&mut self, _: &SessionScope, _: Slot) -> io::Result<()> {
            Ok(())
        }
        fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
            let mut w = self.0.borrow_mut();
            w.events.push("rebind pair".into());
            w.rebind_scopes.push(scope.clone());
            if w.fail_rebind {
                return Err(io::Error::other("private rebind detail"));
            }
            Ok(!w.unvalidated_rebind)
        }
        fn complete_rebind(&mut self, scope: &SessionScope) -> io::Result<()> {
            assert_eq!(self.0.borrow().saved.last().unwrap().scope, *scope);
            self.check_integrity()
        }
        fn cleanup_pending(&self) -> bool {
            let w = self.0.borrow();
            w.residual_cleanup || (w.pending && w.fail_close)
        }
    }
    struct Store(Shared);
    impl SessionStore for Store {
        fn save(&mut self, state: &SessionSnapshot) -> io::Result<()> {
            let mut w = self.0.borrow_mut();
            w.events.push(format!("save {:?}", state.phase));
            if w.fail_save {
                return Err(io::Error::other("private save detail"));
            }
            w.saved.push(state.clone());
            Ok(())
        }
    }
    struct Factory(Shared);
    impl PairFactory for Factory {
        type Native = Native;
        type Store = Store;
        fn recover(&mut self) -> Result<(), ServiceError> {
            let mut w = self.0.borrow_mut();
            w.events.push("recover".into());
            if w.fail_recover {
                Err(ServiceError::Backend("private recovery path".into()))
            } else {
                Ok(())
            }
        }
        fn prepare(
            &mut self,
            command: &Command,
            now: u64,
        ) -> io::Result<SessionControl<Native, Store>> {
            {
                let mut w = self.0.borrow_mut();
                w.events.push("prepare".into());
                w.prepared_at.push(now);
                if w.fail_prepare {
                    return Err(io::Error::other("private factory path"));
                }
                if w.saved.iter().any(|state| &state.scope == command.scope()) {
                    return Err(io::Error::other("reused durable scope"));
                }
            }
            SessionControl::prepare(
                RuntimeSlot::Latest,
                command,
                Native(self.0.clone()),
                Store(self.0.clone()),
                now,
            )
        }
    }
    type Actor = CompositeBackend<Single, Factory>;
    #[test]
    fn composite_version_advertises_support_and_status_uses_cached_pair_snapshot() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        let expected = status(&mut actor);
        w.borrow_mut().events.clear();
        let mut handler = crate::TunnelRequestHandler::new(actor, "test");
        assert!(
            handler
                .handle(crate::Request::version())
                .desktop_redundancy_v1
        );
        assert_eq!(
            handler.handle(crate::Request::status()).redundancy,
            Some(expected)
        );
        assert!(w.borrow().events.is_empty());
    }
    fn setup() -> (Actor, Shared) {
        let w = Rc::new(RefCell::new(World::default()));
        let actor = Actor::new(RuntimeSlot::Latest, Single(w.clone()), Factory(w.clone())).unwrap();
        w.borrow_mut().events.clear();
        (actor, w)
    }
    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 10,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 7,
        }
    }

    #[test]
    fn pair_diagnostics_survive_failed_prepare_start_stop_and_reset_for_retry() {
        let (mut actor, w) = setup();
        w.borrow_mut().fail_prepare = true;
        let error = actor.redundant(start()).unwrap_err();
        assert_eq!(error, failed());
        assert_eq!(error.code(), "service_unavailable");
        let report: serde_json::Value =
            serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
        assert_eq!(report["failure"]["stage"], "start");
        assert_eq!(report["failure"]["origin"], "prepare");
        assert_eq!(report["scope"]["connection_generation"], 7);
        assert!(!report.to_string().contains("private"));
        w.borrow_mut().fail_prepare = false;
        w.borrow_mut().fail_start = true;
        w.borrow_mut().fail_close = true;
        assert_eq!(actor.redundant(start()).unwrap_err(), failed());
        actor.redundant(Command::Status { scope: scope() }).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
        assert_eq!(report["failure"]["stage"], "start");
        assert_eq!(report["operation_id"], 2);
        assert!(!report.to_string().contains("secret"));
        assert_eq!(
            actor
                .redundant(Command::Stop { scope: scope() })
                .unwrap_err(),
            failed()
        );
        let report: serde_json::Value =
            serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
        assert_eq!(report["failure"]["stage"], "stop");
        assert_eq!(report["operation_id"], 3);
        w.borrow_mut().fail_close = false;
        actor.redundant(Command::Stop { scope: scope() }).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
        assert!(report["failure"].is_null());
        let mut next = scope();
        next.connection_generation += 1;
        w.borrow_mut().fail_start = false;
        actor.redundant(start_at(next)).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
        assert_eq!(report["scope"]["connection_generation"], 8);
        assert!(report["failure"].is_null());
        assert!(!w.borrow().events.iter().any(|e| e == "single diagnostics"));
    }

    #[test]
    fn single_status_preflight_retains_its_existing_public_error() {
        let (mut actor, w) = setup();
        w.borrow_mut().status_error = Some(ServiceError::Backend("route_conflict".into()));
        let error = actor.redundant(start()).unwrap_err();
        assert_eq!(error.code(), "route_conflict");
        assert_eq!(error, ServiceError::Backend("route_conflict".into()));
        assert!(actor.diagnostics().unwrap().contains("prepare"));
    }
    fn config() -> ParsedConfiguration {
        parse_configuration("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.1:51820\n").unwrap()
    }
    fn start_at(scope: SessionScope) -> Command {
        Command::Start {
            scope,
            primary: Member {
                slot: Slot::A,
                lease_id: "aaaaaaaa-0000-4000-8000-000000000001".into(),
                configuration: TunnelConfiguration::new("fake private config".into()),
                probe: RedundantHealthProbe {
                    kind: HealthProbeKind::DnsA,
                    target_ipv4: "9.9.9.9".parse().unwrap(),
                    query_name: "health.example.net".into(),
                    timeout_ms: 2000,
                },
            },
            role_generation: 0,
            membership_generation: 0,
            warm_stop_v1: true,
            options: DesktopTunnelOptions::default(),
        }
    }
    fn start() -> Command {
        start_at(scope())
    }
    fn status(actor: &mut Actor) -> Snapshot {
        actor.redundant(Command::Status { scope: scope() }).unwrap()
    }

    #[test]
    fn construction_recovers_once_before_any_operation_and_failed_recovery_returns_no_actor() {
        let w = Rc::new(RefCell::new(World::default()));
        let mut actor =
            Actor::new(RuntimeSlot::Latest, Single(w.clone()), Factory(w.clone())).unwrap();
        assert_eq!(w.borrow().events, ["recover"]);
        actor.tick(1).unwrap();
        actor.redundant(start()).unwrap();
        assert_eq!(
            w.borrow()
                .events
                .iter()
                .filter(|e| e.as_str() == "recover")
                .count(),
            1
        );
        let w = Rc::new(RefCell::new(World {
            fail_recover: true,
            ..Default::default()
        }));
        let result = Actor::new(RuntimeSlot::Latest, Single(w.clone()), Factory(w.clone()));
        assert!(result.is_err());
        assert_eq!(w.borrow().events, ["recover"]);
    }

    #[test]
    fn start_seals_starting_before_native_and_uses_last_actor_tick() {
        let (mut actor, w) = setup();
        actor.tick(4000).unwrap();
        w.borrow_mut().events.clear();
        let snapshot = actor.redundant(start()).unwrap();
        assert_eq!(snapshot.session.phase, SessionPhase::Running);
        assert_eq!(w.borrow().prepared_at, [4000]);
        assert_eq!(
            w.borrow().events,
            [
                "single status",
                "prepare",
                "save Starting",
                "primary",
                "save Running"
            ]
        );
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Starting);
    }
    #[test]
    fn runtime_and_validation_fail_before_single_or_factory_queries() {
        let (mut actor, w) = setup();
        let mut foreign = scope();
        foreign.runtime = RuntimeSlot::Stable;
        assert!(actor.redundant(start_at(foreign)).is_err());
        let mut invalid = scope();
        invalid.runtime_generation = 0;
        assert!(actor.redundant(start_at(invalid)).is_err());
        assert!(w.borrow().events.is_empty());
    }
    #[test]
    fn non_stopped_or_unavailable_single_prevents_factory_prepare() {
        for state in [
            ServiceTunnelState::Running,
            ServiceTunnelState::Starting,
            ServiceTunnelState::Stopping,
            ServiceTunnelState::Failed,
        ] {
            let (mut actor, w) = setup();
            w.borrow_mut().single = state;
            assert!(actor.redundant(start()).is_err());
            assert_eq!(w.borrow().events, ["single status"]);
        }
        let (mut actor, w) = setup();
        w.borrow_mut().fail_status = true;
        assert!(actor.redundant(start()).is_err());
        assert_eq!(w.borrow().events, ["single status"]);
    }
    #[test]
    fn failed_start_retains_owner_for_scoped_cleanup_and_redacts_error() {
        let (mut actor, w) = setup();
        {
            let mut w = w.borrow_mut();
            w.fail_start = true;
            w.fail_close = true;
        }
        assert!(!actor
            .redundant(start())
            .unwrap_err()
            .to_string()
            .contains("secret"));
        assert!(status(&mut actor).cleanup_pending);
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Stopping);
        w.borrow_mut().events.clear();
        assert!(actor.stop().is_err());
        assert!(actor
            .start(&config(), &DesktopTunnelOptions::default())
            .is_err());
        assert!(actor.rebind_udp().is_err());
        assert!(actor.redundant(start()).is_err());
        assert!(w.borrow().events.is_empty());
        w.borrow_mut().fail_close = false;
        let stopped = actor.redundant(Command::Stop { scope: scope() }).unwrap();
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        assert_eq!(w.borrow().closed_scopes, [scope(), scope()]);
    }
    #[test]
    fn duplicate_or_foreign_start_cannot_replace_live_pair_or_repeat_effects() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        w.borrow_mut().events.clear();
        assert!(actor.redundant(start()).is_err());
        let mut other = scope();
        other.connection_generation += 1;
        assert!(actor.redundant(start_at(other)).is_err());
        assert!(w.borrow().events.is_empty());
        assert_eq!(status(&mut actor).session.scope, scope());
    }
    #[test]
    fn terminal_owner_rejects_same_scope_but_allows_different_scope() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        actor.redundant(Command::Stop { scope: scope() }).unwrap();
        w.borrow_mut().events.clear();
        assert!(actor.redundant(start()).is_err());
        assert!(w.borrow().events.is_empty());
        let mut next = scope();
        next.connection_generation += 1;
        assert_eq!(
            actor
                .redundant(start_at(next.clone()))
                .unwrap()
                .session
                .scope,
            next
        );
        assert_eq!(w.borrow().prepared_at.len(), 2);
    }
    #[test]
    fn scoped_commands_require_exact_owner_and_do_not_fall_back_to_single() {
        let (mut actor, w) = setup();
        assert!(actor.redundant(Command::Stop { scope: scope() }).is_err());
        assert!(w.borrow().events.is_empty());
        actor.redundant(start()).unwrap();
        w.borrow_mut().events.clear();
        let mut wrong = scope();
        wrong.runtime_generation += 1;
        for command in [
            Command::Stop {
                scope: wrong.clone(),
            },
            Command::Status {
                scope: wrong.clone(),
            },
            Command::NetworkChanged { scope: wrong },
        ] {
            assert!(actor.redundant(command).is_err());
        }
        assert!(w.borrow().events.is_empty());
        actor
            .redundant(Command::NetworkChanged { scope: scope() })
            .unwrap();
        assert!(w.borrow().events.iter().any(|e| e == "rebind pair"));
    }
    #[test]
    fn ordinary_requests_never_touch_single_while_pair_is_live() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        w.borrow_mut().events.clear();
        assert!(actor
            .start(&config(), &DesktopTunnelOptions::default())
            .is_err());
        assert!(actor.stop().is_err());
        assert!(actor.rebind_udp().is_err());
        assert_eq!(actor.metrics(false).unwrap().received_bytes, 123);
        assert!(actor.diagnostics().is_ok());
        assert_eq!(
            actor.physical_network_fingerprint().unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Starting);
        assert_eq!(w.borrow().events, ["pair metrics A", "pair fingerprint"]);
    }
    #[test]
    fn diagnostic_failure_and_stopping_never_fall_back_to_single() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        w.borrow_mut().fail_diagnostics = true;
        w.borrow_mut().events.clear();
        for error in [
            actor.metrics(true).unwrap_err(),
            actor.physical_network_fingerprint().unwrap_err(),
        ] {
            assert!(!error.to_string().contains("private"));
        }
        assert_eq!(w.borrow().events, ["pair metrics A", "pair fingerprint"]);
        actor
            .redundant(Command::PrepareStop { scope: scope() })
            .unwrap();
        w.borrow_mut().events.clear();
        assert!(actor.metrics(false).is_err());
        assert!(actor.physical_network_fingerprint().is_err());
        assert!(w.borrow().events.is_empty());
    }
    #[test]
    fn shutdown_scopes_pair_stop_and_retries_without_single_cleanup() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        w.borrow_mut().fail_close = true;
        assert!(actor.shutdown().is_err());
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Stopping);
        w.borrow_mut().fail_close = false;
        actor.shutdown().unwrap();
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Stopped);
        assert_eq!(w.borrow().closed_scopes, [scope(), scope()]);
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e.starts_with("single ") && e != "single status"));
    }
    #[test]
    fn ticks_poll_control_without_ui_and_backward_time_retains_cleanup_owner() {
        let (mut actor, w) = setup();
        actor.tick(1000).unwrap();
        actor.redundant(start()).unwrap();
        w.borrow_mut().events.clear();
        actor.tick(1000).unwrap();
        assert!(w.borrow().events.iter().any(|e| e == "sample"));
        assert!(w.borrow().events.iter().any(|e| e == "probe"));
        assert!(!w.borrow().events.iter().any(|e| e == "single tick"));
        w.borrow_mut().fail_close = true;
        assert!(actor.tick(999).is_err());
        assert!(status(&mut actor).cleanup_pending);
    }

    #[test]
    fn idle_ticks_detect_change_every_two_seconds_before_health_without_gui() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        actor.tick(0).unwrap();
        let epoch = status(&mut actor).session.network_epoch;
        w.borrow_mut().fingerprint = Some("cd".repeat(32));
        w.borrow_mut().events.clear();
        actor.tick(1999).unwrap();
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e == "pair fingerprint" || e == "rebind pair"));
        w.borrow_mut().events.clear();
        actor.tick(2000).unwrap();
        assert_eq!(status(&mut actor).session.network_epoch, epoch + 2);
        let events = w.borrow().events.clone();
        let rebind = events.iter().position(|e| e == "rebind pair").unwrap();
        assert_eq!(events[0], "pair fingerprint");
        assert!(events[..rebind].iter().any(|e| e == "save Running"));
        assert!(events[..rebind].iter().any(|e| e == "cancel probe"));
        assert!(!events[..rebind]
            .iter()
            .any(|e| e == "sample" || e == "receive probe"));
        assert_eq!(w.borrow().rebind_scopes, [scope()]);
        assert!(!events.iter().any(|e| e == "single rebind" || e == "close"));
        w.borrow_mut().events.clear();
        actor.tick(4000).unwrap();
        assert_eq!(w.borrow().rebind_scopes.len(), 1);
        assert_eq!(status(&mut actor).session.network_epoch, epoch + 2);
    }

    #[test]
    fn discovery_failure_invalidates_once_and_retries_same_fingerprint_without_shutdown() {
        for invalid in [None, Some(String::new()), Some("invalid".into())] {
            let (mut actor, w) = setup();
            actor.redundant(start()).unwrap();
            actor.tick(0).unwrap();
            let epoch = status(&mut actor).session.network_epoch;
            w.borrow_mut().fail_diagnostics = invalid.is_none();
            w.borrow_mut().fingerprint = invalid;
            w.borrow_mut().events.clear();
            actor.tick(2000).unwrap();
            let report: serde_json::Value =
                serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
            assert_eq!(report["failure"]["stage"], "tick");
            assert_eq!(report["failure"]["origin"], "fingerprint");
            assert_eq!(report["scope"]["connection_generation"], 7);
            assert!(!report.to_string().contains("private"));
            assert_eq!(status(&mut actor).session.network_epoch, epoch + 1);
            assert!(!status(&mut actor).primary_ready);
            assert!(w.borrow().events.iter().any(|e| e == "cancel probe"));
            assert!(!w.borrow().events.iter().any(|e| matches!(
                e.as_str(),
                "sample" | "receive probe" | "probe" | "rebind pair" | "close"
            )));
            w.borrow_mut().events.clear();
            actor.tick(3999).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&actor.diagnostics().unwrap()).unwrap(),
                report
            );
            assert!(w.borrow().events.is_empty());
            actor.tick(4000).unwrap();
            assert_eq!(status(&mut actor).session.network_epoch, epoch + 1);
            w.borrow_mut().fail_diagnostics = false;
            w.borrow_mut().fingerprint = None; // original fingerprint, but evidence is invalid
            w.borrow_mut().events.clear();
            actor.tick(6000).unwrap();
            assert_eq!(w.borrow().rebind_scopes, [scope()]);
            assert_eq!(status(&mut actor).session.network_epoch, epoch + 3);
            assert!(!w
                .borrow()
                .events
                .iter()
                .any(|e| e == "close" || e.starts_with("single ")));
        }
    }

    #[test]
    fn failed_or_unvalidated_rebind_retries_without_health_or_ordinary_fallback() {
        for failed_rebind in [false, true] {
            let (mut actor, w) = setup();
            actor.redundant(start()).unwrap();
            actor.tick(0).unwrap();
            w.borrow_mut().fingerprint = Some("cd".repeat(32));
            w.borrow_mut().fail_rebind = failed_rebind;
            w.borrow_mut().unvalidated_rebind = !failed_rebind;
            w.borrow_mut().events.clear();
            actor.tick(2000).unwrap();
            if failed_rebind {
                let report: serde_json::Value =
                    serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
                assert_eq!(report["failure"]["stage"], "tick");
                assert_eq!(report["failure"]["origin"], "network_changed");
                assert!(!report.to_string().contains("private"));
            }
            assert!(!w
                .borrow()
                .events
                .iter()
                .any(|e| matches!(e.as_str(), "sample" | "receive probe" | "probe" | "close")));
            assert_eq!(w.borrow().rebind_scopes.len(), 1);
            actor.tick(3999).unwrap();
            assert_eq!(w.borrow().rebind_scopes.len(), 1);
            w.borrow_mut().fail_rebind = false;
            w.borrow_mut().unvalidated_rebind = false;
            actor.tick(4000).unwrap();
            assert_eq!(w.borrow().rebind_scopes, [scope(), scope()]);
            assert!(!w
                .borrow()
                .events
                .iter()
                .any(|e| e == "close" || e.starts_with("single ")));
            actor.tick(6000).unwrap();
            assert_eq!(w.borrow().rebind_scopes.len(), 2);
        }
    }

    #[test]
    fn optional_unsupported_provider_does_not_disable_existing_health_but_loss_does() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        w.borrow_mut().fingerprint_unsupported = true;
        w.borrow_mut().events.clear();
        actor.tick(0).unwrap();
        let epoch = status(&mut actor).session.network_epoch;
        assert!(w.borrow().events.iter().any(|e| e == "sample"));
        assert!(
            serde_json::from_str::<serde_json::Value>(&actor.diagnostics().unwrap()).unwrap()
                ["failure"]
                .is_null()
        );
        assert!(w.borrow().rebind_scopes.is_empty());
        w.borrow_mut().fingerprint_unsupported = false;
        actor.tick(2000).unwrap();
        w.borrow_mut().fingerprint_unsupported = true;
        w.borrow_mut().events.clear();
        actor.tick(4000).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&actor.diagnostics().unwrap()).unwrap();
        assert_eq!(report["failure"]["cause"], "unsupported");
        assert_eq!(status(&mut actor).session.network_epoch, epoch + 1);
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e == "sample" || e == "close"));
    }

    #[test]
    fn stopping_and_new_scope_do_not_reuse_cached_network_or_trigger_rebind() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        actor.tick(0).unwrap();
        actor
            .redundant(Command::PrepareStop { scope: scope() })
            .unwrap();
        assert!(actor.physical_fingerprint.is_none());
        w.borrow_mut().events.clear();
        actor.tick(500).unwrap();
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e == "pair fingerprint" || e == "rebind pair"));
        actor.redundant(Command::Stop { scope: scope() }).unwrap();
        let mut next = scope();
        next.connection_generation += 1;
        actor.redundant(start_at(next)).unwrap();
        w.borrow_mut().fingerprint = Some("cd".repeat(32));
        w.borrow_mut().events.clear();
        actor.tick(600).unwrap();
        assert!(w.borrow().events.iter().any(|e| e == "pair fingerprint"));
        assert!(w.borrow().rebind_scopes.is_empty());
    }

    #[test]
    fn failed_first_discovery_blocks_health_until_a_scoped_rebind_validates_it() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        w.borrow_mut().fail_diagnostics = true;
        w.borrow_mut().events.clear();
        actor.tick(0).unwrap();
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| matches!(e.as_str(), "sample" | "probe" | "close")));
        w.borrow_mut().fail_diagnostics = false;
        actor.tick(2000).unwrap();
        assert_eq!(w.borrow().rebind_scopes, [scope()]);
    }

    #[test]
    fn failed_epoch_persistence_is_not_swallowed_as_transient_discovery_failure() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        actor.tick(0).unwrap();
        w.borrow_mut().fail_save = true;
        w.borrow_mut().fail_diagnostics = true;
        w.borrow_mut().events.clear();
        assert!(actor.tick(2000).is_err());
        assert_eq!(w.borrow().closed_scopes, [scope()]);
        assert!(w.borrow().rebind_scopes.is_empty());
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e == "sample" || e == "single rebind"));
    }
    #[test]
    fn no_pair_preserves_single_mode_and_terminal_pair_can_yield_to_single() {
        let (mut actor, w) = setup();
        actor.tick(1).unwrap();
        assert_eq!(
            actor
                .start(&config(), &DesktopTunnelOptions::default())
                .unwrap(),
            ServiceTunnelState::Running
        );
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Running);
        actor.rebind_udp().unwrap();
        actor.diagnostics().unwrap();
        actor.physical_network_fingerprint().unwrap();
        let _ = actor.metrics(false);
        actor.shutdown().unwrap();
        assert_eq!(w.borrow().single, ServiceTunnelState::Stopped);
        assert!(w.borrow().events.iter().any(|e| e == "single tick"));
        actor.redundant(start()).unwrap();
        actor.redundant(Command::Stop { scope: scope() }).unwrap();
        actor
            .start(&config(), &DesktopTunnelOptions::default())
            .unwrap();
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Running);
        actor.stop().unwrap();
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Stopped);
    }
    #[test]
    fn prepare_failure_has_no_native_start_and_is_redacted() {
        let (mut actor, w) = setup();
        w.borrow_mut().fail_prepare = true;
        let error = actor.redundant(start()).unwrap_err();
        assert!(!error.to_string().contains("private"));
        assert_eq!(w.borrow().events, ["single status", "prepare"]);
        actor.shutdown().unwrap();
        assert!(w.borrow().events.iter().any(|e| e == "single shutdown"));
    }

    #[test]
    fn terminal_native_cleanup_still_fences_replacement_and_shutdown_ack() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        w.borrow_mut().residual_cleanup = true;
        let snapshot = actor.redundant(Command::Stop { scope: scope() }).unwrap();
        assert_eq!(snapshot.session.phase, SessionPhase::Stopped);
        assert!(snapshot.cleanup_pending);
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Stopping);
        w.borrow_mut().events.clear();
        let mut next = scope();
        next.connection_generation += 1;
        assert!(actor.redundant(start_at(next)).is_err());
        assert!(actor
            .start(&config(), &DesktopTunnelOptions::default())
            .is_err());
        assert!(w.borrow().events.is_empty());
        assert!(actor.shutdown().is_err());
        w.borrow_mut().residual_cleanup = false;
        actor.shutdown().unwrap();
    }

    #[test]
    fn fresh_actor_honors_factory_rejection_of_previously_used_durable_scope() {
        let (mut actor, w) = setup();
        actor.redundant(start()).unwrap();
        actor.shutdown().unwrap();
        drop(actor);
        let mut actor =
            Actor::new(RuntimeSlot::Latest, Single(w.clone()), Factory(w.clone())).unwrap();
        w.borrow_mut().events.clear();
        assert!(actor.redundant(start()).is_err());
        assert_eq!(w.borrow().events, ["single status", "prepare"]);
        assert_eq!(actor.status().unwrap(), ServiceTunnelState::Stopped);
    }
}
