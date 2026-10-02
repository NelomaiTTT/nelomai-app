//! Serialized Windows single/pair ownership inside the existing engine actor.
//! Native factory construction is restricted to the authenticated service owner.

use crate::{DefenderStatus, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use nelomai_client_tunnel::{
    redundancy::{
        control::{PairControl, SessionControl},
        driver::SessionStore,
        protocol::{Command, Snapshot},
        session::SessionPhase,
    },
    DesktopTunnelOptions, TunnelMetrics, TunnelTransport,
};
use nelomai_contracts::RuntimeSlot;
use std::io;

const PHYSICAL_SAMPLE_MS: u64 = 2_000;

pub trait PairFactory {
    type Native: PairControl;
    type Store: SessionStore;
    /// Cleanup-only durable recovery for the authenticated runtime. Never adopt
    /// a discovered pair or resume health. Failure prevents actor construction.
    fn recover(&mut self, runtime: RuntimeSlot) -> Result<(), ServiceError>;
    /// Persist Starting without starting native members. Reject any reused
    /// durable scope. On error, no native ownership may escape this method.
    /// Runtime is supplied by the authenticated actor, not chosen by app IPC.
    fn prepare(
        &mut self,
        runtime: RuntimeSlot,
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
}
impl<B: ServiceTunnelBackend, F: PairFactory> CompositeBackend<B, F> {
    pub fn new(runtime: RuntimeSlot, single: B, mut factory: F) -> Result<Self, ServiceError> {
        factory.recover(runtime).map_err(|error| match error {
            ServiceError::PairOperation(_) => error,
            _ => failed(),
        })?;
        Ok(Self {
            single,
            factory,
            runtime,
            pair: None,
            snapshot: None,
            now: 0,
            physical_fingerprint: None,
            next_physical_sample: 0,
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

    /// Run before health under the same serialized actor ownership. Reuse the
    /// shared NetworkChanged four-second grace; no additional debounce or task.
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
                // Match Unix's optional-hook behavior only before any working
                // provider was observed. Losing an established provider fences.
                Ok(())
            }
            Err(_) => {
                // Failed discovery is not proof of the old network. Invalidate
                // once, cancel old queries, and wait for a fresh sample to rebind.
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
                    if let Err(error) = pair.execute(
                        Command::NetworkChanged {
                            scope: snapshot.session.scope,
                        },
                        now,
                    ) {
                        // Retry transient native rebind failure at the next
                        // physical sample without driving health or legacy code.
                        // Failed durable fencing/stop must still reach the actor.
                        if pair.snapshot().session.phase != SessionPhase::Running
                            || pair.network_validated()
                        {
                            return Err(error);
                        }
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
    // Only an explicitly constructed composite opts in. No production factory
    // or ordinary Windows backend is changed by this module's registration.
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
        self.refresh();
        let stage = match &command {
            Command::Start { .. } => "start",
            Command::Attach { .. } => "attach",
            Command::StageCandidate { .. } => "stage_candidate",
            Command::RemoveStandby { .. } => "remove_standby",
            Command::RetireInactive { .. } => "retire_inactive",
            Command::CommitCandidate { .. } => "commit_candidate",
            Command::Status { .. } => "status",
            Command::PrepareStop { .. } => "prepare_stop",
            Command::PrepareRecoveryStop { .. } => "prepare_recovery_stop",
            Command::Stop { .. } => "stop",
            Command::NetworkChanged { .. } => "network_changed",
            Command::ConfirmRole { .. } => "confirm_role",
        };
        let result = if let Command::Start {
            primary, options, ..
        } = &command
        {
            if self
                .snapshot
                .as_ref()
                .is_some_and(|s| !terminal(s) || &s.session.scope == command.scope())
            {
                return Err(failed());
            }
            if self.single.status()? != ServiceTunnelState::Stopped {
                return Err(failed());
            }
            let pair = self
                .factory
                .prepare(self.runtime, &command, self.now)
                .map_err(|e| operation_failed("prepare", e))?;
            // A partially failed native Start remains reachable by scoped Stop
            // and shutdown. Never lose the owner by starting a local temporary.
            self.pair = Some(pair);
            self.physical_fingerprint = None;
            self.next_physical_sample = self.now;
            self.pair
                .as_mut()
                .ok_or_else(failed)?
                .start_primary(primary, options)
        } else {
            self.pair
                .as_mut()
                .ok_or_else(failed)?
                .execute(command, self.now)
        };
        // Refresh on failures too: no stale Running status or legacy fallback.
        self.refresh();
        result.map_err(|e| operation_failed(stage, e))
    }
    fn tick(&mut self, now: u64) -> Result<(), ServiceError> {
        let backwards = now < self.now;
        if !backwards {
            self.now = now;
        }
        if self.pair.is_some() {
            // The shared driver fences/closes on a backwards clock. Preserve
            // the actor's last monotonic time even for the next session.
            let result = (|| {
                if !backwards {
                    self.poll_physical(now)?;
                }
                self.pair
                    .as_mut()
                    .expect("pair retained during physical poll")
                    .tick(now)
            })();
            self.refresh();
            result.map_err(|e| operation_failed("tick", e))?;
            if backwards {
                return Err(failed());
            }
            Ok(())
        } else if backwards {
            Err(failed())
        } else {
            self.single.tick(now)
        }
    }
    fn shutdown(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.refresh();
        let Some(snapshot) = &self.snapshot else {
            return self.single.shutdown();
        };
        let snapshot = self.redundant(Command::Stop {
            scope: snapshot.session.scope.clone(),
        })?;
        if terminal(&snapshot) {
            Ok(ServiceTunnelState::Stopped)
        } else {
            Err(failed())
        }
    }
    fn start(
        &mut self,
        configuration: &str,
        options: &DesktopTunnelOptions,
        transport: TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        if self.pair_blocks_single() {
            return Err(failed());
        }
        // Terminal pair ownership has been fully cleaned. Clear its cache first
        // so even a partial singleton Start remains owned by the single backend.
        self.pair = None;
        self.snapshot = None;
        self.physical_fingerprint = None;
        self.next_physical_sample = self.now;
        self.single.start(configuration, options, transport)
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
    fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        if let Some(s) = &self.snapshot {
            return Ok(if s.cleanup_pending {
                ServiceTunnelState::Stopping
            } else {
                match s.session.phase {
                    SessionPhase::Running if s.primary_ready => ServiceTunnelState::Running,
                    SessionPhase::Starting | SessionPhase::Running => ServiceTunnelState::Starting,
                    SessionPhase::Stopping => ServiceTunnelState::Stopping,
                    SessionPhase::Stopped => ServiceTunnelState::Stopped,
                }
            });
        }
        self.single.status()
    }
    fn metrics(&mut self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        if let Some(pair) = &self.pair {
            // Pair probes are exclusively driven by helper tick, never UI polls.
            return pair.metrics().map_err(|e| operation_failed("metrics", e));
        }
        self.single.metrics(probe)
    }
    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        if let Some(pair) = &self.pair {
            return pair
                .physical_network_fingerprint()
                .map_err(|e| operation_failed("physical_network", e));
        }
        self.single.physical_network_fingerprint()
    }
    fn diagnostics(&mut self) -> Result<String, ServiceError> {
        if self.pair.is_some() {
            return Err(unsupported());
        }
        self.single.diagnostics()
    }
    fn defender_status(&mut self) -> Result<DefenderStatus, ServiceError> {
        self.single.defender_status()
    }
    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        if self.pair.is_some() {
            return Err(unsupported());
        }
        self.single.rebind_udp()
    }
}
fn terminal(s: &Snapshot) -> bool {
    s.session.phase == SessionPhase::Stopped && !s.cleanup_pending
}
fn unsupported() -> ServiceError {
    ServiceError::Backend("redundant_operation_unsupported".into())
}
fn failed() -> ServiceError {
    ServiceError::Backend("redundant_actor_failed".into())
}
pub(crate) fn operation_failed(stage: &'static str, error: io::Error) -> ServiceError {
    let failure = ServiceError::PairOperation(crate::PairFailure::io(stage, error));
    #[cfg(windows)]
    crate::windows::record_service_diagnostic("redundant operation", &failure);
    failure
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefenderExclusionState;
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
        saved: Vec<SessionSnapshot>,
        recovered: Vec<RuntimeSlot>,
        prepared: Vec<(RuntimeSlot, u64)>,
        closed: Vec<SessionScope>,
        native: [bool; 2],
        tx: [u64; 2],
        rx: [u64; 2],
        dead: [bool; 2],
        fail_recover: bool,
        fail_prepare: bool,
        fail_status: bool,
        fail_start: bool,
        fail_close: bool,
        residual: bool,
        fail_save: bool,
        lose_running_ack: bool,
        fail_diagnostics: bool,
        fingerprint: Option<String>,
        fingerprint_unsupported: bool,
        fail_rebind: bool,
        unvalidated_rebind: bool,
        rebind_scopes: Vec<SessionScope>,
        hold_replies: bool,
    }
    type Shared = Rc<RefCell<World>>;
    fn index(slot: Slot) -> usize {
        if slot == Slot::A {
            0
        } else {
            1
        }
    }
    struct Single(Shared);
    impl ServiceTunnelBackend for Single {
        fn start(
            &mut self,
            configuration: &str,
            _: &DesktopTunnelOptions,
            transport: TunnelTransport,
        ) -> Result<ServiceTunnelState, ServiceError> {
            assert_eq!(configuration, "single fake config");
            assert_eq!(transport, TunnelTransport::WireGuard);
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
        fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            let mut w = self.0.borrow_mut();
            w.events.push("single status".into());
            if w.fail_status {
                Err(failed())
            } else {
                Ok(w.single)
            }
        }
        fn metrics(&mut self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
            self.0
                .borrow_mut()
                .events
                .push(format!("single metrics {probe}"));
            Ok(metric(99))
        }
        fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
            self.0.borrow_mut().events.push("single fingerprint".into());
            Ok("single physical".into())
        }
        fn diagnostics(&mut self) -> Result<String, ServiceError> {
            self.0.borrow_mut().events.push("single diagnostics".into());
            Ok("single diagnostics".into())
        }
        fn defender_status(&mut self) -> Result<DefenderStatus, ServiceError> {
            self.0.borrow_mut().events.push("defender".into());
            Ok(DefenderStatus {
                state: DefenderExclusionState::Excluded,
                dll_present: true,
                detail_code: None,
                antivirus_products: vec![],
                antivirus_detail_code: None,
            })
        }
        fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            self.0.borrow_mut().events.push("single rebind".into());
            Ok(ServiceTunnelState::Running)
        }
        fn tick(&mut self, now: u64) -> Result<(), ServiceError> {
            self.0
                .borrow_mut()
                .events
                .push(format!("single tick {now}"));
            Ok(())
        }
        fn shutdown(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            self.0.borrow_mut().events.push("single shutdown".into());
            self.stop()
        }
    }
    fn metric(bytes: u64) -> TunnelMetrics {
        TunnelMetrics {
            received_bytes: bytes,
            sent_bytes: bytes,
            latest_handshake_epoch_millis: None,
            probe_target: None,
        }
    }
    struct Socket {
        world: Shared,
        slot: Slot,
        query: Vec<u8>,
        replied: bool,
    }
    impl Drop for Socket {
        fn drop(&mut self) {
            self.world.borrow_mut().events.push("drop probe".into());
        }
    }
    impl ProbeDatagram for Socket {
        fn send(&mut self, p: &[u8]) -> io::Result<usize> {
            self.query = p.to_vec();
            self.world.borrow_mut().tx[index(self.slot)] += 1;
            Ok(p.len())
        }
        fn receive(&mut self, p: &mut [u8]) -> io::Result<usize> {
            self.world.borrow_mut().events.push("receive probe".into());
            if self.replied
                || self.world.borrow().dead[index(self.slot)]
                || self.world.borrow().hold_replies
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut r = self.query.clone();
            r[2] = 0x81;
            r[3] = 0x80;
            r[7] = 1;
            r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
            p[..r.len()].copy_from_slice(&r);
            self.replied = true;
            self.world.borrow_mut().rx[index(self.slot)] += 1;
            Ok(r.len())
        }
    }
    struct Native(Shared);
    impl NativePair for Native {
        type Socket = Socket;
        fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
            let mut w = self.0.borrow_mut();
            w.events.push(format!("sample {slot:?}"));
            let i = index(slot);
            Some(NativeHealthSample {
                admitted: w.native[i] && !w.dead[i],
                closed: w.dead[i],
                handshake_fresh: !w.dead[i],
                tx_packets: w.tx[i],
                rx_data_packets: w.rx[i],
            })
        }
        fn open_probe(&mut self, slot: Slot) -> io::Result<(Socket, String)> {
            self.0.borrow_mut().events.push(format!("probe {slot:?}"));
            Ok((
                Socket {
                    world: self.0.clone(),
                    slot,
                    query: vec![],
                    replied: false,
                },
                "example.com".into(),
            ))
        }
        fn select_active(&mut self, _: &SessionScope, slot: Slot) -> io::Result<()> {
            self.0.borrow_mut().events.push(format!("select {slot:?}"));
            Ok(())
        }
        fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
            let mut w = self.0.borrow_mut();
            w.events.push("close".into());
            w.closed.push(scope.clone());
            if w.fail_close {
                return Err(io::Error::other("private close"));
            }
            w.native = [false; 2];
            Ok(())
        }
    }
    impl PairControl for Native {
        fn complete_start(&mut self, scope: &SessionScope) -> io::Result<()> {
            assert_eq!(self.0.borrow().saved.last().unwrap().scope, *scope);
            self.check_integrity()
        }
        fn start_primary(
            &mut self,
            scope: &SessionScope,
            member: &Member,
            _: &DesktopTunnelOptions,
        ) -> io::Result<()> {
            let mut w = self.0.borrow_mut();
            let saved = w.saved.last().unwrap();
            assert_eq!(saved.phase, SessionPhase::Starting);
            assert_eq!(&saved.scope, scope);
            w.events.push("primary".into());
            w.native[index(member.slot)] = true;
            if w.fail_start {
                Err(io::Error::other("private start"))
            } else {
                Ok(())
            }
        }
        fn attach(&mut self, _: &SessionScope, member: &Member) -> io::Result<()> {
            let mut w = self.0.borrow_mut();
            w.events.push("attach".into());
            w.native[index(member.slot)] = true;
            Ok(())
        }
        fn remove_standby(&mut self, _: &SessionScope, slot: Slot) -> io::Result<()> {
            self.0.borrow_mut().native[index(slot)] = false;
            Ok(())
        }
        fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
            let mut w = self.0.borrow_mut();
            w.events.push("pair rebind".into());
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
            w.residual || (w.fail_close && w.native.iter().any(|v| *v))
        }
        fn metrics(&self, slot: Slot) -> io::Result<TunnelMetrics> {
            let mut w = self.0.borrow_mut();
            w.events.push(format!("pair metrics {slot:?}"));
            if w.fail_diagnostics {
                Err(io::Error::other("private metrics"))
            } else {
                Ok(metric(100 + index(slot) as u64))
            }
        }
        fn physical_network_fingerprint(&self) -> io::Result<String> {
            let mut w = self.0.borrow_mut();
            w.events.push("pair fingerprint".into());
            if w.fingerprint_unsupported {
                return Err(io::ErrorKind::Unsupported.into());
            }
            if w.fail_diagnostics {
                Err(io::Error::other("private fingerprint"))
            } else {
                Ok(w.fingerprint.clone().unwrap_or_else(|| "ab".repeat(32)))
            }
        }
    }
    struct Store(Shared);
    impl SessionStore for Store {
        fn save(&mut self, s: &SessionSnapshot) -> io::Result<()> {
            let mut w = self.0.borrow_mut();
            w.events.push(format!("save {:?}", s.phase));
            if w.fail_save {
                return Err(io::Error::other("private disk"));
            }
            w.saved.push(s.clone());
            if w.lose_running_ack && s.phase == SessionPhase::Running {
                w.lose_running_ack = false;
                return Err(io::Error::other("lost save ACK"));
            }
            Ok(())
        }
    }
    struct Factory(Shared);
    impl PairFactory for Factory {
        type Native = Native;
        type Store = Store;
        fn recover(&mut self, runtime: RuntimeSlot) -> Result<(), ServiceError> {
            let mut w = self.0.borrow_mut();
            w.events.push("recover".into());
            w.recovered.push(runtime);
            if w.fail_recover {
                Err(ServiceError::Backend("private recover".into()))
            } else {
                w.native = [false; 2];
                Ok(())
            }
        }
        fn prepare(
            &mut self,
            runtime: RuntimeSlot,
            command: &Command,
            now: u64,
        ) -> io::Result<SessionControl<Native, Store>> {
            {
                let mut w = self.0.borrow_mut();
                w.events.push("prepare".into());
                w.prepared.push((runtime, now));
                if w.fail_prepare || w.saved.iter().any(|s| &s.scope == command.scope()) {
                    return Err(io::Error::other("private factory/reused scope"));
                }
            }
            SessionControl::prepare(
                runtime,
                command,
                Native(self.0.clone()),
                Store(self.0.clone()),
                now,
            )
        }
    }
    type Actor = CompositeBackend<Single, Factory>;
    fn setup() -> (Actor, Shared) {
        let w = Rc::new(RefCell::new(World::default()));
        let actor = Actor::new(RuntimeSlot::Latest, Single(w.clone()), Factory(w.clone())).unwrap();
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
    fn member(slot: Slot) -> Member {
        Member {
            slot,
            lease_id: if slot == Slot::A {
                "aaaaaaaa-0000-4000-8000-000000000001"
            } else {
                "bbbbbbbb-0000-4000-8000-000000000002"
            }
            .into(),
            configuration: TunnelConfiguration::new("fake private config".into()),
            probe: RedundantHealthProbe {
                kind: HealthProbeKind::DnsA,
                target_ipv4: "9.9.9.9".parse().unwrap(),
                query_name: "example.com".into(),
                timeout_ms: 2000,
            },
        }
    }
    fn start(scope: SessionScope) -> Command {
        Command::Start {
            scope,
            primary: member(Slot::A),
            role_generation: 0,
            membership_generation: 0,
            warm_stop_v1: true,
            options: DesktopTunnelOptions::default(),
        }
    }
    fn single_start(a: &mut Actor) -> Result<ServiceTunnelState, ServiceError> {
        a.start(
            "single fake config",
            &DesktopTunnelOptions::default(),
            TunnelTransport::WireGuard,
        )
    }
    fn attach(a: &mut Actor) {
        let s = a.current_redundancy_snapshot().unwrap().session;
        a.redundant(Command::Attach {
            scope: s.scope,
            member: member(Slot::B),
            expected_revision: s.local_revision,
            expected_network_epoch: s.network_epoch,
            expected_membership_generation: s.membership_generation,
            membership_generation: s.membership_generation,
        })
        .unwrap();
    }

    #[test]
    fn construction_recovers_authenticated_runtime_once_and_never_adopts() {
        let w = Rc::new(RefCell::new(World {
            native: [true, true],
            ..Default::default()
        }));
        let mut a = Actor::new(RuntimeSlot::Stable, Single(w.clone()), Factory(w.clone())).unwrap();
        assert_eq!(w.borrow().recovered, [RuntimeSlot::Stable]);
        assert_eq!(w.borrow().native, [false, false]);
        assert!(a.current_redundancy_snapshot().is_none());
        a.tick(1).unwrap();
        assert_eq!(w.borrow().recovered.len(), 1);
        w.borrow_mut().fail_recover = true;
        assert!(Actor::new(RuntimeSlot::Latest, Single(w.clone()), Factory(w.clone())).is_err());
    }
    #[test]
    fn primary_is_journaled_before_native_at_latest_actor_time() {
        let (mut a, w) = setup();
        a.tick(4000).unwrap();
        w.borrow_mut().events.clear();
        let s = a.redundant(start(scope())).unwrap();
        assert_eq!(s.session.phase, SessionPhase::Running);
        assert_eq!(w.borrow().prepared, [(RuntimeSlot::Latest, 4000)]);
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
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Starting);
        a.tick(4000).unwrap();
        a.tick(4100).unwrap();
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Running);
    }
    #[test]
    fn runtime_and_invalid_scope_rejected_before_single_or_factory() {
        let (mut a, w) = setup();
        w.borrow_mut().events.clear();
        let mut wrong = scope();
        wrong.runtime = RuntimeSlot::Stable;
        assert!(a.redundant(start(wrong)).is_err());
        let mut wrong = scope();
        wrong.runtime_generation = 0;
        assert!(a.redundant(start(wrong)).is_err());
        assert!(w.borrow().events.is_empty());
    }
    #[test]
    fn running_or_unqueryable_single_blocks_pair_preparation() {
        for state in [
            ServiceTunnelState::Running,
            ServiceTunnelState::Starting,
            ServiceTunnelState::Stopping,
            ServiceTunnelState::Failed,
        ] {
            let (mut a, w) = setup();
            w.borrow_mut().events.clear();
            w.borrow_mut().single = state;
            assert!(a.redundant(start(scope())).is_err());
            assert_eq!(w.borrow().events, ["single status"]);
        }
        let (mut a, w) = setup();
        w.borrow_mut().events.clear();
        w.borrow_mut().fail_status = true;
        assert!(a.redundant(start(scope())).is_err());
        assert_eq!(w.borrow().events, ["single status"]);
    }
    #[test]
    fn native_failures_keep_safe_stage_without_private_error_text() {
        let (mut actor, world) = setup();
        world.borrow_mut().fail_prepare = true;
        let error = actor.redundant(start(scope())).unwrap_err().to_string();
        assert!(error.contains("stage=prepare"), "{error}");
        assert!(!error.contains("private"), "{error}");
        world.borrow_mut().fail_prepare = false;
        world.borrow_mut().fail_start = true;
        let error = actor.redundant(start(scope())).unwrap_err().to_string();
        assert!(error.contains("stage=start"), "{error}");
        assert!(!error.contains("private"), "{error}");
        world.borrow_mut().fail_close = true;
        let error = actor
            .redundant(Command::Stop { scope: scope() })
            .unwrap_err();
        assert_eq!(error.code(), "redundant_actor_failed");
        assert!(error.to_string().contains("stage=stop"));
        assert!(!error.to_string().contains("private"));
    }
    #[test]
    fn failed_native_start_retains_owner_and_exact_shutdown_retry() {
        let (mut a, w) = setup();
        w.borrow_mut().fail_start = true;
        w.borrow_mut().fail_close = true;
        assert!(!a
            .redundant(start(scope()))
            .unwrap_err()
            .to_string()
            .contains("private"));
        assert!(a.current_redundancy_snapshot().unwrap().cleanup_pending);
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Stopping);
        w.borrow_mut().events.clear();
        assert!(single_start(&mut a).is_err());
        assert!(a.stop().is_err());
        assert!(a.rebind_udp().is_err());
        assert!(a.redundant(start(scope())).is_err());
        assert!(w.borrow().events.is_empty());
        w.borrow_mut().fail_close = false;
        assert_eq!(a.shutdown().unwrap(), ServiceTunnelState::Stopped);
        assert_eq!(w.borrow().closed, [scope(), scope()]);
        assert_eq!(w.borrow().native, [false, false]);
        assert!(!w.borrow().events.iter().any(|e| e.starts_with("single")));
    }
    #[test]
    fn lost_running_save_ack_keeps_failed_owner_until_cleanup() {
        let (mut a, w) = setup();
        w.borrow_mut().lose_running_ack = true;
        w.borrow_mut().fail_close = true;
        assert!(a.redundant(start(scope())).is_err());
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Stopping);
        assert!(a.current_redundancy_snapshot().unwrap().cleanup_pending);
        w.borrow_mut().fail_close = false;
        a.shutdown().unwrap();
        assert_eq!(w.borrow().native, [false, false]);
    }
    #[test]
    fn duplicate_foreign_and_stale_scope_never_repeat_effects() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        w.borrow_mut().events.clear();
        let mut other = scope();
        other.connection_generation += 1;
        for command in [
            start(scope()),
            start(other.clone()),
            Command::Stop {
                scope: other.clone(),
            },
            Command::Status {
                scope: other.clone(),
            },
            Command::NetworkChanged { scope: other },
        ] {
            assert!(a.redundant(command).is_err());
        }
        assert!(w.borrow().events.is_empty());
        assert_eq!(
            a.current_redundancy_snapshot().unwrap().session.scope,
            scope()
        );
    }
    #[test]
    fn singleton_operations_are_fenced_but_readonly_defender_delegates() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        w.borrow_mut().events.clear();
        assert!(single_start(&mut a).is_err());
        assert!(a.stop().is_err());
        assert!(a.rebind_udp().is_err());
        assert!(a.diagnostics().is_err());
        assert_eq!(a.metrics(true).unwrap().received_bytes, 100);
        assert_eq!(a.physical_network_fingerprint().unwrap(), "ab".repeat(32));
        assert_eq!(
            a.defender_status().unwrap().state,
            DefenderExclusionState::Excluded
        );
        assert_eq!(
            w.borrow().events,
            ["pair metrics A", "pair fingerprint", "defender"]
        );
    }
    #[test]
    fn diagnostics_error_or_stopping_never_falls_back_to_single() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        w.borrow_mut().fail_diagnostics = true;
        w.borrow_mut().events.clear();
        for e in [
            a.metrics(false).unwrap_err(),
            a.physical_network_fingerprint().unwrap_err(),
        ] {
            assert!(!e.to_string().contains("private"));
        }
        assert_eq!(w.borrow().events, ["pair metrics A", "pair fingerprint"]);
        a.redundant(Command::PrepareStop { scope: scope() })
            .unwrap();
        w.borrow_mut().events.clear();
        assert!(a.metrics(false).is_err());
        assert!(a.physical_network_fingerprint().is_err());
        assert!(w.borrow().events.is_empty());
    }
    #[test]
    fn ticks_promote_without_ui_and_metrics_follow_actual_active() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        attach(&mut a);
        a.tick(0).unwrap();
        a.tick(100).unwrap();
        w.borrow_mut().dead[0] = true;
        for now in (200..=3500).step_by(100) {
            a.tick(now).unwrap();
        }
        assert_eq!(
            a.current_redundancy_snapshot().unwrap().session.active,
            Slot::B
        );
        assert_eq!(a.metrics(true).unwrap().received_bytes, 101);
        assert!(w.borrow().events.iter().any(|e| e == "select B"));
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e.starts_with("single tick")));
    }
    #[test]
    fn tick_deadline_closes_prepared_pair_and_backward_time_retains_cleanup() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        attach(&mut a);
        a.tick(100).unwrap();
        a.redundant(Command::PrepareStop { scope: scope() })
            .unwrap();
        a.tick(1099).unwrap();
        assert!(w.borrow().closed.is_empty());
        a.tick(1100).unwrap();
        assert_eq!(w.borrow().closed, [scope()]);
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Stopped);
        let (mut a, w) = setup();
        a.tick(1000).unwrap();
        a.redundant(start(scope())).unwrap();
        w.borrow_mut().fail_close = true;
        assert!(a.tick(999).is_err());
        assert!(a.current_redundancy_snapshot().unwrap().cleanup_pending);
        w.borrow_mut().fail_close = false;
        a.shutdown().unwrap();
        let mut next = scope();
        next.connection_generation += 1;
        a.redundant(start(next)).unwrap();
        assert_eq!(w.borrow().prepared.last().unwrap().1, 1000);
    }
    #[test]
    fn cached_private_snapshot_status_never_queries_legacy_and_plain_backend_stays_unsupported() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        let expected = a.current_redundancy_snapshot();
        w.borrow_mut().events.clear();
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Starting);
        assert_eq!(a.current_redundancy_snapshot(), expected);
        assert!(w.borrow().events.is_empty());
        assert!(!Single(w).supports_redundancy());
    }
    #[test]
    fn terminal_scope_cannot_restart_but_different_scope_or_single_can() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        a.shutdown().unwrap();
        w.borrow_mut().events.clear();
        assert!(a.redundant(start(scope())).is_err());
        assert!(w.borrow().events.is_empty());
        let mut next = scope();
        next.connection_generation += 1;
        a.redundant(start(next)).unwrap();
        a.shutdown().unwrap();
        assert_eq!(single_start(&mut a).unwrap(), ServiceTunnelState::Running);
        assert!(a.current_redundancy_snapshot().is_none());
        assert_eq!(a.shutdown().unwrap(), ServiceTunnelState::Stopped);
        assert!(a.redundant(start(scope())).is_err()); // durable factory still rejects reuse after single mode
    }
    #[test]
    fn terminal_residual_cleanup_blocks_single_replacement_and_shutdown_success() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        w.borrow_mut().residual = true;
        assert!(a.shutdown().is_err());
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Stopping);
        let mut next = scope();
        next.connection_generation += 1;
        assert!(a.redundant(start(next)).is_err());
        assert!(single_start(&mut a).is_err());
        w.borrow_mut().residual = false;
        assert_eq!(a.shutdown().unwrap(), ServiceTunnelState::Stopped);
    }
    #[test]
    fn no_pair_preserves_single_signatures_and_prepare_failure_cannot_start_native() {
        let (mut a, w) = setup();
        a.tick(100).unwrap();
        assert_eq!(single_start(&mut a).unwrap(), ServiceTunnelState::Running);
        assert_eq!(a.metrics(true).unwrap().received_bytes, 99);
        a.rebind_udp().unwrap();
        a.diagnostics().unwrap();
        a.physical_network_fingerprint().unwrap();
        assert_eq!(a.shutdown().unwrap(), ServiceTunnelState::Stopped);
        w.borrow_mut().fail_prepare = true;
        w.borrow_mut().events.clear();
        assert!(!a
            .redundant(start(scope()))
            .unwrap_err()
            .to_string()
            .contains("private"));
        assert_eq!(w.borrow().events, ["single status", "prepare"]);
        assert!(a.current_redundancy_snapshot().is_none());
        w.borrow_mut().fail_prepare = false;
        w.borrow_mut().fail_save = true;
        assert!(a.redundant(start(scope())).is_err());
        assert!(!w.borrow().events.iter().any(|e| e == "primary"));
    }

    #[test]
    fn shutdown_clears_both_members_without_legacy_global_stop() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        attach(&mut a);
        assert_eq!(w.borrow().native, [true, true]);
        w.borrow_mut().events.clear();
        assert_eq!(a.shutdown().unwrap(), ServiceTunnelState::Stopped);
        assert_eq!(w.borrow().native, [false, false]);
        assert_eq!(w.borrow().closed, [scope()]);
        assert!(!w.borrow().events.iter().any(|e| e.starts_with("single")));
        w.borrow_mut().events.clear();
        assert_eq!(a.stop().unwrap(), ServiceTunnelState::Stopped);
        assert!(w.borrow().events.is_empty());
    }

    #[test]
    fn restart_is_cleanup_only_and_factory_durably_rejects_old_scope() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        attach(&mut a);
        drop(a); // no hidden native cleanup/destructor
        assert_eq!(w.borrow().native, [true, true]);
        let mut a = Actor::new(RuntimeSlot::Latest, Single(w.clone()), Factory(w.clone())).unwrap();
        assert_eq!(w.borrow().native, [false, false]);
        assert!(a.current_redundancy_snapshot().is_none());
        assert!(a.redundant(start(scope())).is_err());
        assert_eq!(a.status().unwrap(), ServiceTunnelState::Stopped);
    }

    #[test]
    fn no_pair_scoped_stop_or_backwards_tick_never_reaches_single() {
        let (mut a, w) = setup();
        a.tick(100).unwrap();
        w.borrow_mut().events.clear();
        assert!(a.redundant(Command::Stop { scope: scope() }).is_err());
        assert!(a.tick(99).is_err());
        assert!(w.borrow().events.is_empty());
        a.redundant(start(scope())).unwrap();
        assert_eq!(w.borrow().prepared.last().unwrap().1, 100);
        a.tick(100).unwrap();
        let tx = w.borrow().tx;
        a.tick(100).unwrap();
        assert_eq!(w.borrow().tx, tx);
    }

    fn snapshot(a: &Actor) -> Snapshot {
        a.current_redundancy_snapshot().unwrap()
    }
    fn has_health_event(events: &[String]) -> bool {
        events
            .iter()
            .any(|e| e.starts_with("sample ") || e.starts_with("probe ") || e == "receive probe")
    }

    #[test]
    fn physical_sample_runs_every_two_seconds_before_health_without_gui() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        w.borrow_mut().hold_replies = true;
        a.tick(0).unwrap();
        let epoch = snapshot(&a).session.network_epoch;
        w.borrow_mut().fingerprint = Some("cd".repeat(32));
        w.borrow_mut().events.clear();
        a.tick(1999).unwrap();
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e == "pair fingerprint" || e == "pair rebind"));
        w.borrow_mut().events.clear();
        a.tick(2000).unwrap();
        let events = w.borrow().events.clone();
        assert_eq!(events[0], "pair fingerprint");
        let rebind = events.iter().position(|e| e == "pair rebind").unwrap();
        assert!(events[..rebind].iter().any(|e| e == "drop probe"));
        assert!(events[..rebind].iter().any(|e| e == "save Running"));
        assert!(!has_health_event(&events[..rebind]));
        assert_eq!(w.borrow().rebind_scopes, [scope()]);
        assert_eq!(snapshot(&a).session.network_epoch, epoch + 2);
        a.tick(4000).unwrap();
        assert_eq!(w.borrow().rebind_scopes.len(), 1);
    }

    #[test]
    fn failed_or_malformed_discovery_invalidates_once_and_fresh_same_value_rebinds() {
        for invalid in [
            None,
            Some(String::new()),
            Some("AB".repeat(32)),
            Some("z".repeat(64)),
        ] {
            let (mut a, w) = setup();
            a.redundant(start(scope())).unwrap();
            a.tick(0).unwrap();
            let epoch = snapshot(&a).session.network_epoch;
            w.borrow_mut().fail_diagnostics = invalid.is_none();
            w.borrow_mut().fingerprint = invalid;
            w.borrow_mut().events.clear();
            a.tick(2000).unwrap();
            assert_eq!(snapshot(&a).session.network_epoch, epoch + 1);
            assert!(
                !snapshot(&a).primary_ready
                    && !snapshot(&a).standby_ready
                    && !snapshot(&a).standby_failed
            );
            assert!(w.borrow().events.iter().any(|e| e == "drop probe"));
            assert!(!has_health_event(&w.borrow().events));
            assert!(w.borrow().closed.is_empty());
            assert!(w.borrow().rebind_scopes.is_empty());
            w.borrow_mut().events.clear();
            a.tick(3999).unwrap();
            assert!(w.borrow().events.is_empty());
            a.tick(4000).unwrap();
            assert_eq!(snapshot(&a).session.network_epoch, epoch + 1);
            w.borrow_mut().fail_diagnostics = false;
            w.borrow_mut().fingerprint = None;
            a.tick(6000).unwrap();
            assert_eq!(w.borrow().rebind_scopes, [scope()]);
            assert_eq!(snapshot(&a).session.network_epoch, epoch + 3);
            assert!(w.borrow().closed.is_empty());
        }
    }

    #[test]
    fn failed_or_unvalidated_physical_rebind_suspends_health_and_retries_next_sample() {
        for fail in [false, true] {
            let (mut a, w) = setup();
            a.redundant(start(scope())).unwrap();
            a.tick(0).unwrap();
            w.borrow_mut().fingerprint = Some("cd".repeat(32));
            w.borrow_mut().fail_rebind = fail;
            w.borrow_mut().unvalidated_rebind = !fail;
            w.borrow_mut().events.clear();
            a.tick(2000).unwrap();
            assert!(!has_health_event(&w.borrow().events));
            assert!(w.borrow().closed.is_empty());
            assert_eq!(w.borrow().rebind_scopes, [scope()]);
            a.tick(3999).unwrap();
            assert_eq!(w.borrow().rebind_scopes.len(), 1);
            w.borrow_mut().fail_rebind = false;
            w.borrow_mut().unvalidated_rebind = false;
            a.tick(4000).unwrap();
            assert_eq!(w.borrow().rebind_scopes, [scope(), scope()]);
            a.tick(6000).unwrap();
            assert_eq!(w.borrow().rebind_scopes.len(), 2);
            assert!(!w
                .borrow()
                .events
                .iter()
                .any(|e| e == "single rebind" || e == "close"));
        }
    }

    #[test]
    fn first_failed_sample_blocks_health_but_never_supported_hook_is_optional() {
        for unsupported in [false, true] {
            let (mut a, w) = setup();
            a.redundant(start(scope())).unwrap();
            w.borrow_mut().fingerprint_unsupported = unsupported;
            w.borrow_mut().fail_diagnostics = !unsupported;
            w.borrow_mut().events.clear();
            a.tick(0).unwrap();
            assert_eq!(has_health_event(&w.borrow().events), unsupported);
            w.borrow_mut().fingerprint_unsupported = false;
            w.borrow_mut().fail_diagnostics = false;
            a.tick(2000).unwrap();
            assert_eq!(w.borrow().rebind_scopes.len(), usize::from(!unsupported));
            let epoch = snapshot(&a).session.network_epoch;
            w.borrow_mut().fingerprint_unsupported = true;
            w.borrow_mut().events.clear();
            a.tick(4000).unwrap();
            assert_eq!(snapshot(&a).session.network_epoch, epoch + 1);
            assert!(!has_health_event(&w.borrow().events));
            assert!(w.borrow().closed.is_empty());
        }
    }

    #[test]
    fn physical_invalidation_save_failure_propagates_and_closes_exact_pair() {
        for discovery_error in [false, true] {
            let (mut a, w) = setup();
            a.redundant(start(scope())).unwrap();
            a.tick(0).unwrap();
            w.borrow_mut().fail_save = true;
            w.borrow_mut().fail_diagnostics = discovery_error;
            w.borrow_mut().fingerprint = Some("cd".repeat(32));
            w.borrow_mut().events.clear();
            assert!(a.tick(2000).is_err());
            assert_eq!(w.borrow().closed, [scope()]);
            assert!(!has_health_event(&w.borrow().events));
            assert!(w.borrow().rebind_scopes.is_empty());
            assert_eq!(snapshot(&a).session.phase, SessionPhase::Stopped);
        }
    }

    #[test]
    fn physical_rebind_retains_shared_four_second_failover_suppression() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        attach(&mut a);
        a.tick(0).unwrap();
        a.tick(100).unwrap();
        w.borrow_mut().fingerprint = Some("cd".repeat(32));
        w.borrow_mut().dead[0] = true;
        a.tick(2000).unwrap();
        for now in (2100..6000).step_by(100) {
            a.tick(now).unwrap();
        }
        assert_eq!(snapshot(&a).session.active, Slot::A);
        for now in (6000..=8500).step_by(100) {
            a.tick(now).unwrap();
        }
        assert_eq!(snapshot(&a).session.active, Slot::B);
        assert_eq!(w.borrow().rebind_scopes, [scope()]);
    }

    #[test]
    fn physical_cache_resets_on_stop_and_new_scope_and_backward_tick_skips_discovery() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        a.tick(0).unwrap();
        a.redundant(Command::PrepareStop { scope: scope() })
            .unwrap();
        w.borrow_mut().events.clear();
        a.tick(500).unwrap();
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e == "pair fingerprint" || e == "pair rebind"));
        a.shutdown().unwrap();
        let mut next = scope();
        next.connection_generation += 1;
        a.redundant(start(next)).unwrap();
        w.borrow_mut().fingerprint = Some("cd".repeat(32));
        w.borrow_mut().events.clear();
        a.tick(600).unwrap();
        assert!(w.borrow().events.iter().any(|e| e == "pair fingerprint"));
        assert!(w.borrow().rebind_scopes.is_empty());
        w.borrow_mut().events.clear();
        assert!(a.tick(599).is_err());
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e == "pair fingerprint" || e == "pair rebind"));
    }

    #[test]
    fn retire_inactive_request_equality_checks_every_exact_fence_and_variant() {
        let make = || Command::RetireInactive {
            scope: scope(),
            slot: Slot::B,
            lease_id: member(Slot::B).lease_id,
            expected_revision: 2,
            expected_network_epoch: 1,
            expected_membership_generation: 3,
        };
        assert!(crate::redundant_command_eq(&make(), &make()));
        for field in 0..9 {
            let mut wrong = make();
            let Command::RetireInactive {
                scope,
                slot,
                lease_id,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
            } = &mut wrong
            else {
                unreachable!()
            };
            match field {
                0 => scope.runtime = RuntimeSlot::Stable,
                1 => scope.runtime_generation += 1,
                2 => scope.session_id = "22222222-2222-4222-8222-222222222222".into(),
                3 => scope.connection_generation += 1,
                4 => *slot = Slot::A,
                5 => *lease_id = member(Slot::A).lease_id,
                6 => *expected_revision += 1,
                7 => *expected_network_epoch += 1,
                _ => *expected_membership_generation += 1,
            }
            assert!(
                !crate::redundant_command_eq(&make(), &wrong),
                "field {field}"
            );
            assert!(
                !crate::redundant_command_eq(&wrong, &make()),
                "field {field}"
            );
        }
        let remove = Command::RemoveStandby {
            scope: scope(),
            slot: Slot::B,
            lease_id: member(Slot::B).lease_id,
            expected_revision: 2,
            expected_network_epoch: 1,
            expected_membership_generation: 3,
        };
        assert!(!crate::redundant_command_eq(&make(), &remove));
        assert!(!crate::redundant_command_eq(&remove, &make()));
    }

    #[test]
    fn canonical_current_map_survives_inactive_native_retirement() {
        let (mut a, w) = setup();
        a.redundant(start(scope())).unwrap();
        attach(&mut a);
        let before = snapshot(&a);
        assert_eq!(before.current_leases, before.leases);
        assert!(!before.standby_failed);
        let s = before.session;
        let retired = a
            .redundant(Command::RetireInactive {
                scope: s.scope,
                slot: Slot::B,
                lease_id: member(Slot::B).lease_id,
                expected_revision: s.local_revision,
                expected_network_epoch: s.network_epoch,
                expected_membership_generation: s.membership_generation,
            })
            .unwrap();
        assert_eq!(retired.current_leases, before.current_leases);
        assert_eq!(retired.leases, [before.leases[0].clone(), None]);
        assert!(!retired.standby_failed);
        assert_eq!(w.borrow().native, [true, false]);
    }
}
