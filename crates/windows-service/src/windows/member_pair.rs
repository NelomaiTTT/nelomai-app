//! Native assembly used by the engine's CompositeBackend.
//! Construction accepts an authenticated service layout
//! and protected record adapter, never paths or runtime authority from IPC.
use super::{
    member_files::MemberFiles, member_guard::NativeGuard, member_metrics::MemberMetrics,
    member_owner::NativeMemberIo, member_routes::NativeRowIo, member_session::*,
};
use crate::{
    member_actor::PairFactory,
    member_diagnostic::{context, PairFailure},
    member_dns::{self, Identity, Ownership},
    member_guard::{ExchangePlan, GuardStore, Model, ProbeTuple, SplitEngines},
    member_owner::{Journal, MemberOwner, Phase, Record as OwnerRecord},
    member_pair::*,
    member_physical::{Family, InterfaceIdentity, PhysicalProof, PhysicalRoute, PhysicalSnapshot},
    member_plan::{member_route_plan, InterfaceMetric},
    member_routes::{IdentityCheck, MemberRoutes, NativeProof, Row, RowIo},
};
use nelomai_client_tunnel::{
    detect_configuration_transport,
    redundancy::{
        control::SessionControl,
        driver::{NativePair as _, SessionStore},
        evidence::NativeHealthSample,
        network::{
            NetworkJournalStore, NetworkOwner, NetworkSystem, NetworkValue, ResourceKey,
            RouteScope, RouteValue,
        },
        protocol::{Command, Member},
        NativeProbeSocket, SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelMetrics,
};
use nelomai_contracts::RuntimeSlot;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};

type Owner = MemberOwner<MemberFiles, NativeMemberIo<MemberFiles>>;
#[derive(Clone)]
struct Proofs {
    members: [Option<MemberRecord>; 2],
    physical: Vec<PhysicalLease>,
}
#[derive(Clone)]
struct Identities(Rc<RefCell<Proofs>>);
impl IdentityCheck for Identities {
    fn verify(&mut self, index: u32) -> io::Result<NativeProof> {
        let proofs = self.0.borrow();
        if let Some(m) = proofs
            .members
            .iter()
            .flatten()
            .find(|m| m.owner.proof.is_some_and(|p| p.interface.index == index))
        {
            verify_record(m)?;
            let p = m.owner.proof.ok_or_else(failed)?;
            return Ok(NativeProof {
                index,
                luid: p.interface.luid,
            });
        }
        let p = proofs
            .physical
            .iter()
            .find(|p| p.interface == index)
            .ok_or_else(failed)?;
        let actual = super::member_physical::read_identity(index)?;
        if actual
            != (InterfaceIdentity {
                index,
                luid: p.luid,
                guid: p.guid,
            })
        {
            return Err(failed());
        }
        Ok(NativeProof {
            index,
            luid: p.luid,
        })
    }
}
struct RouteStore<F: SessionFiles> {
    store: Rc<RefCell<ProtectedStore<F, NativeNetworkRecord>>>,
    proofs: Identities,
}
impl<F: SessionFiles> NetworkJournalStore for RouteStore<F> {
    fn save(
        &mut self,
        journal: &nelomai_client_tunnel::redundancy::network::NetworkJournal,
    ) -> io::Result<()> {
        self.store.borrow_mut().save_value(&NativeNetworkRecord {
            journal: journal.clone(),
            physical: self.proofs.0.borrow().physical.clone(),
        })
    }
}
struct CheckedRows {
    rows: MemberRoutes<NativeRowIo, Identities>,
    proofs: Identities,
}
impl CheckedRows {
    fn absent_member(&self, key: &ResourceKey) -> io::Result<bool> {
        let ResourceKey::Route(_, RouteScope::WindowsInterface(index)) = key else {
            return Err(failed());
        };
        let member = self
            .proofs
            .0
            .borrow()
            .members
            .iter()
            .flatten()
            .find(|m| {
                m.owner
                    .proof
                    .or(m.owner.retired_proof)
                    .is_some_and(|p| p.interface.index == *index)
            })
            .cloned();
        match member {
            Some(m) => retained_owner(&m)?
                .confirm_absent(&m.owner)
                .map_err(|_| failed()),
            None => Ok(false),
        }
    }
}
impl NetworkSystem for CheckedRows {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        if self.absent_member(key)? {
            return crate::member_routes::read_absent_route(&mut NativeRowIo, key, || {
                self.absent_member(key)
            });
        }
        self.rows.read(key)
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        if self.absent_member(key)? {
            if before.is_none() && after.is_none() && self.read(key)?.is_none() {
                return Ok(());
            }
            return Err(failed());
        }
        self.rows.compare_exchange(key, before, after)
    }
}
type Routes<F> = NetworkOwner<CheckedRows, RouteStore<F>>;
pub(crate) struct WindowsPairIo<F: SessionFiles> {
    scope: SessionScope,
    engine: PathBuf,
    runtime: Rc<tokio::runtime::Runtime>,
    owners: [Option<Owner>; 2],
    guard: NativeGuard,
    routes: Option<Routes<F>>,
    proofs: Identities,
    guard_reopen: bool,
    guard_read_failed: bool,
    files: F,
}
impl<F: SessionFiles> WindowsPairIo<F> {
    fn open(
        scope: SessionScope,
        engine: PathBuf,
        runtime: Rc<tokio::runtime::Runtime>,
        files: F,
        recovered: Option<&PairRecord>,
    ) -> io::Result<Self> {
        let (store, saved) = ProtectedStore::<F, NativeNetworkRecord>::open(
            files.clone(),
            scope.clone(),
            RecordKind::Network,
        )?;
        let saved = saved.unwrap_or_default();
        let members = recovered.map(|r| r.members.clone()).unwrap_or([None, None]);
        let proofs = Identities(Rc::new(RefCell::new(Proofs {
            members,
            physical: saved.physical,
        })));
        let routes = NetworkOwner::recover(
            CheckedRows {
                rows: MemberRoutes::new(NativeRowIo, proofs.clone()),
                proofs: proofs.clone(),
            },
            RouteStore {
                store: Rc::new(RefCell::new(store)),
                proofs: proofs.clone(),
            },
            saved.journal,
        )?;
        let guard =
            NativeGuard::open(scope.clone()).map_err(|e| PairFailure::guard("guard_open", e))?;
        let mut value = Self {
            scope,
            engine,
            runtime,
            owners: [None, None],
            guard,
            routes: Some(routes),
            proofs,
            guard_reopen: false,
            guard_read_failed: false,
            files,
        };
        if let Some(record) = recovered {
            for slot in [Slot::A, Slot::B] {
                if let Some(m) = &record.members[slot.idx()] {
                    if value.abandon_unstarted(m)? {
                        continue;
                    }
                    let mut files = MemberFiles::new().map_err(|_| failed())?;
                    let saved = files
                        .load(slot_native(slot))
                        .map_err(|_| failed())?
                        .ok_or_else(failed)?;
                    if saved.intent != m.owner.intent {
                        return Err(failed());
                    }
                    let io = NativeMemberIo::for_retained_cleanup(
                        &saved,
                        MemberFiles::new().map_err(|_| failed())?,
                    )
                    .map_err(|_| failed())?;
                    value.owners[slot.idx()] = Some(
                        MemberOwner::recover_for_cleanup(
                            value.scope.clone(),
                            slot_native(slot),
                            saved.intent.transport,
                            value.engine.clone(),
                            saved,
                            files,
                            io,
                        )
                        .map_err(|_| failed())?,
                    );
                }
            }
        }
        Ok(value)
    }
    fn owner(&mut self, m: &MemberRecord) -> io::Result<&mut Owner> {
        if m.owner.intent.scope != self.scope {
            return Err(failed());
        }
        self.owners[slot_shared(m.owner.intent.slot).idx()]
            .as_mut()
            .ok_or_else(failed)
    }
    fn sync_proofs(&mut self, members: &[Option<MemberRecord>; 2]) {
        for slot in [Slot::A, Slot::B] {
            if let Some(m) = &members[slot.idx()] {
                self.proofs.0.borrow_mut().members[slot.idx()] = Some(m.clone());
            }
        }
    }
    fn physical_snapshot(
        &mut self,
        members: &[Option<MemberRecord>; 2],
    ) -> io::Result<PhysicalSnapshot> {
        verify_physical_members(self, members)?;
        let snapshot = super::member_physical::capture(&owned(members))?;
        let proofs = self.proofs.0.borrow();
        let mut excluded = Vec::new();
        for route in self.routes.as_ref().ok_or_else(failed)?.excluded_routes() {
            if proofs.members.iter().flatten().any(|m| {
                m.owner
                    .proof
                    .or(m.owner.retired_proof)
                    .is_some_and(|p| p.interface.index == route.interface)
            }) {
                continue;
            }
            let retained = proofs
                .physical
                .iter()
                .find(|p| p.interface == route.interface)
                .ok_or_else(failed)?;
            let identity = super::member_physical::read_identity(route.interface)?;
            if identity
                != (InterfaceIdentity {
                    index: route.interface,
                    luid: retained.luid,
                    guid: retained.guid,
                })
            {
                return Err(failed());
            }
            excluded.push(crate::member_routes::Row::static_route(
                route,
                NativeProof {
                    index: identity.index,
                    luid: identity.luid,
                },
            ));
        }
        let snapshot = snapshot
            .without_owned_rows(&excluded)
            .map_err(|_| failed())?;
        drop(proofs);
        verify_physical_members(self, members)?;
        Ok(snapshot)
    }
}
impl<F: SessionFiles> PairIo for WindowsPairIo<F> {
    type Socket = NativeProbeSocket;
    fn prepare_member(&mut self, scope: &SessionScope, m: &Member) -> io::Result<MemberRecord> {
        if scope != &self.scope {
            return Err(failed());
        }
        if let Some(owner) = &mut self.owners[m.slot.idx()] {
            let retired = owner.snapshot().map_err(|_| failed())?.ok_or_else(failed)?;
            let (_, pair) =
                WindowsPairStore::open(self.files.clone(), scope.clone(), RecordKind::Pair)?;
            let routes = self.routes.as_ref().ok_or_else(failed)?;
            if routes.cleanup_pending() {
                return Err(failed());
            }
            let guard = GuardStore::snapshot(&mut self.guard, scope).map_err(|_| failed())?;
            verify_retired_slot(
                &retired,
                &pair.ok_or_else(failed)?,
                &routes.excluded_routes(),
                &guard,
            )?;
            if !owner.confirm_absent(&retired).map_err(|_| failed())? {
                return Err(failed());
            }
        }
        let p = MemberParameters::parse(m.configuration.expose())?;
        if !p
            .allowed
            .iter()
            .any(|n| n.contains(&IpAddr::V4(m.probe.target_ipv4)))
        {
            return Err(failed());
        }
        let transport = detect_configuration_transport(m.configuration.expose());
        let native = NativeMemberIo::from_trusted_factory(
            self.engine.clone(),
            slot_native(m.slot),
            transport,
            MemberFiles::new().map_err(|_| failed())?,
        )
        .map_err(|_| failed())?;
        let mut owner = MemberOwner::from_trusted_engine(
            scope.clone(),
            slot_native(m.slot),
            transport,
            self.engine.clone(),
            m.configuration.expose(),
            MemberFiles::new().map_err(|_| failed())?,
            native,
        )
        .map_err(|_| failed())?;
        let prior_stopped = owner.prior_stopped().map_err(|_| failed())?;
        let record = MemberRecord {
            prior_stopped,
            owner: OwnerRecord {
                intent: owner.intent().clone(),
                phase: Phase::Prepared,
                proof: None,
                retired_proof: None,
                previous_config_sha256: None,
            },
            source: p.source,
            endpoint: p.endpoint,
            allowed: p.allowed,
            dns: p.dns,
            probe: m.probe.clone(),
            peer: p.peer,
            started_epoch_ms: epoch_ms()?,
        };
        self.owners[m.slot.idx()] = Some(owner);
        Ok(record)
    }
    fn start(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
        self.owner(m)?
            .start_with_prior(m.prior_stopped.as_ref())
            .map_err(|e| PairFailure::owner("member_start", e))
    }
    fn abandon_unstarted(&mut self, m: &MemberRecord) -> io::Result<bool> {
        if m.owner.intent.scope != self.scope || m.owner.intent.engine != self.engine {
            return Err(failed());
        }
        let mut files = MemberFiles::new().map_err(|_| failed())?;
        let current = files.load(m.owner.intent.slot).map_err(|_| failed())?;
        if !matches_unstarted_prior(m, current.as_ref())? {
            return Ok(false);
        }
        let absent = if let Some(prior) = &current {
            let mut retained = m.clone();
            retained.owner = prior.clone();
            retained_owner(&retained)?
                .confirm_absent(prior)
                .map_err(|_| failed())?
        } else {
            let mut io = NativeMemberIo::from_trusted_factory(
                self.engine.clone(),
                m.owner.intent.slot,
                m.owner.intent.transport,
                MemberFiles::new().map_err(|_| failed())?,
            )
            .map_err(|_| failed())?;
            let observed = io.observe_unclaimed().map_err(|_| failed())?;
            observed.config_sha256.is_none()
                && observed.service.is_none()
                && !observed.alternative_service_present
                && observed.interface.is_none()
                && observed.retained_interfaces.is_empty()
        };
        if !absent || files.load(m.owner.intent.slot).map_err(|_| failed())? != current {
            return Err(failed());
        }
        self.proofs.0.borrow_mut().members[slot_shared(m.owner.intent.slot).idx()] = None;
        Ok(true)
    }
    fn current(&mut self, slot: Slot) -> io::Result<Option<OwnerRecord>> {
        let current = self.owners[slot.idx()]
            .as_mut()
            .ok_or_else(failed)?
            .snapshot()
            .map_err(|_| failed())?;
        if let (Some(m), Some(r)) = (
            &mut self.proofs.0.borrow_mut().members[slot.idx()],
            &current,
        ) {
            if m.owner.intent != r.intent {
                return Err(failed());
            }
            m.owner = r.clone();
        }
        Ok(current)
    }
    fn verify(&mut self, m: &MemberRecord) -> io::Result<()> {
        self.owner(m)?
            .verify_live(&m.owner)
            .map_err(|e| PairFailure::owner("member_verify", e))
    }
    fn verify_endpoint(&mut self, m: &MemberRecord) -> io::Result<()> {
        self.verify(m)?;
        if m.owner.intent.scope != self.scope {
            return Err(failed());
        }
        let routes = self.routes.as_ref().ok_or_else(failed)?;
        if routes.cleanup_pending() || routes.active().is_none() {
            return Err(failed());
        }
        let destination = ipnet::IpNet::from(m.endpoint);
        let mut expected = Vec::new();
        let physical = self.proofs.0.borrow().physical.clone();
        for route in routes
            .excluded_routes()
            .into_iter()
            .filter(|r| r.destination == destination)
        {
            // An endpoint exclusion must belong to an attested physical NIC,
            // never to either member. Native metadata is checked, not adopted.
            if let Some(p) = physical.iter().find(|p| p.interface == route.interface) {
                let row = Row::static_route(
                    route,
                    NativeProof {
                        index: p.interface,
                        luid: p.luid,
                    },
                );
                if !expected.contains(&row) {
                    expected.push(row);
                }
            }
        }
        if expected.is_empty() {
            // A preexisting exact physical host route is retained, never owned
            // or deleted. Its complete saved row remains the read-only proof.
            for p in physical
                .iter()
                .filter(|p| p.route.destination == destination)
            {
                let row = p.restore().row;
                if !expected.contains(&row) {
                    expected.push(row);
                }
            }
        }
        if expected.len() != 1 {
            return Err(failed());
        }
        let expected = &expected[0];
        let identity = self.proofs.verify(expected.route.interface)?;
        if identity.luid != expected.luid
            || NativeRowIo.read(destination, expected.route.interface)? != [expected.clone()]
        {
            return Err(failed());
        }
        let best = super::member_routes::best_route(m.endpoint)?;
        if best.route != expected.route
            || best.luid != expected.luid
            || self.proofs.verify(expected.route.interface)? != identity
        {
            return Err(failed());
        }
        self.verify(m)
    }
    fn confirm_absent(&mut self, m: &MemberRecord) -> io::Result<bool> {
        self.owner(m)?
            .confirm_absent(&m.owner)
            .map_err(|_| failed())
    }
    fn confirm_inactive_for_discovery(&mut self, m: &MemberRecord) -> io::Result<bool> {
        self.owner(m)?
            .confirm_inactive_for_discovery(&m.owner)
            .map_err(|_| failed())
    }
    fn stop(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
        let owner = self.owner(m)?;
        let current = owner.snapshot().map_err(|_| failed())?.ok_or_else(failed)?;
        if current.intent != m.owner.intent {
            return Err(failed());
        }
        owner
            .stop_best_effort(&current)
            .map_err(|e| PairFailure::owner("member_stop", e))
    }
    fn rebind(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
        self.owner(m)?
            .rebind(&m.owner)
            .map_err(|e| PairFailure::owner("member_rebind", e))
    }
    fn observe(&mut self, m: &MemberRecord) -> io::Result<(TunnelMetrics, NativeHealthSample)> {
        self.verify(m)?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(failed());
        }
        let metrics = MemberMetrics::capture_owned(
            m.owner.intent.slot,
            m.owner.intent.transport,
            m.owner.proof.ok_or_else(failed)?,
            m.peer,
            m.started_epoch_ms,
        )?;
        let sample = self.runtime.block_on(metrics.read())?;
        self.verify(m)?;
        let now = epoch_ms()?;
        let handshake_fresh = sample
            .transport
            .latest_handshake_epoch_millis
            .filter(|t| *t > 0)
            .and_then(|t| now.checked_sub(t))
            .is_some_and(|age| age <= 180_000);
        Ok((
            sample.transport,
            NativeHealthSample {
                admitted: true,
                closed: false,
                handshake_fresh,
                tx_packets: sample.sent_unicast_packets,
                rx_data_packets: sample.received_unicast_packets,
            },
        ))
    }
    fn fingerprint(&mut self, members: &[Option<MemberRecord>; 2]) -> io::Result<String> {
        let snapshot = self.physical_snapshot(members)?;
        let mut hash = Sha256::new();
        let mut found = false;
        for family in [Family::V4, Family::V6] {
            if let Some(path) = snapshot.default_route(family).map_err(|_| failed())? {
                found = true;
                hash.update(format!(
                    "{family:?}|{}|{}|{:?}|{}|{:?}|{};",
                    path.proof.identity.index,
                    path.proof.identity.luid,
                    path.proof.identity.guid,
                    path.proof.metric,
                    path.row.route.gateway,
                    path.row.route.metric
                ));
                let mut lan = snapshot
                    .rows()
                    .iter()
                    .filter(|r| {
                        r.route.interface == path.proof.identity.index
                            && r.route.gateway.is_none()
                            && r.route.destination.prefix_len() > 0
                            && Family::of(r.route.destination.addr()) == family
                    })
                    .map(|r| r.route.destination.to_string())
                    .collect::<Vec<_>>();
                lan.sort();
                lan.dedup();
                for n in lan {
                    hash.update(n);
                    hash.update(b";");
                }
            }
        }
        if !found {
            return Err(failed());
        }
        Ok(format!("{:x}", hash.finalize()))
    }
    fn open_base(&mut self, m: &MemberRecord) -> io::Result<(Self::Socket, ProbeTuple)> {
        self.verify(m)?;
        let proof = m.owner.proof.ok_or_else(failed)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        crate::member_source::wait_until_preferred(
            || {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                self.verify(m)?;
                source_readiness(m)
            },
            || {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(io::ErrorKind::TimedOut)?;
                std::thread::sleep(remaining.min(Duration::from_millis(50)));
                Ok(())
            },
        )?;
        let socket = NativeProbeSocket::open(proof.interface.index, m.source, m.probe.target_ipv4)?;
        self.verify(m)?;
        verify_source(m)?;
        let source = socket.local_addr()?;
        if source.ip() != IpAddr::V4(m.source) || source.port() == 0 {
            return Err(failed());
        }
        Ok((
            socket,
            ProbeTuple {
                source: source.ip(),
                source_port: source.port(),
                target: m.probe.target_ipv4.into(),
                target_port: 53,
                protocol: 17,
            },
        ))
    }
    fn guard_snapshot(&mut self) -> io::Result<crate::member_guard::Snapshot> {
        if self.guard_read_failed {
            // The first failure was already returned to the pair's sticky
            // fail-stop latch. A fresh read handle can prove cleanup after BFE
            // restarts; it never recreates filters or resumes the old pair.
            self.guard = NativeGuard::open(self.scope.clone())
                .map_err(|e| PairFailure::guard("guard_reopen", e))?;
            self.guard_read_failed = false;
            self.guard_reopen = false;
        }
        let result = GuardStore::snapshot(&mut self.guard, &self.scope)
            .map_err(|e| PairFailure::guard("guard_read", e));
        if result.is_err() {
            self.guard_read_failed = true;
        }
        result
    }
    fn guard_exchange(&mut self, p: &ExchangePlan) -> io::Result<Model> {
        if *p
            != ExchangePlan::new(&p.expected, &p.desired)
                .map_err(|e| PairFailure::guard("guard_plan", e))?
        {
            return Err(failed());
        }
        if self.guard_reopen {
            let mut replacement = NativeGuard::open(self.scope.clone())
                .map_err(|e| PairFailure::guard("guard_reopen", e))?;
            if GuardStore::snapshot(&mut replacement, &self.scope)
                .map_err(|e| PairFailure::guard("guard_read", e))?
                != p.expected.expected
            {
                return Err(failed());
            }
            self.guard = replacement;
            self.guard_reopen = false;
        }
        GuardStore::compare_exchange(&mut self.guard, &p.expected, &p.desired)
            .map_err(|e| PairFailure::guard("guard_apply", e))
    }
    fn close_permits(&mut self) -> io::Result<()> {
        SplitEngines::close_permits(&mut self.guard)
            .map_err(|e| PairFailure::guard("guard_close", e))?;
        self.guard_reopen = true;
        Ok(())
    }
    fn select_routes(
        &mut self,
        active: Slot,
        members: &[Option<MemberRecord>; 2],
        options: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        let live = live_route_members(self, active, members)?;
        let snapshot = self
            .physical_snapshot(members)
            .map_err(|e| context("physical_discovery", e))?;
        let (routes, physical) =
            plan(&snapshot, active, &live, options).map_err(|e| context("route_plan", e))?;
        self.sync_proofs(members);
        // Keep old physical identities too: removals/rollback must validate the
        // original interface, never authorize index reuse from a fresh discovery.
        {
            let mut proofs = self.proofs.0.borrow_mut();
            for p in &physical {
                if let Some(old) = proofs
                    .physical
                    .iter()
                    .find(|old| old.interface == p.interface)
                {
                    if old.luid != p.luid || old.guid != p.guid {
                        return Err(failed());
                    }
                }
                if !proofs.physical.contains(p) {
                    proofs.physical.push(p.clone());
                }
            }
        }
        // Old leases attest interface identity for deletion, not the continued
        // existence of the old gateway/default. New selection is independently
        // revalidated before any owned route additions below.
        for p in &physical {
            super::member_physical::verify(&p.restore(), &owned(members))
                .map_err(|e| context("physical_verify", e))?;
        }
        self.routes
            .as_mut()
            .ok_or_else(failed)?
            .select(
                active,
                routes.into_iter().map(NetworkValue::Route).collect(),
            )
            .map_err(|e| context("route_apply", e))?;
        let verified = live_route_members(self, active, members)?;
        // Also covers direct selections during standby retirement, not only
        // the common activate/rollback path in SessionNativePair::routes.
        for member in verified.iter().flatten() {
            self.verify_endpoint(member)
                .map_err(|e| context("endpoint_verify", e))?;
        }
        Ok(())
    }
    fn cleanup_routes(&mut self) -> io::Result<()> {
        let routes = self.routes.as_mut().ok_or_else(failed)?;
        routes.cleanup().map_err(|e| context("route_cleanup", e))?;
        // Cleanup is terminal for one NetworkOwner transaction lifetime. A
        // validated rebind may start another empty lifetime under the SAME
        // protected store, only after complete exact cleanup succeeded.
        let (system, mut store) = self.routes.take().ok_or_else(failed)?.into_parts();
        self.proofs.0.borrow_mut().physical.clear();
        let saved = store.save(&Default::default());
        self.routes = Some(NetworkOwner::fresh(system, store));
        saved
    }
    fn read_dns(&mut self, m: &MemberRecord) -> io::Result<member_dns::Snapshot> {
        let interface = dns_interface(m)?;
        super::member_dns::owned(interface, OwnedIdentity(m.clone()))
            .map_err(|e| PairFailure::dns("dns_open", e))?
            .snapshot()
            .map_err(|e| PairFailure::dns("dns_read", e))
    }
    fn exchange_dns(
        &mut self,
        before: &member_dns::Snapshot,
        after: &member_dns::Snapshot,
    ) -> io::Result<()> {
        let m = self
            .proofs
            .0
            .borrow()
            .members
            .iter()
            .flatten()
            .find(|m| {
                m.owner
                    .proof
                    .is_some_and(|p| p.interface.index == before.interface.index)
            })
            .cloned()
            .ok_or_else(failed)?;
        let interface = dns_interface(&m)?;
        if interface != before.interface || interface != after.interface {
            return Err(failed());
        }
        super::member_dns::owned(interface, OwnedIdentity(m))
            .map_err(|e| PairFailure::dns("dns_open", e))?
            .compare_exchange(before, after)
            .map_err(|e| PairFailure::dns("dns_apply", e))?;
        Ok(())
    }
}
fn epoch_ms() -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failed())?
            .as_millis(),
    )
    .map_err(|_| failed())
}
fn owned(members: &[Option<MemberRecord>; 2]) -> Vec<InterfaceIdentity> {
    members
        .iter()
        .flatten()
        .filter_map(|m| {
            m.owner.proof.map(|p| InterfaceIdentity {
                index: p.interface.index,
                luid: p.interface.luid,
                guid: p.interface.guid,
            })
        })
        .collect()
}
fn verify_record(m: &MemberRecord) -> io::Result<()> {
    retained_owner(m)?
        .verify_retained(&m.owner)
        .map_err(|_| failed())
}
fn retained_owner(m: &MemberRecord) -> io::Result<Owner> {
    let files = MemberFiles::new().map_err(|_| failed())?;
    let native =
        NativeMemberIo::for_retained_cleanup(&m.owner, MemberFiles::new().map_err(|_| failed())?)
            .map_err(|_| failed())?;
    // Only retained exact proof is queried; no service creation/adoption.
    MemberOwner::recover_for_cleanup(
        m.owner.intent.scope.clone(),
        m.owner.intent.slot,
        m.owner.intent.transport,
        m.owner.intent.engine.clone(),
        m.owner.clone(),
        files,
        native,
    )
    .map_err(|_| failed())
}
struct OwnedIdentity(MemberRecord);
impl Identity for OwnedIdentity {
    fn verify_owned(&mut self, i: &member_dns::OwnedInterface) -> member_dns::Result<Ownership> {
        if dns_interface(&self.0).map_err(|_| member_dns::DnsError::Ownership)? != *i {
            return Err(member_dns::DnsError::Ownership);
        }
        verify_record(&self.0).map_err(|_| member_dns::DnsError::Ownership)?;
        Ok(Ownership::NewlyCreated)
    }
}
fn dns_interface(m: &MemberRecord) -> io::Result<member_dns::OwnedInterface> {
    let p = m.owner.proof.ok_or_else(failed)?;
    Ok(member_dns::OwnedInterface {
        scope: m.owner.intent.scope.clone(),
        index: p.interface.index,
        luid: p.interface.luid,
        guid: p.interface.guid,
    })
}
fn verify_source(m: &MemberRecord) -> io::Result<()> {
    match source_readiness(m)? {
        crate::member_source::Readiness::Preferred => Ok(()),
        crate::member_source::Readiness::Tentative => Err(failed()),
    }
}
fn source_readiness(m: &MemberRecord) -> io::Result<crate::member_source::Readiness> {
    let p = m.owner.proof.ok_or_else(failed)?;
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = p.interface.index;
    row.InterfaceLuid.Value = p.interface.luid;
    row.Address.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(m.source.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    if unsafe { GetUnicastIpAddressEntry(&mut row) } != 0 {
        return Err(failed());
    }
    crate::member_source::classify(
        (p.interface.index, p.interface.luid),
        (row.InterfaceIndex, unsafe { row.InterfaceLuid.Value }),
        row.DadState,
    )
}

pub(crate) type NativeWindowsPair<F> = SessionNativePair<WindowsPairIo<F>, WindowsPairStore<F>>;
pub(crate) struct NativePairFactory<F: SessionFiles> {
    files: F,
    runtime: RuntimeSlot,
    engine: PathBuf,
    executor: Rc<tokio::runtime::Runtime>,
    root: PathBuf,
    owner: std::sync::Arc<nelomai_contracts::dispatcher::MutationGuard>,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    // Discovery is retained BEFORE signed/private postflight. A failed native
    // selection must never fall through the legacy recovery decoder.
    recovery_entry: Option<Rc<super::member_carrier_recovery::native::NativeFactoryRecoveryEntry>>,
    // Retain actual cleanup composition BEFORE its first static BFE effect.
    // Full native emptiness/claim retirement remain independent requirements.
    recovery_guard: Option<Rc<super::member_carrier_recovery_guard::NativeColdGuardCleanup>>,
    execution: crate::install_recovery::RecoveryExecutable,
}
impl<F: SessionFiles> NativePairFactory<F> {
    pub(crate) fn new(
        files: F,
        runtime: RuntimeSlot,
        trusted_engine: &Path,
        root: &Path,
        owner: std::sync::Arc<nelomai_contracts::dispatcher::MutationGuard>,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> io::Result<Self> {
        if tokio::runtime::Handle::try_current().is_ok()
            || !trusted_engine.is_absolute()
            || !root.is_absolute()
        {
            return Err(failed());
        }
        owner.verify_at(&root.join("engine-owner.lock"))?;
        let engine = std::fs::canonicalize(trusted_engine)?;
        if !crate::member_pair::canonical_engine_matches(trusted_engine, &engine) {
            return Err(failed());
        }
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let factory = Self {
            files,
            runtime,
            engine,
            executor: Rc::new(executor),
            root: root.to_owned(),
            owner,
            cancelled,
            recovery_entry: None,
            recovery_guard: None,
            execution: crate::install_recovery::RecoveryExecutable::Engine,
        };
        factory.verify_service_owner()?;
        Ok(factory)
    }
    fn verify_service_owner(&self) -> io::Result<()> {
        self.owner.verify_at(&self.root.join("engine-owner.lock"))
    }
    fn complete_unrecorded_claim(
        &mut self,
        scope: &SessionScope,
        session_files: &mut F,
    ) -> io::Result<()> {
        let mut records_present = [false; 3];
        for (index, kind) in [RecordKind::Session, RecordKind::Pair, RecordKind::Network]
            .into_iter()
            .enumerate()
        {
            records_present[index] = session_files.read(scope, kind)?.is_some();
        }
        let mut guard = NativeGuard::open(scope.clone()).map_err(|_| failed())?;
        verify_empty_claim(
            scope,
            records_present,
            |slot| {
                let slot = slot_native(slot);
                let mut files = MemberFiles::new().map_err(|_| failed())?;
                let record = files.load(slot).map_err(|_| failed())?;
                let private = MemberFiles::new().map_err(|_| failed())?;
                let mut native = match &record {
                    Some(record) => NativeMemberIo::for_retained_cleanup(record, private),
                    None => NativeMemberIo::from_trusted_factory(
                        self.engine.clone(),
                        slot,
                        nelomai_client_tunnel::TunnelTransport::WireGuard,
                        private,
                    ),
                }
                .map_err(|_| failed())?;
                // observe_unclaimed also rejects the other transport's service /
                // alias. No synthetic intent, config write or SCM primitive.
                let observed = match &record {
                    Some(record) => crate::member_owner::MemberIo::inspect(
                        &mut native,
                        &record.intent,
                        record.retired_proof.as_ref(),
                    )
                    .map_err(|_| failed())?,
                    None => native.observe_unclaimed().map_err(|_| failed())?,
                };
                if files.load(slot).map_err(|_| failed())? != record {
                    return Err(failed());
                }
                Ok((record, observed))
            },
            || GuardStore::snapshot(&mut guard, scope).map_err(|_| failed()),
        )?;
        // The protected adapter atomically rechecks all three records are still
        // absent, then durably tombstones the claim. Read/ACK errors retain it.
        session_files.complete_empty(scope)
    }

    fn retire_completed_members(&mut self) -> io::Result<()> {
        for slot in [Slot::A, Slot::B] {
            let mut files = MemberFiles::new().map_err(|_| failed())?;
            let Some(record) = files.load(slot_native(slot)).map_err(|_| failed())? else {
                continue;
            };
            if record.phase != Phase::Stopped {
                return Err(failed());
            }
            if self
                .files
                .completed_in_previous_boot(&record.intent.scope)?
            {
                let mut native = NativeMemberIo::for_retained_cleanup(
                    &record,
                    MemberFiles::new().map_err(|_| failed())?,
                )
                .map_err(|_| failed())?;
                crate::member_reboot::retire_member(true, &mut files, &mut native, &record)
                    .map_err(|_| failed())?;
            }
        }
        Ok(())
    }

    fn recover_previous_boot(
        &self,
        scope: &SessionScope,
        files: &mut F,
        mut store: WindowsPairStore<F>,
        mut record: PairRecord,
    ) -> io::Result<()> {
        let empty = crate::member_guard::Model::empty(scope.clone()).map_err(|_| failed())?;
        let mut guard = NativeGuard::open(scope.clone()).map_err(|_| failed())?;
        if GuardStore::snapshot(&mut guard, scope).map_err(|_| failed())? != empty.expected {
            return Err(failed());
        }
        let (mut network, saved) = ProtectedStore::<F, NativeNetworkRecord>::open(
            files.clone(),
            scope.clone(),
            RecordKind::Network,
        )?;
        if saved
            .as_ref()
            .is_some_and(|s| !s.journal.windows_boot_resources_are_ephemeral())
        {
            return Err(failed());
        }
        record.closing = true;
        record.active = None;
        store.save(&record)?;
        for slot in [Slot::A, Slot::B] {
            let mut owners = MemberFiles::new().map_err(|_| failed())?;
            let owner = owners.load(slot_native(slot)).map_err(|_| failed())?;
            let member = record.members[slot.idx()].as_ref();
            if let Some(member) = member {
                // Accept only this attempt or its exact unpublished predecessor.
                if owner
                    .as_ref()
                    .is_none_or(|o| o.intent != member.owner.intent)
                    && !matches_unstarted_prior(member, owner.as_ref())?
                {
                    return Err(failed());
                }
            } else if owner.as_ref().is_some_and(|o| o.phase != Phase::Stopped) {
                return Err(failed());
            }
            let mut guids = Vec::new();
            if let Some(dns) = &record.dns[slot.idx()] {
                guids.push(dns.baseline.interface.guid);
                guids.push(dns.current.interface.guid);
                if let Some(pending) = &dns.pending {
                    guids.push(pending.interface.guid);
                }
            }
            super::member_owner::require_reboot_guids_absent(slot_native(slot), &guids)
                .map_err(|_| failed())?;
            match owner {
                Some(owner) => {
                    let mut native = NativeMemberIo::for_retained_cleanup(
                        &owner,
                        MemberFiles::new().map_err(|_| failed())?,
                    )
                    .map_err(|_| failed())?;
                    crate::member_reboot::retire_member(true, &mut owners, &mut native, &owner)
                        .map_err(|_| failed())?;
                }
                None => {
                    let mut native = NativeMemberIo::from_trusted_factory(
                        self.engine.clone(),
                        slot_native(slot),
                        nelomai_client_tunnel::TunnelTransport::WireGuard,
                        MemberFiles::new().map_err(|_| failed())?,
                    )
                    .map_err(|_| failed())?;
                    let observed = native.observe_unclaimed().map_err(|_| failed())?;
                    if observed.config_sha256.is_some()
                        || observed.service.is_some()
                        || observed.alternative_service_present
                        || observed.interface.is_some()
                        || !observed.retained_interfaces.is_empty()
                    {
                        return Err(failed());
                    }
                }
            }
        }
        if GuardStore::snapshot(&mut guard, scope).map_err(|_| failed())? != empty.expected {
            return Err(failed());
        }
        // IP Helper active route rows do not survive a kernel reboot. DNS was
        // scoped to owned adapter GUIDs, whose absence was proved above. Never
        // replay old indices/LUIDs, restore physical DNS or reinstall WFP here.
        network.save_value(&NativeNetworkRecord::default())?;
        record.members = [None, None];
        record.dns = [None, None];
        record.guard = empty;
        record.pending_guard = None;
        record.closing = false;
        store.save(&record)?;
        let (mut session, saved) =
            WindowsSessionStore::open(files.clone(), scope.clone(), RecordKind::Session)?;
        session.save(&stopped_after_cleanup(scope, saved)?)?;
        files.complete(scope)
    }
}
impl<F: SessionFiles> NativePairFactory<F> {
    fn recover_legacy(&mut self, runtime: RuntimeSlot) -> io::Result<()> {
        (|| -> io::Result<()> {
            self.verify_service_owner()?;
            if runtime != self.runtime {
                return Err(failed());
            }
            let (mut files, different_boot) = self
                .files
                .recovery_view(runtime)?
                .unwrap_or((self.files.clone(), false));
            for scope in files.scopes(runtime)? {
                if scope.runtime != runtime || !scope.validate() {
                    return Err(failed());
                }
                let (store, saved) =
                    WindowsPairStore::open(files.clone(), scope.clone(), RecordKind::Pair)?;
                let Some(mut record) = saved else {
                    if different_boot {
                        self.retire_completed_members()?;
                    }
                    self.complete_unrecorded_claim(&scope, &mut files)?;
                    continue;
                };
                if different_boot {
                    self.recover_previous_boot(&scope, &mut files, store, record)?;
                    continue;
                }
                let recovery_engine = record
                    .members
                    .iter()
                    .flatten()
                    .next()
                    .map(|m| m.owner.intent.engine.clone())
                    .unwrap_or_else(|| self.engine.clone());
                if record
                    .members
                    .iter()
                    .flatten()
                    .any(|m| m.owner.intent.engine != recovery_engine)
                {
                    return Err(failed());
                }
                let native = WindowsPairIo::open(
                    scope.clone(),
                    recovery_engine,
                    self.executor.clone(),
                    files.clone(),
                    Some(&record),
                )?;
                // Member owner journals may have advanced after the pair journal
                // write. Same intent only; never substitute a new scope/engine.
                let mut native = native;
                for slot in [Slot::A, Slot::B] {
                    if let Some(member) = record.members[slot.idx()].as_ref() {
                        if native.abandon_unstarted(member)? {
                            record.members[slot.idx()] = None;
                            continue;
                        }
                    }
                    if let Some(m) = &mut record.members[slot.idx()] {
                        if let Some(current) = native.current(slot)? {
                            if current.intent != m.owner.intent {
                                return Err(failed());
                            }
                            m.owner = current;
                        }
                    }
                }
                let mut pair =
                    SessionNativePair::recover_for_cleanup(scope.clone(), native, store, record)?;
                pair.close(&scope)?;
                let (mut state_store, saved) =
                    WindowsSessionStore::open(files.clone(), scope.clone(), RecordKind::Session)?;
                state_store.save(&stopped_after_cleanup(&scope, saved)?)?;
                files.complete(&scope)?;
            }
            self.retire_completed_members()?;
            self.verify_service_owner()
        })()
    }
}
impl PairFactory for NativePairFactory<NativeSessionFiles> {
    type Native = NativeWindowsPair<NativeSessionFiles>;
    type Store = CompletedSessionStore<NativeSessionFiles>;
    fn recover(&mut self, runtime: RuntimeSlot) -> Result<(), crate::ServiceError> {
        (|| {
            self.verify_service_owner()?;
            if runtime != self.runtime
                || self.recovery_entry.is_some()
                || self.recovery_guard.is_some()
            {
                return Err(failed());
            }
            let entry = Rc::new(
                super::member_carrier_recovery::native::NativeFactoryRecoveryEntry::new(
                    &self.root,
                    self.owner.clone(),
                    self.files.clone(),
                    runtime,
                    self.execution.clone(),
                ),
            );
            self.recovery_entry = Some(entry.clone());
            match entry.classify()? {
                Some(super::member_carrier_recovery::RecoveryLayout::NativeCarrier) => {
                    if entry.retained_facts()?.guard.is_some() {
                        let cleanup = Rc::new(
                            super::member_carrier_recovery_guard::NativeColdGuardCleanup::new(
                                entry.clone(),
                            )?,
                        );
                        self.recovery_guard = Some(cleanup.clone());
                        cleanup.cleanup()?;
                    }
                    // Independent readonly FULL EMPTY, then original protected
                    // index retirement only. No legacy projection or SDK ACK
                    // reconstruction. Failure retains this SAME entry/root.
                    entry.retire_cold_native()?;
                    entry.verify()?;
                    self.verify_service_owner()?;
                    // Release the NEW current-engine hard-call owner only
                    // after independent full EMPTY and storage retirement.
                    self.recovery_guard.take();
                    self.recovery_entry.take();
                    return Ok(());
                }
                None
                | Some(super::member_carrier_recovery::RecoveryLayout::LegacyOnly)
                | Some(super::member_carrier_recovery::RecoveryLayout::UnpublishedClaim) => {}
            }
            self.recover_legacy(runtime)?;
            entry.verify()?;
            self.verify_service_owner()?;
            self.recovery_entry.take();
            Ok(())
        })()
        .map_err(|e| crate::member_actor::operation_failed("recovery", e))
    }
    fn prepare(
        &mut self,
        runtime: RuntimeSlot,
        command: &Command,
        now: u64,
    ) -> io::Result<SessionControl<Self::Native, Self::Store>> {
        self.execution.require_engine()?;
        require_factory_start_context(
            runtime,
            self.runtime,
            tokio::runtime::Handle::try_current().is_ok(),
            self.cancelled.load(std::sync::atomic::Ordering::SeqCst),
        )?;
        self.verify_service_owner()?;
        command.validate(runtime)?;
        let Command::Start { scope, primary, .. } = command else {
            return Err(failed());
        };
        MemberParameters::parse(primary.configuration.expose())?;
        self.recover(runtime).map_err(|error| match error {
            crate::ServiceError::PairOperation(failure) => io::Error::other(failure),
            _ => context("recovery", failed()),
        })?;
        // Recovery can outlast an EOF delivered by the independent sole reader.
        // Recheck before durable claim; cancellation never grants cleanup.
        require_factory_start_context(
            runtime,
            self.runtime,
            tokio::runtime::Handle::try_current().is_ok(),
            self.cancelled.load(std::sync::atomic::Ordering::SeqCst),
        )?;
        self.files.claim(scope)?;
        self.verify_service_owner()?;
        let (pair_store, old) =
            WindowsPairStore::open(self.files.clone(), scope.clone(), RecordKind::Pair)?;
        if old.is_some() {
            return Err(failed());
        }
        let native = WindowsPairIo::open(
            scope.clone(),
            self.engine.clone(),
            self.executor.clone(),
            self.files.clone(),
            None,
        )?;
        let pair = SessionNativePair::new(scope.clone(), native, pair_store)?;
        let (store, old) =
            WindowsSessionStore::open(self.files.clone(), scope.clone(), RecordKind::Session)?;
        if old.is_some() {
            return Err(failed());
        }
        SessionControl::prepare(
            runtime,
            command,
            pair,
            CompletedSessionStore {
                store,
                files: self.files.clone(),
                scope: scope.clone(),
                completion: CompletionState::default(),
            },
            now,
        )
    }
}
pub(crate) struct CompletedSessionStore<F: SessionFiles> {
    store: WindowsSessionStore<F>,
    files: F,
    scope: SessionScope,
    completion: CompletionState,
}

/// Concrete initial-NoC completion ONLY. This is not a legacy-store upgrade or
/// a native factory selector. The caller roots it before transferring the SAME
/// Startup into the actor; only that Startup can bind completed native NoC.
/// A Stopped snapshot schedules callbacks but cannot authenticate retirement.
#[allow(dead_code)] // Factory remains disabled until the remaining native gates close.
pub(crate) struct NativeInitialDataSessionStore {
    store: WindowsSessionStore<NativeSessionFiles>,
    files: NativeSessionFiles,
    scope: SessionScope,
    original: Option<Rc<super::member_carrier_startup::native::NativeNoCInitialDataRetirement>>,
    completion: InitialDataCompletionState,
}
#[allow(dead_code)]
impl NativeInitialDataSessionStore {
    pub(crate) fn retain_from_startup_into(
        startup: &super::member_carrier_startup::native::NativeStartupRoot,
        store: WindowsSessionStore<NativeSessionFiles>,
        files: NativeSessionFiles,
        destination: &mut Option<Self>,
    ) -> io::Result<()> {
        if destination.is_some() {
            return Err(failed());
        }
        let original = startup
            .initial_data_retirement_root()
            .map_err(|_| failed())?;
        *destination = Some(Self {
            scope: startup.context().intent.scope.clone(),
            store,
            files,
            original: Some(original),
            completion: InitialDataCompletionState::default(),
        });
        // The SAME backend/execution identity is authenticated by the actual
        // original initial DATA pin during retirement, not equal scope alone.
        Ok(())
    }
}
impl SessionStore for NativeInitialDataSessionStore {
    fn save(
        &mut self,
        snapshot: &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
    ) -> io::Result<()> {
        let original = self.original.as_ref().cloned();
        self.completion.save(
            &self.scope,
            snapshot,
            |snapshot| self.store.save(snapshot),
            || {
                original
                    .as_ref()
                    .ok_or_else(failed)?
                    .retire()
                    .map_err(|_| failed())
            },
            |scope| self.files.complete(scope),
            || {
                original
                    .as_ref()
                    .ok_or_else(failed)?
                    .release_retired_originals()
                    .map_err(|_| failed())
            },
        )?;
        if snapshot.phase == nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped {
            self.original.take(); // only after ALL actual callbacks returned ACK
        }
        Ok(())
    }
}
impl<F: SessionFiles> SessionStore for CompletedSessionStore<F> {
    fn save(
        &mut self,
        snapshot: &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
    ) -> io::Result<()> {
        self.completion.save(
            &self.scope,
            snapshot,
            |snapshot| self.store.save(snapshot),
            |scope| self.files.complete(scope),
        )
    }
}
impl NativePairFactory<NativeSessionFiles> {
    /// Cleanup-only installer: source is derived from the validated installed
    /// client location, never IPC. Actual classification rechecks its signed
    /// package/current executable and the OLD full installed layout each edge.
    pub(crate) fn from_installer_cleanup(
        root: &Path,
        identity: nelomai_contracts::dispatcher::EngineIdentity,
        engine: &Path,
        owner: std::sync::Arc<nelomai_contracts::dispatcher::MutationGuard>,
        execution: crate::install_recovery::RecoveryExecutable,
    ) -> io::Result<Self> {
        if matches!(
            execution,
            crate::install_recovery::RecoveryExecutable::Engine
        ) {
            return Err(failed());
        }
        let mut factory = Self::from_service(
            root,
            identity,
            engine,
            owner,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )?;
        factory.execution = execution;
        Ok(factory)
    }
    /// Called by the authenticated engine owner while holding its mutation lock.
    pub(crate) fn from_service(
        root: &Path,
        identity: nelomai_contracts::dispatcher::EngineIdentity,
        engine: &Path,
        owner: std::sync::Arc<nelomai_contracts::dispatcher::MutationGuard>,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> io::Result<Self> {
        if !root.is_absolute() {
            return Err(failed());
        }
        owner.verify_at(&root.join("engine-owner.lock"))?;
        let runtime = identity.slot;
        let boot = super::member_boot::boot_id()?;
        let files =
            ProtectedSessionFiles::new(MemberFiles::new().map_err(|_| failed())?, identity, boot)?;
        Self::new(files, runtime, engine, root, owner, cancelled)
    }
}

impl PhysicalLease {
    fn capture(p: &PhysicalRoute) -> Self {
        Self {
            interface: p.proof.identity.index,
            luid: p.proof.identity.luid,
            guid: p.proof.identity.guid,
            ipv6: p.proof.family == Family::V6,
            interface_metric: p.proof.metric,
            route: p.row.route.clone(),
            protocol: p.row.protocol,
            origin: p.row.origin,
            site_prefix_length: p.row.site_prefix_length,
            valid_lifetime: p.row.valid_lifetime,
            preferred_lifetime: p.row.preferred_lifetime,
            flags: p.row.flags,
        }
    }
    fn restore(&self) -> PhysicalRoute {
        PhysicalRoute {
            proof: PhysicalProof {
                identity: InterfaceIdentity {
                    index: self.interface,
                    luid: self.luid,
                    guid: self.guid,
                },
                family: if self.ipv6 { Family::V6 } else { Family::V4 },
                metric: self.interface_metric,
            },
            row: crate::member_routes::Row {
                route: self.route.clone(),
                luid: self.luid,
                protocol: self.protocol,
                origin: self.origin,
                site_prefix_length: self.site_prefix_length,
                valid_lifetime: self.valid_lifetime,
                preferred_lifetime: self.preferred_lifetime,
                flags: self.flags,
            },
        }
    }
}
fn interface_metric(m: &MemberRecord, ipv6: bool) -> io::Result<InterfaceMetric> {
    verify_record(m)?;
    let proof = m.owner.proof.ok_or_else(failed)?;
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = if ipv6 { AF_INET6 } else { AF_INET };
    row.InterfaceIndex = proof.interface.index;
    row.InterfaceLuid.Value = proof.interface.luid;
    if unsafe { GetIpInterfaceEntry(&mut row) } != 0
        || row.InterfaceIndex != proof.interface.index
        || unsafe { row.InterfaceLuid.Value } != proof.interface.luid
    {
        return Err(failed());
    }
    verify_record(m)?;
    Ok(InterfaceMetric {
        interface: proof.interface.index,
        ipv6,
        metric: row.Metric,
    })
}
fn plan(
    snapshot: &PhysicalSnapshot,
    active: Slot,
    members: &[Option<MemberRecord>; 2],
    options: &DesktopTunnelOptions,
) -> io::Result<(Vec<RouteValue>, Vec<PhysicalLease>)> {
    options.validate().map_err(|_| failed())?;
    let mut exclusions = options
        .excluded_ipv4_cidrs
        .iter()
        .map(|s| s.parse::<ipnet::IpNet>().map_err(|_| failed()))
        .collect::<io::Result<Vec<_>>>()?;
    if options.exclude_local_networks {
        exclusions.extend(snapshot.lan_prefixes());
    }
    for m in members.iter().flatten() {
        // Endpoint hosts are not LAN prefixes: retain the stricter unicast /
        // explicit-zone requirement even when an exact on-link row exists.
        snapshot.resolve_host(m.endpoint).map_err(|_| failed())?;
        exclusions.push(ipnet::IpNet::from(m.endpoint));
    }
    exclusions.sort();
    exclusions.dedup();
    let mut physical = Vec::new();
    let mut bypasses = Vec::new();
    let mut retained = Vec::new();
    let destinations = exclusions
        .iter()
        .copied()
        .chain(
            members
                .iter()
                .flatten()
                .map(|m| ipnet::IpNet::from(IpAddr::V4(m.probe.target_ipv4))),
        )
        .collect::<Vec<_>>();
    for destination in destinations {
        let path = snapshot.resolve_bypass(destination).map_err(|_| failed())?;
        let route = RouteValue {
            destination,
            scope: RouteScope::WindowsInterface(path.proof.identity.index),
            interface: path.proof.identity.index,
            gateway: path.row.route.gateway,
            metric: path.row.route.metric,
        };
        if path.row.route == route {
            retained.push(route.clone());
        }
        bypasses.push(route);
        physical.push(PhysicalLease::capture(&path));
    }
    let ipv6 = members
        .iter()
        .flatten()
        .any(|m| m.allowed.iter().any(|n| n.addr().is_ipv6()));
    let mut metrics = Vec::new();
    let mut routes = Vec::new();
    for slot in [Slot::A, Slot::B] {
        if let Some(m) = &members[slot.idx()] {
            metrics.push(interface_metric(m, false)?);
            if ipv6 {
                metrics.push(interface_metric(m, true)?);
            }
            routes.push(
                nelomai_client_tunnel::redundancy::route_plan::MemberRoutes {
                    slot,
                    interface: m.owner.proof.ok_or_else(failed)?.interface.index,
                    allowed: m.allowed.clone(),
                    probe: m.probe.target_ipv4,
                },
            );
        }
    }
    for p in snapshot.proofs().values() {
        metrics.push(InterfaceMetric {
            interface: p.identity.index,
            ipv6: p.family == Family::V6,
            metric: p.metric,
        });
    }
    let plan = member_route_plan(active, &routes, &exclusions, &bypasses, &metrics, 0)
        .map_err(PairFailure::plan)?;
    crate::member_plan::validate_retained_probe_routes(&plan, &routes, &retained, &metrics)
        .map_err(PairFailure::plan)?;
    let routes = plan
        .routes
        .into_iter()
        .filter(|r| !retained.contains(r))
        .collect();
    Ok((routes, physical))
}
