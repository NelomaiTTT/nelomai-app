//! Explicit production selector; the carrier factory is cleanup-only here.
use super::{
    member_files::{MemberFiles, PrivateFile, SessionFileIo},
    member_pair::NativePairFactory,
    member_session::NativeSessionFiles,
    member_worker::{self, Control, Store},
    member_worker_guard::Guard,
};
use crate::{member_actor::PairFactory, member_pair::FactoryPreparationSlot, ServiceError};
use nelomai_client_tunnel::redundancy::{
    control::SessionControl, protocol::Command, session::SessionPhase,
};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, MutationGuard},
    RuntimeSlot,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
};

pub(crate) struct WorkerPairFactory {
    legacy: NativePairFactory<NativeSessionFiles>,
    files: NativeSessionFiles,
    root: PathBuf,
    owner: Arc<MutationGuard>,
    runtime: RuntimeSlot,
    preparation: FactoryPreparationSlot<SessionControl<Control, Store>>,
}
impl WorkerPairFactory {
    pub(crate) fn from_service(
        root: &Path,
        identity: EngineIdentity,
        engine: &Path,
        owner: Arc<MutationGuard>,
        cancelled: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Ok(
            NativePairFactory::from_service(root, identity, engine, owner, cancelled)?
                .into_worker_factory(),
        )
    }
    pub(crate) fn from_legacy(
        legacy: NativePairFactory<NativeSessionFiles>,
        files: NativeSessionFiles,
        root: PathBuf,
        owner: Arc<MutationGuard>,
        runtime: RuntimeSlot,
    ) -> Self {
        Self {
            legacy,
            files,
            root,
            owner,
            runtime,
            preparation: FactoryPreparationSlot::default(),
        }
    }
    fn parts(&mut self, runtime: RuntimeSlot, start: &Command) -> io::Result<(Control, Store)> {
        self.legacy.verify_worker_start_context(runtime)?;
        start.validate(runtime)?;
        self.recover(runtime)
            .map_err(|_| io::Error::other("worker_factory_recovery"))?;
        self.legacy.verify_worker_start_context(runtime)?;
        member_worker::prepare(
            &self.root,
            self.owner.clone(),
            self.files.clone(),
            start.scope().clone(),
        )
    }
}
impl PairFactory for WorkerPairFactory {
    type Native = Control;
    type Store = Store;
    fn recover(&mut self, runtime: RuntimeSlot) -> Result<(), ServiceError> {
        let result = (|| {
            self.owner.verify_at(&self.root.join("engine-owner.lock"))?;
            if runtime != self.runtime {
                return Err(io::Error::other("worker_recovery_runtime"));
            }
            if self.preparation.is_pending() {
                self.preparation.cleanup(|original| {
                    let scope = original.snapshot().session.scope;
                    let stopped = original.execute(Command::Stop { scope }, 0)?;
                    if stopped.session.phase != SessionPhase::Stopped || stopped.cleanup_pending {
                        return Err(io::Error::other("worker_recovery_original"));
                    }
                    Ok(())
                })?;
            }
            let mut private = MemberFiles::new().map_err(|_| io::Error::other("worker_private"))?;
            let record = private.transaction(|files| files.read(PrivateFile::Worker))?;
            if let Some(bytes) = record {
                // Unknown/live worker state never falls into legacy cleanup.
                // Cold deletion/adoption of old WFP/process owners is forbidden.
                let (scope, _, _) = member_worker::terminal_identity(&bytes)?;
                self.files.verify_completed_worker()?;
                member_worker::verify_terminal_record(&bytes)?;
                let mut observer = Guard::open(crate::member_worker_guard::Model::empty(scope))
                    .map_err(|_| io::Error::other("worker_guard_absence"))?;
                observer
                    .close()
                    .map_err(|_| io::Error::other("worker_guard_absence"))?;
            }
            self.legacy
                .recover(runtime)
                .map_err(|_| io::Error::other("worker_legacy_cleanup"))
        })();
        result.map_err(|e| crate::member_actor::operation_failed("worker_recovery", e))
    }
    fn prepare(
        &mut self,
        runtime: RuntimeSlot,
        start: &Command,
        now: u64,
    ) -> io::Result<SessionControl<Control, Store>> {
        let (native, store) = self.parts(runtime, start)?;
        self.preparation.prepare(|destination| {
            SessionControl::prepare_retained_into(
                destination,
                runtime,
                start,
                &mut Some(native),
                &mut Some(store),
                now,
            )
        })
    }
    fn prepare_retained_into(
        &mut self,
        destination: &mut Option<SessionControl<Control, Store>>,
        runtime: RuntimeSlot,
        start: &Command,
        now: u64,
    ) -> io::Result<()> {
        if destination.is_some() {
            return Err(io::Error::other("worker_destination_occupied"));
        }
        let (native, store) = self.parts(runtime, start)?;
        SessionControl::prepare_retained_into(
            destination,
            runtime,
            start,
            &mut Some(native),
            &mut Some(store),
            now,
        )
    }
}
