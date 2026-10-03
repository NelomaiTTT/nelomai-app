//! The real factory's cold carrier preparation and session completion.
//! No SDK effect is performed until this owner lives in SessionControl/actor.
use super::{
    member_carrier_control::NativeCarrierPairFinalizer,
    member_carrier_pair_io::native::{NativeCarrierPairIo, NativePairJournal},
    member_carrier_startup::native::{NativeNoCInitialDataRetirement, NativeStartupRoot},
    member_session::{NativeSessionFiles, RecordKind, SessionFiles, WindowsSessionStore},
};
use crate::{
    member_carrier_control::{CarrierPairControl, CarrierPairPreparation},
    member_carrier_pair::CarrierNativePair,
    member_pair::{CompletionState, InitialDataCompletionState},
};
use nelomai_client_tunnel::redundancy::{
    driver::SessionStore,
    session::{SessionPhase, SessionSnapshot},
    SessionScope,
};
use nelomai_contracts::dispatcher::MutationGuard;
use std::{
    cell::RefCell,
    io,
    path::PathBuf,
    rc::Rc,
    sync::{atomic::AtomicBool, Arc},
};
use zeroize::Zeroizing;

type InitialRetirement = Rc<RefCell<Option<Rc<NativeNoCInitialDataRetirement>>>>;
type Finalizer = Rc<RefCell<NativeCarrierPairFinalizer<'static>>>;
pub(crate) type NativeFactoryControl =
    CarrierPairControl<NativeCarrierPairIo<'static>, NativePairJournal, Finalizer>;
fn pending() -> io::Error {
    io::Error::other("carrier_factory_original_or_pending")
}

pub(crate) struct NativeCarrierPreparation {
    root: PathBuf,
    engine: PathBuf,
    owner: Arc<MutationGuard>,
    files: NativeSessionFiles,
    scope: SessionScope,
    logical: Zeroizing<String>,
    cancelled: Arc<AtomicBool>,
    // These slots outlive every from_claim/transfer Err and unwind.
    startup: Option<NativeStartupRoot>,
    io: Option<NativeCarrierPairIo<'static>>,
    journal: Option<NativePairJournal>,
    retirement: InitialRetirement,
}
impl CarrierPairPreparation<NativeCarrierPairIo<'static>, NativePairJournal>
    for NativeCarrierPreparation
{
    fn prepare_retained_into(
        &mut self,
        destination: &mut Option<
            CarrierNativePair<NativeCarrierPairIo<'static>, NativePairJournal>,
        >,
    ) -> io::Result<()> {
        if destination.is_some()
            || self.startup.is_some()
            || self.io.is_some()
            || self.journal.is_some()
        {
            return Err(pending());
        }
        NativeStartupRoot::from_claim_into(
            &mut self.startup,
            &self.root,
            self.engine.clone(),
            self.owner.clone(),
            self.files.clone(),
            &self.scope,
            &self.logical,
            self.cancelled.clone(),
        )
        .map_err(|_| pending())?;
        // Weak until the SAME Startup has bound a completed initial-NoC
        // outcome; normal C cannot keep its Runtime alive via this handle.
        *self.retirement.try_borrow_mut().map_err(|_| pending())? = Some(
            self.startup
                .as_ref()
                .ok_or_else(pending)?
                .initial_data_retirement_root()
                .map_err(|_| pending())?,
        );
        NativeStartupRoot::into_pair_retained_into(
            &mut self.startup,
            &mut self.io,
            &mut self.journal,
            destination,
        )
    }
    fn begin_cleanup_before_pair(&mut self, scope: &SessionScope) -> io::Result<()> {
        if *scope != self.scope || self.io.is_some() || self.journal.is_some() {
            return Err(pending());
        }
        let startup = self.startup.as_mut().ok_or_else(pending)?;
        startup
            .begin_cleanup_before_pair(scope)
            .map_err(|_| pending())?;
        // Select only this Startup's actual initialized NoC root. It still
        // cannot retire DATA until the original whole native disposition binds
        // an outcome. Unknown initialization never produces this handle.
        let original = startup
            .initial_data_retirement_root()
            .map_err(|_| pending())?;
        let mut retained = self.retirement.try_borrow_mut().map_err(|_| pending())?;
        match retained.as_ref() {
            Some(existing) if !Rc::ptr_eq(existing, &original) => Err(pending()),
            Some(_) => Ok(()),
            None => {
                *retained = Some(original);
                Ok(())
            }
        }
    }
}

pub(crate) struct NativeCarrierSessionStore {
    store: WindowsSessionStore<NativeSessionFiles>,
    files: NativeSessionFiles,
    scope: SessionScope,
    finalizer: Finalizer,
    retirement: InitialRetirement,
    normal: CompletionState,
    initial: InitialDataCompletionState,
    completed: Option<SessionSnapshot>,
}
impl SessionStore for NativeCarrierSessionStore {
    fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()> {
        if let Some(completed) = &self.completed {
            return if completed == snapshot {
                Ok(())
            } else {
                Err(pending())
            };
        }
        if snapshot.phase != SessionPhase::Stopped {
            return self.normal.save(
                &self.scope,
                snapshot,
                |s| self.store.save(s),
                |_| Err(pending()),
            );
        }
        // A session phase does not select terminal authority. Read only the
        // actual finalizer's completed branch; every callback keeps its guards.
        let initial = self
            .finalizer
            .try_borrow()
            .map_err(|_| pending())?
            .completed_initial_noc()?;
        if initial {
            let root = self
                .retirement
                .try_borrow()
                .map_err(|_| pending())?
                .clone()
                .ok_or_else(pending)?;
            self.initial.save(
                &self.scope,
                snapshot,
                |s| self.store.save(s),
                || root.retire().map_err(|_| pending()),
                |scope| self.files.complete(scope),
                || root.release_retired_originals().map_err(|_| pending()),
            )?;
        } else {
            self.normal.save(
                &self.scope,
                snapshot,
                |s| self.store.save(s),
                |scope| self.files.complete(scope),
            )?;
        }
        self.retirement
            .try_borrow_mut()
            .map_err(|_| pending())?
            .take();
        self.completed = Some(snapshot.clone());
        Ok(())
    }
}

/// Sole production selector: the old addressed-member type is not an output.
/// Trusted context/claim validation remains in NativePairFactory; this merely
/// joins its retained owner to the existing real Startup/coordinator/finalizer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn select_carrier(
    root: PathBuf,
    engine: PathBuf,
    owner: Arc<MutationGuard>,
    files: NativeSessionFiles,
    scope: SessionScope,
    logical: &str,
    cancelled: Arc<AtomicBool>,
) -> io::Result<(NativeFactoryControl, NativeCarrierSessionStore)> {
    let (store, old) =
        WindowsSessionStore::open(files.clone(), scope.clone(), RecordKind::Session)?;
    if old.is_some() {
        return Err(pending());
    }
    let retirement = Rc::new(RefCell::new(None));
    let finalizer = Rc::new(RefCell::new(NativeCarrierPairFinalizer::new()));
    let control = CarrierPairControl::from_preparation(
        scope.clone(),
        Box::new(NativeCarrierPreparation {
            root,
            engine,
            owner,
            files: files.clone(),
            scope: scope.clone(),
            logical: Zeroizing::new(logical.to_owned()),
            cancelled,
            startup: None,
            io: None,
            journal: None,
            retirement: retirement.clone(),
        }),
        finalizer.clone(),
    );
    Ok((
        control,
        NativeCarrierSessionStore {
            store,
            files,
            scope,
            finalizer,
            retirement,
            normal: CompletionState::default(),
            initial: InitialDataCompletionState::default(),
            completed: None,
        },
    ))
}

#[cfg(test)]
#[test]
fn carrier_factory_selects_new_path_for_supported_pair_type_contract() {
    // Windows compile/type gate, NOT SDK execution: the actual production
    // factory cannot regress to SessionNativePair<WindowsPairIo> unnoticed.
    fn require_actual_factory<
        F: crate::member_actor::PairFactory<
            Native = NativeFactoryControl,
            Store = NativeCarrierSessionStore,
        >,
    >() {
    }
    require_actual_factory::<super::member_pair::NativePairFactory<NativeSessionFiles>>();
}
