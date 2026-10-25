//! Explicit production selector; the carrier factory is cleanup-only here.
use super::{
    member_files::{MemberFiles, PrivateFile, SessionFileIo},
    member_pair::NativePairFactory,
    member_session::{NativeSessionFiles, SessionFiles},
    member_worker::{self, Control, Store},
    member_worker_guard::Guard,
};
use crate::{
    member_actor::PairFactory,
    member_diagnostic::{context, PairFailure},
    member_pair::FactoryPreparationSlot,
    ServiceError,
};
use nelomai_client_tunnel::redundancy::{
    control::SessionControl, protocol::Command, session::SessionPhase,
};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, MutationGuard},
    RuntimeSlot,
};
use std::{
    cell::RefCell,
    io,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

pub(crate) struct WorkerPairFactory {
    legacy: NativePairFactory<NativeSessionFiles>,
    files: NativeSessionFiles,
    root: PathBuf,
    owner: Arc<MutationGuard>,
    runtime: RuntimeSlot,
    preparation: FactoryPreparationSlot<SessionControl<Control, Store>>,
    recovery: Option<member_worker::SharedJournal>,
    recovery_guard: Option<
        Rc<super::member_carrier_guard::NativeColdStaticCleanup<RefCell<member_worker::Journal>>>,
    >,
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
            recovery: None,
            recovery_guard: None,
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
            self.owner
                .verify_at(&self.root.join("engine-owner.lock"))
                .map_err(|e| context("worker_cold_owner", e))?;
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
            let mut private =
                MemberFiles::new().map_err(|e| PairFailure::owner("worker_cold_read", e))?;
            let record = private
                .transaction(|files| files.read(PrivateFile::Worker))
                .map_err(|e| context("worker_cold_read", e))?;
            if let Some(bytes) = record {
                if self.recovery.is_some() {
                    return Err(io::Error::other("worker_cold_previous_attempt"));
                }
                let data: member_worker::Record = serde_json::from_slice(&bytes)
                    .map_err(|e| context("worker_cold_decode", e.into()))?;
                if data.scope.runtime != runtime || !data.scope.validate() {
                    return Err(io::Error::other("worker_cold_scope"));
                }
                let mut files = self
                    .files
                    .recovery_view(runtime)
                    .map_err(|e| context("worker_cold_protected_context", e))?
                    .map(|(files, _)| files)
                    .unwrap_or_else(|| self.files.clone());
                let selected = files
                    .inspect_recovery_records(runtime, |facts| Ok(facts.clone()))
                    .map_err(|e| context("worker_cold_protected_context", e))?;
                if data.stopped || (selected.is_none() && files.verify_completed_worker().is_ok()) {
                    member_worker::terminal_identity(&bytes, !data.stopped)?;
                    files.verify_completed_worker()?;
                    member_worker::verify_terminal_record(&bytes)?;
                    let mut observer =
                        Guard::open(crate::member_worker_guard::Model::empty(data.scope))
                            .map_err(|e| io::Error::other(format!("worker_guard_absence:{e:?}")))?;
                    observer
                        .close(false, None)
                        .map_err(|e| io::Error::other(format!("worker_guard_absence:{e:?}")))?;
                } else {
                    let selected =
                        selected.ok_or_else(|| io::Error::other("worker_cold_active_claim"))?;
                    if selected.scope != data.scope
                        || selected.provenance.runtime != data.runtime
                        || selected.provenance.boot_id != data.boot
                        || selected.worker.as_ref() != Some(&bytes)
                        || selected.records.iter().any(|(kind, record)| {
                            *kind != super::member_session::RecordKind::Session && record.is_some()
                        })
                    {
                        return Err(context(
                            "worker_cold_protected_context",
                            io::ErrorKind::Other.into(),
                        ));
                    }
                    let source = Rc::new(
                        super::member_carrier_payload::native::WorkerSource::new(
                            &self.root,
                            self.owner.clone(),
                        )
                        .map_err(|e| context("worker_cold_source", io::Error::other(e)))?,
                    );
                    let allow_effects = data.version == 2
                        && data.creator.is_some()
                        && data.process.is_some()
                        && data.boot == super::member_boot::boot_id()?
                        && data.runtime == *source.identity();
                    let physical = Rc::new(RefCell::new(
                        data.physical
                            .iter()
                            .map(super::member_session::PhysicalLease::restore)
                            .collect(),
                    ));
                    let journal = Rc::new(RefCell::new(member_worker::Journal {
                        private,
                        owner: self.owner.clone(),
                        root: self.root.clone(),
                        current: data,
                        expected: Some(bytes),
                        initial_attempt: None,
                        closing_attempt: None,
                        source,
                        cold: true,
                        retirement: None,
                        cleanup_busy: false,
                        retirement_attempted: false,
                        retirement_failed: false,
                        retirement_verified: false,
                        retirement_ack: None,
                        retained: None,
                    }));
                    self.recovery = Some(journal.clone());
                    journal
                        .borrow_mut()
                        .verify()
                        .map_err(|e| context("worker_cold_initial_verify", e))?;
                    let mut routes =
                        nelomai_client_tunnel::redundancy::network::NetworkOwner::recover(
                            member_worker::WorkerIdentity {
                                original: None,
                                journal: journal.clone(),
                                physical: physical.clone(),
                            },
                            member_worker::RouteJournal(journal.clone(), physical),
                            journal.borrow().current.network.clone(),
                        )
                        .map_err(|e| context("worker_cold_routes", e))?;
                    routes
                        .cleanup()
                        .map_err(|e| context("worker_cold_routes", e))?;
                    if allow_effects {
                        member_worker::Control::restore_dns(journal.clone(), None)
                            .map_err(|e| context("worker_cold_DNS_restore", e))?;
                    }
                    journal
                        .borrow_mut()
                        .save(|record| {
                            record.dns = None;
                            record.address = None;
                        })
                        .map_err(|e| context("worker_cold_save", e))?;
                    let scope = journal.borrow().current.scope.clone();
                    let cold = super::member_carrier_guard::issue_cold_static_cleanup(
                        scope,
                        journal.clone(),
                        |cold| {
                            self.recovery_guard = Some(cold);
                            Ok(())
                        },
                    )
                    .map_err(|e| PairFailure::guard("worker_cold_WFP_open", e))?;
                    cold.cleanup(allow_effects)
                        .map_err(|e| PairFailure::guard("worker_cold_WFP_delete", e))?;
                    if cold.disposition() != (true, true, false) {
                        return Err(io::Error::other("worker_cold_WFP_unconfirmed"));
                    }
                    let name = format!(
                        "NeloWorker-{}",
                        journal
                            .borrow()
                            .current
                            .scope
                            .session_id
                            .get(..8)
                            .ok_or_else(|| io::Error::other("worker_cold_scope_name"))?
                    );
                    if allow_effects && journal.borrow().current.interface.is_some() {
                        use super::member_carrier_provider as provider;
                        use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
                        let (proof, expected) = {
                            let mut state = journal.borrow_mut();
                            state.verify()?;
                            if !state.cold
                                || state.retained.is_some()
                                || state.retirement_failed
                                || state.cleanup_busy
                                || state.current.version != 2
                                || state.current.creator.is_none()
                                || state.current.process.is_none()
                                || state.current.runtime != *state.source.identity()
                                || state.current.boot != super::member_boot::boot_id()?
                                || cold.scope != state.current.scope
                                || cold.disposition() != (true, true, false)
                                || state.current.dns.is_some()
                                || state.current.address.is_some()
                            {
                                return Err(io::Error::other("worker_cold_PnP_authority"));
                            }
                            (
                                state
                                    .current
                                    .interface
                                    .ok_or_else(|| io::Error::other("worker_cold_PnP_identity"))?,
                                state.expected.clone(),
                            )
                        };
                        let targets = [provider::AbsenceTarget {
                            guid: proof.guid,
                            name: name.clone(),
                        }];
                        let rows = provider::native::table()
                            .map_err(|e| io::Error::other(format!("worker_cold_PnP_MIB:{e:?}")))?;
                        let mut want = provider::Expected {
                            guid: proof.guid,
                            luid: proof.luid,
                            index: proof.index,
                            name: name.clone(),
                            description: "WireGuard Tunnel".into(),
                            if_type: 53,
                            tunnel_type: 0,
                        };
                        provider::validate_expected(&want).map_err(|e| {
                            io::Error::other(format!("worker_cold_PnP_identity:{e:?}"))
                        })?;
                        let matching = rows
                            .iter()
                            .filter(|row| provider::collides(&want, row))
                            .collect::<Vec<_>>();
                        if matching.len() > 1 {
                            return Err(io::Error::other("worker_cold_PnP_MIB_namespace"));
                        }
                        let before = if let Some(row) = matching.first() {
                            want.description = row.identity.description.clone();
                            if (
                                row.identity.guid,
                                row.identity.luid,
                                row.identity.index,
                                row.identity.name.as_str(),
                                row.identity.if_type,
                                row.identity.tunnel_type,
                            ) != (proof.guid, proof.luid, proof.index, name.as_str(), 53, 0)
                                || !crate::member_interface_description::matches_requested(
                                    "WireGuard Tunnel",
                                    &want.description,
                                )
                            {
                                return Err(io::Error::other("worker_cold_PnP_MIB_binding"));
                            }
                            let observed = provider::native::interfaces(&want).map_err(|e| {
                                io::Error::other(format!("worker_cold_PnP_mapping:{e:?}"))
                            })?;
                            provider::validate_interfaces(&want, &observed).map_err(|e| {
                                io::Error::other(format!("worker_cold_PnP_mapping:{e:?}"))
                            })?;
                            Some(observed)
                        } else {
                            // Full zero tuple/name collisions, not an invented
                            // live mapping. Registry facts still bind the LUID.
                            None
                        };
                        let snapshot =
                            provider::native::device_snapshot(&targets).map_err(|e| {
                                io::Error::other(format!("worker_cold_PnP_census:{e:?}"))
                            })?;
                        let mut related = Vec::new();
                        for device in snapshot.nodes {
                            if provider::device_related(&targets, &device).map_err(|e| {
                                io::Error::other(format!("worker_cold_PnP_namespace:{e:?}"))
                            })? {
                                related.push(device);
                            }
                        }
                        if !related.is_empty() {
                            provider::validate_provider_device(
                                &want,
                                provider::ProviderKind::Wintun,
                                &related,
                                true,
                            )
                            .map_err(|e| {
                                io::Error::other(format!("worker_cold_PnP_phantom:{e:?}"))
                            })?;
                            let original = &related[0];
                            let class = windows_sys::core::GUID::from_u128(u128::from_be_bytes(
                                original.class_guid,
                            ));
                            let raw = unsafe {
                                SetupDiCreateDeviceInfoList(&class, std::ptr::null_mut())
                            };
                            if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as isize
                                || raw == 0
                            {
                                let error = io::Error::last_os_error();
                                #[cfg(test)]
                                eprintln!(
                                    "worker cold PnP SetupDiCreateDeviceInfoList failed: {error:?}"
                                );
                                return Err(error);
                            }
                            let set = provider::native::InfoSet(raw);
                            let mut selected = SP_DEVINFO_DATA {
                                cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                                ..Default::default()
                            };
                            let instance = original
                                .instance
                                .encode_utf16()
                                .chain(Some(0))
                                .collect::<Vec<_>>();
                            if unsafe {
                                SetupDiOpenDeviceInfoW(
                                    set.0,
                                    instance.as_ptr(),
                                    std::ptr::null_mut(),
                                    0,
                                    &mut selected,
                                )
                            } == 0
                            {
                                let error = io::Error::last_os_error();
                                #[cfg(test)]
                                eprintln!(
                                    "worker cold PnP SetupDiOpenDeviceInfoW failed: {error:?}"
                                );
                                return Err(error);
                            }
                            if selected.DevInst != original.devinst
                                || selected.ClassGuid.data1 != class.data1
                                || selected.ClassGuid.data2 != class.data2
                                || selected.ClassGuid.data3 != class.data3
                                || selected.ClassGuid.data4 != class.data4
                                || !provider::native::instance(&set, &selected)
                                    .map_err(|e| {
                                        io::Error::other(format!("worker_cold_PnP_selected:{e:?}"))
                                    })?
                                    .eq_ignore_ascii_case(&original.instance)
                                || provider::native::live(&original.instance, &selected).map_err(
                                    |e| io::Error::other(format!("worker_cold_PnP_selected:{e:?}")),
                                )? != (provider::Presence::Phantom, 0, 0)
                            {
                                return Err(io::Error::other("worker_cold_PnP_selected_changed"));
                            }
                            let snapshot =
                                provider::native::device_snapshot(&targets).map_err(|e| {
                                    io::Error::other(format!("worker_cold_PnP_recheck:{e:?}"))
                                })?;
                            let mut current = Vec::new();
                            for device in snapshot.nodes {
                                if provider::device_related(&targets, &device).map_err(|e| {
                                    io::Error::other(format!("worker_cold_PnP_namespace:{e:?}"))
                                })? {
                                    current.push(device);
                                }
                            }
                            provider::validate_provider_device(
                                &want,
                                provider::ProviderKind::Wintun,
                                &current,
                                true,
                            )
                            .map_err(|e| {
                                io::Error::other(format!("worker_cold_PnP_phantom:{e:?}"))
                            })?;
                            let after = if before.is_some() {
                                let observed =
                                    provider::native::interfaces(&want).map_err(|e| {
                                        io::Error::other(format!("worker_cold_PnP_mapping:{e:?}"))
                                    })?;
                                provider::validate_interfaces(&want, &observed).map_err(|e| {
                                    io::Error::other(format!("worker_cold_PnP_mapping:{e:?}"))
                                })?;
                                Some(observed)
                            } else {
                                let rows = provider::native::table().map_err(|e| {
                                    io::Error::other(format!("worker_cold_PnP_MIB:{e:?}"))
                                })?;
                                if rows.iter().any(|row| provider::collides(&want, row)) {
                                    return Err(io::Error::other(
                                        "worker_cold_PnP_MIB_absence_changed",
                                    ));
                                }
                                None
                            };
                            if current != related
                                || before
                                    .as_ref()
                                    .map(|o| (&o.by_guid, &o.by_index, &o.by_luid))
                                    != after
                                        .as_ref()
                                        .map(|o| (&o.by_guid, &o.by_index, &o.by_luid))
                            {
                                return Err(io::Error::other("worker_cold_PnP_binding_changed"));
                            }
                            {
                                let mut state = journal.borrow_mut();
                                state.verify()?;
                                if state.expected != expected
                                    || state.retained.is_some()
                                    || state.retirement_failed
                                    || state.cleanup_busy
                                    || cold.scope != state.current.scope
                                    || cold.disposition() != (true, true, false)
                                {
                                    return Err(io::Error::other(
                                        "worker_cold_PnP_authority_changed",
                                    ));
                                }
                            }
                            // Exact selected phantom only; no SDK adapter adoption or
                            // global driver cleanup. Registry query handles are gone.
                            let remove = SP_REMOVEDEVICE_PARAMS {
                                ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                                    cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                                    InstallFunction: DIF_REMOVE,
                                },
                                Scope: DI_REMOVEDEVICE_GLOBAL,
                                HwProfile: 0,
                            };
                            if unsafe {
                                SetupDiSetClassInstallParamsW(
                                    set.0,
                                    &selected,
                                    &remove.ClassInstallHeader,
                                    std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
                                )
                            } == 0
                            {
                                let error = io::Error::last_os_error();
                                #[cfg(test)]
                                eprintln!("worker cold PnP SetupDiSetClassInstallParamsW DIF_REMOVE failed: {error:?}");
                                return Err(error);
                            }
                            if unsafe { SetupDiCallClassInstaller(DIF_REMOVE, set.0, &selected) }
                                == 0
                            {
                                let error = io::Error::last_os_error();
                                #[cfg(test)]
                                eprintln!("worker cold PnP SetupDiCallClassInstaller DIF_REMOVE failed: {error:?}");
                                return Err(error);
                            }
                            journal.borrow_mut().verify()?;
                        }
                        if before.is_some() && !member_worker::absent(proof.guid, Some(proof))? {
                            // DIF_REMOVE can leave the exact old MIB row pending
                            // while the trigger-start cleanup service is idle.
                            // Same authority as removal; never wake for an
                            // unproven mapping or an already absent interface.
                            journal.borrow_mut().verify()?;
                            use windows_service::service::{ServiceAccess, ServiceState};
                            use windows_service::service_manager::{
                                ServiceManager, ServiceManagerAccess,
                            };
                            let manager = ServiceManager::local_computer(
                                None::<&str>,
                                ServiceManagerAccess::CONNECT,
                            )
                            .map_err(io::Error::other)?;
                            let service = manager
                                .open_service(
                                    "NetSetupSvc",
                                    ServiceAccess::START | ServiceAccess::QUERY_STATUS,
                                )
                                .map_err(io::Error::other)?;
                            match service.query_status().map_err(io::Error::other)?.current_state {
                                ServiceState::Running | ServiceState::StartPending => {}
                                ServiceState::Stopped => match service.start::<&str>(&[]) {
                                    Ok(()) => {}
                                    Err(windows_service::Error::Winapi(error))
                                        if error.raw_os_error()
                                            == Some(windows_sys::Win32::Foundation::ERROR_SERVICE_ALREADY_RUNNING as i32) => {}
                                    Err(error) => return Err(io::Error::other(error)),
                                },
                                _ => return Err(io::Error::other("worker_cold_cleanup_service")),
                            }
                            journal.borrow_mut().verify()?;
                        }
                    }
                    let deadline = Instant::now() + Duration::from_secs(7);
                    loop {
                        let gone = {
                            let journal = journal.borrow();
                            member_worker::absent(
                                journal.current.requested_guid,
                                if selected.changed_boot {
                                    None
                                } else {
                                    journal.current.interface
                                },
                            )
                            .map_err(|e| context("worker_cold_MIB_absence", e))?
                        };
                        if gone {
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(crate::member_diagnostic::context(
                                "worker_cold_MIB_absence",
                                io::Error::new(io::ErrorKind::TimedOut, "worker_cold_MIB_pending"),
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    super::member_carrier_provider::native::inspect_absent(
                        journal.borrow().current.requested_guid,
                        &name,
                    )
                    .map_err(|_| context("worker_cold_PnP", io::ErrorKind::Other.into()))?;
                    journal.borrow_mut().retirement_verified = true;
                    journal
                        .borrow_mut()
                        .verify()
                        .map_err(|e| context("worker_cold_retire", e))?;
                    let selected = files
                        .inspect_recovery_records(runtime, |facts| Ok(facts.clone()))
                        .map_err(|e| context("worker_cold_retire", e))?
                        .ok_or_else(|| io::Error::other("worker_cold_retirement_snapshot"))?;
                    journal.borrow_mut().retirement =
                        Some((files.read_identity(), selected.clone()));
                    files
                        .retire_native_empty(&selected, journal.as_ref(), |ack| {
                            journal.borrow_mut().retirement_ack = Some(ack);
                            Ok(())
                        })
                        .map_err(|e| context("worker_cold_retire", e))?;
                    let ack =
                        journal.borrow().retirement_ack.clone().ok_or_else(|| {
                            io::Error::other("worker_cold_retirement_unconfirmed")
                        })?;
                    if !ack.matches_origin(&files.read_identity()) {
                        return Err(io::Error::other("worker_cold_retirement_origin"));
                    }
                    journal
                        .borrow_mut()
                        .verify()
                        .map_err(|e| context("worker_cold_retire", e))?;
                    files
                        .verify_completed_worker()
                        .map_err(|e| context("worker_cold_retire", e))?;
                }
            }
            self.legacy
                .recover(runtime)
                .map_err(|_| io::Error::other("worker_legacy_cleanup"))?;
            self.recovery_guard = None;
            self.recovery = None;
            Ok(())
        })();
        result.map_err(|e| {
            #[cfg(test)]
            eprintln!("worker factory recovery failed: {e:?}");
            crate::member_actor::operation_failed("worker_recovery", e)
        })
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
