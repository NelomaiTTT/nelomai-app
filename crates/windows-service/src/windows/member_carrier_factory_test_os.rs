//! Test-only external source/filesystem inputs. No selector, Startup, journal,
//! coordinator, ownership, native-effect or completion implementation is fake.
//! Cold fixtures use signed DATA. Native fixtures use the audited genuine DLLs
//! and external package inventory; SDK effects remain in the production path.
use super::{
    member_carrier_wintun::native::NativeKernelReferenceRead, member_files,
    member_pair::NativePairFactory, member_session::*,
};
use nelomai_contracts::dispatcher::{self as d, Installation, MutationGuard};
use std::{
    any::Any,
    cell::{Cell, RefCell},
    io,
    path::{Path, PathBuf},
    rc::{Rc, Weak},
    sync::{atomic::AtomicBool, Arc},
};

struct Inputs {
    root: PathBuf,
    state: PathBuf,
    executable: Option<PathBuf>,
    key: [u8; 32],
    fault: Option<(member_files::PrivateFile, bool)>,
    native_fault: Option<(NativePublication, bool)>,
    native_fault_reached: Option<NativePublication>,
    native_originals: Vec<(&'static str, Weak<dyn Any>)>,
    package_source_reads: usize,
    package_paths: Option<[PathBuf; 5]>,
    wireguard_package: Option<([PathBuf; 5], u64)>,
    native_loads: usize,
    module_originals: Vec<Weak<dyn Any>>,
    inventory_fault: Option<bool>,
    inventory_fault_reached: bool,
    resolver_reference_fault: Option<bool>,
    resolver_reference_fault_reached: bool,
    resolver_reference_acquisitions: usize,
    resolver_reference_releases: usize,
    resolver_reference_original: Option<Weak<NativeKernelReferenceRead>>,
    adapter_reference_fault: Option<bool>,
    adapter_reference_fault_reached: bool,
    adapter_reference_acquisitions: usize,
    adapter_reference_releases: usize,
    adapter_reference_original: Option<Weak<NativeKernelReferenceRead>>,
    adapter_create_attempts: usize,
    route_postflight_fault: Option<bool>,
    route_postflight_fault_reached: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativePublication {
    Carrier,
    Member,
    Running,
}
thread_local! {
    static INPUTS: RefCell<Option<Inputs>> = const { RefCell::new(None) };
    static RUNTIME_CURRENT_CHECKS: Cell<u64> = const { Cell::new(0) };
    static SOURCE_CURRENT_CHECKS: Cell<u64> = const { Cell::new(0) };
}
pub(crate) fn installation(root: &Path) -> Option<Installation> {
    INPUTS.with(|inputs| {
        inputs
            .borrow()
            .as_ref()
            .filter(|v| v.root == root)
            .map(|v| Installation::for_owner(root, v.key, "windows", "x86_64", 0))
    })
}
pub(crate) fn executable() -> Option<PathBuf> {
    INPUTS.with(|inputs| inputs.borrow().as_ref().and_then(|v| v.executable.clone()))
}
pub(crate) fn key(directory: &Path) -> Option<[u8; 32]> {
    INPUTS.with(|inputs| {
        inputs
            .borrow()
            .as_ref()
            .filter(|v| directory.starts_with(&v.root))
            .map(|v| v.key)
    })
}
pub(crate) fn state() -> Option<PathBuf> {
    INPUTS.with(|inputs| inputs.borrow().as_ref().map(|v| v.state.clone()))
}
pub(crate) fn publication_ack(file: member_files::PrivateFile, desired: &[u8]) -> io::Result<()> {
    INPUTS.with(|inputs| {
        let mut inputs = inputs.borrow_mut();
        let Some(inputs) = inputs.as_mut() else {
            return Ok(());
        };
        if let Some((target, unwind)) = inputs.native_fault.filter(|(target, _)| {
            file == match target {
                NativePublication::Carrier | NativePublication::Member => {
                    member_files::PrivateFile::Pair
                }
                NativePublication::Running => member_files::PrivateFile::Session,
            }
        }) {
            // Only external filesystem ACK selection. These published DATA
            // do not choose the production path or supply owning receipts.
            let envelope: serde_json::Value = serde_json::from_slice(desired)?;
            let wrapped: serde_json::Value = serde_json::from_str(
                envelope["data"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("fixture envelope"))?,
            )?;
            let payload = &wrapped["payload"];
            let reached = match (target, file) {
                (
                    NativePublication::Carrier | NativePublication::Member,
                    member_files::PrivateFile::Pair,
                ) => {
                    let record: crate::member_carrier_pair::Record =
                        serde_json::from_value(payload.clone())?;
                    record.pending.is_none()
                        && record.carrier.is_some()
                        && if target == NativePublication::Carrier {
                            record.phase == crate::member_carrier_pair::Phase::Starting
                                && match record.operation {
                                    Some(crate::member_carrier_pair::Operation::Start(slot)) => {
                                        let i = usize::from(
                                            slot == nelomai_client_tunnel::redundancy::Slot::B,
                                        );
                                        record.members[i].as_ref().is_some_and(|member| {
                                            member.owner.phase
                                                == crate::member_owner::Phase::Prepared
                                        }) && record.members[1 - i].is_none()
                                    }
                                    _ => false,
                                }
                        } else {
                            record.members.iter().flatten().any(|member| {
                                member.owner.phase == crate::member_owner::Phase::Running
                            })
                        }
                }
                (NativePublication::Running, member_files::PrivateFile::Session) => {
                    payload["session"]["phase"] == "Running"
                }
                _ => false,
            };
            if reached {
                require_native_originals(inputs, target);
                inputs.native_fault = None;
                inputs.native_fault_reached = Some(target);
                if unwind {
                    panic!("fixture {target:?} native publication ACK unwind");
                }
                return Err(io::Error::other("fixture native publication ACK lost"));
            }
        }
        if inputs
            .fault
            .as_ref()
            .is_some_and(|(target, _)| *target == file)
        {
            let (_, unwind) = inputs.fault.take().expect("selected external ACK fault");
            if unwind {
                panic!("fixture filesystem publication ACK unwind");
            }
            return Err(io::Error::other("fixture filesystem publication ACK lost"));
        }
        Ok(())
    })
}
// Only external SDK/table boundaries. The successful native create returns
// unchanged so its real owner retains the ACK before a later table-read fault.
pub(crate) fn route_created() {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            if inputs.route_postflight_fault == Some(false) {
                inputs.route_postflight_fault = Some(true);
            }
        }
    });
}
pub(crate) fn route_table_read() -> io::Result<()> {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            if inputs.route_postflight_fault == Some(true) {
                inputs.route_postflight_fault = None;
                inputs.route_postflight_fault_reached = true;
                return Err(io::Error::other(
                    "fixture route table read after native create ACK",
                ));
            }
        }
        Ok(())
    })
}
pub(crate) fn native_original_retained<T: Any>(kind: &'static str, original: &Rc<T>) {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            let root: Rc<dyn Any> = original.clone();
            inputs.native_originals.push((kind, Rc::downgrade(&root)));
        }
    });
    if kind == "carrier" {
        trace_step("C native CreateAdapter original ACK retained");
    }
}
fn require_native_originals(inputs: &Inputs, target: NativePublication) {
    for kind in ["carrier", "member"] {
        if kind == "member" && target == NativePublication::Carrier {
            continue;
        }
        let originals: Vec<_> = inputs
            .native_originals
            .iter()
            .filter(|(actual, _)| *actual == kind)
            .collect();
        assert_eq!(
            originals.len(),
            1,
            "missing/repeated actual {kind} return before {target:?}"
        );
        assert!(
            originals[0].1.upgrade().is_some(),
            "actual {kind} discarded before {target:?} ACK/protected completion"
        );
    }
}
pub(crate) fn package_source_read() {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            inputs.package_source_reads += 1;
        }
    });
}
pub(crate) fn native_module_loaded<T: Any>(module: &Rc<T>) {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            inputs.native_loads += 1;
            let original: Rc<dyn Any> = module.clone();
            inputs.module_originals.push(Rc::downgrade(&original));
        }
    });
}
/// External failure after the real OS return, never a synthetic acquisition.
pub(crate) fn native_resolver_reference_returned(
    original: &Rc<NativeKernelReferenceRead>,
) -> io::Result<()> {
    INPUTS.with(|inputs| {
        let mut inputs = inputs.borrow_mut();
        let Some(inputs) = inputs.as_mut() else {
            return Ok(());
        };
        inputs.resolver_reference_acquisitions += 1;
        inputs.resolver_reference_original = Some(Rc::downgrade(original));
        if let Some(unwind) = inputs.resolver_reference_fault.take() {
            inputs.resolver_reference_fault_reached = true;
            assert_eq!(inputs.resolver_reference_acquisitions, 1);
            assert_eq!(inputs.native_loads, 1);
            assert!(inputs.module_originals[0].upgrade().is_some());
            if unwind {
                panic!("fixture post-GetModuleHandleEx reference return unwind");
            }
            return Err(io::Error::other(
                "fixture resolver reference postflight lost",
            ));
        }
        Ok(())
    })
}
pub(crate) fn native_resolver_reference_release_attempted() {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            inputs.resolver_reference_releases += 1;
        }
    });
}
/// Postflight fault after the DISTINCT adapter reference actually returned.
pub(crate) fn native_adapter_reference_returned(
    original: &Rc<NativeKernelReferenceRead>,
) -> io::Result<()> {
    INPUTS.with(|inputs| {
        let mut inputs = inputs.borrow_mut();
        let Some(inputs) = inputs.as_mut() else {
            return Ok(());
        };
        inputs.adapter_reference_acquisitions += 1;
        inputs.adapter_reference_original = Some(Rc::downgrade(original));
        if let Some(unwind) = inputs.adapter_reference_fault.take() {
            inputs.adapter_reference_fault_reached = true;
            assert_eq!(inputs.adapter_reference_acquisitions, 1);
            assert_eq!(inputs.adapter_create_attempts, 0);
            original
                .verify_retained_original()
                .expect("actual adapter reference");
            if unwind {
                panic!("fixture post-GetModuleHandleEx adapter reference unwind");
            }
            return Err(io::Error::other(
                "fixture adapter reference postflight lost",
            ));
        }
        Ok(())
    })
}
pub(crate) fn native_adapter_create_attempted() {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            inputs.adapter_create_attempts += 1;
        }
    });
}
pub(crate) fn native_adapter_reference_release_attempted() {
    INPUTS.with(|inputs| {
        if let Some(inputs) = inputs.borrow_mut().as_mut() {
            inputs.adapter_reference_releases += 1;
        }
    });
}
pub(crate) fn package_paths(source: &Path) -> io::Result<Option<[PathBuf; 5]>> {
    INPUTS.with(|inputs| {
        let mut inputs = inputs.borrow_mut();
        let Some(inputs) = inputs.as_mut().filter(|v| source.starts_with(&v.root)) else {
            return Ok(None);
        };
        if inputs.native_loads > 0 {
            if let Some(unwind) = inputs.inventory_fault.take() {
                // Observe retention AT the external failure boundary, before
                // SessionDriver may perform its actual original Stop on Err.
                assert_eq!(inputs.native_loads, 1);
                assert_eq!(inputs.module_originals.len(), 1);
                assert!(
                    inputs.module_originals[0].upgrade().is_some(),
                    "actual returned module missing at post-load fault"
                );
                inputs.inventory_fault_reached = true;
                if unwind {
                    panic!("fixture package inventory read after native LoadLibrary");
                }
                return Err(io::Error::other("fixture package inventory read lost"));
            }
        }
        Ok(inputs.package_paths.clone())
    })
}
pub(crate) fn wireguard_package_paths(source: &Path) -> Option<([PathBuf; 5], u64)> {
    INPUTS.with(|inputs| {
        inputs
            .borrow()
            .as_ref()
            .filter(|v| source.starts_with(&v.root))
            .and_then(|v| v.wireguard_package.clone())
    })
}

pub(crate) fn trace_native(step: &'static str, error: &crate::member_carrier::CarrierError) {
    if state().is_some() {
        eprintln!("actual native step {step}: {error:?} tick={}", unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        });
    }
}
pub(crate) fn trace_step(step: &str) {
    if INPUTS.with(|inputs| inputs.borrow().is_some()) {
        match step {
            "runtime current check" => {
                RUNTIME_CURRENT_CHECKS.with(|count| count.set(count.get() + 1));
                return;
            }
            "source current check" => {
                SOURCE_CURRENT_CHECKS.with(|count| count.set(count.get() + 1));
                return;
            }
            _ => {}
        }
        eprintln!("actual native step {step} tick={}", unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        });
    }
}

// Created before Fixture so ordinary return/unwind reports after its teardown.
// Counters live separately from INPUTS, which Fixture::drop clears first.
pub(crate) struct ChildCurrentCheckReport;
impl ChildCurrentCheckReport {
    pub(crate) fn new() -> Self {
        RUNTIME_CURRENT_CHECKS.with(|count| count.set(0));
        SOURCE_CURRENT_CHECKS.with(|count| count.set(0));
        Self
    }
}
impl Drop for ChildCurrentCheckReport {
    fn drop(&mut self) {
        use std::io::Write as _;
        let runtime = RUNTIME_CURRENT_CHECKS.with(Cell::get);
        let source = SOURCE_CURRENT_CHECKS.with(Cell::get);
        // A lost footer is unknown to the parent. Never double-panic on stderr
        // failure while already unwinding an actual native scenario.
        let _ = writeln!(
            std::io::stderr().lock(),
            "actual native factory current checks runtime_current_check_attempts={runtime} source_current_check_attempts={source}"
        );
    }
}

pub(crate) struct Fixture {
    root: PathBuf,
    state: PathBuf,
    installation: Installation,
    identity: d::EngineIdentity,
    executable: PathBuf,
}
impl Fixture {
    pub(crate) fn original_root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn new() -> io::Result<Self> {
        Self::with_runtime(None)
    }
    pub(crate) fn new_native_modules() -> io::Result<Self> {
        let directory = std::env::var_os("NELOMAI_FACTORY_RUNTIME_DIRECTORY")
            .ok_or_else(|| io::Error::other("actual factory runtime fixture input absent"))?;
        Self::with_runtime(Some(PathBuf::from(directory)))
    }
    fn with_runtime(native_runtime: Option<PathBuf>) -> io::Result<Self> {
        use ed25519_dalek::{Signer, SigningKey};
        use member_files::SessionFileIo;
        use nelomai_contracts::CONTAINER_MANIFEST_SIGNATURE_DOMAIN;
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                },
                SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::CreateDirectoryW,
        };
        if INPUTS.with(|inputs| inputs.borrow().is_some()) {
            return Err(io::Error::other("nested factory OS fixture"));
        }
        // Fresh owned CI directory only. No existing parent ACL, token,
        // privileged runtime, service, driver, NIC or product record is changed.
        let nonce = format!(
            "Nelomai-FactoryFixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos()
        );
        let parent = PathBuf::from(
            std::env::var_os("ProgramData")
                .ok_or_else(|| io::Error::other("ProgramData absent"))?,
        )
        .join(nonce);
        let root = parent.join("installation");
        let sddl = super::wide("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let created = unsafe { CreateDirectoryW(super::wide(&parent).as_ptr(), &attributes) };
        let error = io::Error::last_os_error();
        // Installation::install preserves Windows ACLs; its portable filesystem
        // writer does not create a protected native root. Exclusively create our
        // new root with the exact private DACL before installing signed bytes.
        let root_created = if created != 0 {
            unsafe { CreateDirectoryW(super::wide(&root).as_ptr(), &attributes) }
        } else {
            0
        };
        let root_error = io::Error::last_os_error();
        unsafe {
            LocalFree(descriptor);
        }
        if created == 0 {
            return Err(error);
        }
        if root_created == 0 {
            return Err(root_error);
        }
        let state = parent.join("state");
        let key = SigningKey::from_bytes(&[83; 32]); // existing test trust boundary only
        INPUTS.with(|inputs| {
            *inputs.borrow_mut() = Some(Inputs {
                root: root.clone(),
                state: state.clone(),
                executable: None,
                key: key.verifying_key().to_bytes(),
                fault: None,
                native_fault: None,
                native_fault_reached: None,
                native_originals: vec![],
                package_source_reads: 0,
                package_paths: None,
                wireguard_package: None,
                native_loads: 0,
                module_originals: vec![],
                inventory_fault: None,
                inventory_fault_reached: false,
                resolver_reference_fault: None,
                resolver_reference_fault_reached: false,
                resolver_reference_acquisitions: 0,
                resolver_reference_releases: 0,
                resolver_reference_original: None,
                adapter_reference_fault: None,
                adapter_reference_fault_reached: false,
                adapter_reference_acquisitions: 0,
                adapter_reference_releases: 0,
                adapter_reference_original: None,
                adapter_create_attempts: 0,
                route_postflight_fault: None,
                route_postflight_fault_reached: false,
            })
        });
        // Real private-directory/ancestor/lock/CAS implementation creates state.
        let mut backend = member_files::MemberFiles::new().map_err(io::Error::other)?;
        backend.transaction(|_| Ok(()))?;
        let source = parent.join("source");
        let bin = source.join("engines/latest/0.3.3");
        std::fs::create_dir_all(&bin)?;
        let names = [
            "nelomai-windows-service.exe",
            "wintun.dll",
            "wireguard.dll",
            "tunnel.dll",
            "amneziawg-tunnel.dll",
        ];
        let payloads = match &native_runtime {
            Some(directory) => names
                .iter()
                .map(|name| std::fs::read(directory.join(name)))
                .collect::<io::Result<Vec<_>>>()?,
            None => names
                .iter()
                .map(|name| format!("fixture {name} DATA").into_bytes())
                .collect(),
        };
        let mut files = Vec::new();
        for (index, (name, bytes)) in names.iter().zip(&payloads).enumerate() {
            let role = if index == 0 {
                "executable"
            } else {
                "shared_library"
            };
            std::fs::write(bin.join(name), bytes)?;
            files.push(serde_json::json!({"path": name, "size_bytes": bytes.len(), "sha256": d::digest(bytes), "role": role}));
        }
        let manifest = serde_json::to_vec(&serde_json::json!({
            "format_version": 1, "container_version": "0.3.3", "release_set_id": "factory-fixture",
            "minimum_runtime_contract": 1, "maximum_runtime_contract": 1,
            "slots": [{"slot": "latest", "manifest": {"format_version": 1,
                "runtime_version": "0.3.3", "source_commit": "a".repeat(40), "platform": "windows",
                "architecture": "x86_64", "contract_version": 1, "files": files}}]
        }))?;
        let message = [CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &manifest].concat();
        std::fs::write(source.join(d::MANIFEST_NAME), &manifest)?;
        std::fs::write(
            source.join(d::SIGNATURE_NAME),
            key.sign(&message).to_bytes(),
        )?;
        let client = parent.join("client.exe");
        std::fs::write(&client, b"fixture client DATA")?;
        let installation = Installation::for_owner(
            &root,
            key.verifying_key().to_bytes(),
            "windows",
            "x86_64",
            0,
        );
        let layout = installation.install(&source, &client, "S-1-5-21-1000", &d::RealInstallIo)?;
        let executable = std::fs::canonicalize(layout.engine_path())?;
        if native_runtime.is_some() {
            let wireguard_package =
                crate::member_owner::cold_wireguard_data::native::prepare_fixture_package(
                    &executable.with_file_name("wireguard.dll"),
                    &parent.join("wireguard-package-input"),
                )
                .map_err(|e| {
                    io::Error::other(format!("audited WireGuard package fixture: {e:?}"))
                })?;
            let paths = super::member_carrier_wintun_package::native::prepare_fixture_package(
                &executable.with_file_name("wintun.dll"),
                &parent.join("package-input"),
            )
            .map_err(|e| io::Error::other(format!("audited package fixture: {e:?}")))?;
            INPUTS.with(|inputs| {
                let mut inputs = inputs.borrow_mut();
                let inputs = inputs.as_mut().expect("fixture inputs");
                inputs.package_paths = Some(paths);
                inputs.wireguard_package = Some(wireguard_package);
            });
        }
        INPUTS.with(|inputs| {
            inputs
                .borrow_mut()
                .as_mut()
                .expect("fixture inputs")
                .executable = Some(executable.clone())
        });
        Ok(Self {
            root,
            state,
            installation,
            identity: layout.identity,
            executable,
        })
    }
    pub(crate) fn factory(&self) -> io::Result<NativePairFactory<NativeSessionFiles>> {
        member_files::pin_private_directory(&self.root)
            .map_err(|e| io::Error::other(format!("fixture native root pin: {e:?}")))?
            .verify()
            .map_err(|e| io::Error::other(format!("fixture native root continuity: {e:?}")))?;
        let files = ProtectedSessionFiles::new(
            member_files::MemberFiles::new().map_err(io::Error::other)?,
            self.identity.clone(),
            super::member_boot::boot_id()?,
        )?;
        let owner = Arc::new(MutationGuard::at(&self.root.join("engine-owner.lock"))?);
        NativePairFactory::new(
            files,
            self.identity.slot,
            &self.executable,
            &self.root,
            owner,
            Arc::new(AtomicBool::new(false)),
        )
    }
    pub(crate) fn lose_ack(&self, target: member_files::PrivateFile, unwind: bool) {
        INPUTS.with(|inputs| {
            inputs.borrow_mut().as_mut().expect("fixture inputs").fault = Some((target, unwind))
        });
    }
    pub(crate) fn lose_route_postflight(&self) {
        INPUTS.with(|inputs| {
            inputs
                .borrow_mut()
                .as_mut()
                .expect("fixture inputs")
                .route_postflight_fault = Some(false);
        });
    }
    pub(crate) fn require_route_postflight_fault(&self) {
        INPUTS.with(|inputs| {
            let inputs = inputs.borrow();
            let inputs = inputs.as_ref().expect("fixture inputs");
            assert!(
                inputs.route_postflight_fault_reached,
                "actual successful route create/table fault not reached"
            );
            assert!(inputs.route_postflight_fault.is_none());
        });
    }
    pub(crate) fn lose_native_publication_ack(&self, target: NativePublication, unwind: bool) {
        INPUTS.with(|inputs| {
            inputs
                .borrow_mut()
                .as_mut()
                .expect("fixture inputs")
                .native_fault = Some((target, unwind))
        });
    }
    pub(crate) fn require_native_publication_fault(
        &self,
        target: NativePublication,
        pending: bool,
    ) {
        INPUTS.with(|inputs| {
            let inputs = inputs.borrow();
            let inputs = inputs.as_ref().expect("fixture inputs");
            assert_eq!(
                inputs.native_fault_reached,
                Some(target),
                "actual publication fault not reached"
            );
            assert!(inputs.native_fault.is_none());
            if pending {
                require_native_originals(inputs, target);
            }
        });
    }
    pub(crate) fn lose_inventory_after_load(&self, unwind: bool) {
        INPUTS.with(|inputs| {
            inputs
                .borrow_mut()
                .as_mut()
                .expect("fixture inputs")
                .inventory_fault = Some(unwind)
        });
    }
    pub(crate) fn lose_resolver_reference_postflight(&self, unwind: bool) {
        INPUTS.with(|inputs| {
            inputs
                .borrow_mut()
                .as_mut()
                .expect("fixture inputs")
                .resolver_reference_fault = Some(unwind);
        });
    }
    pub(crate) fn require_retained_resolver_reference(&self) {
        INPUTS.with(|inputs| {
            let inputs = inputs.borrow();
            let inputs = inputs.as_ref().expect("fixture inputs");
            assert!(inputs.resolver_reference_fault_reached);
            assert!(inputs.resolver_reference_fault.is_none());
            assert_eq!(
                inputs.resolver_reference_acquisitions, 1,
                "native reference acquisition retried"
            );
            assert_eq!(
                inputs.resolver_reference_releases, 0,
                "uncertain resolver reference released"
            );
            // Upgrade only for this read. The fixture keeps no owning alias;
            // this SAME object owns the actual native pin, not a counter copy.
            inputs
                .resolver_reference_original
                .as_ref()
                .expect("actual reference origin")
                .upgrade()
                .expect("caller lost the original native kernel reference owner")
                .verify_retained_original()
                .expect("original native pin/return was lost or released");
            assert!(
                inputs.module_originals[0].upgrade().is_some(),
                "caller lost the original loaded module owner"
            );
        });
    }
    pub(crate) fn lose_adapter_reference_postflight(&self, unwind: bool) {
        INPUTS.with(|inputs| {
            inputs
                .borrow_mut()
                .as_mut()
                .expect("fixture inputs")
                .adapter_reference_fault = Some(unwind);
        });
    }
    pub(crate) fn require_retained_adapter_reference(&self) {
        INPUTS.with(|inputs| {
            let inputs = inputs.borrow();
            let inputs = inputs.as_ref().expect("fixture inputs");
            assert!(inputs.adapter_reference_fault_reached);
            assert!(inputs.adapter_reference_fault.is_none());
            assert_eq!(
                inputs.adapter_reference_acquisitions, 1,
                "adapter reference retried"
            );
            assert_eq!(
                inputs.adapter_reference_releases, 0,
                "adapter reference released"
            );
            assert_eq!(
                inputs.adapter_create_attempts, 0,
                "adapter create reached after fault"
            );
            assert!(
                inputs.native_originals.is_empty(),
                "adapter ACK manufactured"
            );
            // The fixture owns only Weak; this SAME rooted object must still
            // own the actual returned original HMODULE after Err/unwind/Stop.
            let adapter = inputs
                .adapter_reference_original
                .as_ref()
                .expect("actual adapter reference origin")
                .upgrade()
                .expect("caller lost the original adapter reference owner");
            adapter
                .verify_retained_original()
                .expect("original adapter pin/return lost");
            let resolver = inputs
                .resolver_reference_original
                .as_ref()
                .expect("actual resolver reference origin")
                .upgrade()
                .expect("caller lost the distinct resolver reference owner");
            assert!(
                !adapter.same_original(&resolver),
                "distinct acquisitions merged"
            );
            assert_eq!(inputs.native_loads, 1);
            assert!(
                inputs.module_originals[0].upgrade().is_some(),
                "original loaded module lost"
            );
        });
    }
    pub(crate) fn require_original_load_and_fault(&self, cleanup_pending: bool) {
        INPUTS.with(|inputs| {
            let inputs = inputs.borrow();
            let inputs = inputs.as_ref().expect("fixture inputs");
            assert_eq!(
                inputs.native_loads, 1,
                "missing/repeated actual LoadLibrary ACK"
            );
            assert_eq!(inputs.module_originals.len(), 1);
            if cleanup_pending {
                assert!(
                    inputs.module_originals[0].upgrade().is_some(),
                    "actual returned module owner discarded before protected completion"
                );
            }
            assert!(
                inputs.inventory_fault_reached,
                "post-load external read fault not reached"
            );
            assert!(inputs.inventory_fault.is_none());
        });
    }
    pub(crate) fn verify_files(&self) -> io::Result<()> {
        if INPUTS.with(|inputs| inputs.borrow().as_ref().is_none_or(|v| v.fault.is_some())) {
            return Err(io::Error::other(
                "requested filesystem ACK fault was not reached",
            ));
        }
        self.installation.load_engine(&self.executable)?;
        if !self.state.is_dir() {
            return Err(io::Error::other("original fixture state lost"));
        }
        Ok(())
    }
    pub(crate) fn require_package_source_read(&self) {
        assert!(
            INPUTS.with(|inputs| inputs
                .borrow()
                .as_ref()
                .is_some_and(|v| v.package_source_reads > 0)),
            "primary did not reach the actual carrier package source read"
        );
    }
    pub(crate) fn trace_pair_stage(&self) {
        use member_files::SessionFileIo;
        let result = (|| -> io::Result<()> {
            let mut files = member_files::MemberFiles::new().map_err(io::Error::other)?;
            let raw = files
                .transaction(|records| records.read(member_files::PrivateFile::Pair))?
                .ok_or_else(|| io::Error::other("fixture Pair absent"))?;
            let envelope: serde_json::Value = serde_json::from_slice(&raw)?;
            let data = envelope
                .get("data")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other("fixture Pair payload missing"))?;
            let wrapped: serde_json::Value = serde_json::from_str(data)?;
            let pair = wrapped
                .get("payload")
                .ok_or_else(|| io::Error::other("fixture Pair envelope payload missing"))?;
            eprintln!(
                "actual Pair phase={} stop_stage={} pending={}",
                pair["phase"], pair["stop_stage"], pair["pending"]
            );
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("actual Pair diagnostic read: {error}");
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        INPUTS.with(|inputs| inputs.borrow_mut().take());
        // No guessed cleanup of uncertain protected publications. Each child
        // exits with its original roots retained; ephemeral CI owns the tree.
    }
}
