//! Test-only external source/filesystem inputs. No selector, Startup, journal,
//! coordinator, ownership, native-effect or completion implementation is fake.
//! Cold fixtures use signed DATA. Module-only fixtures use the audited genuine
//! Wintun DLL and external package inventory; no constructor is invoked.
use super::{member_files, member_pair::NativePairFactory, member_session::*};
use nelomai_contracts::dispatcher::{self as d, Installation, MutationGuard};
use std::{
    any::Any,
    cell::RefCell,
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
    package_source_reads: usize,
    package_paths: Option<[PathBuf; 5]>,
    native_loads: usize,
    module_originals: Vec<Weak<dyn Any>>,
    inventory_fault: Option<bool>,
    inventory_fault_reached: bool,
}
thread_local! {
    static INPUTS: RefCell<Option<Inputs>> = const { RefCell::new(None) };
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
pub(crate) fn publication_ack(file: member_files::PrivateFile) -> io::Result<()> {
    INPUTS.with(|inputs| {
        let mut inputs = inputs.borrow_mut();
        let Some(inputs) = inputs.as_mut() else {
            return Ok(());
        };
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
pub(crate) fn package_paths(source: &Path) -> io::Result<Option<[PathBuf; 5]>> {
    INPUTS.with(|inputs| {
        let mut inputs = inputs.borrow_mut();
        let Some(inputs) = inputs.as_mut().filter(|v| source.starts_with(&v.root)) else {
            return Ok(None);
        };
        if inputs.native_loads > 0 {
            if let Some(unwind) = inputs.inventory_fault.take() {
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

pub(crate) fn trace_native(step: &'static str, error: &crate::member_carrier::CarrierError) {
    if state().is_some() {
        eprintln!("actual native step {step}: {error:?} tick={}", unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        });
    }
}
pub(crate) fn trace_step(step: &'static str) {
    if state().is_some() {
        eprintln!("actual native step {step} tick={}", unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        });
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
    pub(crate) fn new() -> io::Result<Self> {
        Self::with_wintun(None)
    }
    pub(crate) fn new_module_only() -> io::Result<Self> {
        let path = std::env::var_os("NELOMAI_FACTORY_WINTUN_DLL")
            .ok_or_else(|| io::Error::other("audited Wintun DLL fixture input absent"))?;
        Self::with_wintun(Some(std::fs::read(path)?))
    }
    fn with_wintun(wintun: Option<Vec<u8>>) -> io::Result<Self> {
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
                package_source_reads: 0,
                package_paths: None,
                native_loads: 0,
                module_originals: vec![],
                inventory_fault: None,
                inventory_fault_reached: false,
            })
        });
        // Real private-directory/ancestor/lock/CAS implementation creates state.
        let mut backend = member_files::MemberFiles::new().map_err(io::Error::other)?;
        backend.transaction(|_| Ok(()))?;
        let source = parent.join("source");
        let bin = source.join("engines/latest/0.3.3");
        std::fs::create_dir_all(&bin)?;
        let payloads: [(&str, &[u8], &str); 5] = [
            (
                "nelomai-windows-service.exe",
                b"fixture engine DATA",
                "executable",
            ),
            (
                "wintun.dll",
                wintun.as_deref().unwrap_or(b"fixture Wintun DATA"),
                "shared_library",
            ),
            ("wireguard.dll", b"fixture WG DATA", "shared_library"),
            ("tunnel.dll", b"fixture tunnel DATA", "shared_library"),
            (
                "amneziawg-tunnel.dll",
                b"fixture AWG DATA",
                "shared_library",
            ),
        ];
        let mut files = Vec::new();
        for (name, bytes, role) in payloads {
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
        if wintun.is_some() {
            let paths = super::member_carrier_wintun_package::native::prepare_fixture_package(
                &executable.with_file_name("wintun.dll"),
                &parent.join("package-input"),
            )
            .map_err(|e| io::Error::other(format!("audited package fixture: {e:?}")))?;
            INPUTS.with(|inputs| {
                inputs
                    .borrow_mut()
                    .as_mut()
                    .expect("fixture inputs")
                    .package_paths = Some(paths)
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
    pub(crate) fn lose_inventory_after_load(&self, unwind: bool) {
        INPUTS.with(|inputs| {
            inputs
                .borrow_mut()
                .as_mut()
                .expect("fixture inputs")
                .inventory_fault = Some(unwind)
        });
    }
    pub(crate) fn require_original_load_and_fault(&self) {
        INPUTS.with(|inputs| {
            let inputs = inputs.borrow();
            let inputs = inputs.as_ref().expect("fixture inputs");
            assert_eq!(
                inputs.native_loads, 1,
                "missing/repeated actual LoadLibrary ACK"
            );
            assert_eq!(inputs.module_originals.len(), 1);
            assert!(
                inputs.module_originals[0].upgrade().is_some(),
                "actual returned module owner was discarded after Err/unwind"
            );
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
