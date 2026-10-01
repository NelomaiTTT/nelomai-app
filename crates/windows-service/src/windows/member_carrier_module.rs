//! Retained original DLL loading only; never NIC/key/row/effect authority.
#![allow(dead_code)] // Carrier factory is still gated on lifecycle integration.

use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Conflict,
    Native,
    Cancelled,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Only the slow OS/authentication boundary is injected. No successful defaults.
trait Kernel {
    type Lease;
    type Module;
    fn source(&mut self) -> Result<()>;
    fn absent_module(&mut self) -> Result<()>;
    fn lease(&mut self, cancelled: &AtomicBool) -> Result<Self::Lease>;
    fn verify_lease(&mut self, lease: &mut Self::Lease, cancelled: &AtomicBool) -> Result<()>;
    fn package(&mut self) -> Result<()>;
    fn load(&mut self) -> Result<Self::Module>;
    fn module(&mut self, module: &Self::Module) -> Result<()>;
}

struct Loaded<K: Kernel> {
    // Drop the original DLL reference BEFORE releasing the package/source pins.
    module: K::Module,
    kernel: K,
    valid: bool,
}

fn checkpoint(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn load<K: Kernel>(mut kernel: K, cancelled: &AtomicBool) -> Result<Loaded<K>> {
    checkpoint(cancelled)?;
    kernel.source()?;
    checkpoint(cancelled)?;
    kernel.absent_module()?;
    let mut lease = kernel.lease(cancelled)?;
    checkpoint(cancelled)?;
    kernel.source()?;
    kernel.package()?;
    kernel.source()?;
    kernel.verify_lease(&mut lease, cancelled)?;
    checkpoint(cancelled)?;
    kernel.absent_module()?;
    checkpoint(cancelled)?;
    let module = kernel.load()?;
    kernel.module(&module)?;
    kernel.package()?;
    kernel.source()?;
    kernel.verify_lease(&mut lease, cancelled)?;
    checkpoint(cancelled)?;
    Ok(Loaded {
        module,
        kernel,
        valid: true,
    })
}
impl<K: Kernel> Loaded<K> {
    fn reattest_cold(&mut self, cancelled: &AtomicBool) -> Result<()> {
        if !self.valid {
            return Err(Error::Conflict);
        }
        // A late error, cancellation or unwind cannot revive cached load trust.
        self.valid = false;
        checkpoint(cancelled)?;
        let mut lease = self.kernel.lease(cancelled)?;
        self.kernel.source()?;
        self.kernel.package()?;
        self.kernel.source()?;
        self.kernel.verify_lease(&mut lease, cancelled)?;
        self.kernel.module(&self.module)?;
        self.kernel.verify_lease(&mut lease, cancelled)?;
        checkpoint(cancelled)?;
        self.valid = true;
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_key_authority::KeyLock, member_carrier_payload::native::WintunSource,
        member_carrier_preload::native::WintunPreload, member_carrier_wintun::Functions,
        member_carrier_wintun_lock::native::Lease,
    };
    use std::{ffi::c_void, mem::size_of, os::windows::ffi::OsStrExt, ptr::NonNull};
    use windows_sys::{
        core::w,
        Win32::{
            Foundation::{FreeLibrary, GetLastError, ERROR_MOD_NOT_FOUND},
            System::{
                LibraryLoader::{
                    GetModuleFileNameW, GetModuleHandleW, GetProcAddress, LoadLibraryExW,
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                },
                ProcessStatus::{K32GetModuleInformation, MODULEINFO},
                Threading::GetCurrentProcess,
            },
        },
    };

    struct Module(NonNull<c_void>);
    impl Drop for Module {
        fn drop(&mut self) {
            // This owner exposes NO adapter/session calls. Audited0.14.1
            // PROCESS_DETACH only tears down its heap/security/namespace; it
            // doesn't remove NICs. Release ONLY our original LoadLibrary ref.
            unsafe {
                FreeLibrary(self.0.as_ptr());
            }
        }
    }
    struct Boundary<'source, 'lock> {
        source: &'source WintunSource,
        lock: &'lock mut KeyLock,
        package: Option<WintunPreload<'source>>,
    }
    impl Kernel for Boundary<'_, '_> {
        type Lease = Lease;
        type Module = Module;
        fn source(&mut self) -> Result<()> {
            self.lock
                .verify_source(self.source)
                .map_err(|_| Error::Conflict)
        }
        fn absent_module(&mut self) -> Result<()> {
            // Never adopt an earlier DLL with the same basename/path: it may
            // have been mapped before the independently pinned source existed.
            if !unsafe { GetModuleHandleW(w!("wintun.dll")) }.is_null() {
                return Err(Error::Conflict);
            }
            if unsafe { GetLastError() } != ERROR_MOD_NOT_FOUND {
                return Err(Error::Native);
            }
            Ok(())
        }
        fn lease(&mut self, cancelled: &AtomicBool) -> Result<Lease> {
            Lease::take(cancelled, 5000).map_err(|_| Error::Conflict)
        }
        fn verify_lease(&mut self, lease: &mut Lease, cancelled: &AtomicBool) -> Result<()> {
            lease.verify(cancelled).map_err(|_| Error::Conflict)
        }
        fn package(&mut self) -> Result<()> {
            match &mut self.package {
                Some(package) => package.reattest().map_err(|_| Error::Conflict),
                None => {
                    self.package =
                        Some(WintunPreload::new(self.source).map_err(|_| Error::Conflict)?);
                    Ok(())
                }
            }
        }
        fn load(&mut self) -> Result<Module> {
            // The trusted source constructor accepts NO IPC path, authenticates
            // kernelcurrentexe, full signed installed payloads, held owner lock
            // and write/delete-denied source/ancestor handles. Only this fixed
            // absolute path can be loaded; dependencies search SYSTEM32 only.
            self.source()?;
            let path = self.source.path().map_err(|_| Error::Conflict)?;
            let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let raw = unsafe {
                LoadLibraryExW(
                    path.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            NonNull::new(raw).map(Module).ok_or(Error::Native)
        }
        fn module(&mut self, module: &Module) -> Result<()> {
            self.source()?;
            let mut path = vec![0; 32768];
            let count = unsafe {
                GetModuleFileNameW(module.0.as_ptr(), path.as_mut_ptr(), path.len() as u32)
            } as usize;
            if count == 0 || count >= path.len() {
                return Err(Error::Native);
            }
            let actual = std::path::PathBuf::from(std::ffi::OsString::from_wide(&path[..count]));
            if std::fs::canonicalize(actual).map_err(|_| Error::Native)?
                != self.source.path().map_err(|_| Error::Conflict)?
            {
                return Err(Error::Conflict);
            }
            let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
            if unsafe {
                K32GetModuleInformation(
                    GetCurrentProcess(),
                    module.0.as_ptr(),
                    &mut info,
                    size_of::<MODULEINFO>() as u32,
                )
            } == 0
            {
                return Err(Error::Native);
            }
            let base = module.0.as_ptr() as usize;
            if info.lpBaseOfDll != module.0.as_ptr()
                || info.SizeOfImage == 0
                || info.SizeOfImage > 16 * 1024 * 1024
            {
                return Err(Error::Conflict);
            }
            let end = base
                .checked_add(info.SizeOfImage as usize)
                .ok_or(Error::Conflict)?;
            // Verify nine required audited exports, NEVER call one. Reject any
            // export forwarded outside the original retained image, not merely
            // an expected symbol name on an arbitrary loaded module.
            let _functions = unsafe {
                Functions::resolve(|name| {
                    GetProcAddress(module.0.as_ptr(), name.as_ptr().cast()).filter(|symbol| {
                        let address = *symbol as usize;
                        address >= base && address < end
                    })
                })
            }
            .map_err(|_| Error::Conflict)?;
            self.source()
        }
    }
    use std::os::windows::ffi::OsStringExt;

    /// Original source+DLL reference only. The cold package is independently
    /// verified under cooperative upstream installation locks. No constructor
    /// for ModuleRuntimeAuthority or any creation/mutation permission is provided.
    /// Original-creator-aware POST-create maintenance/cleanup still must be
    /// integrated separately; cold reattestation cannot whitelist saved GUIDs.
    pub(crate) struct LoadedWintun<'source, 'lock> {
        loaded: Loaded<Boundary<'source, 'lock>>,
    }
    impl<'source, 'lock> LoadedWintun<'source, 'lock> {
        pub(crate) fn new(
            source: &'source WintunSource,
            lock: &'lock mut KeyLock,
            cancelled: &AtomicBool,
        ) -> Result<Self> {
            load(
                Boundary {
                    source,
                    lock,
                    package: None,
                },
                cancelled,
            )
            .map(|loaded| Self { loaded })
        }
        /// Returning a number grants no effect authority. The unsafe native
        /// carrier seam additionally requires independently implemented real
        /// module/runtime/current protected context/key/fresh permission gates.
        pub(crate) fn original_cold_module(
            &mut self,
            cancelled: &AtomicBool,
        ) -> Result<NonNull<c_void>> {
            self.loaded.reattest_cold(cancelled)?;
            Ok(self.loaded.module.0)
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_module_tests.rs"]
mod tests;
