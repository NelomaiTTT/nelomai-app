//! Kernel synchronization only; never source, module, driver or effect authority.
//!
//! Audited Wintun 0.14.1 bfef136abfa1665c2592be09a7e383d646cdbe6e:
//! api/namespace.c, main.c (and cooperative adapter.c/driver.c call sites).
//! Same-context SYSTEM boundary "Wintun", Device then Driver mutexes.
//! Each lease uses a fresh PROCESS-LOCAL alias to the SAME actual boundary.
//! Opening alias "Wintun" twice in one process fails ERROR_DUP_NAME52 and
//! occupying it also prevents the DLL's own NamespaceRuntimeInit. Native proof
//! confirms distinct aliases reach the SAME mutex (existing183, other-thread
//! wait258). Never change the boundary SID/name or upstream object basenames.
//! Recursive same-thread upstream acquisition is possible. Never move a lease
//! to a worker thread. ClosePrivateNamespace(flags=0), never destroy it.
//!
//! DLL_PROCESS_ATTACH's AdapterCleanupLegacyDevices DOES NOT take these locks.
//! The lease serializes cooperative Create/Close/orphan cleanup/DriverInstall;
//! Close queues orphan cleanup, so it does not prove that deferred work ended.
//! It cannot serialize hostile/noncooperative privileged actors or make DLL
//! initialization safe. Main must borrow its actual authenticated WintunSource,
//! SAME KeyLock and matching cold package, retain all pins, and repeat ALL-device
//! preflight and runtime serialization immediately before executable load/create.
//! Existing ModuleRuntimeAuthority remains unimplemented; no bypass is supplied.
//!
//! The five-second bound covers cooperative acquisition and finite native waits,
//! not hard interruption of token/security/namespace APIs, enumeration or trust.
//! No files, devices, services, networking, driver or firewall changes occur here.
#![allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid,
    Conflict,
    Native,
    Retired,
    Deadline,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Principal {
    System,
    Admins,
    Other,
}
#[derive(Clone)]
struct Ace {
    kind: u8,
    flags: u8,
    mask: u32,
    principal: Principal,
}
#[derive(Clone)]
struct Security {
    owner: Principal,
    protected: bool,
    dacl: Option<Vec<Ace>>,
}
enum Wait {
    Acquired,
    Abandoned,
    Timeout,
}
trait Kernel {
    type Handle;
    fn now(&mut self) -> Duration;
    fn authenticate(&mut self, cancelled: &AtomicBool) -> Result<()>;
    fn namespace(&mut self, cancelled: &AtomicBool) -> Result<bool>;
    fn open(&mut self, name: &'static str, cancelled: &AtomicBool) -> Result<Self::Handle>;
    fn security(&mut self, handle: &Self::Handle, cancelled: &AtomicBool) -> Result<Security>;
    fn wait(
        &mut self,
        handle: &Self::Handle,
        milliseconds: u32,
        cancelled: &AtomicBool,
    ) -> Result<Wait>;
    fn release(&mut self, handle: &Self::Handle) -> Result<()>;
    fn cleanup_failed(&mut self);
}
const NAMES: [&str; 2] = [
    "Wintun\\Wintun-Device-Installation-Mutex",
    "Wintun\\Wintun-Driver-Installation-Mutex",
];
const MAX_MS: u32 = 5000;
const SLICE_MS: u32 = 50;

struct Alias(String);
impl Alias {
    fn new(process: u32, sequence: u64) -> Result<Self> {
        if process == 0 || sequence == 0 || sequence == u64::MAX {
            return Err(Error::Invalid);
        }
        Ok(Self(format!("NelomaiWintunLease-{process}-{sequence}")))
    }
    fn qualified(&self, name: &str) -> Result<String> {
        if !NAMES.contains(&name) {
            return Err(Error::Invalid);
        }
        let object = name.strip_prefix("Wintun\\").ok_or(Error::Invalid)?;
        Ok(format!("{}\\{object}", self.0))
    }
}

fn validate_security(s: &Security) -> Result<()> {
    if !matches!(s.owner, Principal::System | Principal::Admins) || !s.protected {
        return Err(Error::Conflict);
    }
    let acl = s.dacl.as_ref().ok_or(Error::Conflict)?;
    if acl.len() != 2 {
        return Err(Error::Conflict);
    }
    let mut system = false;
    let mut admins = false;
    for ace in acl {
        // Only ordinary, explicit access-allowed ACEs; exact generic ALL or
        // its kernel mutex mapping. No weaker or unknown mask is accepted.
        if ace.kind != 0 || ace.flags != 0 || !matches!(ace.mask, 0x001f0001 | 0x10000000) {
            return Err(Error::Conflict);
        }
        match ace.principal {
            Principal::System if !system => system = true,
            Principal::Admins if !admins => admins = true,
            _ => return Err(Error::Conflict),
        }
    }
    if system && admins {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
struct Deadline {
    start: Duration,
    last: Duration,
    budget: Duration,
}
impl Deadline {
    fn remaining<K: Kernel>(&mut self, kernel: &mut K, cancelled: &AtomicBool) -> Result<u32> {
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::Retired);
        }
        let now = kernel.now();
        if now < self.last {
            return Err(Error::Deadline);
        }
        self.last = now;
        let elapsed = now.checked_sub(self.start).ok_or(Error::Deadline)?;
        let left = self.budget.checked_sub(elapsed).ok_or(Error::Deadline)?;
        // Round DOWN: never round a finite remainder past the shared deadline.
        let milliseconds = left.as_millis() as u32;
        if milliseconds == 0 {
            Err(Error::Deadline)
        } else {
            Ok(milliseconds)
        }
    }
}
struct Held<K: Kernel> {
    kernel: K,
    handles: Vec<(K::Handle, bool)>,
    revoked: bool,
    // ReleaseMutex must run on the acquiring thread. No Send, Sync or Clone.
    _thread: PhantomData<Rc<()>>,
}
impl<K: Kernel> Held<K> {
    fn verify(&mut self, cancelled: &AtomicBool) -> Result<()> {
        if self.revoked {
            return Err(Error::Retired);
        }
        // Failures/unwind permanently retire this lease. Observation may not
        // turn a previously denied lease back into a valid one.
        self.revoked = true;
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::Retired);
        }
        self.kernel.authenticate(cancelled)?;
        for (handle, owned) in &self.handles {
            if !owned || cancelled.load(Ordering::Acquire) {
                return Err(Error::Retired);
            }
            validate_security(&self.kernel.security(handle, cancelled)?)?;
        }
        if self.handles.len() != 2 || cancelled.load(Ordering::Acquire) {
            return Err(Error::Retired);
        }
        self.kernel.authenticate(cancelled)?;
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::Retired);
        }
        self.revoked = false;
        Ok(())
    }
    fn release_all(&mut self) -> Result<()> {
        let mut failed = false;
        while let Some((handle, owned)) = self.handles.pop() {
            // Remove ownership BEFORE attempting release, including errors:
            // Drop cannot retry an unacknowledged release/double-release.
            if owned && self.kernel.release(&handle).is_err() {
                failed = true;
            }
            drop(handle);
        }
        if failed {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
    fn release(mut self) -> Result<()> {
        self.release_all()
    }
}
impl<K: Kernel> Drop for Held<K> {
    fn drop(&mut self) {
        if self.release_all().is_err() {
            self.kernel.cleanup_failed();
        }
    }
}
fn take<K: Kernel>(mut kernel: K, cancelled: &AtomicBool, milliseconds: u32) -> Result<Held<K>> {
    if milliseconds == 0 || milliseconds > MAX_MS {
        return Err(Error::Invalid);
    }
    let start = kernel.now();
    let mut deadline = Deadline {
        start,
        last: start,
        budget: Duration::from_millis(milliseconds.into()),
    };
    let mut held = Held {
        kernel,
        handles: Vec::with_capacity(2),
        revoked: false,
        _thread: PhantomData,
    };
    deadline.remaining(&mut held.kernel, cancelled)?;
    held.kernel.authenticate(cancelled)?;
    loop {
        deadline.remaining(&mut held.kernel, cancelled)?;
        if held.kernel.namespace(cancelled)? {
            break;
        }
    }
    for name in NAMES {
        deadline.remaining(&mut held.kernel, cancelled)?;
        let handle = held.kernel.open(name, cancelled)?;
        held.handles.push((handle, false));
        deadline.remaining(&mut held.kernel, cancelled)?;
        let index = held.handles.len() - 1;
        let security = held.kernel.security(&held.handles[index].0, cancelled)?;
        deadline.remaining(&mut held.kernel, cancelled)?;
        validate_security(&security)?;
        loop {
            let remaining = deadline.remaining(&mut held.kernel, cancelled)?;
            let result =
                held.kernel
                    .wait(&held.handles[index].0, remaining.min(SLICE_MS), cancelled)?;
            match result {
                Wait::Acquired | Wait::Abandoned => {
                    // Windows grants ownership on BOTH outcomes; acknowledge
                    // before cancellation/time/security/error can unwind.
                    held.handles[index].1 = true;
                    if matches!(result, Wait::Abandoned) {
                        return Err(Error::Conflict);
                    }
                    deadline.remaining(&mut held.kernel, cancelled)?;
                    break;
                }
                Wait::Timeout => {}
            }
        }
    }
    deadline.remaining(&mut held.kernel, cancelled)?;
    held.verify(cancelled)?;
    deadline.remaining(&mut held.kernel, cancelled)?;
    Ok(held)
}
#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use std::{
        ffi::c_void,
        mem::{size_of, size_of_val},
        ptr::{self, NonNull},
        time::Instant,
    };
    use windows_sys::{
        core::w,
        Win32::{
            Foundation::{
                CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS,
                ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, ERROR_PATH_NOT_FOUND, HANDLE,
                WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
            },
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                    SE_KERNEL_OBJECT,
                },
                CreateWellKnownSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
                GetSecurityDescriptorLength, GetTokenInformation, IsValidAcl,
                IsValidSecurityDescriptor, IsValidSid, IsWellKnownSid, TokenUser,
                WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
                ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
                SE_DACL_PRESENT, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
            },
            System::Threading::{
                AddSIDToBoundaryDescriptor, ClosePrivateNamespace, CreateBoundaryDescriptorW,
                CreateMutexW, CreatePrivateNamespaceW, DeleteBoundaryDescriptor, GetCurrentProcess,
                GetCurrentProcessId, GetCurrentThread, OpenPrivateNamespaceW, OpenProcessToken,
                OpenThreadToken, ReleaseMutex, WaitForSingleObject,
            },
        },
    };
    static ALIAS_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    /// Opaque kernel-only lease, !Send/!Sync/!Clone. No raw/serialized handle
    /// access, DLL loader, creation capability or successful authority default.
    #[must_use = "retain the lease on this thread through the cooperative operation"]
    pub(crate) struct Lease(Held<NativeKernel>);
    impl Lease {
        /// The caller is main's authenticated source/runtime actor holding its
        /// SAME key lock and pins. Actual unimpersonated SYSTEM is independently
        /// checked here; it does not establish source/runtime/effect authority.
        pub(crate) fn take(cancelled: &AtomicBool, milliseconds: u32) -> Result<Self> {
            if milliseconds == 0 || milliseconds > MAX_MS {
                return Err(Error::Invalid);
            }
            let kernel = NativeKernel {
                alias: Alias::new(
                    unsafe { GetCurrentProcessId() },
                    ALIAS_SEQUENCE
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                        .map_err(|_| Error::Retired)?,
                )?,
                namespace: None,
                boundary: None,
                descriptor: None,
                start: Instant::now(),
                budget: Duration::from_millis(milliseconds.into()),
                acquiring: true,
            };
            let mut held = super::take(kernel, cancelled, milliseconds)?;
            held.kernel.acquiring = false;
            Ok(Self(held))
        }
        /// Main must call at each protected seam in addition to independently
        /// rechecking its own authority. Denial/unwind retires irreversibly;
        /// retain until explicit release/drop. This is not runtime authorization.
        pub(crate) fn verify(&mut self, cancelled: &AtomicBool) -> Result<()> {
            self.0.verify(cancelled)
        }
        /// Consumes the lease even on failure; every acquired mutex is attempted
        /// once, in reverse order. Errors must retire main's operation authority.
        pub(crate) fn release(self) -> Result<()> {
            self.0.release()
        }
    }

    struct Handle(NonNull<c_void>);
    impl Handle {
        fn new(raw: HANDLE) -> Result<Self> {
            NonNull::new(raw).map(Self).ok_or(Error::Native)
        }
        fn raw(&self) -> HANDLE {
            self.0.as_ptr()
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            // A retained, non-pseudo handle is closed once. Failed cleanup must
            // never silently continue, including while unwinding.
            if unsafe { CloseHandle(self.raw()) } == 0 {
                std::process::abort();
            }
        }
    }
    struct Boundary(HANDLE);
    impl Drop for Boundary {
        fn drop(&mut self) {
            unsafe {
                DeleteBoundaryDescriptor(self.0);
            }
        }
    }
    struct Namespace(NonNull<c_void>);
    impl Drop for Namespace {
        fn drop(&mut self) {
            if !unsafe { ClosePrivateNamespace(self.0.as_ptr(), 0) } {
                std::process::abort();
            }
        }
    }
    struct LocalMemory(NonNull<c_void>);
    impl LocalMemory {
        fn raw(&self) -> *mut c_void {
            self.0.as_ptr()
        }
    }
    impl Drop for LocalMemory {
        fn drop(&mut self) {
            if !unsafe { LocalFree(self.raw()) }.is_null() {
                std::process::abort();
            }
        }
    }
    struct NativeKernel {
        // Field drop order: close alias (no DESTROY), delete boundary, free SD.
        namespace: Option<Namespace>,
        boundary: Option<Boundary>,
        descriptor: Option<LocalMemory>,
        alias: Alias,
        start: Instant,
        budget: Duration,
        acquiring: bool,
    }
    impl NativeKernel {
        fn check(&self, cancelled: &AtomicBool) -> Result<()> {
            if cancelled.load(Ordering::Acquire) {
                return Err(Error::Retired);
            }
            if self.acquiring && self.start.elapsed() >= self.budget {
                return Err(Error::Deadline);
            }
            Ok(())
        }
        fn attributes(&self) -> Result<SECURITY_ATTRIBUTES> {
            Ok(SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.descriptor.as_ref().ok_or(Error::Native)?.raw(),
                bInheritHandle: 0,
            })
        }
        fn prepare(&mut self, cancelled: &AtomicBool) -> Result<()> {
            if self.descriptor.is_none() {
                self.check(cancelled)?;
                let mut raw = ptr::null_mut();
                // EXACT audited SYSTEM descriptor, with HI NW/NR/NX label.
                let ok = unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        w!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)"),
                        1,
                        &mut raw,
                        ptr::null_mut(),
                    )
                };
                if let Some(raw) = NonNull::new(raw) {
                    self.descriptor = Some(LocalMemory(raw));
                }
                if ok == 0 || self.descriptor.is_none() {
                    return Err(Error::Native);
                }
            }
            if self.boundary.is_none() {
                self.check(cancelled)?;
                let raw = unsafe { CreateBoundaryDescriptorW(w!("Wintun"), 0) };
                if raw.is_null() {
                    return Err(Error::Native);
                }
                self.boundary = Some(Boundary(raw));
                // Aligned maximum Windows SID buffer, independently SYSTEM.
                let mut sid = [0u32; 17];
                let mut len = size_of_val(&sid) as u32;
                self.check(cancelled)?;
                if unsafe {
                    CreateWellKnownSid(
                        WinLocalSystemSid,
                        ptr::null_mut(),
                        sid.as_mut_ptr().cast(),
                        &mut len,
                    )
                } == 0
                {
                    return Err(Error::Native);
                }
                self.check(cancelled)?;
                let boundary = self.boundary.as_mut().ok_or(Error::Native)?;
                if unsafe { AddSIDToBoundaryDescriptor(&mut boundary.0, sid.as_mut_ptr().cast()) }
                    == 0
                {
                    return Err(Error::Native);
                }
            }
            self.check(cancelled)
        }
    }

    // SID reads are bounded by the actual token/descriptor/ACE allocation, not
    // a caller-supplied SID. Validate revision/count before calling SID helpers.
    fn contains(base: *const c_void, len: usize, part: *const c_void, size: usize) -> bool {
        let base = base as usize;
        let part = part as usize;
        part >= base
            && part
                .checked_add(size)
                .zip(base.checked_add(len))
                .is_some_and(|(end, bound)| end <= bound)
    }
    unsafe fn principal(
        sid: *mut c_void,
        base: *const c_void,
        len: usize,
        kernel: &NativeKernel,
        cancelled: &AtomicBool,
    ) -> Result<Principal> {
        if !contains(base, len, sid, 8) {
            return Err(Error::Conflict);
        }
        // SAFETY: header range was checked; SID subauthority count is byte1.
        let bytes = sid.cast::<u8>();
        let count = unsafe { *bytes.add(1) } as usize;
        let size = 8 + count * 4;
        if unsafe { *bytes } != 1 || count > 15 || !contains(base, len, sid, size) {
            return Err(Error::Conflict);
        }
        kernel.check(cancelled)?;
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(Error::Conflict);
        }
        kernel.check(cancelled)?;
        if unsafe { GetLengthSid(sid) } as usize != size {
            return Err(Error::Conflict);
        }
        kernel.check(cancelled)?;
        if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
            Ok(Principal::System)
        } else {
            kernel.check(cancelled)?;
            if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0 {
                Ok(Principal::Admins)
            } else {
                Ok(Principal::Other)
            }
        }
    }
    impl Kernel for NativeKernel {
        type Handle = Handle;
        fn now(&mut self) -> Duration {
            self.start.elapsed()
        }
        fn authenticate(&mut self, cancelled: &AtomicBool) -> Result<()> {
            self.check(cancelled)?;
            let mut raw = ptr::null_mut();
            // Even SYSTEM impersonation is denied. Access-denied/other errors
            // never stand in for ERROR_NO_TOKEN.
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
                let _token = Handle::new(raw)?;
                return Err(Error::Conflict);
            }
            if unsafe { GetLastError() } != ERROR_NO_TOKEN {
                return Err(Error::Conflict);
            }
            self.check(cancelled)?;
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
                return Err(Error::Native);
            }
            let token = Handle::new(raw)?;
            let mut required = 0;
            self.check(cancelled)?;
            if unsafe {
                GetTokenInformation(token.raw(), TokenUser, ptr::null_mut(), 0, &mut required)
            } != 0
                || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
                || required < size_of::<TOKEN_USER>() as u32
                || required > 65536
            {
                return Err(Error::Native);
            }
            let mut buffer = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
            let capacity = size_of_val(buffer.as_slice());
            self.check(cancelled)?;
            if unsafe {
                GetTokenInformation(
                    token.raw(),
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut required,
                )
            } == 0
                || required < size_of::<TOKEN_USER>() as u32
                || required as usize > capacity
            {
                return Err(Error::Native);
            }
            // SAFETY: aligned TOKEN_USER allocation and actual returned size.
            let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
            self.check(cancelled)?;
            if unsafe {
                principal(
                    user.User.Sid,
                    buffer.as_ptr().cast(),
                    required as usize,
                    self,
                    cancelled,
                )
            }? != Principal::System
            {
                return Err(Error::Conflict);
            }
            self.check(cancelled)
        }
        fn namespace(&mut self, cancelled: &AtomicBool) -> Result<bool> {
            self.prepare(cancelled)?;
            if self.namespace.is_some() {
                return Ok(true);
            }
            let attributes = self.attributes()?;
            let boundary = self.boundary.as_ref().ok_or(Error::Native)?.0;
            let alias: Vec<u16> = self.alias.0.encode_utf16().chain(Some(0)).collect();
            self.check(cancelled)?;
            let raw = unsafe { CreatePrivateNamespaceW(&attributes, boundary, alias.as_ptr()) };
            if let Some(raw) = NonNull::new(raw) {
                self.namespace = Some(Namespace(raw));
                return Ok(true);
            }
            if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
                return Err(Error::Native);
            }
            self.check(cancelled)?;
            let raw = unsafe { OpenPrivateNamespaceW(boundary, alias.as_ptr()) };
            if let Some(raw) = NonNull::new(raw) {
                self.namespace = Some(Namespace(raw));
                return Ok(true);
            }
            // Upstream's disappearing-namespace race is retried only under the
            // same total deadline, never its unbounded for(;;).
            if unsafe { GetLastError() } == ERROR_PATH_NOT_FOUND {
                Ok(false)
            } else {
                Err(Error::Native)
            }
        }
        fn open(&mut self, name: &'static str, cancelled: &AtomicBool) -> Result<Handle> {
            if self.namespace.is_none() {
                return Err(Error::Native);
            }
            let attributes = self.attributes()?;
            let qualified = self.alias.qualified(name)?;
            let wide: Vec<u16> = qualified.encode_utf16().chain(Some(0)).collect();
            self.check(cancelled)?;
            // FALSE initial ownership: security is checked BEFORE the wait.
            Handle::new(unsafe { CreateMutexW(&attributes, 0, wide.as_ptr()) })
        }
        fn security(&mut self, handle: &Handle, cancelled: &AtomicBool) -> Result<Security> {
            let mut owner = ptr::null_mut();
            let mut dacl: *mut ACL = ptr::null_mut();
            let mut raw = ptr::null_mut();
            self.check(cancelled)?;
            // Read only: never change grants/ownership. SACL is NOT requested
            // here; existing-object HI label is explicitly NOT verified.
            let status = unsafe {
                GetSecurityInfo(
                    handle.raw(),
                    SE_KERNEL_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    ptr::null_mut(),
                    &mut dacl,
                    ptr::null_mut(),
                    &mut raw,
                )
            };
            let allocation = NonNull::new(raw).map(LocalMemory);
            if status != 0 {
                return Err(Error::Native);
            }
            let allocation = allocation.ok_or(Error::Native)?;
            self.check(cancelled)?;
            if unsafe { IsValidSecurityDescriptor(allocation.raw()) } == 0 {
                return Err(Error::Conflict);
            }
            self.check(cancelled)?;
            let len = unsafe { GetSecurityDescriptorLength(allocation.raw()) } as usize;
            let mut control = 0;
            let mut revision = 0;
            self.check(cancelled)?;
            if unsafe {
                GetSecurityDescriptorControl(allocation.raw(), &mut control, &mut revision)
            } == 0
                || revision != 1
            {
                return Err(Error::Conflict);
            }
            self.check(cancelled)?;
            let owner = unsafe { principal(owner, allocation.raw(), len, self, cancelled) }?;
            if control & SE_DACL_PRESENT == 0 || dacl.is_null() {
                return Ok(Security {
                    owner,
                    protected: control & SE_DACL_PROTECTED != 0,
                    dacl: None,
                });
            }
            if !contains(allocation.raw(), len, dacl.cast(), size_of::<ACL>()) {
                return Err(Error::Conflict);
            }
            // SAFETY: ACL header fits the returned OS descriptor.
            let acl = unsafe { &*dacl };
            if acl.AclRevision != 2
                || acl.AceCount != 2
                || !contains(allocation.raw(), len, dacl.cast(), acl.AclSize as usize)
            {
                return Err(Error::Conflict);
            }
            self.check(cancelled)?;
            if unsafe { IsValidAcl(dacl) } == 0 {
                return Err(Error::Conflict);
            }
            let mut entries = Vec::with_capacity(2);
            for index in 0..2 {
                let mut raw_ace = ptr::null_mut();
                self.check(cancelled)?;
                if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0
                    || !contains(
                        dacl.cast(),
                        acl.AclSize as usize,
                        raw_ace,
                        size_of::<ACE_HEADER>(),
                    )
                {
                    return Err(Error::Conflict);
                }
                // SAFETY: header fits ACL. Reject types before casting layout.
                let header = unsafe { ptr::read_unaligned(raw_ace.cast::<ACE_HEADER>()) };
                if header.AceType != 0
                    || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>()
                    || !contains(
                        dacl.cast(),
                        acl.AclSize as usize,
                        raw_ace,
                        header.AceSize as usize,
                    )
                {
                    return Err(Error::Conflict);
                }
                let ace = unsafe { ptr::read_unaligned(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
                let sid = unsafe { raw_ace.cast::<u8>().add(8).cast::<c_void>() };
                self.check(cancelled)?;
                let who =
                    unsafe { principal(sid, raw_ace, header.AceSize as usize, self, cancelled) }?;
                self.check(cancelled)?;
                if 8 + unsafe { GetLengthSid(sid) } as usize != header.AceSize as usize {
                    return Err(Error::Conflict);
                }
                entries.push(Ace {
                    kind: header.AceType,
                    flags: header.AceFlags,
                    mask: ace.Mask,
                    principal: who,
                });
            }
            self.check(cancelled)?;
            Ok(Security {
                owner,
                protected: control & SE_DACL_PROTECTED != 0,
                dacl: Some(entries),
            })
        }
        fn wait(
            &mut self,
            handle: &Handle,
            milliseconds: u32,
            cancelled: &AtomicBool,
        ) -> Result<Wait> {
            self.check(cancelled)?;
            let remaining = self
                .budget
                .checked_sub(self.start.elapsed())
                .ok_or(Error::Deadline)?
                .as_millis() as u32;
            let milliseconds = milliseconds.min(remaining).min(SLICE_MS);
            if milliseconds == 0 {
                return Err(Error::Deadline);
            }
            // Return immediately, with no post-call fallible work, so the real
            // policy acknowledges ownership before cancellation/unwind.
            match unsafe { WaitForSingleObject(handle.raw(), milliseconds) } {
                WAIT_OBJECT_0 => Ok(Wait::Acquired),
                WAIT_ABANDONED => Ok(Wait::Abandoned),
                WAIT_TIMEOUT => Ok(Wait::Timeout),
                _ => Err(Error::Native),
            }
        }
        fn release(&mut self, handle: &Handle) -> Result<()> {
            if unsafe { ReleaseMutex(handle.raw()) } == 0 {
                Err(Error::Native)
            } else {
                Ok(())
            }
        }
        fn cleanup_failed(&mut self) {
            std::process::abort();
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_wintun_lock_tests.rs"]
mod tests;
