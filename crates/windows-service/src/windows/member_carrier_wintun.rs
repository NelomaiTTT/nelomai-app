//! Retained original-creator Wintun substrate. Factory deliberately disconnected.
#![allow(dead_code)]
#[cfg(all(test, windows))]
use crate::windows::member_carrier_factory_test_os::trace_step as trace_observe;
use std::ffi::{c_void, CStr};
use std::sync::atomic::{AtomicBool, Ordering};

// SAME irreversible original module-release protocol. These facts are never
// Runtime/Calling/G or whole unload/destructor permission.
#[cfg(not(windows))]
use crate::member_carrier_module as reference_module;
#[cfg(windows)]
use crate::windows::member_carrier_module as reference_module;
pub(super) struct ClosedReferenceRelease(reference_module::ModuleRelease);
impl ClosedReferenceRelease {
    pub(super) fn new() -> Self {
        Self(reference_module::ModuleRelease::new())
    }
    pub(super) fn acknowledged(&self) -> bool {
        self.0.acknowledged()
    }
    pub(super) fn was_attempted(&self) -> bool {
        self.0.was_attempted()
    }
    pub(super) fn run(
        &self,
        check: impl FnOnce() -> Result<()>,
        effect: impl FnOnce() -> Result<()>,
        post: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let original_error = std::cell::Cell::new(None);
        let boundary = |result: Result<()>| {
            result.map_err(|e| {
                original_error.set(Some(e));
                reference_module::Error::Conflict
            })
        };
        self.0
            .run(
                || boundary(check()),
                || boundary(effect()),
                || boundary(post()),
            )
            .map_err(|_| original_error.get().unwrap_or(Error::Conflict))
    }
}

/// Releases only per-call cooperative resources. Original native handles,
/// source/runtime pins, serialized owner and pending receipts are NOT released.
pub(super) trait CallResources {
    fn release_call_resources(&mut self);
}
pub(super) fn with_call_resources<O: CallResources, T>(
    owner: &mut O,
    action: impl FnOnce(&mut O) -> T,
) -> T {
    struct Call<'a, O: CallResources>(&'a mut O);
    impl<O: CallResources> Drop for Call<'_, O> {
        fn drop(&mut self) {
            self.0.release_call_resources();
        }
    }
    let held = Call(owner);
    action(held.0)
}

// Shared with the portable retention tests; native authority stays opaque.
#[cfg(any(windows, test))]
pub(super) enum AuthorityHolder<'a, A> {
    Borrowed(&'a mut A),
    Owned(A),
}
#[cfg(any(windows, test))]
impl<A> AuthorityHolder<'_, A> {
    pub(super) fn as_mut(&mut self) -> &mut A {
        match self {
            Self::Borrowed(authority) => authority,
            Self::Owned(authority) => authority,
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_original_ack_tests.rs"]
mod original_ack_tests;

#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalState {
    Live,
    ClosePending,
    Closed,
}
struct OriginalShared<R> {
    resource: std::mem::ManuallyDrop<R>,
    state: std::cell::Cell<OriginalState>,
    close_taken: std::cell::Cell<bool>,
}
impl<R> Drop for OriginalShared<R> {
    fn drop(&mut self) {
        // An unresolved native result cannot authorize destructive cleanup or
        // unload its code. Bounded original retention deliberately leaks to
        // process exit; only acknowledged exact native close releases pins.
        if self.state.get() == OriginalState::Closed {
            unsafe {
                std::mem::ManuallyDrop::drop(&mut self.resource);
            }
        }
    }
}
struct OriginalReceipt<R>(std::rc::Rc<OriginalShared<R>>);
struct OriginalRead<R>(std::rc::Rc<OriginalShared<R>>);
struct OriginalClosed<R>(std::rc::Rc<OriginalShared<R>>);
impl<R> OriginalReceipt<R> {
    // Private; actual Windows caller must pass ONLY the returned new raw ACK.
    fn acknowledged(resource: R) -> Self {
        Self(std::rc::Rc::new(OriginalShared {
            resource: std::mem::ManuallyDrop::new(resource),
            state: std::cell::Cell::new(OriginalState::Live),
            close_taken: std::cell::Cell::new(false),
        }))
    }
    fn read_pin(&self) -> OriginalRead<R> {
        OriginalRead(self.0.clone())
    }
    fn acknowledged_then(resource: R, retain: impl FnOnce(OriginalRead<R>)) -> Self {
        let original = Self::acknowledged(resource);
        // Actual ACK is owned BEFORE inventory/publication, and the caller's
        // prepared observer is invoked BEFORE any fallible post-create reads.
        // An unwind leaks unresolved pins, never implicitly closes/adopts.
        retain(original.read_pin());
        original
    }
    fn close(self, effect: impl FnOnce(&R)) -> Result<()> {
        if self.0.state.get() != OriginalState::Live {
            return Err(Error::Pending);
        }
        self.0.state.set(OriginalState::ClosePending);
        effect(&self.0.resource);
        self.0.state.set(OriginalState::Closed);
        Ok(())
    }
}
impl<R> OriginalRead<R> {
    fn read_pin(&self) -> Self {
        Self(self.0.clone())
    }
    fn live_resource(&self) -> Result<&R> {
        match self.0.state.get() {
            OriginalState::Live => Ok(&self.0.resource),
            OriginalState::ClosePending => Err(Error::Pending),
            OriginalState::Closed => Err(Error::Retired),
        }
    }
    fn take_closed(&self) -> Result<OriginalClosed<R>> {
        if self.0.state.get() != OriginalState::Closed {
            return Err(Error::Pending);
        }
        if self.0.close_taken.replace(true) {
            return Err(Error::Retired);
        }
        Ok(OriginalClosed(self.0.clone()))
    }
    fn verify_closed(&self, proof: &OriginalClosed<R>) -> Result<()> {
        if !std::rc::Rc::ptr_eq(&self.0, &proof.0)
            || self.0.state.get() != OriginalState::Closed
            || !self.0.close_taken.get()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

// Wintun 0.14.1 api/wintun.h (bfef136abfa1665c2592be09a7e383d646cdbe6e).
// WINAPI = system, DWORD = u32, VOID returns (). No Open/Send/Delete/Logger.
#[repr(C)]
pub(crate) struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}
impl Guid {
    fn new(bytes: [u8; 16]) -> Self {
        Self {
            data1: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            data2: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            data3: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            data4: bytes[8..].try_into().unwrap(),
        }
    }
}
type Create = unsafe extern "system" fn(*const u16, *const u16, *const Guid) -> *mut c_void;
type Close = unsafe extern "system" fn(*mut c_void);
#[cfg(windows)]
type NetLuid = windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
// Host resolver tests never invoke this alias or claim Windows ABI proof.
#[cfg(not(windows))]
type NetLuid = u64;
type Luid = unsafe extern "system" fn(*mut c_void, *mut NetLuid);
type Version = unsafe extern "system" fn() -> u32;
type Start = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type Event = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
type ReceiveFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type Release = unsafe extern "system" fn(*mut c_void, *const u8);
type Symbol = unsafe extern "system" fn() -> isize;
pub(crate) struct Functions {
    create: Create,
    close: Close,
    luid: Luid,
    version: Version,
    start: Start,
    end: Close,
    event: Event,
    receive: ReceiveFn,
    release: Release,
}
impl Functions {
    /// # Safety
    /// Caller retains and freshly authenticates the SAME original module used
    /// to resolve these exports throughout this strictly read-only call.
    #[cfg(windows)]
    pub(super) unsafe fn running_driver_version(&self) -> Result<Option<u32>> {
        let version = unsafe { (self.version)() };
        let error = if version == 0 {
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        } else {
            0
        };
        driver_status(version, error)
    }
    /// # Safety
    /// Resolver must address the independently authenticated, STILL PINNED
    /// audited Wintun 0.14.1 module; correct symbol signatures are mandatory.
    /// A path, JSON version or arbitrary numeric module handle is insufficient.
    pub(crate) unsafe fn resolve(
        mut resolver: impl FnMut(&CStr) -> Option<Symbol>,
    ) -> Result<Self> {
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                let name = CStr::from_bytes_with_nul(concat!($name, "\0").as_bytes())
                    .map_err(|_| Error::Unsupported)?;
                let raw = resolver(name).ok_or(Error::Unsupported)?;
                // Safety delegated only to an authenticated module capability above.
                unsafe { std::mem::transmute::<Symbol, $ty>(raw) }
            }};
        }
        Ok(Self {
            create: symbol!("WintunCreateAdapter", Create),
            close: symbol!("WintunCloseAdapter", Close),
            luid: symbol!("WintunGetAdapterLUID", Luid),
            version: symbol!("WintunGetRunningDriverVersion", Version),
            start: symbol!("WintunStartSession", Start),
            end: symbol!("WintunEndSession", Close),
            event: symbol!("WintunGetReadWaitEvent", Event),
            receive: symbol!("WintunReceivePacket", ReceiveFn),
            release: symbol!("WintunReleaseReceivePacket", Release),
        })
    }
}

pub(crate) fn driver_status(version: u32, error: u32) -> Result<Option<u32>> {
    match (version, error) {
        (14, _) => Ok(Some(14)),
        (0, 2) => Ok(None),
        (0, _) => Err(Error::Native),
        _ => Err(Error::Unsupported),
    }
}
pub(crate) fn virtual_role(flags: u8) -> Result<()> {
    // Installed netioapi.h: HardwareInterface0, FilterInterface1, EndPoint7.
    // Other bits are observed volatile status, not writable row permission.
    if flags & 0x83 != 0 {
        Err(Error::Unsupported)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::member_carrier_native_ownership::{self as receipt, NewKeyAck, PrecreationReceipt};
    use std::{
        ptr::{self, NonNull},
        time::Instant,
    };
    use windows_sys::Win32::{
        Foundation::{FreeLibrary, GetLastError, HMODULE},
        NetworkManagement::{
            IpHelper::{FreeMibTable, GetIfEntry2, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2},
            Ndis::NET_LUID_LH,
        },
        System::{
            LibraryLoader::{
                GetModuleHandleExW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            },
            Threading::WaitForSingleObject,
        },
    };
    include!("member_carrier_wintun_original.rs");

    #[cfg(all(windows, test))]
    unsafe extern "system" fn native_error_logger(level: i32, timestamp: u64, message: *const u16) {
        let _ = std::panic::catch_unwind(|| {
            if !(0..=2).contains(&level) || message.is_null() {
                return;
            }
            let mut text = Vec::new();
            for offset in 0..2048 {
                // Vendor callback supplies a live null-terminated LPCWSTR.
                let unit = unsafe { message.add(offset).read() };
                if unit == 0 {
                    break;
                }
                text.push(unit);
            }
            use std::io::Write;
            let label = match level {
                0 => "info",
                1 => "warn",
                _ => "error",
            };
            let _ = writeln!(
                std::io::stderr().lock(),
                "actual Wintun SDK {label} timestamp={timestamp}: {}",
                String::from_utf16_lossy(&text)
            );
        });
    }

    /// Independent privileged capability contract, NOT a record-derived fact.
    /// No production implementation is supplied; factory stays disconnected.
    ///
    /// # Safety
    /// Implementer owns a REAL authenticated Installation::load_engine runtime
    /// and full signed payload verification plus private pinned DLL source,
    /// ancestor ACL/handle/link/reparse checks and the real privileged lock.
    /// BEFORE original executable DLL load it must inspect embedded INF AS DATA,
    /// exact installed matching package, signed system driver, ALL legacy/problem
    /// and foreign Wintun devices. DLL initialization itself removes legacy NICs.
    /// BeforeClose and the mandatory LAST authorize_create seam recheck
    /// maintenance safety and package continuity: upstream create invokes
    /// DriverInstall and close queues orphan cleanup. Resolve must authenticate
    /// the same live original image/runtime and current Preparing receipt before
    /// adding its reference and reading exports; it cannot load another image.
    /// BeforeCreate authenticates only factual driver/absence queries through
    /// that image. Neither can issue a pending token or replace authorize_create.
    /// Missing/older/mismatched packages never permit install/upgrade.
    /// Each call must independently revalidate full scope/boot/runtime/epoch and
    /// actual held lock AND effect permission. BeforeSession/BeforeDrain need
    /// fresh live permission; BeforeEnd/BeforeClose need cleanup permission and
    /// independently proven row/guard/network restoration ordering. Context
    /// observation alone is NOT effect authorization. The actual key-only
    /// runtime gate is NOT DLL/payload/package-maintenance authority.
    /// Bare dispatcher::trusted(), paths/JSON/booleans are NOT
    /// implementations. The capability must keep the authenticated DLL and
    /// source/runtime pins held while borrowed or owned, including failures.
    pub(crate) unsafe trait ModuleRuntimeAuthority {
        type Key;
        type MutationLock;
        fn verify(&mut self, binding: &Binding, stage: Stage) -> Result<()>;
        /// Reattest exactly the given real retained NEW-key token and SAME lock:
        /// current key/path continuity, exact IPAutoconfigurationEnabled DWORD0,
        /// Preparing/Disabled durable revision and fresh exact NIC absence.
        /// Must verify independently trusted Context AND exact current durable
        /// Preparing/Disabled generation with independently held FRESH effect
        /// permission. Cleanup-only reopen, failed/lost fresh ACK or a context
        /// observation alone must deny creation, even if desired bytes exist.
        /// Must also recheck the exact matching installed package and absence
        /// of foreign/legacy/problem Wintun devices at this LAST create seam.
        fn authorize_create(
            &mut self,
            binding: &Binding,
            record: &receipt::Record,
            ack: &NewKeyAck<Self::Key>,
            lock: &mut Self::MutationLock,
        ) -> Result<()>;
        /// Actual PnP/provider attestation: WireGuard LLC, matching0.14.0.0,
        /// SWD\\Wintun instance and exact requested GUID/name/description/type.
        /// Observe requires live permission; CleanupObserve must instead
        /// validate current Closing and original factual pins without rearming
        /// forward trust. Neither stage alone authorizes end/close effects.
        fn provider(&mut self, binding: &Binding, identity: &Identity, stage: Stage) -> Result<()>;
        /// Infallible retention of the SAME newly returned opaque native ACK.
        /// Prepared runtime/source/lease capabilities MUST already be held.
        /// Retain before any fallible provider/read/journal query. A failed
        /// publication poisons later live checks, NEVER discards/reopens/close
        /// by metadata or converts this acknowledged create to a zero-ACK Err.
        fn acknowledged_original(&mut self, original: OriginalAdapterRead);
        /// Infallible retention of the SAME Carrier's private session state,
        /// installed from the rooted carrier before reference acquisition or Start.
        /// Neither metadata nor a second read may replace this original.
        fn retain_original_session(&mut self, original: SessionEndRead);
        /// Infallibly release ONLY cooperative installation leases at the
        /// outer call boundary, including errors/unwind. Retain raw originals,
        /// uncertain ACK/retirement state, module/source/serialized actor pins
        /// and irreversible forward revocation. This grants no effect rights.
        fn release_call_resources(&mut self);
    }

    /// Opaque borrowed or owned authenticated module/runtime/lock capability. No Clone,
    /// serde, path-based loader or successful production default constructor.
    pub(crate) struct AuthenticatedModule<'a, A: ModuleRuntimeAuthority> {
        module: NonNull<c_void>,
        authority: AuthorityHolder<'a, A>,
    }
    impl<'a, A: ModuleRuntimeAuthority> AuthenticatedModule<'a, A> {
        /// # Safety
        /// module is the actual pinned HMODULE loaded ONLY after Authority's
        /// pre-initialization checks; the authenticated payload is audited0.14.1
        /// x64, not a caller path/number. authority holds the REAL source pins,
        /// module owner and runtime/mutation lock. They outlive this borrow.
        pub(crate) unsafe fn borrow(module: NonNull<c_void>, authority: &'a mut A) -> Self {
            Self {
                module,
                authority: AuthorityHolder::Borrowed(authority),
            }
        }
        /// Retains the actual authority by value for a persistent carrier.
        /// References inside A keep their real lifetimes; no static owner is required.
        ///
        /// # Safety
        /// module is the SAME independently authenticated, pinned original
        /// HMODULE loaded after A's pre-initialization checks for audited0.14.1
        /// x64. A owns the REAL module/source/runtime/lock capabilities and
        /// retains them throughout this module and its carrier, including errors.
        /// A path, numeric handle or metadata alone cannot grant this capability.
        pub(crate) unsafe fn own(module: NonNull<c_void>, authority: A) -> Self {
            Self {
                module,
                authority: AuthorityHolder::Owned(authority),
            }
        }
    }
    struct AdapterResource {
        raw: NonNull<c_void>,
        context: receipt::Context,
        binding: receipt::Binding,
        generation: u64,
        tunnel_type: String,
        module: std::rc::Rc<NativeKernelReferenceRead>,
        luid: Luid,
    }
    pub(crate) struct Adapter(OriginalReceipt<AdapterResource>);
    /// Actual original native-create ACK, opaque/read-only/non-Clone/non-Send.
    /// Can be obtained only from the Adapter returned by the real kernel seam.
    /// No paths/names/raw-pointer/record constructor and no close/effect API.
    pub(crate) struct OriginalAdapterRead(OriginalRead<AdapterResource>);
    pub(crate) struct OriginalAdapterClosed(OriginalClosed<AdapterResource>);
    /// Actual returned FreeLibrary ACK for THIS originally created and closed
    /// adapter's extra reference. Immutable history stays alive. No numeric,
    /// record or source constructor; no whole module-unload/effect permission.
    pub(crate) struct OriginalAdapterModuleReleased(OriginalRead<AdapterResource>);
    impl OriginalAdapterModuleReleased {
        pub(super) fn verify_original(
            &self,
            original: &OriginalAdapterRead,
            closed: &OriginalAdapterClosed,
        ) -> Result<()> {
            original.verify_closed(closed)?;
            if !std::rc::Rc::ptr_eq(&self.0 .0, &original.0 .0)
                || self.0 .0.resource.module.verify_released().is_err()
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
    }
    impl OriginalAdapterRead {
        pub(super) fn read_pin(&self) -> Self {
            Self(self.0.read_pin())
        }
        pub(super) fn creation(&self) -> (&receipt::Context, &receipt::Binding, u64) {
            let r = &self.0 .0.resource;
            (&r.context, &r.binding, r.generation)
        }
        pub(super) fn original_module(&self) -> NonNull<c_void> {
            self.0 .0.resource.module.original
        }
        pub(super) fn original_luid(&self) -> Result<u64> {
            let r = self.0.live_resource()?;
            let mut luid = NET_LUID_LH { Value: 0 };
            unsafe {
                (r.luid)(r.raw.as_ptr(), &mut luid);
            }
            let value = unsafe { luid.Value };
            if value == 0 {
                Err(Error::Conflict)
            } else {
                Ok(value)
            }
        }
        pub(super) fn take_closed(&self) -> Result<OriginalAdapterClosed> {
            self.0.take_closed().map(OriginalAdapterClosed)
        }
        pub(super) fn verify_closed(&self, proof: &OriginalAdapterClosed) -> Result<()> {
            self.0.verify_closed(&proof.0)
        }
        /// Main's caller must hold the SAME actual Runtime/Calling/Retired SDK
        /// bracket. Both actual adapter CloseACK and original loader remain
        /// rooted outside this operation. Not a C close or forward permission.
        pub(super) fn release_closed_module_reference_with_pin(
            &self,
            closed: &OriginalAdapterClosed,
            retain: impl FnOnce(std::rc::Rc<OriginalAdapterModuleReleased>) -> Result<()>,
        ) -> Result<()> {
            self.verify_closed(closed)?;
            let module = &self.0 .0.resource.module;
            let pin = module.pin.get().ok_or(Error::Retired)?;
            module.release.run(
                || {
                    self.verify_closed(closed)?;
                    module.verify_acquired_original()
                },
                || {
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::native_adapter_reference_release_attempted();
                    if unsafe { FreeLibrary(pin.as_ptr()) } == 0 {
                        return Err(Error::Native);
                    }
                    Ok(())
                },
                || {
                    // Factual ACK state is retained in the SAME original BEFORE
                    // external callback/postflight, even on Err/unwind.
                    module.pin.set(None);
                    let ack = std::rc::Rc::new(OriginalAdapterModuleReleased(self.0.read_pin()));
                    retain(ack)?;
                    self.verify_closed(closed)
                },
            )
        }
        /// Cleanup-only read of the ACK ALREADY returned by the native release.
        /// A failed later postflight cannot erase it; raw effect failure cannot
        /// mint it. Caller independently repeats its original full brackets.
        pub(super) fn closed_module_reference_read(
            &self,
            closed: &OriginalAdapterClosed,
        ) -> Result<std::rc::Rc<OriginalAdapterModuleReleased>> {
            self.verify_closed(closed)?;
            self.0 .0.resource.module.verify_released()?;
            Ok(std::rc::Rc::new(OriginalAdapterModuleReleased(
                self.0.read_pin(),
            )))
        }
    }
    pub(crate) struct Session(NonNull<c_void>);
    pub(crate) struct Packet(NonNull<u8>);
    pub(crate) struct NativeKernel<'a, A: ModuleRuntimeAuthority> {
        module: AuthenticatedModule<'a, A>,
        functions: Functions,
        reference: std::rc::Rc<NativeKernelReferenceRead>,
        adapter_reference: Option<std::rc::Rc<NativeKernelReferenceRead>>,
        clock: Instant,
    }
    /// SAME actual extra-reference owner and its original acquire/release
    /// outcomes. Read aliases retain this object without reborrowing Authority.
    /// No public handle/metadata/success constructor or implicit unload exists.
    pub(crate) struct NativeKernelReferenceRead {
        original: NonNull<c_void>,
        attempted: std::cell::Cell<bool>,
        returned: std::cell::Cell<bool>,
        pin: std::cell::Cell<Option<NonNull<c_void>>>,
        release: ClosedReferenceRelease,
    }
    pub(crate) struct NativeCarrierComponentsTerminalRead {
        pub(crate) reference: std::rc::Rc<NativeKernelReferenceRead>,
        pub(crate) adapter_reference: Option<std::rc::Rc<NativeKernelReferenceRead>>,
        pub(crate) session: SessionEndRead,
    }
    impl NativeCarrierComponentsTerminalRead {
        pub(crate) fn verify_released(&self) -> Result<()> {
            self.reference.verify_released()?;
            if let Some(reference) = &self.adapter_reference {
                reference.verify_released()?;
            }
            if !matches!(
                self.session.0.state.get(),
                SessionEndState::NeverStarted | SessionEndState::Acknowledged
            ) {
                return Err(Error::Pending);
            }
            Ok(())
        }
    }
    impl NativeKernelReferenceRead {
        fn new(original: NonNull<c_void>) -> Self {
            Self {
                original,
                attempted: std::cell::Cell::new(false),
                returned: std::cell::Cell::new(false),
                pin: std::cell::Cell::new(None),
                release: ClosedReferenceRelease::new(),
            }
        }
        fn live(&self) -> Result<()> {
            if !self.returned.get() || self.pin.get() != Some(self.original) {
                return Err(Error::Retired);
            }
            Ok(())
        }
        pub(crate) fn verify_acquired_original(&self) -> Result<()> {
            if !self.attempted.get() {
                return Err(Error::Pending);
            }
            self.live()
        }
        #[cfg(test)]
        pub(in crate::windows) fn verify_retained_original(&self) -> Result<()> {
            if !self.attempted.get() || self.release.was_attempted() {
                return Err(Error::Pending);
            }
            self.live()
        }
        pub(crate) fn verify_released(&self) -> Result<()> {
            if self.pin.get().is_some() || !self.release.acknowledged() {
                return Err(Error::Pending);
            }
            Ok(())
        }
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            std::ptr::eq(self, other)
        }
        fn release_original(&self) -> Result<()> {
            let pin = self.pin.get().ok_or(Error::Retired)?;
            self.release.run(
                || self.verify_acquired_original(),
                || {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::native_resolver_reference_release_attempted();
                    if unsafe { FreeLibrary(pin.as_ptr()) } == 0 {
                        return Err(Error::Native);
                    }
                    Ok(())
                },
                || {
                    self.pin.set(None);
                    Ok(())
                },
            )
        }
    }
    impl<A: ModuleRuntimeAuthority> Carrier<NativeKernel<'_, A>> {
        pub(crate) fn kernel_reference_read(&self) -> std::rc::Rc<NativeKernelReferenceRead> {
            self.kernel.reference.clone()
        }
        /// Roots factual reads before fallible checks. The actual original
        /// counters, never a phase/Option or caller snapshot, acknowledge release.
        pub(crate) fn terminal_components_read(
            &self,
        ) -> std::rc::Rc<NativeCarrierComponentsTerminalRead> {
            std::rc::Rc::new(NativeCarrierComponentsTerminalRead {
                reference: self.kernel_reference_read(),
                adapter_reference: self.kernel.adapter_reference.clone(),
                session: self.session_end_read(),
            })
        }
        pub(crate) fn verify_terminal_components(&self) -> Result<()> {
            if self.phase != Phase::Closed
                || self.adapter.is_some()
                || self.session.is_some()
                || self.kernel.reference.verify_released().is_err()
                || !matches!(
                    self.session_end.state.get(),
                    SessionEndState::NeverStarted | SessionEndState::Acknowledged
                )
            {
                return Err(Error::Pending);
            }
            Ok(())
        }
    }
    /// Prepares the carrier without acquiring a native module reference. The
    /// caller must root it before initializing its extra original reference.
    pub(crate) fn prepare_carrier<A: ModuleRuntimeAuthority>(
        module: AuthenticatedModule<'_, A>,
        binding: Binding,
    ) -> Result<Carrier<NativeKernel<'_, A>>> {
        validate_binding(&binding)?;
        Carrier::new(NativeKernel::prepare(module, &binding)?, binding)
    }
    impl<A: ModuleRuntimeAuthority> Carrier<NativeKernel<'_, A>> {
        /// Invoke only on the caller's retained slot. The SAME carrier and its
        /// actual returned reference survive every subsequent Err or unwind.
        pub(crate) fn initialize_original_reference(&mut self) -> Result<()> {
            if self.kernel.reference.attempted.replace(true) {
                return Err(Error::Pending);
            }
            with_call_resources(self, |carrier| {
                let original = carrier.session_end_read();
                carrier
                    .kernel
                    .module
                    .authority
                    .as_mut()
                    .retain_original_session(original);
                carrier.kernel.initialize_reference(&carrier.binding)
            })
        }
    }
    impl<'a, A: ModuleRuntimeAuthority> NativeKernel<'a, A> {
        fn prepare(mut module: AuthenticatedModule<'a, A>, binding: &Binding) -> Result<Self> {
            if !cfg!(target_arch = "x86_64") {
                return Err(Error::Unsupported);
            }
            let functions = with_call_resources(&mut module, |module| {
                module.authority.as_mut().verify(binding, Stage::Resolve)?;
                // Resolve exports through the already-held original HMODULE.
                // Failure here precedes acquiring any extra native reference.
                unsafe {
                    Functions::resolve(|name| {
                        GetProcAddress(module.module.as_ptr(), name.as_ptr().cast())
                    })
                }
            })?;
            Ok(Self {
                reference: std::rc::Rc::new(NativeKernelReferenceRead::new(module.module)),
                adapter_reference: None,
                module,
                functions,
                clock: Instant::now(),
            })
        }
        fn initialize_reference(&mut self, binding: &Binding) -> Result<()> {
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(
                "C native Resolve authorization",
            );
            self.module
                .authority
                .as_mut()
                .verify(binding, Stage::Resolve)?;
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(
                "C native Resolve GetModuleHandleExW",
            );
            let mut pin: HMODULE = ptr::null_mut();
            // Adds a reference to the SAME original, without DLL initialization.
            let returned = unsafe {
                GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    self.module.module.as_ptr().cast(),
                    &mut pin,
                )
            };
            // FIRST retain the actual OS output in the caller's owning kernel.
            // Neither an unexpected identity nor any later fault unloads it.
            self.reference.pin.set(NonNull::new(pin));
            self.reference.returned.set(returned != 0);
            if returned == 0 {
                return Err(Error::Native);
            }
            if pin != self.module.module.as_ptr() {
                return Err(Error::Conflict);
            }
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::native_resolver_reference_returned(
                &self.reference,
            )
            .map_err(|_| Error::Native)?;
            Ok(())
        }
        fn live(&self) -> Result<()> {
            self.reference.live()
        }
    }
    impl<A: ModuleRuntimeAuthority> CallResources for AuthenticatedModule<'_, A> {
        fn release_call_resources(&mut self) {
            self.authority.as_mut().release_call_resources();
        }
    }
    // Deliberately no Drop cleanup: implicit destructive close cannot reattest
    // restored rows/guard obligations. A dropped unfinished kernel leaks its
    // extra HMODULE ref and raw capabilities to process exit, never unloads code
    // underneath them or adopts by name. Explicit returned errors retain Self.
    impl<A: ModuleRuntimeAuthority> Kernel for NativeKernel<'_, A> {
        type Adapter = Adapter;
        type Session = Session;
        type Packet = Packet;
        type Row = MIB_IF_ROW2;
        type Key = A::Key;
        type MutationLock = A::MutationLock;
        type Prerequisite<'p>
            = PrecreationReceipt<'p, A::Key, A::MutationLock>
        where
            A::Key: 'p,
            A::MutationLock: 'p;
        fn verify(&mut self, binding: &Binding, stage: Stage) -> Result<()> {
            self.live()?;
            self.module.authority.as_mut().verify(binding, stage)
        }
        fn driver_version(&mut self) -> Result<Option<u32>> {
            self.live()?;
            let version = unsafe { (self.functions.version)() };
            let error = if version == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            driver_status(version, error)
        }
        fn absent(&mut self, binding: &Binding) -> Result<()> {
            self.live()?;
            let mut raw: *mut MIB_IF_TABLE2 = ptr::null_mut();
            let status = unsafe { GetIfTable2(&mut raw) };
            struct Table(*mut MIB_IF_TABLE2);
            impl Drop for Table {
                fn drop(&mut self) {
                    if !self.0.is_null() {
                        unsafe {
                            FreeMibTable(self.0.cast());
                        }
                    }
                }
            }
            let table = Table(raw);
            #[cfg(test)]
            if status == 0 && !table.0.is_null() {
                crate::windows::member_carrier_factory_test_os::native_table_read(true)
                    .map_err(|_| Error::Native)?;
            }
            if status != 0 || table.0.is_null() {
                return Err(Error::Native);
            }
            let count = unsafe { (*table.0).NumEntries } as usize;
            if count > 4096 {
                return Err(Error::Unsupported);
            }
            let rows = unsafe {
                std::slice::from_raw_parts(
                    ptr::addr_of!((*table.0).Table).cast::<MIB_IF_ROW2>(),
                    count,
                )
            };
            for row in rows {
                let alias = wide_string(&row.Alias)?;
                if guid_bytes(&row.InterfaceGuid) == binding.guid
                    || alias.eq_ignore_ascii_case(&binding.name)
                {
                    return Err(Error::Conflict);
                }
            }
            Ok(())
        }
        fn create<'p>(
            &mut self,
            binding: &Binding,
            prerequisite: Self::Prerequisite<'p>,
        ) -> Result<Adapter>
        where
            Self::Key: 'p,
            Self::MutationLock: 'p,
        {
            self.live()?;
            // Carrier already performed the factual driver/absence queries
            // under BeforeCreate. The mandatory authorize_create below again
            // verifies the FULL original package/running driver/universe and
            // exact NEW-HKEY/lock LAST before the SDK effect. Repeating those
            // early queries here cannot replace or strengthen that final gate.
            receipt::validate_record(prerequisite.record).map_err(|_| Error::Invalid)?;
            if prerequisite.binding.role != receipt::Role::RoleCarrier
                || prerequisite.binding.guid != binding.guid
                || prerequisite.binding.name != binding.name
                || prerequisite.record.context.bindings[0] != *prerequisite.binding
                || prerequisite.record.phase != receipt::Phase::Preparing
                || prerequisite.record.keys[0].phase != receipt::KeyPhase::Disabled
            {
                return Err(Error::Conflict);
            }
            // Root this DISTINCT extra-reference owner before the OS attempt.
            // Failed authorization/create keeps it in the original kernel;
            // successful create shares this SAME owner with the adapter ACK.
            if self.adapter_reference.is_some() {
                return Err(Error::Pending);
            }
            let original_module =
                std::rc::Rc::new(NativeKernelReferenceRead::new(self.module.module));
            self.adapter_reference = Some(original_module.clone());
            original_module.attempted.set(true);
            let mut raw_pin: HMODULE = ptr::null_mut();
            let returned = unsafe {
                GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    self.module.module.as_ptr().cast(),
                    &mut raw_pin,
                )
            };
            // FIRST preserve the actual returned output, including unexpected
            // identity/failure. No Err/unwind or Drop can unload or retry it.
            original_module.pin.set(NonNull::new(raw_pin));
            original_module.returned.set(returned != 0);
            if returned == 0 {
                return Err(Error::Native);
            }
            if raw_pin != self.module.module.as_ptr() {
                return Err(Error::Conflict);
            }
            #[cfg(test)]
            crate::windows::member_carrier_factory_test_os::native_adapter_reference_returned(
                &original_module,
            )
            .map_err(|_| Error::Native)?;
            let context = prerequisite.record.context.clone();
            let original_binding = prerequisite.binding.clone();
            let generation = prerequisite.record.generation;
            let tunnel_type = binding.tunnel_type.clone();
            // LAST native attestation before create, still borrowing the ACTUAL
            // captured token and mutation lock from before_adapter_create.
            self.module.authority.as_mut().authorize_create(
                binding,
                prerequisite.record,
                prerequisite.new_key_ack,
                prerequisite.mutation_lock,
            )?;
            #[cfg(all(windows, test))]
            if crate::windows::member_carrier_factory_test_os::state().is_some() {
                if let Some(raw) = unsafe {
                    GetProcAddress(
                        self.module.module.as_ptr(),
                        c"WintunSetLogger".as_ptr().cast(),
                    )
                } {
                    // SAME authenticated resident adapter-reference pin; not the test resolver.
                    let set_logger: unsafe extern "system" fn(
                        Option<unsafe extern "system" fn(i32, u64, *const u16)>,
                    ) = unsafe { std::mem::transmute(raw) };
                    unsafe { set_logger(Some(native_error_logger)) };
                }
            }
            let name: Vec<u16> = binding.name.encode_utf16().chain(Some(0)).collect();
            let kind: Vec<u16> = binding.tunnel_type.encode_utf16().chain(Some(0)).collect();
            let guid = Guid::new(binding.guid);
            #[cfg(test)]
            crate::windows::member_carrier_factory_test_os::trace_step(
                "C native CreateAdapter entered",
            );
            #[cfg(test)]
            crate::windows::member_carrier_factory_test_os::native_adapter_create_attempted();
            let raw = unsafe { (self.functions.create)(name.as_ptr(), kind.as_ptr(), &guid) };
            // Consume the actual borrowed receipt AFTER the native call. The
            // caller-held lock/token, not this record, supply live authority.
            let _held_through_effect = prerequisite;
            let raw = NonNull::new(raw).ok_or(Error::Native)?;
            // FIRST operation after successful native return retains the ACK.
            // No PnP/row/journal lookup or fallible publication precedes it.
            Ok(Adapter(OriginalReceipt::acknowledged_then(
                AdapterResource {
                    raw,
                    context,
                    binding: original_binding,
                    generation,
                    tunnel_type,
                    module: original_module,
                    luid: self.functions.luid,
                },
                |read| {
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::native_original_retained(
                        "carrier", &read.0,
                    );
                    self.module
                        .authority
                        .as_mut()
                        .acknowledged_original(OriginalAdapterRead(read))
                },
            )))
        }
        fn luid(&mut self, adapter: &Adapter) -> Result<u64> {
            self.live()?;
            let mut native_luid = NET_LUID_LH { Value: 0 };
            let raw = adapter.0.read_pin();
            unsafe { (self.functions.luid)(raw.live_resource()?.raw.as_ptr(), &mut native_luid) };
            let luid = unsafe { native_luid.Value };
            if luid == 0 {
                Err(Error::Conflict)
            } else {
                Ok(luid)
            }
        }
        fn row_luid(&mut self, luid: u64) -> Result<MIB_IF_ROW2> {
            self.live()?;
            let mut row = MIB_IF_ROW2 {
                InterfaceLuid: NET_LUID_LH { Value: luid },
                ..Default::default()
            };
            if unsafe { GetIfEntry2(&mut row) } != 0 {
                return Err(Error::Native);
            }
            Ok(row)
        }
        fn row_index(&mut self, index: u32) -> Result<MIB_IF_ROW2> {
            self.live()?;
            let mut row = MIB_IF_ROW2 {
                InterfaceIndex: index,
                ..Default::default()
            };
            if unsafe { GetIfEntry2(&mut row) } != 0 {
                return Err(Error::Native);
            }
            Ok(row)
        }
        fn identity(&self, row: &MIB_IF_ROW2) -> Result<Identity> {
            virtual_role(row.InterfaceAndOperStatusFlags._bitfield)?;
            Ok(Identity {
                guid: guid_bytes(&row.InterfaceGuid),
                luid: unsafe { row.InterfaceLuid.Value },
                index: row.InterfaceIndex,
                name: wide_string(&row.Alias)?,
                description: wide_string(&row.Description)?,
                if_type: row.Type,
                tunnel_type: row.TunnelType,
            })
        }
        fn attest(&mut self, binding: &Binding, identity: &Identity, stage: Stage) -> Result<()> {
            if !matches!(stage, Stage::Observe | Stage::CleanupObserve) {
                return Err(Error::Invalid);
            }
            self.module
                .authority
                .as_mut()
                .provider(binding, identity, stage)
        }
        fn start(&mut self, adapter: &Adapter, capacity: u32) -> Result<Session> {
            self.live()?;
            if capacity != 0x20000 {
                return Err(Error::Unsupported);
            }
            let raw = adapter.0.read_pin();
            NonNull::new(unsafe {
                (self.functions.start)(raw.live_resource()?.raw.as_ptr(), capacity)
            })
            .map(Session)
            .ok_or(Error::Native)
        }
        fn receive(&mut self, session: &Session) -> Result<Receive<Packet>> {
            self.live()?;
            let mut size = 0;
            let raw = unsafe { (self.functions.receive)(session.0.as_ptr(), &mut size) };
            if let Some(packet) = NonNull::new(raw) {
                return Ok(Receive::Packet(Packet(packet), size));
            }
            match unsafe { GetLastError() } {
                259 => Ok(Receive::Empty),
                38 => Ok(Receive::Eof),
                _ => Err(Error::Native),
            }
        }
        fn release(&mut self, session: &Session, packet: Packet) {
            unsafe { (self.functions.release)(session.0.as_ptr(), packet.0.as_ptr()) };
        }
        fn wait(&mut self, session: &Session, milliseconds: u32) -> Result<()> {
            self.live()?;
            if milliseconds > 50 {
                return Err(Error::Invalid);
            }
            let event = unsafe { (self.functions.event)(session.0.as_ptr()) };
            if event.is_null() || event as isize == -1 {
                return Err(Error::Native);
            }
            match unsafe { WaitForSingleObject(event, milliseconds) } {
                0 | 258 => Ok(()),
                _ => Err(Error::Native),
            }
        }
        fn now_ms(&self) -> u64 {
            self.clock.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
        }
        fn end(&mut self, session: Session) {
            unsafe { (self.functions.end)(session.0.as_ptr()) };
        }
        fn close(&mut self, adapter: Adapter) {
            // Outer Carrier independently authorizes exact cleanup before this
            // seam. Unknown close outcome remains pending; never a retry/adopt.
            let _closed = adapter
                .0
                .close(|r| unsafe { (self.functions.close)(r.raw.as_ptr()) });
        }
        fn release_module(&mut self) -> Result<()> {
            self.reference.release_original()
        }
        fn release_call_resources(&mut self) {
            self.module.authority.as_mut().release_call_resources();
        }
    }
    impl<A: ModuleRuntimeAuthority> Carrier<NativeKernel<'_, A>> {
        /// Works after a later capture/publication failure while the SAME raw
        /// original still needs cleanup; no rearm or permission is supplied.
        pub(super) fn original_adapter_read(&self) -> Result<OriginalAdapterRead> {
            let adapter = self.adapter.as_ref().ok_or(Error::Pending)?;
            Ok(OriginalAdapterRead(adapter.0.read_pin()))
        }
    }
    fn wide_string(chars: &[u16]) -> Result<String> {
        let end = chars
            .iter()
            .position(|c| *c == 0)
            .ok_or(Error::Unsupported)?;
        String::from_utf16(&chars[..end]).map_err(|_| Error::Unsupported)
    }
    fn guid_bytes(g: &windows_sys::core::GUID) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&g.data1.to_be_bytes());
        bytes[4..6].copy_from_slice(&g.data2.to_be_bytes());
        bytes[6..8].copy_from_slice(&g.data3.to_be_bytes());
        bytes[8..].copy_from_slice(&g.data4);
        bytes
    }
    const _: () = {
        assert!(std::mem::size_of::<Guid>() == std::mem::size_of::<windows_sys::core::GUID>());
        assert!(std::mem::align_of::<Guid>() == std::mem::align_of::<windows_sys::core::GUID>());
        assert!(
            std::mem::offset_of!(Guid, data1)
                == std::mem::offset_of!(windows_sys::core::GUID, data1)
        );
        assert!(
            std::mem::offset_of!(Guid, data2)
                == std::mem::offset_of!(windows_sys::core::GUID, data2)
        );
        assert!(
            std::mem::offset_of!(Guid, data3)
                == std::mem::offset_of!(windows_sys::core::GUID, data3)
        );
        assert!(
            std::mem::offset_of!(Guid, data4)
                == std::mem::offset_of!(windows_sys::core::GUID, data4)
        );
        assert!(std::mem::size_of::<NET_LUID_LH>() == 8);
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid,
    Unsupported,
    Native,
    Conflict,
    Pending,
    Retired,
    Cancelled,
    Deadline,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Binding {
    pub guid: [u8; 16],
    pub name: String,
    pub tunnel_type: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub guid: [u8; 16],
    pub luid: u64,
    pub index: u32,
    pub name: String,
    pub description: String,
    pub if_type: u32,
    pub tunnel_type: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    Resolve,
    Observe,
    CleanupObserve,
    BeforeCreate,
    BeforeSession,
    BeforeDrain,
    BeforeEnd,
    BeforeClose,
    AfterClose,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Empty,
    CreatePending,
    Created,
    Session,
    Closing,
    ClosePending,
    Closed,
}
pub(crate) enum Receive<P> {
    Packet(P, u32),
    Empty,
    Eof,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DrainStop {
    Cancelled,
    Deadline,
    PacketLimit,
    Eof,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Drain {
    pub discarded: u32,
    pub stop: DrainStop,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionEndState {
    NeverStarted,
    StartPending,
    Live,
    EndPending,
    Acknowledged,
}
struct SessionEndShared {
    state: std::cell::Cell<SessionEndState>,
}
/// Read-only retention of this carrier's one original session-end outcome.
/// Neither a read alias nor an imported identity can acknowledge an effect.
pub(crate) struct SessionEndRead(std::rc::Rc<SessionEndShared>);
/// Constructed only from the SAME retained state after Kernel::end returns.
pub(crate) struct SessionEnded(std::rc::Rc<SessionEndShared>);
/// One original read registered by the actual native Carrier constructor.
/// Duplicate/late registration never replaces the first opaque original.
pub(crate) struct OriginalSessionRead {
    original: Option<SessionEndRead>,
    invalid: bool,
}
impl OriginalSessionRead {
    pub(crate) fn new() -> Self {
        Self {
            original: None,
            invalid: false,
        }
    }
    pub(crate) fn retain(&mut self, read: SessionEndRead) {
        if self.original.is_some() || self.invalid {
            self.invalid = true;
            return;
        }
        self.original = Some(read); // original retained before validation
        if self
            .original
            .as_ref()
            .expect("retained")
            .verify_never_started()
            .is_err()
        {
            self.invalid = true;
        }
    }
    pub(crate) fn endable(&self) -> Result<()> {
        if self.invalid {
            return Err(Error::Pending);
        }
        self.original
            .as_ref()
            .ok_or(Error::Pending)?
            .verify_endable()
    }
    pub(crate) fn retain_handoff(&mut self, read: SessionEndRead) {
        if self.original.is_some() || self.invalid {
            self.invalid = true;
            return;
        }
        self.original = Some(read); // SAME original rooted before validation
        if self
            .original
            .as_ref()
            .expect("retained")
            .verify_endable()
            .is_err()
        {
            self.invalid = true;
        }
    }
    pub(crate) fn live(&self) -> Result<()> {
        if self.invalid {
            return Err(Error::Pending);
        }
        if self.original.as_ref().ok_or(Error::Pending)?.0.state.get() != SessionEndState::Live {
            return Err(Error::Pending);
        }
        Ok(())
    }
    pub(crate) fn no_live_session(&self) -> Result<()> {
        if self.invalid {
            return Err(Error::Pending);
        }
        self.original
            .as_ref()
            .ok_or(Error::Pending)?
            .verify_no_live_session()
    }
}
impl SessionEndRead {
    /// Factual SAME original outcome only; never authorizes native Close.
    pub(crate) fn verify_no_live_session(&self) -> Result<()> {
        match self.0.state.get() {
            SessionEndState::NeverStarted | SessionEndState::Acknowledged => Ok(()),
            _ => Err(Error::Pending),
        }
    }
    /// Registration precedes any native Start; unknown or ended replacements
    /// cannot be installed as the original lifecycle's initial observation.
    pub(crate) fn verify_never_started(&self) -> Result<()> {
        if self.0.state.get() == SessionEndState::NeverStarted {
            Ok(())
        } else {
            Err(Error::Pending)
        }
    }
    /// End may consume only Live, or freshly reattest its SAME original ACK.
    pub(crate) fn verify_endable(&self) -> Result<()> {
        match self.0.state.get() {
            SessionEndState::Live | SessionEndState::Acknowledged => Ok(()),
            _ => Err(Error::Pending),
        }
    }
    pub(crate) fn read_pin(&self) -> Self {
        Self(self.0.clone())
    }
    pub(crate) fn acknowledged(&self) -> Result<SessionEnded> {
        if self.0.state.get() != SessionEndState::Acknowledged {
            return Err(Error::Pending);
        }
        Ok(SessionEnded(self.0.clone()))
    }
    pub(crate) fn verify_acknowledged(&self, ack: &SessionEnded) -> Result<()> {
        if !std::rc::Rc::ptr_eq(&self.0, &ack.0)
            || self.0.state.get() != SessionEndState::Acknowledged
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// The slow native boundary only. Every method is required; no native authority
/// is supplied by default, a name, an index or serialized provenance.
pub(crate) trait Kernel {
    type Adapter;
    type Session;
    type Packet;
    type Row;
    type Key;
    type MutationLock;
    type Prerequisite<'p>
    where
        Self::Key: 'p,
        Self::MutationLock: 'p;
    fn verify(&mut self, binding: &Binding, stage: Stage) -> Result<()>;
    fn driver_version(&mut self) -> Result<Option<u32>>;
    fn absent(&mut self, binding: &Binding) -> Result<()>;
    fn create<'p>(
        &mut self,
        binding: &Binding,
        prerequisite: Self::Prerequisite<'p>,
    ) -> Result<Self::Adapter>
    where
        Self::Key: 'p,
        Self::MutationLock: 'p;
    fn luid(&mut self, adapter: &Self::Adapter) -> Result<u64>;
    fn row_luid(&mut self, luid: u64) -> Result<Self::Row>;
    fn row_index(&mut self, index: u32) -> Result<Self::Row>;
    fn identity(&self, row: &Self::Row) -> Result<Identity>;
    fn attest(&mut self, binding: &Binding, identity: &Identity, stage: Stage) -> Result<()>;
    /// Returned Err certifies no session was started (native NULL/preflight
    /// failure). An unknown outcome must not be reported as that fact.
    fn start(&mut self, adapter: &Self::Adapter, capacity: u32) -> Result<Self::Session>;
    fn receive(&mut self, session: &Self::Session) -> Result<Receive<Self::Packet>>;
    fn release(&mut self, session: &Self::Session, packet: Self::Packet);
    fn wait(&mut self, session: &Self::Session, milliseconds: u32) -> Result<()>;
    fn now_ms(&self) -> u64;
    fn end(&mut self, session: Self::Session);
    fn close(&mut self, adapter: Self::Adapter);
    fn release_module(&mut self) -> Result<()>;
    fn release_call_resources(&mut self);
}

/// No Clone/serde/recovery-by-name. Errors return with this same object holding
/// its original capabilities. The owner must retain it until explicit cleanup.
pub(crate) struct Carrier<K: Kernel> {
    kernel: K,
    binding: Binding,
    phase: Phase,
    adapter: Option<K::Adapter>,
    session: Option<K::Session>,
    session_end: std::rc::Rc<SessionEndShared>,
    original: Option<Identity>,
    captured: Option<K::Row>,
    observed: Option<K::Row>,
    poisoned: bool,
}
impl<K: Kernel> CallResources for Carrier<K> {
    fn release_call_resources(&mut self) {
        self.kernel.release_call_resources();
    }
}
impl<K: Kernel> Carrier<K> {
    pub(crate) fn new(kernel: K, binding: Binding) -> Result<Self> {
        validate_binding(&binding)?;
        Ok(Self {
            kernel,
            binding,
            phase: Phase::Empty,
            adapter: None,
            session: None,
            session_end: std::rc::Rc::new(SessionEndShared {
                state: std::cell::Cell::new(SessionEndState::NeverStarted),
            }),
            original: None,
            captured: None,
            observed: None,
            poisoned: false,
        })
    }
    pub(crate) fn create<'p>(&mut self, prerequisite: K::Prerequisite<'p>) -> Result<()>
    where
        K::Key: 'p,
        K::MutationLock: 'p,
    {
        with_call_resources(self, |owner| owner.create_inner(prerequisite))
    }
    fn create_inner<'p>(&mut self, prerequisite: K::Prerequisite<'p>) -> Result<()>
    where
        K::Key: 'p,
        K::MutationLock: 'p,
    {
        if self.phase != Phase::Empty || self.poisoned {
            return Err(Error::Pending);
        }
        self.kernel.verify(&self.binding, Stage::BeforeCreate)?;
        if !matches!(self.kernel.driver_version()?, None | Some(14)) {
            return Err(Error::Unsupported);
        }
        self.kernel.absent(&self.binding)?;
        self.phase = Phase::CreatePending; // Caller must journal BEFORE this effect.
        self.poisoned = true;
        self.adapter = Some(self.kernel.create(&self.binding, prerequisite)?);
        if self.kernel.driver_version()? != Some(14) {
            return Err(Error::Unsupported);
        }
        self.capture()?;
        self.phase = Phase::Created;
        self.poisoned = false;
        Ok(())
    }
    fn capture(&mut self) -> Result<()> {
        self.capture_for(Stage::Observe)
    }
    fn capture_for(&mut self, stage: Stage) -> Result<()> {
        self.kernel
            .verify(&self.binding, stage)
            .inspect_err(|_error| {
                #[cfg(all(test, windows))]
                if stage == Stage::Observe {
                    trace_observe(&format!("C Observe capture kernel error={_error:?}"));
                }
            })?;
        #[cfg(all(test, windows))]
        if stage == Stage::Observe {
            trace_observe("C Observe capture kernel verify accepted");
        }
        let adapter = self.adapter.as_ref().ok_or(Error::Pending)?;
        let luid = self.kernel.luid(adapter)?;
        if luid == 0 {
            return Err(Error::Conflict);
        }
        let row = self.kernel.row_luid(luid)?;
        let identity = self.kernel.identity(&row)?;
        if identity.luid != luid
            || identity.index == 0
            || identity.guid != self.binding.guid
            || identity.name != self.binding.name
            || identity.if_type != 53
            || !crate::member_interface_description::matches_requested(
                &format!("{} Tunnel", self.binding.tunnel_type),
                &identity.description,
            )
            || self.original.as_ref().is_some_and(|old| *old != identity)
        {
            #[cfg(all(test, windows))]
            if stage == Stage::Observe {
                trace_observe("C Observe capture raw identity mismatch: Conflict");
            }
            return Err(Error::Conflict);
        }
        let by_index = self.kernel.row_index(identity.index)?;
        if self.kernel.identity(&by_index)? != identity || self.kernel.luid(adapter)? != luid {
            #[cfg(all(test, windows))]
            if stage == Stage::Observe {
                trace_observe("C Observe capture by-index mismatch: Conflict");
            }
            return Err(Error::Conflict);
        }
        self.kernel
            .attest(&self.binding, &identity, stage)
            .inspect_err(|_error| {
                #[cfg(all(test, windows))]
                if stage == Stage::Observe {
                    trace_observe(&format!("C Observe capture provider error={_error:?}"));
                }
            })?;
        #[cfg(all(test, windows))]
        if stage == Stage::Observe {
            trace_observe("C Observe capture provider attest accepted");
        }
        if self.original.is_none() {
            self.original = Some(identity);
            self.captured = Some(row);
        }
        self.observed = Some(by_index);
        Ok(())
    }
    pub(crate) fn start(&mut self) -> Result<()> {
        with_call_resources(self, Self::start_inner)
    }
    fn start_inner(&mut self) -> Result<()> {
        if self.phase != Phase::Created || self.poisoned {
            return Err(Error::Pending);
        }
        self.kernel.verify(&self.binding, Stage::BeforeSession)?;
        self.capture()?;
        self.poisoned = true;
        // A missing session after a caught start unwind is not evidence that
        // no native session was started. Keep its outcome unresolved.
        self.session_end.state.set(SessionEndState::StartPending);
        match self
            .kernel
            .start(self.adapter.as_ref().ok_or(Error::Pending)?, 0x20000)
        {
            Ok(session) => self.session = Some(session),
            Err(error) => {
                // Actual NativeKernel errors precede start or report NULL.
                // This certifies no session, never a successful end ACK.
                self.session_end.state.set(SessionEndState::NeverStarted);
                return Err(error);
            }
        }
        self.session_end.state.set(SessionEndState::Live);
        self.phase = Phase::Session;
        self.capture()?;
        self.poisoned = false;
        Ok(())
    }
    pub(crate) fn reattest(&mut self) -> Result<&K::Row> {
        with_call_resources(self, |owner| owner.reattest_inner().map(|_| ()))?;
        self.observed.as_ref().ok_or(Error::Pending)
    }
    fn reattest_inner(&mut self) -> Result<&K::Row> {
        if matches!(
            self.phase,
            Phase::Empty | Phase::Closed | Phase::ClosePending
        ) {
            return Err(Error::Retired);
        }
        if self.poisoned {
            return Err(Error::Pending);
        }
        // A failed observation revokes live use permanently. Cleanup still
        // captures the original retained handle independently in close().
        self.poisoned = true;
        self.capture()?;
        let row = self.observed.as_ref().ok_or(Error::Pending)?;
        self.poisoned = false;
        Ok(row)
    }
    pub(crate) fn drain(
        &mut self,
        cancel: &AtomicBool,
        milliseconds: u32,
        packets: u32,
    ) -> Result<Drain> {
        with_call_resources(self, |owner| {
            owner.drain_inner(cancel, milliseconds, packets)
        })
    }
    fn drain_inner(
        &mut self,
        cancel: &AtomicBool,
        milliseconds: u32,
        packets: u32,
    ) -> Result<Drain> {
        if !(1..=1000).contains(&milliseconds) || !(1..=32).contains(&packets) {
            return Err(Error::Invalid);
        }
        if self.phase != Phase::Session || self.poisoned {
            return Err(Error::Pending);
        }
        self.poisoned = true;
        let result = self.drain_live(cancel, milliseconds, packets);
        if result
            .as_ref()
            .is_ok_and(|drain| drain.stop != DrainStop::Eof)
        {
            self.poisoned = false;
        }
        result
    }
    fn drain_live(
        &mut self,
        cancel: &AtomicBool,
        milliseconds: u32,
        packets: u32,
    ) -> Result<Drain> {
        self.kernel.verify(&self.binding, Stage::BeforeDrain)?;
        self.capture()?;
        let mut last = self.kernel.now_ms();
        let deadline = last
            .checked_add(u64::from(milliseconds))
            .ok_or(Error::Invalid)?;
        let mut discarded = 0;
        loop {
            if cancel.load(Ordering::Acquire) {
                return Ok(Drain {
                    discarded,
                    stop: DrainStop::Cancelled,
                });
            }
            let now = self.kernel.now_ms();
            if now < last {
                return Err(Error::Conflict);
            }
            last = now;
            if now >= deadline {
                return Ok(Drain {
                    discarded,
                    stop: DrainStop::Deadline,
                });
            }
            if discarded >= packets {
                return Ok(Drain {
                    discarded,
                    stop: DrainStop::PacketLimit,
                });
            }
            self.capture()?;
            let session = self.session.as_ref().ok_or(Error::Pending)?;
            match self.kernel.receive(session)? {
                Receive::Packet(packet, size) => {
                    // Discard without reading, logging, forwarding or allocating
                    // any send packet. Always release the original pointer first.
                    self.kernel.release(session, packet);
                    if !(1..=65535).contains(&size) {
                        self.poisoned = true;
                        return Err(Error::Unsupported);
                    }
                    discarded += 1;
                    self.capture()?;
                }
                Receive::Empty => self.kernel.wait(session, (deadline - now).min(50) as u32)?,
                Receive::Eof => {
                    self.poisoned = true;
                    return Ok(Drain {
                        discarded,
                        stop: DrainStop::Eof,
                    });
                }
            }
        }
    }
    pub(crate) fn session_end_read(&self) -> SessionEndRead {
        SessionEndRead(self.session_end.clone())
    }
    /// Ends only the original session. Adapter, module and captured identity
    /// remain retained for a separately authorized close operation. The caller's
    /// integrating supervisor supplies the hard synchronous native-call deadline.
    pub(crate) fn end_session(&mut self, cancel: &AtomicBool) -> Result<()> {
        with_call_resources(self, |owner| {
            owner.poisoned = true;
            owner.cleanup_checkpoint(cancel)?;
            owner.end_session_inner(cancel)
        })
    }
    fn end_session_inner(&mut self, cancel: &AtomicBool) -> Result<()> {
        match self.session_end.state.get() {
            SessionEndState::Acknowledged => {
                // The retained VOID return is a historical fact only. An
                // explicit End retry still requires today's exact operation
                // authority and SAME original adapter observation.
                self.kernel.verify(&self.binding, Stage::BeforeEnd)?;
                self.capture_for(Stage::CleanupObserve)?;
                return self.cleanup_checkpoint(cancel);
            }
            SessionEndState::Live => {}
            // No ACK can be inferred from phase or Option<Session>. Unknown
            // native return stays pending even if a caller catches an unwind.
            _ => return Err(Error::Pending),
        }
        self.kernel.verify(&self.binding, Stage::BeforeEnd)?;
        self.capture_for(Stage::CleanupObserve)?;
        self.cleanup_checkpoint(cancel)?;
        self.phase = Phase::Closing;
        self.session_end.state.set(SessionEndState::EndPending);
        self.kernel.end(self.session.take().ok_or(Error::Pending)?);
        // Native EndSession is VOID. Record its actual return before ANY
        // fallible cancellation/provider postflight can obscure it.
        self.session_end.state.set(SessionEndState::Acknowledged);
        self.cleanup_checkpoint(cancel)?;
        self.capture_for(Stage::CleanupObserve)?;
        self.cleanup_checkpoint(cancel)
    }
    /// Closes the exact original under the caller's hard native-call supervisor.
    pub(crate) fn close_original(&mut self, cancel: &AtomicBool) -> Result<()> {
        with_call_resources(self, |owner| owner.close_inner(cancel))
    }
    /// Reauthenticate the retained close ACK only; leave handle/module cleanup
    /// pending for the original close path, with no repeated native close.
    pub(crate) fn verify_pending_close(&mut self) -> Result<bool> {
        with_call_resources(self, |owner| {
            if owner.phase != Phase::ClosePending {
                return Ok(false);
            }
            owner.kernel.verify(&owner.binding, Stage::AfterClose)?;
            Ok(true)
        })
    }
    fn close_inner(&mut self, cancel: &AtomicBool) -> Result<()> {
        if self.phase == Phase::Closed {
            return Ok(());
        }
        self.poisoned = true; // Teardown never resumes packet/session progression.
        self.cleanup_checkpoint(cancel)?;
        if self.phase == Phase::Empty {
            self.kernel.verify(&self.binding, Stage::AfterClose)?;
            self.kernel.absent(&self.binding)?;
            self.phase = Phase::ClosePending;
            self.cleanup_checkpoint(cancel)?;
            self.kernel.release_module()?;
            self.phase = Phase::Closed;
            return Ok(());
        }
        if self.phase != Phase::ClosePending {
            if matches!(
                self.session_end.state.get(),
                SessionEndState::StartPending | SessionEndState::EndPending
            ) {
                return Err(Error::Pending);
            }
            self.capture_for(Stage::CleanupObserve)?;
            self.phase = Phase::Closing;
            self.poisoned = true;
            if self.session_end.state.get() == SessionEndState::Live {
                // A separately acknowledged End is already complete. Close
                // must use its own pending operation, never authorize End from
                // a CarrierClose record or repeat the consumed native call.
                self.end_session_inner(cancel)?;
            }
            self.kernel.verify(&self.binding, Stage::BeforeClose)?;
            self.capture_for(Stage::CleanupObserve)?;
            #[cfg(all(test, windows))]
            eprintln!("actual native CarrierClose final capture accepted");
            self.cleanup_checkpoint(cancel)?;
            // Native close is VOID. The original handle is consumed exactly once;
            // failure of later absence checks must NEVER retry a freed handle.
            self.kernel
                .close(self.adapter.take().ok_or(Error::Pending)?);
            #[cfg(all(test, windows))]
            eprintln!("actual native CarrierClose native close returned");
            self.phase = Phase::ClosePending;
            self.cleanup_checkpoint(cancel)?;
        }
        self.kernel
            .verify(&self.binding, Stage::AfterClose)
            .inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native CarrierClose AfterClose verify: {_error:?}");
            })?;
        self.kernel.absent(&self.binding)?;
        self.cleanup_checkpoint(cancel)?;
        self.kernel.release_module()?;
        self.phase = Phase::Closed;
        Ok(())
    }
    fn cleanup_checkpoint(&self, cancel: &AtomicBool) -> Result<()> {
        if cancel.load(Ordering::Acquire) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    pub(crate) fn captured(&self) -> Option<&K::Row> {
        self.captured.as_ref()
    }
}
fn validate_binding(binding: &Binding) -> Result<()> {
    if binding.guid == [0; 16]
        || [&binding.name, &binding.tunnel_type].iter().any(|s| {
            s.is_empty()
                || !s.is_ascii()
                || s.trim() != s.as_str()
                || s.encode_utf16().count() > 127
                || s.chars().any(char::is_control)
        })
    {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
