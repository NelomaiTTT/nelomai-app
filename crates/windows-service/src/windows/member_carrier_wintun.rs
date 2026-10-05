//! Retained original-creator Wintun substrate. Factory deliberately disconnected.
#![allow(dead_code)]
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

    #[cfg(test)]
    fn actual_original_ack_composes_with_independent_creator_inventory(
        adapter: OriginalAdapterRead,
        runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
        image: &crate::windows::member_carrier_module::native::OriginalImage,
        scope: crate::windows::member_carrier_creators::Scope,
    ) -> std::result::Result<(), crate::windows::member_carrier_creators::Error> {
        // Compile-only API contract, NOT an actual native-create/runtime test.
        let prepared = PreparedOriginal::new(runtime, image, scope)?;
        // Nothing fallible may precede raw-ACK retention after native return.
        let original: OriginalWintun = prepared.acknowledge(adapter);
        let universe = OriginalUniverse::new(runtime, image)?;
        let context = original.scope.context.clone();
        let (_producer, _observer) = crate::windows::member_carrier_creators::Producer::<
            OriginalWintun,
        >::intent(context, universe)?;
        Ok(())
    }

    #[cfg(test)]
    fn actual_original_registry_supplies_live_package_facts_without_lookup_adoption(
        observer: creators::Observer<OriginalWintun>,
        runtime: &RuntimeRead,
        image: &OriginalImage,
    ) -> creators::Result<()> {
        // Compile-only actual API contract: no hardware execution/permission.
        let mut originals = OriginalPackageInventory::new(observer, runtime, image)?;
        let _ =
            crate::windows::member_carrier_wintun_package::OriginalDevices::observe(&mut originals)
                .map_err(original_error)?;
        Ok(())
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
    /// Resolve/BeforeCreate/BeforeClose recheck maintenance safety and package
    /// continuity: upstream create invokes DriverInstall and close queues orphan
    /// cleanup. Missing/older/mismatched packages never permit install/upgrade.
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
        /// installed by retained_carrier before it can perform any Start.
        /// Neither metadata nor a second read may replace this original.
        fn retain_original_session(&mut self, original: SessionEndRead);
        /// Infallibly release ONLY cooperative installation leases at the
        /// outer call boundary, including errors/unwind. Retain raw originals,
        /// uncertain ACK/retirement state, module/source/serialized actor pins
        /// and irreversible forward revocation. This grants no effect rights.
        fn release_call_resources(&mut self);
    }

    #[cfg(test)]
    unsafe fn owned_native_controller_compile_contract<'a, 'p, A: ModuleRuntimeAuthority + 'a>(
        original_loaded_module: NonNull<c_void>,
        authority: A,
        binding: Binding,
        prerequisite: PrecreationReceipt<'p, A::Key, A::MutationLock>,
    ) -> Result<Carrier<NativeKernel<'a, A>>>
    where
        A::Key: 'p,
        A::MutationLock: 'p,
    {
        // Compile-only real Windows API/borrow contract, NOT native execution.
        // Caller independently authenticated the original loaded HMODULE and A
        // under the same safety contract as AuthenticatedModule::own.
        // The returned carrier owns this local A; it cannot borrow this stack.
        let module = unsafe { AuthenticatedModule::own(original_loaded_module, authority) };
        let mut carrier = retained_carrier(module, binding)?;
        // Every lifecycle API remains usable through the actual NativeKernel.
        // These statements are type-checked only; this function is never run.
        let _ = carrier.create(prerequisite);
        let _ = carrier.reattest();
        let _ = carrier.start();
        let _ = carrier.drain(&AtomicBool::new(false), 100, 2);
        let _ = carrier.original_adapter_read();
        let _ = carrier.close_bounded(&AtomicBool::new(false), 100);
        Ok(carrier)
    }

    #[cfg(test)]
    unsafe fn borrowed_native_controller_compile_contract<'a, A: ModuleRuntimeAuthority>(
        original_loaded_module: NonNull<c_void>,
        authority: &'a mut A,
        binding: Binding,
    ) -> Result<Carrier<NativeKernel<'a, A>>> {
        // Compile-only preservation of the existing borrowed Windows API.
        // Caller meets AuthenticatedModule::borrow's original safety contract.
        let module = unsafe { AuthenticatedModule::borrow(original_loaded_module, authority) };
        retained_carrier(module, binding)
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
    struct ModuleReference(NonNull<c_void>, ClosedReferenceRelease);
    impl Drop for ModuleReference {
        fn drop(&mut self) {
            if !self.1.was_attempted() {
                // Legacy acknowledged native-close teardown only. The new
                // explicit terminal path releases this reference beforehand;
                // failed/unwound explicit attempts NEVER retry through Drop.
                unsafe {
                    FreeLibrary(self.0.as_ptr());
                }
            }
        }
    }
    struct AdapterResource {
        raw: NonNull<c_void>,
        context: receipt::Context,
        binding: receipt::Binding,
        generation: u64,
        tunnel_type: String,
        module: ModuleReference,
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
                || !self.0 .0.resource.module.1.acknowledged()
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
            self.0 .0.resource.module.0
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
            module.1.run(
                || self.verify_closed(closed),
                || {
                    if unsafe { FreeLibrary(module.0.as_ptr()) } == 0 {
                        return Err(Error::Native);
                    }
                    Ok(())
                },
                || {
                    // Factual ACK state is retained in the SAME original BEFORE
                    // external callback/postflight, even on Err/unwind.
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
            if !self.0 .0.resource.module.1.acknowledged() {
                return Err(Error::Pending);
            }
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
        pin: Option<NonNull<c_void>>,
        reference: std::rc::Rc<ClosedReferenceRelease>,
        clock: Instant,
    }
    /// Actual NativeKernel extra-reference return ACK only. It can be read
    /// without reborrowing the actual Authority while its loader is borrowed.
    /// No handle, metadata, equality-by-value or success constructor exists.
    pub(crate) struct NativeKernelReferenceRead(std::rc::Rc<ClosedReferenceRelease>);
    pub(crate) struct NativeCarrierComponentsTerminalRead {
        reference: std::rc::Rc<NativeKernelReferenceRead>,
        session: SessionEndRead,
    }
    impl NativeCarrierComponentsTerminalRead {
        pub(crate) fn verify_released(&self) -> Result<()> {
            self.reference.verify_released()?;
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
        pub(crate) fn verify_released(&self) -> Result<()> {
            if !self.0.acknowledged() {
                return Err(Error::Pending);
            }
            Ok(())
        }
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            std::rc::Rc::ptr_eq(&self.0, &other.0)
        }
    }
    impl<A: ModuleRuntimeAuthority> Carrier<NativeKernel<'_, A>> {
        pub(crate) fn kernel_reference_read(&self) -> std::rc::Rc<NativeKernelReferenceRead> {
            std::rc::Rc::new(NativeKernelReferenceRead(self.kernel.reference.clone()))
        }
        /// Roots factual reads before fallible checks. The actual original
        /// counters, never a phase/Option or caller snapshot, acknowledge release.
        pub(crate) fn terminal_components_read(
            &self,
        ) -> std::rc::Rc<NativeCarrierComponentsTerminalRead> {
            std::rc::Rc::new(NativeCarrierComponentsTerminalRead {
                reference: self.kernel_reference_read(),
                session: self.session_end_read(),
            })
        }
        pub(crate) fn verify_terminal_components(&self) -> Result<()> {
            if self.phase != Phase::Closed
                || self.adapter.is_some()
                || self.session.is_some()
                || self.kernel.pin.is_some()
                || !self.kernel.reference.acknowledged()
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
    /// The only safe construction seam returns the owning lifecycle, not raw
    /// function/adapter/session access. This is NOT product factory selection;
    /// no authenticated module authority implementation or loader exists here.
    pub(crate) fn retained_carrier<A: ModuleRuntimeAuthority>(
        module: AuthenticatedModule<'_, A>,
        binding: Binding,
    ) -> Result<Carrier<NativeKernel<'_, A>>> {
        validate_binding(&binding)?;
        let kernel = NativeKernel::resolve(module, &binding)?;
        let mut carrier = Carrier::new(kernel, binding)?;
        let original = carrier.session_end_read();
        carrier
            .kernel
            .module
            .authority
            .as_mut()
            .retain_original_session(original);
        Ok(carrier)
    }
    impl<'a, A: ModuleRuntimeAuthority> NativeKernel<'a, A> {
        fn resolve(mut module: AuthenticatedModule<'a, A>, binding: &Binding) -> Result<Self> {
            if !cfg!(target_arch = "x86_64") {
                return Err(Error::Unsupported);
            }
            let (pin, functions) = with_call_resources(&mut module, |module| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "C native Resolve authorization",
                );
                module.authority.as_mut().verify(binding, Stage::Resolve)?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "C native Resolve GetModuleHandleExW",
                );
                let mut pin: HMODULE = ptr::null_mut();
                // Adds a module reference without executing another DLL initialization.
                if unsafe {
                    GetModuleHandleExW(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                        module.module.as_ptr().cast(),
                        &mut pin,
                    )
                } == 0
                {
                    return Err(Error::Native);
                }
                if pin != module.module.as_ptr() {
                    if !pin.is_null() {
                        unsafe {
                            FreeLibrary(pin);
                        }
                    }
                    return Err(Error::Conflict);
                }
                let functions =
                    unsafe { Functions::resolve(|name| GetProcAddress(pin, name.as_ptr().cast())) };
                let functions = match functions {
                    Ok(functions) => functions,
                    Err(error) => {
                        unsafe {
                            FreeLibrary(pin);
                        }
                        return Err(error);
                    }
                };
                Ok((pin, functions))
            })?;
            Ok(Self {
                module,
                functions,
                pin: NonNull::new(pin),
                reference: std::rc::Rc::new(ClosedReferenceRelease::new()),
                clock: Instant::now(),
            })
        }
        fn live(&self) -> Result<()> {
            if self.pin.is_none() {
                Err(Error::Retired)
            } else {
                Ok(())
            }
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
            self.verify(binding, Stage::BeforeCreate)?;
            if !matches!(self.driver_version()?, None | Some(14)) {
                return Err(Error::Unsupported);
            }
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
            self.absent(binding)?;
            // An additional actual reference to the SAME acknowledged image
            // stays with this original adapter ACK, including lost publication.
            // Acquired BEFORE final effect authorization; failure creates no NIC.
            let mut raw_pin: HMODULE = ptr::null_mut();
            if unsafe {
                GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    self.module.module.as_ptr().cast(),
                    &mut raw_pin,
                )
            } == 0
            {
                return Err(Error::Native);
            }
            let original_module = ModuleReference(
                NonNull::new(raw_pin).ok_or(Error::Native)?,
                ClosedReferenceRelease::new(),
            );
            if original_module.0 != self.module.module {
                return Err(Error::Conflict);
            }
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
            let name: Vec<u16> = binding.name.encode_utf16().chain(Some(0)).collect();
            let kind: Vec<u16> = binding.tunnel_type.encode_utf16().chain(Some(0)).collect();
            let guid = Guid::new(binding.guid);
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
            let pin = self.pin.ok_or(Error::Retired)?;
            self.reference.run(
                || Ok(()),
                || {
                    if unsafe { FreeLibrary(pin.as_ptr()) } == 0 {
                        return Err(Error::Native);
                    }
                    Ok(())
                },
                || {
                    self.pin = None;
                    Ok(())
                },
            )
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
        self.kernel.verify(&self.binding, stage)?;
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
            return Err(Error::Conflict);
        }
        let by_index = self.kernel.row_index(identity.index)?;
        if self.kernel.identity(&by_index)? != identity || self.kernel.luid(adapter)? != luid {
            return Err(Error::Conflict);
        }
        self.kernel.attest(&self.binding, &identity, stage)?;
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
    /// remain retained for a separately authorized close operation. Scheduling
    /// bounds cannot interrupt the synchronous native call; G supplies that.
    pub(crate) fn end_session_bounded(
        &mut self,
        cancel: &AtomicBool,
        milliseconds: u32,
    ) -> Result<()> {
        with_call_resources(self, |owner| {
            if !(1..=1000).contains(&milliseconds) {
                return Err(Error::Invalid);
            }
            owner.poisoned = true;
            let mut last = owner.kernel.now_ms();
            let deadline = last
                .checked_add(u64::from(milliseconds))
                .ok_or(Error::Invalid)?;
            owner.cleanup_checkpoint(cancel, &mut last, deadline)?;
            owner.end_session_inner(cancel, &mut last, deadline)
        })
    }
    fn end_session_inner(
        &mut self,
        cancel: &AtomicBool,
        last: &mut u64,
        deadline: u64,
    ) -> Result<()> {
        match self.session_end.state.get() {
            SessionEndState::Acknowledged => {
                // The retained VOID return is a historical fact only. An
                // explicit End retry still requires today's exact operation
                // authority and SAME original adapter observation.
                self.kernel.verify(&self.binding, Stage::BeforeEnd)?;
                self.capture_for(Stage::CleanupObserve)?;
                return self.cleanup_checkpoint(cancel, last, deadline);
            }
            SessionEndState::Live => {}
            // No ACK can be inferred from phase or Option<Session>. Unknown
            // native return stays pending even if a caller catches an unwind.
            _ => return Err(Error::Pending),
        }
        self.kernel.verify(&self.binding, Stage::BeforeEnd)?;
        self.capture_for(Stage::CleanupObserve)?;
        self.cleanup_checkpoint(cancel, last, deadline)?;
        self.phase = Phase::Closing;
        self.session_end.state.set(SessionEndState::EndPending);
        self.kernel.end(self.session.take().ok_or(Error::Pending)?);
        // Native EndSession is VOID. Record its actual return before ANY
        // fallible deadline/cancellation/provider postflight can obscure it.
        self.session_end.state.set(SessionEndState::Acknowledged);
        self.cleanup_checkpoint(cancel, last, deadline)?;
        self.capture_for(Stage::CleanupObserve)?;
        self.cleanup_checkpoint(cancel, last, deadline)
    }
    /// Bounds scheduling/waits BETWEEN audited synchronous calls; cannot
    /// interrupt WintunEndSession/CloseAdapter or a blocking attestor call.
    /// The integrating supervisor must supply the hard native-call deadline.
    pub(crate) fn close_bounded(&mut self, cancel: &AtomicBool, milliseconds: u32) -> Result<()> {
        with_call_resources(self, |owner| owner.close_inner(cancel, milliseconds))
    }
    fn close_inner(&mut self, cancel: &AtomicBool, milliseconds: u32) -> Result<()> {
        if self.phase == Phase::Closed {
            return Ok(());
        }
        if !(1..=1000).contains(&milliseconds) {
            return Err(Error::Invalid);
        }
        self.poisoned = true; // Teardown never resumes packet/session progression.
        let mut last = self.kernel.now_ms();
        let deadline = last
            .checked_add(u64::from(milliseconds))
            .ok_or(Error::Invalid)?;
        self.cleanup_checkpoint(cancel, &mut last, deadline)?;
        if self.phase == Phase::Empty {
            self.kernel.verify(&self.binding, Stage::AfterClose)?;
            self.kernel.absent(&self.binding)?;
            self.phase = Phase::ClosePending;
            self.cleanup_checkpoint(cancel, &mut last, deadline)?;
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
                self.end_session_inner(cancel, &mut last, deadline)?;
            }
            self.kernel.verify(&self.binding, Stage::BeforeClose)?;
            self.capture_for(Stage::CleanupObserve)?;
            self.cleanup_checkpoint(cancel, &mut last, deadline)?;
            // Native close is VOID. The original handle is consumed exactly once;
            // failure of later absence checks must NEVER retry a freed handle.
            self.kernel
                .close(self.adapter.take().ok_or(Error::Pending)?);
            self.phase = Phase::ClosePending;
            self.cleanup_checkpoint(cancel, &mut last, deadline)?;
        }
        self.kernel.verify(&self.binding, Stage::AfterClose)?;
        self.kernel.absent(&self.binding)?;
        self.cleanup_checkpoint(cancel, &mut last, deadline)?;
        self.kernel.release_module()?;
        self.phase = Phase::Closed;
        Ok(())
    }
    fn cleanup_checkpoint(&self, cancel: &AtomicBool, last: &mut u64, deadline: u64) -> Result<()> {
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        let now = self.kernel.now_ms();
        if now < *last {
            return Err(Error::Conflict);
        }
        *last = now;
        if now >= deadline {
            Err(Error::Deadline)
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
