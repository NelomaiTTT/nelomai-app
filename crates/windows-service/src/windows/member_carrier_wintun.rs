//! Retained original-creator Wintun substrate. Factory deliberately disconnected.
#![allow(dead_code)]
use std::ffi::{c_void, CStr};
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// implementations. The borrowed capability must keep the authenticated DLL
    /// and source/runtime pins held for this entire borrow, including failures.
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
        fn provider(&mut self, binding: &Binding, identity: &Identity) -> Result<()>;
    }
    /// Opaque borrowed authenticated module/runtime/lock capability. No Clone,
    /// serde, path-based loader or successful production default constructor.
    pub(crate) struct AuthenticatedModule<'a, A: ModuleRuntimeAuthority> {
        module: NonNull<c_void>,
        authority: &'a mut A,
    }
    impl<'a, A: ModuleRuntimeAuthority> AuthenticatedModule<'a, A> {
        /// # Safety
        /// module is the actual pinned HMODULE loaded ONLY after Authority's
        /// pre-initialization checks; the authenticated payload is audited0.14.1
        /// x64, not a caller path/number. authority holds the REAL source pins,
        /// module owner and runtime/mutation lock. They outlive this borrow.
        pub(crate) unsafe fn borrow(module: NonNull<c_void>, authority: &'a mut A) -> Self {
            Self { module, authority }
        }
    }
    pub(crate) struct Adapter(NonNull<c_void>);
    pub(crate) struct Session(NonNull<c_void>);
    pub(crate) struct Packet(NonNull<u8>);
    pub(crate) struct NativeKernel<'a, A: ModuleRuntimeAuthority> {
        module: AuthenticatedModule<'a, A>,
        functions: Functions,
        pin: Option<NonNull<c_void>>,
        clock: Instant,
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
        Carrier::new(kernel, binding)
    }
    impl<'a, A: ModuleRuntimeAuthority> NativeKernel<'a, A> {
        fn resolve(module: AuthenticatedModule<'a, A>, binding: &Binding) -> Result<Self> {
            if !cfg!(target_arch = "x86_64") {
                return Err(Error::Unsupported);
            }
            module.authority.verify(binding, Stage::Resolve)?;
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
            Ok(Self {
                module,
                functions,
                pin: NonNull::new(pin),
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
            self.module.authority.verify(binding, stage)
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
            // LAST native attestation before create, still borrowing the ACTUAL
            // captured token and mutation lock from before_adapter_create.
            self.module.authority.authorize_create(
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
            NonNull::new(raw).map(Adapter).ok_or(Error::Native)
        }
        fn luid(&mut self, adapter: &Adapter) -> Result<u64> {
            self.live()?;
            let mut native_luid = NET_LUID_LH { Value: 0 };
            unsafe { (self.functions.luid)(adapter.0.as_ptr(), &mut native_luid) };
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
        fn attest(&mut self, binding: &Binding, identity: &Identity) -> Result<()> {
            self.module.authority.provider(binding, identity)
        }
        fn start(&mut self, adapter: &Adapter, capacity: u32) -> Result<Session> {
            self.live()?;
            if capacity != 0x20000 {
                return Err(Error::Unsupported);
            }
            NonNull::new(unsafe { (self.functions.start)(adapter.0.as_ptr(), capacity) })
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
            unsafe { (self.functions.close)(adapter.0.as_ptr()) };
        }
        fn release_module(&mut self) -> Result<()> {
            let pin = self.pin.ok_or(Error::Retired)?;
            if unsafe { FreeLibrary(pin.as_ptr()) } == 0 {
                return Err(Error::Native);
            }
            self.pin = None;
            Ok(())
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
    fn attest(&mut self, binding: &Binding, identity: &Identity) -> Result<()>;
    fn start(&mut self, adapter: &Self::Adapter, capacity: u32) -> Result<Self::Session>;
    fn receive(&mut self, session: &Self::Session) -> Result<Receive<Self::Packet>>;
    fn release(&mut self, session: &Self::Session, packet: Self::Packet);
    fn wait(&mut self, session: &Self::Session, milliseconds: u32) -> Result<()>;
    fn now_ms(&self) -> u64;
    fn end(&mut self, session: Self::Session);
    fn close(&mut self, adapter: Self::Adapter);
    fn release_module(&mut self) -> Result<()>;
}

/// No Clone/serde/recovery-by-name. Errors return with this same object holding
/// its original capabilities. The owner must retain it until explicit cleanup.
pub(crate) struct Carrier<K: Kernel> {
    kernel: K,
    binding: Binding,
    phase: Phase,
    adapter: Option<K::Adapter>,
    session: Option<K::Session>,
    original: Option<Identity>,
    captured: Option<K::Row>,
    observed: Option<K::Row>,
    poisoned: bool,
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
        self.kernel.verify(&self.binding, Stage::Observe)?;
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
            || identity.description != format!("{} Tunnel", self.binding.tunnel_type)
            || self.original.as_ref().is_some_and(|old| *old != identity)
        {
            return Err(Error::Conflict);
        }
        let by_index = self.kernel.row_index(identity.index)?;
        if self.kernel.identity(&by_index)? != identity || self.kernel.luid(adapter)? != luid {
            return Err(Error::Conflict);
        }
        self.kernel.attest(&self.binding, &identity)?;
        if self.original.is_none() {
            self.original = Some(identity);
            self.captured = Some(row);
        }
        self.observed = Some(by_index);
        Ok(())
    }
    pub(crate) fn start(&mut self) -> Result<()> {
        if self.phase != Phase::Created || self.poisoned {
            return Err(Error::Pending);
        }
        self.kernel.verify(&self.binding, Stage::BeforeSession)?;
        self.capture()?;
        self.poisoned = true;
        self.session = Some(
            self.kernel
                .start(self.adapter.as_ref().ok_or(Error::Pending)?, 0x20000)?,
        );
        self.phase = Phase::Session;
        self.capture()?;
        self.poisoned = false;
        Ok(())
    }
    pub(crate) fn reattest(&mut self) -> Result<&K::Row> {
        if matches!(
            self.phase,
            Phase::Empty | Phase::Closed | Phase::ClosePending
        ) {
            return Err(Error::Retired);
        }
        self.capture()?;
        self.observed.as_ref().ok_or(Error::Pending)
    }
    pub(crate) fn drain(
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
    /// Bounds scheduling/waits BETWEEN audited synchronous calls; cannot
    /// interrupt WintunEndSession/CloseAdapter or a blocking attestor call.
    /// The integrating supervisor must supply the hard native-call deadline.
    pub(crate) fn close_bounded(&mut self, cancel: &AtomicBool, milliseconds: u32) -> Result<()> {
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
            self.capture()?;
            self.phase = Phase::Closing;
            self.poisoned = true;
            if self.session.is_some() {
                self.kernel.verify(&self.binding, Stage::BeforeEnd)?;
                self.capture()?;
                self.cleanup_checkpoint(cancel, &mut last, deadline)?;
                self.kernel.end(self.session.take().ok_or(Error::Pending)?);
                self.cleanup_checkpoint(cancel, &mut last, deadline)?;
                self.capture()?;
            }
            self.kernel.verify(&self.binding, Stage::BeforeClose)?;
            self.capture()?;
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
