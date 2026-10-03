//! Original-handle registry observations are DATA, never disposition authority.
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
};

const NAME_BYTES: usize = 32 * 1024;
const SECURITY_BYTES: usize = 64 * 1024;
const CLASS_UNITS: usize = 1024;
const FULL_SECURITY: u32 = 0x0f; // OWNER | GROUP | DACL | SACL; no reduced retry.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetadataError {
    Pending(i32),
    Invalid,
    Busy,
    Attempted,
    Changed,
}
pub(crate) type Result<T> = std::result::Result<T, MetadataError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyInfo {
    pub class: String,
    pub subkeys: u32,
    pub max_subkey_name: u32,
    pub max_subkey_class: u32,
    pub values: u32,
    pub max_value_name: u32,
    pub max_value_data: u32,
    pub security_bytes: u32,
    pub last_write: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Component {
    pub offset: usize,
    pub length: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Acl {
    Absent,
    Null,
    Present(Component),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SecurityLayout {
    pub revision: u8,
    pub control: u16,
    pub owner: Component,
    pub group: Component,
    pub sacl: Acl,
    pub dacl: Acl,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SecurityMetadata {
    pub raw: Vec<u8>,
    pub layout: SecurityLayout,
    pub native_revision: u32,
    pub native_control: u16,
    pub native_length: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Metadata {
    pub name: String,
    pub info: KeyInfo,
    pub security: SecurityMetadata,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Observation {
    Present(Box<Metadata>),
    KeyDeleted { status: u32 },
}

fn u16_at(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(MetadataError::Invalid)?
            .try_into()
            .map_err(|_| MetadataError::Invalid)?,
    ))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(MetadataError::Invalid)?
            .try_into()
            .map_err(|_| MetadataError::Invalid)?,
    ))
}
fn text(units: &[u16], empty: bool) -> Result<String> {
    if (!empty && units.is_empty()) || units.contains(&0) {
        return Err(MetadataError::Invalid);
    }
    String::from_utf16(units).map_err(|_| MetadataError::Invalid)
}
fn parse_name(bytes: &[u8], returned: usize) -> Result<String> {
    if !(6..=NAME_BYTES).contains(&returned) || returned > bytes.len() {
        return Err(MetadataError::Invalid);
    }
    let n = u32_at(bytes, 0)? as usize;
    if n % 2 != 0 || n.checked_add(4) != Some(returned) {
        return Err(MetadataError::Invalid);
    }
    let units = bytes[4..returned]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    let name = text(&units, false)?;
    if !name
        .get(..10)
        .is_some_and(|s| s.eq_ignore_ascii_case("\\REGISTRY\\"))
    {
        return Err(MetadataError::Invalid);
    }
    Ok(name)
}
fn component(bytes: &[u8], offset: u32, sid: bool) -> Result<Component> {
    let at = offset as usize;
    if at < 20 || at % 4 != 0 || bytes.get(at..at + 8).is_none() {
        return Err(MetadataError::Invalid);
    }
    let length = if sid {
        if bytes[at] != 1 || bytes[at + 1] > 15 {
            return Err(MetadataError::Invalid);
        }
        8 + 4 * bytes[at + 1] as usize
    } else {
        if ![2, 4].contains(&bytes[at]) || bytes[at + 1] != 0 || u16_at(bytes, at + 6)? != 0 {
            return Err(MetadataError::Invalid);
        }
        let length = u16_at(bytes, at + 2)? as usize;
        if length < 8
            || length % 4 != 0
            || at.checked_add(length).is_none_or(|end| end > bytes.len())
        {
            return Err(MetadataError::Invalid);
        }
        let mut cursor = at + 8;
        for _ in 0..u16_at(bytes, at + 4)? {
            if cursor.checked_add(4).is_none_or(|end| end > at + length) {
                return Err(MetadataError::Invalid);
            }
            let size = u16_at(bytes, cursor + 2)? as usize;
            if size < 4
                || size % 4 != 0
                || cursor.checked_add(size).is_none_or(|end| end > at + length)
            {
                return Err(MetadataError::Invalid);
            }
            cursor += size;
        }
        length
    };
    if at.checked_add(length).is_none_or(|end| end > bytes.len()) {
        return Err(MetadataError::Invalid);
    }
    Ok(Component { offset: at, length })
}
fn acl(bytes: &[u8], present: bool, offset: u32) -> Result<Acl> {
    match (present, offset) {
        (false, 0) => Ok(Acl::Absent),
        (true, 0) => Ok(Acl::Null),
        (true, n) => component(bytes, n, false).map(Acl::Present),
        _ => Err(MetadataError::Invalid),
    }
}
fn parse_security(bytes: &[u8]) -> Result<SecurityLayout> {
    if !(20..=SECURITY_BYTES).contains(&bytes.len()) || bytes[0] != 1 {
        return Err(MetadataError::Invalid);
    }
    let control = u16_at(bytes, 2)?;
    if control & 0x8000 == 0 {
        return Err(MetadataError::Invalid);
    } // relative offsets only, never pointers
    let owner = component(bytes, u32_at(bytes, 4)?, true)?;
    let group = component(bytes, u32_at(bytes, 8)?, true)?;
    let sacl = acl(bytes, control & 0x10 != 0, u32_at(bytes, 12)?)?;
    let dacl = acl(bytes, control & 4 != 0, u32_at(bytes, 16)?)?;
    let mut components = vec![owner, group];
    for a in [sacl, dacl] {
        if let Acl::Present(c) = a {
            components.push(c);
        }
    }
    for (i, a) in components.iter().enumerate() {
        for (j, b) in components[..i].iter().enumerate() {
            if a.offset < b.offset + b.length
                && b.offset < a.offset + a.length
                && !(i == 1 && j == 0 && a == b)
            // legitimate shared owner/group SID
            {
                return Err(MetadataError::Invalid);
            }
        }
    }
    if components.iter().map(|c| c.offset + c.length).max() != Some(bytes.len()) {
        return Err(MetadataError::Invalid);
    }
    Ok(SecurityLayout {
        revision: 1,
        control,
        owner,
        group,
        sacl,
        dacl,
    })
}

struct RawInfo {
    status: Option<i32>,
    class: Vec<u16>,
    class_len: u32,
    subkeys: u32,
    max_subkey_name: u32,
    max_subkey_class: u32,
    values: u32,
    max_value_name: u32,
    max_value_data: u32,
    security_bytes: u32,
    last_write: u64,
}
impl RawInfo {
    fn new() -> Self {
        Self {
            status: None,
            class: vec![0; CLASS_UNITS],
            class_len: CLASS_UNITS as u32,
            subkeys: 0,
            max_subkey_name: 0,
            max_subkey_class: 0,
            values: 0,
            max_value_name: 0,
            max_value_data: 0,
            security_bytes: 0,
            last_write: 0,
        }
    }
}
struct RawBuffer {
    status: Option<i32>,
    words: Vec<u32>,
    returned: u32,
}
impl RawBuffer {
    fn new(bytes: usize) -> Self {
        Self {
            status: None,
            words: vec![0; bytes / 4],
            returned: bytes as u32,
        }
    }
    fn bytes(&self) -> &[u8] {
        // Initialized u32 storage is aligned for native structures and all bit
        // patterns are valid bytes. This does not dereference a native pointer.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.words.len() * 4) }
    }
    #[cfg(test)]
    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.words.len() * 4)
        }
    }
}
#[derive(Default)]
struct DescriptorCheck {
    valid: Option<bool>,
    control_ok: Option<bool>,
    control: u16,
    revision: u32,
    length: u32,
    components_valid: Option<bool>,
    error: Option<u32>,
}
struct RawSample {
    info: RawInfo,
    name: RawBuffer,
    security: RawBuffer,
    descriptor: DescriptorCheck,
}
impl RawSample {
    fn new() -> Self {
        Self {
            info: RawInfo::new(),
            name: RawBuffer::new(NAME_BYTES),
            security: RawBuffer::new(SECURITY_BYTES),
            descriptor: DescriptorCheck::default(),
        }
    }
}

/// Retained native outputs including failures, NOT validated metadata/ACKs.
pub(crate) struct Acquired {
    samples: [RawSample; 2],
}
impl Acquired {
    #[cfg(test)]
    pub(crate) fn statuses(&self) -> [[Option<i32>; 3]; 2] {
        self.samples
            .each_ref()
            .map(|s| [s.info.status, s.name.status, s.security.status])
    }
    #[cfg(test)]
    pub(crate) fn security_output(&self, sample: usize) -> Option<(&[u8], u32)> {
        self.samples
            .get(sample)
            .map(|s| (s.security.bytes(), s.security.returned))
    }
}
// External query/validation calls write DIRECTLY into the caller-retained
// capture. No owning IO Result is discarded before fallible comparisons.
trait Queries {
    fn info(&mut self, output: &mut RawInfo);
    fn name(&mut self, output: &mut RawBuffer);
    fn security(&mut self, information: u32, output: &mut RawBuffer);
    fn descriptor(
        &mut self,
        raw: &RawBuffer,
        layout: &SecurityLayout,
        output: &mut DescriptorCheck,
    );
}

/// One physical bounded observation attempt. Rc marker makes this !Send;
/// it owns no HKEY and has no authority/context/import constructor.
pub(crate) struct RegistryMetadataCapture {
    acquired: RefCell<Acquired>,
    observations: RefCell<[Option<Observation>; 2]>,
    busy: Cell<bool>,
    attempted: Cell<bool>,
    failed: Cell<bool>,
    local: PhantomData<Rc<()>>,
}
impl RegistryMetadataCapture {
    /// Completed factual DATA only; not ownership or native-effect permission.
    pub(crate) fn present_data(&self) -> Result<Metadata> {
        self.check()?;
        if !self.attempted.get() || self.busy.get() {
            return Err(MetadataError::Busy);
        }
        let data = self
            .observations
            .try_borrow()
            .map_err(|_| MetadataError::Busy)?;
        match (&data[0], &data[1]) {
            (Some(Observation::Present(first)), Some(Observation::Present(second)))
                if first == second =>
            {
                Ok(first.as_ref().clone())
            }
            _ => Err(MetadataError::Invalid),
        }
    }
    pub(crate) fn new() -> Self {
        Self {
            acquired: RefCell::new(Acquired {
                samples: std::array::from_fn(|_| RawSample::new()),
            }),
            observations: RefCell::new([None, None]),
            busy: Cell::new(false),
            attempted: Cell::new(false),
            failed: Cell::new(false),
            local: PhantomData,
        }
    }
    /// Failure history only. Even raw successful statuses cannot grant root
    /// absence, deletion, close, creation or transaction ownership.
    #[cfg(test)]
    pub(crate) fn inspect_acquired(&self, inspect: impl FnOnce(&Acquired)) -> Result<()> {
        let raw = self
            .acquired
            .try_borrow()
            .map_err(|_| MetadataError::Busy)?;
        inspect(&raw);
        Ok(())
    }
    fn check(&self) -> Result<()> {
        if self.failed.get() {
            Err(MetadataError::Attempted)
        } else {
            Ok(())
        }
    }
    fn sample(&self, io: &mut impl Queries, index: usize) -> Result<Observation> {
        self.check()?;
        let mut acquired = self
            .acquired
            .try_borrow_mut()
            .map_err(|_| MetadataError::Busy)?;
        let s = &mut acquired.samples[index];
        io.info(&mut s.info);
        self.check()?;
        if s.info.status == Some(1018) {
            return Ok(Observation::KeyDeleted { status: 1018 });
        }
        success(s.info.status)?;
        let info = parse_info(&s.info)?;
        io.name(&mut s.name);
        self.check()?;
        success(s.name.status)?;
        let name = parse_name(s.name.bytes(), s.name.returned as usize)?;
        io.security(FULL_SECURITY, &mut s.security);
        self.check()?;
        success(s.security.status)?;
        let n = s.security.returned as usize;
        if !(20..=SECURITY_BYTES).contains(&n) {
            return Err(MetadataError::Invalid);
        }
        let bytes = &s.security.bytes()[..n];
        let layout = parse_security(bytes)?;
        io.descriptor(&s.security, &layout, &mut s.descriptor);
        self.check()?;
        let d = &s.descriptor;
        if d.control_ok != Some(true) {
            return Err(MetadataError::Pending(d.error.map_or(-1, |e| e as i32)));
        }
        if d.valid != Some(true)
            || d.components_valid != Some(true)
            || d.control != layout.control
            || d.revision != layout.revision as u32
            || d.length != s.security.returned
        {
            return Err(MetadataError::Invalid);
        }
        Ok(Observation::Present(Box::new(Metadata {
            name,
            info,
            security: SecurityMetadata {
                raw: s.security.bytes()[..n].to_vec(),
                layout,
                native_revision: d.revision,
                native_control: d.control,
                native_length: d.length,
            },
        })))
    }
    fn read(
        &self,
        io: &mut impl Queries,
        inspect: impl FnOnce(&Observation) -> Result<()>,
    ) -> Result<()> {
        if self.busy.replace(true) {
            self.failed.set(true);
            return Err(MetadataError::Busy);
        }
        let mut flight = ReadFlight {
            capture: self,
            complete: false,
        };
        if self.attempted.replace(true) || self.failed.get() {
            return Err(MetadataError::Attempted);
        }
        let first = self.sample(io, 0)?;
        self.observations
            .try_borrow_mut()
            .map_err(|_| MetadataError::Busy)?[0] = Some(first);
        let observations = self
            .observations
            .try_borrow()
            .map_err(|_| MetadataError::Busy)?;
        inspect(observations[0].as_ref().ok_or(MetadataError::Invalid)?)?;
        drop(observations);
        self.check()?;
        let second = self.sample(io, 1)?;
        let mut observations = self
            .observations
            .try_borrow_mut()
            .map_err(|_| MetadataError::Busy)?;
        observations[1] = Some(second);
        if observations[0] != observations[1] {
            return Err(MetadataError::Changed);
        }
        self.check()?;
        flight.complete = true;
        Ok(())
    }
}
struct ReadFlight<'a> {
    capture: &'a RegistryMetadataCapture,
    complete: bool,
}
impl Drop for ReadFlight<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.capture.failed.set(true);
        }
        self.capture.busy.set(false);
    }
}
fn success(status: Option<i32>) -> Result<()> {
    match status {
        Some(0) => Ok(()),
        Some(e) => Err(MetadataError::Pending(e)),
        None => Err(MetadataError::Pending(-1)),
    }
}
fn parse_info(raw: &RawInfo) -> Result<KeyInfo> {
    let n = raw.class_len as usize;
    if n >= raw.class.len() || raw.class[n] != 0 || raw.security_bytes as usize > SECURITY_BYTES {
        return Err(MetadataError::Invalid);
    }
    Ok(KeyInfo {
        class: text(&raw.class[..n], true)?,
        subkeys: raw.subkeys,
        max_subkey_name: raw.max_subkey_name,
        max_subkey_class: raw.max_subkey_class,
        values: raw.values,
        max_value_name: raw.max_value_name,
        max_value_data: raw.max_value_data,
        security_bytes: raw.security_bytes,
        last_write: raw.last_write,
    })
}

#[cfg(windows)]
mod native {
    use super::*;
    use windows_sys::{
        Wdk::System::Registry::{KeyNameInformation, NtQueryKey},
        Win32::{
            Foundation::{GetLastError, FILETIME},
            Security::{
                GetSecurityDescriptorControl, GetSecurityDescriptorLength, IsValidAcl,
                IsValidSecurityDescriptor, IsValidSid,
            },
            System::Registry::{RegGetKeySecurity, RegQueryInfoKeyW, HKEY},
        },
    };
    struct OriginalQueries {
        handle: HKEY,
    }
    impl Queries for OriginalQueries {
        fn info(&mut self, output: &mut RawInfo) {
            let mut time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            output.status = Some(unsafe {
                RegQueryInfoKeyW(
                    self.handle,
                    output.class.as_mut_ptr(),
                    &mut output.class_len,
                    std::ptr::null_mut(),
                    &mut output.subkeys,
                    &mut output.max_subkey_name,
                    &mut output.max_subkey_class,
                    &mut output.values,
                    &mut output.max_value_name,
                    &mut output.max_value_data,
                    &mut output.security_bytes,
                    &mut time,
                )
            } as i32);
            output.last_write =
                (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        }
        fn name(&mut self, output: &mut RawBuffer) {
            let capacity = output.words.len() * 4;
            output.status = Some(unsafe {
                NtQueryKey(
                    self.handle,
                    KeyNameInformation,
                    output.words.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut output.returned,
                )
            });
        }
        fn security(&mut self, information: u32, output: &mut RawBuffer) {
            output.status = Some(unsafe {
                RegGetKeySecurity(
                    self.handle,
                    information,
                    output.words.as_mut_ptr().cast(),
                    &mut output.returned,
                )
            } as i32);
        }
        fn descriptor(
            &mut self,
            raw: &RawBuffer,
            layout: &SecurityLayout,
            output: &mut DescriptorCheck,
        ) {
            let descriptor = raw.words.as_ptr().cast_mut().cast();
            output.valid = Some(unsafe { IsValidSecurityDescriptor(descriptor) } != 0);
            if output.valid != Some(true) {
                return;
            }
            output.control_ok = Some(
                unsafe {
                    GetSecurityDescriptorControl(
                        descriptor,
                        &mut output.control,
                        &mut output.revision,
                    )
                } != 0,
            );
            if output.control_ok != Some(true) {
                output.error = Some(unsafe { GetLastError() });
                return;
            }
            output.length = unsafe { GetSecurityDescriptorLength(descriptor) };
            let base = raw.words.as_ptr().cast::<u8>();
            // Parser bounds/alignment checks ran first, native descriptor was
            // validated before length/component calls. No unchecked raw offset.
            let sid = |component: Component| unsafe {
                IsValidSid(base.add(component.offset).cast_mut().cast()) != 0
            };
            let acl = |component: &Acl| match component {
                Acl::Absent | Acl::Null => true,
                Acl::Present(component) => unsafe {
                    IsValidAcl(base.add(component.offset).cast()) != 0
                },
            };
            output.components_valid = Some(
                sid(layout.owner) && sid(layout.group) && acl(&layout.sacl) && acl(&layout.dacl),
            );
        }
    }
    impl RegistryMetadataCapture {
        /// # Safety
        /// `original` is a still-open caller-owned HKEY, held for this entire
        /// synchronous read. No handle adoption/reopen/close, privilege change,
        /// size-driven allocation, SACL fallback or mutation is performed.
        pub(in crate::windows) unsafe fn read_original_native(&self, original: HKEY) -> Result<()> {
            if original.is_null() {
                return Err(MetadataError::Invalid);
            }
            self.read(&mut OriginalQueries { handle: original }, |_| Ok(()))
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_registry_metadata_tests.rs"]
mod tests;
#[cfg(test)]
pub(crate) use tests::read_empty_metadata_for_key;
