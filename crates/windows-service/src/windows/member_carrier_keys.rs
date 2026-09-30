//! Exact retained-key IO for precreation receipts. Factory remains disconnected.
//! Native effect tests replace only RegistryKernel, never this identity/CAS logic.
#![allow(dead_code)]
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{
    self as receipt, Binding, Context, KeyPhase, KeyPresence, NativeFacts, NativeKeyIo,
    NativeValue, NewKeyAck, Phase, Record, Value, ValueCas,
};

const PARENT: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const VALUE: &str = "IPAutoconfigurationEnabled";
const MAX_NAME: usize = 2048;
pub(crate) fn decode_value(kind: u32, bytes: &[u8]) -> Result<NativeValue> {
    if bytes.len() > 256 {
        return Err(Error::Invalid);
    }
    if kind == 4 && bytes.len() == 4 {
        Ok(NativeValue::Dword(u32::from_le_bytes(
            bytes.try_into().map_err(|_| Error::Invalid)?,
        )))
    } else {
        Ok(NativeValue::Other {
            kind,
            bytes: bytes.to_vec(),
        })
    }
}

/// Must perform independent actual runtime/boot/epoch and owning-lock checks.
/// No production implementation, successful defaults or journal-seeded proof.
pub(crate) trait NativeAuthority {
    type Lock;
    fn verify(&mut self, lock: &mut Self::Lock, context: &Context) -> Result<()>;
    /// Separate native-effect authorization from read-only context/lock checks.
    /// Must re-read the protected pending record and actual fresh/cleanup claim.
    fn authorize_effect(
        &mut self,
        lock: &mut Self::Lock,
        pending: &Record,
        binding: &Binding,
        effect: Effect,
    ) -> Result<()>;
    fn nic_absence(
        &mut self,
        lock: &mut Self::Lock,
        context: &Context,
        binding: &Binding,
    ) -> Result<(bool, bool, bool)>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    Create,
    Value(ValueCas),
}

/// The storage snapshot is independently authenticated by SessionFiles, not
/// supplied by the caller. This pure policy does not attest native ownership.
pub(crate) fn effect_matches_storage(
    pending: &Record,
    binding: &Binding,
    effect: Effect,
    actual: &Record,
    fresh: bool,
) -> Result<()> {
    receipt::validate_record(pending)?;
    if actual != pending {
        return Err(Error::Conflict);
    }
    let index = pending
        .context
        .bindings
        .iter()
        .position(|b| b == binding)
        .ok_or(Error::Conflict)?;
    let key = &pending.keys[index];
    let allowed = match effect {
        Effect::Create => {
            fresh
                && pending.phase == Phase::Preparing
                && key.phase == KeyPhase::CreatePending
                && !key.new_key_ack
                && key.baseline == Value::Absent
                && key.current == Value::Absent
                && key.pending.is_none()
        }
        Effect::Value(value) => {
            value.value_name == VALUE
                && key.new_key_ack
                && key.current == value.expected
                && key.pending == Some(value.desired)
                && (matches!(
                    (pending.phase, key.phase, value.expected, value.desired),
                    (
                        Phase::Closing,
                        KeyPhase::RestorePending,
                        Value::DwordZero,
                        Value::Absent
                    )
                ) || fresh
                    && matches!(
                        (pending.phase, key.phase, value.expected, value.desired),
                        (
                            Phase::Preparing,
                            KeyPhase::DisablePending,
                            Value::Absent,
                            Value::DwordZero
                        )
                    ))
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
pub(crate) trait RegistryKernel {
    type Handle;
    fn interfaces(&mut self) -> Result<Self::Handle>;
    fn name(&mut self, handle: &Self::Handle) -> Result<String>;
    fn open(&mut self, parent: &Self::Handle, child: &str) -> Result<Option<Self::Handle>>;
    fn create(&mut self, parent: &Self::Handle, child: &str) -> Result<(Self::Handle, u32)>;
    fn value(&mut self, handle: &Self::Handle) -> Result<NativeValue>;
    fn zero(&mut self, handle: &Self::Handle) -> Result<()>;
    fn delete_value(&mut self, handle: &Self::Handle) -> Result<()>;
    fn flush(&mut self, handle: &Self::Handle) -> Result<()>;
}
/// Actual owning create ACK handle, not Clone, serde or a numeric journal key.
pub(crate) struct Held<H> {
    handle: H,
    parent: String,
    child: String,
    context: Context,
    binding: Binding,
}
pub(crate) struct Keys<K: RegistryKernel, A: NativeAuthority> {
    kernel: K,
    authority: A,
    context: Context,
    poisoned: bool,
}
pub(crate) fn decode_name(bytes: &[u8], returned: usize) -> Result<String> {
    if !(6..=MAX_NAME).contains(&returned) || returned > bytes.len() {
        return Err(Error::Invalid);
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::Invalid)?) as usize;
    if n == 0 || n % 2 != 0 || n.checked_add(4) != Some(returned) {
        return Err(Error::Invalid);
    }
    let chars: Vec<u16> = bytes[4..returned]
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let name = String::from_utf16(&chars).map_err(|_| Error::Invalid)?;
    if name.chars().any(|c| c.is_control()) {
        return Err(Error::Invalid);
    }
    Ok(name)
}
pub(crate) fn parent_valid(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let parts: Vec<_> = lower.split('\\').collect();
    parts.len() == 9
        && parts[..4] == ["", "registry", "machine", "system"]
        && parts[4].len() == 13
        && parts[4].starts_with("controlset")
        && parts[4][10..].bytes().all(|b| b.is_ascii_digit())
        && &parts[4][10..] != "000"
        && parts[5..] == ["services", "tcpip", "parameters", "interfaces"]
}
impl<K: RegistryKernel, A: NativeAuthority> Keys<K, A> {
    pub(crate) fn new(kernel: K, authority: A, context: Context) -> Self {
        Self {
            kernel,
            authority,
            context,
            poisoned: false,
        }
    }
    fn binding<'a>(&self, record: &'a Record, binding: &Binding) -> Result<&'a Binding> {
        receipt::validate_record(record)?;
        if record.context != self.context {
            return Err(Error::Conflict);
        }
        record
            .context
            .bindings
            .iter()
            .find(|b| *b == binding)
            .ok_or(Error::Conflict)
    }
    fn parent(&mut self) -> Result<(K::Handle, String)> {
        let handle = self.kernel.interfaces()?;
        let name = self.kernel.name(&handle)?;
        if !parent_valid(&name) {
            return Err(Error::Conflict);
        }
        Ok((handle, name))
    }
    fn child(binding: &Binding) -> Result<&str> {
        binding
            .registry_path
            .strip_prefix(PARENT)
            .and_then(|s| s.strip_prefix('\\'))
            .filter(|s| s.len() == 38 && !s.contains('\\'))
            .ok_or(Error::Invalid)
    }
    fn observed(
        &mut self,
        lock: &mut A::Lock,
        record: &Record,
        binding: &Binding,
        retained: Option<&NewKeyAck<Held<K::Handle>>>,
        challenge: u64,
    ) -> Result<NativeFacts> {
        if self.poisoned {
            return Err(Error::Pending);
        }
        self.observed_inner(lock, record, binding, retained, challenge)
    }
    fn observed_inner(
        &mut self,
        lock: &mut A::Lock,
        record: &Record,
        binding: &Binding,
        retained: Option<&NewKeyAck<Held<K::Handle>>>,
        challenge: u64,
    ) -> Result<NativeFacts> {
        self.assert_serialized_lock(lock, &record.context)?;
        self.binding(record, binding)?;
        if challenge == 0 {
            return Err(Error::Pending);
        }
        let (parent, parent_name) = self.parent()?;
        let child = Self::child(binding)?;
        let expected = format!("{parent_name}\\{child}");
        let opened = self.kernel.open(&parent, child)?;
        let (key, value) = match (opened, retained) {
            (None, None) => (KeyPresence::Absent, NativeValue::Absent),
            (None, Some(_)) => return Err(Error::Conflict),
            (Some(opened), None) => {
                if !self.kernel.name(&opened)?.eq_ignore_ascii_case(&expected) {
                    return Err(Error::Conflict);
                }
                (KeyPresence::Foreign, self.kernel.value(&opened)?)
            }
            (Some(opened), Some(ack)) => {
                let held = ack.retained_handle();
                if held.context != self.context
                    || held.binding != *binding
                    || held.child != child
                    || !held.parent.eq_ignore_ascii_case(&parent_name)
                    || !self
                        .kernel
                        .name(&held.handle)?
                        .eq_ignore_ascii_case(&expected)
                    || !self.kernel.name(&opened)?.eq_ignore_ascii_case(&expected)
                {
                    return Err(Error::Conflict);
                }
                let value = self.kernel.value(&held.handle)?;
                if value != self.kernel.value(&opened)?
                    || !self
                        .kernel
                        .name(&held.handle)?
                        .eq_ignore_ascii_case(&expected)
                    || !self
                        .kernel
                        .name(&parent)?
                        .eq_ignore_ascii_case(&parent_name)
                {
                    return Err(Error::Conflict);
                }
                (KeyPresence::ExactRetainedNewKey, value)
            }
        };
        let (name_absent, guid_absent, retained_nic_absent) =
            self.authority.nic_absence(lock, &self.context, binding)?;
        self.assert_serialized_lock(lock, &record.context)?;
        Ok(NativeFacts {
            context: self.context.clone(),
            binding: binding.clone(),
            generation: record.generation,
            challenge,
            key,
            value,
            name_absent,
            guid_absent,
            retained_nic_absent,
        })
    }
    fn check_fact(record: &Record, binding: &Binding, f: &NativeFacts) -> Result<()> {
        if f.context != record.context
            || f.binding != *binding
            || f.generation != record.generation
            || f.challenge == 0
            || !f.name_absent
            || !f.guid_absent
            || !f.retained_nic_absent
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn key_phase<'a>(record: &'a Record, binding: &Binding) -> Result<&'a receipt::KeyReceipt> {
        record
            .keys
            .iter()
            .find(|k| k.role == binding.role)
            .ok_or(Error::Invalid)
    }
}
impl<K: RegistryKernel, A: NativeAuthority> NativeKeyIo for Keys<K, A> {
    type Key = Held<K::Handle>;
    type MutationLock = A::Lock;
    fn assert_serialized_lock(&mut self, lock: &mut A::Lock, context: &Context) -> Result<()> {
        if context != &self.context {
            return Err(Error::Conflict);
        }
        self.authority.verify(lock, context)
    }
    fn inspect(
        &mut self,
        lock: &mut A::Lock,
        record: &Record,
        binding: &Binding,
        retained: Option<&NewKeyAck<Self::Key>>,
        challenge: u64,
    ) -> Result<NativeFacts> {
        self.observed(lock, record, binding, retained, challenge)
    }
    fn create_new_key(
        &mut self,
        lock: &mut A::Lock,
        pending: &Record,
        binding: &Binding,
        absent: &NativeFacts,
    ) -> Result<NewKeyAck<Self::Key>> {
        Self::check_fact(pending, binding, absent)?;
        self.binding(pending, binding)?;
        if pending.phase != Phase::Preparing
            || Self::key_phase(pending, binding)?.phase != KeyPhase::CreatePending
            || absent.key != KeyPresence::Absent
            || absent.value != NativeValue::Absent
        {
            return Err(Error::Conflict);
        }
        let fresh = self.observed(lock, pending, binding, None, absent.challenge)?;
        Self::check_fact(pending, binding, &fresh)?;
        if fresh.key != KeyPresence::Absent || fresh.value != NativeValue::Absent {
            return Err(Error::Conflict);
        }
        let (parent, parent_name) = self.parent()?;
        let child = Self::child(binding)?.to_owned();
        self.assert_serialized_lock(lock, &pending.context)?;
        self.authority
            .authorize_effect(lock, pending, binding, Effect::Create)?;
        self.poisoned = true;
        let (handle, disposition) = self
            .kernel
            .create(&parent, &child)
            .inspect_err(|_| self.poisoned = true)?;
        if disposition != 1 {
            self.poisoned = true;
            return Err(Error::Pending);
        }
        let held = Held {
            handle,
            parent: parent_name,
            child,
            context: self.context.clone(),
            binding: binding.clone(),
        };
        let ack = NewKeyAck::from_native_created_new_key(disposition, held)?;
        self.kernel
            .flush(&parent)
            .inspect_err(|_| self.poisoned = true)?;
        let read = self
            .observed_inner(lock, pending, binding, Some(&ack), absent.challenge)
            .inspect_err(|_| self.poisoned = true)?;
        Self::check_fact(pending, binding, &read)?;
        if read.key != KeyPresence::ExactRetainedNewKey || read.value != NativeValue::Absent {
            self.poisoned = true;
            return Err(Error::Conflict);
        }
        self.poisoned = false;
        Ok(ack)
    }
    fn compare_exchange_value(
        &mut self,
        lock: &mut A::Lock,
        pending: &Record,
        binding: &Binding,
        retained: &NewKeyAck<Self::Key>,
        fresh: &NativeFacts,
        mutation: ValueCas,
    ) -> Result<()> {
        self.binding(pending, binding)?;
        Self::check_fact(pending, binding, fresh)?;
        let key = Self::key_phase(pending, binding)?;
        if mutation.value_name != VALUE
            || !key.new_key_ack
            || key.current != mutation.expected
            || key.pending != Some(mutation.desired)
            || !matches!(
                (
                    pending.phase,
                    key.phase,
                    mutation.expected,
                    mutation.desired
                ),
                (
                    Phase::Preparing,
                    KeyPhase::DisablePending,
                    Value::Absent,
                    Value::DwordZero
                ) | (
                    Phase::Closing,
                    KeyPhase::RestorePending,
                    Value::DwordZero,
                    Value::Absent
                )
            )
        {
            return Err(Error::Invalid);
        }
        let expected = match mutation.expected {
            Value::Absent => NativeValue::Absent,
            Value::DwordZero => NativeValue::Dword(0),
        };
        let desired = match mutation.desired {
            Value::Absent => NativeValue::Absent,
            Value::DwordZero => NativeValue::Dword(0),
        };
        if fresh.key != KeyPresence::ExactRetainedNewKey || fresh.value != expected {
            return Err(Error::Conflict);
        }
        let current = self.observed(lock, pending, binding, Some(retained), fresh.challenge)?;
        Self::check_fact(pending, binding, &current)?;
        if current.key != KeyPresence::ExactRetainedNewKey || current.value != expected {
            return Err(Error::Conflict);
        }
        self.assert_serialized_lock(lock, &pending.context)?;
        self.authority
            .authorize_effect(lock, pending, binding, Effect::Value(mutation))?;
        // Windows offers no registry value CAS. Serialization is independently
        // mandatory; only our captured handle is written, never an opened path.
        self.poisoned = true;
        let h = &retained.retained_handle().handle;
        match mutation.desired {
            Value::DwordZero => self.kernel.zero(h)?,
            Value::Absent => self.kernel.delete_value(h)?,
        }
        self.kernel.flush(h)?;
        let after = self
            .observed_inner(lock, pending, binding, Some(retained), fresh.challenge)
            .inspect_err(|_| self.poisoned = true)?;
        Self::check_fact(pending, binding, &after).inspect_err(|_| self.poisoned = true)?;
        if after.key != KeyPresence::ExactRetainedNewKey || after.value != desired {
            self.poisoned = true;
            return Err(Error::Conflict);
        }
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(all(test, windows))]
#[path = "member_carrier_keys_tests.rs"]
mod tests;

/// Audited SDK boundary, not a custom FFI or numeric/path ownership surrogate.
#[cfg(windows)]
pub(crate) mod win32 {
    use super::*;
    use std::ptr;
    use windows_sys::{
        Wdk::System::Registry::{KeyNameInformation, NtQueryKey},
        Win32::{
            Foundation::{ERROR_FILE_NOT_FOUND, NO_ERROR},
            System::Registry::*,
        },
    };
    pub(crate) struct Handle(HKEY);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    RegCloseKey(self.0);
                }
            }
        }
    }
    pub(crate) struct Kernel;
    fn wide(s: &str) -> Result<Vec<u16>> {
        if s.is_empty() || s.len() > 1024 || s.chars().any(|c| c.is_control()) {
            return Err(Error::Invalid);
        }
        Ok(s.encode_utf16().chain(Some(0)).collect())
    }
    fn status(rc: u32) -> Result<()> {
        if rc == NO_ERROR {
            Ok(())
        } else {
            Err(Error::Pending)
        }
    }
    fn owned(rc: u32, handle: HKEY) -> Result<Handle> {
        let h = Handle(handle);
        status(rc)?;
        if h.0.is_null() {
            return Err(Error::Pending);
        }
        Ok(h)
    }
    impl RegistryKernel for Kernel {
        type Handle = Handle;
        fn interfaces(&mut self) -> Result<Handle> {
            let p = wide(PARENT)?;
            let mut h = ptr::null_mut();
            owned(
                unsafe {
                    RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        p.as_ptr(),
                        0,
                        KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY,
                        &mut h,
                    )
                },
                h,
            )
        }
        fn name(&mut self, h: &Handle) -> Result<String> {
            // Fixed aligned buffer, never use attacker-controlled required size
            // to allocate. Native result excludes a terminating WCHAR.
            let mut buffer = [0u32; MAX_NAME / 4];
            let mut n = 0u32;
            let rc = unsafe {
                NtQueryKey(
                    h.0,
                    KeyNameInformation,
                    buffer.as_mut_ptr().cast(),
                    MAX_NAME as u32,
                    &mut n,
                )
            };
            if rc != 0 {
                return Err(Error::Conflict);
            }
            let bytes =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), MAX_NAME) };
            decode_name(bytes, n as usize)
        }
        fn open(&mut self, parent: &Handle, child: &str) -> Result<Option<Handle>> {
            let child = wide(child)?;
            let mut h = ptr::null_mut();
            let rc = unsafe {
                RegOpenKeyExW(
                    parent.0,
                    child.as_ptr(),
                    REG_OPTION_OPEN_LINK,
                    KEY_QUERY_VALUE,
                    &mut h,
                )
            };
            if rc == ERROR_FILE_NOT_FOUND {
                let _h = Handle(h);
                return Ok(None);
            }
            owned(rc, h).map(Some)
        }
        fn create(&mut self, parent: &Handle, child: &str) -> Result<(Handle, u32)> {
            let child = wide(child)?;
            let mut h = ptr::null_mut();
            let mut disposition = 0;
            let rc = unsafe {
                RegCreateKeyExW(
                    parent.0,
                    child.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    ptr::null(),
                    &mut h,
                    &mut disposition,
                )
            };
            Ok((owned(rc, h)?, disposition))
        }
        fn value(&mut self, h: &Handle) -> Result<NativeValue> {
            let name = wide(VALUE)?;
            let mut data = [0u8; 256];
            let mut len = data.len() as u32;
            let mut kind = 0;
            let rc = unsafe {
                RegQueryValueExW(
                    h.0,
                    name.as_ptr(),
                    ptr::null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut len,
                )
            };
            if rc == ERROR_FILE_NOT_FOUND {
                return Ok(NativeValue::Absent);
            }
            status(rc)?;
            if len as usize > data.len() {
                return Err(Error::Invalid);
            }
            decode_value(kind, &data[..len as usize])
        }
        fn zero(&mut self, h: &Handle) -> Result<()> {
            let name = wide(VALUE)?;
            let bytes = 0u32.to_le_bytes();
            status(unsafe { RegSetValueExW(h.0, name.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4) })
        }
        fn delete_value(&mut self, h: &Handle) -> Result<()> {
            let name = wide(VALUE)?;
            status(unsafe { RegDeleteValueW(h.0, name.as_ptr()) })
        }
        fn flush(&mut self, h: &Handle) -> Result<()> {
            status(unsafe { RegFlushKey(h.0) })
        }
    }
}
