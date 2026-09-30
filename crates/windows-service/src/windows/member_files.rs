//! Private native files. Pure security/decoder policy is tested on the
//! host; Windows IO is compiled only, never invoked by tests.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.

use crate::member_owner::{OwnerError, Phase, Record, Result};
use nelomai_contracts::dispatcher::TunnelSlot;
use sha2::{Digest, Sha256};
use std::io::Read;
use zeroize::Zeroizing;

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const ALL_ACCESS: u32 = 0x1f01ff;
const PROTECTED: u16 = 0x1000;
const MAX_JOURNAL: usize = 64 * 1024;
const DIRECTORY_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// No caller-supplied path or basename crosses the private-file boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum PrivateFile {
    Index,
    Session,
    Pair,
    Network,
    Carrier,
    NativeCarrierReceipts,
    CarrierRows,
    MemberARows,
    MemberBRows,
    /// SHA256 of the canonical SessionScope, computed by the trusted adapter.
    /// Never accepts a path component or text from IPC.
    Completed([u8; 32]),
}
impl PrivateFile {
    pub(crate) fn name(self) -> String {
        match self {
            Self::Index => "nelomai-redundant-index.json".into(),
            Self::Session => "nelomai-redundant-session.json".into(),
            Self::Pair => "nelomai-redundant-pair.json".into(),
            Self::Network => "nelomai-redundant-network.json".into(),
            Self::Carrier => "nelomai-redundant-carrier.json".into(),
            Self::NativeCarrierReceipts => "nelomai-redundant-native-carrier-receipts.json".into(),
            Self::CarrierRows => "nelomai-redundant-carrier-rows.json".into(),
            Self::MemberARows => "nelomai-redundant-member-a-rows.json".into(),
            Self::MemberBRows => "nelomai-redundant-member-b-rows.json".into(),
            Self::Completed(hash) => format!(
                "nelomai-redundant-completed-{}.json",
                hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
        }
    }
    pub(crate) fn limit(self) -> usize {
        match self {
            Self::Index => 8192,
            Self::Completed(_) => 4096,
            Self::Carrier
            | Self::NativeCarrierReceipts
            | Self::CarrierRows
            | Self::MemberARows
            | Self::MemberBRows => 64 * 1024,
            _ => 32 * 1024 * 1024 + 8192,
        }
    }
}
pub(crate) trait PrivateRecords {
    fn read(&mut self, file: PrivateFile) -> std::io::Result<Option<Vec<u8>>>;
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> std::io::Result<()>;
}
/// Hold the same exclusive lifecycle file lock over index + record operations.
pub(crate) trait SessionFileIo {
    fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut dyn PrivateRecords) -> std::io::Result<T>,
    ) -> std::io::Result<T>;
}
fn private_replace_allowed(
    file: PrivateFile,
    current: Option<&[u8]>,
    expected: Option<&[u8]>,
    desired: &[u8],
) -> bool {
    desired.len() <= file.limit()
        && current.is_none_or(|b| b.len() <= file.limit())
        && current == expected
        && (!matches!(file, PrivateFile::Completed(_)) || current.is_none_or(|b| b == desired))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Ace {
    kind: u8,
    flags: u8,
    mask: u32,
    sid: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Acl {
    owner: String,
    control: u16,
    aces: Vec<Ace>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protection {
    Ancestor,
    Directory,
    File,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Facts {
    attributes: u32,
    links: u32,
    size: u64,
}

fn privileged(sid: &str) -> bool {
    matches!(sid, SYSTEM | ADMINISTRATORS | TRUSTED_INSTALLER)
}

// Existing ancestors may grant create-child, write-EA and write-attributes
// (ProgramData's Users 0x116). They cannot grant deletion/replacement or ACL/
// owner changes. ready() pins the complete non-reparse chain without delete
// sharing before private IO; every ancestor then retains an undeletable child
// and cannot become an empty directory junction. Missing children require the
// stricter creation gate below. Owned directories/files remain SYSTEM/Admin only.
fn ancestor_ace_allowed(ace: &Ace) -> bool {
    matches!(ace.kind, 0 | 1)
        && (ace.flags & 8 != 0
            || ace.kind == 1
            || privileged(&ace.sid)
            || ace.mask & 0xf00d_0040 == 0)
}
fn acl_allowed(acl: &Acl, protection: Protection) -> bool {
    if protection == Protection::Ancestor {
        return privileged(&acl.owner) && acl.aces.iter().all(ancestor_ace_allowed);
    }
    matches!(acl.owner.as_str(), SYSTEM | ADMINISTRATORS)
        && acl.control & PROTECTED != 0
        && acl.aces.len() == 2
        && [SYSTEM, ADMINISTRATORS].iter().all(|sid| {
            acl.aces
                .iter()
                .filter(|ace| {
                    ace.sid == *sid
                        && ace.kind == 0
                        && ace.mask == ALL_ACCESS
                        && ace.flags
                            == if protection == Protection::Directory {
                                3
                            } else {
                                0
                            }
                })
                .count()
                == 1
        })
}
fn recovery_marker_acl_allowed(acl: &Acl) -> bool {
    // The dispatcher writes this non-secret identity file under a pinned
    // protected root using ordinary inherited ACLs. Normalize inheritance only
    // for this marker; durable member secrets retain the stricter File policy.
    let mut explicit = acl.clone();
    explicit.control |= PROTECTED;
    for ace in &mut explicit.aces {
        ace.flags &= !0x10;
    }
    acl_allowed(&explicit, Protection::File)
}
fn ancestor_creation_allowed(acl: &Acl) -> bool {
    acl_allowed(acl, Protection::Ancestor)
        && acl.aces.iter().all(|ace| {
            ace.flags & 8 != 0 || ace.kind == 1 || privileged(&ace.sid) || ace.mask & 0x102 == 0
        })
}

// install::install creates Tunnel and applies its protected SYSTEM/Admin DACL
// before starting the manager. Runtime opens that existing subtree even when
// ProgramData/Nelomai grant Users 0x116. A missing child of an exposed parent
// needs installer repair; runtime must not race a reparse conversion on an
// empty parent. Keep this decision shared with portable tests of the IO boundary.
fn open_directory_or_create_owned<T>(
    depth: usize,
    parent: Option<&Acl>,
    mut open: impl FnMut() -> std::result::Result<T, u32>,
    create: impl FnOnce() -> Result<bool>,
) -> Result<(T, bool)> {
    match open() {
        Ok(file) => Ok((file, false)),
        Err(2) if depth <= 1 => {
            // ERROR_FILE_NOT_FOUND
            if !parent.is_some_and(ancestor_creation_allowed) {
                return Err(OwnerError::Conflict);
            }
            let created = create()?;
            Ok((open().map_err(|_| OwnerError::Native)?, created))
        }
        Err(_) => Err(OwnerError::Native),
    }
}
fn local_drive_path(text: &str) -> bool {
    if text.encode_utf16().count() > 32760 {
        return false;
    }
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let bytes = text.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
        return false;
    }
    if bytes.len() == 3 {
        return true;
    }
    text[3..].split('\\').all(|part| {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        !part.is_empty()
            && !part.ends_with(['.', ' '])
            && !part
                .chars()
                .any(|c| c.is_control() || "<>:\"/|?*".contains(c))
            && !matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            && !["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|s| {
                    matches!(
                        s,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            })
    })
}
fn facts_allowed(facts: Facts, directory: bool, limit: usize) -> bool {
    facts.attributes & 0x400 == 0
        && (facts.attributes & 0x10 != 0) == directory
        && facts.links == 1
        && (directory || facts.size <= limit as u64)
}
fn bounded_read(reader: impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((limit as u64).checked_add(1).ok_or(OwnerError::Invalid)?)
        .read_to_end(&mut bytes)
        .map_err(|_| OwnerError::Native)?;
    if bytes.len() > limit {
        return Err(OwnerError::Invalid);
    }
    Ok(bytes)
}
fn decode_journal(slot: TunnelSlot, bytes: &[u8]) -> Result<Record> {
    if bytes.len() > MAX_JOURNAL {
        return Err(OwnerError::Journal);
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| OwnerError::Journal)?;
    if record.intent.slot != slot
        || !record.intent.scope.validate()
        || !record.intent.engine.to_str().is_some_and(local_drive_path)
        || (record.phase == Phase::Running && record.proof.is_none())
        || (matches!(record.phase, Phase::Prepared | Phase::Stopped) && record.proof.is_some())
        || !previous_config_valid(&record)
        || record
            .proof
            .iter()
            .chain(record.retired_proof.iter())
            .any(|p| {
                p.process.pid == 0
                    || p.process.creation_time == 0
                    || p.interface.index == 0
                    || p.interface.luid == 0
                    || p.interface.guid == [0; 16]
            })
        || record
            .proof
            .zip(record.retired_proof)
            .is_some_and(|(p, r)| p.process == r.process)
    {
        return Err(OwnerError::Journal);
    }
    Ok(record)
}
/// Shape only, NOT permission to replace config or adopt a native object. The
/// owner must positively verify absence of both variants and retained IDs.
pub(crate) fn previous_config_valid(record: &Record) -> bool {
    record.previous_config_sha256.is_none()
        || (matches!(record.phase, Phase::Prepared | Phase::Stopped) && record.proof.is_none())
}
fn prepare_journal_replace(
    slot: TunnelSlot,
    current: Option<&[u8]>,
    expected: Option<&Record>,
    desired: &Record,
) -> Result<Zeroizing<Vec<u8>>> {
    let current = current
        .map(|bytes| decode_journal(slot, bytes))
        .transpose()?;
    if current.as_ref() != expected {
        return Err(OwnerError::Conflict);
    }
    let bytes = Zeroizing::new(serde_json::to_vec(desired).map_err(|_| OwnerError::Journal)?);
    decode_journal(slot, &bytes)?;
    Ok(bytes)
}
fn canonical_config(bytes: &[u8]) -> Result<()> {
    if bytes.len() > crate::MAX_FRAME_SIZE || bytes.contains(&0) {
        return Err(OwnerError::Invalid);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| OwnerError::Invalid)?;
    let rendered = crate::redundancy::slot_configuration(text).map_err(|_| OwnerError::Invalid)?;
    if rendered.as_bytes() != bytes {
        return Err(OwnerError::Invalid);
    }
    Ok(())
}

/// Implementations return a pinned, bounded, ACL-checked file, not a path-only
/// observation. The caller holds the slot lock through publication/readback.
trait ConfigStorage {
    type Current;
    fn read_owned(&mut self) -> Result<Option<Self::Current>>;
    fn bytes(current: &Self::Current) -> &[u8];
    fn publish_owned(&mut self, current: Option<Self::Current>, canonical: &[u8]) -> Result<()>;
}
fn replace_config<S: ConfigStorage>(
    storage: &mut S,
    expected: Option<[u8; 32]>,
    canonical: &[u8],
) -> Result<()> {
    canonical_config(canonical)?;
    let current = storage.read_owned()?;
    let observed = current
        .as_ref()
        .map(|file| {
            let bytes = S::bytes(file);
            canonical_config(bytes)?;
            Ok::<[u8; 32], OwnerError>(Sha256::digest(bytes).into())
        })
        .transpose()?;
    if observed != expected {
        return Err(OwnerError::Conflict);
    }
    // No retry or expected-digest substitution after a lost acknowledgement.
    // Ownership of the SAME pinned read handle flows into secure publication.
    storage.publish_owned(current, canonical)
}

fn exact_config_slot(
    path: &std::ffi::OsStr,
    a: &std::ffi::OsStr,
    b: &std::ffi::OsStr,
) -> Result<TunnelSlot> {
    if path == a {
        Ok(TunnelSlot::A)
    } else if path == b {
        Ok(TunnelSlot::B)
    } else {
        Err(OwnerError::Invalid)
    }
}

#[cfg(windows)]
pub(crate) use native::{pin_private_directory, pin_recovery_marker, MemberFiles};

#[cfg(windows)]
mod native {
    use super::*;
    use crate::member_owner::Journal;
    use crate::windows::{install::state_directory, member_owner::PrivateConfig};
    use std::{
        ffi::c_void,
        fs::File,
        io::Write,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Path, PathBuf},
        ptr,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::{
            GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
            GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetAce, GetSecurityDescriptorControl, IsValidAcl, IsValidSid, ACL,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::*,
    };

    struct Allocation(*mut c_void);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    struct Security(Allocation);
    impl Security {
        fn new(sddl: &str) -> Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut raw = ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut raw,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(OwnerError::Native);
            }
            Ok(Self(Allocation(raw)))
        }
        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0 .0,
                bInheritHandle: 0,
            }
        }
    }
    fn wide(path: &Path) -> Result<Vec<u16>> {
        if !path.to_str().is_some_and(local_drive_path) {
            return Err(OwnerError::Invalid);
        }
        Ok(path.as_os_str().encode_wide().chain(Some(0)).collect())
    }
    fn sid_text(sid: PSID) -> Result<String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(OwnerError::Conflict);
        }
        let mut raw = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
            return Err(OwnerError::Native);
        }
        let _allocation = Allocation(raw.cast());
        let mut len = 0;
        while len < 256 && unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        if len == 256 {
            return Err(OwnerError::Conflict);
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
            .map_err(|_| OwnerError::Conflict)
    }
    fn acl(file: &File, protection: Protection) -> Result<Acl> {
        let mut owner = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        } != 0
        {
            return Err(OwnerError::Native);
        }
        let _descriptor = Allocation(descriptor);
        if descriptor.is_null() || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
            return Err(OwnerError::Conflict);
        }
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(OwnerError::Native);
        }
        let count = unsafe { (*dacl).AceCount } as u32;
        if count > 1024 {
            return Err(OwnerError::Conflict);
        }
        let mut aces = Vec::new();
        for index in 0..count {
            let mut raw = ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
                return Err(OwnerError::Conflict);
            }
            let raw = raw.cast::<u8>();
            // IsValidAcl validates ACE extents. Validate the variable SID extent
            // before passing its pointer to a SID API (also for deny ACEs).
            let kind = unsafe { *raw };
            let flags = unsafe { *raw.add(1) };
            let size = unsafe { ptr::read_unaligned(raw.add(2).cast::<u16>()) } as usize;
            if !matches!(kind, 0 | 1) || size < 16 {
                return Err(OwnerError::Conflict);
            }
            let sid_len = 8 + 4 * unsafe { *raw.add(9) } as usize;
            if sid_len > 68 || sid_len + 8 != size {
                return Err(OwnerError::Conflict);
            }
            let mask = unsafe { ptr::read_unaligned(raw.add(4).cast::<u32>()) };
            aces.push(Ace {
                kind,
                flags,
                mask,
                sid: sid_text(unsafe { raw.add(8) }.cast())?,
            });
        }
        let result = Acl {
            owner: sid_text(owner)?,
            control,
            aces,
        };
        if !acl_allowed(&result, protection) {
            return Err(OwnerError::Conflict);
        }
        Ok(result)
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Identity {
        volume: u32,
        high: u32,
        low: u32,
    }
    #[derive(Clone, Eq, PartialEq)]
    struct Stamp {
        id: Identity,
        facts: Facts,
        created: u64,
        modified: u64,
    }
    fn stamp(file: &File, directory: bool, limit: usize) -> Result<Stamp> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        {
            return Err(OwnerError::Native);
        }
        let facts = Facts {
            attributes: info.dwFileAttributes,
            links: info.nNumberOfLinks,
            size: (info.nFileSizeHigh as u64) << 32 | info.nFileSizeLow as u64,
        };
        if !facts_allowed(facts, directory, limit) {
            return Err(OwnerError::Conflict);
        }
        let time = |t: windows_sys::Win32::Foundation::FILETIME| {
            (t.dwHighDateTime as u64) << 32 | t.dwLowDateTime as u64
        };
        Ok(Stamp {
            id: Identity {
                volume: info.dwVolumeSerialNumber,
                high: info.nFileIndexHigh,
                low: info.nFileIndexLow,
            },
            facts,
            created: time(info.ftCreationTime),
            modified: time(info.ftLastWriteTime),
        })
    }
    fn open(
        path: &Path,
        access: u32,
        share: u32,
        disposition: u32,
        directory: bool,
        security: Option<&Security>,
    ) -> std::result::Result<File, u32> {
        let path = wide(path).map_err(|_| 87u32)?;
        let attributes = security.map(Security::attributes);
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                share,
                attributes.as_ref().map_or(ptr::null(), |s| s),
                disposition,
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        FILE_ATTRIBUTE_NORMAL
                    },
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(unsafe { GetLastError() });
        }
        // Sole owner of a newly returned synchronous disk handle; all failure
        // paths close it through File's RAII, including directory handles.
        Ok(unsafe { File::from_raw_handle(raw) })
    }
    fn open_directory(path: &Path) -> std::result::Result<File, u32> {
        open(
            path,
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            None,
        ) // NO FILE_SHARE_DELETE: pin ancestor names.
    }
    struct Directory {
        path: PathBuf,
        file: File,
        id: Identity,
        acl: Acl,
        protection: Protection,
    }
    impl Directory {
        fn verify(&self) -> Result<()> {
            let by_path = open_directory(&self.path).map_err(|_| OwnerError::Native)?;
            for file in [&self.file, &by_path] {
                if stamp(file, true, 0)?.id != self.id || acl(file, self.protection)? != self.acl {
                    return Err(OwnerError::Conflict);
                }
            }
            Ok(())
        }
    }

    /// Read-only pinning for installer recovery. Never creates directories or
    /// repairs permissions: every existing ancestor must pass the same guards
    /// as durable member ownership, with a protected SYSTEM/Admin-only root.
    pub(crate) struct PinnedDirectory(Vec<Directory>);
    impl PinnedDirectory {
        pub(crate) fn verify(&self) -> Result<()> {
            for directory in &self.0 {
                directory.verify()?;
            }
            Ok(())
        }
    }
    pub(crate) fn pin_private_directory(root: &Path) -> Result<PinnedDirectory> {
        let paths: Vec<_> = root.ancestors().map(Path::to_path_buf).collect();
        let drive = wide(paths.last().ok_or(OwnerError::Invalid)?)?;
        if unsafe { GetDriveTypeW(drive.as_ptr()) } != 3 {
            return Err(OwnerError::Invalid);
        }
        let mut pinned = PinnedDirectory(Vec::new());
        for (depth, path) in paths.iter().enumerate().rev() {
            pinned.verify()?;
            let file = open_directory(path).map_err(|_| OwnerError::Native)?;
            let protection = if depth == 0 {
                Protection::Directory
            } else {
                Protection::Ancestor
            };
            let id = stamp(&file, true, 0)?.id;
            let acl = acl(&file, protection)?;
            let directory = Directory {
                path: path.clone(),
                file,
                id,
                acl,
                protection,
            };
            directory.verify()?;
            pinned.0.push(directory);
        }
        Ok(pinned)
    }

    /// Caller holds PinnedDirectory for the protected installation root.
    /// Deny writes while cleanup runs, reject reparse/multi-link files, and
    /// permit only the final checked unlink while retaining this read handle.
    pub(crate) fn pin_recovery_marker(path: &Path) -> Result<File> {
        let file = open(
            path,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            false,
            None,
        )
        .map_err(|_| OwnerError::Native)?;
        stamp(
            &file,
            false,
            nelomai_contracts::dispatcher::MAX_DISPATCHER_FRAME,
        )?;
        if !recovery_marker_acl_allowed(&acl(&file, Protection::Ancestor)?) {
            return Err(OwnerError::Conflict);
        }
        Ok(file)
    }
    struct ReadFile {
        file: File,
        bytes: Zeroizing<Vec<u8>>,
        stamp: Stamp,
        acl: Acl,
    }
    impl ReadFile {
        fn verify(&self, limit: usize) -> Result<()> {
            if stamp(&self.file, false, limit)? != self.stamp
                || acl(&self.file, Protection::File)? != self.acl
            {
                return Err(OwnerError::Conflict);
            }
            Ok(())
        }
    }

    /// Unwired Journal + PrivateConfig implementation. Construction is lexical
    /// only; the first runtime operation opens/creates the private directories.
    ///
    /// File sync_all + same-directory MoveFileEx(WRITE_THROUGH) + readback is NOT
    /// a filesystem transaction or an atomic OS compare/exchange. No directory
    /// fsync/power-loss guarantee is available here; journal/config/SCM are not
    /// one transaction. A per-slot no-share lock serializes cooperating writers.
    /// Other privileged writers can race the close/rename window; the enclosing
    /// owner MUST also serialize lifecycle operations. Lost ACK: load again.
    /// Failed publication may leave an old/new target or a restricted orphan
    /// temp; there is deliberately no enumeration or speculative file deletion.
    pub(crate) struct MemberFiles {
        root: PathBuf,
        directories: Vec<Directory>,
    }
    impl MemberFiles {
        pub(crate) fn new() -> Result<Self> {
            let root = state_directory().map_err(|_| OwnerError::Invalid)?;
            if !root.to_str().is_some_and(local_drive_path) {
                return Err(OwnerError::Invalid);
            }
            Ok(Self {
                root,
                directories: Vec::new(),
            })
        }
        fn verify_directories(&self) -> Result<()> {
            for directory in &self.directories {
                directory.verify()?;
            }
            Ok(())
        }
        fn ready(&mut self) -> Result<()> {
            if !self.directories.is_empty() {
                return self.verify_directories();
            }
            let paths: Vec<PathBuf> = self.root.ancestors().map(Path::to_path_buf).collect();
            let drive = wide(paths.last().ok_or(OwnerError::Invalid)?)?;
            // Conservative: fixed local disks only; reject mapped/remote drives.
            if unsafe { GetDriveTypeW(drive.as_ptr()) } != 3 {
                return Err(OwnerError::Invalid);
            }
            let security = Security::new(DIRECTORY_SDDL)?;
            let mut directories: Vec<Directory> = Vec::new();
            for (depth, path) in paths.iter().enumerate().rev() {
                for directory in &directories {
                    directory.verify()?;
                }
                let (file, created) = open_directory_or_create_owned(
                    depth,
                    directories.last().map(|parent| &parent.acl),
                    || open_directory(path),
                    || {
                        let path_wide = wide(path)?;
                        if unsafe { CreateDirectoryW(path_wide.as_ptr(), &security.attributes()) }
                            == 0
                        {
                            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                                Ok(false)
                            } else {
                                Err(OwnerError::Native)
                            }
                        } else {
                            Ok(true)
                        }
                    },
                )?;
                let protection = if depth == 0 || created {
                    Protection::Directory
                } else {
                    Protection::Ancestor
                };
                let id = stamp(&file, true, 0)?.id;
                let acl = acl(&file, protection)?;
                let directory = Directory {
                    path: path.clone(),
                    file,
                    id,
                    acl,
                    protection,
                };
                directory.verify()?;
                directories.push(directory);
            }
            self.directories = directories;
            self.verify_directories()
        }
        fn config_slot(&self, path: &Path) -> Result<TunnelSlot> {
            // Compare the spelling as well: Path equality normalizes some aliases.
            exact_config_slot(
                path.as_os_str(),
                self.config_path(TunnelSlot::A).as_os_str(),
                self.config_path(TunnelSlot::B).as_os_str(),
            )
        }
        fn config_path(&self, slot: TunnelSlot) -> PathBuf {
            self.root
                .join(crate::redundancy::slot_config_filename(slot))
        }
        fn journal_path(&self, slot: TunnelSlot) -> PathBuf {
            self.root.join(match slot {
                TunnelSlot::A => "nelomai-a.owner.json",
                TunnelSlot::B => "nelomai-b.owner.json",
            })
        }
        fn lock(&self, slot: TunnelSlot) -> Result<File> {
            self.lock_named(match slot {
                TunnelSlot::A => "nelomai-a.owner.lock",
                TunnelSlot::B => "nelomai-b.owner.lock",
            })
        }
        fn lock_named(&self, name: &'static str) -> Result<File> {
            self.verify_directories()?;
            let path = self.root.join(name);
            let security = Security::new(FILE_SDDL)?;
            let file = open(
                &path,
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                0,
                OPEN_ALWAYS,
                false,
                Some(&security),
            )
            .map_err(|_| OwnerError::Native)?;
            stamp(&file, false, 0)?;
            acl(&file, Protection::File)?;
            self.verify_directories()?;
            Ok(file)
        }
        fn read(&self, path: &Path, limit: usize, share: u32) -> Result<Option<ReadFile>> {
            self.verify_directories()?;
            let mut file = match open(
                path,
                GENERIC_READ | READ_CONTROL,
                share,
                OPEN_EXISTING,
                false,
                None,
            ) {
                Ok(file) => file,
                Err(ERROR_FILE_NOT_FOUND) => {
                    self.verify_directories()?;
                    return Ok(None);
                }
                Err(_) => return Err(OwnerError::Native),
            };
            let before = stamp(&file, false, limit)?;
            let security = acl(&file, Protection::File)?;
            let bytes = bounded_read(&mut file, limit)?;
            if bytes.len() as u64 != before.facts.size {
                return Err(OwnerError::Conflict);
            }
            let read = ReadFile {
                file,
                bytes,
                stamp: before,
                acl: security,
            };
            read.verify(limit)?;
            self.verify_directories()?;
            Ok(Some(read))
        }
        fn temporary(&self, slot: TunnelSlot) -> Result<(PathBuf, File)> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let security = Security::new(FILE_SDDL)?;
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| OwnerError::Native)?
                .as_nanos();
            for _ in 0..16 {
                let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
                let prefix = match slot {
                    TunnelSlot::A => "a",
                    TunnelSlot::B => "b",
                };
                let path = self.root.join(format!(
                    ".nelomai-{prefix}-{}-{time:x}-{sequence:x}.tmp",
                    std::process::id()
                ));
                match open(
                    &path,
                    GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                    0,
                    CREATE_NEW,
                    false,
                    Some(&security),
                ) {
                    Ok(file) => {
                        stamp(&file, false, 0)?;
                        acl(&file, Protection::File)?;
                        return Ok((path, file));
                    }
                    Err(ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) => continue,
                    Err(_) => return Err(OwnerError::Native),
                }
            }
            Err(OwnerError::Native)
        }
        fn publish(
            &self,
            slot: TunnelSlot,
            path: &Path,
            current: Option<ReadFile>,
            bytes: &[u8],
            limit: usize,
        ) -> Result<()> {
            self.verify_directories()?;
            let (temp, mut file) = self.temporary(slot)?;
            let id = stamp(&file, false, 0)?.id;
            file.write_all(bytes).map_err(|_| OwnerError::Native)?;
            file.sync_all().map_err(|_| OwnerError::Native)?;
            if stamp(&file, false, limit)?.id != id {
                return Err(OwnerError::Conflict);
            }
            acl(&file, Protection::File)?;
            drop(file);
            // Only the source handle shares DELETE, to allow the required rename.
            // It still denies WRITE and its ID/bytes are checked through readback.
            let source = self
                .read(&temp, limit, FILE_SHARE_READ | FILE_SHARE_DELETE)?
                .ok_or(OwnerError::Conflict)?;
            if source.stamp.id != id || source.bytes.as_slice() != bytes {
                return Err(OwnerError::Conflict);
            }
            if let Some(current) = &current {
                current.verify(limit)?;
            }
            self.verify_directories()?;
            let replace = current.is_some();
            drop(current); // destination read handle disallows delete until here.
            if unsafe {
                MoveFileExW(
                    wide(&temp)?.as_ptr(),
                    wide(path)?.as_ptr(),
                    MOVEFILE_WRITE_THROUGH
                        | if replace {
                            MOVEFILE_REPLACE_EXISTING
                        } else {
                            0
                        },
                )
            } == 0
            {
                return Err(OwnerError::Native); // may be a lost ACK: caller reloads.
            }
            let readback = self
                .read(path, limit, FILE_SHARE_READ)?
                .ok_or(OwnerError::Conflict)?;
            source.verify(limit)?;
            if readback.stamp.id != id
                || readback.bytes.as_slice() != bytes
                || readback.acl != source.acl
            {
                return Err(OwnerError::Conflict);
            }
            self.verify_directories()
        }
    }
    struct SessionRecords<'a>(&'a MemberFiles);
    impl PrivateRecords for SessionRecords<'_> {
        fn read(&mut self, file: PrivateFile) -> std::io::Result<Option<Vec<u8>>> {
            self.0
                .read(
                    &self.0.root.join(file.name()),
                    file.limit(),
                    FILE_SHARE_READ,
                )
                .map(|value| value.map(|r| r.bytes.to_vec()))
                .map_err(|_| std::io::Error::other("protected_session_file_failed"))
        }
        fn compare_exchange(
            &mut self,
            file: PrivateFile,
            expected: Option<&[u8]>,
            desired: &[u8],
        ) -> std::io::Result<()> {
            (|| -> Result<()> {
                let path = self.0.root.join(file.name());
                let current = self.0.read(&path, file.limit(), FILE_SHARE_READ)?;
                if !private_replace_allowed(
                    file,
                    current.as_ref().map(|r| r.bytes.as_slice()),
                    expected,
                    desired,
                ) {
                    return Err(OwnerError::Conflict);
                }
                // Slot only selects an opaque CREATE_NEW temporary prefix; the
                // publication destination is always the closed file allowlist.
                self.0
                    .publish(TunnelSlot::A, &path, current, desired, file.limit())
            })()
            .map_err(|_| std::io::Error::other("protected_session_file_failed"))
        }
    }
    impl SessionFileIo for MemberFiles {
        fn transaction<T>(
            &mut self,
            action: impl FnOnce(&mut dyn PrivateRecords) -> std::io::Result<T>,
        ) -> std::io::Result<T> {
            self.ready()
                .map_err(|_| std::io::Error::other("protected_session_file_failed"))?;
            let _lock = self
                .lock_named("nelomai-redundant.lock")
                .map_err(|_| std::io::Error::other("protected_session_file_failed"))?;
            let result = action(&mut SessionRecords(self));
            self.verify_directories()
                .map_err(|_| std::io::Error::other("protected_session_file_failed"))?;
            result
        }
    }
    impl Journal for MemberFiles {
        fn load(&mut self, slot: TunnelSlot) -> Result<Option<Record>> {
            self.ready()?;
            let _lock = self.lock(slot)?;
            self.read(&self.journal_path(slot), MAX_JOURNAL, FILE_SHARE_READ)?
                .map(|file| decode_journal(slot, &file.bytes))
                .transpose()
        }
        fn compare_exchange(
            &mut self,
            slot: TunnelSlot,
            expected: Option<&Record>,
            desired: &Record,
        ) -> Result<()> {
            self.ready()?;
            let _lock = self.lock(slot)?;
            let path = self.journal_path(slot);
            let current = self.read(&path, MAX_JOURNAL, FILE_SHARE_READ)?;
            let bytes = prepare_journal_replace(
                slot,
                current.as_ref().map(|f| f.bytes.as_slice()),
                expected,
                desired,
            )?;
            self.publish(slot, &path, current, &bytes, MAX_JOURNAL)
        }
    }
    struct ConfigFiles<'a> {
        files: &'a MemberFiles,
        slot: TunnelSlot,
    }
    impl ConfigStorage for ConfigFiles<'_> {
        type Current = ReadFile;
        fn read_owned(&mut self) -> Result<Option<ReadFile>> {
            self.files.read(
                &self.files.config_path(self.slot),
                crate::MAX_FRAME_SIZE,
                FILE_SHARE_READ,
            )
        }
        fn bytes(current: &ReadFile) -> &[u8] {
            &current.bytes
        }
        fn publish_owned(&mut self, current: Option<ReadFile>, canonical: &[u8]) -> Result<()> {
            self.files.publish(
                self.slot,
                &self.files.config_path(self.slot),
                current,
                canonical,
                crate::MAX_FRAME_SIZE,
            )
        }
    }
    impl PrivateConfig for MemberFiles {
        fn replace_atomically(
            &mut self,
            path: &Path,
            expected_sha256: Option<[u8; 32]>,
            canonical: &str,
        ) -> Result<()> {
            // Reject untrusted spelling and oversized/noncanonical input before
            // creating/opening any directories, locks or temporary files.
            let slot = self.config_slot(path)?;
            canonical_config(canonical.as_bytes())?;
            self.ready()?;
            let _lock = self.lock(slot)?;
            replace_config(
                &mut ConfigFiles { files: self, slot },
                expected_sha256,
                canonical.as_bytes(),
            )
        }
        fn read_digest(&mut self, path: &Path) -> Result<Option<[u8; 32]>> {
            let slot = self.config_slot(path)?;
            self.ready()?;
            let _lock = self.lock(slot)?;
            self.read(
                &self.config_path(slot),
                crate::MAX_FRAME_SIZE,
                FILE_SHARE_READ,
            )?
            .map(|file| {
                canonical_config(&file.bytes)?;
                Ok(Sha256::digest(&file.bytes).into())
            })
            .transpose()
        }
    }
}

#[cfg(test)]
#[path = "member_files_tests.rs"]
mod tests;

// Exercise the protected session adapter against fake bytes on non-Windows.
#[cfg(all(test, not(windows)))]
#[path = "member_session.rs"]
mod member_session;
