//! Windows private launch. No private HANDLE is ever inheritable in common.
//! A never-resumed donor owns inheritable duplicates for the explicit child
//! handle list; this also prevents leakage into unrelated concurrent spawns.
use super::*;
use crate::ipc::windows::{capture_inherited_stdio, noninheritable_pipe_pair, PrivatePipeIo};
use std::{
    cell::Cell,
    ffi::{c_void, OsString},
    io::{Read, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, LocalFree, SetHandleInformation, DUPLICATE_SAME_ACCESS, HANDLE,
        HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
        GetAce, IsValidAcl, IsValidSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID,
    },
    Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
            InitializeProcThreadAttributeList, QueryFullProcessImageNameW, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED,
            CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTF_USESTDHANDLES, STARTUPINFOEXW,
            STARTUPINFOW,
        },
    },
};
#[path = "windows_policy.rs"]
mod policy;
const HELLO: &[u8; 12] = b"NELORUNTIME1";

fn error() -> io::Error {
    io::Error::last_os_error()
}
fn wide(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(blocked());
    }
    value.push(0);
    Ok(value)
}

struct ThreadWake(std::thread::Thread);
impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Blocking native engine I/O over the existing bounded/cancellable anonymous
/// pipe workers. Deadlines poison and join the endpoint: no late pending write
/// can be mistaken for a new request after a timeout. No nested Tokio runtime.
pub struct NativeStream {
    io: Option<PrivatePipeIo>,
    read_timeout: Cell<Option<Duration>>,
    write_timeout: Cell<Option<Duration>>,
}
impl NativeStream {
    pub fn from_private_pipe(io: PrivatePipeIo) -> Self {
        Self {
            io: Some(io),
            read_timeout: Cell::new(None),
            write_timeout: Cell::new(None),
        }
    }
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        set_timeout(&self.read_timeout, timeout)
    }
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        set_timeout(&self.write_timeout, timeout)
    }
    fn into_pipe(mut self) -> io::Result<PrivatePipeIo> {
        self.io.take().ok_or_else(blocked)
    }
    fn wait<T>(
        &mut self,
        timeout: Option<Duration>,
        mut poll: impl FnMut(Pin<&mut PrivatePipeIo>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> io::Result<T> {
        let deadline = timeout.map(|duration| Instant::now() + duration);
        let waker = Arc::new(ThreadWake(std::thread::current())).into();
        let mut context = Context::from_waker(&waker);
        loop {
            let pipe = self
                .io
                .as_mut()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
            match poll(Pin::new(pipe), &mut context) {
                Poll::Ready(Ok(result)) => return Ok(result),
                Poll::Ready(Err(error)) => {
                    self.io.take();
                    return Err(error);
                }
                Poll::Pending => {}
            }
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    self.io.take();
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::park_timeout(deadline - now);
            } else {
                std::thread::park();
            }
        }
    }
}
fn set_timeout(cell: &Cell<Option<Duration>>, value: Option<Duration>) -> io::Result<()> {
    if value.is_some_and(|duration| {
        duration.is_zero() || Instant::now().checked_add(duration).is_none()
    }) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    cell.set(value);
    Ok(())
}
impl Read for NativeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.wait(self.read_timeout.get(), |pipe, context| {
            let mut buffer = ReadBuf::new(buffer);
            match pipe.poll_read(context, &mut buffer) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
    }
}
impl Write for NativeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.wait(self.write_timeout.get(), |pipe, context| {
            pipe.poll_write(context, buffer)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.wait(self.write_timeout.get(), |pipe, context| {
            pipe.poll_flush(context)
        })
    }
}

struct Process {
    handle: OwnedHandle,
    pid: u32,
}
impl Process {
    fn exited(&self) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(error()),
        }
    }
    fn terminate(&self) -> io::Result<()> {
        if self.exited()? {
            return Ok(());
        }
        if unsafe { TerminateProcess(self.handle.as_raw_handle(), 1) } == 0 && !self.exited()? {
            return Err(error());
        }
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 10_000) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(io::ErrorKind::TimedOut.into()),
            _ => Err(error()),
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub struct VerifiedChild {
    pub(crate) target: nelomai_client_api::RuntimeTarget,
    executable: PathBuf,
    process: Process,
    auth: Option<PrivatePipeIo>,
    native: Option<NativeStream>,
}
impl VerifiedChild {
    pub fn id(&self) -> u32 {
        self.process.pid
    }
    pub fn kernel_executable(&self) -> io::Result<PathBuf> {
        let mut value = vec![0u16; 32768];
        let mut size = value.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(
                self.process.handle.as_raw_handle(),
                0,
                value.as_mut_ptr(),
                &mut size,
            )
        } == 0
        {
            return Err(error());
        }
        std::fs::canonicalize(PathBuf::from(OsString::from_wide(&value[..size as usize])))
    }
    pub fn exited(&mut self) -> io::Result<bool> {
        self.process.exited()
    }
    pub fn terminate(&mut self) -> io::Result<()> {
        self.process.terminate()
    }
    pub fn take_native(&mut self) -> io::Result<NativeStream> {
        self.native.take().ok_or_else(blocked)
    }
    pub(crate) fn take_auth(&mut self) -> io::Result<PrivatePipeIo> {
        self.auth.take().ok_or_else(blocked)
    }
    pub(crate) fn verify_alive(&mut self) -> io::Result<()> {
        if self.exited()? || self.kernel_executable()? != self.executable {
            return Err(blocked());
        }
        Ok(())
    }
}

/// Attribute values are remote HANDLE numbers owned by the suspended donor.
/// The donor outlives both the attribute list and CreateProcessW invocation.
struct Startup<'a> {
    value: STARTUPINFOEXW,
    _storage: Vec<usize>,
    _handles: Box<[HANDLE; 5]>,
    _parent: Box<HANDLE>,
    _donor: &'a Process,
}
impl<'a> Startup<'a> {
    fn new(donor: &'a Process, handles: [HANDLE; 5]) -> io::Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(error());
        }
        let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let attributes = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if unsafe { InitializeProcThreadAttributeList(attributes, 2, 0, &mut bytes) } == 0 {
            return Err(error());
        }
        let mut value: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        value.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        value.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        value.StartupInfo.hStdInput = handles[0];
        value.StartupInfo.hStdOutput = handles[1];
        value.StartupInfo.hStdError = handles[2];
        value.lpAttributeList = attributes;
        let startup = Self {
            value,
            _storage: storage,
            _handles: Box::new(handles),
            _parent: Box::new(donor.handle.as_raw_handle()),
            _donor: donor,
        };
        for (kind, data, length) in [
            (
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                startup._parent.as_ref() as *const HANDLE as *const c_void,
                std::mem::size_of::<HANDLE>(),
            ),
            (
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                startup._handles.as_ptr().cast(),
                std::mem::size_of::<[HANDLE; 5]>(),
            ),
        ] {
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes,
                    0,
                    kind as usize,
                    data,
                    length,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(error());
            }
        }
        Ok(startup)
    }
}
impl Drop for Startup<'_> {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.value.lpAttributeList);
        }
    }
}

fn environment() -> io::Result<Vec<u16>> {
    // No auth, configuration, runtime identity or arbitrary DLL/search override.
    const NAMES: &[&str] = &[
        "ALLUSERSPROFILE",
        "APPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    ];
    let mut entries = Vec::new();
    for name in NAMES {
        if let Some(value) = std::env::var_os(name) {
            let mut entry = OsString::from(name);
            entry.push("=");
            entry.push(value);
            entries.push((name.to_ascii_uppercase(), wide(&entry)?));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut result: Vec<u16> = entries.into_iter().flat_map(|(_, entry)| entry).collect();
    if result.is_empty() {
        result.push(0);
    }
    result.push(0);
    Ok(result)
}
fn create(
    executable: &Path,
    arguments: &str,
    environment: &[u16],
    startup: &STARTUPINFOW,
    extended: bool,
    suspended: bool,
) -> io::Result<Process> {
    let application = wide(executable.as_os_str())?;
    let command = format!(
        "{} {arguments}",
        policy::quoted_argument(executable.to_str().ok_or_else(blocked)?)
    );
    let mut command = wide(std::ffi::OsStr::new(&command))?;
    let directory = wide(executable.parent().ok_or_else(blocked)?.as_os_str())?;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let flags = CREATE_UNICODE_ENVIRONMENT
        | if extended {
            EXTENDED_STARTUPINFO_PRESENT
        } else {
            0
        }
        | if suspended { CREATE_SUSPENDED } else { 0 };
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            extended.into(),
            flags,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            startup,
            &mut info,
        )
    } == 0
    {
        return Err(error());
    }
    // The initial thread handle is never used to resume the donor. Closing it
    // does not resume execution; Process owns kill/wait even on later failure.
    drop(unsafe { OwnedHandle::from_raw_handle(info.hThread) });
    Ok(Process {
        handle: unsafe { OwnedHandle::from_raw_handle(info.hProcess) },
        pid: info.dwProcessId,
    })
}
fn remote_duplicate(source: &OwnedHandle, donor: &Process) -> io::Result<HANDLE> {
    let mut handle = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source.as_raw_handle(),
            donor.handle.as_raw_handle(),
            &mut handle,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(error());
    }
    // Not an OwnedHandle: this number belongs to donor, and is closed by its
    // mandatory termination on every success/error path, never in common.
    Ok(handle)
}

impl VerifiedRuntime {
    pub fn spawn(&self) -> io::Result<VerifiedChild> {
        crate::startup_diagnostics::stage("runtime.reverify");
        self.reverify()?;
        crate::startup_diagnostics::stage("runtime.verify_acl");
        self.verify_windows_acl()?;
        crate::startup_diagnostics::stage("runtime.create_pipes");
        let executable = std::fs::canonicalize(&self.executable)?;
        let identity = self
            .manifest
            .identity(self.slot, None)
            .map_err(|_| blocked())?;
        let (auth, child_auth) = noninheritable_pipe_pair()?;
        let (native, child_native) = noninheritable_pipe_pair()?;
        let environment = environment()?;
        let mut info: STARTUPINFOW = unsafe { std::mem::zeroed() };
        info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        crate::startup_diagnostics::stage("runtime.create_donor");
        let donor = create(
            &executable,
            "--private-donor-never-resume",
            &environment,
            &info,
            false,
            true,
        )?;
        let auth_handles = child_auth.handles();
        let native_handles = child_native.handles();
        let handles = [
            remote_duplicate(auth_handles[0], &donor)?,
            remote_duplicate(auth_handles[1], &donor)?,
            remote_duplicate(auth_handles[2], &donor)?,
            remote_duplicate(native_handles[0], &donor)?,
            remote_duplicate(native_handles[1], &donor)?,
        ];
        crate::startup_diagnostics::stage("runtime.prepare_handles");
        let startup = Startup::new(&donor, handles)?;
        let arguments = format!(
            "--private-runtime-v1 {} {}",
            handles[3] as usize, handles[4] as usize
        );
        crate::startup_diagnostics::stage("runtime.create_process");
        let process = create(
            &executable,
            &arguments,
            &environment,
            &startup.value.StartupInfo,
            true,
            false,
        )?;
        drop(startup);
        donor.terminate()?;
        drop((donor, child_auth, child_native));
        let mut child = VerifiedChild {
            target: nelomai_client_api::RuntimeTarget {
                container_version: identity.container_version,
                runtime_version: identity.runtime_version,
                runtime_contract_version: identity.runtime_contract_version,
                runtime_slot: identity.slot,
            },
            executable,
            process,
            auth: None,
            native: Some(NativeStream::from_private_pipe(native)),
        };
        let mut auth = NativeStream::from_private_pipe(auth);
        auth.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut hello = [0; 12];
        crate::startup_diagnostics::stage("runtime.wait_hello");
        auth.read_exact(&mut hello)?;
        if &hello != HELLO {
            return Err(blocked());
        }
        child.verify_alive()?;
        self.reverify()?;
        self.verify_windows_acl()?;
        crate::startup_diagnostics::stage("runtime.hello_verified");
        child.auth = Some(auth.into_pipe()?);
        Ok(child)
    }
    fn verify_windows_acl(&self) -> io::Result<()> {
        // All existing ancestors are checked for replacement rights; selected
        // payload objects additionally reject content/child-creation rights.
        verify_protected_path(&self.root)?;
        for name in ["container-manifest-v1.json", "container-manifest-v1.sig"] {
            verify_acl(&self.root.join(name), false)?;
        }
        let runtime = self.manifest.selected(self.slot).ok_or_else(blocked)?;
        for file in &runtime.files {
            let path = self.resource_root().join(&file.path);
            for object in path.ancestors().take_while(|path| *path != self.root) {
                verify_acl(object, false)?;
            }
        }
        Ok(())
    }
}

/// Verify protection before canonicalizing, otherwise a reparse ancestor could
/// disappear from the path under inspection. A remote server's ACL/owner claim
/// is not local machine protection; only absolute drive paths are accepted.
/// The caller separately verifies the signed manifest and exact installed path.
pub fn verify_protected_path(path: &Path) -> io::Result<()> {
    use std::path::{Component, Prefix};
    if !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
    {
        return Err(blocked());
    }
    for object in path.ancestors() {
        verify_acl(object, object != path)?;
    }
    Ok(())
}

pub fn capture_inherited_channels() -> io::Result<(PrivatePipeIo, NativeStream)> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    let handles = policy::native_handles(&args).ok_or_else(blocked)?;
    let standard = unsafe {
        [
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        ]
    };
    for handle in handles {
        let raw = handle as HANDLE;
        if standard.contains(&raw) || unsafe { GetFileType(raw) } != FILE_TYPE_PIPE {
            return Err(blocked());
        }
        if unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(error());
        }
    }
    // SAFETY: strict early trampoline, exact unique inherited pipe IDs, captured
    // once before Tauri/stdio threads. Win32+CRT stdio ownership handled centrally.
    let auth = unsafe { capture_inherited_stdio()? };
    let native = unsafe {
        PrivatePipeIo::new(
            OwnedHandle::from_raw_handle(handles[0] as HANDLE),
            OwnedHandle::from_raw_handle(handles[1] as HANDLE),
        )?
    };
    let mut auth = NativeStream::from_private_pipe(auth);
    auth.set_write_timeout(Some(Duration::from_secs(10)))?;
    auth.write_all(HELLO)?;
    auth.flush()?;
    Ok((auth.into_pipe()?, NativeStream::from_private_pipe(native)))
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn privileged_sid(sid: PSID) -> io::Result<bool> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(blocked());
    }
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(error());
    }
    let _allocation = LocalAllocation(text.cast());
    let mut length = 0;
    while length < 256 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(blocked());
    }
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| blocked())?;
    Ok(matches!(
        text.as_str(),
        "S-1-5-18"
            | "S-1-5-32-544"
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    ))
}
fn verify_acl(path: &Path, ancestor: bool) -> io::Result<()> {
    trusted(path, 0)?; // reparse/link rejection complements explicit owner/DACL
    let path = wide(path.as_os_str())?;
    let mut owner = std::ptr::null_mut();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _descriptor = LocalAllocation(descriptor);
    if !privileged_sid(owner)? || acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(blocked());
    }
    for index in 0..unsafe { (*acl).AceCount } as u32 {
        let mut raw = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut raw) } == 0 {
            return Err(error());
        }
        let header = unsafe { &*(raw as *const ACE_HEADER) };
        if !matches!(header.AceType, 0 | 1)
            || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(blocked());
        }
        let ace = unsafe { &*(raw as *const ACCESS_ALLOWED_ACE) };
        let sid = std::ptr::addr_of!(ace.SidStart) as PSID;
        if !policy::ace_allowed(
            header.AceType,
            header.AceFlags,
            ace.Mask,
            privileged_sid(sid)?,
            ancestor,
        ) {
            return Err(blocked());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_or_relative_paths_are_not_local_protected_installations() {
        for path in [
            r"runtime.exe",
            r"C:runtime.exe",
            r"\runtime.exe",
            r"\\host\share\runtime.exe",
            r"\\?\UNC\host\share\runtime.exe",
            r"\\.\pipe\runtime.exe",
        ] {
            assert!(verify_protected_path(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn suspended_donor_is_reaped_without_ever_running_its_entry_point() {
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let donor = create(
            &std::env::current_exe().unwrap(),
            "--never-run",
            &environment().unwrap(),
            &startup,
            false,
            true,
        )
        .unwrap();
        assert!(!donor.exited().unwrap());
        let mut retained = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    donor.handle.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut retained,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let retained = unsafe { OwnedHandle::from_raw_handle(retained) };
        drop(donor);
        assert_eq!(
            unsafe { WaitForSingleObject(retained.as_raw_handle(), 0) },
            WAIT_OBJECT_0
        );
    }

    #[test]
    fn remote_handle_list_works_with_no_inheritable_handles_in_common() {
        use windows_sys::Win32::Foundation::GetHandleInformation;
        let executable =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe");
        let (auth, child_auth) = noninheritable_pipe_pair().unwrap();
        let (native, child_native) = noninheritable_pipe_pair().unwrap();
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let environment = environment().unwrap();
        let donor = create(
            &executable,
            "/D /C exit 99",
            &environment,
            &startup,
            false,
            true,
        )
        .unwrap();
        let a = child_auth.handles();
        let n = child_native.handles();
        let sources = [a[0], a[1], a[2], n[0], n[1]];
        let mut handles = [std::ptr::null_mut(); 5];
        for (index, source) in sources.into_iter().enumerate() {
            let mut flags = 0;
            assert_ne!(
                unsafe { GetHandleInformation(source.as_raw_handle(), &mut flags) },
                0
            );
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            handles[index] = remote_duplicate(source, &donor).unwrap();
        }
        let startup = Startup::new(&donor, handles).unwrap();
        let process = create(
            &executable,
            "/D /C echo NELORUNTIME1",
            &environment,
            &startup.value.StartupInfo,
            true,
            false,
        )
        .unwrap();
        drop(startup);
        drop(donor);
        drop((child_auth, child_native));
        let mut auth = NativeStream::from_private_pipe(auth);
        auth.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut hello = [0; 12];
        auth.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, HELLO);
        drop((process, auth, native));
    }
}
