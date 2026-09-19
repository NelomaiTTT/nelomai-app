//! Anonymous Windows pipes are synchronous handles, never Tokio overlapped
//! pipes. Dedicated workers own them and cancellation joins both workers.
//! Task9 owns CreateProcess/verified child association and early bootstrap calls.
use std::{
    fs::File,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    thread::JoinHandle,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, SetHandleInformation, DUPLICATE_SAME_ACCESS, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        Console::{
            GetStdHandle, SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        },
        Pipes::CreatePipe,
        Threading::{
            DeleteProcThreadAttributeList, GetCurrentProcess, InitializeProcThreadAttributeList,
            UpdateProcThreadAttribute, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        },
        IO::CancelSynchronousIo,
    },
};

const CHUNK: usize = 64 * 1024;
fn error() -> io::Error {
    io::Error::last_os_error()
}
fn duplicate(handle: HANDLE, inherit: bool) -> io::Result<OwnedHandle> {
    let mut result = std::ptr::null_mut();
    // SAFETY: live process pseudo handle; result becomes exclusively owned.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut result,
            0,
            inherit.into(),
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(result) })
}
fn pipe(inherit: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: inherit.into(),
    };
    let (mut read, mut write) = (std::ptr::null_mut(), std::ptr::null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, &security, 0) } == 0 {
        return Err(error());
    }
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}
fn no_inherit(handle: &OwnedHandle) -> io::Result<()> {
    if unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(error())
    } else {
        Ok(())
    }
}
fn null_file(inherit: bool) -> io::Result<OwnedHandle> {
    let name: Vec<u16> = "NUL\0".encode_utf16().collect();
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: inherit.into(),
    };
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            0xC0000000,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        Err(error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}

/// Sole inheritable handles supplied to the future launcher's explicit handle
/// list. Nothing is encoded in environment/argv or exposed as diagnostic text.
pub struct InheritedChildPipes {
    read: OwnedHandle,
    write: OwnedHandle,
    stderr: OwnedHandle,
}
pub fn private_pipe_pair() -> io::Result<(PrivatePipeIo, InheritedChildPipes)> {
    pair(true)
}
/// Production launch keeps every handle non-inheritable in the common process.
/// Only duplicates in a suspended donor process are made inheritable.
pub fn noninheritable_pipe_pair() -> io::Result<(PrivatePipeIo, InheritedChildPipes)> {
    pair(false)
}
fn pair(inherit: bool) -> io::Result<(PrivatePipeIo, InheritedChildPipes)> {
    let (child_read, parent_write) = pipe(inherit)?;
    let (parent_read, child_write) = pipe(inherit)?;
    no_inherit(&parent_read)?;
    no_inherit(&parent_write)?;
    let child = InheritedChildPipes {
        read: child_read,
        write: child_write,
        stderr: null_file(inherit)?,
    };
    Ok((PrivatePipeIo::new(parent_read, parent_write)?, child))
}
impl InheritedChildPipes {
    pub fn handles(&self) -> [&OwnedHandle; 3] {
        [&self.read, &self.write, &self.stderr]
    }
    /// Local loopback/embedded consumer, including platform tests. A launched
    /// process must instead capture its inherited standard handles immediately.
    pub fn into_local_io(self) -> io::Result<PrivatePipeIo> {
        no_inherit(&self.read)?;
        no_inherit(&self.write)?;
        PrivatePipeIo::new(self.read, self.write)
    }
    pub fn startup(&self) -> io::Result<PrivateStartup<'_>> {
        PrivateStartup::new(self)
    }
}

/// Owns attribute storage and borrows child handles through CreateProcessW.
/// The caller must use EXTENDED_STARTUPINFO_PRESENT and bInheritHandles=TRUE.
pub struct PrivateStartup<'a> {
    startup: STARTUPINFOEXW,
    _storage: Vec<usize>,
    _handles: Box<[HANDLE; 3]>,
    _child: &'a InheritedChildPipes,
}
impl<'a> PrivateStartup<'a> {
    fn new(child: &'a InheritedChildPipes) -> io::Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(error());
        }
        let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let attributes = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut bytes) } == 0 {
            return Err(error());
        }
        let handles = Box::new([
            child.read.as_raw_handle(),
            child.write.as_raw_handle(),
            child.stderr.as_raw_handle(),
        ]);
        if unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles.as_ref()),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            let error = error();
            unsafe {
                DeleteProcThreadAttributeList(attributes);
            }
            return Err(error);
        }
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes;
        Ok(Self {
            startup,
            _storage: storage,
            _handles: handles,
            _child: child,
        })
    }
    pub fn as_mut_ptr(&mut self) -> *mut STARTUPINFOEXW {
        &mut self.startup
    }
}
impl Drop for PrivateStartup<'_> {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.startup.lpAttributeList);
        }
    }
}

/// Capture before Tauri/native initialization or any stdout writer exists.
/// Redirects both Win32 handles and this executable's linked CRT fds to NUL.
/// Does not claim to rewrite independently linked CRTs or loader-time output.
///
/// # Safety
/// The launcher must have supplied distinct exclusively owned anonymous pipe
/// stdin/stdout and NUL stderr handles. No concurrent code may read/cache/change
/// process standard handles or CRT fds. Call exactly once at the trampoline.
/// Any error is a fatal bootstrap failure: redirection may be partial, so the
/// caller must terminate before Tauri/native initialization.
pub unsafe fn capture_inherited_stdio() -> io::Result<PrivatePipeIo> {
    unsafe extern "C" {
        fn _get_osfhandle(fd: i32) -> isize;
        fn _open_osfhandle(handle: isize, flags: i32) -> i32;
        fn _dup2(source: i32, target: i32) -> i32;
        fn _close(fd: i32) -> i32;
    }
    use std::os::windows::io::IntoRawHandle;
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if [input, output, stderr]
        .iter()
        .any(|handle| handle.is_null() || *handle == INVALID_HANDLE_VALUE)
        || input == output
        || input == stderr
        || output == stderr
    {
        return Err(io::Error::other("invalid private inherited stdio"));
    }
    let read = duplicate(input, false)?;
    let write = duplicate(output, false)?;
    let crt = [
        unsafe { _get_osfhandle(0) },
        unsafe { _get_osfhandle(1) },
        unsafe { _get_osfhandle(2) },
    ];
    let close_explicitly =
        explicit_standard_owners([input as isize, output as isize, stderr as isize], crt)?;
    // CRT owns originals appearing in _get_osfhandle; _dup2 closes those. Do
    // not construct a second OwnedHandle for them, even along failure paths.
    let _original_owners: Vec<OwnedHandle> = close_explicitly
        .into_iter()
        .map(|raw| unsafe { OwnedHandle::from_raw_handle(raw as HANDLE) })
        .collect();
    for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = null_file(false)?;
        if unsafe { SetStdHandle(kind, handle.as_raw_handle()) } == 0 {
            return Err(error());
        }
        // SetStdHandle does not transfer ownership. Retain this successfully
        // installed NUL handle for process lifetime, including later failures.
        let _ = handle.into_raw_handle();
    }
    for fd in 0..3 {
        let handle = null_file(false)?.into_raw_handle();
        let source = unsafe { _open_osfhandle(handle as isize, 0x8000) };
        if source < 0 {
            drop(unsafe { OwnedHandle::from_raw_handle(handle) });
            return Err(io::Error::other("private CRT redirection failed"));
        }
        let result = unsafe { _dup2(source, fd) };
        if source != fd {
            unsafe {
                _close(source);
            }
        }
        if result != 0 {
            return Err(io::Error::other("private CRT redirection failed"));
        }
    }
    PrivatePipeIo::new(read, write)
}

fn explicit_standard_owners(standard: [isize; 3], crt: [isize; 3]) -> io::Result<Vec<isize>> {
    let valid: Vec<_> = crt
        .into_iter()
        .filter(|handle| !matches!(*handle, -2..=0))
        .collect();
    if valid
        .iter()
        .enumerate()
        .any(|(index, value)| valid[..index].contains(value))
    {
        return Err(io::Error::other("aliased CRT handle ownership"));
    }
    Ok(standard
        .into_iter()
        .filter(|handle| !valid.contains(handle))
        .collect())
}

struct WriteCommand {
    bytes: Vec<u8>,
    done: oneshot::Sender<io::Result<()>>,
}
pub struct PrivatePipeIo {
    reads: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    writes: Option<mpsc::Sender<WriteCommand>>,
    pending: Option<oneshot::Receiver<io::Result<()>>>,
    buffered: Vec<u8>,
    offset: usize,
    cancelled: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}
impl PrivatePipeIo {
    pub(crate) fn new(read: OwnedHandle, write: OwnedHandle) -> io::Result<Self> {
        let (read_sender, reads) = mpsc::channel(1);
        let (writes, mut write_receiver) = mpsc::channel::<WriteCommand>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let reader_cancel = cancelled.clone();
        let mut read = File::from(read);
        let reader = std::thread::Builder::new()
            .name("private-pipe-reader".into())
            .spawn(move || {
                while !reader_cancel.load(Ordering::SeqCst) {
                    let mut bytes = vec![0; CHUNK];
                    match read.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(length) => {
                            bytes.truncate(length);
                            if read_sender.blocking_send(Ok(bytes)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = read_sender.blocking_send(Err(error));
                            break;
                        }
                    }
                }
            })?;
        let writer_cancel = cancelled.clone();
        let mut write = File::from(write);
        let writer = std::thread::Builder::new()
            .name("private-pipe-writer".into())
            .spawn(move || {
                while let Some(command) = write_receiver.blocking_recv() {
                    if writer_cancel.load(Ordering::SeqCst) {
                        break;
                    }
                    let result = write.write_all(&command.bytes);
                    let failed = result.is_err();
                    let _ = command.done.send(result);
                    if failed {
                        break;
                    }
                }
            });
        let mut io = Self {
            reads: Some(reads),
            writes: Some(writes),
            pending: None,
            buffered: Vec::new(),
            offset: 0,
            cancelled,
            workers: vec![reader],
        };
        io.workers.push(writer?);
        Ok(io)
    }
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::future::Future;
        if let Some(pending) = self.pending.as_mut() {
            match Pin::new(pending).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.pending = None;
                    return Poll::Ready(
                        result.unwrap_or_else(|_| {
                            Err(io::Error::other("private pipe writer closed"))
                        }),
                    );
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for PrivatePipeIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.offset == self.buffered.len() {
            match self
                .reads
                .as_mut()
                .expect("live read channel")
                .poll_recv(cx)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(Some(Ok(bytes))) => {
                    self.buffered = bytes;
                    self.offset = 0;
                }
            }
        }
        let count = buffer.remaining().min(self.buffered.len() - self.offset);
        buffer.put_slice(&self.buffered[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for PrivatePipeIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        let count = bytes.len().min(CHUNK);
        if count == 0 {
            return Poll::Ready(Ok(0));
        }
        let (done, pending) = oneshot::channel();
        self.writes
            .as_ref()
            .ok_or_else(|| io::Error::other("private pipe closed"))?
            .try_send(WriteCommand {
                bytes: bytes[..count].into(),
                done,
            })
            .map_err(|_| io::Error::other("private pipe writer unavailable"))?;
        self.pending = Some(pending);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_pending(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.writes = None;
                Poll::Ready(result)
            }
        }
    }
}
impl Drop for PrivatePipeIo {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        // Unblock channel sends/receives before cancelling synchronous kernel
        // I/O. Repeated cancellation closes the pre-ReadFile scheduling race.
        self.reads = None;
        self.writes = None;
        for worker in self.workers.drain(..) {
            while !worker.is_finished() {
                unsafe {
                    CancelSynchronousIo(worker.as_raw_handle());
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // Join is the completion ACK: no abandoned blocking worker.
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crt_dup2_owns_its_original_close_and_explicit_close_never_repeats_it() {
        assert_eq!(
            explicit_standard_owners([11, 12, 13], [11, 12, 13]).unwrap(),
            Vec::<isize>::new()
        );
        assert_eq!(
            explicit_standard_owners([11, 12, 13], [11, -1, -2]).unwrap(),
            vec![12, 13]
        );
        assert!(explicit_standard_owners([11, 12, 13], [11, 11, 13]).is_err());
    }
}
