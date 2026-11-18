//! Launch provenance, never name-only adoption. The native reader sends no UAPI
//! requests. Environment buffers are bounded and zeroized; errors are redacted.
use super::member_owner::{MemberTransport, UserspaceIdentity};
use super::redundancy::SocketIdentity;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(super) const NONCE_ENV: &str = "NELOMAI_MEMBER_LAUNCH_NONCE";
const NAME_ENV: &[u8] = b"WG_TUN_NAME_FILE";
const MAX_ARGS: usize = 256 * 1024;
const PEER_WAIT_MS: u64 = 200;
const MANAGED_PEER_WAIT_MS: u64 = 3000;
const PEER_POLL_MS: u64 = 10;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchReceipt {
    pub transport: MemberTransport,
    pub boot: String,
    pub launch_nonce: String,
    pub executable: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<ManagedUtun>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedUtun {
    pub name: String,
    pub index: u32,
    /// Written before publishing the listener or handing either FD to the child.
    pub socket: Option<SocketIdentity>,
}
impl std::fmt::Debug for LaunchReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaunchReceipt([redacted])")
    }
}
impl LaunchReceipt {
    pub(super) fn valid(&self) -> bool {
        let n = self.launch_nonce.as_bytes();
        !self.boot.is_empty()
            && self.boot.len() <= 128
            && !self.boot.chars().any(char::is_control)
            && self.executable.is_absolute()
            && self.executable.as_os_str().len() <= 4096
            && self.executable.components().all(|c| {
                matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            && self.managed.as_ref().is_none_or(|managed| {
                managed.index != 0
                    && managed.name.strip_prefix("utun").is_some_and(|unit| {
                        !unit.is_empty()
                            && unit.len() <= 10
                            && unit.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    && managed.socket.is_none_or(|socket| socket.inode != 0)
            })
            && n.len() == 36
            && n[14] == b'4'
            && matches!(n[19], b'8' | b'9' | b'a' | b'b')
            && n.iter().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Peer {
    pid: i32,
    uid: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Process {
    pid: i32,
    uid: u32,
    real_uid: u32,
    saved_uid: u32,
    started_sec: u64,
    started_usec: u64,
    executable: PathBuf,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessStamp {
    pid: i32,
    started_sec: u64,
    started_usec: u64,
}
impl ProcessStamp {
    pub(super) fn valid(self) -> bool {
        self.pid > 1 && self.started_sec != 0 && self.started_usec < 1_000_000
    }
}
impl From<Process> for ProcessStamp {
    fn from(value: Process) -> Self {
        Self {
            pid: value.pid,
            started_sec: value.started_sec,
            started_usec: value.started_usec,
        }
    }
}
/// Each read is independently fallible. Holding the channel across the two
/// observations ties PID evidence to the actual named UAPI listener.
trait LaunchProbe {
    type Channel;
    fn resource(&mut self) -> io::Result<UserspaceIdentity>;
    fn connect(&mut self, resource: &UserspaceIdentity) -> io::Result<Self::Channel>;
    fn peer(&mut self, channel: &Self::Channel) -> io::Result<Peer>;
    fn process(&mut self, pid: i32) -> io::Result<Process>;
    fn arguments(&mut self, pid: i32) -> io::Result<Zeroizing<Vec<u8>>>;
    fn now_ms(&self) -> u64;
    fn wait_peer(&mut self, millis: u64);
}
pub(super) struct VerifiedLaunch {
    receipt: LaunchReceipt,
    identity: UserspaceIdentity,
    process: ProcessStamp,
}
impl VerifiedLaunch {
    pub(super) fn managed_process(&self) -> Option<ProcessStamp> {
        self.receipt.managed.as_ref().map(|_| self.process)
    }
    pub(super) fn into_identity(self, receipt: &LaunchReceipt) -> io::Result<UserspaceIdentity> {
        if self.receipt != *receipt {
            return Err(invalid());
        }
        Ok(self.identity)
    }
}
#[cfg(target_os = "macos")]
pub(super) struct VerifiedLegacy {
    transport: MemberTransport,
    identity: UserspaceIdentity,
}
#[cfg(target_os = "macos")]
impl VerifiedLegacy {
    pub(super) fn transport(&self) -> MemberTransport {
        self.transport
    }
    pub(super) fn into_identity(self) -> UserspaceIdentity {
        self.identity
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "member_launch_unproven")
}
fn peer_pending() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "member_launch_unproven")
}
fn attest(
    receipt: &LaunchReceipt,
    state_file: &Path,
    probe: &mut impl LaunchProbe,
) -> io::Result<VerifiedLaunch> {
    if !receipt.valid() {
        return Err(invalid());
    }
    let (identity, process) = attest_identity(
        &receipt.boot,
        &receipt.executable,
        Some(&receipt.launch_nonce),
        state_file,
        probe,
        receipt.managed.as_ref(),
    )?;
    Ok(VerifiedLaunch {
        receipt: receipt.clone(),
        identity,
        process,
    })
}

fn attest_identity(
    boot: &str,
    executable: &Path,
    nonce: Option<&str>,
    state_file: &Path,
    probe: &mut impl LaunchProbe,
    managed: Option<&ManagedUtun>,
) -> io::Result<(UserspaceIdentity, ProcessStamp)> {
    if !state_file.is_absolute() {
        return Err(invalid());
    }
    let wait_ms = if managed.is_some() {
        MANAGED_PEER_WAIT_MS
    } else {
        PEER_WAIT_MS
    };
    let deadline = probe.now_ms().saturating_add(wait_ms);
    let retries = wait_ms / PEER_POLL_MS;
    let before = probe.resource()?;
    if !before.valid()
        || before.boot != boot
        || managed.is_some_and(|managed| {
            managed.name != before.interface
                || managed.index != before.index
                || managed.socket != Some(before.socket)
        })
    {
        return Err(invalid());
    }
    let channel = probe.connect(&before)?;
    // XNU sonewconn inherits listener last_pid; accept's soacceptlock invokes
    // so_update_last_owner_locked on that connected socket. LOCAL_PEERPID reads
    // peerso->last_pid on EACH query, so one held channel can observe the child
    // after accept. Connect completion itself does not prove accept happened.
    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket2.c
    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c
    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c
    // This source-based contract is not a native runtime timing test.
    for attempt in 0..=retries {
        let observed = attest_channel(executable, nonce, state_file, probe, &channel);
        if probe.resource()? != before {
            return Err(invalid());
        }
        match observed {
            Ok(process) if probe.now_ms() <= deadline => return Ok((before, process.into())),
            Err(error)
                if (error.kind() == io::ErrorKind::WouldBlock || managed.is_some())
                    && attempt < retries
                    && probe.now_ms() < deadline =>
            {
                probe.wait_peer(PEER_POLL_MS.min(deadline.saturating_sub(probe.now_ms())));
            }
            _ => return Err(invalid()),
        }
    }
    Err(invalid())
}
fn attest_channel<P: LaunchProbe>(
    executable: &Path,
    nonce: Option<&str>,
    state_file: &Path,
    probe: &mut P,
    channel: &P::Channel,
) -> io::Result<Process> {
    let peer = probe.peer(channel)?;
    if peer.uid != 0 || peer.pid <= 0 {
        return Err(invalid());
    }
    let process = probe.process(peer.pid)?;
    if process.pid != peer.pid
        || process.uid != 0
        || process.real_uid != 0
        || process.saved_uid != 0
        || process.started_sec == 0
        || process.started_usec >= 1_000_000
        || process.executable != executable
    {
        return Err(invalid());
    }
    let args = probe.arguments(peer.pid)?;
    check_process_arguments(&args, executable, nonce, state_file)?;
    drop(args); // Zeroize the whole sysctl allocation before further observations.
    if probe.process(peer.pid)? != process {
        return Err(invalid());
    }
    let after = probe.peer(channel)?;
    if after.uid != 0 || after.pid <= 0 {
        return Err(invalid());
    }
    if after != peer {
        return Err(peer_pending());
    }
    Ok(process)
}
// Layout follows Apple's KERN_PROCARGS2 / ps: argc, saved executable path,
// alignment NULs, argc terminated argv strings, terminated environment strings.
// https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/print.c
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sysctl.c
// XNU can append Apple auxiliary strings after the environment's terminating
// NUL/alignment. Like ps, stop at that boundary; auxiliary data is not evidence.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c
// Missing/omitted or unterminated environment is not proof.
#[cfg(test)]
fn check_arguments(bytes: &[u8], receipt: &LaunchReceipt, state_file: &Path) -> io::Result<()> {
    check_process_arguments(
        bytes,
        &receipt.executable,
        Some(&receipt.launch_nonce),
        state_file,
    )
}

fn check_process_arguments(
    bytes: &[u8],
    executable: &Path,
    expected_nonce: Option<&str>,
    state_file: &Path,
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    if bytes.len() < 4 || bytes.len() >= MAX_ARGS {
        return Err(invalid());
    }
    let argc = i32::from_ne_bytes(bytes[..4].try_into().map_err(|_| invalid())?);
    if !(1..=4096).contains(&argc) {
        return Err(invalid());
    }
    let mut rest = &bytes[4..];
    if take_string(&mut rest)? != executable.as_os_str().as_bytes() {
        return Err(invalid());
    }
    while rest.first() == Some(&0) {
        rest = &rest[1..];
    }
    for _ in 0..argc {
        take_string(&mut rest)?;
    }
    let mut nonce = false;
    let mut name = false;
    while !rest.is_empty() && rest[0] != 0 {
        let entry = take_string(&mut rest)?;
        let split = entry.iter().position(|b| *b == b'=').ok_or_else(invalid)?;
        let (key, value) = (&entry[..split], &entry[split + 1..]);
        if key == NONCE_ENV.as_bytes() {
            if nonce || Some(value) != expected_nonce.map(str::as_bytes) {
                return Err(invalid());
            }
            nonce = true;
        } else if key == NAME_ENV {
            if name || value != state_file.as_os_str().as_bytes() {
                return Err(invalid());
            }
            name = true;
        }
    }
    if nonce != expected_nonce.is_some() || !name || rest.first() != Some(&0) {
        return Err(invalid());
    }
    Ok(())
}
fn take_string<'a>(rest: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let end = rest.iter().position(|b| *b == 0).ok_or_else(invalid)?;
    let value = &rest[..end];
    *rest = &rest[end + 1..];
    Ok(value)
}

trait SocketConnect {
    type Handle;
    fn create(&mut self) -> io::Result<Self::Handle>;
    fn close_on_exec(&mut self, handle: &Self::Handle) -> io::Result<()>;
    fn nonblocking(&mut self, handle: &Self::Handle) -> io::Result<()>;
    fn connect(&mut self, handle: &Self::Handle, path: &Path) -> io::Result<()>;
}
// No retries, wait threads, or blocking connect. Pending/backlogged connections
// are not evidence and may be retried by the enclosing cleanup owner later.
fn bounded_connection<S: SocketConnect>(socket: &mut S, path: &Path) -> io::Result<S::Handle> {
    let handle = socket.create()?;
    socket.close_on_exec(&handle)?;
    socket.nonblocking(&handle)?;
    socket.connect(&handle, path)?;
    Ok(handle)
}

#[cfg(target_os = "macos")]
pub(super) use native::{new_receipt, probe_listener, process_alive, prove, prove_ordinary_legacy};
#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::{
        fs,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                ffi::OsStringExt,
                fs::{MetadataExt, OpenOptionsExt},
                net::UnixStream,
            },
        },
    };
    use zeroize::Zeroize;

    pub(in crate::backend) fn probe_listener(path: &Path) -> io::Result<()> {
        bounded_connection(&mut NativeSocket, path).map(drop)
    }

    pub(in crate::backend) fn process_alive(expected: ProcessStamp) -> io::Result<bool> {
        let (count, info) = process_info(expected.pid);
        if count == std::mem::size_of_val(&info) as i32 && info.pbi_pid as i32 == expected.pid {
            return Ok(info.pbi_start_tvsec == expected.started_sec
                && info.pbi_start_tvusec == expected.started_usec);
        }
        // Signal 0 only tests existence. An unreadable PID is not absence.
        if count <= 0 {
            if unsafe { libc::kill(expected.pid, 0) } == 0 {
                return Ok(true);
            }
            if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return Ok(false);
            }
        }
        Err(invalid())
    }

    fn process_info(pid: i32) -> (i32, libc::proc_bsdinfo) {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let count = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                std::mem::size_of_val(&info) as i32,
            )
        };
        (count, info)
    }

    pub(in crate::backend) fn new_receipt(
        transport: MemberTransport,
        executable: &Path,
    ) -> io::Result<LaunchReceipt> {
        let executable = fs::canonicalize(executable).map_err(|_| invalid())?;
        trusted_binary(&executable)?;
        let mut random = Zeroizing::new([0u8; 16]);
        // OS entropy only; never a clock/PID fallback. Not invoked by tests.
        if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
            return Err(invalid());
        }
        random[6] = (random[6] & 0x0f) | 0x40;
        random[8] = (random[8] & 0x3f) | 0x80;
        let mut nonce = String::with_capacity(36);
        use std::fmt::Write;
        for (i, b) in random.iter().enumerate() {
            if [4, 6, 8, 10].contains(&i) {
                nonce.push('-');
            }
            write!(&mut nonce, "{b:02x}").map_err(|_| invalid())?;
        }
        let receipt = LaunchReceipt {
            transport,
            executable,
            launch_nonce: nonce,
            boot: super::super::macos::boot_identity().map_err(|_| invalid())?,
            managed: None,
        };
        if !receipt.valid() {
            return Err(invalid());
        }
        Ok(receipt)
    }
    fn trusted_binary(path: &Path) -> io::Result<()> {
        let meta = fs::symlink_metadata(path).map_err(|_| invalid())?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || fs::canonicalize(path).map_err(|_| invalid())? != path
        {
            return Err(invalid());
        }
        // Canonical path ancestors may not allow unprivileged replacement.
        for parent in path.ancestors().skip(1) {
            let m = fs::symlink_metadata(parent).map_err(|_| invalid())?;
            if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(in crate::backend) fn prove(
        directory: &Path,
        receipt: &LaunchReceipt,
        ordinary: bool,
    ) -> io::Result<VerifiedLaunch> {
        trusted_binary(&receipt.executable)?;
        let proof = attest(
            receipt,
            &directory.join("interface-name"),
            &mut Native {
                directory,
                ordinary,
                started: std::time::Instant::now(),
            },
        )?;
        trusted_binary(&receipt.executable)?;
        Ok(proof)
    }
    pub(in crate::backend) fn prove_ordinary_legacy(
        directory: &Path,
        boot: &str,
        executable: &Path,
        transport: MemberTransport,
    ) -> io::Result<VerifiedLegacy> {
        let executable = fs::canonicalize(executable)?;
        trusted_binary(&executable)?;
        let (identity, _) = attest_identity(
            boot,
            &executable,
            None,
            &directory.join("interface-name"),
            &mut Native {
                directory,
                ordinary: true,
                started: std::time::Instant::now(),
            },
            None,
        )?;
        trusted_binary(&executable)?;
        Ok(VerifiedLegacy {
            transport,
            identity,
        })
    }
    struct Native<'a> {
        directory: &'a Path,
        ordinary: bool,
        started: std::time::Instant,
    }
    struct NativeSocket;
    impl SocketConnect for NativeSocket {
        type Handle = OwnedFd;
        fn create(&mut self) -> io::Result<OwnedFd> {
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                return Err(invalid());
            }
            // Ownership transfers immediately, including every fcntl failure.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
        fn close_on_exec(&mut self, fd: &OwnedFd) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            if flags < 0
                || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) }
                    < 0
            {
                return Err(invalid());
            }
            Ok(())
        }
        fn nonblocking(&mut self, fd: &OwnedFd) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(invalid());
            }
            Ok(())
        }
        fn connect(&mut self, fd: &OwnedFd, path: &Path) -> io::Result<()> {
            let address = socket_address(path)?;
            let result = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    address.sun_len.into(),
                )
            };
            // Includes EINPROGRESS/EAGAIN: do not wait for a listener or assume
            // asynchronous success. The owned fd is closed on every error.
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    fn socket_address(path: &Path) -> io::Result<libc::sockaddr_un> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if !path.is_absolute() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err(invalid());
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // Darwin's two-byte sockaddr header followed by the terminated path.
        address.sun_len =
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as u8;
        for (out, input) in address.sun_path.iter_mut().zip(bytes) {
            *out = *input as libc::c_char;
        }
        Ok(address)
    }
    fn check_process_info(count: i32, info: &libc::proc_bsdinfo, pid: i32) -> io::Result<()> {
        if count <= 0 {
            return Err(peer_pending());
        }
        if count as usize != std::mem::size_of_val(info) || info.pbi_pid != pid as u32 {
            return Err(invalid());
        }
        if info.pbi_flags & 4 != 0 {
            return Err(peer_pending());
        } // PROC_FLAG_INEXIT
        Ok(())
    }
    impl LaunchProbe for Native<'_> {
        type Channel = UnixStream;
        fn now_ms(&self) -> u64 {
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
        }
        fn wait_peer(&mut self, millis: u64) {
            std::thread::sleep(std::time::Duration::from_millis(millis));
        }
        fn resource(&mut self) -> io::Result<UserspaceIdentity> {
            let dir = fs::symlink_metadata(self.directory).map_err(|_| invalid())?;
            if !self.directory.is_absolute()
                || !dir.is_dir()
                || dir.uid() != 0
                || dir.mode() & (if self.ordinary { 0o022 } else { 0o077 }) != 0
            {
                return Err(invalid());
            }
            let path = self.directory.join("interface-name");
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&path)
                .map_err(|_| invalid())?;
            let before = file.metadata().map_err(|_| invalid())?;
            if !before.is_file()
                || before.uid() != 0
                || before.nlink() != 1
                || before.mode() & 0o022 != 0
                || before.len() > 64
            {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            (&file)
                .take(65)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid())?;
            if bytes.len() > 64 {
                return Err(invalid());
            }
            let name = std::str::from_utf8(&bytes).map_err(|_| invalid())?.trim();
            if !name.strip_prefix("utun").is_some_and(|s| {
                !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())
            }) {
                return Err(invalid());
            }
            let boot = super::super::macos::boot_identity().map_err(|_| invalid())?;
            let identity =
                super::super::macos::capture_member(name, &boot).map_err(|_| invalid())?;
            let after = fs::symlink_metadata(path).map_err(|_| invalid())?;
            let dir_after = fs::symlink_metadata(self.directory).map_err(|_| invalid())?;
            if (
                before.dev(),
                before.ino(),
                before.mode(),
                before.uid(),
                before.len(),
                before.nlink(),
            ) != (
                after.dev(),
                after.ino(),
                after.mode(),
                after.uid(),
                after.len(),
                after.nlink(),
            ) || (dir.dev(), dir.ino(), dir.mode(), dir.uid())
                != (
                    dir_after.dev(),
                    dir_after.ino(),
                    dir_after.mode(),
                    dir_after.uid(),
                )
            {
                return Err(invalid());
            }
            Ok(identity)
        }
        fn connect(&mut self, resource: &UserspaceIdentity) -> io::Result<UnixStream> {
            // A connect and kernel socket queries only: no UAPI writes/configure.
            bounded_connection(
                &mut NativeSocket,
                &super::super::userspace_socket_path(&resource.interface),
            )
            .map(UnixStream::from)
            .map_err(|_| invalid())
        }
        fn peer(&mut self, channel: &UnixStream) -> io::Result<Peer> {
            let mut uid = 0;
            let mut gid = 0;
            let mut pid: libc::pid_t = 0;
            let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
            if unsafe { libc::getpeereid(channel.as_raw_fd(), &mut uid, &mut gid) } != 0
                || unsafe {
                    libc::getsockopt(
                        channel.as_raw_fd(),
                        0,
                        libc::LOCAL_PEERPID,
                        (&mut pid as *mut libc::pid_t).cast(),
                        &mut length,
                    )
                } != 0
                || length as usize != std::mem::size_of::<libc::pid_t>()
                || pid <= 0
            {
                return Err(invalid());
            }
            Ok(Peer { pid, uid })
        }
        fn process(&mut self, pid: i32) -> io::Result<Process> {
            // Use libc's Darwin ABI, requiring the full PROC_PIDTBSDINFO size.
            // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
            let (count, info) = process_info(pid);
            check_process_info(count, &info, pid)?;
            let mut path = [0u8; 4096];
            let count =
                unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
            if count <= 0 {
                return Err(peer_pending());
            }
            if count as usize >= path.len() {
                return Err(invalid());
            }
            let end = path.iter().position(|b| *b == 0).ok_or_else(invalid)?;
            if end == 0 || end > count as usize {
                return Err(invalid());
            }
            Ok(Process {
                pid,
                uid: info.pbi_uid,
                real_uid: info.pbi_ruid,
                saved_uid: info.pbi_svuid,
                started_sec: info.pbi_start_tvsec,
                started_usec: info.pbi_start_tvusec,
                executable: PathBuf::from(std::ffi::OsString::from_vec(path[..end].to_vec())),
            })
        }
        fn arguments(&mut self, pid: i32) -> io::Result<Zeroizing<Vec<u8>>> {
            let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
            let mut bytes = Zeroizing::new(vec![0u8; MAX_ARGS]);
            let mut length = bytes.len();
            let result = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    bytes.as_mut_ptr().cast(),
                    &mut length,
                    std::ptr::null_mut(),
                    0,
                )
            };
            // XNU may truncate without an error for a small buffer. Reject a
            // filled buffer, as well as absent/SIP-hidden environment in parser.
            if result != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return Err(peer_pending());
            }
            if result != 0 || length < 4 || length >= bytes.len() {
                return Err(invalid());
            }
            bytes[length..].zeroize();
            bytes.truncate(length);
            Ok(bytes)
        }
    }

    #[cfg(test)]
    mod abi_tests {
        use super::*;
        #[test]
        fn listener_probe_distinguishes_missing_and_closed_unix_sockets() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("probe.sock");
            assert_eq!(
                probe_listener(&path).unwrap_err().raw_os_error(),
                Some(libc::ENOENT)
            );
            drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
            assert_eq!(
                probe_listener(&path).unwrap_err().raw_os_error(),
                Some(libc::ECONNREFUSED)
            );
        }

        #[test]
        fn vanished_or_exiting_parent_is_transient_but_partial_abi_and_wrong_pid_are_not() {
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            info.pbi_pid = 123;
            let size = std::mem::size_of_val(&info) as i32;
            assert!(check_process_info(size, &info, 123).is_ok());
            assert_eq!(
                check_process_info(0, &info, 123).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                check_process_info(size - 1, &info, 123).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                check_process_info(size, &info, 124).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            info.pbi_flags = 4; // PROC_FLAG_INEXIT in Apple's proc_info.h
            assert_eq!(
                check_process_info(size, &info, 123).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        #[test]
        fn darwin_socket_address_is_bounded_and_terminated_without_native_calls() {
            let path = "/var/run/wireguard/utun42.sock";
            let address = socket_address(Path::new(path)).unwrap();
            assert_eq!(std::mem::offset_of!(libc::sockaddr_un, sun_path), 2);
            assert_eq!(address.sun_family, libc::AF_UNIX as libc::sa_family_t);
            assert_eq!(address.sun_len as usize, path.len() + 3);
            assert_eq!(address.sun_path[path.len()], 0);
            assert!(socket_address(Path::new("relative")).is_err());
            assert!(socket_address(Path::new("/bad\0path")).is_err());
            assert!(socket_address(Path::new(&format!("/{}", "x".repeat(104)))).is_err());
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::redundancy::SocketIdentity;
    use super::*;
    use std::collections::VecDeque;
    const STATE: &str = "/private/var/run/nelomai/slot-a/interface-name";
    pub(crate) fn receipt(transport: MemberTransport) -> LaunchReceipt {
        LaunchReceipt {
            transport,
            boot: "boot-one".into(),
            launch_nonce: "72cc17e2-0000-4000-8000-000000000001".into(),
            executable: "/Library/Nelomai/awg".into(),
            managed: None,
        }
    }
    fn identity() -> UserspaceIdentity {
        UserspaceIdentity {
            boot: "boot-one".into(),
            interface: "utun42".into(),
            index: 42,
            socket: SocketIdentity {
                device: 1,
                inode: 2,
            },
        }
    }
    fn args(extra: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(2i32.to_ne_bytes().to_vec());
        b.extend_from_slice(b"/Library/Nelomai/awg\0\0\0awg\0-f\0");
        b.extend_from_slice(b"NELOMAI_MEMBER_LAUNCH_NONCE=72cc17e2-0000-4000-8000-000000000001\0WG_TUN_NAME_FILE=/private/var/run/nelomai/slot-a/interface-name\0");
        for entry in extra {
            b.extend_from_slice(entry);
            b.push(0);
        }
        b.push(0);
        b
    }
    struct Fake {
        resources: VecDeque<UserspaceIdentity>,
        peers: VecDeque<Peer>,
        processes: VecDeque<Process>,
        args: Zeroizing<Vec<u8>>,
        events: Vec<&'static str>,
        fail: Option<usize>,
        channel_live: std::rc::Rc<std::cell::Cell<bool>>,
        transient_process_reads: usize,
        now_ms: u64,
        stall_clock: bool,
    }
    struct FakeChannel(std::rc::Rc<std::cell::Cell<bool>>);
    impl Drop for FakeChannel {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }
    impl Fake {
        fn new() -> Self {
            let p = Process {
                pid: 123,
                uid: 0,
                real_uid: 0,
                saved_uid: 0,
                started_sec: 5,
                started_usec: 7,
                executable: "/Library/Nelomai/awg".into(),
            };
            Self {
                resources: vec![identity(), identity()].into(),
                peers: vec![Peer { pid: 123, uid: 0 }; 2].into(),
                processes: vec![p.clone(), p].into(),
                args: args(&[]),
                events: vec![],
                fail: None,
                channel_live: Default::default(),
                transient_process_reads: 0,
                now_ms: 0,
                stall_clock: false,
            }
        }
        fn event(&mut self, name: &'static str) -> io::Result<()> {
            self.events.push(name);
            if self.fail == Some(self.events.len()) {
                Err(invalid())
            } else {
                Ok(())
            }
        }
    }
    impl LaunchProbe for Fake {
        type Channel = FakeChannel;
        fn now_ms(&self) -> u64 {
            self.now_ms
        }
        fn wait_peer(&mut self, millis: u64) {
            assert!(self.channel_live.get());
            self.events.push("wait");
            if !self.stall_clock {
                self.now_ms += millis;
            }
        }
        fn resource(&mut self) -> io::Result<UserspaceIdentity> {
            self.event("resource")?;
            Ok(if self.resources.len() > 1 {
                self.resources.pop_front().unwrap()
            } else {
                self.resources[0].clone()
            })
        }
        fn connect(&mut self, _: &UserspaceIdentity) -> io::Result<FakeChannel> {
            self.event("connect")?;
            self.channel_live.set(true);
            Ok(FakeChannel(self.channel_live.clone()))
        }
        fn peer(&mut self, _: &FakeChannel) -> io::Result<Peer> {
            assert!(self.channel_live.get());
            self.event("peer")?;
            Ok(if self.peers.len() > 1 {
                self.peers.pop_front().unwrap()
            } else {
                self.peers[0].clone()
            })
        }
        fn process(&mut self, pid: i32) -> io::Result<Process> {
            assert!(self.channel_live.get());
            self.event("process")?;
            if self.transient_process_reads > 0 {
                self.transient_process_reads -= 1;
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            if pid != 123 {
                return Err(invalid());
            } // unknown foreign process
            self.processes.pop_front().ok_or_else(invalid)
        }
        fn arguments(&mut self, pid: i32) -> io::Result<Zeroizing<Vec<u8>>> {
            assert_eq!(pid, 123);
            self.event("args")?;
            Ok(self.args.clone())
        }
    }
    #[test]
    fn legacy_ordinary_proof_requires_exact_binary_and_runtime_and_rejects_a_nonce() {
        let binary = Path::new("/Library/Nelomai/awg");
        let state = Path::new(STATE);
        let mut old_args = args(&[]);
        let nonce = old_args
            .windows(NONCE_ENV.len())
            .position(|v| v == NONCE_ENV.as_bytes())
            .unwrap();
        let end = nonce + old_args[nonce..].iter().position(|v| *v == 0).unwrap() + 1;
        old_args.drain(nonce..end);
        for (path, executable, legacy, valid) in [
            (state, binary, true, true),
            (Path::new("/other/interface-name"), binary, true, false),
            (state, Path::new("/Library/Nelomai/other"), true, false),
            (state, binary, false, false),
        ] {
            let mut fake = Fake::new();
            if legacy {
                fake.args = old_args.clone();
            }
            assert_eq!(
                attest_identity("boot-one", executable, None, path, &mut fake, None).is_ok(),
                valid
            );
        }
    }

    #[test]
    fn managed_launch_checks_the_recorded_interface_and_listener_before_connecting() {
        let expected = identity();
        let mut r = receipt(MemberTransport::WireGuard);
        let managed = ManagedUtun {
            name: expected.interface.clone(),
            index: expected.index,
            socket: Some(expected.socket),
        };
        r.managed = Some(managed.clone());
        assert!(attest(&r, Path::new(STATE), &mut Fake::new()).is_ok());

        for altered in [
            ManagedUtun {
                name: "utun199".into(),
                ..managed.clone()
            },
            ManagedUtun {
                index: managed.index + 1,
                ..managed.clone()
            },
            ManagedUtun {
                socket: Some(SocketIdentity {
                    inode: expected.socket.inode + 1,
                    ..expected.socket
                }),
                ..managed.clone()
            },
            ManagedUtun {
                socket: None,
                ..managed.clone()
            },
        ] {
            r.managed = Some(altered);
            let mut fake = Fake::new();
            assert!(attest(&r, Path::new(STATE), &mut fake).is_err());
            assert_eq!(fake.events, ["resource"]);
        }
    }

    pub(crate) fn verified() -> VerifiedLaunch {
        attest(
            &receipt(MemberTransport::WireGuard),
            Path::new(STATE),
            &mut Fake::new(),
        )
        .unwrap()
    }
    #[test]
    fn proof_requires_ordered_kernel_process_environment_and_resource_rechecks() {
        let mut f = Fake::new();
        let r = receipt(MemberTransport::WireGuard);
        assert_eq!(
            attest(&r, Path::new(STATE), &mut f)
                .unwrap()
                .into_identity(&r)
                .unwrap(),
            identity()
        );
        assert_eq!(
            f.events,
            ["resource", "connect", "peer", "process", "args", "process", "peer", "resource"]
        );
        assert!(!f.channel_live.get());
        assert!(!format!("{r:?}").contains(&r.launch_nonce));
    }

    #[test]
    fn daemon_accept_can_replace_dead_parent_peer_on_the_same_held_channel() {
        let mut f = Fake::new();
        f.peers[0].pid = 999; // parent's stale last_pid until accept updates it
        f.transient_process_reads = 1;
        assert!(attest(
            &receipt(MemberTransport::WireGuard),
            Path::new(STATE),
            &mut f
        )
        .is_ok());
        assert_eq!(f.events.iter().filter(|e| **e == "connect").count(), 1);
        assert_eq!(f.events.iter().filter(|e| **e == "wait").count(), 1);
        assert_eq!(f.now_ms, 10);
        assert!(!f.channel_live.get());
    }
    #[test]
    fn accept_wait_is_bounded_and_never_accepts_replaced_resources() {
        for stall in [false, true] {
            let mut f = Fake::new();
            f.stall_clock = stall;
            f.transient_process_reads = usize::MAX;
            assert!(attest(
                &receipt(MemberTransport::WireGuard),
                Path::new(STATE),
                &mut f
            )
            .is_err());
            assert_eq!(f.events.iter().filter(|e| **e == "connect").count(), 1);
            assert_eq!(f.events.iter().filter(|e| **e == "wait").count(), 20);
            assert!(f.now_ms <= 200);
            assert!(!f.channel_live.get());
        }
        let mut f = Fake::new();
        f.transient_process_reads = 1;
        f.resources[1].socket.inode += 1;
        assert!(attest(
            &receipt(MemberTransport::WireGuard),
            Path::new(STATE),
            &mut f
        )
        .is_err());
        assert!(!f.events.contains(&"args"));
    }
    #[test]
    fn every_unavailable_kernel_step_fails_closed() {
        for step in 1..=8 {
            let mut f = Fake::new();
            f.fail = Some(step);
            assert!(attest(
                &receipt(MemberTransport::WireGuard),
                Path::new(STATE),
                &mut f
            )
            .is_err());
            assert!(!f.channel_live.get());
        }
    }
    #[test]
    fn foreign_or_changing_process_channel_boot_interface_and_socket_rejected() {
        for change in 0..13 {
            let mut f = Fake::new();
            match change {
                0 => f.peers[0].uid = 501,
                1 => f.peers[1].pid += 1,
                2 => f.processes[0].uid = 501,
                3 => f.processes[1].started_sec += 1,
                4 => f.processes[1].executable = "/foreign".into(),
                5 => f.resources[0].boot = "other".into(),
                6 => f.resources[1].boot = "other".into(),
                7 => f.resources[1].index += 1,
                8 => f.resources[1].socket.device += 1,
                9 => f.resources[1].socket.inode += 1,
                10 => f.processes[0].pid += 1,
                11 => f.processes[0].real_uid = 501,
                _ => f.resources[1].interface = "utun43".into(),
            }
            assert!(
                attest(
                    &receipt(MemberTransport::WireGuard),
                    Path::new(STATE),
                    &mut f
                )
                .is_err(),
                "case {change}"
            );
        }
    }
    #[test]
    fn bounded_parser_accepts_exact_environment_not_argv_or_duplicates() {
        let r = receipt(MemberTransport::WireGuard);
        assert!(check_arguments(&args(&[b"OTHER=not-secret"]), &r, Path::new(STATE)).is_ok());
        for extra in [
            b"NELOMAI_MEMBER_LAUNCH_NONCE=wrong".as_slice(),
            b"NELOMAI_MEMBER_LAUNCH_NONCE=72cc17e2-0000-4000-8000-000000000001",
            b"WG_TUN_NAME_FILE=/foreign",
            b"WG_TUN_NAME_FILE=/private/var/run/nelomai/slot-a/interface-name",
        ] {
            assert!(check_arguments(&args(&[extra]), &r, Path::new(STATE)).is_err());
        }
        assert!(check_arguments(&args(&[]), &r, Path::new("/other-slot/interface-name")).is_err());
        let mut wrong = r.clone();
        wrong.launch_nonce.replace_range(35..36, "2");
        assert!(check_arguments(&args(&[]), &wrong, Path::new(STATE)).is_err());
        let mut argv_only = args(&[]);
        argv_only[..4].copy_from_slice(&4i32.to_ne_bytes());
        assert!(check_arguments(&argv_only, &r, Path::new(STATE)).is_err());
    }
    #[test]
    fn procargs_apple_vector_after_environment_is_not_launch_authority() {
        let r = receipt(MemberTransport::WireGuard);
        let mut b = args(&[]);
        b.extend_from_slice(b"\0\0ptr_munge=0x1234\0main_stack=0x1,0x2,0x3,0x4\0executable_file=0x1,0x2\0dyld_file=0x3,0x4\0executable_cdhash=0123456789abcdef\0executable_boothash=abcdef0123456789\0th_port=0x103\0security_config=0x0\0");
        // Auxiliary strings cannot override the already verified environment.
        b.extend_from_slice(b"NELOMAI_MEMBER_LAUNCH_NONCE=wrong\0WG_TUN_NAME_FILE=/foreign\0");
        assert!(check_arguments(&b, &r, Path::new(STATE)).is_ok());
    }
    #[test]
    fn procargs_apple_vector_cannot_supply_missing_environment_evidence() {
        let r = receipt(MemberTransport::WireGuard);
        for environment in [
            b"".as_slice(),
            b"NELOMAI_MEMBER_LAUNCH_NONCE=72cc17e2-0000-4000-8000-000000000001\0",
            b"WG_TUN_NAME_FILE=/private/var/run/nelomai/slot-a/interface-name\0",
        ] {
            let mut b = 2i32.to_ne_bytes().to_vec();
            b.extend_from_slice(b"/Library/Nelomai/awg\0\0\0awg\0-f\0");
            b.extend_from_slice(environment);
            b.extend_from_slice(b"\0ptr_munge=0x1234\0NELOMAI_MEMBER_LAUNCH_NONCE=72cc17e2-0000-4000-8000-000000000001\0WG_TUN_NAME_FILE=/private/var/run/nelomai/slot-a/interface-name\0");
            assert!(check_arguments(&b, &r, Path::new(STATE)).is_err());
        }
    }
    #[test]
    fn malformed_and_truncated_procargs_rejected_without_panics() {
        let r = receipt(MemberTransport::WireGuard);
        let b = args(&[]);
        for n in 0..b.len() {
            assert!(
                check_arguments(&b[..n], &r, Path::new(STATE)).is_err(),
                "len {n}"
            );
        }
        for argc in [-1i32, 0, i32::MAX] {
            let mut bad = b.clone();
            bad[..4].copy_from_slice(&argc.to_ne_bytes());
            assert!(check_arguments(&bad, &r, Path::new(STATE)).is_err());
        }
        assert!(check_arguments(&vec![0; MAX_ARGS + 1], &r, Path::new(STATE)).is_err());
    }

    #[test]
    fn connection_is_nonblocking_before_connect_and_releases_every_failed_handle() {
        struct SocketFake {
            calls: Vec<&'static str>,
            fail: usize,
            live: std::rc::Rc<std::cell::Cell<bool>>,
        }
        impl SocketFake {
            fn event(&mut self, name: &'static str) -> io::Result<()> {
                self.calls.push(name);
                if self.calls.len() == self.fail {
                    Err(invalid())
                } else {
                    Ok(())
                }
            }
        }
        impl SocketConnect for SocketFake {
            type Handle = FakeChannel;
            fn create(&mut self) -> io::Result<FakeChannel> {
                self.event("create")?;
                self.live.set(true);
                Ok(FakeChannel(self.live.clone()))
            }
            fn close_on_exec(&mut self, _: &FakeChannel) -> io::Result<()> {
                self.event("cloexec")
            }
            fn nonblocking(&mut self, _: &FakeChannel) -> io::Result<()> {
                self.event("nonblocking")
            }
            fn connect(&mut self, _: &FakeChannel, _: &Path) -> io::Result<()> {
                self.event("connect")
            }
        }
        for fail in 0..=4 {
            let mut fake = SocketFake {
                calls: vec![],
                fail,
                live: Default::default(),
            };
            let result = bounded_connection(&mut fake, Path::new("/var/run/wireguard/utun42.sock"));
            assert_eq!(result.is_ok(), fail == 0);
            assert_eq!(
                fake.calls,
                ["create", "cloexec", "nonblocking", "connect"][..if fail == 0 { 4 } else { fail }]
            );
            drop(result);
            assert!(!fake.live.get());
        }
    }
}
