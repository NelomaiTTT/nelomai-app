//! Desktop launch admission. Signed payload verification precedes process creation;
//! the launcher retains process and private endpoint ownership through admission.
use nelomai_contracts::{
    dispatcher::{blocked, file_digest, trusted},
    RuntimeFileRole, RuntimeSlot, VerifiedContainerManifest,
};
use std::{
    io,
    path::{Path, PathBuf},
};
#[cfg(windows)]
#[path = "desktop/windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::{capture_inherited_channels, verify_protected_path, NativeStream, VerifiedChild};

/// A fixed one-byte channel tag followed by an existing little-endian frame.
/// Engine JSON retains its full 1 MiB budget; native control uses 64 KiB. There
/// is no JSON/base64 envelope that can multiply either allocation budget.
pub fn write_native_frame(writer: &mut impl io::Write, tag: u8, body: &[u8]) -> io::Result<()> {
    let limit = native_limit(tag)?;
    if body.len() > limit {
        return Err(blocked());
    }
    writer.write_all(&[tag])?;
    writer.write_all(&(body.len() as u32).to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}
pub fn read_native_frame(reader: &mut impl io::Read) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    reader.read_exact(&mut header)?;
    let limit = native_limit(header[0])?;
    let len = u32::from_le_bytes(header[1..].try_into().map_err(|_| blocked())?) as usize;
    if len > limit {
        return Err(blocked());
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body)?;
    Ok((header[0], body))
}
fn native_limit(tag: u8) -> io::Result<usize> {
    match tag {
        1 => Ok(1024 * 1024),
        2 | 255 => Ok(65536),
        _ => Err(blocked()),
    }
}

pub async fn stop_runtime_before_helper(
    process: &std::sync::Mutex<Option<VerifiedChild>>,
    helper: impl std::future::Future<Output = io::Result<()>>,
) -> io::Result<()> {
    {
        let mut child = process.lock().map_err(|_| blocked())?;
        if let Some(child) = child.as_mut() {
            child.terminate()?;
        }
    }
    helper.await
}

pub struct VerifiedRuntime {
    root: PathBuf,
    executable: PathBuf,
    manifest: VerifiedContainerManifest,
    slot: RuntimeSlot,
    owner: u32,
}
impl VerifiedRuntime {
    pub fn open(
        root: &Path,
        key: &[u8],
        slot: RuntimeSlot,
        platform: &str,
        architecture: &str,
        owner: u32,
    ) -> io::Result<Self> {
        trusted(root, owner)?;
        for name in ["container-manifest-v1.json", "container-manifest-v1.sig"] {
            trusted(&root.join(name), owner)?;
        }
        let manifest = crate::installed_runtime::verify_installed_manifest(
            root,
            Some(key),
            platform,
            architecture,
        )?;
        Self::from_verified(root, manifest, slot, owner)
    }
    pub(crate) fn from_verified(
        root: &Path,
        manifest: VerifiedContainerManifest,
        slot: RuntimeSlot,
        owner: u32,
    ) -> io::Result<Self> {
        let runtime = manifest.selected(slot).ok_or_else(blocked)?;
        let name = if runtime.platform == "windows" {
            "nelomai-runtime.exe"
        } else {
            "nelomai-runtime"
        };
        if !runtime
            .files
            .iter()
            .any(|entry| entry.path == name && entry.role == RuntimeFileRole::Executable)
        {
            return Err(blocked());
        }
        let executable = root
            .join("engines")
            .join(match slot {
                RuntimeSlot::Latest => "latest",
                RuntimeSlot::Stable => "stable",
            })
            .join(&runtime.runtime_version)
            .join(name);
        let verified = Self {
            root: root.into(),
            executable,
            manifest,
            slot,
            owner,
        };
        verified.reverify()?;
        Ok(verified)
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn container_version(&self) -> &str {
        &self.manifest.manifest().container_version
    }
    pub fn resource_root(&self) -> &Path {
        self.executable
            .parent()
            .expect("verified executable parent")
    }
    pub(crate) fn reverify(&self) -> io::Result<()> {
        trusted(&self.root, self.owner)?;
        let runtime = self.manifest.selected(self.slot).ok_or_else(blocked)?;
        let mut root = self.root.clone();
        for part in [
            "engines",
            match self.slot {
                RuntimeSlot::Latest => "latest",
                RuntimeSlot::Stable => "stable",
            },
            runtime.runtime_version.as_str(),
        ] {
            root.push(part);
            trusted(&root, self.owner)?;
        }
        for entry in &runtime.files {
            let mut path = root.clone();
            for part in Path::new(&entry.path).components() {
                path.push(part);
                trusted(&path, self.owner)?;
            }
            let metadata = std::fs::metadata(&path)?;
            if !metadata.is_file()
                || metadata.len() != entry.size_bytes
                || file_digest(&path)? != entry.sha256
            {
                return Err(blocked());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if entry.role == RuntimeFileRole::Executable
                    && (metadata.permissions().mode() & 0o111 == 0
                        || metadata.permissions().mode() & 0o6000 != 0)
                {
                    return Err(blocked());
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use unix::{capture_inherited_channels, VerifiedChild};
#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{net::UnixStream, process::CommandExt},
        },
        process::{Child, Command, Stdio},
        time::Duration,
    };
    const HELLO: &[u8; 12] = b"NELORUNTIME1";
    const ENVIRONMENT: &[&str] = &[
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "LANG",
        "LC_ALL",
    ];
    pub struct VerifiedChild {
        pub(crate) target: nelomai_client_api::RuntimeTarget,
        executable: PathBuf,
        process: Child,
        auth: Option<UnixStream>,
        native: Option<UnixStream>,
    }
    impl Drop for VerifiedChild {
        fn drop(&mut self) {
            let _ = self.terminate();
        }
    }
    impl VerifiedRuntime {
        pub fn spawn(&self) -> io::Result<VerifiedChild> {
            self.reverify()?;
            let (mut auth, child_auth) = UnixStream::pair()?;
            let (native, child_native) = UnixStream::pair()?;
            // Keep sources outside fixed destination descriptors, including
            // when another thread's descriptors were allocated between pairs.
            let duplicate = |fd: i32| -> io::Result<OwnedFd> {
                let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            };
            let auth_source = duplicate(child_auth.as_raw_fd())?;
            let native_source = duplicate(child_native.as_raw_fd())?;
            let mut command = Command::new(&self.executable);
            command
                .arg("--private-runtime-v1")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            for name in ENVIRONMENT {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            #[cfg(target_os = "linux")]
            if std::env::current_exe()?
                == Path::new("/usr/local/libexec/nelomai/common/AppDir/usr/bin/nelomai-app")
            {
                let appdir = Path::new("/usr/local/libexec/nelomai/common/AppDir");
                trusted(appdir, 0)?;
                command.env("APPDIR",appdir)
                    .env("LD_LIBRARY_PATH","/usr/local/libexec/nelomai/common/AppDir/usr/lib:/usr/local/libexec/nelomai/common/AppDir/usr/lib/x86_64-linux-gnu")
                    .env("GSETTINGS_SCHEMA_DIR",appdir.join("usr/share/glib-2.0/schemas"));
            }
            let auth_fd = auth_source.as_raw_fd();
            let native_fd = native_source.as_raw_fd();
            // Only the forked child clears CLOEXEC. Parent and unrelated spawn
            // calls never observe an inheritable copy of either private socket.
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(auth_fd, 3) < 0 || libc::dup2(native_fd, 4) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let process = command.spawn()?;
            drop((child_auth, child_native, auth_source, native_source));
            let identity = self
                .manifest
                .identity(self.slot, None)
                .map_err(|_| blocked())?;
            let mut child = VerifiedChild {
                target: nelomai_client_api::RuntimeTarget {
                    container_version: identity.container_version,
                    runtime_version: identity.runtime_version,
                    runtime_contract_version: identity.runtime_contract_version,
                    runtime_slot: identity.slot,
                },
                executable: std::fs::canonicalize(&self.executable)?,
                process,
                auth: None,
                native: Some(native),
            };
            auth.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut hello = [0; 12];
            auth.read_exact(&mut hello)?;
            if &hello != HELLO || child.kernel_executable()? != child.executable {
                return Err(blocked());
            }
            self.reverify()?;
            auth.set_read_timeout(None)?;
            child.auth = Some(auth);
            Ok(child)
        }
    }
    impl VerifiedChild {
        pub fn native(&mut self) -> &mut UnixStream {
            self.native
                .as_mut()
                .expect("native endpoint not yet transferred")
        }
        pub fn take_native(&mut self) -> io::Result<UnixStream> {
            self.native.take().ok_or_else(blocked)
        }
        pub(crate) fn take_auth(&mut self) -> io::Result<UnixStream> {
            self.auth.take().ok_or_else(blocked)
        }
        pub fn id(&self) -> u32 {
            self.process.id()
        }
        pub fn kernel_executable(&self) -> io::Result<PathBuf> {
            kernel_executable(self.process.id())
        }
        pub fn exited(&mut self) -> io::Result<bool> {
            Ok(self.process.try_wait()?.is_some())
        }
        pub fn terminate(&mut self) -> io::Result<()> {
            if !self.exited()? {
                self.process.kill()?;
                self.process.wait()?;
            }
            Ok(())
        }
        pub(crate) fn verify_alive(&mut self) -> io::Result<()> {
            if self.exited()? || self.kernel_executable()? != self.executable {
                return Err(blocked());
            }
            Ok(())
        }
    }
    pub fn capture_inherited_channels() -> io::Result<(UnixStream, UnixStream)> {
        if std::env::args().nth(1).as_deref() != Some("--private-runtime-v1")
            || std::env::args().count() != 2
        {
            return Err(blocked());
        }
        for fd in [3, 4] {
            let mut kind = 0;
            let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut kind as *mut i32).cast(),
                    &mut len,
                )
            } != 0
                || kind != libc::SOCK_STREAM
            {
                return Err(blocked());
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: this is called once at the runtime binary entry point, before
        // creating threads or launching any external process.
        let mut auth = unsafe { UnixStream::from_raw_fd(3) };
        let native = unsafe { UnixStream::from_raw_fd(4) };
        auth.write_all(HELLO)?;
        Ok((auth, native))
    }
    fn kernel_executable(pid: u32) -> io::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_link(format!("/proc/{pid}/exe"))
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut path = vec![0u8; 4096];
            if unsafe {
                libc::proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32)
            } <= 0
            {
                return Err(io::Error::last_os_error());
            }
            let end = path
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(blocked)?;
            Ok(PathBuf::from(std::ffi::OsString::from_vec(
                path[..end].to_vec(),
            )))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            Err(blocked())
        }
    }
}
