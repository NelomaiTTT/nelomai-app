use std::{
    ffi::CStr,
    io,
    mem::size_of,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
pub(super) struct Utun {
    fd: OwnedFd,
    name: String,
    ifindex: u32,
}

pub(super) struct GuardedEngine {
    guardian: Option<UnixStream>,
    child: Child,
}

impl GuardedEngine {
    pub(super) fn stop(&mut self) -> io::Result<()> {
        drop(self.guardian.take());
        let deadline = Instant::now() + super::START_TIMEOUT;
        while self.child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                return Err(io::Error::other("userspace_cleanup_pending"));
            }
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

impl Drop for GuardedEngine {
    fn drop(&mut self) {
        drop(self.guardian.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Utun {
    pub(super) fn open() -> io::Result<Self> {
        let (fd, address) = control_socket(0)?; // The kernel selects a free unit.
        if unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ctl).cast(),
                address.sc_len as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut name = [0u8; libc::IFNAMSIZ];
        let mut name_len = name.len() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut name_len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let name = CStr::from_bytes_with_nul(name.get(..name_len as usize).unwrap_or_default())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        let name = name
            .to_str()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .to_owned();
        Ok(Self { fd, name, ifindex })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub(super) fn launch(
        &self,
        mut command: Command,
        uapi: &UnixListener,
    ) -> io::Result<GuardedEngine> {
        command.process_group(0);
        let guardian = nelomai_contracts::dispatcher::own_process_group(&mut command)?;
        let child = self.spawn(command, uapi)?;
        Ok(GuardedEngine {
            guardian: Some(guardian),
            child,
        })
    }

    fn spawn(&self, mut command: Command, uapi: &UnixListener) -> io::Result<Child> {
        // The foreground engine uses the inherited descriptors directly. Only
        // these two private duplicates lose CLOEXEC, and only in the child.
        let tun = duplicate_cloexec(self.fd.as_raw_fd(), libc::STDERR_FILENO + 1)?;
        let uapi = duplicate_cloexec(uapi.as_raw_fd(), libc::STDERR_FILENO + 1)?;
        let tun_fd = tun.as_raw_fd();
        let uapi_fd = uapi.as_raw_fd();
        command
            .env("WG_PROCESS_FOREGROUND", "1")
            .env("WG_TUN_FD", tun_fd.to_string())
            .env("WG_UAPI_FD", uapi_fd.to_string());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(tun_fd, libc::F_SETFD, 0) < 0
                    || libc::fcntl(uapi_fd, libc::F_SETFD, 0) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }
}

fn duplicate_cloexec(fd: RawFd, minimum: RawFd) -> io::Result<OwnedFd> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// Bind reserves a unit independently of connecting it as a network
/// interface. Use this while retiring an orphaned socket to exclude a new
/// tunnel claiming the same name in the meantime.
pub(super) fn reserve_name(name: &str) -> io::Result<OwnedFd> {
    let unit = name
        .strip_prefix("utun")
        .and_then(|number| number.parse::<u32>().ok())
        .and_then(|number| number.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid utun name"))?;
    let (fd, address) = control_socket(unit)?;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_ctl).cast(),
            address.sc_len as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn control_socket(unit: u32) -> io::Result<(OwnedFd, libc::sockaddr_ctl)> {
    let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // Darwin supplies no SOCK_CLOEXEC socket flag.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if fd.as_raw_fd() <= libc::STDERR_FILENO {
        fd = duplicate_cloexec(fd.as_raw_fd(), libc::STDERR_FILENO + 1)?;
    }
    let mut control = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; libc::MAX_KCTL_NAME],
    };
    for (dest, &byte) in control.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *dest = byte as libc::c_char;
    }
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::CTLIOCGINFO,
            &mut control as *mut libc::ctl_info,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((
        fd,
        libc::sockaddr_ctl {
            sc_len: size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: control.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, os::fd::AsRawFd, os::unix::net::UnixStream, time::Duration};

    #[test]
    fn passes_tunnel_descriptor_only_to_the_configured_child() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let utun = Utun {
            fd: socket.into(),
            name: "utun42".into(),
            ifindex: 99,
        };
        let directory = tempfile::tempdir().unwrap();
        let uapi = UnixListener::bind(directory.path().join("uapi")).unwrap();
        let fd = utun.fd.as_raw_fd();
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            r#"test "$WG_PROCESS_FOREGROUND" = 1 &&
                test -S "/dev/fd/$WG_UAPI_FD" &&
                eval "printf ready >&$WG_TUN_FD""#,
        ]);
        assert!(utun
            .spawn(command, &uapi)
            .unwrap()
            .wait()
            .unwrap()
            .success());

        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut message = [0; 5];
        peer.read_exact(&mut message).unwrap();
        assert_eq!(&message, b"ready");
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, libc::FD_CLOEXEC);
        assert_eq!(
            unsafe { libc::fcntl(uapi.as_raw_fd(), libc::F_GETFD) },
            libc::FD_CLOEXEC
        );
        assert_eq!(
            utun.spawn(Command::new(directory.path().join("missing")), &uapi)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    }
}
