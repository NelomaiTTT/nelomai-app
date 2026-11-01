//! Observe IPC peer closure separately from its directional read EOF.
use std::{
    future::Future,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    pin::Pin,
};
pub(super) fn watch(
    socket: &tokio::net::UnixStream,
) -> io::Result<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>> {
    // Monitor a private event queue, not writable readiness on the data socket.
    // Its readiness is cleared only after the queue actually returns WouldBlock.
    let queue = tokio::io::unix::AsyncFd::with_interest(
        queue(socket.as_raw_fd())?,
        tokio::io::Interest::READABLE,
    )?;
    Ok(Box::pin(async move {
        loop {
            let mut ready = queue.readable().await?;
            match ready.try_io(|queue| closed(queue.as_raw_fd())) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }))
}
#[cfg(target_os = "macos")]
fn queue(socket: RawFd) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::kqueue() };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let change = libc::kevent {
        ident: socket as _,
        filter: libc::EVFILT_WRITE,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags: libc::NOTE_LOWAT,
        data: i32::MAX as _,
        udata: std::ptr::null_mut(),
    };
    if unsafe { libc::kevent(fd, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(queue)
}
#[cfg(target_os = "macos")]
fn closed(queue: RawFd) -> io::Result<()> {
    loop {
        let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let count =
            unsafe { libc::kevent(queue, std::ptr::null(), 0, event.as_mut_ptr(), 1, &timeout) };
        if count < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let event = unsafe { event.assume_init() };
        if event.flags & libc::EV_ERROR != 0 && event.data != 0 {
            return Err(io::Error::from_raw_os_error(event.data as i32));
        }
        if event.flags & libc::EV_EOF != 0 {
            return Ok(());
        }
        // Drain ordinary writable events until the queue is actually empty.
    }
}
#[cfg(target_os = "linux")]
fn queue(socket: RawFd) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(fd) };
    // HUP/ERR are delivered without requesting normal writable/readable events.
    // Peer write-half shutdown (RDHUP) alone must not terminate a response.
    let mut event = libc::epoll_event { events: 0, u64: 0 };
    if unsafe { libc::epoll_ctl(fd, libc::EPOLL_CTL_ADD, socket, &mut event) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(queue)
}
#[cfg(target_os = "linux")]
fn closed(queue: RawFd) -> io::Result<()> {
    loop {
        let mut event = std::mem::MaybeUninit::<libc::epoll_event>::uninit();
        let count = unsafe { libc::epoll_wait(queue, event.as_mut_ptr(), 1, 0) };
        if count < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let event = unsafe { event.assume_init() };
        if event.events & (libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
            return Ok(());
        }
    }
}
