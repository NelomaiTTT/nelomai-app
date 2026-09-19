//! Keychain stays in the common process. Runtime owns record semantics, but
//! accesses only its admitted records through an anonymous, dedicated socket.
use nelomai_client_storage::{ProtectedRecordStore, StorageError};
use std::{
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::{Arc, Mutex},
    time::Duration,
};

// Separate from tunnel/auth IPC: storage can be needed while those channels
// are waiting for runtime cleanup. It must not share their request mutex.
const MAX_FRAME: usize = 8 * 1024 * 1024;
fn failed() -> io::Error {
    io::Error::other("private runtime storage unavailable")
}
fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(failed());
    }
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(bytes)
}
fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_le_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(failed());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub(crate) struct StorageClient(Mutex<Option<UnixStream>>);
impl StorageClient {
    pub(crate) fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_read_timeout(Some(Duration::from_secs(130)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self(Mutex::new(Some(stream))))
    }
    fn exchange(&self, body: &[u8]) -> Result<Vec<u8>, StorageError> {
        let mut guard = self.0.lock().map_err(|_| failed())?;
        let result = (|| {
            let stream = guard.as_mut().ok_or_else(failed)?;
            write_frame(stream, body)?;
            read_frame(stream)
        })();
        match result {
            Ok(reply) if reply == [255] => Err(failed().into()),
            Ok(reply) => Ok(reply),
            Err(_) => {
                *guard = None;
                Err(failed().into())
            }
        }
    }
}
pub(crate) struct RemoteRecord {
    client: Arc<StorageClient>,
    index: u8,
}
impl RemoteRecord {
    pub(crate) fn new(client: Arc<StorageClient>, index: u8) -> Self {
        Self { client, index }
    }
}
impl ProtectedRecordStore for RemoteRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let reply = self.client.exchange(&[1, self.index])?;
        match reply.as_slice() {
            [0] => Ok(None),
            [1, bytes @ ..] => Ok(Some(bytes.to_vec())),
            _ => Err(failed().into()),
        }
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        if bytes.len() > MAX_FRAME - 2 {
            return Err(failed().into());
        }
        let mut body = Vec::with_capacity(bytes.len() + 2);
        body.extend([2, self.index]);
        body.extend_from_slice(bytes);
        if self.client.exchange(&body)? == [0] {
            Ok(())
        } else {
            Err(failed().into())
        }
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        if self.client.exchange(&[3, self.index])? == [0] {
            Ok(())
        } else {
            Err(failed().into())
        }
    }
}
pub(crate) fn serve<R: ProtectedRecordStore>(mut stream: UnixStream, records: Vec<R>) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    while let Ok(body) = read_frame(&mut stream) {
        let result = (|| -> Result<Vec<u8>, StorageError> {
            let (&op, rest) = body.split_first().ok_or_else(failed)?;
            let (&index, data) = rest.split_first().ok_or_else(failed)?;
            let record = records.get(index as usize).ok_or_else(failed)?;
            match op {
                1 if data.is_empty() => match record.load_record()? {
                    None => Ok(vec![0]),
                    Some(bytes) if bytes.len() < MAX_FRAME => {
                        let mut reply = vec![1];
                        reply.extend(bytes);
                        Ok(reply)
                    }
                    _ => Err(failed().into()),
                },
                2 => {
                    record.save_record(data)?;
                    Ok(vec![0])
                }
                3 if data.is_empty() => {
                    record.delete_record()?;
                    Ok(vec![0])
                }
                _ => Err(failed().into()),
            }
        })();
        if write_frame(&mut stream, &result.unwrap_or_else(|_| vec![255])).is_err() {
            break;
        }
    }
}

// A single SCM_RIGHTS endpoint, transferred only over the already inherited
// and verified native socket. No filesystem socket, listener or public name.
#[repr(C)]
struct Control {
    header: libc::cmsghdr,
    fd: libc::c_int,
}
pub(crate) fn send_endpoint(stream: &mut UnixStream, endpoint: &UnixStream) -> io::Result<()> {
    let mut byte = 1u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = Control {
        header: libc::cmsghdr {
            cmsg_len: unsafe { libc::CMSG_LEN(4) },
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
        },
        fd: endpoint.as_raw_fd(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&mut control as *mut Control).cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) };
    if unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) } != 1 {
        return Err(failed());
    }
    Ok(())
}
pub(crate) fn receive_endpoint(stream: &mut UnixStream) -> io::Result<UnixStream> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control: Control = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&mut control as *mut Control).cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) };
    if unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) } != 1 {
        return Err(failed());
    }
    if msg.msg_controllen < unsafe { libc::CMSG_LEN(4) }
        || control.header.cmsg_level != libc::SOL_SOCKET
        || control.header.cmsg_type != libc::SCM_RIGHTS
    {
        return Err(failed());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(control.fd) };
    if byte != 1
        || msg.msg_flags & libc::MSG_CTRUNC != 0
        || control.header.cmsg_len != unsafe { libc::CMSG_LEN(4) }
    {
        return Err(failed());
    }
    // Called once before run_product creates runtime threads/subprocesses.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket: UnixStream = fd.into();
    socket.peer_addr()?;
    Ok(socket)
}

#[cfg(test)]
#[path = "macos_storage_tests.rs"]
mod tests;
