//! User-private byte transport. TLS and HTTP remain owned by reqwest.
use std::{io, mem::size_of, ptr};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct LocalMemory(*mut core::ffi::c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(raw);
    let mut length = 0u32;
    if unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || length < size_of::<TOKEN_USER>() as u32
        || length > 64 * 1024
    {
        return Err(io::Error::other("control_pipe_identity_unavailable"));
    }
    // TOKEN_USER contains a pointer; use pointer-aligned backing storage.
    let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _memory = LocalMemory(sid.cast());
    if sid.is_null() {
        return Err(io::Error::other("control_pipe_identity_unavailable"));
    }
    let mut count = 0;
    while count < 256 && unsafe { *sid.add(count) } != 0 {
        count += 1;
    }
    if count == 256 {
        return Err(io::Error::other("control_pipe_identity_unavailable"));
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(sid, count) })
        .map_err(|_| io::Error::other("control_pipe_identity_unavailable"))
}

fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let sid = current_user_sid()?;
    // Protected DACL: exactly the current process user and Local System.
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _memory = LocalMemory(descriptor);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // The descriptor remains live until CreateNamedPipeW has copied it.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    }
}

pub(super) struct Listener {
    name: String,
    pending: Vec<NamedPipeServer>,
}

// Match the relay's bounded in-flight connection limit. ClientOptions::open
// does not wait for PIPE_BUSY, so all burst slots must exist before it runs.
const PENDING_INSTANCES: usize = 16;

pub(super) fn bind() -> io::Result<Listener> {
    let name = format!(r"\\.\pipe\nelomai-control-{}", uuid::Uuid::new_v4());
    let mut pending = Vec::with_capacity(PENDING_INSTANCES);
    for index in 0..PENDING_INSTANCES {
        pending.push(create(&name, index == 0)?);
    }
    Ok(Listener { name, pending })
}

impl Listener {
    pub fn configure(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder.windows_named_pipe(self.name.as_str())
    }

    pub async fn accept(&mut self) -> io::Result<super::relay::BoxIo> {
        if self.pending.is_empty() {
            return Err(io::Error::other("control_pipe_closed"));
        }
        let index = {
            let connections: Vec<_> = self
                .pending
                .iter()
                .map(|server| Box::pin(server.connect()))
                .collect();
            let (result, index, remaining) = futures_util::future::select_all(connections).await;
            drop(remaining);
            result?;
            index
        };
        // Replenish this slot before exposing its accepted stream. All other
        // pre-created instances remain available while the relay is scheduled.
        let next = match create(&self.name, false) {
            Ok(next) => next,
            Err(error) => {
                self.pending.clear();
                return Err(error);
            }
        };
        let accepted = std::mem::replace(&mut self.pending[index], next);
        Ok(Box::new(accepted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ClientOptions,
    };
    use windows_sys::Win32::Security::{
        AclSizeInformation,
        Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
        GetAce, GetAclInformation, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };

    #[tokio::test]
    async fn native_pipe_accepts_a_full_request_burst_before_listener_is_polled() {
        let mut listener = bind().unwrap();
        let mut clients = Vec::new();
        // The old single-instance listener fails the second open with PIPE_BUSY.
        for _ in 0..16 {
            clients.push(ClientOptions::new().open(&listener.name).unwrap());
        }
        for (index, client) in clients.iter_mut().enumerate() {
            client.write_all(&[index as u8]).await.unwrap();
        }
        let mut observed = Vec::new();
        for _ in 0..clients.len() {
            let mut accepted = listener.accept().await.unwrap();
            observed.push(accepted.read_u8().await.unwrap());
        }
        observed.sort();
        assert_eq!(observed, (0..16).collect::<Vec<u8>>());
    }

    #[tokio::test]
    async fn native_pipe_successor_is_ready_and_drop_leaves_accepted_stream_alive() {
        let mut listener = bind().unwrap();
        let name = listener.name.clone();
        let mut first_client = ClientOptions::new().open(&name).unwrap();
        let mut first = listener.accept().await.unwrap();
        // Opening immediately proves the next instance precedes accept's return.
        let mut second_client = ClientOptions::new().open(&name).unwrap();
        let mut second = listener.accept().await.unwrap();
        drop(listener);
        assert!(ClientOptions::new().open(&name).is_err());
        first_client.write_all(b"one").await.unwrap();
        second_client.write_all(b"two").await.unwrap();
        let mut buffer = [0; 3];
        first.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"one");
        second.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"two");
    }

    #[tokio::test]
    async fn native_pipe_dacl_has_only_current_user_and_system() {
        let listener = bind().unwrap();
        let handle = listener.pending[0].as_raw_handle();
        let mut descriptor = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0);
        let _memory = LocalMemory(descriptor);
        let mut control = 0u16;
        let mut revision = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        assert!(!dacl.is_null());
        let mut size = ACL_SIZE_INFORMATION::default();
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        assert_eq!(size.AceCount, 2);
        let mut sids = Vec::new();
        for index in 0..2 {
            let mut raw = ptr::null_mut();
            assert_ne!(unsafe { GetAce(dacl, index, &mut raw) }, 0);
            let header = unsafe { &*raw.cast::<ACE_HEADER>() };
            assert_eq!(header.AceType, 0); // ACCESS_ALLOWED_ACE_TYPE
            let ace = raw.cast::<ACCESS_ALLOWED_ACE>();
            let sid = unsafe { ptr::addr_of!((*ace).SidStart).cast_mut().cast() };
            let mut text = ptr::null_mut();
            assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
            let _text_memory = LocalMemory(text.cast());
            let mut length = 0;
            while unsafe { *text.add(length) } != 0 {
                length += 1;
            }
            sids.push(
                String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap(),
            );
        }
        sids.sort();
        let mut expected = vec!["S-1-5-18".to_string(), current_user_sid().unwrap()];
        expected.sort();
        assert_eq!(sids, expected);
    }

    #[tokio::test]
    async fn native_pipe_name_cannot_be_claimed_as_another_first_instance() {
        let listener = bind().unwrap();
        assert!(create(&listener.name, true).is_err());
        let client = ClientOptions::new().open(&listener.name).unwrap();
        drop(client);
    }
}
