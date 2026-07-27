use super::{platform_error, wide};
use crate::{
    authorize_client, decode_request, decode_response, encode_request, encode_response,
    pipe_security_descriptor, ClientIdentity, ClientPolicy, Request, Response, ServiceError,
    ServiceTransport, MAX_FRAME_SIZE, PIPE_NAME,
};
use async_trait::async_trait;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenThreadToken, QueryFullProcessImageNameW,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

pub struct NamedPipeTransport;

impl NamedPipeTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NamedPipeTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ServiceTransport for NamedPipeTransport {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
        tokio::task::spawn_blocking(move || exchange_blocking(request))
            .await
            .map_err(|error| platform_error("join named pipe operation", error))?
    }
}

pub(crate) struct PipeServer {
    policy: ClientPolicy,
}

impl PipeServer {
    pub(crate) fn new(policy: ClientPolicy) -> Self {
        Self { policy }
    }

    pub(crate) fn accept(&self) -> Result<Option<(Request, HANDLE)>, ServiceError> {
        let descriptor =
            SecurityDescriptor::from_sddl(&pipe_security_descriptor(&self.policy.owner_sid)?)?;
        let attributes = descriptor.attributes();
        let pipe_name = wide(PIPE_NAME);
        let pipe = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                (MAX_FRAME_SIZE + 4) as u32,
                (MAX_FRAME_SIZE + 4) as u32,
                0,
                &attributes,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(last_error("create named pipe"));
        }

        let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            unsafe {
                CloseHandle(pipe);
            }
            return Err(last_error("connect named pipe"));
        }

        let result = (|| {
            // Windows exposes the pipe client's impersonation token only after
            // the server has read data from that client.
            let frame = read_frame(pipe)?;
            let identity = identity_for_pipe_client(pipe)?;
            authorize_client(&self.policy, &identity).map_err(|_| {
                ServiceError::Backend(format!(
                    "authorize pipe client: actual SID {}, expected SID {}, actual path {}, expected path {}",
                    identity.sid,
                    self.policy.owner_sid,
                    identity.process_path.display(),
                    self.policy.installed_client_path.display()
                ))
            })?;
            let request = decode_request(&frame)?;
            Ok(Some((request, pipe)))
        })();

        if result.is_err() {
            unsafe {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
        }
        result
    }
}

pub(crate) fn finish_request(pipe: HANDLE, response: &Response) -> Result<(), ServiceError> {
    let result = (|| {
        write_all(pipe, &encode_response(response)?)?;
        unsafe {
            FlushFileBuffers(pipe);
        }
        Ok(())
    })();
    unsafe {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    result
}

pub(crate) fn wake_server() {
    let pipe_name = wide(PIPE_NAME);
    let handle = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle != INVALID_HANDLE_VALUE {
        unsafe {
            CloseHandle(handle);
        }
    }
}

fn exchange_blocking(request: Request) -> Result<Response, ServiceError> {
    let pipe_name = wide(PIPE_NAME);
    let pipe = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(last_error("open named pipe"));
    }
    let result = (|| {
        write_all(pipe, &encode_request(&request)?)?;
        decode_response(&read_frame(pipe)?)
    })();
    unsafe {
        CloseHandle(pipe);
    }
    result
}

fn read_frame(handle: HANDLE) -> Result<Vec<u8>, ServiceError> {
    let mut header = [0u8; 4];
    read_exact(handle, &mut header)?;
    let body_length = u32::from_le_bytes(header) as usize;
    if body_length > MAX_FRAME_SIZE {
        return Err(ServiceError::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(body_length + 4);
    frame.extend_from_slice(&header);
    frame.resize(body_length + 4, 0);
    read_exact(handle, &mut frame[4..])?;
    Ok(frame)
}

fn read_exact(handle: HANDLE, mut buffer: &mut [u8]) -> Result<(), ServiceError> {
    while !buffer.is_empty() {
        let mut read = 0u32;
        let success = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                &mut read,
                null_mut(),
            )
        };
        if success == 0 || read == 0 {
            return Err(ServiceError::TruncatedFrame);
        }
        buffer = &mut buffer[read as usize..];
    }
    Ok(())
}

fn write_all(handle: HANDLE, mut buffer: &[u8]) -> Result<(), ServiceError> {
    while !buffer.is_empty() {
        let mut written = 0u32;
        let success = unsafe {
            WriteFile(
                handle,
                buffer.as_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                &mut written,
                null_mut(),
            )
        };
        if success == 0 || written == 0 {
            return Err(last_error("write named pipe"));
        }
        buffer = &buffer[written as usize..];
    }
    Ok(())
}

fn identity_for_pipe_client(pipe: HANDLE) -> Result<ClientIdentity, ServiceError> {
    let process_path = process_path_for_pipe_client(pipe)?;
    let sid = sid_for_pipe_client(pipe)?;
    Ok(ClientIdentity { sid, process_path })
}

fn process_path_for_pipe_client(pipe: HANDLE) -> Result<PathBuf, ServiceError> {
    let mut process_id = 0u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0 {
        return Err(last_error("read named pipe client process"));
    }
    let process =
        OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) })?;
    let mut path = vec![0u16; 32_768];
    let mut length = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.raw(), 0, path.as_mut_ptr(), &mut length) } == 0
    {
        return Err(last_error("read named pipe client path"));
    }
    path.truncate(length as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&path)))
}

fn sid_for_pipe_client(pipe: HANDLE) -> Result<String, ServiceError> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(last_error("impersonate named pipe client"));
    }
    let _revert = RevertGuard;
    let token = {
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(last_error("open named pipe client token"));
        }
        OwnedHandle(token)
    };

    let mut required = 0u32;
    unsafe {
        GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &mut required);
    }
    if required == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_error("size named pipe client token"));
    }
    let mut buffer = vec![0u8; required as usize];
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_error("read named pipe client token"));
    }
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(token_user.User.Sid)
}

fn sid_to_string(sid: *mut c_void) -> Result<String, ServiceError> {
    let mut value = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(last_error("convert client SID"));
    }
    let result = unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    };
    unsafe {
        LocalFree(value.cast());
    }
    Ok(result)
}

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, ServiceError> {
        let sddl = wide(sddl);
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(last_error("build security descriptor"));
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self, ServiceError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(last_error("open Windows handle"))
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct RevertGuard;

impl Drop for RevertGuard {
    fn drop(&mut self) {
        unsafe {
            RevertToSelf();
        }
    }
}

fn last_error(context: &str) -> ServiceError {
    platform_error(context, io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use super::super::elevation::current_process_sid;
    use super::{exchange_blocking, finish_request, PipeServer};
    use crate::{ClientPolicy, Request, Response};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn named_pipe_round_trip_reads_before_impersonation() {
        let policy = ClientPolicy {
            owner_sid: current_process_sid().expect("read current process SID"),
            installed_client_path: std::env::current_exe().expect("resolve test executable"),
        };
        let server = PipeServer::new(policy);
        let server_thread = thread::spawn(move || {
            let (request, pipe) = server
                .accept()
                .expect("accept pipe request")
                .expect("receive pipe request");
            assert!(matches!(request, Request::Version { .. }));
            let mut response = Response::success(None);
            response.service_version = Some("test".to_string());
            finish_request(pipe, &response).expect("send pipe response");
        });

        thread::sleep(Duration::from_millis(100));
        let response =
            exchange_blocking(Request::version()).expect("complete named pipe round trip");
        assert_eq!(response.service_version.as_deref(), Some("test"));
        server_thread.join().expect("join pipe server");
    }
}
