use super::wide;
use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use std::ptr::null_mut;
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER, HANDLE,
    WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

#[derive(Debug, Error)]
pub enum RepairError {
    #[error("required Windows tunnel resources are missing")]
    ResourcesUnavailable,
    #[error("Windows administrator authorization was cancelled")]
    Cancelled,
    #[error("Windows administrator authorization failed: {0}")]
    AuthorizationUnavailable(String),
    #[error("Windows tunnel service installation failed with exit code {0}")]
    InstallFailed(u32),
}

pub fn repair_installation(
    service_executable: &Path,
    client_executable: &Path,
) -> Result<(), RepairError> {
    if !service_executable.is_file() || !client_executable.is_file() {
        return Err(RepairError::ResourcesUnavailable);
    }

    let owner_sid = current_process_sid()?;
    let parameters = install_parameters(&owner_sid, client_executable)?;
    run_elevated(service_executable, &parameters)
}

fn install_parameters(owner_sid: &str, client_executable: &Path) -> Result<String, RepairError> {
    let client_executable = client_executable.to_string_lossy();
    if owner_sid.is_empty()
        || owner_sid.contains('"')
        || client_executable.is_empty()
        || client_executable.contains('"')
    {
        return Err(RepairError::ResourcesUnavailable);
    }
    Ok(format!(
        "install --owner-sid \"{owner_sid}\" --client-path \"{client_executable}\""
    ))
}

fn current_process_sid() -> Result<String, RepairError> {
    let token = {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_authorization_error("open current process token"));
        }
        OwnedHandle(token)
    };

    let mut required = 0u32;
    unsafe {
        GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &mut required);
    }
    if required == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_authorization_error("size current process token"));
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
        return Err(last_authorization_error("read current process token"));
    }

    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut value = null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut value) } == 0 {
        return Err(last_authorization_error("convert current process SID"));
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

fn run_elevated(executable: &Path, parameters: &str) -> Result<(), RepairError> {
    let verb = wide("runas");
    let executable = wide(executable.as_os_str());
    let parameters = wide(parameters);
    let mut execute_info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };

    if unsafe { ShellExecuteExW(&mut execute_info) } == 0 {
        return match unsafe { GetLastError() } {
            ERROR_CANCELLED => Err(RepairError::Cancelled),
            _ => Err(last_authorization_error("start elevated service installer")),
        };
    }

    let process = OwnedHandle(execute_info.hProcess);
    let wait_result = unsafe { WaitForSingleObject(process.raw(), INFINITE) };
    if wait_result == WAIT_FAILED {
        return Err(last_authorization_error(
            "wait for elevated service installer",
        ));
    }
    if wait_result != WAIT_OBJECT_0 {
        return Err(RepairError::AuthorizationUnavailable(format!(
            "unexpected wait result {wait_result}"
        )));
    }

    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } == 0 {
        return Err(last_authorization_error(
            "read elevated service installer result",
        ));
    }
    if exit_code == 0 {
        Ok(())
    } else {
        Err(RepairError::InstallFailed(exit_code))
    }
}

fn last_authorization_error(context: &str) -> RepairError {
    RepairError::AuthorizationUnavailable(format!("{context}: {}", std::io::Error::last_os_error()))
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::install_parameters;
    use std::path::Path;

    #[test]
    fn quotes_installation_parameters() {
        assert_eq!(
            install_parameters(
                "S-1-5-21-123",
                Path::new(r"C:\Program Files\Nelomai\nelomai-app.exe")
            )
            .unwrap(),
            r#"install --owner-sid "S-1-5-21-123" --client-path "C:\Program Files\Nelomai\nelomai-app.exe""#
        );
    }

    #[test]
    fn rejects_unsafe_installation_parameters() {
        assert!(install_parameters("S-1-5-21-123", Path::new(r#"C:\Nelomai"\app.exe"#)).is_err());
    }
}
