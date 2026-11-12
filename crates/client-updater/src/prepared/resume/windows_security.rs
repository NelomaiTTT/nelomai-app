// FILE_GENERIC_READ and FILE_GENERIC_EXECUTE, plus their unmapped generic
// equivalents. Untrusted trustees may only receive these access bits.
const READ_ONLY: u32 = 0xa012_00a9;

fn ace_allowed(kind: u8, mask: u32, trusted: bool) -> bool {
    match kind {
        0 => trusted || mask & !READ_ONLY == 0, // ACCESS_ALLOWED_ACE_TYPE
        1 => true,                              // ACCESS_DENIED_ACE_TYPE
        _ => false,
    }
}

#[cfg(windows)]
pub(super) use native::{private_directory, private_file};

#[cfg(windows)]
mod native {
    use super::ace_allowed;
    use std::{
        ffi::c_void,
        fs::File,
        mem::{offset_of, size_of},
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::Path,
        ptr,
        sync::OnceLock,
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER},
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            EqualSid, GetAce, GetTokenInformation, IsValidAcl, IsValidSid, IsWellKnownSid,
            TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerSid, WinLocalSystemSid,
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
            OWNER_SECURITY_INFORMATION, PSID, SID, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_READ_ATTRIBUTES, READ_CONTROL,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct UserSid(Vec<usize>);

    impl UserSid {
        fn load() -> Option<Self> {
            let mut raw = ptr::null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
                return None;
            }
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut length = 0;
            if unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    ptr::null_mut(),
                    0,
                    &mut length,
                )
            } != 0
                || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
                || length < size_of::<TOKEN_USER>() as u32
                || length > 64 * 1024
            {
                return None;
            }
            // TOKEN_USER contains a pointer into this aligned allocation.
            let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
            if unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } == 0
            {
                return None;
            }
            let user = Self(buffer);
            valid_sid(user.sid()).then_some(user)
        }

        fn sid(&self) -> PSID {
            unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }

    fn process_user() -> Option<&'static UserSid> {
        static USER: OnceLock<UserSid> = OnceLock::new();
        if USER.get().is_none() {
            let _ = USER.set(UserSid::load()?);
        }
        USER.get()
    }

    struct Descriptor(*mut c_void);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn valid_sid(sid: PSID) -> bool {
        !sid.is_null() && unsafe { IsValidSid(sid) } != 0
    }

    fn trusted_sid(sid: PSID, user: &UserSid) -> bool {
        unsafe {
            EqualSid(sid, user.sid()) != 0
                || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        }
    }

    fn acl_is_private(acl: *const ACL, user: &UserSid) -> bool {
        if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
            return false;
        }
        for index in 0..u32::from(unsafe { (*acl).AceCount }) {
            let mut raw = ptr::null_mut();
            if unsafe { GetAce(acl, index, &mut raw) } == 0 || raw.is_null() {
                return false;
            }
            // GetAce returns an ACE inside the validated ACL. Bound the
            // variable-length SID before passing it to the SID APIs.
            let header = unsafe { &*raw.cast::<ACE_HEADER>() };
            let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            let sid_header = offset_of!(SID, SubAuthority);
            let length = usize::from(header.AceSize);
            if !matches!(header.AceType, 0 | 1) || length < sid_offset + sid_header {
                return false;
            }
            let sid = unsafe { raw.cast::<u8>().add(sid_offset) };
            let subauthorities = usize::from(unsafe { *sid.add(1) });
            if length < sid_offset + sid_header + subauthorities * size_of::<u32>() {
                return false;
            }
            let sid = sid.cast();
            if !valid_sid(sid) {
                return false;
            }
            // An inherit-only CREATOR OWNER ACE is replaced by the owner
            // when Windows creates a child. Other inheritable write grants
            // are unsafe even if they do not apply to the directory itself.
            let creator_owner = u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
                && unsafe { IsWellKnownSid(sid, WinCreatorOwnerSid) } != 0;
            let mask = unsafe { (*raw.cast::<ACCESS_ALLOWED_ACE>()).Mask };
            if !ace_allowed(
                header.AceType,
                mask,
                trusted_sid(sid, user) || creator_owner,
            ) {
                return false;
            }
        }
        true
    }

    fn security_is_private(owner: PSID, acl: *const ACL, user: &UserSid) -> bool {
        valid_sid(owner) && trusted_sid(owner, user) && acl_is_private(acl, user)
    }

    fn private_handle(file: &File) -> bool {
        let Some(user) = process_user() else {
            return false;
        };
        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        let _descriptor = Descriptor(descriptor);
        result == 0 && security_is_private(owner, acl, user)
    }

    pub(in super::super) fn private_directory(path: &Path) -> bool {
        let Ok(directory) = File::options()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        else {
            return false;
        };
        directory.metadata().is_ok_and(|metadata| {
            metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
        }) && private_handle(&directory)
    }

    pub(in super::super) fn private_file(file: &File) -> bool {
        private_handle(file)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        };

        fn private_sddl(sddl: &str) -> bool {
            let wide: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut raw = ptr::null_mut();
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        wide.as_ptr(),
                        SDDL_REVISION_1,
                        &mut raw,
                        ptr::null_mut(),
                    )
                },
                0,
                "{sddl}"
            );
            let descriptor = Descriptor(raw);
            let mut owner = ptr::null_mut();
            let mut acl = ptr::null_mut();
            let mut defaulted = 0;
            let mut present = 0;
            assert_ne!(
                unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) },
                0
            );
            assert_ne!(
                unsafe {
                    GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted)
                },
                0
            );
            present != 0 && security_is_private(owner, acl, process_user().unwrap())
        }

        #[test]
        fn native_acl_parser_accepts_inherited_read_and_creator_owner() {
            assert!(private_sddl(
                "O:SYD:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FR;;;AU)(A;OICIIO;FA;;;CO)"
            ));
        }

        #[test]
        fn native_acl_parser_rejects_foreign_owner_and_inheritable_write() {
            assert!(!private_sddl("O:AUD:(A;;FA;;;SY)"));
            assert!(!private_sddl("O:SYD:(A;;FA;;;SY)(A;OICIIO;FW;;;AU)"));
            assert!(!private_sddl("O:SYD:NO_ACCESS_CONTROL"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_accounts_can_read_but_cannot_mutate_cache_entries() {
        for mask in [
            0x0012_00a9, // file read/execute and read-control
            0x8000_0000, // generic read
            0x2000_0000, // generic execute
        ] {
            assert!(ace_allowed(0, mask, false), "{mask:#x}");
        }
        for mask in [
            0x2,        // write data / add file
            0x4,        // append / add directory
            0x10,       // write extended attributes
            0x40,       // delete child
            0x100,      // write attributes
            0x10000,    // delete
            0x40000,    // write DACL
            0x80000,    // write owner
            0x40000000, // generic write
            0x10000000, // generic all
        ] {
            assert!(!ace_allowed(0, mask, false), "{mask:#x}");
            assert!(ace_allowed(0, mask, true), "{mask:#x}");
        }
    }

    #[test]
    fn deny_aces_do_not_grant_access_and_unknown_aces_fail_closed() {
        assert!(ace_allowed(1, u32::MAX, false));
        assert!(!ace_allowed(5, 0, true));
    }
}
