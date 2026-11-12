use std::{
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::io::AsRawHandle,
    ptr::{from_mut, from_ref, null, null_mut},
};
use windows_sys::{
    Wdk::Storage::FileSystem::{NtQueryEaFile, NtSetEaFile},
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, NTSTATUS, STATUS_EAS_NOT_SUPPORTED,
            STATUS_INVALID_DEVICE_REQUEST, STATUS_NONEXISTENT_EA_ENTRY, STATUS_NO_EAS_ON_FILE,
            STATUS_SUCCESS,
        },
        Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        System::IO::IO_STATUS_BLOCK,
    },
};

const NAME: &[u8; 16] = b"NELOMAI_CACHEID\0";
const NAME_LEN: u8 = (NAME.len() - 1) as u8;
type Token = [u8; 16];

// FILE_GET_EA_INFORMATION and FILE_FULL_EA_INFORMATION with their trailing
// name and value stored inline. The leading u32 supplies the required alignment.
#[repr(C)]
struct EaQuery {
    next: u32,
    name_len: u8,
    name: [u8; NAME.len()],
}

#[derive(Default)]
#[repr(C)]
struct EaEntry {
    next: u32,
    flags: u8,
    name_len: u8,
    value_len: u16,
    name: [u8; NAME.len()],
    value: Token,
}

const QUERY_LEN: u32 = (offset_of!(EaQuery, name) + NAME.len()) as u32;
const ENTRY_LEN: usize = offset_of!(EaEntry, value) + size_of::<Token>();

pub(super) fn read(file: &File) -> io::Result<Option<Token>> {
    let query = EaQuery {
        next: 0,
        name_len: NAME_LEN,
        name: *NAME,
    };
    let mut entry = EaEntry::default();
    let mut result = IO_STATUS_BLOCK::default();
    // The cache uses synchronous handles. Both buffers remain live for the call.
    let status = unsafe {
        NtQueryEaFile(
            file.as_raw_handle(),
            &mut result,
            from_mut(&mut entry).cast(),
            ENTRY_LEN as u32,
            true,
            from_ref(&query).cast(),
            QUERY_LEN,
            null(),
            true,
        )
    };
    match status {
        STATUS_EAS_NOT_SUPPORTED
        | STATUS_INVALID_DEVICE_REQUEST
        | STATUS_NO_EAS_ON_FILE
        | STATUS_NONEXISTENT_EA_ENTRY => return Ok(None),
        STATUS_SUCCESS => {}
        _ => return Err(native_error(status)),
    }
    if entry.next != 0 || entry.flags != 0 || entry.name_len != NAME_LEN || entry.name != *NAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    match (entry.value_len as usize, result.Information) {
        (0, size) if size == offset_of!(EaEntry, value) => Ok(None),
        (length, ENTRY_LEN) if length == size_of::<Token>() && entry.value != [0; 16] => {
            Ok(Some(entry.value))
        }
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

pub(super) fn create(file: &File) -> io::Result<Option<Token>> {
    let mut entry = EaEntry {
        name_len: NAME_LEN,
        value_len: size_of::<Token>() as u16,
        name: *NAME,
        ..EaEntry::default()
    };
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            entry.value.as_mut_ptr(),
            entry.value.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(native_error(status));
    }
    // Bind the token to the owned handle before publication. NTFS can tunnel
    // creation times and object IDs when another file takes the old name.
    let status = unsafe {
        NtSetEaFile(
            file.as_raw_handle(),
            &mut IO_STATUS_BLOCK::default(),
            from_ref(&entry).cast(),
            ENTRY_LEN as u32,
        )
    };
    match status {
        // Filesystems without EAs keep the previous creation-time check.
        STATUS_EAS_NOT_SUPPORTED | STATUS_INVALID_DEVICE_REQUEST => return Ok(None),
        STATUS_SUCCESS => {}
        _ => return Err(native_error(status)),
    }
    file.sync_all()?;
    if read(file)? != Some(entry.value) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(entry.value))
}

fn native_error(status: NTSTATUS) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}
