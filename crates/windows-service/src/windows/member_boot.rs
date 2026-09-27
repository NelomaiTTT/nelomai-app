//! Read-only boot identity. No uptime/clock/machine-ID/random fallback.
//!
//! Private ABI source (NOT a Microsoft-documented boot structure):
//! https://raw.githubusercontent.com/winsiderss/phnt/master/ntexapi.h
//! SYSTEM_INFORMATION_CLASS: SystemBootEnvironmentInformation = 90;
//! SYSTEM_BOOT_ENVIRONMENT_INFORMATION, lines 3670..3692 at implementation:
//! GUID at 0, FIRMWARE_TYPE (u32) at 16, padding at 20, BootFlags (u64) at 24.
//! Supported Windows 10/11 x64/ARM64 layout is exactly 32 bytes, alignment 8.
//! Availability/ABI may change; fail closed, do not infer another identity:
//! https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
//! A boot ID is NOT a BFE epoch and cannot detect an in-boot BFE restart.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.

use std::io;

const INFORMATION_CLASS: u32 = 90;
const INFORMATION_SIZE: usize = 32;

#[repr(C, align(8))]
struct BootBuffer([u8; INFORMATION_SIZE]);
const _: () = assert!(std::mem::size_of::<BootBuffer>() == 32);
const _: () = assert!(std::mem::align_of::<BootBuffer>() == 8);

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "member_boot_identity_unavailable",
    )
}

fn decode(status: i32, returned: u32, bytes: &[u8]) -> io::Result<[u8; 16]> {
    // Deliberately accept STATUS_SUCCESS only, not every NT_SUCCESS code.
    // No old 20-byte layout, truncation, sizing retry, or newer schema fallback.
    if status != 0 || returned != 32 || bytes.len() != INFORMATION_SIZE {
        return Err(unsupported());
    }
    let firmware = u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| unsupported())?);
    // Known usable FIRMWARE_TYPE values: BIOS=1, UEFI=2. Unknown/max/new values
    // cannot attest this schema. Padding and BootFlags remain opaque, unused.
    if !matches!(firmware, 1 | 2) {
        return Err(unsupported());
    }
    let mut id: [u8; 16] = bytes[..16].try_into().map_err(|_| unsupported())?;
    if id == [0; 16] {
        return Err(unsupported());
    }
    // Stable canonical GUID byte order, independent of Windows' mixed-endian
    // memory representation. Persist these bytes directly (no hash or fallback).
    id[..4].reverse();
    id[4..6].reverse();
    id[6..8].reverse();
    Ok(id)
}

fn query_boot(query: impl FnOnce(u32, &mut [u8], &mut u32) -> i32) -> io::Result<[u8; 16]> {
    let mut buffer = BootBuffer([0; INFORMATION_SIZE]);
    let mut returned = 0;
    let status = query(INFORMATION_CLASS, &mut buffer.0, &mut returned);
    decode(status, returned, &buffer.0)
}

/// Read-only native query; never invoked by this module's tests. This attests
/// neither BFE continuity nor lifecycle readiness. Caller owns those checks.
#[cfg(all(
    windows,
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn boot_id() -> io::Result<[u8; 16]> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::{FreeLibrary, HMODULE},
        System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
    };
    type NtQuery = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
    struct Library(HMODULE);
    impl Drop for Library {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }

    let name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
    // System-directory-only search: never the working directory, application
    // directory, PATH, or a caller-provided DLL path. No mandatory ntdll import.
    let module =
        unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return Err(unsupported());
    }
    let library = Library(module);
    let procedure =
        unsafe { GetProcAddress(library.0, c"NtQuerySystemInformation".as_ptr().cast()) }
            .ok_or_else(unsupported)?;
    // SAFETY: exact exported NTAPI signature from the cited declarations; the
    // module reference stays alive through the call. Only the supported little-
    // endian x64/ARM64 ABI reaches here. Buffer is initialized, aligned to 8,
    // writable for exactly 32 bytes, and return-length points to a live u32.
    let query: NtQuery = unsafe { std::mem::transmute(procedure) };
    query_boot(|class, buffer, returned| unsafe {
        query(
            class,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            returned,
        )
    })
}

#[cfg(all(
    windows,
    not(all(
        target_endian = "little",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
pub(crate) fn boot_id() -> io::Result<[u8; 16]> {
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    fn valid() -> [u8; 32] {
        [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

    #[test]
    fn query_is_once_exact_bounded_zeroed_and_aligned_and_returns_canonical_guid_bytes() {
        let id = query_boot(|class, buffer, returned| {
            assert_eq!(class, 90);
            assert_eq!(buffer.len(), 32);
            assert_eq!(buffer.as_ptr() as usize % 8, 0);
            assert!(buffer.iter().all(|b| *b == 0));
            assert_eq!(*returned, 0);
            buffer.copy_from_slice(&valid());
            *returned = 32;
            0
        })
        .unwrap();
        assert_eq!(id, ID);
    }

    #[test]
    fn guid_is_stable_and_does_not_include_firmware_padding_or_boot_flags() {
        let mut bytes = valid();
        bytes[16] = 1; // BIOS as well as UEFI
        bytes[20..].fill(0xff); // padding/flags are opaque, NOT identity bytes.
        assert_eq!(decode(0, 32, &bytes).unwrap(), ID);
        assert_eq!(decode(0, 32, &valid()).unwrap(), ID);
        bytes[15] ^= 1;
        assert_ne!(decode(0, 32, &bytes).unwrap(), ID);
    }

    #[test]
    fn rejects_failure_warning_and_informational_status_without_a_fallback() {
        for status in [
            -1,
            0xc0000004u32 as i32,
            0xc0000002u32 as i32,
            0x80000005u32 as i32,
            1,
            0x40000000,
        ] {
            let error = query_boot(|_, buffer, returned| {
                buffer.copy_from_slice(&valid());
                *returned = 32;
                status
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(error.to_string(), "member_boot_identity_unavailable");
        }
    }

    #[test]
    fn rejects_every_short_buffer_and_unexpected_return_length() {
        for length in 0..32 {
            assert_eq!(
                decode(0, 32, &valid()[..length]).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert!(decode(0, length as u32, &valid()).is_err());
        }
        for length in [33, 64, u32::MAX] {
            assert!(decode(0, length, &valid()).is_err());
        }
        let mut oversized = valid().to_vec();
        oversized.push(0);
        assert!(decode(0, 32, &oversized).is_err());
        assert!(query_boot(|_, buffer, _| {
            buffer.copy_from_slice(&valid());
            0
        })
        .is_err());
    }

    #[test]
    fn rejects_zero_guid_and_unrecognized_firmware_schema() {
        let mut bytes = valid();
        bytes[..16].fill(0);
        assert_eq!(
            decode(0, 32, &bytes).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        for firmware in [0u32, 3, 4, u32::MAX] {
            let mut bytes = valid();
            bytes[16..20].copy_from_slice(&firmware.to_le_bytes());
            assert_eq!(
                decode(0, 32, &bytes).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }
}
