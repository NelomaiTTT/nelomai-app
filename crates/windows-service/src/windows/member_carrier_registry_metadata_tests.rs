use super::*;

// Hand-checked self-relative descriptor: two S-1-5-* SIDs and two empty ACLs.
// Break: dropping SACL, accepting truncated/absolute SD, or UTF16 replacement.
fn descriptor() -> Vec<u8> {
    vec![
        1, 0, 0x14, 0x80, 20, 0, 0, 0, 32, 0, 0, 0, 44, 0, 0, 0, 52, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        5, 18, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0, 2, 0, 8, 0, 0,
        0, 0, 0,
    ]
}
// External registry-query fixture only. Uses the real bounded capture/parser;
// cannot create any product original/disposition/close permission.
pub(crate) fn read_empty_metadata_for_key(
    capture: &RegistryMetadataCapture,
    name: &str,
    changed_security: bool,
) -> Result<()> {
    struct Empty<'a> {
        io: NativeIo,
        name: &'a str,
        changed_security: bool,
    }
    impl Queries for Empty<'_> {
        fn info(&mut self, o: &mut RawInfo) {
            self.io.info(o);
            o.class_len = 0;
            o.class[0] = 0;
            o.subkeys = 0;
            o.values = 0;
            o.max_subkey_name = 0;
            o.max_subkey_class = 0;
            o.max_value_name = 0;
            o.max_value_data = 0;
        }
        fn name(&mut self, o: &mut RawBuffer) {
            let words: Vec<_> = self.name.encode_utf16().collect();
            let mut bytes = ((words.len() * 2) as u32).to_le_bytes().to_vec();
            for word in words {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            o.status = Some(0);
            o.returned = bytes.len() as u32;
            o.bytes_mut()[..bytes.len()].copy_from_slice(&bytes);
        }
        fn security(&mut self, information: u32, o: &mut RawBuffer) {
            self.io.security(information, o);
            if self.changed_security {
                o.bytes_mut()[40] = 33; // Full, valid changed group SID.
            }
        }
        fn descriptor(
            &mut self,
            raw: &RawBuffer,
            layout: &SecurityLayout,
            o: &mut DescriptorCheck,
        ) {
            self.io.descriptor(raw, layout, o);
        }
    }
    capture.read(
        &mut Empty {
            io: NativeIo::good(),
            name,
            changed_security,
        },
        |_| Ok(()),
    )
}
fn name_bytes() -> Vec<u8> {
    let mut b = vec![38, 0, 0, 0]; // 19 WCHARs, no terminating WCHAR in NtQueryKey.
    for w in "\\REGISTRY\\MACHINE\\X".encode_utf16() {
        b.extend_from_slice(&w.to_le_bytes());
    }
    // Literal length below catches accidentally assuming NULL-terminated native names.
    b[0] = 38;
    b
}
#[test]
fn registry_metadata_decodes_full_self_relative_owner_group_sacl_dacl() {
    let layout = parse_security(&descriptor()).unwrap();
    assert_eq!(
        layout,
        SecurityLayout {
            revision: 1,
            control: 0x8014,
            owner: Component {
                offset: 20,
                length: 12
            },
            group: Component {
                offset: 32,
                length: 12
            },
            sacl: Acl::Present(Component {
                offset: 44,
                length: 8
            }),
            dacl: Acl::Present(Component {
                offset: 52,
                length: 8
            })
        }
    );
}

#[test]
fn completed_present_metadata_is_readonly_data_and_denies_partial_or_failed_capture() {
    let capture = RegistryMetadataCapture::new();
    assert!(capture.present_data().is_err());
    let mut io = NativeIo::good();
    capture.read(&mut io, |_| Ok(())).unwrap();
    let data = capture.present_data().unwrap();
    assert_eq!(data.name, "\\REGISTRY\\MACHINE\\X");
    assert_eq!(data.security.raw, descriptor());
    assert_eq!(capture.present_data().unwrap(), data);
    // A real post-read failure revokes successful DATA exposure; retained raw
    // outputs are history, never a live original-disposition authorization.
    let failed = RegistryMetadataCapture::new();
    assert!(failed
        .read(&mut NativeIo::good(), |_| Err(MetadataError::Changed))
        .is_err());
    assert!(failed.present_data().is_err());
    assert!(capture.read(&mut NativeIo::good(), |_| Ok(())).is_err());
    assert!(capture.present_data().is_err());
}
#[test]
fn registry_metadata_native_name_is_exact_length_strict_utf16() {
    let bytes = name_bytes();
    assert_eq!(
        parse_name(&bytes, bytes.len()).unwrap(),
        "\\REGISTRY\\MACHINE\\X"
    );
    let mut bad = bytes.clone();
    bad[4..6].copy_from_slice(&0xd800u16.to_le_bytes());
    assert_eq!(parse_name(&bad, bad.len()), Err(MetadataError::Invalid));
    assert!(parse_name(&bytes, bytes.len() - 1).is_err());
}

#[cfg(windows)]
#[test]
fn native_metadata_reader_keeps_full_security_denial_on_existing_readonly_key() {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_QUERY_VALUE},
    };
    // Read-only native CI gate. No key creation/delete, privilege adjustment,
    // path fallback or driver/user-PC prerequisite. This owns the returned HKEY.
    let name: Vec<u16> = "Software\0".encode_utf16().collect();
    let mut original = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                name.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut original,
            )
        },
        ERROR_SUCCESS
    );
    struct Held(windows_sys::Win32::System::Registry::HKEY);
    impl Drop for Held {
        fn drop(&mut self) {
            assert_eq!(unsafe { RegCloseKey(self.0) }, ERROR_SUCCESS);
        }
    }
    let held = Held(original);
    let capture = RegistryMetadataCapture::new();
    // SAFETY: held is SAME original open for the entire synchronous read.
    assert_eq!(
        unsafe { capture.read_original_native(held.0) },
        Err(MetadataError::Pending(5))
    );
    capture
        .inspect_acquired(|raw| {
            assert_eq!(raw.statuses()[0], [Some(0), Some(0), Some(5)]);
            assert_eq!(raw.statuses()[1], [None; 3]);
        })
        .unwrap();
    assert_eq!(
        unsafe { capture.read_original_native(held.0) },
        Err(MetadataError::Attempted)
    );
}

struct NativeIo {
    fail_security: bool,
    calls: Vec<&'static str>,
}
impl NativeIo {
    fn good() -> Self {
        Self {
            fail_security: false,
            calls: Vec::new(),
        }
    }
}
impl Queries for NativeIo {
    fn info(&mut self, o: &mut RawInfo) {
        self.calls.push("info");
        o.status = Some(0);
        o.class_len = 5;
        o.class[..6].copy_from_slice(&[111, 119, 110, 101, 100, 0]);
        o.subkeys = 3;
        o.max_subkey_name = 9;
        o.max_subkey_class = 3;
        o.values = 2;
        o.max_value_name = 7;
        o.max_value_data = 11;
        o.security_bytes = 60;
        o.last_write = 1234;
    }
    fn name(&mut self, o: &mut RawBuffer) {
        self.calls.push("name");
        let b = name_bytes();
        o.status = Some(0);
        o.returned = b.len() as u32;
        o.bytes_mut()[..b.len()].copy_from_slice(&b);
    }
    fn security(&mut self, information: u32, o: &mut RawBuffer) {
        assert_eq!(information, 15);
        self.calls.push("security");
        let b = descriptor();
        o.status = Some(if self.fail_security { 5 } else { 0 });
        o.returned = 60;
        o.bytes_mut()[..60].copy_from_slice(&b);
    }
    fn descriptor(&mut self, _raw: &RawBuffer, _layout: &SecurityLayout, o: &mut DescriptorCheck) {
        self.calls.push("descriptor");
        o.valid = Some(true);
        o.control_ok = Some(true);
        o.control = 0x8014;
        o.revision = 1;
        o.length = 60;
        o.components_valid = Some(true);
    }
}
#[test]
fn registry_metadata_full_native_observation_has_all_fields_before_callback() {
    let capture = RegistryMetadataCapture::new();
    let mut io = NativeIo::good();
    capture
        .read(&mut io, |observation| {
            let Observation::Present(m) = observation else {
                panic!("not deleted");
            };
            assert_eq!(m.name, "\\REGISTRY\\MACHINE\\X");
            assert_eq!(
                m.info,
                KeyInfo {
                    class: "owned".into(),
                    subkeys: 3,
                    max_subkey_name: 9,
                    max_subkey_class: 3,
                    values: 2,
                    max_value_name: 7,
                    max_value_data: 11,
                    security_bytes: 60,
                    last_write: 1234
                }
            );
            assert_eq!(m.security.raw, descriptor());
            assert_eq!(m.security.native_revision, 1);
            assert_eq!(m.security.native_control, 0x8014);
            assert_eq!(m.security.native_length, 60);
            capture
                .inspect_acquired(|raw| {
                    assert_eq!(raw.statuses()[0], [Some(0), Some(0), Some(0)]);
                    assert_eq!(raw.security_output(0).unwrap().1, 60);
                })
                .unwrap();
            Ok(())
        })
        .unwrap();
    assert_eq!(
        io.calls,
        vec![
            "info",
            "name",
            "security",
            "descriptor",
            "info",
            "name",
            "security",
            "descriptor"
        ]
    );
}

// Break: use buffer capacity as descriptor length when the successful native
// fill leaves its in/out length unchanged. Exercise the SAME production OS
// buffer adapter and complete capture/parser; only native calls are doubled.
#[test]
fn registry_metadata_sizes_full_security_before_an_unchanged_length_fill() {
    struct SizedIo(NativeIo, Vec<&'static str>);
    impl Queries for SizedIo {
        fn info(&mut self, out: &mut RawInfo) {
            self.0.info(out);
        }
        fn name(&mut self, out: &mut RawBuffer) {
            self.0.name(out);
        }
        fn security(&mut self, information: u32, out: &mut RawBuffer) {
            assert_eq!(information, FULL_SECURITY, "never reduce SACL request");
            out.registry_security_with(|buffer, length| {
                if let Some(words) = buffer {
                    self.1.push("fill");
                    // Native success writes the descriptor, not a padded SD.
                    let bytes = descriptor();
                    for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
                        *word = u32::from_le_bytes(bytes.try_into().unwrap());
                    }
                    0 // Deliberately leave the input length unchanged.
                } else {
                    self.1.push("size");
                    assert_eq!(*length, 0);
                    *length = descriptor().len() as u32;
                    122
                }
            });
        }
        fn descriptor(
            &mut self,
            raw: &RawBuffer,
            layout: &SecurityLayout,
            out: &mut DescriptorCheck,
        ) {
            self.0.descriptor(raw, layout, out);
        }
    }
    let capture = RegistryMetadataCapture::new();
    let mut io = SizedIo(NativeIo::good(), Vec::new());
    capture.read(&mut io, |_| Ok(())).unwrap();
    assert_eq!(capture.present_data().unwrap().security.raw, descriptor());
    assert_eq!(io.1, ["size", "fill", "size", "fill"]);
}

// Break: retry a denied/oversized size query, allocate a requested large
// buffer, or turn a changed/failed fill into complete security DATA.
#[test]
fn registry_security_sizing_denies_unknown_and_changed_native_outputs_without_retry() {
    for (size_status, required, fill_status, filled, expected_calls) in [
        (5, 0, 0, 60, 1),
        (122, 0, 0, 60, 1),
        (122, 19, 0, 60, 1),
        (122, 65_537, 0, 60, 1),
        (0, 60, 0, 60, 1),
        (122, 60, 122, 80, 2),
        (122, 60, 5, 60, 2),
    ] {
        let mut raw = RawBuffer::new(SECURITY_BYTES);
        let pointer = raw.words.as_ptr();
        let mut calls = 0;
        raw.registry_security_with(|buffer, size| {
            calls += 1;
            if buffer.is_none() {
                assert_eq!(*size, 0);
                *size = required;
                size_status
            } else {
                assert_eq!(*size, 60);
                *size = filled;
                fill_status
            }
        });
        assert_eq!(calls, expected_calls);
        assert_eq!(raw.words.as_ptr(), pointer, "must keep same bounded buffer");
        assert_eq!(raw.words.len(), 16_384);
        assert_eq!(raw.security_size_status, Some(size_status));
        assert_eq!(raw.security_size_returned, required);
        assert_eq!(raw.returned, if calls == 1 { required } else { filled });
        assert_ne!(
            raw.status,
            Some(0),
            "unknown query must not become fill ACK"
        );
    }
}

#[cfg(windows)]
#[test]
fn native_security_buffer_sizes_readonly_descriptor_without_capacity_padding() {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{GetSecurityDescriptorLength, IsValidSecurityDescriptor},
        Storage::FileSystem::READ_CONTROL,
        System::Registry::{
            RegCloseKey, RegGetKeySecurity, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
        },
    };
    // Read-only characterization of the actual buffer adapter. Mask7 is ONLY
    // for this query-only HKCU fixture: production still requests full mask15,
    // and the separate native denial test checks missing SACL access. No
    // privilege, key/ACL creation or product ownership/effect permission.
    let path: Vec<u16> = "Software\0".encode_utf16().collect();
    let mut handle = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE | READ_CONTROL,
                &mut handle,
            )
        },
        ERROR_SUCCESS
    );
    struct Held(windows_sys::Win32::System::Registry::HKEY);
    impl Drop for Held {
        fn drop(&mut self) {
            assert_eq!(unsafe { RegCloseKey(self.0) }, ERROR_SUCCESS);
        }
    }
    let original = Held(handle);
    let mut oversized = RawBuffer::new(SECURITY_BYTES);
    oversized.status = Some(unsafe {
        RegGetKeySecurity(
            original.0,
            7,
            oversized.words.as_mut_ptr().cast(),
            &mut oversized.returned,
        )
    } as i32);
    assert_eq!(oversized.status, Some(0));
    let descriptor = oversized.words.as_ptr().cast_mut().cast();
    assert_ne!(unsafe { IsValidSecurityDescriptor(descriptor) }, 0);
    let oversized_native_length = unsafe { GetSecurityDescriptorLength(descriptor) };
    assert!((20..=65_536).contains(&oversized_native_length));
    let mut exact = RawBuffer::new(SECURITY_BYTES);
    exact.registry_security_with(|buffer, size| unsafe {
        RegGetKeySecurity(
            original.0,
            7,
            buffer.map_or(std::ptr::null_mut(), |b| b.as_mut_ptr().cast()),
            size,
        )
    } as i32);
    assert_eq!(exact.security_size_status, Some(122));
    assert_eq!(exact.status, Some(0));
    let descriptor = exact.words.as_ptr().cast_mut().cast();
    assert_ne!(unsafe { IsValidSecurityDescriptor(descriptor) }, 0);
    let actual = unsafe { GetSecurityDescriptorLength(descriptor) };
    assert_eq!(exact.returned, actual);
    assert_eq!(exact.security_size_returned, actual);
    parse_security(&exact.bytes()[..actual as usize]).unwrap();
    eprintln!("native-readonly-security-sizing oversized_returned={} oversized_native={} exact_required={} exact_native={actual}; mask7 DATA only, no SACL/product authority",
        oversized.returned, oversized_native_length, exact.security_size_returned);
}
#[test]
fn registry_metadata_no_sacl_rights_is_pending_with_actual_outputs_retained() {
    let capture = RegistryMetadataCapture::new();
    let mut io = NativeIo::good();
    io.fail_security = true;
    assert_eq!(
        capture.read(&mut io, |_| panic!("no SACL fallback")),
        Err(MetadataError::Pending(5))
    );
    capture
        .inspect_acquired(|r| {
            assert_eq!(r.statuses()[0], [Some(0), Some(0), Some(5)]);
            assert_eq!(&r.security_output(0).unwrap().0[..60], descriptor());
        })
        .unwrap();
    assert_eq!(
        capture.read(&mut NativeIo::good(), |_| Ok(())),
        Err(MetadataError::Attempted)
    );
}
