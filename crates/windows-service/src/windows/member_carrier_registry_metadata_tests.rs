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
