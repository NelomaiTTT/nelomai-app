use super::*;
use std::collections::BTreeMap;

// Independent stamped-INF fixture values, never aliases of implementation
// constants: 2021-10-13 FILETIME and packed version 0.14.0.0 respectively.
const FIXTURE_DATE: u64 = 132785568000000000;
const FIXTURE_VERSION: u64 = 60129542144;

fn pending_bytes(strings: &[&str]) -> Vec<u8> {
    strings
        .iter()
        .flat_map(|s| s.encode_utf16().chain([0]))
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}
fn protected_paths() -> Vec<String> {
    [
        r"C:\Program Files\Nelomai",
        r"C:\Windows\System32\drivers",
        r"C:\Windows\System32\DriverStore",
        r"C:\Windows\INF",
    ]
    .map(str::to_owned)
    .to_vec()
}
#[test]
fn pending_unrelated_retired_deletions_do_not_require_driver_maintenance() {
    // Native queue observed after the reboot, including EMPTY destinations.
    let bytes = pending_bytes(&[
        r"*1\??\C:\Windows\System32\gamingservicesproxy_13.dll.0",
        "",
        r"*1\??\C:\WRP8983.tmp",
        "",
    ]);
    let mut proven = vec![];
    assert_eq!(
        pending_deletions(&bytes, &protected_paths(), true, |path| {
            proven.push(path.to_owned());
            Ok(())
        }),
        Ok(false)
    );
    assert_eq!(
        proven,
        [
            r"C:\Windows\System32\gamingservicesproxy_13.dll.0",
            r"C:\WRP8983.tmp"
        ]
    );
}
#[test]
fn pending_deletions_keep_related_ambiguous_and_rename_obligations() {
    for (source, destination) in [
        (r"\??\C:\Windows\System32\drivers\wintun.sys", ""),
        (r"\??\C:\Elsewhere\Wintun.dll.0", ""),
        (r"\??\C:\Program Files\Nelomai\data.tmp", ""),
        (r"\??\c:\WINDOWS\INF\oem10.inf.tmp", ""),
        (r"\??\C:\Windows\System32\DriverStore\temp.tmp", ""),
        (r"\??\C:\Windows\System32\kernel32.dll", ""),
        (
            r"\??\C:\temp.tmp",
            r"!\??\C:\Windows\System32\drivers\wintun.sys",
        ),
        (r"\??\C:\Program Files", r"\??\C:\old"),
        (r"*9\??\C:\foo.tmp", ""),
        (r"*1*1\??\C:\foo.tmp", ""),
        (r"C:\foo.tmp", ""),
        (r"\??\UNC\server\foo.tmp", ""),
        (r"\??\C:\temp\..\foo.tmp", ""),
        (r"\??\C:\temp.\foo.tmp", ""),
        (r"\??\C:\temp \foo.tmp", ""),
        (r"\??\C:\PROGRA~1\foo.tmp", ""),
        (r"\??\C:\nul.tmp", ""),
        (r"\??\C:\foo:bar.tmp", ""),
        (r"\??\C:\foo.dll.abc", ""),
    ] {
        assert_eq!(
            pending_deletions(
                &pending_bytes(&[source, destination]),
                &protected_paths(),
                true,
                |_| panic!("unproven path must not reach native file proof")
            ),
            Ok(true),
            "{source} -> {destination}"
        );
    }
}
#[test]
fn pending_ambiguous_file_proof_is_still_maintenance() {
    let bytes = pending_bytes(&[r"*1\??\C:\missing.tmp", ""]);
    for reason in [
        Error::Changed,
        Error::Invalid("directory/reparse/hardlink"),
        Error::Native("access denied/missing", 5),
    ] {
        assert_eq!(
            pending_deletions(&bytes, &protected_paths(), true, |_| Err(reason.clone())),
            Ok(true)
        );
    }
}
#[test]
fn pending_pairs_preserve_empty_destinations_and_reject_malformed_data() {
    assert_eq!(
        pending_deletions(&[0, 0, 0, 0], &protected_paths(), true, |_| panic!()),
        Ok(false)
    );
    let mut no_extra_sentinel = pending_bytes(&[r"\??\C:\file.tmp", ""]);
    no_extra_sentinel.truncate(no_extra_sentinel.len() - 2);
    assert_eq!(
        pending_deletions(&no_extra_sentinel, &protected_paths(), true, |_| Ok(())),
        Ok(false)
    );
    for bytes in [
        vec![],
        vec![0],
        vec![0, 0],
        vec![0, 0, 0, 0, 0, 0],
        r"\??\C:\file.tmp"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect(),
        pending_bytes(&["", r"\??\C:\file.tmp"]),
        vec![0x00, 0xd8, 0, 0, 0, 0, 0, 0],
        vec![1; 65538],
    ] {
        assert!(pending_deletions(&bytes, &protected_paths(), true, |_| Ok(())).is_err());
    }
    let bytes = pending_bytes(&[
        r"\??\C:\file.tmp",
        "",
        r"\??\C:\Windows\System32\drivers\other.tmp",
        "",
    ]);
    let mut count = 0;
    assert_eq!(
        pending_deletions(&bytes, &protected_paths(), true, |_| {
            count += 1;
            Ok(())
        }),
        Ok(true)
    );
    assert_eq!(count, 1); // First unrelated deletion must not conceal later driver work.
}
#[test]
fn pending_star_source_flags_need_exact_audited_smss_not_any_windows_version() {
    let bytes = pending_bytes(&[r"*1\??\C:\file.tmp", ""]);
    assert_eq!(
        pending_deletions(&bytes, &protected_paths(), false, |_| Ok(())),
        Ok(true)
    );
    let bytes = pending_bytes(&[r"\??\C:\file.tmp", ""]);
    assert_eq!(
        pending_deletions(&bytes, &protected_paths(), false, |_| Ok(())),
        Ok(false)
    );
}
#[test]
fn pending_install_layout_is_exact_and_unknown_unicode_cannot_panic() {
    assert_eq!(
        pending_installation_root(r"D:\custom\runtime\engines\latest\0.3.3\wintun.dll"),
        Some(r"D:\custom")
    );
    for source in [
        "界".repeat(51),
        "😀".repeat(21),
        r"C:\wrong\wintun.dll".into(),
    ] {
        assert_eq!(pending_installation_root(&source), None);
    }
}
#[test]
fn pending_snapshot_drift_revokes_even_if_queue_stays_classified_unrelated() {
    for change_file in [false, true] {
        let mut f = Fake::good();
        f.inventory.pending.queues[0] = Some(pending_bytes(&[r"\??\C:\retired.tmp", ""]));
        f.inventory
            .pending
            .files
            .push((r"C:\retired.tmp".into(), observed(vec![1], 100).stamp));
        let mut checked = check(f).unwrap();
        let before = checked.kernel.inventory.pending.clone();
        if change_file {
            checked.kernel.inventory.pending.files[0].1.id += 1;
        } else {
            checked.kernel.inventory.pending.queues[1] =
                Some(pending_bytes(&[r"\??\C:\other.tmp", ""]));
        }
        assert_eq!(checked.reattest(), Err(Error::Changed));
        checked.kernel.inventory.pending = before;
        assert_eq!(checked.reattest(), Err(Error::Changed));
    }
}
#[test]
fn driver_store_and_installed_sys_may_be_exactly_one_closed_hardlink_pair() {
    let pair: [String; 2] = [
        r"C:\Windows\System32\DriverStore\FileRepository\wintun.inf_amd64_x\wintun.sys".into(),
        r"C:\Windows\System32\drivers\wintun.sys".into(),
    ];
    for path in &pair {
        assert_eq!(package_link_set(path, &pair, &pair, 2), Ok(()));
        assert_eq!(
            package_link_set(path, &pair, std::slice::from_ref(path), 1),
            Ok(())
        );
    }
}
#[test]
fn driver_hardlinks_reject_foreign_missing_duplicate_or_count_drift() {
    let pair: [String; 2] = [
        r"C:\store\wintun.sys".into(),
        r"C:\drivers\wintun.sys".into(),
    ];
    for (reported, count) in [
        (vec![], 0),
        (pair.to_vec(), 1),
        (vec![pair[0].clone()], 2),
        (vec![pair[1].clone()], 1),
        (vec![pair[0].clone(), pair[0].clone()], 2),
        (vec![pair[0].clone(), r"C:\foreign\wintun.sys".into()], 2),
        (
            vec![
                pair[0].clone(),
                pair[1].clone(),
                r"C:\third\wintun.sys".into(),
            ],
            3,
        ),
    ] {
        assert!(package_link_set(&pair[0], &pair, &reported, count).is_err());
    }
    assert!(package_link_set(r"C:\foreign\wintun.sys", &pair, &pair, 2).is_err());
    assert!(package_link_set(&pair[0], &[pair[0].clone(), pair[0].clone()], &pair, 2).is_err());
    let swapped = [pair[1].to_uppercase(), pair[0].to_uppercase()];
    assert_eq!(package_link_set(&pair[0], &pair, &swapped, 2), Ok(()));
}
#[test]
fn audited_catalog_member_tags_use_the_catalogs_algorithm_not_its_signature_algorithm() {
    // Independently hashed installed CAT; its signed content has SHA1 SYS/INF
    // member tags, although the catalog's signature uses SHA256.
    let digest = [
        0x83, 0x41, 0x39, 0x2f, 0xf3, 0xee, 0x58, 0x95, 0xc5, 0x6e, 0xc9, 0x00, 0xd5, 0x6b, 0x1e,
        0x7e, 0xbd, 0xfe, 0xf4, 0xa1, 0xfa, 0xfd, 0xd9, 0x26, 0x58, 0x70, 0xb1, 0xe6, 0xe3, 0x7c,
        0x79, 0x46,
    ];
    assert_eq!(catalog_hash_profile(&digest), Ok(("SHA1", 20)));
    for index in 0..32 {
        let mut foreign = digest;
        foreign[index] ^= 1;
        assert!(catalog_hash_profile(&foreign).is_err());
    }
}

// Independent expected metadata of the audited, stamped amd64 INF. Synthetic
// PE/resources below exercise parsing, NOT Authenticode or cold native acceptance.
const INF: &str = r#"[Version]
Signature="$Windows NT$"
Class=Net
ClassGUID={4D36E972-E325-11CE-BFC1-08002BE10318}
Provider=%Wintun.CompanyName%
CatalogFile.NT=wintun.cat
PnpLockdown=1
DriverVer=10/13/2021,0.14.0.0
[Manufacturer]
%Wintun.CompanyName%=%Wintun.Name%,NTamd64
[SourceDisksNames]
1=%Wintun.DiskDesc%,"",,
[SourceDisksFiles]
wintun.sys=1
[DestinationDirs]
DefaultDestDir=12
Wintun.CopyFiles.Sys=12
[Wintun.CopyFiles.Sys]
wintun.sys,,,0x00004002
[Wintun.NTamd64]
%Wintun.DeviceDesc%=Wintun.Install,Wintun
[Wintun.Install]
Characteristics=0x1
AddReg=Wintun.Ndi
AddProperty=Wintun.Properties
CopyFiles=Wintun.CopyFiles.Sys
*IfType=53
*MediaType=19
*PhysicalMediaType=0
EnableDhcp=0
[Wintun.Properties]
DeviceVendorWebsite,,,,"https://www.wintun.net/"
[Wintun.Install.Services]
AddService=wintun,2,Wintun.Service,Wintun.EventLog
[Wintun.Ndi]
HKR,Ndi,Service,0,wintun
HKR,Ndi\Interfaces,UpperRange,,"ndis5"
HKR,Ndi\Interfaces,LowerRange,,"nolower"
[Wintun.Service]
DisplayName=%Wintun.Name%
Description=%Wintun.DeviceDesc%
ServiceType=1
StartType=3
ErrorControl=1
ServiceBinary=%12%\wintun.sys
[Wintun.EventLog]
HKR,,EventMessageFile,0x00020000,"%11%\IoLogMsg.dll;%12%\wintun.sys"
HKR,,TypesSupported,0x00010001,7
[Strings]
Wintun.Name="Wintun"
Wintun.DiskDesc="Wintun Driver Install Disk"
Wintun.DeviceDesc="Wintun Userspace Tunnel"
Wintun.CompanyName="WireGuard LLC"
"#;

fn put16(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn pe(inf: &[u8]) -> Vec<u8> {
    pe_resources(inf, false)
}
fn pe_resources(inf: &[u8], arm64: bool) -> Vec<u8> {
    let sys = driver();
    let mut b = vec![0; 0xa000];
    b[..2].copy_from_slice(b"MZ");
    put32(&mut b, 0x3c, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut b, 0x84, 0x8664);
    put16(&mut b, 0x86, 1);
    put16(&mut b, 0x94, 240);
    put16(&mut b, 0x98, 0x20b);
    put32(&mut b, 0x98 + 108, 16);
    put32(&mut b, 0x98 + 112 + 16, 0x1000);
    put32(&mut b, 0x98 + 112 + 20, 0x9800);
    let s = 0x98 + 240;
    put32(&mut b, s + 8, 0x9800);
    put32(&mut b, s + 12, 0x1000);
    put32(&mut b, s + 16, 0x9800);
    put32(&mut b, s + 20, 0x200);
    let r = 0x200;
    put16(&mut b, r + 14, 1);
    put32(&mut b, r + 16, 10);
    put32(&mut b, r + 20, 0x80000040);
    let mut resources = vec![
        ("wintun.inf", inf),
        ("wintun.cat", b"signed catalog".as_slice()),
        ("wintun.sys", sys.as_slice()),
    ];
    if arm64 {
        for name in [
            "wintun-arm64.inf",
            "wintun-arm64.cat",
            "wintun-arm64.sys",
            "setupapihost-arm64.dll",
        ] {
            resources.push((name, b"unused cross-machine data".as_slice()));
        }
    }
    put16(&mut b, r + 0x40 + 12, resources.len() as u16);
    for (i, (name, data)) in resources.iter().enumerate() {
        let nameoff = 0x100 + i * 0x40;
        let sub = 0x400 + i * 0x40;
        let ent = 0x600 + i * 0x20;
        let payload = 0x1000 + i * 0x1000;
        put32(&mut b, r + 0x50 + i * 8, 0x80000000 | nameoff as u32);
        put32(&mut b, r + 0x54 + i * 8, 0x80000000 | sub as u32);
        put16(&mut b, r + nameoff, name.len() as u16);
        for (j, c) in name.encode_utf16().enumerate() {
            put16(&mut b, r + nameoff + 2 + j * 2, c);
        }
        put16(&mut b, r + sub + 14, 1);
        put32(&mut b, r + sub + 16, 1033);
        put32(&mut b, r + sub + 20, ent as u32);
        put32(&mut b, r + ent, 0x1000 + payload as u32);
        put32(&mut b, r + ent + 4, data.len() as u32);
        b[r + payload..r + payload + data.len()].copy_from_slice(data);
    }
    b
}
fn driver() -> Vec<u8> {
    let mut b = vec![0; 512];
    b[..2].copy_from_slice(b"MZ");
    put32(&mut b, 0x3c, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut b, 0x84, 0x8664);
    put16(&mut b, 0x94, 240);
    put16(&mut b, 0x98, 0x20b);
    b
}
fn observed(bytes: Vec<u8>, id: u64) -> Observed {
    Observed {
        stamp: Stamp {
            volume: 1,
            id,
            size: bytes.len() as u64,
            modified: 1,
        },
        bytes,
    }
}
struct Fake {
    source: Observed,
    inventory: Inventory,
    files: BTreeMap<String, Observed>,
    fail: Option<&'static str>,
    calls: Vec<&'static str>,
    fail_nth: Option<(&'static str, usize)>,
    change_on_signature: bool,
    panic_nth: Option<(&'static str, usize)>,
    events: std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>,
}

struct Originals {
    devices: Vec<Device>,
    version: Option<u32>,
    observations: usize,
    disappear_after: Option<usize>,
    panic_after: Option<usize>,
    events: std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>,
}
// SAFETY: Test-only replacement for native creator/source/runtime lease reads.
// No fake may be used to construct a product package or grant native effects.
unsafe impl OriginalDevices for Originals {
    fn observe(&mut self) -> Result<(Option<u32>, Vec<Device>)> {
        self.observations += 1;
        self.events.borrow_mut().push("original");
        if self.panic_after == Some(self.observations) {
            panic!("injected original ACK read unwind");
        }
        if self.disappear_after == Some(self.observations) {
            return Err(Error::Changed);
        }
        Ok((self.version, self.devices.clone()))
    }
}
fn live_original() -> Device {
    Device {
        instance: r"SWD\WINTUN\{01010101-0101-0101-0101-010101010101}".into(),
        status: 8,
        problem: 0,
    }
}
fn owned_package() -> (Checked<Fake>, Originals) {
    let mut checked = check(Fake::good()).unwrap();
    checked.kernel.calls.clear();
    checked.kernel.events.borrow_mut().clear();
    checked.kernel.inventory.service_state = 4;
    checked.kernel.inventory.devices = vec![live_original()];
    let originals = Originals {
        devices: vec![live_original()],
        version: Some(14),
        observations: 0,
        disappear_after: None,
        panic_after: None,
        events: std::rc::Rc::clone(&checked.kernel.events),
    };
    (checked, originals)
}

fn assert_forward_denied(checked: &mut Checked<Fake>, originals: &mut Originals) {
    let events = checked.kernel.events.borrow().clone();
    assert_eq!(checked.reattest(), Err(Error::Changed));
    assert_eq!(checked.reattest_owned(originals), Err(Error::Changed));
    assert_eq!(*checked.kernel.events.borrow(), events);
    assert!(!checked.valid);
}

#[test]
fn cleanup_outer_preserves_prior_validity_without_hidden_inner_resurrection() {
    for outer_valid in [false, true] {
        for inner_valid in [false, true] {
            let (mut checked, mut originals) = owned_package();
            checked.valid = inner_valid;
            let pins = checked.pins.clone();
            let mut valid = outer_valid;
            refresh_original(
                &mut checked,
                &mut valid,
                ReattestMode::Cleanup,
                |kernel| {
                    kernel.events.borrow_mut().push("authenticated_source");
                    Ok(())
                },
                |checked| checked.reattest_owned_cleanup(&mut originals),
            )
            .unwrap();
            assert_eq!(valid, outer_valid);
            assert_eq!(checked.valid, outer_valid && inner_valid);
            assert_eq!(checked.pins, pins);
            assert_eq!(
                checked.kernel.events.borrow().as_slice(),
                [
                    "authenticated_source",
                    "original",
                    "source",
                    "inventory",
                    "read",
                    "read",
                    "read",
                    "read",
                    "read",
                    "signatures",
                    "read",
                    "read",
                    "read",
                    "read",
                    "read",
                    "inventory",
                    "source",
                    "original",
                    "authenticated_source",
                ]
            );
            if !outer_valid {
                assert_eq!(
                    refresh_original(
                        &mut checked,
                        &mut valid,
                        ReattestMode::Forward,
                        |_| panic!("denied outer must not verify source"),
                        |_| panic!("denied outer must not refresh package"),
                    ),
                    Err(Error::Changed)
                );
            }
            if !(outer_valid && inner_valid) {
                assert_forward_denied(&mut checked, &mut originals);
            }
        }
    }
}

#[test]
fn cleanup_outer_source_or_package_failure_and_unwind_poison_both_gates() {
    for mode in [ReattestMode::Forward, ReattestMode::Cleanup] {
        for previously_valid in [false, true] {
            if mode == ReattestMode::Forward && !previously_valid {
                continue;
            }
            for failed in 0..3 {
                for unwind in [false, true] {
                    let (mut checked, mut originals) = owned_package();
                    let pins = checked.pins.clone();
                    let source = checked.source.clone();
                    let inventory = checked.inventory.clone();
                    let files = checked.files.clone();
                    let mut valid = previously_valid;
                    let mut source_reads = 0;
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        refresh_original(
                            &mut checked,
                            &mut valid,
                            mode,
                            |_| {
                                let step = if source_reads == 0 { 0 } else { 2 };
                                source_reads += 1;
                                if step == failed {
                                    if unwind {
                                        panic!("injected authenticated source unwind");
                                    }
                                    return Err(Error::Changed);
                                }
                                Ok(())
                            },
                            |checked| {
                                if failed == 1 {
                                    if unwind {
                                        checked.kernel.panic_nth = Some(("signatures", 1));
                                    } else {
                                        checked.kernel.fail_nth = Some(("signatures", 1));
                                    }
                                }
                                if mode == ReattestMode::Cleanup {
                                    checked.reattest_owned_cleanup(&mut originals)
                                } else {
                                    checked.reattest_owned(&mut originals)
                                }
                            },
                        )
                    }));
                    if unwind {
                        assert!(outcome.is_err(), "boundary {failed}");
                    } else {
                        assert!(outcome.unwrap().is_err());
                    }
                    assert!(!valid);
                    assert!(!checked.valid, "boundary {failed}");
                    assert_eq!(checked.pins, pins);
                    assert_eq!(checked.source, source);
                    assert_eq!(checked.inventory, inventory);
                    assert_eq!(checked.files, files);
                    checked.kernel.panic_nth = None;
                    checked.kernel.fail_nth = None;
                    assert_forward_denied(&mut checked, &mut originals);
                    refresh_original(
                        &mut checked,
                        &mut valid,
                        ReattestMode::Cleanup,
                        |_| Ok(()),
                        |checked| checked.reattest_owned_cleanup(&mut originals),
                    )
                    .unwrap();
                    assert!(!valid);
                    assert_forward_denied(&mut checked, &mut originals);
                }
            }
        }
    }
}

#[test]
fn cleanup_owned_clean_facts_preserve_poison_and_all_original_pins() {
    for previously_valid in [false, true] {
        let (mut checked, mut originals) = owned_package();
        let source = checked.source.clone();
        let inventory = checked.inventory.clone();
        let files = checked.files.clone();
        let pins = checked.pins.clone();
        if !previously_valid {
            assert_eq!(checked.reattest(), Err(Error::Changed));
        }
        checked.kernel.calls.clear();
        checked.kernel.events.borrow_mut().clear();
        for _ in 0..2 {
            assert_eq!(checked.reattest_owned_cleanup(&mut originals), Ok(()));
            assert_eq!(checked.valid, previously_valid);
            assert_eq!(checked.source, source);
            assert_eq!(checked.inventory, inventory);
            assert_eq!(checked.files, files);
            assert_eq!(checked.pins, pins);
        }
        assert_eq!(
            checked.kernel.events.borrow().as_slice(),
            [
                "original",
                "source",
                "inventory",
                "read",
                "read",
                "read",
                "read",
                "read",
                "signatures",
                "read",
                "read",
                "read",
                "read",
                "read",
                "inventory",
                "source",
                "original",
                "original",
                "source",
                "inventory",
                "read",
                "read",
                "read",
                "read",
                "read",
                "signatures",
                "read",
                "read",
                "read",
                "read",
                "read",
                "inventory",
                "source",
                "original",
            ]
        );
        assert!(!checked.kernel.calls.contains(&"open"));
        if previously_valid {
            checked.reattest_owned(&mut originals).unwrap();
            assert_eq!(checked.reattest(), Err(Error::Changed));
        }
        assert_forward_denied(&mut checked, &mut originals);
    }
}

#[test]
fn cleanup_owned_errors_and_unwinds_at_every_boundary_deny_and_retain_pins() {
    // The independently counted full bracket has 2 original reads, 2 source
    // reads, 2 inventory reads, 10 pinned file reads and 1 trust call.
    for (op, count) in [
        ("original", 2),
        ("source", 2),
        ("inventory", 2),
        ("read", 10),
        ("signatures", 1),
    ] {
        for index in 1..=count {
            for previously_valid in [false, true] {
                for unwind in [false, true] {
                    let (mut checked, mut originals) = owned_package();
                    checked.valid = previously_valid;
                    let pins = checked.pins.clone();
                    let source = checked.source.clone();
                    let inventory = checked.inventory.clone();
                    let files = checked.files.clone();
                    if op == "original" {
                        if unwind {
                            originals.panic_after = Some(index);
                        } else {
                            originals.disappear_after = Some(index);
                        }
                    } else if unwind {
                        checked.kernel.panic_nth = Some((op, index));
                    } else {
                        checked.kernel.fail_nth = Some((op, index));
                    }
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        checked.reattest_owned_cleanup(&mut originals)
                    }));
                    if unwind {
                        assert!(outcome.is_err(), "{op} {index}");
                    } else {
                        assert!(outcome.unwrap().is_err(), "{op} {index}");
                    }
                    assert!(!checked.valid);
                    assert_eq!(checked.pins, pins);
                    assert_eq!(checked.source, source);
                    assert_eq!(checked.inventory, inventory);
                    assert_eq!(checked.files, files);
                    checked.kernel.fail_nth = None;
                    checked.kernel.panic_nth = None;
                    originals.disappear_after = None;
                    originals.panic_after = None;
                    assert_forward_denied(&mut checked, &mut originals);
                    checked.reattest_owned_cleanup(&mut originals).unwrap();
                    assert_forward_denied(&mut checked, &mut originals);
                }
            }
        }
    }
}

#[test]
fn cleanup_owned_keeps_every_cold_inventory_source_and_foreign_guard() {
    for case in 0..24 {
        let (mut checked, mut originals) = owned_package();
        checked.valid = false;
        match case {
            0 => checked.kernel.inventory.native_amd64_win10_plus = false,
            1 => checked.kernel.inventory.candidates[0].date += 1,
            2 => checked.kernel.inventory.candidates[0].version += 1,
            3 => checked.kernel.inventory.candidates[0].provider = "foreign".into(),
            4 => checked.kernel.inventory.candidates[0].published_inf = "foreign".into(),
            5 => checked.kernel.inventory.candidates[0].store_inf = "foreign".into(),
            6 => checked.kernel.inventory.candidates[0].store_cat = "foreign".into(),
            7 => checked.kernel.inventory.candidates[0].store_sys = "foreign".into(),
            8 => checked
                .kernel
                .inventory
                .candidates
                .push(checked.inventory.candidates[0].clone()),
            9 => checked.kernel.inventory.service_type = 16,
            10 => checked.kernel.inventory.service_start = 2,
            11 => checked.kernel.inventory.service_state = 2,
            12 => checked.kernel.inventory.pending_maintenance = true,
            13 => {
                checked.kernel.inventory.pending.queues[0] =
                    Some(pending_bytes(&[r"\??\C:\other.tmp", ""]))
            }
            14 => {
                checked.kernel.inventory.pending.queues[1] =
                    Some(pending_bytes(&[r"\??\C:\other.tmp", ""]))
            }
            15 => checked
                .kernel
                .inventory
                .pending
                .files
                .push(("foreign".into(), checked.source.stamp.clone())),
            16 => checked.kernel.inventory.system_sys = "foreign".into(),
            17 => checked.kernel.source.stamp.id += 1,
            18 => checked.kernel.source.bytes[0] ^= 1,
            19 => checked.kernel.inventory.devices.push(Device {
                instance: r"SWD\WINTUN\{02020202-0202-0202-0202-020202020202}".into(),
                ..live_original()
            }),
            20 => originals.devices.push(live_original()),
            21 => originals.devices[0].instance = r"ROOT\NET\0001".into(),
            22 => originals.devices[0].problem = 1,
            23 => originals.version = Some(15),
            _ => unreachable!(),
        }
        assert!(
            checked.reattest_owned_cleanup(&mut originals).is_err(),
            "case {case}"
        );
        assert_forward_denied(&mut checked, &mut originals);
    }
}

#[test]
fn cleanup_owned_rejects_each_pinned_file_drift_and_changes_during_trust() {
    for name in ["published", "inf", "cat", "sys", "system"] {
        for stamp_only in [false, true] {
            let (mut checked, mut originals) = owned_package();
            checked.valid = false;
            let original = checked.kernel.files[name].clone();
            if stamp_only {
                checked.kernel.files.get_mut(name).unwrap().stamp.id += 1;
            } else {
                checked.kernel.files.get_mut(name).unwrap().bytes[0] ^= 1;
            }
            assert_eq!(
                checked.reattest_owned_cleanup(&mut originals),
                Err(Error::Changed)
            );
            checked.kernel.files.insert(name.into(), original);
            checked.reattest_owned_cleanup(&mut originals).unwrap();
            assert_forward_denied(&mut checked, &mut originals);
        }
    }
    let (mut checked, mut originals) = owned_package();
    checked.valid = false;
    checked.kernel.change_on_signature = true;
    assert_eq!(
        checked.reattest_owned_cleanup(&mut originals),
        Err(Error::Changed)
    );
    assert_forward_denied(&mut checked, &mut originals);
}

#[test]
fn actual_original_owned_arrival_keeps_original_file_pins_not_cold_adoption() {
    let (mut checked, mut originals) = owned_package();
    assert_eq!(checked.reattest_owned(&mut originals), Ok(()));
    assert!(checked.valid);
    assert_eq!(originals.observations, 2);
    assert_eq!(
        checked
            .kernel
            .calls
            .iter()
            .filter(|c| **c == "read")
            .count(),
        10
    );
    assert_eq!(
        checked
            .kernel
            .calls
            .iter()
            .filter(|c| **c == "signatures")
            .count(),
        1
    );
    assert!(!checked.kernel.calls.contains(&"open"));
    // The exact same device still cannot pass the ordinary cold gate.
    assert_eq!(checked.reattest(), Err(Error::Changed));
}
#[test]
fn original_owned_post_create_still_accepts_only_same_pinned_package() {
    let (mut checked, mut originals) = owned_package();
    assert_eq!(checked.reattest_owned(&mut originals), Ok(()));
    checked.kernel.files.get_mut("system").unwrap().bytes[1] ^= 1;
    assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
    checked.kernel.files.get_mut("system").unwrap().bytes[1] ^= 1;
    let count = originals.observations;
    assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
    assert_eq!(originals.observations, count);
}
#[test]
fn original_owned_refresh_rechecks_creator_after_slow_trust_calls() {
    let (mut checked, mut originals) = owned_package();
    originals.disappear_after = Some(2);
    assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
    assert_eq!(originals.observations, 2);
    assert!(checked.kernel.calls.contains(&"signatures"));
    assert!(!checked.valid);
    originals.disappear_after = None;
    assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
    assert_eq!(originals.observations, 2);
}

#[test]
fn original_owned_foreign_legacy_duplicate_problem_and_unbound_driver_deny() {
    for case in 0..14 {
        let (mut checked, mut originals) = owned_package();
        match case {
            0 => checked.kernel.inventory.devices.clear(),
            1 => checked.kernel.inventory.devices.push(Device {
                instance: r"SWD\WINTUN\{02020202-0202-0202-0202-020202020202}".into(),
                ..live_original()
            }),
            2 => originals.devices.clear(),
            3 => originals.devices.push(live_original()),
            4 => originals.devices[0].instance = r"ROOT\NET\0001".into(),
            5 => {
                originals.devices[0].instance =
                    r"SWD\WINTUN\{00000000-0000-0000-0000-000000000000}".into()
            }
            6 => originals.devices[0].instance.push('\0'),
            7 => originals.devices[0].instance = "界".repeat(20),
            8 => originals.devices[0].status = 0,
            9 => originals.devices[0].problem = 1,
            10 => originals.version = None,
            11 => originals.version = Some(15),
            12 => checked.kernel.inventory.service_state = 2,
            13 => originals.devices = vec![live_original(); 4],
            _ => unreachable!(),
        }
        assert!(
            checked.reattest_owned(&mut originals).is_err(),
            "case {case}"
        );
        assert!(!checked.valid);
        let calls = checked.kernel.calls.clone();
        assert!(checked.reattest_owned(&mut originals).is_err());
        assert_eq!(checked.kernel.calls, calls);
    }
}

#[test]
fn original_owned_package_platform_scm_queue_and_source_changes_deny() {
    for case in 0..9 {
        let (mut checked, mut originals) = owned_package();
        match case {
            0 => checked.kernel.inventory.native_amd64_win10_plus = false,
            1 => checked.kernel.inventory.candidates[0].version += 1,
            2 => checked.kernel.inventory.candidates[0].store_inf = "foreign".into(),
            3 => checked.kernel.inventory.service_type = 16,
            4 => checked.kernel.inventory.service_start = 2,
            5 => checked.kernel.inventory.pending_maintenance = true,
            6 => {
                checked.kernel.inventory.pending.queues[0] =
                    Some(pending_bytes(&[r"\??\C:\other.tmp", ""]))
            }
            7 => checked.kernel.inventory.system_sys = "replacement".into(),
            8 => checked.kernel.source.stamp.id += 1,
            _ => unreachable!(),
        }
        assert!(
            checked.reattest_owned(&mut originals).is_err(),
            "case {case}"
        );
        assert!(!checked.valid);
    }
}

#[test]
fn original_owned_each_actual_boundary_error_revokes_instead_of_caching() {
    let (mut good, mut originals) = owned_package();
    good.reattest_owned(&mut originals).unwrap();
    for op in ["source", "inventory", "read", "signatures"] {
        let count = good.kernel.calls.iter().filter(|call| **call == op).count();
        for index in 1..=count {
            let (mut checked, mut originals) = owned_package();
            checked.kernel.fail_nth = Some((op, index));
            assert!(
                checked.reattest_owned(&mut originals).is_err(),
                "{op} {index}"
            );
            assert!(!checked.valid);
            checked.kernel.fail_nth = None;
            assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
        }
    }
}

#[test]
fn original_owned_no_devices_can_finish_only_with_exact_driver_state() {
    let mut checked = check(Fake::good()).unwrap();
    let mut originals = Originals {
        devices: vec![],
        version: None,
        observations: 0,
        disappear_after: None,
        panic_after: None,
        events: std::rc::Rc::clone(&checked.kernel.events),
    };
    checked.reattest_owned(&mut originals).unwrap();
    checked.reattest().unwrap();
    checked.kernel.inventory.service_state = 4;
    originals.version = Some(14);
    checked.reattest_owned(&mut originals).unwrap();
    // Running matching driver after close is NOT cold pre-load or no-load proof.
    assert_eq!(checked.reattest(), Err(Error::Changed));
}

#[test]
fn original_owned_unwind_at_every_package_read_permanently_revokes() {
    let (mut good, mut originals) = owned_package();
    good.reattest_owned(&mut originals).unwrap();
    for op in ["source", "inventory", "read", "signatures"] {
        let count = good.kernel.calls.iter().filter(|call| **call == op).count();
        for index in 1..=count {
            let (mut checked, mut originals) = owned_package();
            checked.kernel.panic_nth = Some((op, index));
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    checked.reattest_owned(&mut originals)
                }))
                .is_err(),
                "{op} {index}"
            );
            assert!(!checked.valid);
            checked.kernel.panic_nth = None;
            let calls = checked.kernel.calls.clone();
            let observations = originals.observations;
            assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
            assert_eq!(checked.kernel.calls, calls);
            assert_eq!(originals.observations, observations);
        }
    }
}

#[test]
fn original_owned_refresh_orders_originals_around_the_full_pinned_baseline() {
    let (mut checked, mut originals) = owned_package();
    checked.reattest_owned(&mut originals).unwrap();
    assert_eq!(
        *checked.kernel.events.borrow(),
        [
            "original",
            "source",
            "inventory",
            "read",
            "read",
            "read",
            "read",
            "read",
            "signatures",
            "read",
            "read",
            "read",
            "read",
            "read",
            "inventory",
            "source",
            "original",
        ]
    );
}

#[test]
fn original_owned_error_or_unwind_at_either_ack_read_denies_both_refresh_paths() {
    for index in [1, 2] {
        for unwind in [false, true] {
            let (mut checked, mut originals) = owned_package();
            if unwind {
                originals.panic_after = Some(index);
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    checked.reattest_owned(&mut originals)
                }))
                .is_err());
            } else {
                originals.disappear_after = Some(index);
                assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
            }
            assert!(!checked.valid);
            assert_eq!(checked.kernel.events.borrow().last(), Some(&"original"));
            let events = checked.kernel.events.borrow().clone();
            originals.panic_after = None;
            originals.disappear_after = None;
            assert_eq!(checked.reattest_owned(&mut originals), Err(Error::Changed));
            assert_eq!(checked.reattest(), Err(Error::Changed));
            assert_eq!(*checked.kernel.events.borrow(), events);
        }
    }
}
impl Fake {
    fn good() -> Self {
        let mut files = BTreeMap::new();
        for (n, b) in [
            ("published", INF.as_bytes().to_vec()),
            ("inf", INF.as_bytes().to_vec()),
            ("cat", b"signed catalog".to_vec()),
            ("sys", driver()),
            ("system", driver()),
        ] {
            let id = files.len() as u64 + 1;
            files.insert(n.into(), observed(b, id));
        }
        Self {
            source: observed(pe(INF.as_bytes()), 99),
            files,
            fail: None,
            calls: vec![],
            fail_nth: None,
            change_on_signature: false,
            panic_nth: None,
            events: std::rc::Rc::new(std::cell::RefCell::new(vec![])),
            inventory: Inventory {
                native_amd64_win10_plus: true,
                candidates: vec![Candidate {
                    date: FIXTURE_DATE,
                    version: FIXTURE_VERSION,
                    provider: "WireGuard LLC".into(),
                    published_inf: "published".into(),
                    store_inf: "inf".into(),
                    store_cat: "cat".into(),
                    store_sys: "sys".into(),
                }],
                devices: vec![],
                service_type: 1,
                service_start: 3,
                service_state: 1,
                pending_maintenance: false,
                pending: PendingSnapshot::default(),
                system_sys: "system".into(),
            },
        }
    }
    fn call(&mut self, n: &'static str) -> Result<()> {
        self.calls.push(n);
        self.events.borrow_mut().push(n);
        if self.panic_nth.is_some_and(|(name, index)| {
            name == n && self.calls.iter().filter(|call| **call == n).count() == index
        }) {
            panic!("injected {n} unwind");
        }
        if self.fail == Some(n)
            || self.fail_nth.is_some_and(|(name, index)| {
                name == n && self.calls.iter().filter(|call| **call == n).count() == index
            })
        {
            Err(Error::Native(n, 5))
        } else {
            Ok(())
        }
    }
}
impl Kernel for Fake {
    type Pin = String;
    fn source(&mut self) -> Result<Observed> {
        self.call("source")?;
        Ok(self.source.clone())
    }
    fn inventory(&mut self) -> Result<Inventory> {
        self.call("inventory")?;
        Ok(self.inventory.clone())
    }
    fn open(&mut self, p: &str) -> Result<String> {
        self.call("open")?;
        Ok(p.into())
    }
    fn read(&mut self, p: &String) -> Result<Observed> {
        self.call("read")?;
        self.files.get(p).cloned().ok_or(Error::Changed)
    }
    fn signatures(&mut self, _: &[String; 5]) -> Result<()> {
        self.call("signatures")?;
        if self.change_on_signature {
            self.files.get_mut("system").unwrap().bytes[1] ^= 1;
        }
        Ok(())
    }
}
#[test]
fn exact_stamped_inf_is_accepted() {
    assert_eq!(parse_inf(INF.as_bytes()), Ok(()));
}
#[test]
fn embedded_data_is_extracted_without_loader() {
    let p = extract_package(&pe(INF.as_bytes())).unwrap();
    assert_eq!(p.inf, INF.as_bytes());
    assert_eq!(p.sys, driver());
}
#[test]
fn exact_existing_readonly_package_can_be_reobserved() {
    let mut c = check(Fake::good()).unwrap();
    c.reattest().unwrap();
    assert!(c.kernel.calls.contains(&"signatures"));
}
#[test]
fn failed_reattest_cannot_resurrect_a_checked_observation() {
    let mut c = check(Fake::good()).unwrap();
    c.kernel.fail = Some("inventory");
    assert!(c.reattest().is_err());
    c.kernel.fail = None;
    assert!(
        c.reattest().is_err(),
        "failure must revoke, not leave usable stale success"
    );
}
#[test]
fn exact_inf_rejects_every_security_relevant_change() {
    for (old, new) in [
        ("0.14.0.0", "0.13.0.0"),
        ("10/13/2021", "10/14/2021"),
        ("WireGuard LLC", "Foreign LLC"),
        ("NTamd64", "NTarm64"),
        ("wintun.cat", "other.cat"),
        ("StartType=3", "StartType=2"),
        ("%12%\\wintun.sys", "C:\\temp\\wintun.sys"),
        ("Class=Net", "Class=Unknown"),
    ] {
        assert!(
            parse_inf(INF.replace(old, new).as_bytes()).is_err(),
            "{old}"
        );
    }
    for extra in [
        "\nUnknown=1",
        "\n[Unknown]\na=b",
        "\n[Version]\nDriverVer=10/13/2021,0.14.0.0",
        "\nWintun.CompanyName=\"WireGuard LLC\"",
    ] {
        assert!(parse_inf(format!("{INF}{extra}").as_bytes()).is_err());
    }
}
#[test]
fn inf_supports_bom_comments_and_spacing_not_ambiguous_quotes() {
    let text = INF.replace("Class=Net", "Class = Net ; ordinary comment");
    let mut utf16 = vec![0xff, 0xfe];
    for w in text.encode_utf16() {
        utf16.extend(w.to_le_bytes());
    }
    assert_eq!(parse_inf(&utf16), Ok(()));
    utf16.push(0);
    assert!(parse_inf(&utf16).is_err());
    assert!(parse_inf(
        INF.replace("\"WireGuard LLC\"", "\"WireGuard LLC")
            .as_bytes()
    )
    .is_err());
}
#[test]
fn bounded_inf_and_source_reject_empty_huge_invalid_encoding() {
    for b in [vec![], vec![b'a'; MAX_INF + 1], vec![0xff], b"\0".to_vec()] {
        assert!(parse_inf(&b).is_err());
    }
    assert!(extract_package(&vec![0; MAX_SOURCE + 1]).is_err());
}
#[test]
fn malformed_pe_resources_never_use_a_loader_or_fallback() {
    let original = pe(INF.as_bytes());
    for (offset, value) in [
        (0x3c, 0xfffffffc),
        (0x200 + 20, 0x40),
        (0x200 + 0x54, 0x200),
        (0x200 + 0x414, 0x80000600),
        (0x200 + 0x600, 0xfffff000),
        (0x200 + 0x604, 0xffffffff),
        (0x200 + 0x60c, 1),
    ] {
        let mut b = original.clone();
        put32(&mut b, offset, value);
        assert!(extract_package(&b).is_err(), "offset {offset:x}");
    }
    for n in [0, 1, 63, 0x80, 0x200, 0x600, 0x1000] {
        assert!(extract_package(&original[..n]).is_err());
    }
    let mut b = original;
    put16(&mut b, 0x84, 0xaa64);
    assert!(extract_package(&b).is_err());
}
#[test]
fn resource_names_are_case_insensitive_but_duplicate_names_fail() {
    let mut b = pe(INF.as_bytes());
    for (j, c) in "WINTUN.INF".encode_utf16().enumerate() {
        put16(&mut b, 0x302 + j * 2, c);
    }
    assert!(extract_package(&b).is_ok());
    put32(&mut b, 0x200 + 0x58, 0x80000100);
    assert!(extract_package(&b).is_err());
}
#[test]
fn older_newer_and_duplicate_nodes_fail_even_alongside_a_match() {
    for (date, version) in [
        (FIXTURE_DATE - 1, FIXTURE_VERSION),
        (FIXTURE_DATE + 1, FIXTURE_VERSION),
        (FIXTURE_DATE, FIXTURE_VERSION - 1),
        (FIXTURE_DATE, FIXTURE_VERSION + 1),
        (FIXTURE_DATE, FIXTURE_VERSION),
    ] {
        let mut f = Fake::good();
        let mut other = f.inventory.candidates[0].clone();
        other.date = date;
        other.version = version;
        f.inventory.candidates.push(other);
        assert!(check(f).is_err());
    }
    let mut f = Fake::good();
    f.inventory.candidates.clear();
    assert!(check(f).is_err());
}
#[test]
fn single_candidate_provider_date_and_version_are_exact() {
    let mut f = Fake::good();
    f.inventory.candidates[0].provider = "Other".into();
    assert!(check(f).is_err());
    let mut f = Fake::good();
    f.inventory.candidates[0].date -= 1;
    assert!(check(f).is_err());
    let mut f = Fake::good();
    f.inventory.candidates[0].version += 1;
    assert!(check(f).is_err());
}
#[test]
fn all_relevant_devices_fail_including_healthy_nonpresent_legacy_and_problem() {
    for (instance, status, problem) in [
        ("SWD\\WINTUN\\healthy", 8, 0),
        ("SWD\\WINTUN\\orphan", 0, 24),
        ("ROOT\\NET\\legacy", 8, 0),
        ("ROOT\\WINTUN\\win7", 0, 0),
    ] {
        let mut f = Fake::good();
        f.inventory.devices.push(Device {
            instance: instance.into(),
            status,
            problem,
        });
        assert!(check(f).is_err());
    }
}
#[test]
fn unknown_platform_and_pending_service_never_pass() {
    let mut f = Fake::good();
    f.inventory.native_amd64_win10_plus = false;
    assert!(check(f).is_err());
    for state in [0, 2, 3, 5, 6, 7, u32::MAX] {
        let mut f = Fake::good();
        f.inventory.service_state = state;
        assert!(check(f).is_err());
    }
    for (kind, start) in [(2, 3), (1, 0), (1, 2)] {
        let mut f = Fake::good();
        f.inventory.service_type = kind;
        f.inventory.service_start = start;
        assert!(check(f).is_err());
    }
    let mut f = Fake::good();
    f.inventory.service_state = 4;
    assert!(
        check(f).is_err(),
        "cold preload cannot prove a running image from its disk path"
    );
}
#[test]
fn pending_maintenance_and_running_image_fail_cold_preload() {
    let mut f = Fake::good();
    f.inventory.pending_maintenance = true;
    assert!(check(f).is_err());
}
#[test]
fn audited_amd64_dll_may_contain_unused_complete_arm64_resource_group() {
    assert!(extract_package(&pe_resources(INF.as_bytes(), true)).is_ok());
    let mut partial = pe_resources(INF.as_bytes(), true);
    put16(&mut partial, 0x200 + 0x40 + 12, 6);
    assert!(extract_package(&partial).is_err());
}
#[test]
fn every_native_boundary_failure_fails_closed() {
    for failure in ["source", "inventory", "open", "read", "signatures"] {
        let mut f = Fake::good();
        f.fail = Some(failure);
        assert!(check(f).is_err(), "{failure}");
        let mut c = check(Fake::good()).unwrap();
        c.kernel.fail = Some(failure);
        if failure != "open" {
            assert!(c.reattest().is_err(), "{failure}");
        }
    }
}
#[test]
fn every_installed_file_must_equal_embedded_bytes() {
    for name in ["published", "inf", "cat", "sys", "system"] {
        let mut f = Fake::good();
        f.files.get_mut(name).unwrap().bytes[0] ^= 1;
        assert!(check(f).is_err(), "{name}");
    }
}
#[test]
fn retained_identity_and_content_are_rechecked_not_just_paths() {
    for name in ["published", "inf", "cat", "sys", "system"] {
        let mut c = check(Fake::good()).unwrap();
        c.kernel.files.get_mut(name).unwrap().stamp.id += 100;
        assert!(c.reattest().is_err(), "{name}");
        let mut c = check(Fake::good()).unwrap();
        c.kernel.files.get_mut(name).unwrap().bytes[0] ^= 1;
        assert!(c.reattest().is_err(), "{name}");
    }
    let mut c = check(Fake::good()).unwrap();
    c.kernel.source.stamp.id += 1;
    assert!(c.reattest().is_err());
}
fn words(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
#[test]
fn native_string_codecs_are_bounded_and_exact() {
    assert_eq!(wide_z(&words("Wintun\0")).unwrap(), "Wintun");
    assert!(wide_z(&words("Wintun")).is_err());
    assert!(wide_z(&[0xd800, 0]).is_err());
    assert_eq!(
        multi_sz(&words("Wintun\0other\0\0")).unwrap(),
        vec!["Wintun", "other"]
    );
    for v in ["Wintun\0", "Wintun\0\0garbage", "Wintun\0\0\0"] {
        assert!(multi_sz(&words(v)).is_err());
    }
}
#[test]
fn driver_detail_ids_respect_offset_length_not_assumed_double_nul() {
    assert_eq!(
        driver_ids(&words("Wintun\0"), 7, 0).unwrap(),
        vec!["Wintun"]
    );
    assert_eq!(
        driver_ids(&words("other\0Wintun\0\0"), 6, 8).unwrap(),
        vec!["other", "Wintun"]
    );
    assert_eq!(
        driver_ids(&words("\0Wintun\0\0"), 1, 8).unwrap(),
        vec!["Wintun"]
    );
    for (off, len) in [(usize::MAX, 1), (1, 99), (2, 0), (0, 8)] {
        assert!(driver_ids(&words("Wintun\0"), off, len).is_err());
    }
}
#[test]
fn actual_setupapi_empty_id_reply_is_shorter_than_padded_sdk_structure() {
    // DESKTOP-1DGFU8K 30Sep11:01:35: required1578, offsetof HardwareID1576,
    // sizeof SDK structure1584, CompatIDsOffset/Length0. Only one WCHAR NUL,
    // not the six bytes of C tail padding, belongs to this variable response.
    assert_eq!(driver_detail_words(1578, 1576, 65536), Ok(1));
    assert_eq!(driver_ids(&[0], 0, 0).unwrap(), Vec::<String>::new());
    assert_eq!(driver_detail_words(1590, 1576, 65536), Ok(7));
    assert_eq!(
        driver_ids(&words("Wintun\0"), 7, 0).unwrap(),
        vec!["Wintun"]
    );
}
#[test]
fn variable_driver_reply_rejects_prefix_truncation_odd_tail_and_overflow() {
    for (required, offset, capacity) in [
        (1576, 1576, 65536),
        (1577, 1576, 65536),
        (1579, 1576, 65536),
        (65538, 1576, 65536),
        (1578, 1576, 1577),
        (1578, usize::MAX, 65536),
        (usize::MAX, 1576, 65536),
    ] {
        assert!(driver_detail_words(required, offset, capacity).is_err());
    }
}
#[test]
fn actual_scm_query_buffer_respects_documented_eight_kib_rpc_limit() {
    let buffer = service_query_buffer();
    // QueryServiceConfigW documents maximum8192 BYTES, not SetupAPI's64KiB.
    assert_eq!(std::mem::size_of_val(buffer.as_slice()), 8192);
    assert_eq!(buffer.as_ptr() as usize % std::mem::align_of::<u64>(), 0);
    assert!(buffer.iter().all(|word| *word == 0));
}
#[test]
fn native_classification_catches_stub_legacy_service_and_compatible_ids() {
    for instance in ["SWD\\Wintun\\stub", "ROOT\\WINTUN\\old"] {
        assert!(related_device(instance, &[], None));
    }
    assert!(related_device("ROOT\\NET\\0001", &["wintun".into()], None));
    assert!(related_device("FOREIGN\\instance", &[], Some("WINTUN")));
    assert!(!related_device(
        "SWD\\WintunOther\\normal",
        &["NotWintun".into()],
        Some("NotWintun")
    ));
}
#[test]
fn winverifytrust_only_exact_zero_is_success() {
    assert_eq!(trust_status(0), Ok(()));
    for n in [1, -1, i32::MIN, 0x800b0100u32 as i32] {
        assert!(trust_status(n).is_err());
    }
}
#[test]
fn every_observation_stage_fault_returns_no_capability() {
    let baseline = check(Fake::good()).unwrap();
    for op in ["source", "inventory", "open", "read", "signatures"] {
        let count = baseline
            .kernel
            .calls
            .iter()
            .filter(|call| **call == op)
            .count();
        for n in 1..=count {
            let mut f = Fake::good();
            f.fail_nth = Some((op, n));
            assert!(check(f).is_err(), "{op} occurrence {n}");
        }
    }
}
#[test]
fn fresh_read_after_signature_success_detects_boundary_time_change() {
    let mut f = Fake::good();
    f.change_on_signature = true;
    assert!(check(f).is_err());
    let mut c = check(Fake::good()).unwrap();
    c.kernel.change_on_signature = true;
    assert!(c.reattest().is_err());
}
#[test]
fn all_metadata_changes_after_preflight_revoke_without_adoption() {
    let mut c = check(Fake::good()).unwrap();
    c.kernel.inventory.candidates[0].published_inf = "replacement".into();
    assert!(c.reattest().is_err());
    let mut c = check(Fake::good()).unwrap();
    c.kernel.inventory.devices.push(Device {
        instance: "SWD\\WINTUN\\arrived".into(),
        status: 8,
        problem: 0,
    });
    assert!(c.reattest().is_err());
    let mut c = check(Fake::good()).unwrap();
    c.kernel.inventory.pending_maintenance = true;
    assert!(c.reattest().is_err());
    let mut c = check(Fake::good()).unwrap();
    c.kernel.inventory.service_state = 4;
    assert!(c.reattest().is_err());
}
#[test]
fn complete_candidate_inventory_is_required_and_missing_pin_is_not_replaced() {
    for file in ["published", "inf", "cat", "sys", "system"] {
        let mut f = Fake::good();
        f.files.remove(file);
        assert!(check(f).is_err());
    }
    let mut f = Fake::good();
    f.inventory.system_sys = "unknown".into();
    assert!(check(f).is_err());
}
#[test]
fn no_mutation_load_or_effect_method_exists_in_boundary_transcript() {
    let c = check(Fake::good()).unwrap();
    assert!(c.kernel.calls.iter().all(|call| [
        "source",
        "inventory",
        "open",
        "read",
        "signatures"
    ]
    .contains(call)));
    assert!(
        c.kernel
            .calls
            .iter()
            .filter(|call| **call == "inventory")
            .count()
            >= 2
    );
}
#[test]
fn ancestors_allow_existing_and_future_writers_but_never_delete_sharing() {
    assert_eq!(
        share_policy(true),
        SharePolicy {
            read: true,
            write: true,
            delete: false
        }
    );
    assert_eq!(
        share_policy(false),
        SharePolicy {
            read: true,
            write: false,
            delete: false
        }
    );
}
