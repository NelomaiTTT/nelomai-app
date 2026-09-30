use super::*;
use std::collections::BTreeMap;

// Independent stamped-INF fixture values, never aliases of implementation
// constants: 2021-10-13 FILETIME and packed version 0.14.0.0 respectively.
const FIXTURE_DATE: u64 = 132785568000000000;
const FIXTURE_VERSION: u64 = 60129542144;

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
                system_sys: "system".into(),
            },
        }
    }
    fn call(&mut self, n: &'static str) -> Result<()> {
        self.calls.push(n);
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
