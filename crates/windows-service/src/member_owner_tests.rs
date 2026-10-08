use super::*;
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, rc::Rc};

mod cold_wireguard {
    use super::super::cold_wireguard_data::*;
    #[test]
    fn cold_backend_modules_reject_any_preloaded_wg_or_awg_and_unknown_query() {
        for (transport, names) in [
            (
                super::TunnelTransport::WireGuard,
                vec!["wireguard.dll", "tunnel.dll"],
            ),
            (
                super::TunnelTransport::AmneziaWg3,
                vec!["amneziawg-tunnel.dll"],
            ),
        ] {
            let mut queried = Vec::new();
            verify_cold_backend_modules(transport, |name| {
                queried.push(name);
                Ok(None)
            })
            .unwrap();
            assert_eq!(
                queried,
                names
                    .iter()
                    .chain(names.iter())
                    .copied()
                    .collect::<Vec<_>>()
            );
            for selected in names.iter() {
                assert!(verify_cold_backend_modules(transport, |name| Ok(
                    (name == *selected).then_some(())
                ))
                .is_err());
            }
            assert!(
                verify_cold_backend_modules(transport, |_| Err(Error::Native("module query", 5)))
                    .is_err()
            );
            let mut count = 0;
            assert!(verify_cold_backend_modules(transport, |_| {
                count += 1;
                Ok((count > names.len()).then_some(()))
            })
            .is_err());
        }
    }
    #[test]
    fn wireguard_package_only_audited_signed_source_not_inf_or_version_equal_library() {
        let digest = [
            0xb1, 0xb8, 0x5e, 0x07, 0x2c, 0x45, 0xd8, 0x13, 0x58, 0xbe, 0x29, 0xd9, 0x4c, 0x59,
            0x9d, 0xc7, 0x66, 0x52, 0xf9, 0x12, 0xbe, 0x8c, 0x0f, 0x0a, 0x41, 0xe2, 0xd5, 0xd8,
            0x9a, 0x64, 0x61, 0xd3,
        ];
        assert_eq!(require_audited_source_digest(&digest), Ok(()));
        for index in 0..32 {
            let mut other = digest;
            other[index] ^= 1;
            assert!(require_audited_source_digest(&other).is_err());
        }
    }
    #[test]
    fn wireguard_package_payload_denies_write_delete_and_parent_denies_replacement() {
        let payload = share_policy(false);
        assert!(payload.read);
        assert!(!payload.write && !payload.delete);
        let directory = share_policy(true);
        assert!(directory.read && directory.write);
        assert!(!directory.delete);
    }
    use std::collections::BTreeMap;

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
            ("wireguard.inf", inf),
            ("wireguard.cat", b"signed catalog".as_slice()),
            ("wireguard.sys", sys.as_slice()),
        ];
        if arm64 {
            for name in [
                "wireguard-arm64.inf",
                "wireguard-arm64.cat",
                "wireguard-arm64.sys",
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
                        date: 133485408000000000,
                        version: 281479271677952,
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
        fn open_driver_pair(&mut self, p: [&str; 2]) -> Result<[String; 2]> {
            Ok([self.open(p[0])?, self.open(p[1])?])
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
    fn wireguard_package_complete_readonly_original_recheck_and_every_file_byte_match() {
        let mut c = check(Fake::good()).unwrap();
        c.reattest().unwrap();
        for name in ["published", "inf", "cat", "sys", "system"] {
            let mut f = Fake::good();
            f.files.get_mut(name).unwrap().bytes[0] ^= 1;
            assert!(check(f).is_err(), "{name}");
        }
    }
    #[test]
    fn wireguard_package_requires_full_unique_candidate_universe_no_maintenance_or_driver_effects()
    {
        for case in 0..11 {
            let mut f = Fake::good();
            match case {
                0 => f.inventory.candidates.clear(),
                1 => f
                    .inventory
                    .candidates
                    .push(f.inventory.candidates[0].clone()),
                2 => f.inventory.candidates[0].date += 1,
                3 => f.inventory.candidates[0].version += 1,
                4 => f.inventory.candidates[0].provider = "Foreign".into(),
                5 => f.inventory.devices.push(Device {
                    instance: r"ROOT\NET\old".into(),
                    status: 8,
                    problem: 0,
                }),
                6 => f.inventory.service_type = 16,
                7 => f.inventory.service_start = 2,
                8 => f.inventory.service_state = 4,
                9 => f.inventory.pending_maintenance = true,
                10 => f.inventory.native_amd64_win10_plus = false,
                _ => unreachable!(),
            }
            assert!(check(f).is_err(), "case {case}");
        }
    }
    #[test]
    fn wireguard_package_failed_refresh_or_unwind_permanently_denies_original_pins() {
        for unwind in [false, true] {
            let mut c = check(Fake::good()).unwrap();
            c.kernel.calls.clear();
            if unwind {
                c.kernel.panic_nth = Some(("signatures", 1));
            } else {
                c.kernel.fail = Some("signatures");
            }
            let pins = c.pins.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.reattest()));
            if unwind {
                assert!(outcome.is_err());
            } else {
                assert!(outcome.unwrap().is_err());
            }
            assert_eq!(c.pins, pins);
            c.kernel.fail = None;
            c.kernel.panic_nth = None;
            assert!(c.reattest().is_err());
        }
    }
    #[test]
    fn wireguard_package_slow_trust_changes_and_source_identity_are_not_cached_success() {
        let mut c = check(Fake::good()).unwrap();
        c.kernel.change_on_signature = true;
        assert!(c.reattest().is_err());
        let mut c = check(Fake::good()).unwrap();
        c.kernel.source.stamp.id += 1;
        assert!(c.reattest().is_err());
        let mut f = Fake::good();
        f.fail = Some("signatures");
        assert!(check(f).is_err());
    }

    const INF: &str = r#"[Version]
Signature="$Windows NT$"
Class=Net
ClassGUID={4D36E972-E325-11CE-BFC1-08002BE10318}
Provider=%WireGuard.CompanyName%
CatalogFile.NT=wireguard.cat
PnpLockdown=1
DriverVer=01/01/2024,1.1.0.0
[Manufacturer]
%WireGuard.CompanyName%=%WireGuard.Name%,NTamd64
[SourceDisksNames]
1=%WireGuard.DiskDesc%,"",,
[SourceDisksFiles]
wireguard.sys=1
[DestinationDirs]
DefaultDestDir=12
WireGuard.CopyFiles.Sys=12
[WireGuard.CopyFiles.Sys]
wireguard.sys,,,0x00004002
[WireGuard.NTamd64]
%WireGuard.DeviceDesc%=WireGuard.Install,WireGuard
[WireGuard.Install]
Characteristics=0x1
AddReg=WireGuard.Ndi
AddProperty=WireGuard.Properties
CopyFiles=WireGuard.CopyFiles.Sys
*IfType=53
*MediaType=19
*PhysicalMediaType=0
EnableDhcp=0
[WireGuard.Properties]
DeviceIcon,,,,"%12%\wireguard.sys,-7"
DeviceBrandingIcon,,,,"%12%\wireguard.sys,-7"
DeviceVendorWebsite,,,,"https://www.wireguard.com/"
[WireGuard.Install.Services]
AddService=wireguard,2,WireGuard.Service,WireGuard.EventLog
[WireGuard.Ndi]
HKR,Ndi,Service,0,wireguard
HKR,Ndi\Interfaces,UpperRange,,"ndis5"
HKR,Ndi\Interfaces,LowerRange,,"nolower"
[WireGuard.Service]
DisplayName=%WireGuard.Name%
Description=%WireGuard.DeviceDesc%
ServiceType=1
StartType=3
ErrorControl=1
ServiceBinary=%12%\wireguard.sys
[WireGuard.EventLog]
HKR,,EventMessageFile,0x00020000,"%11%\IoLogMsg.dll;%12%\wireguard.sys"
HKR,,TypesSupported,0x00010001,7
[Strings]
WireGuard.Name="WireGuard"
WireGuard.DiskDesc="WireGuard Driver Install Disk"
WireGuard.DeviceDesc="WireGuard Tunnel"
WireGuard.CompanyName="WireGuard LLC"
"#;

    // Removing complete closed INF validation must fail these tests.
    #[test]
    fn wireguard_data_accepts_closed_11_inf_and_derives_installed_stamp_from_signed_data() {
        assert_eq!(parse_inf(INF.as_bytes()), Ok(133485408000000000));
    }
    #[test]
    fn wireguard_data_rejects_other_backend_platform_version_and_install_directives() {
        for (old, new) in [
            ("1.1.0.0", "1.0.0.0"),
            ("NTamd64", "NTarm64"),
            ("WireGuard LLC", "Foreign LLC"),
            ("wireguard.cat", "wintun.cat"),
            ("ServiceType=1", "ServiceType=16"),
            ("StartType=3", "StartType=2"),
            ("EnableDhcp=0", "EnableDhcp=1"),
            ("wireguard.sys,-7", "foreign.sys,-7"),
            ("01/01/2024", "02/30/2024"),
        ] {
            assert!(
                parse_inf(INF.replace(old, new).as_bytes()).is_err(),
                "{old}"
            );
        }
        for extra in [
            "\n[CoInstallers]\nCoInstaller=evil.dll",
            "\n[Version]\nUnknown=1",
            "\nUnknown=1",
            "\n[WireGuard.Service]\nStartType=3",
        ] {
            assert!(parse_inf(format!("{INF}{extra}").as_bytes()).is_err());
        }
    }
    #[test]
    fn wireguard_data_rejects_ambiguous_encoding_duplicate_stamp_and_partial_stamp() {
        for bytes in [
            vec![],
            vec![0xff, 0xfe, 1],
            vec![0; 65538],
            INF.replace(
                "DriverVer=01/01/2024,1.1.0.0",
                "DriverVer=01/01/2024,1.1.0.0\nDriverVer=01/01/2024,1.1.0.0",
            )
            .into_bytes(),
            INF.replace("DriverVer=01/01/2024,1.1.0.0", "DriverVer=01/01/2024")
                .into_bytes(),
            INF.replace("WireGuard LLC", "WireGuard\0 LLC").into_bytes(),
        ] {
            assert!(parse_inf(&bytes).is_err());
        }
    }
    #[test]
    fn wireguard_data_accepts_only_canonical_dates_including_leap_year() {
        assert_eq!(
            parse_inf(INF.replace("01/01/2024", "02/29/2024").as_bytes()),
            Ok(133536384000000000)
        );
        for date in [
            "02/29/2023",
            "00/01/2024",
            "01/00/2024",
            "13/01/2024",
            "1/01/2024",
            "01/01/0000",
        ] {
            assert!(
                parse_inf(INF.replace("01/01/2024", date).as_bytes()).is_err(),
                "{date}"
            );
        }
    }
}

const CONFIG: &str =
    "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\nDNS = 9.9.9.9\n[Peer]\nPublicKey = test\n";
fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    }
}
fn proof() -> NativeProof {
    NativeProof {
        process: ProcessProof {
            pid: 20,
            creation_time: 30,
        },
        interface: InterfaceProof {
            index: 40,
            luid: 50,
            guid: [6; 16],
        },
    }
}
struct State {
    slot: TunnelSlot,
    record: Option<Record>,
    observation: Observation,
    events: Vec<&'static str>,
    fail_save: Option<Phase>,
    lost_save_ack: Option<Phase>,
    change_after_stopping: bool,
    fail_start: bool,
    fail_capture: bool,
    fail_stop: bool,
    fail_rebind: bool,
    changed_after_capture: bool,
    next_proof: NativeProof,
    save_count: usize,
    fail_save_number: Option<usize>,
    lost_save_number: Option<usize>,
    fail_config: bool,
    lost_config_ack: bool,
    written_config: Option<zeroize::Zeroizing<String>>,
    read_step: usize,
    fail_read_step: Option<usize>,
    panic_read_step: Option<usize>,
    drift_read_step: Option<usize>,
    drift_on_running_save: bool,
    original_available: bool,
}
type Shared = Rc<RefCell<State>>;
struct Disk(Shared);
struct Io(Shared, bool); // Revocation belongs to THIS fake native owner.
impl Journal for Disk {
    fn load(&mut self, slot: TunnelSlot) -> Result<Option<Record>> {
        assert_eq!(slot, self.0.borrow().slot);
        let mut s = self.0.borrow_mut();
        read_boundary(&mut s, OwnerError::Journal)?;
        Ok(s.record.clone())
    }
    fn compare_exchange(
        &mut self,
        slot: TunnelSlot,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()> {
        assert_eq!(slot, self.0.borrow().slot);
        let mut s = self.0.borrow_mut();
        if s.record.as_ref() != expected {
            return Err(OwnerError::Conflict);
        }
        s.save_count += 1;
        s.events.push(match desired.phase {
            Phase::Prepared => "prepared",
            Phase::Running => "running",
            Phase::Stopping => "stopping",
            Phase::Stopped => "stopped",
        });
        if s.fail_save == Some(desired.phase) || s.fail_save_number == Some(s.save_count) {
            return Err(OwnerError::Journal);
        }
        s.record = Some(desired.clone());
        if desired.phase == Phase::Running && s.drift_on_running_save {
            s.record
                .as_mut()
                .unwrap()
                .intent
                .scope
                .connection_generation += 1;
        }
        if desired.phase == Phase::Stopping && s.change_after_stopping {
            s.observation
                .service
                .as_mut()
                .unwrap()
                .process
                .as_mut()
                .unwrap()
                .creation_time += 1;
        }
        if s.lost_save_ack == Some(desired.phase) || s.lost_save_number == Some(s.save_count) {
            return Err(OwnerError::Journal);
        }
        Ok(())
    }
}
impl MemberIo for Io {
    fn revoke_original(&mut self) {
        self.1 = true;
    }
    fn inspect_original(&mut self, intent: &Intent, retained: &NativeProof) -> Result<Observation> {
        if self.1 || !self.0.borrow().original_available {
            return Err(OwnerError::Retired);
        }
        self.inspect(intent, Some(retained))
    }
    fn inspect(&mut self, intent: &Intent, retained: Option<&NativeProof>) -> Result<Observation> {
        assert_eq!(intent.slot, self.0.borrow().slot);
        let mut s = self.0.borrow_mut();
        s.events.push("inspect");
        read_boundary(&mut s, OwnerError::Native)?;
        if s.fail_capture && s.observation.service.is_some() {
            return Err(OwnerError::Native);
        }
        let mut out = s.observation.clone();
        if retained.is_some() && out.retained_interfaces.is_empty() {
            out.retained_interfaces = out.interface.into_iter().collect();
        }
        Ok(out)
    }
    fn write_private_config(
        &mut self,
        intent: &Intent,
        expected_sha256: Option<[u8; 32]>,
        canonical: &str,
    ) -> Result<()> {
        assert_eq!(intent.slot, self.0.borrow().slot);
        assert!(canonical.contains("Table = off"));
        assert!(!canonical.contains("DNS"));
        let mut s = self.0.borrow_mut();
        if s.observation.config_sha256 != expected_sha256 {
            return Err(OwnerError::Conflict);
        }
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Prepared);
        s.events.push("config");
        if s.fail_config {
            return Err(OwnerError::Native);
        }
        s.observation.config_sha256 = Some(intent.config_sha256);
        s.written_config = Some(zeroize::Zeroizing::new(canonical.to_owned()));
        if s.lost_config_ack {
            return Err(OwnerError::Native);
        }
        Ok(())
    }
    fn start_fresh(&mut self, intent: &Intent, _: Option<&NativeProof>) -> Result<()> {
        assert_eq!(intent.slot, self.0.borrow().slot);
        let mut s = self.0.borrow_mut();
        assert!(s.observation.service.is_none());
        assert!(!s.observation.alternative_service_present);
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Prepared);
        assert!(s.record.as_ref().unwrap().previous_config_sha256.is_none());
        s.events.push("start");
        s.observation.service = Some(ServiceObservation {
            exact_spec: true,
            process: Some(s.next_proof.process),
        });
        s.observation.interface = Some(s.next_proof.interface);
        if s.fail_start {
            Err(OwnerError::Native)
        } else {
            Ok(())
        }
    }
    fn stop_slot(
        &mut self,
        intent: &Intent,
        _: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        assert_eq!(intent.slot, self.0.borrow().slot);
        let mut s = self.0.borrow_mut();
        assert!(matches!(
            s.record.as_ref().unwrap().phase,
            Phase::Running | Phase::Stopping
        ));
        assert_eq!(expected.service, s.observation.service);
        s.events.push("stop");
        s.observation.service.as_mut().unwrap().process = None;
        s.observation.interface = None;
        s.observation.retained_interfaces.clear();
        if s.fail_stop {
            return Err(OwnerError::Native);
        }
        s.observation.service = None;
        Ok(())
    }
    fn rebind(&mut self, intent: &Intent, old: &NativeProof, expected: &Observation) -> Result<()> {
        assert_eq!(intent.slot, self.0.borrow().slot);
        let mut s = self.0.borrow_mut();
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Prepared);
        assert_eq!(expected.service, s.observation.service);
        assert_eq!(*old, proof());
        s.events.push("rebind");
        if s.fail_rebind {
            return Err(OwnerError::Native);
        }
        if !s.changed_after_capture {
            s.observation.service.as_mut().unwrap().process = Some(ProcessProof {
                pid: 21,
                creation_time: 31,
            });
            s.observation.interface = Some(InterfaceProof {
                index: 41,
                luid: 51,
                guid: [7; 16],
            });
        }
        Ok(())
    }
}
fn owner(s: Shared) -> MemberOwner<Disk, Io> {
    MemberOwner::from_trusted_engine(
        scope(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        CONFIG,
        Disk(s.clone()),
        Io(s, false),
    )
    .unwrap()
}
fn setup() -> (MemberOwner<Disk, Io>, Shared) {
    let s = Rc::new(RefCell::new(State {
        slot: TunnelSlot::B,
        record: None,
        observation: Observation {
            config_sha256: None,
            service: None,
            alternative_service_present: false,
            interface: None,
            retained_interfaces: vec![],
        },
        events: vec![],
        fail_save: None,
        lost_save_ack: None,
        change_after_stopping: false,
        fail_start: false,
        fail_capture: false,
        fail_stop: false,
        fail_rebind: false,
        changed_after_capture: false,
        next_proof: proof(),
        save_count: 0,
        fail_save_number: None,
        lost_save_number: None,
        fail_config: false,
        lost_config_ack: false,
        written_config: None,
        read_step: 0,
        fail_read_step: None,
        panic_read_step: None,
        drift_read_step: None,
        drift_on_running_save: false,
        original_available: true,
    }));
    (owner(s.clone()), s)
}

fn replacement(s: Shared, scope: SessionScope) -> MemberOwner<Disk, Io> {
    replacement_engine(s, scope, &crate::test_engine_path("engine.exe"))
}

const CARRIER_CONFIG: &str = "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\nAddress = 10.240.5.2/32\nDNS = 9.9.9.9\nTable = auto\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = 25\n";
const CARRIER_NATIVE: &str = "[Interface]\nTable = off\nPrivateKey = PRIVATE-TEST-KEY\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = 25\n";

fn carrier_intent() -> crate::member_carrier::Intent {
    crate::member_carrier::Intent {
        scope: scope(),
        addresses: vec!["10.240.5.2/32".parse().unwrap()],
    }
}

const COLD_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
fn cold_owner(extra: &str) -> (MemberOwner<Disk, Io>, Shared) {
    cold_owner_slot(extra, TunnelSlot::B)
}
fn cold_owner_slot(extra: &str, slot: TunnelSlot) -> (MemberOwner<Disk, Io>, Shared) {
    let (_, state) = setup();
    let mut fields = extra.to_string();
    if !extra.is_empty() && !extra.starts_with("MTU") {
        if !extra.contains("HeaderProtectionKey") {
            fields.push_str("HeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
        }
        if !extra.contains("ContentPaddingAddition") {
            fields.push_str("ContentPaddingAddition = 1\n");
        }
    }
    let logical = CARRIER_CONFIG
        .replace("PRIVATE-TEST-KEY", COLD_KEY)
        .replace("[Peer]", &format!("{fields}[Peer]"));
    let transport = nelomai_client_tunnel::detect_configuration_transport(&logical);
    let owner = MemberOwner::from_trusted_carrier_engine(
        &carrier_intent(),
        slot,
        transport,
        crate::test_engine_path("engine.exe"),
        &logical,
        Disk(state.clone()),
        Io(state.clone(), false),
    )
    .unwrap();
    (owner, state)
}

#[test]
fn cold_native_profile_accepts_wg_and_awg_without_io_or_private_writes() {
    for (slot, extra) in [
        (TunnelSlot::A, ""), (TunnelSlot::B, ""),
        (TunnelSlot::A, "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 10-20\nH2 = 30-40\nH3 = 50-60\nH4 = 70-80\nI1 = <b 0x0102><r 8><t>\n"),
        (TunnelSlot::B, "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 10-20\nH2 = 30-40\nH3 = 50-60\nH4 = 70-80\nI1 = <b 0x0102><r 8><t>\n"),
    ] {
        let (mut owner, state) = cold_owner_slot(extra, slot);
        let first = owner.prepare_readonly_native_profile().unwrap();
        let second = owner.prepare_readonly_native_profile().unwrap();
        assert!(Rc::ptr_eq(&first, &second));
        owner.verify_readonly_native_profile(&first).unwrap();
        assert_eq!(state.borrow().read_step, 0);
        assert!(state.borrow().events.is_empty());
        assert!(state.borrow().written_config.is_none());
    }
}

#[test]
fn cold_native_profile_rejects_keys_ranges_and_unsafe_awg_before_effects() {
    for extra in [
        "MTU = 575\n",
        "MTU = 65536\n",
        "Jc = 65536\n",
        "Jc = 4\nJmin = 70\nJmax = 40\n",
        "H1 = 1-3\nH2 = 3-8\n",
        "H1 = 20-10\n",
        "H1 = 0-4294967295\n",
        "I1 = <r -1>\n",
        "I1 = <r 999999999>\n",
        "I1 = <b 0x0>\n",
        "I1 = <unknown 1>\n",
        "I1 = ignored\n",
        "ContentPaddingAddition = 4294967295\n",
        "HeaderProtectionKey = not-a-key\n",
    ] {
        let (mut owner, state) = cold_owner(extra);
        assert!(owner.prepare_readonly_native_profile().is_err(), "{extra}");
        assert_eq!(state.borrow().read_step, 0);
        assert!(state.borrow().events.is_empty());
    }
    for key in [
        "PRIVATE-TEST-KEY",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEF=",
    ] {
        let (mut owner, state) = cold_owner("");
        owner.configuration = zeroize::Zeroizing::new(owner.configuration.replace(COLD_KEY, key));
        owner.intent.config_sha256 = Sha256::digest(owner.configuration.as_bytes()).into();
        assert!(owner.prepare_readonly_native_profile().is_err());
        assert!(state.borrow().events.is_empty());
    }
}

#[test]
fn cold_native_profile_is_original_owner_bound_and_retained_across_unwind() {
    let (mut owner, _) = cold_owner("");
    let first = owner.prepare_readonly_native_profile().unwrap();
    let (mut equal_owner, _) = cold_owner("");
    assert_eq!(owner.intent(), equal_owner.intent());
    equal_owner.prepare_readonly_native_profile().unwrap();
    assert!(equal_owner.verify_readonly_native_profile(&first).is_err());
    let weak = Rc::downgrade(&first);
    drop(first);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _pin = owner.prepare_readonly_native_profile().unwrap();
        panic!("postflight fails after actual parser proof rooted");
    }));
    let pin = weak.upgrade().unwrap();
    owner.verify_readonly_native_profile(&pin).unwrap();
    owner.intent.scope.connection_generation += 1;
    assert!(owner.verify_readonly_native_profile(&pin).is_err());
    drop(owner);
    drop(pin);
    assert!(weak.upgrade().is_none());
}

#[test]
fn cold_native_profile_awg_header_nonce_and_windows_buffer_are_actual_bounds() {
    let protected =
        format!("HeaderProtectionKey = {COLD_KEY}\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n");
    let (mut owner, state) = cold_owner(&protected);
    owner.prepare_readonly_native_profile().unwrap();
    for bad in [
        protected.replace("S4 = 12", "S4 = 11"),
        protected.replace("S1 = 12", "S1 = 1900"),
        format!("{protected}MTU = 1980\n"),
        format!("{protected}ContentPaddingAddition = 2016\n"),
        "Jc = 65535\nJmin = 2000\nJmax = 2016\n".into(),
        "I1 = <r 2017>\n".into(),
        "I1 = <r 1000><r 1000><t><r 20>\n".into(),
        "I1 = <r 2 extra>\n".into(),
        "I1 = <t ignored>\n".into(),
        "RekeyTimeout = 0\n".into(),
    ] {
        let (mut invalid, boundary) = cold_owner(&bad);
        assert!(invalid.prepare_readonly_native_profile().is_err(), "{bad}");
        assert_eq!(boundary.borrow().read_step, 0);
        assert!(boundary.borrow().events.is_empty());
    }
    assert!(state.borrow().events.is_empty());
}

#[test]
fn cold_native_profile_closed_grammar_and_same_bytes_cannot_be_adopted() {
    for (from, to) in [
        ("Table = off", "Table = auto"),
        ("Table = off", "Table = off\nAddress = 10.240.5.2/32"),
        ("Table = off", "Table = off\nDNS = 9.9.9.9"),
        ("Table = off", "Table = off\nPostUp = execute"),
        ("Table = off", "Table = off\nJc = 4"), // WG cannot consume AWG fields.
        ("Table = off", "Table = off\nMTU = 1420\nMTU = 1420"),
        ("192.0.2.1:51820", "192.0.2.1:0"),
        ("192.0.2.1:51820", "example.test:51820"),
        ("0.0.0.0/0", "10.0.0.1/24"),
        ("PersistentKeepalive = 25", "PersistentKeepalive = 65536"),
        (
            "PersistentKeepalive = 25",
            "PersistentKeepalive = 25\nPresharedKey = bad",
        ),
    ] {
        let (mut invalid, state) = cold_owner("");
        invalid.configuration = zeroize::Zeroizing::new(invalid.configuration.replace(from, to));
        invalid.intent.config_sha256 = Sha256::digest(invalid.configuration.as_bytes()).into();
        assert!(invalid.prepare_readonly_native_profile().is_err(), "{to}");
        assert!(state.borrow().events.is_empty());
    }
    let (mut owner, _) = cold_owner("");
    let proof = owner.prepare_readonly_native_profile().unwrap();
    owner.configuration.push('\n'); // Same semantics are not SAME signed bytes.
    assert!(owner.verify_readonly_native_profile(&proof).is_err());
    owner.intent.config_sha256 = Sha256::digest(owner.configuration.as_bytes()).into();
    assert!(owner.prepare_readonly_native_profile().is_err());
    let (mut cleanup, _) = cold_owner("");
    cleanup.cleanup_only = true;
    assert!(cleanup.prepare_readonly_native_profile().is_err());
}

#[test]
fn carrier_member_start_publishes_and_hashes_only_addressless_native_configuration() {
    for (transport, extra) in [
        (TunnelTransport::WireGuard, ""),
        (
            TunnelTransport::AmneziaWg3,
            "Jc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n",
        ),
    ] {
        let (_, s) = setup();
        let logical = CARRIER_CONFIG.replace("[Peer]", &format!("{extra}[Peer]"));
        let expected = CARRIER_NATIVE.replace("[Peer]", &format!("{extra}[Peer]"));
        let mut owner = MemberOwner::from_trusted_carrier_engine(
            &carrier_intent(),
            TunnelSlot::B,
            transport,
            crate::test_engine_path("engine.exe"),
            &logical,
            Disk(s.clone()),
            Io(s.clone(), false),
        )
        .unwrap();
        // Construction cannot claim/start/configure anything; only the existing
        // durable Prepared→config CAS→native Start→Running path can do so.
        assert!(s.borrow().events.is_empty());
        let running = owner.start_with_prior(None).unwrap();
        assert_eq!(running.intent.scope, scope());
        assert_eq!(running.intent.transport, transport);
        assert_eq!(
            running.intent.config_sha256,
            <[u8; 32]>::from(Sha256::digest(expected.as_bytes()))
        );
        assert_ne!(
            running.intent.config_sha256,
            <[u8; 32]>::from(Sha256::digest(logical.as_bytes()))
        );
        assert_eq!(
            s.borrow().written_config.as_deref().map(|s| s.as_str()),
            Some(expected.as_str())
        );
        assert_eq!(running.proof, Some(proof()));
        assert_eq!(owner.stop(&running).unwrap().phase, Phase::Stopped);
    }
}

#[test]
fn carrier_member_rejects_mismatched_network_before_any_journal_or_native_call() {
    for addresses in [
        vec![],
        vec!["10.240.5.3/32".parse().unwrap()],
        vec!["10.240.5.2/24".parse().unwrap()],
        vec!["fd00::2/128".parse().unwrap()],
        vec![
            "10.240.5.2/32".parse().unwrap(),
            "10.240.5.3/32".parse().unwrap(),
        ],
    ] {
        let (_, s) = setup();
        let intent = crate::member_carrier::Intent {
            addresses,
            ..carrier_intent()
        };
        assert!(matches!(
            MemberOwner::from_trusted_carrier_engine(
                &intent,
                TunnelSlot::B,
                TunnelTransport::WireGuard,
                crate::test_engine_path("engine.exe"),
                CARRIER_CONFIG,
                Disk(s.clone()),
                Io(s.clone(), false),
            ),
            Err(OwnerError::Conflict)
        ));
        assert!(s.borrow().events.is_empty());
        assert!(s.borrow().record.is_none());
    }
}

#[test]
fn carrier_member_never_accepts_unvalidated_native_input_or_wrong_transport() {
    let cases = [
        (CARRIER_NATIVE.to_owned(), TunnelTransport::WireGuard),
        (
            CARRIER_CONFIG.replace("10.240.5.2/32", "10.240.5.2/24"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace("10.240.5.2/32", "fd00::2/128"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace("[Peer]", "PostUp = do-not-run\n[Peer]"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace("[Peer]", "ForeignOption = 1\n[Peer]"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace(
                "PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "PublicKey = invalid",
            ),
            TunnelTransport::WireGuard,
        ),
        (CARRIER_CONFIG.to_owned(), TunnelTransport::AmneziaWg3),
        (
            CARRIER_CONFIG.replace("[Peer]", "Jc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n[Peer]"),
            TunnelTransport::WireGuard,
        ),
    ];
    for (logical, transport) in cases {
        let (_, s) = setup();
        assert!(matches!(
            MemberOwner::from_trusted_carrier_engine(
                &carrier_intent(),
                TunnelSlot::B,
                transport,
                crate::test_engine_path("engine.exe"),
                &logical,
                Disk(s.clone()),
                Io(s.clone(), false),
            ),
            Err(OwnerError::Invalid)
        ));
        assert!(s.borrow().events.is_empty());
    }
}

#[test]
fn carrier_member_construction_keeps_actual_scope_and_engine_validation() {
    for (scope, engine) in [
        (
            SessionScope {
                connection_generation: 0,
                ..scope()
            },
            crate::test_engine_path("engine.exe"),
        ),
        (
            SessionScope {
                session_id: "foreign".into(),
                ..scope()
            },
            crate::test_engine_path("engine.exe"),
        ),
        (scope(), PathBuf::from("relative.exe")),
        (scope(), crate::test_engine_path("../engine.exe")),
    ] {
        let (_, s) = setup();
        let intent = crate::member_carrier::Intent {
            scope,
            ..carrier_intent()
        };
        assert!(matches!(
            MemberOwner::from_trusted_carrier_engine(
                &intent,
                TunnelSlot::B,
                TunnelTransport::WireGuard,
                engine,
                CARRIER_CONFIG,
                Disk(s.clone()),
                Io(s.clone(), false),
            ),
            Err(OwnerError::Invalid)
        ));
        assert!(s.borrow().events.is_empty());
    }
}

#[test]
fn ordinary_member_keeps_address_and_does_not_use_carrier_renderer() {
    let (_, s) = setup();
    let mut owner = MemberOwner::from_trusted_engine(
        scope(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        CARRIER_CONFIG,
        Disk(s.clone()),
        Io(s.clone(), false),
    )
    .unwrap();
    let running = owner.start_with_prior(None).unwrap();
    let expected = CARRIER_NATIVE.replace(
        "PrivateKey = PRIVATE-TEST-KEY\n",
        "PrivateKey = PRIVATE-TEST-KEY\nAddress = 10.240.5.2/32\n",
    );
    assert_eq!(
        s.borrow().written_config.as_deref().map(|s| s.as_str()),
        Some(expected.as_str())
    );
    assert_eq!(
        running.intent.config_sha256,
        <[u8; 32]>::from(Sha256::digest(expected.as_bytes()))
    );
}

#[test]
fn carrier_member_lost_prepare_ack_never_writes_config_or_starts() {
    let (_, s) = setup();
    s.borrow_mut().lost_save_ack = Some(Phase::Prepared);
    let mut owner = MemberOwner::from_trusted_carrier_engine(
        &carrier_intent(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        CARRIER_CONFIG,
        Disk(s.clone()),
        Io(s.clone(), false),
    )
    .unwrap();
    assert_eq!(owner.start_with_prior(None), Err(OwnerError::Journal));
    assert!(s.borrow().written_config.is_none());
    assert!(!s.borrow().events.contains(&"start"));
    assert_eq!(owner.start_with_prior(None), Err(OwnerError::Retired));
    assert_eq!(s.borrow().record.as_ref().unwrap().phase, Phase::Prepared);
}
fn replacement_engine(
    s: Shared,
    scope: SessionScope,
    engine: &std::path::Path,
) -> MemberOwner<Disk, Io> {
    MemberOwner::from_trusted_engine(
        scope,
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        PathBuf::from(engine),
        "[Interface]\nPrivateKey = NEXT-PRIVATE-KEY\n[Peer]\nPublicKey = next\n",
        Disk(s.clone()),
        Io(s, false),
    )
    .unwrap()
}

#[test]
fn reincarnation_stopped_predecessor_allows_new_engine_and_runtime_only_when_absent() {
    for (engine, runtime) in [
        (
            crate::test_engine_path("new-engine.exe"),
            RuntimeSlot::Stable,
        ),
        (crate::test_engine_path("engine.exe"), RuntimeSlot::Latest),
        (
            crate::test_engine_path("new-engine.exe"),
            RuntimeSlot::Latest,
        ),
    ] {
        let (mut old, s) = setup();
        let running = old.start().unwrap();
        let prior = old.stop(&running).unwrap();
        let mut cleanup = recover(&prior, s.clone()).unwrap();
        let next_scope = SessionScope {
            runtime,
            connection_generation: 4,
            ..scope()
        };
        s.borrow_mut().next_proof.process.creation_time += 1;
        let mut next = replacement_engine(s.clone(), next_scope.clone(), &engine);
        assert_eq!(next.prior_stopped().unwrap(), Some(prior.clone()));
        let current = next.start_with_prior(Some(&prior)).unwrap();
        assert_eq!(current.intent.engine, engine);
        assert_eq!(current.intent.scope, next_scope);
        assert_eq!(current.retired_proof, prior.retired_proof);
        assert_eq!(s.borrow().record.as_ref(), Some(&current));
        assert_eq!(old.start(), Err(OwnerError::Retired));
        assert_eq!(cleanup.start(), Err(OwnerError::Retired));
    }
}

#[test]
fn reincarnation_cross_runtime_still_rejects_live_foreign_stale_and_nonstopped_prior() {
    for mutation in 0..8 {
        let (mut old, s) = setup();
        let running = old.start().unwrap();
        let prior = old.stop(&running).unwrap();
        {
            let mut state = s.borrow_mut();
            state.events.clear();
            match mutation {
                0 => {
                    state.observation.service = Some(ServiceObservation {
                        exact_spec: true,
                        process: Some(proof().process),
                    })
                }
                1 => state.observation.alternative_service_present = true,
                2 => {
                    state.observation.service = Some(ServiceObservation {
                        exact_spec: false,
                        process: None,
                    })
                }
                3 => state.observation.retained_interfaces.push(InterfaceProof {
                    guid: [9; 16],
                    ..proof().interface
                }),
                4 => {
                    state
                        .record
                        .as_mut()
                        .unwrap()
                        .intent
                        .scope
                        .connection_generation += 1
                }
                5 => {
                    let mut record = prior.clone();
                    record.phase = Phase::Prepared;
                    state.record = Some(record);
                }
                6 => state.record = Some(running),
                _ => state.observation.config_sha256 = Some([99; 32]),
            }
        }
        let baseline = s.borrow().record.clone();
        let next_scope = SessionScope {
            runtime: RuntimeSlot::Latest,
            connection_generation: 4,
            ..scope()
        };
        let mut next = replacement_engine(
            s.clone(),
            next_scope,
            &crate::test_engine_path("new-engine.exe"),
        );
        // Bind the observed predecessor as a pair would. A changed journal
        // after capturing prior is never accepted merely because it is Stopped.
        let bound_prior = if matches!(mutation, 5 | 6) {
            baseline.as_ref()
        } else {
            Some(&prior)
        };
        assert!(next.start_with_prior(bound_prior).is_err());
        assert_eq!(s.borrow().record, baseline);
        assert!(!s
            .borrow()
            .events
            .iter()
            .any(|e| matches!(*e, "prepared" | "config" | "start" | "stop")));
    }
}

#[test]
fn reincarnation_fresh_owner_replaces_stopped_same_or_new_scope_without_deleting_journal() {
    for next_scope in [
        scope(),
        SessionScope {
            connection_generation: 4,
            ..scope()
        },
    ] {
        let (mut original, shared) = setup();
        let running = original.start().unwrap();
        let stopped = original.stop(&running).unwrap();
        shared.borrow_mut().events.clear();
        shared.borrow_mut().next_proof.process.creation_time += 1;
        let mut next = replacement(shared.clone(), next_scope.clone());
        let running = next.start().unwrap();
        assert_eq!(running.phase, Phase::Running);
        assert_eq!(running.intent.scope, next_scope);
        assert_ne!(running.intent.config_sha256, stopped.intent.config_sha256);
        assert_eq!(running.retired_proof, stopped.retired_proof);
        assert_eq!(shared.borrow().record.as_ref(), Some(&running));
        assert!(original.start().is_err());
        assert!(original.stop(&stopped).is_err());
        let stopped = next.stop(&running).unwrap();
        assert!(next.start().is_err());
        assert_eq!(shared.borrow().record.as_ref(), Some(&stopped));
    }
}

#[test]
fn reincarnation_attempt_consumes_fresh_owner_even_when_first_save_fails() {
    let (mut original, shared) = setup();
    shared.borrow_mut().fail_save = Some(Phase::Prepared);
    assert_eq!(original.start().unwrap_err(), OwnerError::Journal);
    shared.borrow_mut().fail_save = None;
    shared.borrow_mut().events.clear();
    assert_eq!(original.start().unwrap_err(), OwnerError::Retired);
    assert!(shared.borrow().record.is_none());
    assert!(shared.borrow().events.is_empty());
}

#[test]
fn reincarnation_stop_consumes_even_a_fresh_owner_used_only_for_cleanup() {
    let (mut original, s) = setup();
    let running = original.start().unwrap();
    let mut other = owner(s.clone());
    other.stop(&running).unwrap();
    s.borrow_mut().events.clear();
    assert_eq!(other.start(), Err(OwnerError::Retired));
    assert!(s.borrow().events.is_empty());
}

#[test]
fn reincarnation_rejects_orphan_config_foreign_service_and_retained_identity_before_cas() {
    for mutation in 0..7 {
        let (mut original, shared) = setup();
        let running = original.start().unwrap();
        let stopped = original.stop(&running).unwrap();
        {
            let mut s = shared.borrow_mut();
            s.events.clear();
            match mutation {
                0 => s.observation.config_sha256 = Some([9; 32]),
                1 => s.observation.alternative_service_present = true,
                2 => {
                    s.observation.service = Some(ServiceObservation {
                        exact_spec: false,
                        process: None,
                    })
                }
                3 => {
                    s.observation.service = Some(ServiceObservation {
                        exact_spec: true,
                        process: Some(ProcessProof {
                            pid: 20,
                            creation_time: 99,
                        }),
                    })
                }
                4 => s.observation.retained_interfaces.push(InterfaceProof {
                    guid: [9; 16],
                    ..proof().interface
                }),
                5 => s.observation.interface = Some(proof().interface),
                _ => s.record.as_mut().unwrap().proof = Some(proof()),
            }
        }
        assert!(replacement(shared.clone(), scope()).start().is_err());
        assert!(!shared
            .borrow()
            .events
            .iter()
            .any(|e| matches!(*e, "prepared" | "config" | "start")));
        if mutation != 6 {
            assert_eq!(shared.borrow().record, Some(stopped));
        }
    }
}

#[test]
fn reincarnation_failed_boundaries_never_start_before_previous_digest_is_durably_cleared() {
    for boundary in 0..6 {
        let (mut original, shared) = setup();
        let running = original.start().unwrap();
        let stopped = original.stop(&running).unwrap();
        {
            let mut s = shared.borrow_mut();
            s.events.clear();
            s.save_count = 0;
            match boundary {
                0 => s.fail_save_number = Some(1),
                1 => s.lost_save_number = Some(1),
                2 => s.fail_config = true,
                3 => s.lost_config_ack = true,
                4 => s.fail_save_number = Some(2),
                _ => s.lost_save_number = Some(2),
            }
        }
        let mut next = replacement(shared.clone(), scope());
        assert!(next.start().is_err());
        assert!(next.start().is_err());
        assert!(!shared.borrow().events.contains(&"start"));
        let s = shared.borrow();
        let saved = s.record.as_ref().unwrap();
        if boundary == 0 {
            assert_eq!(saved, &stopped);
        } else {
            assert_eq!(saved.phase, Phase::Prepared);
            assert_eq!(
                saved.previous_config_sha256,
                if boundary == 5 {
                    None
                } else {
                    Some(stopped.intent.config_sha256)
                }
            );
            assert_eq!(saved.retired_proof, stopped.retired_proof);
        }
        assert_eq!(
            s.observation.config_sha256,
            Some(if boundary <= 2 {
                stopped.intent.config_sha256
            } else {
                next.intent().config_sha256
            })
        );
    }
}

#[test]
fn reincarnation_transition_cleanup_retains_actual_old_new_or_absent_config_without_writing() {
    for digest in 0..3 {
        let (mut original, s) = setup();
        let running = original.start().unwrap();
        let old = original.stop(&running).unwrap();
        s.borrow_mut().fail_config = true;
        let mut next = replacement(s.clone(), scope());
        assert!(next.start().is_err());
        let prepared = s.borrow().record.clone().unwrap();
        let observed = match digest {
            0 => Some(old.intent.config_sha256),
            1 => Some(prepared.intent.config_sha256),
            _ => None,
        };
        s.borrow_mut().observation.config_sha256 = observed;
        s.borrow_mut().events.clear();
        let mut cleanup = recover(&prepared, s.clone()).unwrap();
        let stopped = cleanup.stop(&prepared).unwrap();
        assert_eq!(stopped.phase, Phase::Stopped);
        assert_eq!(
            stopped.previous_config_sha256,
            Some(old.intent.config_sha256)
        );
        assert_eq!(s.borrow().observation.config_sha256, observed);
        assert!(!s
            .borrow()
            .events
            .iter()
            .any(|v| matches!(*v, "config" | "start" | "stop")));
        assert!(cleanup.start().is_err());
        assert!(cleanup.confirm_absent(&stopped).unwrap());
        s.borrow_mut().save_count = 0;
        s.borrow_mut().lost_save_number = Some(1);
        let mut third = replacement(s.clone(), scope());
        assert!(third.start().is_err());
        assert_eq!(
            s.borrow().record.as_ref().unwrap().previous_config_sha256,
            observed
        );
    }
}

#[test]
fn reincarnation_transition_cleanup_lost_terminal_ack_is_exactly_recoverable() {
    let (mut original, s) = setup();
    let running = original.start().unwrap();
    original.stop(&running).unwrap();
    s.borrow_mut().fail_config = true;
    let mut next = replacement(s.clone(), scope());
    assert!(next.start().is_err());
    let prepared = s.borrow().record.clone().unwrap();
    let mut cleanup = recover(&prepared, s.clone()).unwrap();
    s.borrow_mut().lost_save_ack = Some(Phase::Stopped);
    assert_eq!(cleanup.stop(&prepared), Err(OwnerError::Journal));
    let stopped = s.borrow().record.clone().unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    s.borrow_mut().lost_save_ack = None;
    assert_eq!(
        recover(&stopped, s.clone())
            .unwrap()
            .stop(&stopped)
            .unwrap(),
        stopped
    );
    for mode in 0..3 {
        let mut bad = prepared.clone();
        if mode == 0 {
            bad.phase = Phase::Running;
            bad.proof = Some(proof());
        }
        if mode == 1 {
            bad.phase = Phase::Stopping;
        }
        if mode == 2 {
            bad.phase = Phase::Stopped;
            bad.proof = Some(proof());
        }
        s.borrow_mut().record = Some(bad.clone());
        assert!(recover(&bad, s.clone()).is_err());
    }
}

#[test]
fn retired_process_absence_rejects_live_or_recycled_pid_even_without_scm_name() {
    let old = proof().process;
    assert!(require_retired_process_absent(&old, None).is_ok());
    assert!(require_retired_process_absent(&old, Some((old, 0))).is_ok());
    assert_eq!(
        require_retired_process_absent(&old, Some((old, 259))),
        Err(OwnerError::Pending)
    );
    assert_eq!(
        require_retired_process_absent(
            &old,
            Some((
                ProcessProof {
                    creation_time: 99,
                    ..old
                },
                0
            ))
        ),
        Err(OwnerError::Conflict)
    );
}

#[test]
fn reincarnation_pair_bound_prior_rejects_old_writer_before_config_or_native_effects() {
    let (mut original, s) = setup();
    let running = original.start().unwrap();
    let old = original.stop(&running).unwrap();
    let mut next = replacement(s.clone(), scope());
    assert_eq!(next.prior_stopped().unwrap(), Some(old.clone()));
    s.borrow_mut()
        .record
        .as_mut()
        .unwrap()
        .intent
        .scope
        .connection_generation += 1;
    s.borrow_mut().events.clear();
    assert_eq!(next.start_with_prior(Some(&old)), Err(OwnerError::Conflict));
    assert!(s.borrow().events.is_empty());
    assert!(original.stop(&old).is_err());
}

fn recover(saved: &Record, s: Shared) -> Result<MemberOwner<Disk, Io>> {
    MemberOwner::recover_for_cleanup(
        scope(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        saved.clone(),
        Disk(s.clone()),
        Io(s, false),
    )
}
#[test]
fn recovery_has_no_start_or_rebind_authority_and_closes_exact_saved_proof() {
    let (mut original, shared) = setup();
    let saved = original.start().unwrap();
    shared.borrow_mut().events.clear();
    let mut recovered = recover(&saved, shared.clone()).unwrap();
    assert!(recovered.start().is_err());
    assert!(recovered.rebind(&saved).is_err());
    assert!(shared.borrow().events.is_empty());
    assert_eq!(recovered.stop(&saved).unwrap().phase, Phase::Stopped);
    assert!(!shared.borrow().events.contains(&"start"));
    assert!(!shared.borrow().events.contains(&"config"));
}
#[test]
fn recovery_rejects_changed_saved_scope_engine_and_journal_record() {
    let (mut original, shared) = setup();
    let saved = original.start().unwrap();
    for field in 0..3 {
        let mut changed = saved.clone();
        match field {
            0 => changed.intent.scope.connection_generation += 1,
            1 => changed.intent.engine = crate::test_engine_path("other-engine.exe"),
            _ => changed.proof.as_mut().unwrap().process.creation_time += 1,
        }
        assert!(recover(&changed, shared.clone()).is_err());
    }
}
#[test]
fn cleanup_recovery_never_adopts_unproven_live_process_after_partial_start() {
    let (mut original, shared) = setup();
    let mut saved = original.start().unwrap();
    saved.phase = Phase::Prepared;
    saved.proof = None;
    shared.borrow_mut().record = Some(saved.clone());
    shared.borrow_mut().events.clear();
    let mut recovered = recover(&saved, shared.clone()).unwrap();
    assert!(recovered.stop(&saved).is_err());
    assert!(!shared.borrow().events.contains(&"stop"));
}
#[test]
fn physical_discovery_accepts_exact_stopped_service_without_granting_absence_or_liveness() {
    let (mut owner, s) = setup();
    let running = owner.start().unwrap();
    {
        let mut state = s.borrow_mut();
        state.observation.service.as_mut().unwrap().process = None;
        state.observation.interface = None;
        state.observation.retained_interfaces.clear();
        state.events.clear();
    }
    assert!(!owner.confirm_absent(&running).unwrap());
    assert!(owner.confirm_inactive_for_discovery(&running).unwrap());
    assert!(owner.verify_live(&running).is_err());
    assert_eq!(s.borrow().record, Some(running));
    assert!(s.borrow().events.iter().all(|e| *e == "inspect"));
    assert_eq!(owner.start(), Err(OwnerError::Retired));
}

#[test]
fn physical_discovery_stopped_service_rejects_unproven_identity_config_and_read_errors() {
    for mutation in 0..10 {
        let (mut owner, s) = setup();
        let running = owner.start().unwrap();
        {
            let mut state = s.borrow_mut();
            state.observation.service.as_mut().unwrap().process = None;
            state.observation.interface = None;
            state.observation.retained_interfaces.clear();
            match mutation {
                0 => state.observation.service.as_mut().unwrap().exact_spec = false,
                1 => {
                    state.observation.service.as_mut().unwrap().process = Some(ProcessProof {
                        creation_time: 99,
                        ..proof().process
                    })
                }
                2 => state.observation.interface = Some(proof().interface),
                3 => state.observation.retained_interfaces.push(InterfaceProof {
                    guid: [99; 16],
                    ..proof().interface
                }),
                4 => state.observation.config_sha256 = None,
                5 => state.observation.config_sha256 = Some([99; 32]),
                6 => state.observation.alternative_service_present = true,
                7 => {
                    state
                        .record
                        .as_mut()
                        .unwrap()
                        .intent
                        .scope
                        .connection_generation += 1
                }
                8 => state.fail_capture = true,
                _ => state.record.as_mut().unwrap().proof = None,
            }
            state.events.clear();
        }
        let baseline = s.borrow().record.clone();
        assert!(
            !matches!(owner.confirm_inactive_for_discovery(&running), Ok(true)),
            "mutation {mutation}"
        );
        assert_eq!(s.borrow().record, baseline);
        assert!(s.borrow().events.iter().all(|e| *e == "inspect"));
    }
}

#[test]
fn read_only_live_check_rejects_guid_reuse_without_native_effects() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    s.borrow_mut().events.clear();
    o.verify_live(&r).unwrap();
    s.borrow_mut().observation.interface.as_mut().unwrap().guid = [9; 16];
    assert!(o.verify_live(&r).is_err());
    assert!(s.borrow().events.iter().all(|v| *v == "inspect"));
}
#[test]
fn stopping_disk_failure_still_cuts_exact_native_and_retains_saved_proof() {
    let (mut owner, s) = setup();
    let saved = owner.start().unwrap();
    s.borrow_mut().fail_save = Some(Phase::Stopping);
    assert_eq!(owner.stop_best_effort(&saved), Err(OwnerError::Journal));
    assert!(s.borrow().observation.service.is_none());
    assert_eq!(s.borrow().record, Some(saved));
}
#[test]
fn retired_absence_proof_rejects_reused_native_interface() {
    let (mut owner, s) = setup();
    let saved = owner.start().unwrap();
    let stopped = owner.stop(&saved).unwrap();
    assert!(owner.confirm_absent(&stopped).unwrap());
    s.borrow_mut()
        .observation
        .retained_interfaces
        .push(proof().interface);
    assert!(owner.confirm_absent(&stopped).is_err());
}
#[test]
fn prepared_is_durable_before_config_and_start_running_carries_exact_proof() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    assert_eq!(r.phase, Phase::Running);
    assert_eq!(r.proof, Some(proof()));
    assert_eq!(
        s.borrow().events,
        ["inspect", "prepared", "inspect", "config", "inspect", "start", "inspect", "running"]
    );
    assert_ne!(r.intent.config_sha256, [0; 32]);
    assert!(!serde_json::to_string(&r)
        .unwrap()
        .contains("PRIVATE-TEST-KEY"));
    assert_eq!(
        serde_json::from_str::<Record>(&serde_json::to_string(&r).unwrap()).unwrap(),
        r
    );
}
#[test]
fn before_start_journal_failure_has_no_effects() {
    let (mut o, s) = setup();
    s.borrow_mut().fail_save = Some(Phase::Prepared);
    assert_eq!(o.start(), Err(OwnerError::Journal));
    assert!(s.borrow().observation.service.is_none());
    assert!(s.borrow().observation.config_sha256.is_none());
}
#[test]
fn crash_gap_and_capture_or_running_save_failure_keep_prepared_cleanup_authority() {
    for mode in 0..3 {
        let (mut o, s) = setup();
        match mode {
            0 => s.borrow_mut().fail_start = true,
            1 => s.borrow_mut().fail_capture = true,
            _ => s.borrow_mut().fail_save = Some(Phase::Running),
        };
        assert!(o.start().is_err());
        let saved = s.borrow().record.clone().unwrap();
        assert_eq!(saved.phase, Phase::Prepared);
        s.borrow_mut().fail_capture = false;
        s.borrow_mut().fail_save = None;
        let mut recovered = owner(s.clone());
        assert_eq!(recovered.stop(&saved).unwrap().phase, Phase::Stopped);
        assert!(s.borrow().observation.service.is_none());
    }
}
#[test]
fn prepared_without_any_start_cleans_without_scm_call() {
    let (mut o, s) = setup();
    s.borrow_mut().fail_save = Some(Phase::Running);
    assert!(o.start().is_err());
    let saved = s.borrow().record.clone().unwrap();
    s.borrow_mut().observation.service = None;
    s.borrow_mut().observation.interface = None;
    s.borrow_mut().fail_save = None;
    s.borrow_mut().events.clear();
    assert_eq!(owner(s.clone()).stop(&saved).unwrap().phase, Phase::Stopped);
    assert!(!s.borrow().events.contains(&"stop"));
}
#[test]
fn both_transport_names_and_interface_must_be_absent_before_start() {
    for mode in 0..3 {
        let (mut o, s) = setup();
        match mode {
            0 => s.borrow_mut().observation.alternative_service_present = true,
            1 => {
                s.borrow_mut().observation.service = Some(ServiceObservation {
                    exact_spec: true,
                    process: None,
                })
            }
            _ => s.borrow_mut().observation.interface = Some(proof().interface),
        };
        assert_eq!(o.start(), Err(OwnerError::Conflict));
        assert!(s.borrow().record.is_none());
        assert!(!s.borrow().events.contains(&"start"));
    }
}
#[test]
fn prepared_cleanup_never_trusts_name_without_exact_spec_and_private_digest() {
    for mode in 0..3 {
        let (mut o, s) = setup();
        s.borrow_mut().fail_start = true;
        assert!(o.start().is_err());
        let saved = s.borrow().record.clone().unwrap();
        match mode {
            0 => {
                s.borrow_mut()
                    .observation
                    .service
                    .as_mut()
                    .unwrap()
                    .exact_spec = false
            }
            1 => s.borrow_mut().observation.config_sha256 = Some([1; 32]),
            _ => s.borrow_mut().observation.config_sha256 = None,
        };
        assert_eq!(o.stop(&saved), Err(OwnerError::Conflict));
        assert!(!s.borrow().events.contains(&"stop"));
        assert_eq!(s.borrow().record.as_ref().unwrap().phase, Phase::Prepared);
    }
}
#[test]
fn pid_creation_index_luid_and_guid_reuse_never_authorizes_cleanup_or_rebind() {
    for mode in 0..5 {
        let (mut o, s) = setup();
        let r = o.start().unwrap();
        match mode {
            0 => {
                s.borrow_mut()
                    .observation
                    .service
                    .as_mut()
                    .unwrap()
                    .process
                    .as_mut()
                    .unwrap()
                    .pid += 1
            }
            1 => {
                s.borrow_mut()
                    .observation
                    .service
                    .as_mut()
                    .unwrap()
                    .process
                    .as_mut()
                    .unwrap()
                    .creation_time += 1
            }
            2 => s.borrow_mut().observation.interface.as_mut().unwrap().index += 1,
            3 => s.borrow_mut().observation.interface.as_mut().unwrap().luid += 1,
            _ => s.borrow_mut().observation.interface.as_mut().unwrap().guid = [8; 16],
        };
        assert_eq!(o.stop(&r), Err(OwnerError::Conflict));
        assert_eq!(o.rebind(&r), Err(OwnerError::Conflict));
        assert!(!s.borrow().events.contains(&"stop"));
        assert!(!s.borrow().events.contains(&"rebind"));
    }
}
#[test]
fn absent_service_and_interface_is_complete_but_reused_retained_index_is_not() {
    for reuse in [false, true] {
        let (mut o, s) = setup();
        let r = o.start().unwrap();
        s.borrow_mut().observation.service = None;
        s.borrow_mut().observation.interface = None;
        if reuse {
            s.borrow_mut().observation.retained_interfaces = vec![InterfaceProof {
                index: 40,
                luid: 999,
                guid: [9; 16],
            }];
            assert_eq!(o.stop(&r), Err(OwnerError::Conflict));
        } else {
            assert_eq!(o.stop(&r).unwrap().phase, Phase::Stopped);
        }
        assert!(!s.borrow().events.contains(&"stop"));
    }
}
#[test]
fn partial_stop_stays_stopping_and_recovery_never_touches_sibling() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    s.borrow_mut().fail_stop = true;
    assert_eq!(o.stop(&r), Err(OwnerError::Native));
    let stopping = s.borrow().record.clone().unwrap();
    assert_eq!(stopping.phase, Phase::Stopping);
    s.borrow_mut().fail_stop = false;
    assert_eq!(
        owner(s.clone()).stop(&stopping).unwrap().phase,
        Phase::Stopped
    );
}
#[test]
fn wrong_scope_or_retired_proof_has_no_effects() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    let mut wrong = r.clone();
    wrong.intent.scope.connection_generation += 1;
    s.borrow_mut().events.clear();
    assert_eq!(o.stop(&wrong), Err(OwnerError::Conflict));
    assert!(s.borrow().events.is_empty());
    let stopped = o.stop(&r).unwrap();
    s.borrow_mut().events.clear();
    assert_eq!(o.stop(&r), Err(OwnerError::Conflict));
    assert_eq!(o.stop(&stopped).unwrap(), stopped);
    assert!(s.borrow().events.is_empty());
    assert_eq!(o.start(), Err(OwnerError::Retired));
}
#[test]
fn rebind_journals_prepared_then_new_proof_and_rejects_retired_proof() {
    let (mut o, s) = setup();
    let old = o.start().unwrap();
    s.borrow_mut().events.clear();
    let new = o.rebind(&old).unwrap();
    assert_ne!(new.proof, old.proof);
    assert_eq!(new.retired_proof, old.proof);
    assert_eq!(
        s.borrow().events,
        ["inspect", "prepared", "rebind", "inspect", "running"]
    );
    assert_eq!(o.stop(&old), Err(OwnerError::Conflict));
}
#[test]
fn rebind_failure_or_unchanged_process_never_restores_running_authority() {
    for no_change in [false, true] {
        let (mut o, s) = setup();
        let old = o.start().unwrap();
        s.borrow_mut().fail_rebind = !no_change;
        s.borrow_mut().changed_after_capture = no_change;
        assert!(o.rebind(&old).is_err());
        assert_eq!(s.borrow().record.as_ref().unwrap().phase, Phase::Prepared);
    }
}

#[test]
fn stopping_save_failure_and_identity_change_after_save_never_issue_stop() {
    for changed in [false, true] {
        let (mut o, s) = setup();
        let r = o.start().unwrap();
        if changed {
            s.borrow_mut().change_after_stopping = true;
        } else {
            s.borrow_mut().fail_save = Some(Phase::Stopping);
        }
        assert_eq!(
            o.stop(&r),
            Err(if changed {
                OwnerError::Conflict
            } else {
                OwnerError::Journal
            })
        );
        assert!(!s.borrow().events.contains(&"stop"));
    }
}

#[test]
fn stopped_save_failure_leaves_durable_stopping_for_idempotent_completion() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    s.borrow_mut().fail_save = Some(Phase::Stopped);
    assert_eq!(o.stop(&r), Err(OwnerError::Journal));
    let stopping = s.borrow().record.clone().unwrap();
    assert_eq!(stopping.phase, Phase::Stopping);
    assert!(s.borrow().observation.service.is_none());
    s.borrow_mut().fail_save = None;
    s.borrow_mut().events.clear();
    assert_eq!(
        owner(s.clone()).stop(&stopping).unwrap().phase,
        Phase::Stopped
    );
    assert!(!s.borrow().events.contains(&"stop"));
}

#[test]
fn lost_journal_ack_is_reconciled_by_reread_never_duplicate_start() {
    for phase in [Phase::Prepared, Phase::Running] {
        let (mut o, s) = setup();
        s.borrow_mut().lost_save_ack = Some(phase);
        assert_eq!(o.start(), Err(OwnerError::Journal));
        let record = o.snapshot().unwrap().unwrap();
        assert_eq!(record.phase, phase);
        assert_eq!(o.start(), Err(OwnerError::Retired));
        assert_eq!(
            s.borrow()
                .events
                .iter()
                .filter(|op| **op == "start")
                .count(),
            usize::from(phase == Phase::Running)
        );
        s.borrow_mut().lost_save_ack = None;
        assert_eq!(
            owner(s.clone()).stop(&record).unwrap().phase,
            Phase::Stopped
        );
    }
}

#[test]
fn wrong_journal_identity_and_malformed_proof_fail_before_native_inspection() {
    for mode in 0..5 {
        let (mut o, s) = setup();
        let mut r = o.start().unwrap();
        match mode {
            0 => r.intent.scope.runtime_generation += 1,
            1 => r.intent.slot = TunnelSlot::A,
            2 => r.intent.engine = crate::test_engine_path("foreign-engine.exe"),
            3 => r.intent.config_sha256 = [7; 32],
            _ => r.proof.as_mut().unwrap().interface.index = 0,
        };
        s.borrow_mut().record = Some(r);
        s.borrow_mut().events.clear();
        assert!(o.snapshot().is_err());
        assert!(o.start().is_err());
        assert!(s.borrow().events.is_empty());
    }
}

#[test]
fn rebind_save_failure_has_no_scm_effect_and_running_save_failure_is_recoverable() {
    for phase in [Phase::Prepared, Phase::Running] {
        let (mut o, s) = setup();
        let old = o.start().unwrap();
        s.borrow_mut().fail_save = Some(phase);
        assert_eq!(o.rebind(&old), Err(OwnerError::Journal));
        if phase == Phase::Prepared {
            assert!(!s.borrow().events.contains(&"rebind"));
            assert_eq!(o.snapshot().unwrap(), Some(old));
        } else {
            let prepared = o.snapshot().unwrap().unwrap();
            assert_eq!(prepared.phase, Phase::Prepared);
            s.borrow_mut().fail_save = None;
            assert_eq!(o.stop(&prepared).unwrap().phase, Phase::Stopped);
        }
    }
}

#[test]
fn journal_cannot_revive_a_retired_process_proof() {
    let (mut o, s) = setup();
    let mut r = o.start().unwrap();
    r.retired_proof = r.proof;
    s.borrow_mut().record = Some(r);
    s.borrow_mut().events.clear();
    assert_eq!(o.snapshot(), Err(OwnerError::Invalid));
    assert!(s.borrow().events.is_empty());
}

// External file/native reads are the only fault boundary. MemberOwner's real
// start/config/CAS/proof/cleanup paths remain in use, including partial effects.
fn read_boundary(s: &mut State, error: OwnerError) -> Result<()> {
    s.read_step += 1;
    if s.panic_read_step == Some(s.read_step) {
        panic!("injected read unwind");
    }
    if s.fail_read_step == Some(s.read_step) {
        return Err(error);
    }
    if s.drift_read_step == Some(s.read_step) {
        s.record
            .as_mut()
            .unwrap()
            .intent
            .scope
            .connection_generation += 1;
    }
    Ok(())
}

fn original_read(o: &mut MemberOwner<Disk, Io>) -> Result<(Intent, NativeProof)> {
    o.original_live()?.read()
}

#[test]
fn original_live_equal_lookup_without_native_new_receipt_cannot_read() {
    // Break caught: original reads use ordinary name/PID inspection instead of
    // requiring the native adapter's retained NEW service/process receipt.
    let (mut o, s) = setup();
    let running = o.start().unwrap();
    s.borrow_mut().original_available = false;
    o.verify_live(&running).unwrap();
    assert_eq!(original_read(&mut o), Err(OwnerError::Retired));
    s.borrow_mut().original_available = true;
    assert_eq!(original_read(&mut o), Err(OwnerError::Retired));
    assert_eq!(o.stop(&running).unwrap().phase, Phase::Stopped);
}

// These doubles replace only SCM/process calls, not the retention/read policy.
// IDs distinguish kernel objects with equal service names and recycled PIDs.
struct ScmHandle(u8, Rc<std::cell::Cell<usize>>);
impl Drop for ScmHandle {
    fn drop(&mut self) {
        self.1.set(self.1.get() + 1);
    }
}
struct ProcessHandle(u8, Rc<std::cell::Cell<usize>>);
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        self.1.set(self.1.get() + 1);
    }
}
struct OriginBoundary {
    cleanup_state: Option<ServiceCleanupState>,
    image_matches: bool,
    split_start: bool,
    split_fault: u8,
    started_intent: Option<Intent>,
    start_calls: usize,
    service_id: u8,
    process_id: u8,
    process: ProcessProof,
    exit_code: u32,
    facts: OriginalMemberFacts,
    fail_create: bool,
    fail_finish: bool,
    panic_finish: bool,
    fail_query: bool,
    fail_query_once: bool,
    panic_query: bool,
    service_reads: usize,
    drift_after_first: bool,
    service_closes: Rc<std::cell::Cell<usize>>,
    process_closes: Rc<std::cell::Cell<usize>>,
    delete_calls: usize,
    delete_ack: bool,
    fail_delete: bool,
    panic_delete: bool,
    retired_process: Option<(u8, ProcessProof, u32)>,
    stop_still_active: bool,
    restart_fault: u8,
}
impl OriginBoundary {
    fn live() -> Self {
        Self {
            cleanup_state: None,
            image_matches: true,
            split_start: false,
            split_fault: 0,
            started_intent: None,
            start_calls: 0,
            service_id: 1,
            process_id: 1,
            process: proof().process,
            exit_code: 259,
            facts: OriginalMemberFacts {
                exact_spec: true,
                pid: 20,
                alternative_service_present: false,
                interface: Some(proof().interface),
                retained_interfaces: vec![proof().interface],
            },
            fail_create: false,
            fail_finish: false,
            panic_finish: false,
            fail_query: false,
            fail_query_once: false,
            panic_query: false,
            service_reads: 0,
            drift_after_first: false,
            service_closes: Rc::new(std::cell::Cell::new(0)),
            process_closes: Rc::new(std::cell::Cell::new(0)),
            delete_calls: 0,
            delete_ack: false,
            fail_delete: false,
            panic_delete: false,
            retired_process: None,
            stop_still_active: false,
            restart_fault: 0,
        }
    }
}
impl OriginalMemberNative for OriginBoundary {
    type Service = ScmHandle;
    type Process = ProcessHandle;
    fn create(&mut self, intent: &Intent) -> Result<ScmHandle> {
        if self.fail_create {
            Err(OwnerError::Native)
        } else {
            self.started_intent = Some(intent.clone());
            Ok(ScmHandle(self.service_id, self.service_closes.clone()))
        }
    }
    fn finish_created(&mut self, _: &ScmHandle) -> Result<()> {
        assert!(!self.panic_finish, "injected post-create unwind");
        if self.fail_finish {
            Err(OwnerError::Native)
        } else {
            Ok(())
        }
    }
    fn running_pid(&mut self, service: &ScmHandle) -> Result<u32> {
        if service.0 != self.service_id {
            return Err(OwnerError::Conflict);
        }
        Ok(self.facts.pid)
    }
    fn pin_process(&mut self, pid: u32) -> Result<ProcessHandle> {
        if self.split_fault == 10 {
            return Err(OwnerError::Native);
        }
        assert_eq!(pid, self.process.pid);
        Ok(ProcessHandle(self.process_id, self.process_closes.clone()))
    }
    fn query_process(&mut self, handle: &ProcessHandle) -> Result<(ProcessProof, u32)> {
        assert!(!self.panic_query, "injected process query unwind");
        if std::mem::take(&mut self.fail_query_once) {
            return Err(OwnerError::Native);
        }
        if self.fail_query {
            return Err(OwnerError::Native);
        }
        if let Some((id, proof, code)) = self.retired_process {
            if id == handle.0 {
                return Ok((proof, code));
            }
        }
        if handle.0 != self.process_id {
            return Err(OwnerError::Conflict);
        }
        Ok((self.process, self.exit_code))
    }
    fn observe(
        &mut self,
        service: &ScmHandle,
        _: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<OriginalMemberFacts> {
        if service.0 != self.service_id {
            return Err(OwnerError::Conflict);
        }
        self.service_reads += 1;
        if self.drift_after_first && self.service_reads == 2 {
            self.facts.pid += 1;
        }
        Ok(OriginalMemberFacts {
            exact_spec: self.facts.exact_spec,
            pid: self.facts.pid,
            alternative_service_present: self.facts.alternative_service_present,
            interface: self.facts.interface,
            retained_interfaces: if retained.is_some() {
                self.facts.retained_interfaces.clone()
            } else {
                vec![]
            },
        })
    }
    fn observe_cleanup(
        &mut self,
        service: &ScmHandle,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<Observation> {
        let facts = self.observe(service, intent, retained)?;
        Ok(Observation {
            config_sha256: Some(intent.config_sha256),
            service: Some(ServiceObservation {
                exact_spec: facts.exact_spec,
                process: Some(self.process),
            }),
            alternative_service_present: facts.alternative_service_present,
            interface: facts.interface,
            retained_interfaces: facts.retained_interfaces,
        })
    }
    fn stop(&mut self, _: &ScmHandle) -> Result<()> {
        if self.stop_still_active {
            return Ok(()); // SCM ACK without actual original-process exit.
        }
        self.exit_code = 0;
        self.facts.pid = 0;
        self.cleanup_state = Some(ServiceCleanupState::Stopped);
        Ok(())
    }
    fn start_existing(&mut self, service: &ScmHandle) -> Result<()> {
        if service.0 != self.service_id || self.exit_code == 259 {
            return Err(OwnerError::Conflict);
        }
        self.retired_process = Some((self.process_id, self.process, self.exit_code));
        self.process_id += 1;
        self.process.pid += 1;
        self.process.creation_time += 1;
        self.exit_code = 259;
        self.facts.pid = self.process.pid;
        match self.restart_fault {
            1 => return Err(OwnerError::Native), // Lost ACK after actual restart.
            2 => panic!("injected restart unwind"),
            3 => self.fail_query = true,
            4 => self.panic_query = true,
            5 => self.facts.interface.as_mut().unwrap().index += 1,
            _ => {}
        }
        Ok(())
    }
    fn delete(&mut self, _: &ScmHandle) -> Result<()> {
        self.delete_calls += 1;
        assert!(!self.panic_delete, "injected delete unwind");
        if self.fail_delete {
            return Err(OwnerError::Native);
        }
        self.delete_ack = true;
        Ok(())
    }
}

fn origin_cleanup_observation(intent: &Intent) -> Observation {
    Observation {
        config_sha256: Some(intent.config_sha256),
        service: Some(ServiceObservation {
            exact_spec: true,
            process: Some(proof().process),
        }),
        alternative_service_present: false,
        interface: Some(proof().interface),
        retained_interfaces: vec![],
    }
}

impl OriginalServiceCleanupNative for OriginBoundary {
    fn verify_cleanup_process_image(&mut self, process: &ProcessHandle, _: &Intent) -> Result<()> {
        if process.0 != self.process_id || !self.image_matches {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    fn service_cleanup_facts(
        &mut self,
        service: &ScmHandle,
        _: &Intent,
    ) -> Result<ServiceCleanupFacts> {
        if service.0 != self.service_id {
            return Err(OwnerError::Conflict);
        }
        self.service_reads += 1;
        if self.drift_after_first && self.service_reads == 2 {
            self.facts.pid += 1;
        }
        Ok(ServiceCleanupFacts {
            exact_spec: self.facts.exact_spec,
            pid: self.facts.pid,
            state: self.cleanup_state.unwrap_or(if self.facts.pid == 0 {
                ServiceCleanupState::Stopped
            } else {
                ServiceCleanupState::Running
            }),
            alternative_service_present: self.facts.alternative_service_present,
        })
    }
}

impl OriginalMemberStartNative for OriginBoundary {
    fn configure_created(&mut self, service: &ScmHandle, intent: &Intent) -> Result<()> {
        if service.0 != self.service_id || self.started_intent.as_ref() != Some(intent) {
            return Err(OwnerError::Conflict);
        }
        if self.split_fault == 1 {
            return Err(OwnerError::Native);
        }
        Ok(())
    }
    fn start_created(&mut self, service: &ScmHandle) -> Result<()> {
        if service.0 != self.service_id {
            return Err(OwnerError::Conflict);
        }
        self.start_calls += 1;
        assert!(self.split_fault != 3, "lost Start ACK unwind");
        if self.split_fault == 2 {
            return Err(OwnerError::Native);
        }
        Ok(())
    }
    fn first_running_pid(&mut self, service: &ScmHandle) -> Result<u32> {
        if self.split_fault == 4 {
            return Err(OwnerError::Native);
        }
        self.running_pid(service)
    }
    fn finish_started(
        &mut self,
        service: &ScmHandle,
        process: &ProcessHandle,
        birth: &ProcessProof,
        intent: &Intent,
    ) -> Result<()> {
        if service.0 != self.service_id || self.started_intent.as_ref() != Some(intent) {
            return Err(OwnerError::Conflict);
        }
        let (actual, code) = self.query_process(process)?;
        if actual != *birth || code != 259 {
            return Err(OwnerError::Conflict);
        }
        match self.split_fault {
            5 => Err(OwnerError::Native),
            6 => panic!("post-start acceptance unwind"),
            7 => {
                self.process.creation_time += 1;
                Err(OwnerError::Native)
            }
            8 => {
                self.image_matches = false;
                Err(OwnerError::Conflict)
            }
            _ => Ok(()),
        }
    }
}

#[test]
fn partial_start_unknown_pid_stops_only_original_scm_and_remains_pending() {
    // Break caught: StartPending/StopPending is confused with an absent process,
    // or its exact NEW held SCM obligation cannot reach bounded service cleanup.
    for state in [
        ServiceCleanupState::StartPending,
        ServiceCleanupState::StopPending,
        ServiceCleanupState::Running,
    ] {
        for pid in [0, 20] {
            for (slot, transport) in [
                (TunnelSlot::A, TunnelTransport::WireGuard),
                (TunnelSlot::B, TunnelTransport::WireGuard),
                (TunnelSlot::A, TunnelTransport::AmneziaWg3),
                (TunnelSlot::B, TunnelTransport::AmneziaWg3),
            ] {
                let (mut owner, journal) = origin_owner_for(slot, transport);
                owner.io.boundary.split_start = true;
                owner.io.boundary.split_fault = 4; // No valid first Running output.
                owner.io.boundary.cleanup_state = Some(state);
                owner.io.boundary.facts.pid = pid; // Transitional PID is observation ONLY.
                let service_closes = owner.io.boundary.service_closes.clone();
                let process_closes = owner.io.boundary.process_closes.clone();
                let mut member = crate::member_original::RetainedMember::new(owner);
                let pending = member.pending_read().unwrap();
                assert!(member.start_with_prior(None).is_err());
                let cap = pending.partial_cleanup().unwrap();
                let original = cap.inspect().unwrap();
                assert!(original.process.is_none());
                assert!(!original.service_deleted());
                let expected = member.snapshot().unwrap().unwrap();
                assert!(member.stop_partial_original(&expected, &cap).is_err());
                assert_eq!(service_closes.get(), 1); // Actual SAME SCM Delete ACK only.
                assert_eq!(process_closes.get(), 0); // Never adopt transitional PID.
                assert_eq!(
                    journal.borrow().record.as_ref().unwrap().phase,
                    Phase::Stopping
                );
                assert!(member.original_read().is_err());
                assert!(cap.inspect().is_err()); // Unknown-process obligation stays sticky.
            }
        }
    }
}

#[test]
fn partial_transition_stop_ack_is_not_stopped_or_delete_authority() {
    // Break caught: ignored transitional PID becomes zero/Stopped after a
    // successful SCM control call even though actual status never closed.
    for state in [
        ServiceCleanupState::StartPending,
        ServiceCleanupState::StopPending,
    ] {
        let (owner, _) = origin_owner();
        let intent = owner.intent().clone();
        let mut boundary = OriginBoundary::live();
        boundary.split_fault = 4;
        boundary.cleanup_state = Some(state);
        boundary.facts.pid = 0;
        boundary.stop_still_active = true;
        let mut origin = RetainedMemberOrigin::empty();
        assert!(origin
            .start_retaining_process(&mut boundary, &intent)
            .is_err());
        let cap = origin.partial_cleanup_pin(&intent).unwrap();
        cap.inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .unwrap();
        assert!(cap
            .stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
            .is_err());
        assert_eq!(boundary.delete_calls, 0);
        assert_eq!(boundary.service_closes.get(), 0);
        assert_eq!(boundary.process_closes.get(), 0);
        assert!(origin.pin().is_err());
        assert!(cap
            .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .is_err());
    }
}

#[test]
fn partial_running_unknown_pid_cannot_override_a_retained_process_birth() {
    // Break caught: a previously pinned original process is treated as an
    // unknown/no-process Start because its current SCM Running PID disappeared.
    let (owner, _) = origin_owner();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    boundary.split_fault = 5; // Handle/birth already rooted before postflight Err.
    let mut origin = RetainedMemberOrigin::empty();
    assert!(origin
        .start_retaining_process(&mut boundary, &intent)
        .is_err());
    boundary.cleanup_state = Some(ServiceCleanupState::Running);
    boundary.facts.pid = 0;
    let cap = origin.partial_cleanup_pin(&intent).unwrap();
    assert!(cap
        .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert!(cap
        .stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert_eq!(boundary.delete_calls, 0);
    assert_eq!(boundary.service_closes.get(), 0);
    assert_eq!(boundary.process_closes.get(), 0);
}

#[test]
fn original_start_missing_ack_or_valid_pid_keeps_service_only_obligation() {
    // Break caught: lost Start ACK/failed first status is adopted through later
    // PID/name facts, or uncertain start is repeated instead of retaining root.
    for cut in [1, 2, 3, 4, 10] {
        let (mut owner, state) = origin_owner();
        owner.io.boundary.split_start = true;
        owner.io.boundary.split_fault = cut;
        let service_closes = owner.io.boundary.service_closes.clone();
        let process_closes = owner.io.boundary.process_closes.clone();
        let mut member = crate::member_original::RetainedMember::new(owner);
        let pending = member.pending_read().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            member.start_with_prior(None)
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(service_closes.get(), 0);
        assert_eq!(process_closes.get(), 0);
        assert!(member.start_with_prior(None).is_err());
        assert!(member.original_read().is_err());
        let cap = pending.partial_cleanup().unwrap();
        cap.inspect().unwrap();
        let actual = member.snapshot().unwrap().unwrap();
        assert!(member.stop_partial_original(&actual, &cap).is_err());
        assert_eq!(
            state.borrow().record.as_ref().unwrap().phase,
            Phase::Stopping
        );
        assert_eq!(process_closes.get(), 0);
        assert!(cap.inspect().is_err()); // Unknown original process remains sticky.
    }
}

#[test]
fn original_start_wrong_process_image_cannot_become_partial_cleanup_authority() {
    let (owner, _) = origin_owner();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    boundary.split_fault = 8;
    let mut original = RetainedMemberOrigin::empty();
    assert!(original
        .start_retaining_process(&mut boundary, &intent)
        .is_err());
    let cap = original.partial_cleanup_pin(&intent).unwrap();
    assert!(cap
        .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert!(cap
        .stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert_eq!(boundary.service_closes.get(), 0);
    assert_eq!(boundary.process_closes.get(), 0);
    assert_eq!(boundary.delete_calls, 0);
}

#[test]
fn original_service_start_status_selects_only_valid_running_pid() {
    // Break caught: an invalid pending/stopped PID becomes process ownership,
    // or a valid Running output is discarded before the retained root consumes it.
    for pid in [None, Some(0), Some(20)] {
        assert_eq!(
            original_start_process_pid(OriginalServiceStartStatus::StartPending(pid)),
            Ok(None)
        );
    }
    assert_eq!(
        original_start_process_pid(OriginalServiceStartStatus::Running(Some(20))),
        Ok(Some(20))
    );
    assert!(original_start_process_pid(OriginalServiceStartStatus::Running(None)).is_err());
    assert!(original_start_process_pid(OriginalServiceStartStatus::Running(Some(0))).is_err());
    assert!(original_start_process_pid(OriginalServiceStartStatus::Stopped).is_err());
    assert!(original_start_process_pid(OriginalServiceStartStatus::Other).is_err());
}

#[test]
fn original_start_retains_process_before_fallible_post_start_acceptance() {
    // Break caught: composite finish/wait returns before rooting its process,
    // or query/postflight Err/unwind frees the original returned native objects.
    for cut in [5, 6] {
        for (slot, transport) in [
            (TunnelSlot::A, TunnelTransport::WireGuard),
            (TunnelSlot::B, TunnelTransport::WireGuard),
            (TunnelSlot::A, TunnelTransport::AmneziaWg3),
            (TunnelSlot::B, TunnelTransport::AmneziaWg3),
        ] {
            let (mut owner, _) = origin_owner_for(slot, transport);
            owner.io.boundary.split_start = true;
            owner.io.boundary.split_fault = cut;
            let service_closes = owner.io.boundary.service_closes.clone();
            let process_closes = owner.io.boundary.process_closes.clone();
            let mut member = crate::member_original::RetainedMember::new(owner);
            let pending = member.pending_read().unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                member.start_with_prior(None)
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(service_closes.get(), 0);
            assert_eq!(process_closes.get(), 0);
            assert!(member.original_read().is_err());
            let cap = pending.partial_cleanup().unwrap();
            cap.inspect().unwrap();
            let record = member.snapshot().unwrap().unwrap();
            let (_, closed) = member.stop_partial_original(&record, &cap).unwrap();
            member.verify_closed(&closed).unwrap();
            assert_eq!(service_closes.get(), 1);
        }
    }
}

#[test]
fn original_start_query_error_or_unwind_retains_returned_process_before_birth_capture() {
    // Break caught: OpenProcess returned its original object, but the first
    // fallible birth query loses that handle before the partial owner can read it.
    for unwind in [false, true] {
        let (owner, _) = origin_owner();
        let intent = owner.intent().clone();
        let mut boundary = OriginBoundary::live();
        boundary.fail_query = !unwind;
        boundary.panic_query = unwind;
        let mut original = RetainedMemberOrigin::empty();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.start_retaining_process(&mut boundary, &intent)
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(boundary.service_closes.get(), 0);
        assert_eq!(boundary.process_closes.get(), 0);
        assert!(original.pin().is_err()); // No fabricated live proof.
        boundary.fail_query = false;
        boundary.panic_query = false;
        let cap = original.partial_cleanup_pin(&intent).unwrap();
        let observation = cap
            .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .unwrap();
        assert_eq!(observation.process, Some(proof().process));
        // Subsequent reads cannot renew the captured birth by equal PID.
        boundary.process.creation_time += 1;
        assert!(cap
            .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .is_err());
        assert_eq!(boundary.delete_calls, 0);
        assert_eq!(boundary.process_closes.get(), 0);
    }
}

#[test]
fn original_start_completed_proof_and_reader_are_from_the_retained_birth() {
    // Break caught: the successful split path bypasses original capture or
    // returns a record/reader derived from an equal lookup rather than its root.
    for (slot, transport) in [
        (TunnelSlot::A, TunnelTransport::WireGuard),
        (TunnelSlot::B, TunnelTransport::WireGuard),
        (TunnelSlot::A, TunnelTransport::AmneziaWg3),
        (TunnelSlot::B, TunnelTransport::AmneziaWg3),
    ] {
        let (mut owner, _) = origin_owner_for(slot, transport);
        owner.io.boundary.split_start = true;
        let service_closes = owner.io.boundary.service_closes.clone();
        let process_closes = owner.io.boundary.process_closes.clone();
        let mut member = crate::member_original::RetainedMember::new(owner);
        let running = member.start_with_prior(None).unwrap();
        assert_eq!(running.phase, Phase::Running);
        assert_eq!(running.proof, Some(proof()));
        let mut reader = member.original_read().unwrap();
        assert_eq!(reader.read().unwrap(), (running.intent.clone(), proof()));
        let (_, closed) = member.stop(&running).unwrap();
        reader.verify_closed(&closed).unwrap();
        assert_eq!(service_closes.get(), 1);
        assert_eq!(process_closes.get(), 0); // Original reader retains object after its exit.
    }
}

#[test]
fn original_start_birth_is_rooted_before_postflight_can_change_observation() {
    let (owner, _) = origin_owner();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    boundary.split_fault = 7;
    let mut original = RetainedMemberOrigin::empty();
    assert!(original
        .start_retaining_process(&mut boundary, &intent)
        .is_err());
    let cap = original.partial_cleanup_pin(&intent).unwrap();
    assert_eq!(boundary.process_closes.get(), 0);
    // Equal PID cannot recapture a new birth identity after failure.
    assert!(cap
        .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert_eq!(boundary.delete_calls, 0);
}

#[test]
fn service_only_partial_cleanup_uses_new_held_service_without_nic_or_running_ack() {
    // Break caught: requiring NativeProof, reopening a service/NIC, or dropping
    // NEW handles after finish/query error instead of using actual retained SCM.
    for cut in 0..4 {
        let (owner, _) = setup();
        let intent = owner.intent().clone();
        let mut boundary = OriginBoundary::live();
        boundary.facts.interface = None; // No NIC identity can be granted.
        if cut < 2 {
            // Failure before service Start: SAME NEW service is still stopped.
            boundary.facts.pid = 0;
            boundary.exit_code = 0;
        }
        if cut == 0 {
            boundary.fail_finish = true;
        }
        if cut == 1 {
            boundary.panic_finish = true;
        }
        if cut == 2 {
            boundary.fail_query = true;
        }
        if cut == 3 {
            boundary.panic_query = true;
        }
        let mut origin = RetainedMemberOrigin::empty();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            origin.start(&mut boundary, &intent)
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let pin = origin.partial_cleanup_pin(&intent).unwrap();
        assert_eq!(boundary.service_closes.get(), 0);
        assert!(origin.pin().is_err());
        boundary.fail_query = false;
        boundary.panic_query = false;
        pin.inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .unwrap();
        pin.stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
            .unwrap();
        assert_eq!(boundary.delete_calls, 1);
        assert_eq!(boundary.service_closes.get(), 1);
        assert!(pin
            .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .unwrap()
            .service_deleted());
    }
}

#[test]
fn service_only_partial_cleanup_denies_foreign_origin_and_config_without_effects() {
    for cut in 0..6 {
        let (owner, _) = setup();
        let intent = owner.intent().clone();
        let mut boundary = OriginBoundary::live();
        boundary.fail_finish = true;
        let mut origin = RetainedMemberOrigin::empty();
        assert!(origin.start(&mut boundary, &intent).is_err());
        let pin = origin.partial_cleanup_pin(&intent).unwrap();
        match cut {
            0 => boundary.service_id += 1,
            1 => boundary.facts.exact_spec = false,
            2 => boundary.facts.alternative_service_present = true,
            3 => boundary.drift_after_first = true,
            _ => (),
        }
        let digest = if cut == 4 {
            None
        } else if cut == 5 {
            Some([8; 32])
        } else {
            Some(intent.config_sha256)
        };
        assert!(pin.stop_delete(&mut boundary, || Ok(digest)).is_err());
        assert_eq!(boundary.delete_calls, 0);
        assert_eq!(boundary.service_closes.get(), 0);
    }
}

#[test]
fn service_only_partial_cleanup_reconciles_only_actual_delete_ack_without_repeating_effects() {
    let (owner, _) = setup();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    boundary.fail_finish = true;
    boundary.facts.pid = 0;
    boundary.exit_code = 0;
    let mut origin = RetainedMemberOrigin::empty();
    assert!(origin.start(&mut boundary, &intent).is_err());
    let pin = origin.partial_cleanup_pin(&intent).unwrap();
    pin.stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
        .unwrap();
    let observation = pin
        .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
        .unwrap();
    assert!(observation.service_deleted());
    pin.stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
        .unwrap();
    assert_eq!(boundary.delete_calls, 1);
    assert_eq!(boundary.service_closes.get(), 1);
}

#[test]
fn service_only_partial_cleanup_closed_ack_never_bypasses_unknown_read() {
    // Break caught: the no-effect Delete-ACK retry bypasses sticky native denial.
    let (owner, _) = setup();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    boundary.fail_finish = true;
    boundary.facts.pid = 0;
    boundary.exit_code = 0;
    let mut origin = RetainedMemberOrigin::empty();
    assert!(origin.start(&mut boundary, &intent).is_err());
    let pin = origin.partial_cleanup_pin(&intent).unwrap();
    pin.stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
        .unwrap();
    assert!(pin
        .inspect(&mut boundary, || Err(OwnerError::Native))
        .is_err());
    assert!(pin
        .stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert!(pin
        .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert_eq!(boundary.delete_calls, 1);
}

#[test]
fn retained_member_origin_reads_same_created_service_and_pinned_running_process() {
    // Break caught: no receipt from create, or native reads reopen name/PID.
    let (o, _) = setup();
    let intent = o.intent().clone();
    let mut boundary = OriginBoundary::live();
    let mut origin = RetainedMemberOrigin::empty();
    origin.start(&mut boundary, &intent).unwrap();
    let mut pin = origin.pin().unwrap();
    assert_eq!(pin.read(&mut boundary), Ok((intent.clone(), proof())));
    assert_eq!(
        pin.inspect(&mut boundary, |actual, process| {
            assert_eq!(actual, &intent);
            assert_eq!(process.0, 1);
            Ok(7u8)
        }),
        Ok(((intent, proof()), 7))
    );
    boundary.service_id = 2; // Equal facts/name, different SCM object.
    assert_eq!(pin.read(&mut boundary), Err(OwnerError::Conflict));
    boundary.service_id = 1;
    assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
}

#[test]
fn retained_origin_rebind_closes_original_process_and_renews_only_current_pin() {
    let (owner, _) = setup();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    let mut origin = RetainedMemberOrigin::empty();
    origin.start(&mut boundary, &intent).unwrap();
    let mut old_pin = origin.pin().unwrap();
    let ack = origin
        .rebind_original(&mut boundary, &intent, &proof(), || {
            Ok(Some(intent.config_sha256))
        })
        .unwrap();
    assert_eq!(ack.old_proof(), proof());
    let next = origin
        .read_rebound_original(&mut boundary, &ack, || Ok(Some(intent.config_sha256)))
        .unwrap();
    assert_ne!(next.process, proof().process);
    assert_eq!(next.interface, proof().interface);
    assert!(old_pin.read(&mut boundary).is_err());
    assert_eq!(
        origin.pin().unwrap().read(&mut boundary).unwrap(),
        (intent, next)
    );
    assert_eq!(boundary.service_closes.get(), 0);
    assert_eq!(boundary.process_closes.get(), 0);
    assert_eq!(boundary.delete_calls, 0);
}

#[test]
fn original_rebind_final_config_reentry_cannot_acknowledge_ignored_nested_read() {
    // Break caught: final config continuity clears a nested original-read
    // denial, permitting an ACK after the actual borrowed owner was tainted.
    let (owner, _) = setup();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    let mut origin = RetainedMemberOrigin::empty();
    origin.start(&mut boundary, &intent).unwrap();
    let mut nested = origin.pin().unwrap();
    let mut nested_boundary = OriginBoundary::live();
    let mut reads = 0;
    let result = origin.rebind_original(&mut boundary, &intent, &proof(), || {
        reads += 1;
        if reads == 6 {
            assert!(nested.read(&mut nested_boundary).is_err());
        }
        Ok(Some(intent.config_sha256))
    });
    assert!(matches!(result, Err(OwnerError::Conflict)));
    assert!(origin.pin().is_err());
    assert_eq!(boundary.service_closes.get(), 0);
    assert_eq!(boundary.process_closes.get(), 0);
}

#[test]
fn rebound_read_final_config_reentry_cannot_restore_forward_pin() {
    let (owner, _) = setup();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    let mut origin = RetainedMemberOrigin::empty();
    origin.start(&mut boundary, &intent).unwrap();
    let ack = origin
        .rebind_original(&mut boundary, &intent, &proof(), || {
            Ok(Some(intent.config_sha256))
        })
        .unwrap();
    let mut nested = origin.pin().unwrap();
    let mut nested_boundary = OriginBoundary::live();
    let mut reads = 0;
    let result = origin.read_rebound_original(&mut boundary, &ack, || {
        reads += 1;
        if reads == 3 {
            assert!(nested.read(&mut nested_boundary).is_err());
        }
        Ok(Some(intent.config_sha256))
    });
    assert_eq!(result, Err(OwnerError::Conflict));
    assert!(origin.pin().is_err());
}

#[test]
fn original_rebind_unknown_restart_retains_actual_service_and_process_handles() {
    // Break caught: dropping original handles on Err/unwind, retrying unknown
    // restart, or admitting a replacement with a different interface.
    for fault in 1..=5 {
        let (owner, _) = setup();
        let intent = owner.intent().clone();
        let mut boundary = OriginBoundary::live();
        let mut origin = RetainedMemberOrigin::empty();
        origin.start(&mut boundary, &intent).unwrap();
        let mut old_pin = origin.pin().unwrap();
        boundary.restart_fault = fault;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            origin.rebind_original(&mut boundary, &intent, &proof(), || {
                Ok(Some(intent.config_sha256))
            })
        }));
        if fault == 2 || fault == 4 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(old_pin.read(&mut boundary).is_err());
        assert!(origin.pin().is_err());
        assert_eq!(boundary.service_closes.get(), 0);
        assert_eq!(boundary.process_closes.get(), 0);
        boundary.restart_fault = 0;
        boundary.fail_query = false;
        boundary.panic_query = false;
        let process = boundary.process;
        assert!(origin
            .rebind_original(&mut boundary, &intent, &proof(), || Ok(Some(
                intent.config_sha256
            )))
            .is_err());
        assert_eq!(boundary.process, process); // No duplicate native restart.
        drop(origin);
        assert_eq!(boundary.service_closes.get(), 0); // Still held by original pin.
        drop(old_pin);
        assert_eq!(boundary.service_closes.get(), 1);
        assert_eq!(
            boundary.process_closes.get(),
            if fault <= 2 { 1 } else { 2 }
        );
    }
}

#[test]
fn original_rebind_requires_actual_old_exit_and_exact_original_config() {
    for cut in 0..3 {
        let (owner, _) = setup();
        let intent = owner.intent().clone();
        let mut boundary = OriginBoundary::live();
        let mut origin = RetainedMemberOrigin::empty();
        origin.start(&mut boundary, &intent).unwrap();
        let mut expected = intent.clone();
        if cut == 0 {
            boundary.stop_still_active = true;
        }
        if cut == 1 {
            expected.scope.connection_generation += 1;
        }
        let digest = if cut == 2 {
            [7; 32]
        } else {
            intent.config_sha256
        };
        assert!(origin
            .rebind_original(&mut boundary, &expected, &proof(), || Ok(Some(digest)))
            .is_err());
        assert!(origin.pin().is_err());
        assert_eq!(boundary.process, proof().process);
        assert_eq!(boundary.retired_process, None);
        assert_eq!(boundary.delete_calls, 0);
    }
}

#[test]
fn rebound_native_receipt_rejects_equal_foreign_original() {
    let (owner, _) = setup();
    let intent = owner.intent().clone();
    let mut originals = (RetainedMemberOrigin::empty(), RetainedMemberOrigin::empty());
    let mut boundaries = (OriginBoundary::live(), OriginBoundary::live());
    originals.0.start(&mut boundaries.0, &intent).unwrap();
    originals.1.start(&mut boundaries.1, &intent).unwrap();
    let a = originals
        .0
        .rebind_original(&mut boundaries.0, &intent, &proof(), || {
            Ok(Some(intent.config_sha256))
        })
        .unwrap();
    let b = originals
        .1
        .rebind_original(&mut boundaries.1, &intent, &proof(), || {
            Ok(Some(intent.config_sha256))
        })
        .unwrap();
    assert_eq!(
        a.replacement_proof().unwrap(),
        b.replacement_proof().unwrap()
    );
    assert!(!Rc::ptr_eq(&a, &b));
    assert!(originals
        .0
        .read_rebound_original(&mut boundaries.0, &b, || Ok(Some(intent.config_sha256)))
        .is_err());
    assert!(originals.0.pin().is_err());
}

#[test]
fn retained_member_origin_partial_create_finish_and_query_keep_handles_until_cleanup() {
    // Break caught: post-create errors/unwinds drop the acknowledged service,
    // or a later equal lookup/retry fabricates an original receipt.
    for cut in 0..5 {
        let (o, _) = setup();
        let mut boundary = OriginBoundary::live();
        match cut {
            0 => boundary.fail_create = true,
            1 => boundary.fail_finish = true,
            2 => boundary.panic_finish = true,
            3 => boundary.fail_query = true,
            _ => boundary.panic_query = true,
        }
        let mut origin = RetainedMemberOrigin::empty();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            origin.start(&mut boundary, o.intent())
        }));
        if cut == 2 || cut == 4 {
            assert!(result.is_err(), "cut {cut}");
        } else {
            assert_eq!(result.unwrap(), Err(OwnerError::Native), "cut {cut}");
        }
        assert_eq!(boundary.service_closes.get(), 0);
        assert_eq!(boundary.process_closes.get(), 0);
        assert!(origin.pin().is_err());
        boundary.fail_create = false;
        boundary.fail_finish = false;
        boundary.panic_finish = false;
        boundary.fail_query = false;
        boundary.panic_query = false;
        assert_eq!(
            origin.start(&mut boundary, o.intent()),
            Err(OwnerError::Retired)
        );
        if cut == 0 {
            assert_eq!(
                origin.stop_delete(
                    &mut boundary,
                    o.intent(),
                    None,
                    &origin_cleanup_observation(o.intent())
                ),
                Err(OwnerError::Retired)
            );
        } else {
            origin
                .stop_delete(
                    &mut boundary,
                    o.intent(),
                    None,
                    &origin_cleanup_observation(o.intent()),
                )
                .unwrap();
        }
        assert_eq!(boundary.service_closes.get(), usize::from(cut != 0));
        // Pinned process remains available as an observational cleanup receipt.
        assert_eq!(boundary.process_closes.get(), 0);
        drop(origin);
        assert_eq!(boundary.process_closes.get(), usize::from(cut >= 3));
    }
}

#[test]
fn retained_member_origin_native_drift_error_and_unwind_revoke_all_pins() {
    // Break caught: a pin reopens PID, omits a config/status/interface/process
    // fence, or revives itself/another pin after restoration or catch_unwind.
    for drift in 0..13 {
        let (o, _) = setup();
        let mut boundary = OriginBoundary::live();
        let mut origin = RetainedMemberOrigin::empty();
        origin.start(&mut boundary, o.intent()).unwrap();
        let mut pin = origin.pin().unwrap();
        let mut second = origin.pin().unwrap();
        boundary.service_reads = 0;
        match drift {
            0 => boundary.process_id = 2,
            1 => boundary.process.pid = 21,
            2 => boundary.process.creation_time = 31,
            3 => boundary.exit_code = 0,
            4 => boundary.facts.exact_spec = false,
            5 => boundary.facts.pid = 21,
            6 => boundary.facts.interface.as_mut().unwrap().index = 41,
            7 => boundary.facts.interface.as_mut().unwrap().luid = 51,
            8 => boundary.facts.interface.as_mut().unwrap().guid = [7; 16],
            9 => boundary.facts.alternative_service_present = true,
            10 => boundary.fail_query = true,
            11 => boundary.panic_query = true,
            _ => boundary.drift_after_first = true,
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pin.read(&mut boundary)));
        if drift == 11 {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap(),
                Err(if drift == 10 {
                    OwnerError::Native
                } else {
                    OwnerError::Conflict
                }),
                "drift {drift}"
            );
        }
        let service_closes = boundary.service_closes.clone();
        let process_closes = boundary.process_closes.clone();
        boundary = OriginBoundary::live();
        assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
        assert_eq!(second.read(&mut boundary), Err(OwnerError::Retired));
        assert!(origin.pin().is_err());
        origin
            .stop_delete(
                &mut boundary,
                o.intent(),
                None,
                &origin_cleanup_observation(o.intent()),
            )
            .unwrap();
        assert_eq!(service_closes.get(), 1);
        assert_eq!(process_closes.get(), 0);
    }
    for unwind in [false, true] {
        let (o, _) = setup();
        let mut boundary = OriginBoundary::live();
        let mut origin = RetainedMemberOrigin::empty();
        origin.start(&mut boundary, o.intent()).unwrap();
        let mut pin = origin.pin().unwrap();
        let mut second = origin.pin().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pin.inspect(&mut boundary, |_, _| -> Result<()> {
                assert!(!unwind, "native domain query unwind");
                Err(OwnerError::Native)
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
        assert_eq!(second.read(&mut boundary), Err(OwnerError::Retired));
        assert!(origin.pin().is_err());
    }
}

#[test]
fn retained_member_origin_delete_ack_closes_shared_scm_holder_before_absence() {
    // Break caught: an independently held pin keeps SCM deletion pending after
    // explicit cleanup or retains read authority across Stop/rebind revocation.
    let (o, _) = setup();
    let mut boundary = OriginBoundary::live();
    let mut origin = RetainedMemberOrigin::empty();
    origin.start(&mut boundary, o.intent()).unwrap();
    let mut pin = origin.pin().unwrap();
    origin.revoke();
    assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
    assert_eq!(boundary.service_closes.get(), 0);
    origin
        .stop_delete(
            &mut boundary,
            o.intent(),
            None,
            &origin_cleanup_observation(o.intent()),
        )
        .unwrap();
    assert_eq!(boundary.service_closes.get(), 1);
    assert!(boundary.delete_ack);
    assert_eq!(boundary.delete_calls, 1);
    assert_eq!(boundary.process_closes.get(), 0);
    assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
    assert_eq!(
        origin.stop_delete(
            &mut boundary,
            o.intent(),
            None,
            &origin_cleanup_observation(o.intent())
        ),
        Err(OwnerError::Retired)
    );
    assert_eq!(boundary.delete_calls, 1);
}

#[test]
fn retained_member_origin_delete_error_or_unwind_never_retries_or_closes_without_ack() {
    // Break caught: Delete intent is treated as ACK or retried through a name
    // lookup; outstanding pins must revoke without losing the SCM obligation.
    for unwind in [false, true] {
        let (o, _) = setup();
        let mut boundary = OriginBoundary::live();
        let mut origin = RetainedMemberOrigin::empty();
        origin.start(&mut boundary, o.intent()).unwrap();
        let mut pin = origin.pin().unwrap();
        boundary.fail_delete = !unwind;
        boundary.panic_delete = unwind;
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            origin.stop_delete(
                &mut boundary,
                o.intent(),
                None,
                &origin_cleanup_observation(o.intent()),
            )
        }));
        if unwind {
            assert!(attempt.is_err());
        } else {
            assert_eq!(attempt.unwrap(), Err(OwnerError::Native));
        }
        assert_eq!(boundary.service_closes.get(), 0);
        assert_eq!(boundary.delete_calls, 1);
        assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
        boundary.fail_delete = false;
        boundary.panic_delete = false;
        assert_eq!(
            origin.stop_delete(
                &mut boundary,
                o.intent(),
                None,
                &origin_cleanup_observation(o.intent())
            ),
            Err(OwnerError::Pending)
        );
        assert_eq!(boundary.delete_calls, 1);
        assert_eq!(boundary.service_closes.get(), 0);
    }
}

#[test]
fn retained_member_origin_private_config_fences_and_complete_receipt_revoke_pins() {
    // Break caught: pin retains read authority after a private-config error,
    // unwind, third-read drift, or a caller's equal-but-foreign intent/proof.
    for fault in 0..11 {
        let (o, _) = setup();
        let intent = o.intent().clone();
        let mut boundary = OriginBoundary::live();
        let mut origin = RetainedMemberOrigin::empty();
        origin.start(&mut boundary, &intent).unwrap();
        let mut pin = origin.pin().unwrap();
        let mut supplied_intent = intent.clone();
        let mut supplied_proof = proof();
        match fault {
            6 => supplied_intent.scope.connection_generation += 1,
            7 => supplied_intent.engine = crate::test_engine_path("other.exe"),
            8 => supplied_intent.config_sha256 = [9; 32],
            9 => supplied_proof.process.creation_time += 1,
            10 => supplied_proof.interface.guid = [9; 16],
            _ => (),
        }
        let mut reads = 0;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            origin.inspect_original(&mut boundary, &supplied_intent, &supplied_proof, || {
                reads += 1;
                if fault < 3 && reads == fault + 1 {
                    return Err(OwnerError::Native);
                }
                if fault == 3 && reads == 3 {
                    panic!("injected private-config unwind");
                }
                Ok(if fault == 4 && reads == 3 {
                    None
                } else if fault == 5 && reads == 2 {
                    Some([9; 32])
                } else {
                    Some(intent.config_sha256)
                })
            })
        }));
        if fault == 3 {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap(),
                Err(if fault < 3 {
                    OwnerError::Native
                } else {
                    OwnerError::Conflict
                }),
                "fault {fault}"
            );
        }
        assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
        assert_eq!(
            origin.inspect_original(&mut boundary, &intent, &proof(), || Ok(Some(
                intent.config_sha256
            ))),
            Err(OwnerError::Retired)
        );
        assert_eq!(boundary.service_closes.get(), 0);
        origin
            .stop_delete(
                &mut boundary,
                &intent,
                None,
                &origin_cleanup_observation(&intent),
            )
            .unwrap();
        assert_eq!(boundary.delete_calls, 1);
        assert_eq!(boundary.service_closes.get(), 1);
    }
}

// Compose the real owner AND real retention policy, replacing only external
// file/SCM/process operations. No second owner authorization policy is modeled.
struct OriginIo {
    base: Io,
    origin: RetainedMemberOrigin<ScmHandle, ProcessHandle>,
    boundary: OriginBoundary,
}
impl OriginalMemberPartialCleanupIo for OriginIo {
    type CleanupPin = OriginalServiceCleanup<ScmHandle, ProcessHandle>;
    fn partial_cleanup_pin(&mut self, intent: &Intent) -> Result<Self::CleanupPin> {
        self.origin.partial_cleanup_pin(intent)
    }
    fn inspect_partial_cleanup(
        &mut self,
        pin: &Self::CleanupPin,
    ) -> Result<PartialServiceObservation> {
        if !pin.matches_origin(&self.origin) {
            return Err(OwnerError::Conflict);
        }
        if self.base.0.borrow().fail_stop && self.base.0.borrow().observation.service.is_none() {
            self.boundary.exit_code = if self.base.0.borrow().fail_capture {
                259
            } else {
                0
            };
        }
        pin.inspect(&mut self.boundary, || {
            Ok(self.base.0.borrow().observation.config_sha256)
        })
    }
    fn stop_partial_original(&mut self, pin: &Self::CleanupPin) -> Result<()> {
        if !pin.matches_origin(&self.origin) {
            return Err(OwnerError::Conflict);
        }
        pin.stop_delete(&mut self.boundary, || {
            Ok(self.base.0.borrow().observation.config_sha256)
        })?;
        let mut state = self.base.0.borrow_mut();
        state.observation.service = None;
        if !state.fail_stop {
            state.observation.interface = None;
            state.observation.retained_interfaces.clear();
        } // External NIC rundown may lag SAME successful Stop/Delete ACK.
        Ok(())
    }
}

#[test]
fn partial_member_cleanup_lost_running_cas_closes_same_owner_without_live_reader() {
    // Break caught: committed Running required, foreign equal owner accepted,
    // fabricated Closed before original Stop/Delete or double effects on retry.
    for (slot, transport, lost, published) in [
        (TunnelSlot::A, TunnelTransport::WireGuard, false, false),
        (TunnelSlot::B, TunnelTransport::WireGuard, true, false),
        (TunnelSlot::A, TunnelTransport::AmneziaWg3, true, false),
        (TunnelSlot::B, TunnelTransport::AmneziaWg3, false, false),
        (TunnelSlot::A, TunnelTransport::WireGuard, false, true),
        (TunnelSlot::B, TunnelTransport::AmneziaWg3, false, true),
    ] {
        let (mut owner, state) = origin_owner_for(slot, transport);
        owner.io.boundary.split_start = true;
        let service_closes = owner.io.boundary.service_closes.clone();
        let mut retained = crate::member_original::RetainedMember::new(owner);
        let pending = retained.pending_read().unwrap();
        if published {
            retained.start_with_prior(None).unwrap();
        } else if lost {
            state.borrow_mut().lost_save_ack = Some(Phase::Running);
        } else {
            state.borrow_mut().fail_save = Some(Phase::Running);
        }
        if !published {
            assert!(retained.start_with_prior(None).is_err());
        }
        let capability = Rc::new(pending.partial_cleanup().unwrap());
        assert!(pending.partial_cleanup().is_err()); // SAME original, one issuance/root.
        capability.verify_pending_original(&pending).unwrap();
        assert!(retained.original_read().is_err());
        let before = capability.inspect().unwrap();
        assert_eq!(capability.inspect().unwrap(), before);
        let (foreign, _) = origin_owner();
        let foreign = crate::member_original::RetainedMember::new(foreign);
        assert!(capability
            .verify_pending_original(&foreign.pending_read().unwrap())
            .is_err());
        state.borrow_mut().lost_save_ack = None;
        state.borrow_mut().fail_save = None;
        let obligation = retained.snapshot().unwrap().unwrap();
        if published {
            state.borrow_mut().fail_stop = true;
            assert!(retained.stop(&obligation).is_err());
            state.borrow_mut().fail_capture = true;
            assert_eq!(service_closes.get(), 1); // Actual SAME Delete ACK.
            assert_eq!(capability.inspect(), Err(OwnerError::Pending));
            state.borrow_mut().fail_capture = false;
            let stopping = retained.snapshot().unwrap().unwrap();
            assert_eq!(stopping.phase, Phase::Stopping);
            assert_eq!(stopping.proof, obligation.proof);
            assert!(capability.inspect().unwrap().service_deleted());
            assert!(retained
                .stop_partial_original(&stopping, &capability)
                .is_err());
            assert_eq!(service_closes.get(), 1);
            state.borrow_mut().fail_stop = false;
            let (stopped, closed) = retained
                .stop_partial_original(&stopping, &capability)
                .unwrap();
            assert_eq!(stopped.retired_proof, obligation.proof);
            retained.verify_closed(&closed).unwrap();
            continue;
        }
        let (stopped, closed) = retained
            .stop_partial_original(&obligation, &capability)
            .unwrap();
        assert_eq!(stopped.phase, Phase::Stopped);
        retained.verify_closed(&closed).unwrap();
        assert!(capability.inspect().is_err());
        assert!(retained
            .stop_partial_original(&stopped, &capability)
            .is_err());
    }
}

#[test]
fn partial_member_cleanup_unpinned_running_process_is_not_closed_by_scm_ack() {
    // Break caught: SCM PID/Stopped status substituted for an original process
    // handle's acknowledged exit when Start failed before pin_process returned.
    let (mut owner, _) = origin_owner();
    owner.io.boundary.fail_finish = true;
    let service_closes = owner.io.boundary.service_closes.clone();
    let mut retained = crate::member_original::RetainedMember::new(owner);
    let pending = retained.pending_read().unwrap();
    assert!(retained.start_with_prior(None).is_err());
    let cap = Rc::new(pending.partial_cleanup().unwrap());
    cap.inspect().unwrap(); // SAME SCM is factual, not an adopted process pin.
    let expected = retained.snapshot().unwrap().unwrap();
    assert!(retained.stop_partial_original(&expected, &cap).is_err());
    assert_eq!(service_closes.get(), 1); // Actual Delete ACK closes ONLY SCM.
    assert_eq!(retained.snapshot().unwrap().unwrap().phase, Phase::Stopping);
    assert!(cap.inspect().is_err());
    assert!(retained.original_read().is_err());
}

#[test]
fn partial_member_cleanup_stopped_scm_without_original_process_is_not_full_absence() {
    // Break caught: observing PID zero after uncertain finish_created is
    // mistaken for a private never-started receipt or original process closure.
    let (mut owner, _) = origin_owner();
    owner.io.boundary.fail_finish = true;
    owner.io.boundary.facts.pid = 0;
    owner.io.boundary.exit_code = 0;
    let service_closes = owner.io.boundary.service_closes.clone();
    let mut retained = crate::member_original::RetainedMember::new(owner);
    let pending = retained.pending_read().unwrap();
    assert!(retained.start_with_prior(None).is_err());
    let cap = Rc::new(pending.partial_cleanup().unwrap());
    let expected = retained.snapshot().unwrap().unwrap();
    assert!(retained.stop_partial_original(&expected, &cap).is_err());
    assert_eq!(service_closes.get(), 1);
    assert!(cap.inspect().unwrap().service_deleted()); // ONLY SCM ACK.
    assert_eq!(retained.snapshot().unwrap().unwrap().phase, Phase::Stopping);
    assert!(retained.original_read().is_err());
}

#[test]
fn partial_member_cleanup_unknown_stop_or_delete_keeps_original_and_never_issues_closed() {
    // Break caught: intent/SCM Stop ACK or failed Delete is promoted to Closed,
    // its held service is dropped, or retry repeats an uncertain native effect.
    for cut in 0..3 {
        let (mut owner, state) = origin_owner();
        owner.io.boundary.fail_finish = true;
        owner.io.boundary.stop_still_active = cut == 0;
        owner.io.boundary.fail_delete = cut == 1;
        owner.io.boundary.panic_delete = cut == 2;
        let service_closes = owner.io.boundary.service_closes.clone();
        let mut retained = crate::member_original::RetainedMember::new(owner);
        let pending = retained.pending_read().unwrap();
        assert!(retained.start_with_prior(None).is_err());
        let cap = Rc::new(pending.partial_cleanup().unwrap());
        cap.inspect().unwrap();
        let expected = retained.snapshot().unwrap().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retained.stop_partial_original(&expected, &cap)
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(service_closes.get(), 0);
        assert!(cap.inspect().is_err());
        assert!(pending.partial_cleanup().is_err());
        assert!(retained.original_read().is_err());
        let current = retained.snapshot().unwrap().unwrap();
        assert_eq!(current.phase, Phase::Stopping);
        assert!(retained.stop_partial_original(&current, &cap).is_err());
        assert_eq!(service_closes.get(), 0);
        assert_eq!(
            state.borrow().record.as_ref().unwrap().phase,
            Phase::Stopping
        );
    }
}

#[test]
fn partial_member_cleanup_retains_actual_delete_ack_across_lost_stopped_cas() {
    // Break caught: full member ACK fabricated, original cap discarded after
    // CAS error, or second service deletion needed for SAME-owner reconcile.
    for lost in [false, true] {
        let (mut owner, state) = origin_owner();
        owner.io.boundary.fail_query_once = true;
        owner.io.boundary.facts.interface = None;
        let service_closes = owner.io.boundary.service_closes.clone();
        let mut retained = crate::member_original::RetainedMember::new(owner);
        let pending = retained.pending_read().unwrap();
        assert!(retained.start_with_prior(None).is_err());
        // Real process handle is already rooted; only the first external proof
        // read failed. No Running ACK/proof/NIC was ever captured or adopted.
        let cap = Rc::new(pending.partial_cleanup().unwrap());
        cap.inspect().unwrap();
        if lost {
            state.borrow_mut().lost_save_ack = Some(Phase::Stopped);
        } else {
            state.borrow_mut().fail_save = Some(Phase::Stopped);
        }
        let before = retained.snapshot().unwrap().unwrap();
        assert!(retained.stop_partial_original(&before, &cap).is_err());
        assert_eq!(service_closes.get(), 1);
        assert!(cap.inspect().unwrap().service_deleted()); // ACK only; full SDK still mandatory.
        state.borrow_mut().lost_save_ack = None;
        state.borrow_mut().fail_save = None;
        let current = retained.snapshot().unwrap().unwrap();
        let (_, closed) = retained.stop_partial_original(&current, &cap).unwrap();
        retained.verify_closed(&closed).unwrap();
        assert_eq!(service_closes.get(), 1);
    }
}

#[test]
fn service_only_partial_cleanup_read_fault_unwind_or_replaced_process_never_rearms() {
    // Break caught: subsequent restored equal facts rearm a poisoned original,
    // read effects mutate NIC, or losing the issuer drops a still-rooted pin.
    for cut in 0..4 {
        let (owner, _) = setup();
        let intent = owner.intent().clone();
        let mut boundary = OriginBoundary::live();
        boundary.fail_query = true;
        let mut origin = RetainedMemberOrigin::empty();
        assert!(origin.start(&mut boundary, &intent).is_err());
        let pin = origin.partial_cleanup_pin(&intent).unwrap();
        boundary.fail_query = false;
        pin.inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .unwrap();
        match cut {
            0 => boundary.fail_query = true,
            1 => boundary.panic_query = true,
            2 => boundary.process.creation_time += 1,
            _ => (),
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pin.inspect(&mut boundary, || {
                if cut == 3 {
                    Err(OwnerError::Native)
                } else {
                    Ok(Some(intent.config_sha256))
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        boundary.fail_query = false;
        boundary.panic_query = false;
        boundary.process = proof().process;
        assert!(pin
            .inspect(&mut boundary, || Ok(Some(intent.config_sha256)))
            .is_err());
        assert!(origin.partial_cleanup_pin(&intent).is_err());
        assert!(pin
            .stop_delete(&mut boundary, || Ok(Some(intent.config_sha256)))
            .is_err());
        drop(origin);
        assert_eq!(boundary.service_closes.get(), 0);
        assert_eq!(boundary.process_closes.get(), 0);
        // This raw pin test explicitly releases the last holder. Native
        // OperationRoot instead retains the entire uncertain owner/cap bundle.
        drop(pin);
        assert_eq!(boundary.service_closes.get(), 1);
        assert_eq!(boundary.process_closes.get(), 1);
        assert_eq!(boundary.delete_calls, 0);
    }
}
impl MemberIo for OriginIo {
    fn inspect(&mut self, intent: &Intent, retained: Option<&NativeProof>) -> Result<Observation> {
        if self.base.0.borrow().fail_stop && self.base.0.borrow().observation.service.is_none() {
            assert_eq!(
                retained,
                self.base.0.borrow().record.as_ref().unwrap().proof.as_ref()
            );
        }
        self.base.inspect(intent, retained)
    }
    fn inspect_original(&mut self, intent: &Intent, retained: &NativeProof) -> Result<Observation> {
        self.origin
            .inspect_original(&mut self.boundary, intent, retained, || {
                let mut state = self.base.0.borrow_mut();
                read_boundary(&mut state, OwnerError::Native)?;
                Ok(state.observation.config_sha256)
            })
    }
    fn inspect_original_for_cleanup(
        &mut self,
        intent: &Intent,
        retained: &NativeProof,
    ) -> Result<Observation> {
        self.origin
            .inspect_original_for_cleanup(&mut self.boundary, intent, retained, || {
                let mut state = self.base.0.borrow_mut();
                read_boundary(&mut state, OwnerError::Native)?;
                Ok(state.observation.config_sha256)
            })
    }
    fn revoke_original(&mut self) {
        self.origin.revoke();
    }
    fn write_private_config(
        &mut self,
        intent: &Intent,
        expected: Option<[u8; 32]>,
        canonical: &str,
    ) -> Result<()> {
        self.base.write_private_config(intent, expected, canonical)
    }
    fn start_fresh(&mut self, intent: &Intent, retired: Option<&NativeProof>) -> Result<()> {
        self.base.start_fresh(intent, retired)?;
        if self.boundary.split_start {
            return self
                .origin
                .start_retaining_process(&mut self.boundary, intent);
        }
        self.origin.start(&mut self.boundary, intent)
    }
    fn stop_slot(
        &mut self,
        intent: &Intent,
        retained: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        self.origin
            .stop_delete(&mut self.boundary, intent, retained, expected)?;
        if self.base.0.borrow().fail_stop {
            self.base.0.borrow_mut().observation.service = None;
            return Ok(()); // Native Delete ACK precedes external NIC rundown.
        }
        self.base.stop_slot(intent, retained, expected)
    }
    fn rebind(
        &mut self,
        intent: &Intent,
        proof: &NativeProof,
        expected: &Observation,
    ) -> Result<()> {
        self.origin.revoke();
        self.base.rebind(intent, proof, expected)
    }
}
impl OriginalMemberPinSource for OriginIo {
    type Pin = OriginalMemberPin<ScmHandle, ProcessHandle>;
    fn original_read_pin(&mut self) -> Result<Self::Pin> {
        self.origin.pin()
    }
}
impl OriginalMemberRebindIo for OriginIo {
    fn rebind_original(
        &mut self,
        intent: &Intent,
        old: &NativeProof,
    ) -> Result<Rc<OriginalRebindAck>> {
        let digest = self.base.0.borrow().observation.config_sha256;
        let ack = self
            .origin
            .rebind_original(&mut self.boundary, intent, old, || Ok(digest))?;
        let next = ack.replacement_proof()?;
        let mut state = self.base.0.borrow_mut();
        state
            .observation
            .service
            .as_mut()
            .ok_or(OwnerError::Pending)?
            .process = Some(next.process);
        state.observation.interface = Some(next.interface);
        state.observation.retained_interfaces = vec![next.interface];
        Ok(ack)
    }
    fn read_rebound_original(&mut self, ack: &Rc<OriginalRebindAck>) -> Result<NativeProof> {
        let digest = self.base.0.borrow().observation.config_sha256;
        self.origin
            .read_rebound_original(&mut self.boundary, ack, || Ok(digest))
    }
}
fn origin_owner() -> (MemberOwner<Disk, OriginIo>, Shared) {
    origin_owner_for(TunnelSlot::B, TunnelTransport::WireGuard)
}
fn origin_owner_for(
    slot: TunnelSlot,
    transport: TunnelTransport,
) -> (MemberOwner<Disk, OriginIo>, Shared) {
    let (_, state) = setup();
    state.borrow_mut().slot = slot;
    let io = OriginIo {
        base: Io(state.clone(), false),
        origin: RetainedMemberOrigin::empty(),
        boundary: OriginBoundary::live(),
    };
    let configuration = match transport {
        TunnelTransport::WireGuard => CONFIG.to_owned(),
        TunnelTransport::AmneziaWg3 => CONFIG.replace(
            "[Peer]",
            "Jc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n[Peer]",
        ),
    };
    let owner = MemberOwner::from_trusted_engine(
        scope(),
        slot,
        transport,
        crate::test_engine_path("engine.exe"),
        &configuration,
        Disk(state.clone()),
        io,
    )
    .unwrap();
    (owner, state)
}

#[test]
fn same_owner_original_rebind_commits_native_ack_and_new_original_not_equal_lookup() {
    let (mut owner, state) = origin_owner();
    let old = owner.start().unwrap();
    let mut old_pin = owner.original_live().unwrap().native_read_pin().unwrap();
    let (running, ack) = owner.rebind_original(&old).unwrap();
    let next = running.proof.unwrap();
    assert_eq!(ack.old_proof(), old.proof.unwrap());
    assert_eq!(ack.replacement_proof().unwrap(), next);
    assert_eq!(running.retired_proof, old.proof);
    assert_ne!(next.process, old.proof.unwrap().process);
    assert_eq!(next.interface, old.proof.unwrap().interface);
    assert_eq!(state.borrow().record.as_ref(), Some(&running));
    assert_eq!(
        owner.original_live().unwrap().read().unwrap(),
        (running.intent.clone(), next)
    );
    assert!(old_pin.read(&mut owner.io.boundary).is_err());
    assert_eq!(owner.original_live().unwrap().read().unwrap().1, next);
    assert!(owner.rebind_original(&old).is_err());
}

#[test]
fn original_rebind_bad_proposal_retires_native_pins_before_validation_without_effects() {
    let (mut owner, state) = origin_owner();
    let old = owner.start().unwrap();
    let mut pin = owner.original_live().unwrap().native_read_pin().unwrap();
    let writes = state.borrow().save_count;
    let mut wrong = old.clone();
    wrong.intent.scope.connection_generation += 1;
    assert!(owner.rebind_original(&wrong).is_err());
    assert!(pin.read(&mut owner.io.boundary).is_err());
    assert_eq!(state.borrow().save_count, writes);
    assert_eq!(owner.io.boundary.retired_process, None);
}

#[test]
fn original_rebind_failed_or_lost_running_cas_keeps_native_ack_without_read_authority() {
    for lost in [false, true] {
        let (mut owner, state) = origin_owner();
        let old = owner.start().unwrap();
        let mut pin = owner.original_live().unwrap().native_read_pin().unwrap();
        if lost {
            state.borrow_mut().lost_save_ack = Some(Phase::Running);
        } else {
            state.borrow_mut().fail_save = Some(Phase::Running);
        }
        assert!(matches!(
            owner.rebind_original(&old),
            Err(OwnerError::Journal)
        ));
        assert!(owner.original_live().is_err());
        assert!(pin.read(&mut owner.io.boundary).is_err());
        let ack = owner.rebind_ack.as_ref().unwrap();
        assert_eq!(ack.old_proof(), old.proof.unwrap());
        assert_eq!(ack.replacement_proof().unwrap().process.pid, 21);
        assert_eq!(owner.io.boundary.service_closes.get(), 0);
        assert_eq!(owner.io.boundary.process_closes.get(), 0);
        assert_eq!(
            state.borrow().record.as_ref().unwrap().phase,
            if lost {
                Phase::Running
            } else {
                Phase::Prepared
            }
        );
        let writes = state.borrow().save_count;
        assert!(owner.rebind_original(&old).is_err());
        assert_eq!(state.borrow().save_count, writes);
        assert_eq!(owner.io.boundary.process.pid, 21);
    }
}

#[test]
fn retained_original_rebind_roots_closed_old_process_and_exact_replacement_reader() {
    let (owner, _) = origin_owner();
    let mut controller = crate::member_original::RetainedMember::new(owner);
    let old = controller.start_with_prior(None).unwrap();
    let mut old_reader = controller.original_read().unwrap();
    let (running, closed, mut new_reader) = controller.rebind_original(&old).unwrap();
    closed.verify_retired_original_read(&old_reader).unwrap();
    closed
        .verify_replacement_original_read(&new_reader)
        .unwrap();
    controller.verify_rebind_receipt(&closed).unwrap();
    assert_eq!(
        new_reader.read().unwrap(),
        (running.intent.clone(), running.proof.unwrap())
    );
    assert!(old_reader.read().is_err());
    assert_eq!(new_reader.read().unwrap().1, running.proof.unwrap());
    assert!(closed.verify_retired_original_read(&new_reader).is_err());
    assert!(closed
        .verify_replacement_original_read(&old_reader)
        .is_err());
    assert_eq!(closed.running_record(), &running);
    drop(controller);
    assert!(old_reader.read().is_err());
    new_reader.read().unwrap(); // Actual owner is still rooted by both originals/receipt.
}

#[test]
fn actual_origin_cleanup_reads_retire_every_forward_pin_without_native_effects() {
    let (mut owner, state) = origin_owner();
    let running = owner.start().unwrap();
    let mut independent = owner.original_live().unwrap().native_read_pin().unwrap();
    let effects = {
        let s = state.borrow();
        (s.events.clone(), s.save_count)
    };
    for _ in 0..2 {
        assert_eq!(
            owner.read_original_for_cleanup(),
            Ok((running.intent.clone(), proof()))
        );
        assert_eq!(
            independent.read(&mut owner.io.boundary),
            Err(OwnerError::Retired)
        );
        assert_eq!(owner.original_live().err(), Some(OwnerError::Retired));
    }
    let s = state.borrow();
    assert_eq!((s.events.clone(), s.save_count), effects);
    assert_eq!(owner.io.boundary.delete_calls, 0);
    assert_eq!(owner.io.boundary.service_closes.get(), 0);
}

#[test]
fn actual_origin_cleanup_cannot_ignore_same_original_nested_read() {
    let (owner, _) = setup();
    let intent = owner.intent().clone();
    let mut boundary = OriginBoundary::live();
    let mut origin = RetainedMemberOrigin::empty();
    origin.start(&mut boundary, &intent).unwrap();
    let mut pin = origin.pin().unwrap();
    let mut nested_boundary = OriginBoundary::live();
    let result = origin.inspect_original_for_cleanup(&mut boundary, &intent, &proof(), || {
        // Ignore both a refusal and an unwind: the enclosing actual-origin
        // query must still fail, rather than export successful cleanup facts.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pin.read(&mut nested_boundary)
        }));
        Ok(Some(intent.config_sha256))
    });
    assert!(result.is_err());
    assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
    assert!(origin
        .inspect_original_for_cleanup(&mut boundary, &intent, &proof(), || Ok(Some(
            intent.config_sha256
        )))
        .is_ok());
    assert_eq!(pin.read(&mut boundary), Err(OwnerError::Retired));
}

#[test]
fn actual_origin_cleanup_denies_handle_identity_private_config_and_native_drift() {
    for fault in 0..12 {
        let (mut owner, state) = origin_owner();
        let running = owner.start().unwrap();
        let mut pin = owner.original_live().unwrap().native_read_pin().unwrap();
        owner.io.boundary.service_reads = 0;
        match fault {
            0 => owner.io.boundary.service_id += 1,
            1 => owner.io.boundary.process_id += 1,
            2 => owner.io.boundary.process.creation_time += 1,
            3 => owner.io.boundary.facts.interface.as_mut().unwrap().guid = [9; 16],
            4 => owner.io.boundary.facts.interface.as_mut().unwrap().luid += 1,
            5 => owner.io.boundary.facts.alternative_service_present = true,
            6 => owner.io.boundary.fail_query = true,
            7 => owner.io.boundary.panic_query = true,
            8 => state.borrow_mut().observation.config_sha256 = Some([9; 32]),
            9 => {
                state
                    .borrow_mut()
                    .record
                    .as_mut()
                    .unwrap()
                    .intent
                    .scope
                    .connection_generation += 1
            }
            10 => owner.io.boundary.drift_after_first = true,
            _ => owner.io.boundary.exit_code = 0,
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.read_original_for_cleanup()
        }));
        if fault == 7 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err(), "fault {fault}");
        }
        assert_eq!(pin.read(&mut owner.io.boundary), Err(OwnerError::Retired));
        assert!(owner.original_live().is_err());
        // Restore external facts; factual cleanup can retry, but forward cannot.
        owner.io.boundary = OriginBoundary::live();
        {
            let mut s = state.borrow_mut();
            s.record = Some(running.clone());
            s.observation.config_sha256 = Some(running.intent.config_sha256);
        }
        assert_eq!(
            owner.read_original_for_cleanup(),
            Ok((running.intent.clone(), proof()))
        );
        assert!(owner.original_live().is_err());
        assert_eq!(owner.io.boundary.delete_calls, 0);
    }
}

#[test]
fn equal_durable_running_and_default_lookup_cannot_supply_cleanup_origin() {
    // This boundary deliberately has NO actual cleanup-origin implementation.
    let (mut lookup_owner, state) = setup();
    let running = lookup_owner.start().unwrap();
    assert_eq!(
        lookup_owner.read_original_for_cleanup(),
        Err(OwnerError::Retired)
    );
    let (mut other, _) = setup();
    other.journal = Disk(state.clone());
    other.io = Io(state.clone(), false);
    assert_eq!(other.read_original_for_cleanup(), Err(OwnerError::Retired));
    let intent = running.intent.clone();
    let mut recovered = MemberOwner::recover_for_cleanup(
        intent.scope,
        intent.slot,
        intent.transport,
        intent.engine,
        running,
        Disk(state.clone()),
        Io(state, false),
    )
    .unwrap();
    assert_eq!(
        recovered.read_original_for_cleanup(),
        Err(OwnerError::Retired)
    );
}

#[test]
fn original_live_durable_error_and_unwind_revoke_independent_actual_origin_pins() {
    // Break caught: owner revokes only its portable borrow and leaves a pin
    // forwarding fresh native facts after the SAME journal becomes uncertain.
    for unwind in [false, true] {
        let (mut o, state) = origin_owner();
        let running = o.start().unwrap();
        let mut pin = o.original_live().unwrap().native_read_pin().unwrap();
        assert_eq!(
            pin.read(&mut o.io.boundary),
            Ok((running.intent.clone(), proof()))
        );
        {
            let mut s = state.borrow_mut();
            s.read_step = 0;
            if unwind {
                s.panic_read_step = Some(1);
            } else {
                s.fail_read_step = Some(1);
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            o.original_live().unwrap().read()
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(OwnerError::Journal));
        }
        assert_eq!(pin.read(&mut o.io.boundary), Err(OwnerError::Retired));
        state.borrow_mut().fail_read_step = None;
        state.borrow_mut().panic_read_step = None;
        assert_eq!(o.stop(&running).unwrap().phase, Phase::Stopped);
        assert_eq!(o.io.boundary.delete_calls, 1);
        assert_eq!(o.io.boundary.service_closes.get(), 1);
        assert_eq!(pin.read(&mut o.io.boundary), Err(OwnerError::Retired));
    }
}

#[test]
fn original_live_lost_or_failed_running_cas_keeps_native_receipt_cleanup_only() {
    // Break caught: native receipt becomes a read grant even though THIS owner
    // never received its Running CAS ACK, or CAS error discards native handles.
    for lost in [false, true] {
        let (mut o, state) = origin_owner();
        if lost {
            state.borrow_mut().lost_save_ack = Some(Phase::Running);
        } else {
            state.borrow_mut().fail_save = Some(Phase::Running);
        }
        assert_eq!(o.start(), Err(OwnerError::Journal));
        assert!(o.io.origin.pin().is_err());
        assert!(o.original_live().is_err());
        assert_eq!(o.io.boundary.service_closes.get(), 0);
        assert_eq!(o.io.boundary.process_closes.get(), 0);
        state.borrow_mut().lost_save_ack = None;
        state.borrow_mut().fail_save = None;
        let obligation = state.borrow().record.clone().unwrap();
        assert_eq!(o.stop(&obligation).unwrap().phase, Phase::Stopped);
        assert_eq!(o.io.boundary.delete_calls, 1);
        assert_eq!(o.io.boundary.service_closes.get(), 1);
    }
}

#[test]
fn original_live_reads_same_owner_without_native_or_durable_effects() {
    // Break caught: capability returns cached facts or invokes an effect.
    let (mut o, s) = setup();
    let running = o.start_with_prior(None).unwrap();
    s.borrow_mut().events.clear();
    let mut read = o.original_live().unwrap();
    assert_eq!(read.read(), Ok((running.intent.clone(), proof())));
    s.borrow_mut().observation.interface.as_mut().unwrap().guid = [9; 16];
    assert_eq!(read.read(), Err(OwnerError::Conflict));
    s.borrow_mut().observation.interface = Some(proof().interface);
    assert_eq!(read.read(), Err(OwnerError::Retired));
    assert_eq!(s.borrow().record.as_ref(), Some(&running));
    assert!(s.borrow().events.iter().all(|e| *e == "inspect"));
}

#[test]
fn original_live_equal_json_and_live_lookup_cannot_grant_a_new_or_recovered_owner() {
    // Break caught: manufacture origin from matching Running JSON/proof.
    let (mut original, s) = setup();
    let saved = original.start().unwrap();
    let encoded = serde_json::to_vec(&saved).unwrap();
    let decoded: Record = serde_json::from_slice(&encoded).unwrap();
    s.borrow_mut().record = Some(decoded.clone());
    let mut other = owner(s.clone());
    other.verify_live(&decoded).unwrap();
    assert_eq!(original_read(&mut other), Err(OwnerError::Retired));
    assert_eq!(
        other.start_with_prior(Some(&decoded)),
        Err(OwnerError::Pending)
    );
    assert_eq!(original_read(&mut other), Err(OwnerError::Retired));
    let mut recovered = recover(&decoded, s.clone()).unwrap();
    recovered.verify_retained(&decoded).unwrap();
    assert_eq!(original_read(&mut recovered), Err(OwnerError::Retired));
    assert_eq!(original_read(&mut original), Ok((saved.intent, proof())));
}

#[test]
fn original_live_partial_start_and_lost_ack_keep_cleanup_without_origin() {
    // Break caught: a successful lookup after uncertain Start/CAS grants origin.
    for boundary in 0..7 {
        let (mut o, s) = setup();
        {
            let mut state = s.borrow_mut();
            match boundary {
                0 => state.lost_save_ack = Some(Phase::Prepared),
                1 => state.lost_config_ack = true,
                2 => state.fail_start = true,
                3 => state.fail_capture = true,
                4 => state.fail_save = Some(Phase::Running),
                5 => state.lost_save_ack = Some(Phase::Running),
                _ => state.drift_on_running_save = true,
            }
        }
        let result = o.start_with_prior(None);
        if boundary == 6 {
            assert!(result.is_ok()); // Existing Start return behavior unchanged.
        } else {
            assert!(result.is_err(), "boundary {boundary}");
        }
        let obligation = s.borrow().record.clone();
        let native = s.borrow().observation.clone();
        s.borrow_mut().fail_capture = false;
        assert!(original_read(&mut o).is_err(), "boundary {boundary}");
        assert_eq!(s.borrow().record, obligation);
        assert_eq!(s.borrow().observation, native);
        assert_eq!(o.start_with_prior(None), Err(OwnerError::Retired));
        if boundary != 6 {
            s.borrow_mut().fail_save = None;
            s.borrow_mut().lost_save_ack = None;
            assert_eq!(
                o.stop(obligation.as_ref().unwrap()).unwrap().phase,
                Phase::Stopped
            );
        }
    }
}

#[test]
fn original_live_foreign_or_missing_facts_revoke_even_after_exact_restoration() {
    // Break caught: missing any native/config/journal fence, or reviving on ABA.
    for mutation in 0..20 {
        let (mut o, s) = setup();
        let running = o.start().unwrap();
        let observation = s.borrow().observation.clone();
        original_read(&mut o).unwrap();
        {
            let mut state = s.borrow_mut();
            match mutation {
                0 => {
                    state
                        .observation
                        .service
                        .as_mut()
                        .unwrap()
                        .process
                        .as_mut()
                        .unwrap()
                        .pid += 1
                }
                1 => {
                    state
                        .observation
                        .service
                        .as_mut()
                        .unwrap()
                        .process
                        .as_mut()
                        .unwrap()
                        .creation_time += 1
                }
                2 => state.observation.interface.as_mut().unwrap().index += 1,
                3 => state.observation.interface.as_mut().unwrap().luid += 1,
                4 => state.observation.interface.as_mut().unwrap().guid = [9; 16],
                5 => state.observation.config_sha256 = None,
                6 => state.observation.config_sha256 = Some([9; 32]),
                7 => state.observation.service.as_mut().unwrap().exact_spec = false,
                8 => state.observation.alternative_service_present = true,
                9 => state.observation.service = None,
                10 => state.observation.service.as_mut().unwrap().process = None,
                11 => state.observation.interface = None,
                12 => state.observation.retained_interfaces.push(InterfaceProof {
                    guid: [9; 16],
                    ..proof().interface
                }),
                13 => state.record = None,
                14 => {
                    state
                        .record
                        .as_mut()
                        .unwrap()
                        .intent
                        .scope
                        .runtime_generation += 1
                }
                15 => {
                    state
                        .record
                        .as_mut()
                        .unwrap()
                        .intent
                        .scope
                        .connection_generation += 1
                }
                16 => state.record.as_mut().unwrap().intent.config_sha256 = [9; 32],
                17 => {
                    state
                        .record
                        .as_mut()
                        .unwrap()
                        .proof
                        .as_mut()
                        .unwrap()
                        .process
                        .creation_time += 1
                }
                18 => state.record.as_mut().unwrap().phase = Phase::Stopping,
                _ => {
                    state.record.as_mut().unwrap().intent.engine =
                        crate::test_engine_path("foreign.exe")
                }
            }
            state.events.clear();
        }
        assert!(original_read(&mut o).is_err(), "mutation {mutation}");
        {
            let mut state = s.borrow_mut();
            state.record = Some(running.clone());
            state.observation = observation;
        }
        assert_eq!(
            original_read(&mut o),
            Err(OwnerError::Retired),
            "mutation {mutation}"
        );
        assert!(s.borrow().events.iter().all(|e| *e == "inspect"));
        // Revocation never prevents ordinary exact cleanup.
        assert_eq!(o.stop(&running).unwrap().phase, Phase::Stopped);
    }
}

#[test]
fn original_live_failed_stop_or_rebind_revokes_before_any_effect() {
    // Break caught: revocation waits for Stop/Rebind success or durable change.
    for rebind in [false, true] {
        for fail in [false, true] {
            let (mut o, s) = setup();
            let running = o.start().unwrap();
            original_read(&mut o).unwrap();
            if fail {
                s.borrow_mut().fail_save = Some(if rebind {
                    Phase::Prepared
                } else {
                    Phase::Stopping
                });
            }
            let result = if rebind {
                o.rebind(&running)
            } else {
                o.stop(&running)
            };
            assert_eq!(result.is_err(), fail);
            assert_eq!(original_read(&mut o), Err(OwnerError::Retired));
            s.borrow_mut().record = Some(running);
            s.borrow_mut().observation.service = Some(ServiceObservation {
                exact_spec: true,
                process: Some(proof().process),
            });
            s.borrow_mut().observation.interface = Some(proof().interface);
            assert_eq!(original_read(&mut o), Err(OwnerError::Retired));
        }
    }
}

#[test]
fn original_live_read_errors_unwinds_and_midread_journal_drift_revoke_forward() {
    // Break caught: missing a read fence, treating error as facts, or reviving
    // after catch_unwind. There are three journal and two native read boundaries.
    for mode in 0..3 {
        for step in 1..=5 {
            let (mut o, s) = setup();
            let running = o.start().unwrap();
            let observation = s.borrow().observation.clone();
            let mut read = o.original_live().unwrap();
            {
                let mut state = s.borrow_mut();
                state.read_step = 0;
                match mode {
                    0 => state.fail_read_step = Some(step),
                    1 => state.panic_read_step = Some(step),
                    _ => state.drift_read_step = Some(step),
                }
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read.read()));
            match mode {
                0 => assert_eq!(
                    result.unwrap(),
                    Err(if step % 2 == 1 {
                        OwnerError::Journal
                    } else {
                        OwnerError::Native
                    }),
                    "step {step}"
                ),
                1 => assert!(result.is_err(), "step {step}"),
                _ => assert_eq!(result.unwrap(), Err(OwnerError::Conflict), "step {step}"),
            }
            {
                let mut state = s.borrow_mut();
                state.fail_read_step = None;
                state.panic_read_step = None;
                state.drift_read_step = None;
                state.record = Some(running.clone());
                state.observation = observation;
                state.events.clear();
            }
            assert_eq!(read.read(), Err(OwnerError::Retired));
            assert_eq!(original_read(&mut o), Err(OwnerError::Retired));
            assert!(s.borrow().events.is_empty());
            assert_eq!(o.stop(&running).unwrap().phase, Phase::Stopped);
        }
    }
}
