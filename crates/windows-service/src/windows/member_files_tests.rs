use super::*;
use std::{cell::Cell, io};

fn private(directory: bool) -> Acl {
    Acl {
        owner: SYSTEM.into(),
        control: PROTECTED,
        aces: [SYSTEM, ADMINISTRATORS]
            .map(|sid| Ace {
                kind: 0,
                flags: if directory { 3 } else { 0 },
                mask: ALL_ACCESS,
                sid: sid.into(),
            })
            .to_vec(),
    }
}
fn record() -> Record {
    serde_json::from_value(serde_json::json!({
    "intent":{"scope":{"runtime":"stable","runtime_generation":1,"session_id":"11111111-1111-4111-8111-111111111111","connection_generation":2},"slot":"a","transport":"wireguard","engine":"C:\\Program Files\\Nelomai\\engine.exe","config_sha256":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},
    "phase":"Prepared","proof":null,"retired_proof":null,"previous_config_sha256":null
})).unwrap()
}

#[test]
fn private_files_never_accept_world_read_or_inherited_acl() {
    for (directory, mode) in [(true, Protection::Directory), (false, Protection::File)] {
        assert!(acl_allowed(&private(directory), mode));
        for mutation in 0..8 {
            let mut acl = private(directory);
            match mutation {
                0 => acl.aces.push(Ace {
                    kind: 0,
                    flags: 0,
                    mask: 0x120089,
                    sid: "S-1-1-0".into(),
                }),
                1 => acl.control = 0,
                2 => acl.owner = "S-1-5-21-123".into(),
                3 => acl.owner = TRUSTED_INSTALLER.into(),
                4 => acl.aces[0].flags |= 0x10,
                5 => acl.aces[0].kind = 5,
                6 => acl.aces[0].mask = 0x120089,
                _ => acl.aces[1].sid = SYSTEM.into(),
            }
            assert!(!acl_allowed(&acl, mode), "{mutation}");
        }
        assert!(!acl_allowed(
            &Acl {
                owner: SYSTEM.into(),
                control: PROTECTED,
                aces: vec![]
            },
            mode
        ));
    }
}

#[test]
fn executable_payload_allows_inherited_read_but_never_foreign_mutation() {
    let mut acl = private(false);
    acl.owner = TRUSTED_INSTALLER.into();
    acl.control = 0;
    for ace in &mut acl.aces {
        ace.flags = 0x10;
    }
    acl.aces.push(Ace {
        kind: 0,
        flags: 0x10,
        mask: 0x1200a9,
        sid: "S-1-1-0".into(),
    });
    assert!(acl_allowed(&acl, Protection::Payload));
    for mask in [
        2, 4, 16, 256, 0x10000, 0x40000, 0x80000, 0x10000000, 0x20000000, 0x40000000,
    ] {
        let mut bad = acl.clone();
        bad.aces.last_mut().unwrap().mask |= mask;
        assert!(
            !acl_allowed(&bad, Protection::Payload),
            "foreign mask={mask:x}"
        );
    }
    for mutation in 0..4 {
        let mut bad = acl.clone();
        match mutation {
            0 => bad.owner = "S-1-1-0".into(),
            1 => bad.aces.last_mut().unwrap().kind = 5,
            2 => bad.aces.last_mut().unwrap().flags |= 0x80,
            _ => bad.aces.clear(),
        }
        assert!(!acl_allowed(&bad, Protection::Payload));
    }
    assert!(!acl_allowed(&acl, Protection::File)); // secrets not loosened
}

#[test]
fn pinned_payload_read_requires_exact_signed_size_and_digest() {
    // Literal SHA256("abc"), independently published test vector.
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert!(verify_payload_bytes(&b"abc"[..], 3, hash).is_ok());
    for (bytes, size) in [
        (&b"abd"[..], 3),
        (&b"ab"[..], 3),
        (&b"abcd"[..], 3),
        (&b"abc"[..], 2),
        (&b""[..], 0),
        (&b"abc"[..], 16 * 1024 * 1024 + 1),
    ] {
        assert!(verify_payload_bytes(bytes, size, hash).is_err());
    }
    assert!(verify_payload_bytes(&b"abc"[..], 3, &hash.to_uppercase()).is_err());
    assert!(verify_payload_bytes(&b"abc"[..], 3, "untrusted").is_err());
    struct Broken;
    impl io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failure"))
        }
    }
    assert!(verify_payload_bytes(Broken, 3, hash).is_err());
}

#[test]
fn recovery_marker_accepts_only_private_acl_inherited_from_pinned_private_root() {
    let mut inherited = private(false);
    inherited.control = 0;
    for ace in &mut inherited.aces {
        ace.flags = 0x10;
    }
    assert!(recovery_marker_acl_allowed(&inherited));
    assert!(recovery_marker_acl_allowed(&private(false)));
    for mutation in 0..5 {
        let mut bad = inherited.clone();
        match mutation {
            0 => bad.owner = "S-1-5-21-123".into(),
            1 => bad.aces[0].sid = "S-1-1-0".into(),
            2 => bad.aces[0].flags |= 8,
            3 => bad.aces[0].mask = 0x120089,
            _ => bad.aces.push(Ace {
                kind: 0,
                flags: 0,
                mask: 2,
                sid: "S-1-1-0".into(),
            }),
        }
        assert!(!recovery_marker_acl_allowed(&bad));
    }
}

#[test]
fn ancestor_policy_preserves_substitution_and_ownership_fences() {
    let mut ace = Ace {
        kind: 0,
        flags: 0,
        mask: 0x1200a9,
        sid: "S-1-1-0".into(),
    };
    assert!(ancestor_ace_allowed(&ace));
    ace.mask = 2 | 4;
    assert!(ancestor_ace_allowed(&ace)); // sibling creation only
    for mask in [
        0x40, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000, 0x20000000,
    ] {
        ace.mask = mask;
        assert!(!ancestor_ace_allowed(&ace));
    }
    ace.kind = 1;
    ace.mask = u32::MAX;
    assert!(ancestor_ace_allowed(&ace));
    ace.kind = 0;
    ace.flags = 8;
    assert!(ancestor_ace_allowed(&ace));
    ace.kind = 5;
    assert!(!ancestor_ace_allowed(&ace));
    let mut acl = private(true);
    acl.owner = TRUSTED_INSTALLER.into();
    assert!(acl_allowed(&acl, Protection::Ancestor));
    acl.owner = "S-1-5-21-123".into();
    assert!(!acl_allowed(&acl, Protection::Ancestor));
}

#[test]
fn programdata_create_child_acl_is_accepted_only_for_ancestors() {
    let mut acl = private(true);
    acl.control = 0; // Existing ProgramData need not have a protected DACL.
    acl.aces.push(Ace {
        kind: 0,
        flags: 0,
        mask: 0x116, // add file/subdirectory, write EA/attributes
        sid: "S-1-5-32-545".into(),
    });
    assert!(acl_allowed(&acl, Protection::Ancestor));
    assert!(!acl_allowed(&acl, Protection::Directory));
    assert!(!acl_allowed(&acl, Protection::File));
    acl.control = PROTECTED;
    assert!(!acl_allowed(&acl, Protection::Directory));
    for extra in [0x40, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000] {
        acl.aces.last_mut().unwrap().mask = 0x116 | extra;
        assert!(!acl_allowed(&acl, Protection::Ancestor), "{extra:x}");
    }
}

#[test]
fn creating_missing_child_requires_parent_without_public_reparse_rights() {
    let mut acl = private(true);
    assert!(ancestor_creation_allowed(&acl));
    acl.aces.push(Ace {
        kind: 0,
        flags: 0,
        mask: 2, // FILE_WRITE_DATA can also set a reparse point on an empty parent.
        sid: "S-1-5-32-545".into(),
    });
    for mask in [2, 0x100, 0x116] {
        acl.aces.last_mut().unwrap().mask = mask;
        assert!(!ancestor_creation_allowed(&acl), "{mask:x}");
    }
    acl.aces.last_mut().unwrap().flags = 8;
    assert!(ancestor_creation_allowed(&acl));
}

#[test]
fn installed_subtree_opens_below_public_create_acl_but_missing_subtree_needs_repair() {
    let mut parent = private(true);
    parent.aces.push(Ace {
        kind: 0,
        flags: 0,
        mask: 0x116,
        sid: "S-1-5-32-545".into(),
    });
    // The installer prepares Tunnel before manager startup. Both Nelomai and
    // Tunnel already exist; opening them must never invoke the creation gate.
    for depth in [1, 0] {
        let (opened, created) = open_directory_or_create_owned(
            depth,
            Some(&parent),
            || Ok(private(true)),
            || panic!("existing subtree"),
        )
        .unwrap();
        assert!(!created);
        assert!(acl_allowed(&opened, Protection::Directory));
        assert!(acl_allowed(&parent, Protection::Ancestor));
        assert!(open_directory_or_create_owned::<Acl>(
            depth,
            Some(&parent),
            || Err(2),
            || panic!("unsafe parent must not be mutated"),
        )
        .is_err());
    }
    // Runtime may recreate a missing leaf when the parent itself is protected.
    let present = Cell::new(false);
    let (opened, created) = open_directory_or_create_owned(
        0,
        Some(&private(true)),
        || {
            if present.get() {
                Ok(private(true))
            } else {
                Err(2)
            }
        },
        || {
            present.set(true);
            Ok(true)
        },
    )
    .unwrap();
    assert!(created);
    assert!(acl_allowed(&opened, Protection::Directory));
    // Errors other than missing and ancestors outside our two owned levels
    // never trigger a speculative directory creation.
    for (depth, error) in [(0, 5), (0, 3), (2, 2)] {
        assert!(open_directory_or_create_owned::<Acl>(
            depth,
            Some(&private(true)),
            || Err(error),
            || panic!("not ours to create"),
        )
        .is_err());
    }
}

#[test]
fn only_local_absolute_drive_paths_without_alias_escape_are_accepted() {
    for good in [
        r"C:\",
        r"C:\ProgramData\Nelomai\Tunnel",
        r"\\?\C:\ProgramData\Nelomai\Tunnel",
    ] {
        assert!(local_drive_path(good), "{good}");
    }
    for bad in [
        r"relative",
        r"C:relative",
        r"\rooted",
        r"\\host\share\file",
        r"\\?\UNC\host\share",
        r"\\.\pipe\x",
        r"C:\a\..\b",
        r"C:\a\.\b",
        r"C:\a\config:stream",
        r"C:\a.\b",
        r"C:\a \b",
        r"C:\a\NUL",
        r"C:\a\COM1.txt",
        "C:\\a\0b",
        r"C:\a\\b",
    ] {
        assert!(!local_drive_path(bad), "{bad}");
    }
}

#[test]
fn handle_facts_reject_reparse_multilink_and_wrong_object_type() {
    let regular = Facts {
        attributes: 0x80,
        links: 1,
        size: 16,
    };
    assert!(facts_allowed(regular, false, 16));
    for bad in [
        Facts {
            attributes: 0x480,
            ..regular
        },
        Facts {
            links: 2,
            ..regular
        },
        Facts {
            links: 0,
            ..regular
        },
        Facts {
            attributes: 0x10,
            ..regular
        },
        Facts {
            size: 17,
            ..regular
        },
    ] {
        assert!(!facts_allowed(bad, false, 16));
    }
    assert!(facts_allowed(
        Facts {
            attributes: 0x10,
            links: 1,
            size: 0
        },
        true,
        0
    ));
    assert!(!facts_allowed(regular, true, 16));
}

#[test]
fn bounded_reader_stops_at_limit_plus_one_without_allocating_unbounded_input() {
    struct Endless<'a>(&'a Cell<usize>);
    impl Read for Endless<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.0.set(self.0.get() + out.len());
            out.fill(b'x');
            Ok(out.len())
        }
    }
    assert_eq!(&*bounded_read(&b"abcd"[..], 4).unwrap(), b"abcd");
    let seen = Cell::new(0);
    assert!(bounded_read(Endless(&seen), 4).is_err());
    assert_eq!(seen.get(), 5);
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("SECRET-MUST-NOT-LEAK"))
        }
    }
    let error = bounded_read(Broken, 4).unwrap_err();
    assert!(!format!("{error}").contains("SECRET"));
}

#[test]
fn bounded_journal_decoder_rejects_wrong_slot_unknown_fields_and_invalid_state() {
    let valid = record();
    let bytes = serde_json::to_vec(&valid).unwrap();
    assert_eq!(decode_journal(TunnelSlot::A, &bytes).unwrap(), valid);
    assert!(decode_journal(TunnelSlot::B, &bytes).is_err());
    for bytes in [vec![b' '; MAX_JOURNAL + 1], b"{".to_vec(), vec![0xff]] {
        assert!(decode_journal(TunnelSlot::A, &bytes).is_err());
    }
    for (field, value) in [
        ("phase", serde_json::json!("Running")),
        ("extra", serde_json::json!(true)),
    ] {
        let mut changed = serde_json::to_value(&valid).unwrap();
        changed[field] = value;
        assert!(decode_journal(TunnelSlot::A, &serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut malformed = valid.clone();
    malformed.intent.scope.connection_generation = 0;
    assert!(decode_journal(TunnelSlot::A, &serde_json::to_vec(&malformed).unwrap()).is_err());
}

#[test]
fn journal_cas_requires_exact_expected_record_before_producing_replacement() {
    let old = record();
    let bytes = serde_json::to_vec(&old).unwrap();
    let mut next = old.clone();
    next.phase = Phase::Stopping;
    assert_eq!(
        decode_journal(
            TunnelSlot::A,
            &prepare_journal_replace(TunnelSlot::A, Some(&bytes), Some(&old), &next).unwrap()
        )
        .unwrap(),
        next
    );
    assert!(prepare_journal_replace(TunnelSlot::A, None, Some(&old), &next).is_err());
    assert!(prepare_journal_replace(TunnelSlot::A, Some(&bytes), None, &next).is_err());
    assert!(prepare_journal_replace(TunnelSlot::B, Some(&bytes), Some(&old), &next).is_err());
    let mut foreign = old.clone();
    foreign.intent.scope.connection_generation += 1;
    assert!(prepare_journal_replace(
        TunnelSlot::A,
        Some(&serde_json::to_vec(&foreign).unwrap()),
        Some(&old),
        &next
    )
    .is_err());
    assert!(prepare_journal_replace(TunnelSlot::A, None, None, &old).is_ok());
}

#[test]
fn config_accepts_only_bounded_canonical_slot_renderer_output() {
    let valid = b"[Interface]\nTable = off\nPrivateKey = fake\n[Peer]\nPublicKey = fake\n";
    assert!(canonical_config(valid).is_ok());
    for bad in [
        b"[Interface]\nDNS=9.9.9.9\n[Peer]\n".as_slice(),
        b"[Interface]\nTable = auto\n[Peer]\n",
        b"x\0y",
        b"\xff",
    ] {
        assert!(canonical_config(bad).is_err());
    }
    assert!(canonical_config(&vec![b'x'; crate::MAX_FRAME_SIZE + 1]).is_err());
}

#[test]
fn journal_rejects_malformed_or_retired_live_identity_and_nonlocal_engine() {
    use crate::member_owner::{InterfaceProof, NativeProof, ProcessProof};
    let proof = NativeProof {
        process: ProcessProof {
            pid: 42,
            creation_time: 99,
        },
        interface: InterfaceProof {
            index: 5,
            luid: 6,
            guid: [7; 16],
        },
    };
    let mut running = record();
    running.phase = Phase::Running;
    running.proof = Some(proof);
    let decode =
        |record: &Record| decode_journal(TunnelSlot::A, &serde_json::to_vec(record).unwrap());
    assert!(decode(&running).is_ok());
    for mutation in 0..7 {
        let mut changed = running.clone();
        let live = changed.proof.as_mut().unwrap();
        match mutation {
            0 => live.process.pid = 0,
            1 => live.process.creation_time = 0,
            2 => live.interface.index = 0,
            3 => live.interface.luid = 0,
            4 => live.interface.guid = [0; 16],
            5 => changed.retired_proof = Some(proof),
            _ => changed.phase = Phase::Stopped,
        }
        assert!(decode(&changed).is_err(), "{mutation}");
    }
    for path in [
        r"\\remote\engine.exe",
        r"C:\a\..\engine.exe",
        r"relative.exe",
    ] {
        let mut changed = running.clone();
        changed.intent.engine = path.into();
        assert!(decode(&changed).is_err());
    }
}

#[test]
fn journal_lost_ack_is_recoverable_by_loading_not_blind_replacement() {
    // In-memory durable bytes; publication faults are injected without disk IO.
    let old = record();
    let mut next = old.clone();
    next.phase = Phase::Stopping;
    let mut disk = serde_json::to_vec(&old).unwrap();
    let replacement =
        prepare_journal_replace(TunnelSlot::A, Some(&disk), Some(&old), &next).unwrap();
    // Failure before publication leaves the previous complete record.
    assert_eq!(decode_journal(TunnelSlot::A, &disk).unwrap(), old);
    // Publication succeeds but its acknowledgement is lost.
    disk = replacement.to_vec();
    assert_eq!(decode_journal(TunnelSlot::A, &disk).unwrap(), next);
    assert!(prepare_journal_replace(TunnelSlot::A, Some(&disk), Some(&old), &next).is_err());
    assert!(prepare_journal_replace(TunnelSlot::A, Some(&disk), Some(&next), &next).is_ok());
}

#[test]
fn local_paths_reject_dos_aliases_and_oversized_names() {
    for tail in [
        "CON.txt",
        "CONIN$",
        "LPT¹",
        "COM².log",
        "a/b",
        "a?b",
        "a\nb",
    ] {
        assert!(!local_drive_path(&format!("C:\\private\\{tail}")));
    }
    assert!(!local_drive_path(&format!("C:\\{}", "a".repeat(32760))));
}

#[test]
fn session_fixed_files_require_exact_cas_and_bound_both_sides() {
    for file in [
        PrivateFile::Index,
        PrivateFile::Session,
        PrivateFile::Pair,
        PrivateFile::Network,
        PrivateFile::Carrier,
    ] {
        assert!(private_replace_allowed(file, None, None, b"new"));
        assert!(private_replace_allowed(
            file,
            Some(b"old"),
            Some(b"old"),
            b"new"
        ));
        assert!(!private_replace_allowed(file, Some(b"old"), None, b"new"));
        assert!(!private_replace_allowed(file, None, Some(b"old"), b"new"));
        assert!(!private_replace_allowed(
            file,
            Some(b"other"),
            Some(b"old"),
            b"new"
        ));
    }
    let large = vec![0; PrivateFile::Index.limit() + 1];
    assert!(!private_replace_allowed(
        PrivateFile::Index,
        None,
        None,
        &large
    ));
    assert!(!private_replace_allowed(
        PrivateFile::Index,
        Some(&large),
        Some(&large),
        b"new"
    ));
}

#[test]
fn carrier_file_is_distinct_and_bounded_at_64k_before_publication_or_read() {
    let carrier = PrivateFile::Carrier;
    assert_eq!(carrier.name(), "nelomai-redundant-carrier.json");
    assert_eq!(carrier.limit(), 64 * 1024);
    for other in [
        PrivateFile::Index,
        PrivateFile::Session,
        PrivateFile::Pair,
        PrivateFile::Network,
        PrivateFile::Completed([1; 32]),
    ] {
        assert_ne!(carrier.name(), other.name());
    }
    let at_limit = vec![b' '; 64 * 1024];
    let over = vec![b' '; 64 * 1024 + 1];
    assert!(private_replace_allowed(carrier, None, None, &at_limit));
    assert!(!private_replace_allowed(carrier, None, None, &over));
    assert!(!private_replace_allowed(
        carrier,
        Some(&over),
        Some(&over),
        b"small"
    ));
    assert!(!facts_allowed(
        Facts {
            attributes: 0,
            links: 1,
            size: over.len() as u64
        },
        false,
        carrier.limit()
    ));
    assert!(bounded_read(over.as_slice(), carrier.limit()).is_err());
}

#[test]
fn completed_hash_filename_cannot_supply_a_foreign_path_or_unbounded_payload() {
    for byte in 0..=255u8 {
        let file = PrivateFile::Completed([byte; 32]);
        let name = file.name();
        let digest = name
            .strip_prefix("nelomai-redundant-completed-")
            .unwrap()
            .strip_suffix(".json")
            .unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert!(!name.contains(['/', '\\', ':']));
        assert!(!private_replace_allowed(
            file,
            None,
            None,
            &vec![0; file.limit() + 1]
        ));
    }
}

#[test]
fn completed_marker_cas_is_create_only_or_exact_idempotent_republication() {
    let file = PrivateFile::Completed([7; 32]);
    assert!(private_replace_allowed(file, None, None, b"identity"));
    assert!(private_replace_allowed(
        file,
        Some(b"identity"),
        Some(b"identity"),
        b"identity"
    ));
    assert!(!private_replace_allowed(
        file,
        Some(b"identity"),
        Some(b"identity"),
        b"replacement"
    ));
    assert!(!private_replace_allowed(
        file,
        Some(b"identity"),
        None,
        b"replacement"
    ));
}

#[test]
fn previous_config_digest_is_only_prepared_or_terminal_stopped_without_live_proof() {
    use crate::member_owner::{InterfaceProof, NativeProof, ProcessProof};
    let proof = NativeProof {
        process: ProcessProof {
            pid: 2,
            creation_time: 3,
        },
        interface: InterfaceProof {
            index: 4,
            luid: 5,
            guid: [6; 16],
        },
    };
    for (phase, live, allowed) in [
        (Phase::Prepared, None, true),
        (Phase::Stopped, None, true),
        (Phase::Stopping, None, false),
        (Phase::Running, Some(proof), false),
        (Phase::Stopped, Some(proof), false),
        (Phase::Prepared, Some(proof), false),
    ] {
        let mut value = record();
        value.phase = phase;
        value.proof = live;
        value.previous_config_sha256 = Some([9; 32]);
        assert_eq!(
            decode_journal(TunnelSlot::A, &serde_json::to_vec(&value).unwrap()).is_ok(),
            allowed,
            "{phase:?}"
        );
    }
    let mut stopped = record();
    stopped.phase = Phase::Stopped;
    stopped.previous_config_sha256 = Some([9; 32]);
    stopped.retired_proof = Some(proof);
    assert!(decode_journal(TunnelSlot::A, &serde_json::to_vec(&stopped).unwrap()).is_ok());
}

const OLD_CONFIG: &[u8] =
    b"[Interface]\nTable = off\nPrivateKey = old-test-only\n[Peer]\nPublicKey = peer-test-only\n";
const NEW_CONFIG: &[u8] =
    b"[Interface]\nTable = off\nPrivateKey = new-test-only\n[Peer]\nPublicKey = peer-test-only\n";
fn config_hash(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

struct ConfigRead {
    bytes: Vec<u8>,
    parent: u64,
    id: u64,
}
struct ConfigDisk {
    bytes: Option<Vec<u8>>,
    facts: Facts,
    acl: Acl,
    parent: u64,
    id: u64,
    change_parent: bool,
    change_file: bool,
    fail_before_publish: bool,
    lost_ack: bool,
    reads: usize,
    publishes: usize,
}
impl ConfigDisk {
    fn new(bytes: Option<&[u8]>) -> Self {
        Self {
            bytes: bytes.map(<[u8]>::to_vec),
            facts: Facts {
                attributes: 0x80,
                links: 1,
                size: bytes.map_or(0, |b| b.len() as u64),
            },
            acl: private(false),
            parent: 1,
            id: 1,
            change_parent: false,
            change_file: false,
            fail_before_publish: false,
            lost_ack: false,
            reads: 0,
            publishes: 0,
        }
    }
}
impl ConfigStorage for ConfigDisk {
    type Current = ConfigRead;
    fn read_owned(&mut self) -> Result<Option<ConfigRead>> {
        self.reads += 1;
        if self.parent != 1
            || !facts_allowed(self.facts, false, crate::MAX_FRAME_SIZE)
            || !acl_allowed(&self.acl, Protection::File)
        {
            return Err(OwnerError::Conflict);
        }
        Ok(self.bytes.as_ref().map(|bytes| ConfigRead {
            bytes: bytes.clone(),
            parent: self.parent,
            id: self.id,
        }))
    }
    fn bytes(file: &ConfigRead) -> &[u8] {
        &file.bytes
    }
    fn publish_owned(&mut self, current: Option<ConfigRead>, canonical: &[u8]) -> Result<()> {
        if self.change_parent {
            self.parent += 1;
        }
        if self.change_file {
            self.id += 1;
        }
        if self.fail_before_publish {
            return Err(OwnerError::Native);
        }
        if self.parent != 1
            || current
                .as_ref()
                .is_some_and(|f| f.parent != self.parent || f.id != self.id)
            || current.as_ref().map(|f| f.bytes.as_slice()) != self.bytes.as_deref()
        {
            return Err(OwnerError::Conflict);
        }
        self.bytes = Some(canonical.to_vec());
        self.id += 1;
        self.facts.size = canonical.len() as u64;
        self.publishes += 1;
        if self.lost_ack {
            self.lost_ack = false;
            return Err(OwnerError::Native);
        }
        Ok(())
    }
}
#[test]
fn config_storage_cas_creates_absent_and_replaces_exact_owned_digest() {
    let mut disk = ConfigDisk::new(None);
    replace_config(&mut disk, None, OLD_CONFIG).unwrap();
    assert_eq!(disk.bytes.as_deref(), Some(OLD_CONFIG));
    replace_config(&mut disk, Some(config_hash(OLD_CONFIG)), NEW_CONFIG).unwrap();
    assert_eq!(disk.bytes.as_deref(), Some(NEW_CONFIG));
    assert_eq!(disk.publishes, 2);
}
#[test]
fn config_storage_cas_none_foreign_digest_and_missing_expected_never_publish() {
    for (existing, expected) in [
        (Some(OLD_CONFIG), None),
        (Some(OLD_CONFIG), Some(config_hash(NEW_CONFIG))),
        (None, Some(config_hash(OLD_CONFIG))),
    ] {
        let mut disk = ConfigDisk::new(existing);
        assert_eq!(
            replace_config(&mut disk, expected, NEW_CONFIG),
            Err(OwnerError::Conflict)
        );
        assert_eq!(disk.bytes.as_deref(), existing);
        assert_eq!(disk.publishes, 0);
    }
}
#[test]
fn config_storage_cas_lost_ack_requires_readback_not_blind_old_digest_retry() {
    let mut disk = ConfigDisk::new(Some(OLD_CONFIG));
    disk.lost_ack = true;
    assert_eq!(
        replace_config(&mut disk, Some(config_hash(OLD_CONFIG)), NEW_CONFIG),
        Err(OwnerError::Native)
    );
    assert_eq!(disk.bytes.as_deref(), Some(NEW_CONFIG));
    assert_eq!(
        replace_config(&mut disk, Some(config_hash(OLD_CONFIG)), NEW_CONFIG),
        Err(OwnerError::Conflict)
    );
    assert_eq!(disk.publishes, 1);
    let read = disk.read_owned().unwrap().unwrap();
    assert_eq!(
        config_hash(ConfigDisk::bytes(&read)),
        config_hash(NEW_CONFIG)
    );
    let mut created = ConfigDisk::new(None);
    created.lost_ack = true;
    assert_eq!(
        replace_config(&mut created, None, NEW_CONFIG),
        Err(OwnerError::Native)
    );
    assert_eq!(
        replace_config(&mut created, None, NEW_CONFIG),
        Err(OwnerError::Conflict)
    );
    assert_eq!(created.publishes, 1);
}
#[test]
fn config_storage_cas_rejects_untrusted_handles_and_changed_parents() {
    for mutation in 0..7 {
        let mut disk = ConfigDisk::new(Some(OLD_CONFIG));
        match mutation {
            0 => disk.facts.attributes |= 0x400,
            1 => disk.facts.links = 2,
            2 => disk.acl.aces[0].sid = "S-1-1-0".into(),
            3 => disk.parent = 2,
            4 => disk.change_parent = true,
            5 => disk.change_file = true,
            _ => disk.facts.size = crate::MAX_FRAME_SIZE as u64 + 1,
        }
        assert!(replace_config(&mut disk, Some(config_hash(OLD_CONFIG)), NEW_CONFIG).is_err());
        assert_eq!(disk.publishes, 0);
        assert_eq!(disk.bytes.as_deref(), Some(OLD_CONFIG));
    }
}
#[test]
fn config_storage_cas_is_bounded_canonical_and_redacts_failures() {
    let mut disk = ConfigDisk::new(Some(OLD_CONFIG));
    for bad in [
        b"secret\0".to_vec(),
        vec![b'x'; crate::MAX_FRAME_SIZE + 1],
        b"[Interface]\nDNS=9.9.9.9\n[Peer]\n".to_vec(),
    ] {
        assert!(replace_config(&mut disk, Some(config_hash(OLD_CONFIG)), &bad).is_err());
        assert_eq!(disk.reads, 0);
    }
    disk.fail_before_publish = true;
    let error = replace_config(&mut disk, Some(config_hash(OLD_CONFIG)), NEW_CONFIG).unwrap_err();
    assert!(!error.to_string().contains("test-only"));
    assert_eq!(disk.bytes.as_deref(), Some(OLD_CONFIG));
    assert_eq!(disk.publishes, 0);
    for invalid in [
        b"malformed-test-only".as_slice(),
        b"[Interface]\nDNS=9.9.9.9\n[Peer]\n",
    ] {
        let mut disk = ConfigDisk::new(Some(invalid));
        assert!(replace_config(&mut disk, Some(config_hash(invalid)), NEW_CONFIG).is_err());
        assert_eq!(disk.publishes, 0);
    }
}
#[test]
fn config_path_selection_is_exact_before_any_file_effect() {
    use std::ffi::OsStr;
    let a = OsStr::new(r"C:\ProgramData\Nelomai\nelomai-a.conf");
    let b = OsStr::new(r"C:\ProgramData\Nelomai\nelomai-b.conf");
    assert_eq!(exact_config_slot(a, a, b).unwrap(), TunnelSlot::A);
    assert_eq!(exact_config_slot(b, a, b).unwrap(), TunnelSlot::B);
    for path in [
        r"C:\ProgramData\Nelomai\..\nelomai-a.conf",
        r"C:\ProgramData\Nelomai\nelomai-a.conf:stream",
        r"C:\ProgramData\Nelomai\nelomai-a.conf.",
        r"C:\ProgramData\Nelomai\NELOMAI-A.CONF",
        r"\\remote\share\nelomai-a.conf",
        r"C:\foreign\nelomai-a.conf",
        "nelomai-a.conf",
    ] {
        assert_eq!(
            exact_config_slot(OsStr::new(path), a, b),
            Err(OwnerError::Invalid)
        );
    }
}
