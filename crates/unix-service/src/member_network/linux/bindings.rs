//! Durable reservations made by the privileged, exclusively locked session owner.
//! This module never issues native commands. All four occupancy dumps must be
//! collected by the owner before reservation, while it holds its runtime guard.

use crate::member_network::journal::ScopedJournal;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::dispatcher::TunnelSlot;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io, path::Path};

const STATE_FILE: &str = "redundant-linux-bindings.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub slot: TunnelSlot,
    pub index: u32,
    pub name: String,
    pub table: u32,
    pub priority: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingRecord {
    boot: String,
    bindings: Vec<Binding>,
}

/// Union of occupied tables (including rule references) and priorities in both
/// address families. Construct only from successful, complete numeric dumps.
#[derive(Debug)]
pub struct Occupancy {
    tables: BTreeSet<u32>,
    priorities: BTreeSet<u32>,
}

impl Occupancy {
    pub fn parse(
        routes_v4: &str,
        routes_v6: &str,
        rules_v4: &str,
        rules_v6: &str,
    ) -> io::Result<Self> {
        let mut occupied = Self {
            tables: BTreeSet::new(),
            priorities: BTreeSet::new(),
        };
        for (text, rules) in [
            (routes_v4, false),
            (routes_v6, false),
            (rules_v4, true),
            (rules_v6, true),
        ] {
            if text.len() > 8 * 1024 * 1024 {
                return Err(invalid());
            }
            let rows: Vec<OccupancyRow> = serde_json::from_str(text).map_err(|_| invalid())?;
            for row in rows {
                // Other fields (multipath, rule selectors/actions, etc.) do not
                // change occupancy. Never filter a row before parsing its IDs.
                if let Some(table) = row.table.as_ref() {
                    occupied.tables.insert(number(table)?);
                } else if !rules {
                    occupied.tables.insert(254);
                }
                if rules {
                    occupied
                        .priorities
                        .insert(number(row.priority.as_ref().ok_or_else(invalid)?)?);
                }
            }
        }
        Ok(occupied)
    }
}

// Value's object decoder keeps the last duplicate key. Decode occupancy fields
// explicitly so a later key cannot conceal an occupied or malformed identifier.
struct OccupancyRow {
    table: Option<serde_json::Value>,
    priority: Option<serde_json::Value>,
}

impl<'de> Deserialize<'de> for OccupancyRow {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct RowVisitor;
        impl<'de> serde::de::Visitor<'de> for RowVisitor {
            type Value = OccupancyRow;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an ip JSON row with unambiguous occupancy fields")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut row = OccupancyRow {
                    table: None,
                    priority: None,
                };
                while let Some(key) = map.next_key::<String>()? {
                    let field = match key.as_str() {
                        "table" => &mut row.table,
                        "priority" => &mut row.priority,
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            continue;
                        }
                    };
                    if field.is_some() {
                        return Err(serde::de::Error::custom("duplicate occupancy field"));
                    }
                    *field = Some(map.next_value()?);
                }
                Ok(row)
            }
        }
        decoder.deserialize_map(RowVisitor)
    }
}

/// Non-cloneable owner; callers must hold the engine's exclusive runtime guard
/// throughout this object's lifetime and serialize access with `&mut self`.
pub struct BindingAllocator {
    store: ScopedJournal<BindingRecord>,
    record: BindingRecord,
    recovering: bool,
}

impl BindingAllocator {
    /// Explicit fresh start, permitted only when no reservations are pending.
    pub fn fresh_root(root: &Path, scope: SessionScope, boot: &str) -> io::Result<Self> {
        Self::open_for_owner(root, scope, boot, 0, true)
    }

    /// Always cleanup-only, even when the journal has no remaining bindings.
    pub fn reopen_root(root: &Path, scope: SessionScope, boot: &str) -> io::Result<Self> {
        Self::open_for_owner(root, scope, boot, 0, false)
    }

    pub(crate) fn open_for_owner(
        root: &Path,
        scope: SessionScope,
        boot: &str,
        uid: u32,
        fresh: bool,
    ) -> io::Result<Self> {
        if boot.is_empty() || boot.len() > 128 || boot.chars().any(char::is_control) {
            return Err(invalid());
        }
        let mut store = ScopedJournal::<BindingRecord>::open_named(root, scope, uid, STATE_FILE)?;
        let record = match store.load()? {
            Some(record) => {
                validate_record(&record, boot)?;
                record
            }
            None => BindingRecord {
                boot: boot.into(),
                bindings: Vec::new(),
            },
        };
        if fresh {
            if !record.bindings.is_empty() {
                return Err(invalid());
            }
            // Persist even the empty record, so a new OS boot cannot adopt it.
            store.save_state(&record)?;
        }
        Ok(Self {
            store,
            record,
            recovering: !fresh,
        })
    }

    pub fn is_recovering(&self) -> bool {
        self.recovering
    }

    pub fn bindings(&self) -> &[Binding] {
        &self.record.bindings
    }

    /// The index/name must come from privileged capture, never application IPC.
    /// A successful return is the durable reservation required BEFORE writes.
    pub fn reserve(
        &mut self,
        slot: TunnelSlot,
        index: u32,
        name: &str,
        occupied: &Occupancy,
    ) -> io::Result<Binding> {
        if self.recovering || index == 0 || !valid_name(slot, name) {
            return Err(invalid());
        }
        self.ensure_current()?;
        if let Some(existing) = self.record.bindings.iter().find(|b| b.slot == slot) {
            return if existing.index == index && existing.name == name {
                Ok(existing.clone())
            } else {
                Err(invalid())
            };
        }
        if self.record.bindings.len() >= 2
            || self
                .record
                .bindings
                .iter()
                .any(|b| b.index == index || b.name == name)
        {
            return Err(invalid());
        }
        let table = (30000..=30255)
            .find(|id| {
                !occupied.tables.contains(id)
                    && !self.record.bindings.iter().any(|b| b.table == *id)
            })
            .ok_or_else(|| io::Error::other("linux_member_tables_exhausted"))?;
        let priority = (10000..=10255)
            .find(|id| {
                !occupied.priorities.contains(id)
                    && !self.record.bindings.iter().any(|b| b.priority == *id)
            })
            .ok_or_else(|| io::Error::other("linux_member_priorities_exhausted"))?;
        let binding = Binding {
            slot,
            index,
            name: name.into(),
            table,
            priority,
        };
        let mut next = self.record.clone();
        next.bindings.push(binding.clone());
        self.save(next)?;
        Ok(binding)
    }

    /// The owner must confirm ALL member resources are removed before calling.
    /// Only the exact saved binding may be released; this does no native cleanup.
    pub fn release(&mut self, binding: &Binding) -> io::Result<()> {
        self.ensure_current()?;
        let position = self
            .record
            .bindings
            .iter()
            .position(|b| b == binding)
            .ok_or_else(invalid)?;
        let mut next = self.record.clone();
        next.bindings.remove(position);
        self.save(next)
    }

    fn ensure_current(&self) -> io::Result<()> {
        // Detect stale in-memory owners or modified records. This is defense in
        // depth, not a substitute for the enclosing exclusive runtime guard.
        if self.store.load()?.as_ref() != Some(&self.record) {
            return Err(invalid());
        }
        Ok(())
    }

    fn save(&mut self, next: BindingRecord) -> io::Result<()> {
        if let Err(error) = self.store.save_state(&next) {
            // A failed directory fsync can follow a successful rename. Do not
            // publish the assignment or permit further allocation; reopen to
            // inspect the durable cleanup record after such an ambiguous error.
            self.recovering = true;
            return Err(error);
        }
        self.record = next;
        Ok(())
    }
}

fn valid_name(slot: TunnelSlot, name: &str) -> bool {
    matches!(
        (slot, name),
        (TunnelSlot::A, "nlm-wga" | "nlm-awga") | (TunnelSlot::B, "nlm-wgb" | "nlm-awgb")
    )
}

fn validate_record(record: &BindingRecord, boot: &str) -> io::Result<()> {
    if record.boot != boot || record.bindings.len() > 2 {
        return Err(invalid());
    }
    for (position, binding) in record.bindings.iter().enumerate() {
        if binding.index == 0
            || !valid_name(binding.slot, &binding.name)
            || !(30000..=30255).contains(&binding.table)
            || !(10000..=10255).contains(&binding.priority)
            || record.bindings[..position].iter().any(|other| {
                other.slot == binding.slot
                    || other.index == binding.index
                    || other.name == binding.name
                    || other.table == binding.table
                    || other.priority == binding.priority
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn number(value: &serde_json::Value) -> io::Result<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).map_err(|_| invalid());
    }
    let text = value.as_str().ok_or_else(invalid)?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    text.parse().map_err(|_| invalid())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid_linux_member_bindings")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_contracts::RuntimeSlot;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 7,
            session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
            connection_generation: 2,
        }
    }
    fn directory() -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.tmp");
        fs::create_dir_all(&base).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("linux-bindings-")
            .tempdir_in(base)
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    fn open(root: &Path, fresh: bool) -> io::Result<BindingAllocator> {
        BindingAllocator::open_for_owner(
            root,
            scope(),
            "boot-one",
            unsafe { libc::geteuid() },
            fresh,
        )
    }
    fn empty() -> Occupancy {
        Occupancy::parse("[]", "[]", "[]", "[]").unwrap()
    }
    fn primary(owner: &mut BindingAllocator) -> Binding {
        owner
            .reserve(TunnelSlot::A, 11, "nlm-wga", &empty())
            .unwrap()
    }

    #[test]
    fn skips_occupied_resources_in_both_families_and_rule_only_tables() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let occupied = Occupancy::parse(
            r#"[{"dst":"default","table":30000},{"dst":"127.0.0.0/8"}]"#,
            r#"[{"table":"30001","dst":"::/0","multipath":[]}]"#,
            r#"[{"priority":10000,"table":30002},{"priority":0,"table":255}]"#,
            r#"[{"priority":"10001","table":254},{"priority":1234,"action":"blackhole"}]"#,
        )
        .unwrap();
        let a = owner
            .reserve(TunnelSlot::A, 11, "nlm-wga", &occupied)
            .unwrap();
        assert_eq!((a.table, a.priority), (30003, 10002));
        assert!(occupied.tables.contains(&254));
    }

    #[test]
    fn exhausted_tables_or_priorities_do_not_reserve_partial_binding() {
        for tables in [true, false] {
            let dir = directory();
            let mut owner = open(dir.path(), true).unwrap();
            let mut occupied = empty();
            if tables {
                occupied.tables.extend(30000..=30255);
            } else {
                occupied.priorities.extend(10000..=10255);
            }
            assert!(owner
                .reserve(TunnelSlot::A, 11, "nlm-wga", &occupied)
                .is_err());
            assert!(owner.bindings().is_empty());
            assert!(open(dir.path(), false).unwrap().bindings().is_empty());
        }
    }

    #[test]
    fn last_available_table_and_priority_are_usable() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let mut occupied = empty();
        occupied.tables.extend(30000..30255);
        occupied.priorities.extend(10000..10255);
        let a = owner
            .reserve(TunnelSlot::A, 11, "nlm-wga", &occupied)
            .unwrap();
        assert_eq!((a.table, a.priority), (30255, 10255));
    }

    #[test]
    fn malformed_json_or_unknown_table_is_error_not_absence() {
        for bad in [
            "",
            "[",
            "{}",
            "null",
            "[null]",
            "[2]",
            r#"[{"table":"main"}]"#,
            r#"[{"table":null}]"#,
            r#"[{"table":-1}]"#,
            r#"[{"table":1.5}]"#,
            r#"[{"table":4294967296}]"#,
            r#"[{"table":"+30000"}]"#,
            r#"[{"table":true}]"#,
        ] {
            assert!(Occupancy::parse(bad, "[]", "[]", "[]").is_err(), "{bad}");
            assert!(Occupancy::parse("[]", bad, "[]", "[]").is_err(), "{bad}");
        }
        for bad in [
            r#"[{}]"#,
            r#"[{"priority":null}]"#,
            r#"[{"priority":"local"}]"#,
            r#"[{"priority":-1}]"#,
            r#"[{"priority":1.5}]"#,
            r#"[{"priority":4294967296}]"#,
            r#"[{"priority":10000,"table":"custom"}]"#,
        ] {
            assert!(Occupancy::parse("[]", "[]", bad, "[]").is_err(), "{bad}");
            assert!(Occupancy::parse("[]", "[]", "[]", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn duplicate_occupancy_fields_cannot_hide_invalid_or_occupied_ids() {
        for bad in [
            r#"[{"table":"unknown","table":30000}]"#,
            r#"[{"table":30000,"table":254}]"#,
        ] {
            assert!(Occupancy::parse(bad, "[]", "[]", "[]").is_err());
        }
        assert!(
            Occupancy::parse("[]", "[]", r#"[{"priority":10000,"priority":123}]"#, "[]").is_err()
        );
    }

    #[test]
    fn failed_atomic_write_blocks_further_allocation_until_reopen() {
        // A non-root test process can make the private journal readable but
        // unwritable. Root bypasses DAC; the strict-mode failure test covers it.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let a = primary(&mut owner);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        assert!(owner
            .reserve(TunnelSlot::B, 12, "nlm-wgb", &empty())
            .is_err());
        assert!(owner.is_recovering());
        assert_eq!(owner.bindings(), &[a.clone()]);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(owner
            .reserve(TunnelSlot::B, 12, "nlm-wgb", &empty())
            .is_err());
        let mut recovered = open(dir.path(), false).unwrap();
        assert_eq!(recovered.bindings(), &[a.clone()]);
        recovered.release(&a).unwrap();
        assert!(open(dir.path(), true).is_ok());
    }

    #[test]
    fn wrong_scope_or_boot_cannot_reopen_or_start_fresh_even_if_empty() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let a = primary(&mut owner);
        for pending in [true, false] {
            if !pending {
                owner.release(&a).unwrap();
            }
            for fresh in [true, false] {
                let mut other = scope();
                other.connection_generation += 1;
                let uid = unsafe { libc::geteuid() };
                assert!(BindingAllocator::open_for_owner(
                    dir.path(),
                    other,
                    "boot-one",
                    uid,
                    fresh
                )
                .is_err());
                assert!(BindingAllocator::open_for_owner(
                    dir.path(),
                    scope(),
                    "boot-two",
                    uid,
                    fresh
                )
                .is_err());
            }
        }
    }

    #[test]
    fn persistence_failure_does_not_publish_assignment_or_lose_primary() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let a = primary(&mut owner);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(owner
            .reserve(TunnelSlot::B, 12, "nlm-wgb", &empty())
            .is_err());
        assert_eq!(owner.bindings(), &[a.clone()]);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(open(dir.path(), false).unwrap().bindings(), &[a]);
    }

    #[test]
    fn late_standby_keeps_primary_assignment_and_is_persisted_before_return() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let a = primary(&mut owner);
        let b = owner
            .reserve(TunnelSlot::B, 12, "nlm-awgb", &empty())
            .unwrap();
        assert_eq!((a.table, a.priority), (30000, 10000));
        assert_eq!((b.table, b.priority), (30001, 10001));
        assert_eq!(owner.bindings(), &[a.clone(), b.clone()]);
        let recovered = open(dir.path(), false).unwrap();
        assert_eq!(recovered.bindings(), &[a, b]);
        assert_eq!(
            fs::metadata(dir.path().join(STATE_FILE)).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn exact_reservation_is_idempotent_but_replacement_requires_release() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let a = primary(&mut owner);
        let mut occupied = empty();
        occupied.tables.insert(a.table);
        occupied.priorities.insert(a.priority);
        assert_eq!(
            owner
                .reserve(TunnelSlot::A, 11, "nlm-wga", &occupied)
                .unwrap(),
            a
        );
        assert!(owner
            .reserve(TunnelSlot::A, 19, "nlm-wga", &empty())
            .is_err());
        assert!(owner
            .reserve(TunnelSlot::A, 11, "nlm-awga", &empty())
            .is_err());
        owner.release(&a).unwrap();
        assert_eq!(
            owner
                .reserve(TunnelSlot::A, 19, "nlm-awga", &empty())
                .unwrap()
                .index,
            19
        );
    }

    #[test]
    fn recovery_is_cleanup_only_and_fresh_rejects_pending_bindings() {
        let dir = directory();
        let a = primary(&mut open(dir.path(), true).unwrap());
        assert!(open(dir.path(), true).is_err());
        let mut recovered = open(dir.path(), false).unwrap();
        assert!(recovered.is_recovering());
        assert_eq!(recovered.bindings(), &[a.clone()]);
        assert!(recovered
            .reserve(TunnelSlot::A, 11, "nlm-wga", &empty())
            .is_err());
        assert!(recovered
            .reserve(TunnelSlot::B, 12, "nlm-wgb", &empty())
            .is_err());
        recovered.release(&a).unwrap();
        assert!(recovered
            .reserve(TunnelSlot::A, 11, "nlm-wga", &empty())
            .is_err());
        drop(recovered);
        let mut fresh = open(dir.path(), true).unwrap();
        assert!(!fresh.is_recovering());
        primary(&mut fresh);
    }

    #[test]
    fn even_empty_reopen_cannot_allocate() {
        let dir = directory();
        let mut recovered = open(dir.path(), false).unwrap();
        assert!(recovered.is_recovering());
        assert!(recovered
            .reserve(TunnelSlot::A, 11, "nlm-wga", &empty())
            .is_err());
    }

    #[test]
    fn release_requires_every_field_of_the_exact_binding_and_is_durable() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let a = primary(&mut owner);
        let b = owner
            .reserve(TunnelSlot::B, 12, "nlm-wgb", &empty())
            .unwrap();
        for field in 0..5 {
            let mut wrong = a.clone();
            match field {
                0 => wrong.slot = TunnelSlot::B,
                1 => wrong.index += 1,
                2 => wrong.name = "nlm-awga".into(),
                3 => wrong.table += 1,
                _ => wrong.priority += 1,
            }
            assert!(owner.release(&wrong).is_err());
            assert_eq!(owner.bindings(), &[a.clone(), b.clone()]);
        }
        owner.release(&a).unwrap();
        assert_eq!(open(dir.path(), false).unwrap().bindings(), &[b]);
        assert!(owner.release(&a).is_err());
    }

    #[test]
    fn release_save_failure_retains_binding() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        let a = primary(&mut owner);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(owner.release(&a).is_err());
        assert_eq!(owner.bindings(), &[a.clone()]);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(open(dir.path(), false).unwrap().bindings(), &[a]);
    }

    #[test]
    fn rejects_uncaptured_duplicate_or_wrong_slot_identities() {
        let dir = directory();
        let mut owner = open(dir.path(), true).unwrap();
        for (index, name) in [
            (0, "nlm-wga"),
            (11, "eth0"),
            (11, "nlm-wgb"),
            (11, "nlm-wg0"),
            (11, "../nlm-wga"),
        ] {
            assert!(owner.reserve(TunnelSlot::A, index, name, &empty()).is_err());
        }
        let a = primary(&mut owner);
        assert!(owner
            .reserve(TunnelSlot::B, 11, "nlm-wgb", &empty())
            .is_err());
        assert!(owner
            .reserve(TunnelSlot::B, 12, "nlm-wga", &empty())
            .is_err());
        assert_eq!(owner.bindings(), &[a]);
    }

    #[test]
    fn rejects_corrupt_or_conflicting_saved_bindings() {
        for field in 0..7 {
            let dir = directory();
            let mut owner = open(dir.path(), true).unwrap();
            let a = primary(&mut owner);
            let b = owner
                .reserve(TunnelSlot::B, 12, "nlm-wgb", &empty())
                .unwrap();
            let mut record = BindingRecord {
                boot: "boot-one".into(),
                bindings: vec![a.clone(), b],
            };
            match field {
                0 => record.bindings.push(a),
                1 => record.bindings[1].table = 30000,
                2 => record.bindings[1].priority = 10000,
                3 => record.bindings[1].index = 11,
                4 => record.bindings[1].name = "nlm-wga".into(),
                5 => record.bindings[0].table = 254,
                _ => record.bindings[0].priority = 32766,
            }
            owner.store.save_state(&record).unwrap();
            assert!(open(dir.path(), false).is_err());
        }
    }
}
