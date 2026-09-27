//! Private IPv4 DNS-server adapter for an already-owned member interface.
//!
//! IPv6 DNS-server configuration is NOT implemented. This has no bearing on IPv6
//! data routes/traffic. Nothing here changes routes or global/physical DNS.
//! The enclosing owner must durably journal the baseline, expected and desired
//! snapshots BEFORE apply, and serialize its lifecycle/writes. Windows offers no
//! atomic DNS compare-exchange: another writer can race the final read and write.
//! Identity checks detect observed replacement, not a kernel identity lock.
//! On Indeterminate, retain the journal and reread; never blindly roll back.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.

use nelomai_client_tunnel::redundancy::SessionScope;
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};

pub(crate) const MAX_STRING_UNITS: usize = 4096;
const NAMESERVER: u64 = 2;
// Version1 fields that can be exactly retained. IPV6, HOSTNAME (no matching
// Version1 member), profile DNS, DoH/DDR and future flags are unsupported.
const SUPPORTED_FLAGS: u64 = 0x1be;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedInterface {
    pub scope: SessionScope,
    /// GUID in canonical/network byte order, not Windows struct memory order.
    pub guid: [u8; 16],
    pub luid: u64,
    pub index: u32,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub version: u32,
    pub flags: u64,
    pub domain: Option<String>,
    pub name_server: Option<String>,
    pub search_list: Option<String>,
    pub registration_enabled: u32,
    pub register_adapter_name: u32,
    pub enable_llmnr: u32,
    pub query_adapter_name: u32,
    pub profile_name_server: Option<String>,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Settings(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub interface: OwnedInterface,
    pub settings: Settings,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ownership {
    #[cfg(test)] // Negative ownership evidence injected by the policy tests.
    Existing,
    /// The injected owner attests this exact interface was newly created by this
    /// scope and its empty baseline belongs to it, including during restoration.
    NewlyCreated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DnsError {
    #[error("member_dns_invalid")]
    Invalid,
    #[error("member_dns_ipv6_servers_unsupported")]
    Ipv6Unsupported,
    #[error("member_dns_unsupported_settings")]
    Unsupported,
    #[error("member_dns_ownership_conflict")]
    Ownership,
    #[error("member_dns_compare_conflict")]
    Conflict,
    #[error("member_dns_native_status_{0}")]
    Native(u32),
    #[error("member_dns_write_outcome_indeterminate")]
    Indeterminate,
}
pub(crate) type Result<T> = std::result::Result<T, DnsError>;

pub(crate) trait Identity {
    /// MUST attest member ownership from the owner's retained/journaled identity,
    /// not merely existence or a matching interface name. Never attest a physical
    /// interface. Native GUID/LUID/index mapping is checked separately.
    fn verify_owned(&mut self, interface: &OwnedInterface) -> Result<Ownership>;
}

/// Low-level seam; use only through OwnedDns, never as an ownership bypass.
pub(crate) trait DnsIo {
    fn verify_mapping(&mut self, interface: &OwnedInterface) -> Result<()>;
    fn read(&mut self, interface: &OwnedInterface) -> Result<Settings>;
    fn write_nameserver(&mut self, interface: &OwnedInterface, value: Option<&str>) -> Result<()>;
}

pub(crate) struct OwnedDns<I, A> {
    interface: OwnedInterface,
    identity: I,
    io: A,
}

impl Snapshot {
    /// Build a journalable desired value without IO. To restore an empty owned
    /// baseline, pass the original journaled Snapshot, not an empty server list.
    pub(crate) fn with_servers(&self, servers: &[IpAddr]) -> Result<Self> {
        validate_interface(&self.interface)?;
        self.settings.validate(Ownership::NewlyCreated)?;
        if servers.iter().any(IpAddr::is_ipv6) {
            return Err(DnsError::Ipv6Unsupported);
        }
        if servers.is_empty() || servers.len() > 16 {
            return Err(DnsError::Invalid);
        }
        let text = servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        validate_servers(&text)?;
        let mut desired = self.clone();
        desired.settings.name_server = Some(text);
        desired.settings.flags |= NAMESERVER;
        Ok(desired)
    }
}

impl<I: Identity, A: DnsIo> OwnedDns<I, A> {
    pub(crate) fn new(interface: OwnedInterface, identity: I, io: A) -> Result<Self> {
        validate_interface(&interface)?;
        Ok(Self {
            interface,
            identity,
            io,
        })
    }

    pub(crate) fn snapshot(&mut self) -> Result<Snapshot> {
        self.read_checked().map(|(snapshot, _)| snapshot)
    }

    /// Exact compare, single NameServer-only write, exact readback. NOT atomic
    /// against external writers. Any error after attempting Set is Indeterminate.
    pub(crate) fn compare_exchange(
        &mut self,
        expected: &Snapshot,
        desired: &Snapshot,
    ) -> Result<Snapshot> {
        if expected.interface != self.interface || desired.interface != self.interface {
            return Err(DnsError::Ownership);
        }
        expected.settings.validate(Ownership::NewlyCreated)?;
        desired.settings.validate(Ownership::NewlyCreated)?;
        let mut allowed = expected.settings.clone();
        allowed.name_server = desired.settings.name_server.clone();
        allowed.flags = (allowed.flags & !NAMESERVER) | (desired.settings.flags & NAMESERVER);
        if allowed != desired.settings {
            return Err(DnsError::Unsupported);
        }
        let (current, ownership) = self.read_checked()?;
        if &current != expected {
            return Err(DnsError::Conflict);
        }
        desired.settings.validate(ownership)?;
        if expected == desired {
            return Ok(current);
        }
        if self.verify()? != ownership {
            return Err(DnsError::Ownership);
        }
        let write = self
            .io
            .write_nameserver(&self.interface, desired.settings.name_server.as_deref());
        // Revalidate even when Set reports failure: it may have taken effect.
        let after = self.verify();
        if write.is_err() || after != Ok(ownership) {
            return Err(DnsError::Indeterminate);
        }
        let (readback, readback_owner) =
            self.read_checked().map_err(|_| DnsError::Indeterminate)?;
        if &readback != desired || readback_owner != ownership {
            return Err(DnsError::Indeterminate);
        }
        Ok(readback)
    }

    fn verify(&mut self) -> Result<Ownership> {
        let ownership = self.identity.verify_owned(&self.interface)?;
        self.io.verify_mapping(&self.interface)?;
        Ok(ownership)
    }

    fn read_checked(&mut self) -> Result<(Snapshot, Ownership)> {
        let before = self.verify()?;
        let read = self.io.read(&self.interface);
        let after = self.verify()?;
        if before != after {
            return Err(DnsError::Ownership);
        }
        let settings = read?;
        settings.validate(before)?;
        Ok((
            Snapshot {
                interface: self.interface.clone(),
                settings,
            },
            before,
        ))
    }
}

fn validate_interface(interface: &OwnedInterface) -> Result<()> {
    if interface.index == 0
        || interface.luid == 0
        || interface.guid == [0; 16]
        || !interface.scope.validate()
    {
        return Err(DnsError::Invalid);
    }
    Ok(())
}

impl Settings {
    fn validate(&self, ownership: Ownership) -> Result<()> {
        if self.version != 1
            || self.flags & !SUPPORTED_FLAGS != 0
            || self
                .profile_name_server
                .as_ref()
                .is_some_and(|s| !s.is_empty())
            || [
                self.registration_enabled,
                self.register_adapter_name,
                self.enable_llmnr,
                self.query_adapter_name,
            ]
            .iter()
            .any(|v| *v > 1)
        {
            return Err(DnsError::Unsupported);
        }
        for text in [
            &self.domain,
            &self.name_server,
            &self.search_list,
            &self.profile_name_server,
        ]
        .into_iter()
        .flatten()
        {
            if text.contains('\0') || text.encode_utf16().count() > MAX_STRING_UNITS {
                return Err(DnsError::Unsupported);
            }
        }
        match self.name_server.as_deref() {
            None | Some("") if ownership == Ownership::NewlyCreated => Ok(()),
            None | Some("") => Err(DnsError::Unsupported),
            Some(text) => {
                validate_servers(text)?;
                if self.flags & NAMESERVER == 0 {
                    return Err(DnsError::Unsupported);
                }
                Ok(())
            }
        }
    }
}

fn validate_servers(text: &str) -> Result<()> {
    let mut seen = Vec::new();
    for group in text.split(',') {
        if group.trim_matches(' ').is_empty() {
            return Err(DnsError::Invalid);
        }
        for token in group.split(' ').filter(|s| !s.is_empty()) {
            let address = token.parse::<IpAddr>().map_err(|_| DnsError::Invalid)?;
            let IpAddr::V4(address) = address else {
                return Err(DnsError::Ipv6Unsupported);
            };
            if address.is_unspecified()
                || address.is_multicast()
                || address.is_broadcast()
                || address.to_string() != token
                || seen.contains(&address)
                || seen.len() == 16
            {
                return Err(DnsError::Invalid);
            }
            seen.push(address);
        }
    }
    if seen.is_empty() {
        return Err(DnsError::Invalid);
    }
    Ok(())
}

/// Native pointer access stays in the Windows module; decoding/bounds are shared
/// with fake-only tests. At most MAX_STRING_UNITS content units plus one NUL.
pub(crate) fn decode_wide(mut unit: impl FnMut(usize) -> u16) -> Result<String> {
    let mut units = Vec::new();
    for offset in 0..=MAX_STRING_UNITS {
        let value = unit(offset);
        if value == 0 {
            return String::from_utf16(&units).map_err(|_| DnsError::Unsupported);
        }
        if offset == MAX_STRING_UNITS {
            break;
        }
        units.push(value);
    }
    Err(DnsError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_contracts::RuntimeSlot;
    use std::{cell::RefCell, rc::Rc};

    fn interface() -> OwnedInterface {
        OwnedInterface {
            scope: SessionScope {
                runtime: RuntimeSlot::Stable,
                runtime_generation: 1,
                session_id: "11111111-1111-1111-1111-111111111111".into(),
                connection_generation: 7,
            },
            guid: [9; 16],
            luid: 100,
            index: 42,
        }
    }

    fn settings() -> Settings {
        Settings {
            version: 1,
            flags: 0x1be,
            domain: Some("private.invalid".into()),
            name_server: Some("9.9.9.9,149.112.112.112".into()),
            search_list: Some("one.invalid two.invalid".into()),
            registration_enabled: 0,
            register_adapter_name: 1,
            enable_llmnr: 0,
            query_adapter_name: 1,
            profile_name_server: None,
        }
    }

    fn snap() -> Snapshot {
        Snapshot {
            interface: interface(),
            settings: settings(),
        }
    }

    // Only the native boundary is fake: the adapter's validation, comparison,
    // ordering and uncertainty handling are exercised unchanged.
    struct State {
        settings: Settings,
        events: Vec<&'static str>,
        checks: usize,
        fail_check: Option<usize>,
        fail_mapping: Option<usize>,
        ownership: Ownership,
        read_error: bool,
        write_error: bool,
        foreign_readback: bool,
        after_write: Option<fn(&mut Settings)>,
        readback_error: bool,
        writes: usize,
    }
    type Shared = Rc<RefCell<State>>;
    struct Owner(Shared);
    struct Api(Shared);
    impl Identity for Owner {
        fn verify_owned(&mut self, target: &OwnedInterface) -> Result<Ownership> {
            assert_eq!(target, &interface());
            let mut s = self.0.borrow_mut();
            s.events.push("owner");
            s.checks += 1;
            if s.fail_check == Some(s.checks) {
                return Err(DnsError::Ownership);
            }
            Ok(s.ownership)
        }
    }
    impl DnsIo for Api {
        fn verify_mapping(&mut self, target: &OwnedInterface) -> Result<()> {
            assert_eq!(target, &interface());
            let mut s = self.0.borrow_mut();
            s.events.push("mapping");
            if s.fail_mapping == Some(s.checks) {
                return Err(DnsError::Ownership);
            }
            Ok(())
        }
        fn read(&mut self, target: &OwnedInterface) -> Result<Settings> {
            assert_eq!(target, &interface());
            let mut s = self.0.borrow_mut();
            s.events.push("read");
            if s.read_error || s.readback_error && s.writes > 0 {
                return Err(DnsError::Native(5));
            }
            Ok(s.settings.clone())
        }
        fn write_nameserver(&mut self, target: &OwnedInterface, value: Option<&str>) -> Result<()> {
            assert_eq!(target, &interface());
            let mut s = self.0.borrow_mut();
            s.events.push("write");
            s.writes += 1;
            s.settings.name_server = value.map(str::to_owned);
            if value.is_some_and(|v| !v.is_empty()) {
                s.settings.flags |= 2;
            } else {
                s.settings.flags &= !2;
            }
            if s.foreign_readback {
                s.settings.search_list = Some("foreign.invalid".into());
            }
            if let Some(mutate) = s.after_write {
                mutate(&mut s.settings);
            }
            if s.write_error {
                return Err(DnsError::Native(5));
            }
            Ok(())
        }
    }
    fn adapter() -> (OwnedDns<Owner, Api>, Shared) {
        let s = Rc::new(RefCell::new(State {
            settings: settings(),
            events: vec![],
            checks: 0,
            fail_check: None,
            fail_mapping: None,
            ownership: Ownership::Existing,
            read_error: false,
            write_error: false,
            foreign_readback: false,
            after_write: None,
            readback_error: false,
            writes: 0,
        }));
        (
            OwnedDns::new(interface(), Owner(s.clone()), Api(s.clone())).unwrap(),
            s,
        )
    }

    #[test]
    fn snapshot_retains_all_metadata_and_null_vs_empty_for_journal() {
        let (mut adapter, s) = adapter();
        let value = adapter.snapshot().unwrap();
        assert_eq!(value, snap());
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<Snapshot>(&json).unwrap(), value);
        assert_eq!(
            s.borrow().events,
            ["owner", "mapping", "read", "owner", "mapping"]
        );
    }

    #[test]
    fn canonical_servers_are_bounded_and_ipv6_is_never_dropped() {
        let before = snap();
        let after = before
            .with_servers(&["77.88.8.8".parse().unwrap(), "9.9.9.9".parse().unwrap()])
            .unwrap();
        assert_eq!(
            after.settings.name_server.as_deref(),
            Some("77.88.8.8,9.9.9.9")
        );
        assert_eq!(
            before.with_servers(&[
                "9.9.9.9".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap()
            ]),
            Err(DnsError::Ipv6Unsupported)
        );
        let sixteen: Vec<_> = (1..=16).map(|n| IpAddr::from([10, 0, 0, n])).collect();
        assert!(before.with_servers(&sixteen).is_ok());
        let seventeen: Vec<_> = (1..=17).map(|n| IpAddr::from([10, 0, 0, n])).collect();
        assert_eq!(before.with_servers(&seventeen), Err(DnsError::Invalid));
        for bad in ["0.0.0.0", "224.0.0.1", "255.255.255.255"] {
            assert_eq!(
                before.with_servers(&[bad.parse().unwrap()]),
                Err(DnsError::Invalid)
            );
        }
        assert_eq!(before.with_servers(&[]), Err(DnsError::Invalid));
    }

    #[test]
    fn replace_preserves_metadata_and_checks_identity_around_every_operation() {
        let (mut adapter, s) = adapter();
        let before = snap();
        let mut after = before.clone();
        after.settings.name_server = Some("77.88.8.8".into());
        assert_eq!(adapter.compare_exchange(&before, &after).unwrap(), after);
        assert_eq!(s.borrow().settings, after.settings);
        assert_eq!(
            s.borrow().events,
            [
                "owner", "mapping", "read", "owner", "mapping", "owner", "mapping", "write",
                "owner", "mapping", "owner", "mapping", "read", "owner", "mapping",
            ]
        );
    }

    #[test]
    fn foreign_replacement_of_any_snapshot_field_prevents_write() {
        let mutations: &[fn(&mut Settings)] = &[
            |s| s.version = 2,
            |s| s.flags ^= 8,
            |s| s.domain = Some("other.invalid".into()),
            |s| s.name_server = Some("1.1.1.1".into()),
            |s| s.search_list = None,
            |s| s.registration_enabled = 1,
            |s| s.register_adapter_name = 0,
            |s| s.enable_llmnr = 1,
            |s| s.query_adapter_name = 0,
            |s| s.profile_name_server = Some("1.1.1.1".into()),
        ];
        for mutate in mutations {
            let (mut adapter, s) = adapter();
            mutate(&mut s.borrow_mut().settings);
            let foreign = s.borrow().settings.clone();
            let mut after = snap();
            after.settings.name_server = Some("77.88.8.8".into());
            assert!(adapter.compare_exchange(&snap(), &after).is_err());
            assert_eq!(s.borrow().writes, 0);
            assert_eq!(s.borrow().settings, foreign);
        }
    }

    #[test]
    fn empty_baseline_requires_attested_new_owned_interface_and_can_be_restored() {
        for empty in [None, Some(String::new())] {
            let (mut adapter, s) = adapter();
            s.borrow_mut().settings.name_server = empty.clone();
            s.borrow_mut().settings.flags &= !2;
            assert_eq!(adapter.snapshot(), Err(DnsError::Unsupported));
            s.borrow_mut().ownership = Ownership::NewlyCreated;
            let baseline = adapter.snapshot().unwrap();
            let current = baseline
                .with_servers(&["9.9.9.9".parse().unwrap()])
                .unwrap();
            adapter.compare_exchange(&baseline, &current).unwrap();
            adapter.compare_exchange(&current, &baseline).unwrap();
            assert_eq!(adapter.snapshot().unwrap(), baseline);
            assert_eq!(s.borrow().writes, 2);
        }
    }

    #[test]
    fn unsupported_flags_profiles_strings_and_nameserver_states_are_rejected() {
        let mutations: &[fn(&mut Settings)] = &[
            |s| s.flags |= 1,
            |s| s.flags |= 0x400,
            |s| s.flags |= 0x200,
            |s| s.flags |= 0x40,
            |s| s.flags |= 1 << 63,
            |s| s.profile_name_server = Some("9.9.9.9".into()),
            |s| s.name_server = Some("::1".into()),
            |s| s.name_server = Some("resolver.invalid".into()),
            |s| s.name_server = Some("9.9.9.9,,1.1.1.1".into()),
            |s| s.name_server = Some("9.9.9.9;1.1.1.1".into()),
            |s| s.flags &= !2,
            |s| s.domain = Some("x".repeat(4097)),
            |s| s.search_list = Some("a\0b".into()),
            |s| s.registration_enabled = 2,
        ];
        for mutate in mutations {
            let (mut adapter, s) = adapter();
            mutate(&mut s.borrow_mut().settings);
            assert!(adapter.snapshot().is_err());
            assert_eq!(s.borrow().writes, 0);
        }
    }

    #[test]
    fn wrong_scope_or_unrelated_desired_change_never_reaches_io() {
        let (mut adapter, s) = adapter();
        let mut wrong = snap();
        wrong.interface.scope.connection_generation += 1;
        assert_eq!(
            adapter.compare_exchange(&wrong, &wrong),
            Err(DnsError::Ownership)
        );
        let mut changed = snap();
        changed.settings.domain = None;
        assert_eq!(
            adapter.compare_exchange(&snap(), &changed),
            Err(DnsError::Unsupported)
        );
        assert!(s.borrow().events.is_empty());
    }

    #[test]
    fn identity_loss_before_write_is_clean_and_after_write_is_indeterminate() {
        for check in 1..=6 {
            let (mut adapter, s) = adapter();
            s.borrow_mut().fail_check = Some(check);
            let mut after = snap();
            after.settings.name_server = Some("77.88.8.8".into());
            let error = if check <= 3 {
                DnsError::Ownership
            } else {
                DnsError::Indeterminate
            };
            assert_eq!(adapter.compare_exchange(&snap(), &after), Err(error));
            assert_eq!(s.borrow().writes, usize::from(check > 3));
        }
    }

    #[test]
    fn failed_read_still_revalidates_identity_and_never_writes() {
        let (mut adapter, s) = adapter();
        s.borrow_mut().read_error = true;
        assert_eq!(adapter.snapshot(), Err(DnsError::Native(5)));
        assert_eq!(s.borrow().checks, 2);
        assert_eq!(s.borrow().writes, 0);
    }

    #[test]
    fn failed_write_or_foreign_readback_never_triggers_blind_rollback() {
        for fail_write in [false, true] {
            let (mut adapter, s) = adapter();
            s.borrow_mut().write_error = fail_write;
            s.borrow_mut().foreign_readback = !fail_write;
            let mut after = snap();
            after.settings.name_server = Some("77.88.8.8".into());
            assert_eq!(
                adapter.compare_exchange(&snap(), &after),
                Err(DnsError::Indeterminate)
            );
            assert_eq!(s.borrow().writes, 1);
            assert_eq!(
                s.borrow().settings.name_server.as_deref(),
                Some("77.88.8.8")
            );
            assert!(s.borrow().checks >= 4);
        }
    }

    #[test]
    fn invalid_interface_is_rejected_without_native_calls() {
        let mutations: &[fn(&mut OwnedInterface)] = &[
            |i| i.index = 0,
            |i| i.luid = 0,
            |i| i.guid = [0; 16],
            |i| i.scope.connection_generation = 0,
        ];
        for mutate in mutations {
            let (_, s) = adapter();
            let mut target = interface();
            mutate(&mut target);
            assert!(matches!(
                OwnedDns::new(target, Owner(s.clone()), Api(s.clone())),
                Err(DnsError::Invalid)
            ));
            assert!(s.borrow().events.is_empty());
        }
    }

    #[test]
    fn bounded_wide_reader_accepts_exact_limit_and_rejects_invalid_utf16() {
        let mut reads = 0;
        let text = decode_wide(|i| {
            reads += 1;
            if i == 4096 {
                0
            } else {
                120
            }
        })
        .unwrap();
        assert_eq!(text, "x".repeat(4096));
        assert_eq!(reads, 4097);
        let mut reads = 0;
        assert_eq!(
            decode_wide(|_| {
                reads += 1;
                120
            }),
            Err(DnsError::Unsupported)
        );
        assert_eq!(reads, 4097);
        assert_eq!(decode_wide(|i| [0xd800, 0][i]), Err(DnsError::Unsupported));
        assert_eq!(
            decode_wide(|i| [0x0061, 0xd83d, 0xde00, 0][i]).unwrap(),
            "a😀"
        );
    }

    #[test]
    fn debug_does_not_expose_snapshot_strings() {
        let rendered = format!("{:?}", snap());
        assert!(!rendered.contains("private.invalid"));
        assert!(!rendered.contains("9.9.9.9"));
    }

    #[test]
    fn native_mapping_loss_is_checked_before_and_after_each_io() {
        for check in 1..=6 {
            let (mut adapter, s) = adapter();
            s.borrow_mut().fail_mapping = Some(check);
            let mut after = snap();
            after.settings.name_server = Some("77.88.8.8".into());
            let error = if check <= 3 {
                DnsError::Ownership
            } else {
                DnsError::Indeterminate
            };
            assert_eq!(adapter.compare_exchange(&snap(), &after), Err(error));
            assert_eq!(s.borrow().writes, usize::from(check > 3));
        }
    }

    #[test]
    fn readback_compares_every_field_including_profile_and_policy_flags() {
        let mutations: &[fn(&mut Settings)] = &[
            |s| s.version = 2,
            |s| s.flags ^= 8,
            |s| s.domain = Some("foreign.invalid".into()),
            |s| s.name_server = Some("1.1.1.1".into()),
            |s| s.search_list = None,
            |s| s.registration_enabled = 1,
            |s| s.register_adapter_name = 0,
            |s| s.enable_llmnr = 1,
            |s| s.query_adapter_name = 0,
            |s| s.profile_name_server = Some("1.1.1.1".into()),
        ];
        for mutate in mutations {
            let (mut adapter, s) = adapter();
            s.borrow_mut().after_write = Some(*mutate);
            let mut after = snap();
            after.settings.name_server = Some("77.88.8.8".into());
            assert_eq!(
                adapter.compare_exchange(&snap(), &after),
                Err(DnsError::Indeterminate)
            );
            assert_eq!(s.borrow().writes, 1);
        }
    }

    #[test]
    fn failed_readback_is_indeterminate_and_noop_cas_still_checks_fresh_snapshot() {
        let (mut adapter, s) = adapter();
        assert_eq!(adapter.compare_exchange(&snap(), &snap()).unwrap(), snap());
        assert_eq!(s.borrow().writes, 0);
        assert_eq!(s.borrow().checks, 2);
        s.borrow_mut().readback_error = true;
        let mut after = snap();
        after.settings.name_server = Some("77.88.8.8".into());
        assert_eq!(
            adapter.compare_exchange(&snap(), &after),
            Err(DnsError::Indeterminate)
        );
        assert_eq!(s.borrow().writes, 1);
    }
}
