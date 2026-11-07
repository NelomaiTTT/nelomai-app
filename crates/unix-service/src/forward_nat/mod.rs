//! IPv4 NAT for already-forwarded virtual networks; never enables LAN routing.
use crate::member_network::journal::ScopedJournal;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::RuntimeSlot;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[cfg(any(target_os = "linux", test))]
pub(crate) mod linux;
#[cfg(any(target_os = "macos", test))]
pub(crate) mod macos;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Egress {
    pub name: String,
    pub index: u32,
    pub address: Ipv4Addr,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub name: String,
    pub index: u32,
    pub network: String,
    pub host_address: Ipv4Addr,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub egress: Egress,
    pub sources: Vec<Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mss: Option<u16>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Presence {
    Absent,
    Exact,
    // PF can retain an owned subset; nftables applies the whole batch atomically.
    #[cfg_attr(all(target_os = "linux", not(test)), allow(dead_code))]
    OwnedPartial,
    Conflict,
}

pub(crate) trait System {
    fn begin_operation(&mut self) {}
    fn discover(&mut self, name: &str, index: u32) -> io::Result<Option<Plan>>;
    fn inspect(&mut self, token: &str, expected: &Plan) -> io::Result<Presence>;
    /// Compare the complete owned ruleset before replacing it; never adopt.
    fn replace(
        &mut self,
        token: &str,
        before: Option<&Plan>,
        after: Option<&Plan>,
    ) -> io::Result<()>;
}
pub(crate) trait Commands {
    fn begin_operation(&mut self) {}
    fn run(&mut self, program: &str, args: &[String], input: Option<&str>) -> io::Result<String>;
}
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
pub(crate) fn valid_token(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub(crate) fn validate_plan(plan: &Plan) -> bool {
    if !valid_name(&plan.egress.name)
        || !valid_index(plan.egress.index)
        || !usable_address(plan.egress.address)
        || plan.sources.is_empty()
        || plan.sources.len() > 16
        || plan
            .max_mss
            .is_some_and(|mss| !(536..=65495).contains(&mss))
    {
        return false;
    }
    let mut networks = Vec::new();
    for source in &plan.sources {
        let Ok(network) = source.network.parse::<ipnet::Ipv4Net>() else {
            return false;
        };
        if !valid_name(&source.name)
            || !valid_index(source.index)
            || source.name == plan.egress.name
            || source.index == plan.egress.index
            || network.trunc().to_string() != source.network
            || network.prefix_len() > 30
            || !network.network().is_private()
            || !network.broadcast().is_private()
            || !network.contains(&source.host_address)
            || source.host_address == network.network()
            || source.host_address == network.broadcast()
            || network.contains(&plan.egress.address)
        {
            return false;
        }
        // A native index has one name, and a name has one native index. Multiple
        // disjoint IPv4 subnets on the same verified interface remain possible.
        if plan
            .sources
            .iter()
            .any(|other| (source.name == other.name) != (source.index == other.index))
            || networks.iter().any(|other: &ipnet::Ipv4Net| {
                other.contains(&network.network()) || network.contains(&other.network())
            })
        {
            return false;
        }
        networks.push(network);
    }
    true
}

fn valid_index(index: u32) -> bool {
    index > 0 && index <= i32::MAX as u32
}
fn usable_address(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
        && address.octets()[0] != 0
}
fn normalized(mut plan: Plan) -> io::Result<Plan> {
    if !validate_plan(&plan) {
        return Err(invalid());
    }
    plan.sources.sort_by(|a, b| {
        (&a.name, a.index, &a.network, a.host_address).cmp(&(
            &b.name,
            b.index,
            &b.network,
            b.host_address,
        ))
    });
    Ok(plan)
}
fn valid_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid_forward_nat_state")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    before: Option<Plan>,
    after: Option<Plan>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    boot: String,
    token: String,
    committed: Option<Plan>,
    pending: Option<Pending>,
}
impl Record {
    fn valid(&self) -> bool {
        let valid = |plan: &Plan| normalized(plan.clone()).is_ok_and(|p| &p == plan);
        valid_boot(&self.boot)
            && valid_token(&self.token)
            && self.committed.as_ref().is_none_or(valid)
            && self.pending.as_ref().is_none_or(|pending| {
                pending.before == self.committed
                    && pending.before != pending.after
                    && pending.before.as_ref().is_none_or(valid)
                    && pending.after.as_ref().is_none_or(valid)
            })
    }
    fn has_resources(&self) -> bool {
        self.committed.is_some() || self.pending.is_some()
    }
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Default)]
pub(crate) struct NativeCommands {
    deadline: Option<Instant>,
}
impl Commands for NativeCommands {
    fn begin_operation(&mut self) {
        self.deadline = Some(Instant::now() + Duration::from_secs(1));
    }
    fn run(&mut self, program: &str, args: &[String], input: Option<&str>) -> io::Result<String> {
        let stdin = match input {
            Some(input) => Stdio::from(prepared_input(input.as_bytes())?),
            None => Stdio::null(),
        };
        let remaining = self
            .deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_secs(1));
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "forward_nat_operation_timed_out",
            ));
        }
        let output = crate::process::output_with_timeout(
            Command::new(program).args(args).stdin(stdin),
            remaining.min(Duration::from_secs(1)),
        )?;
        if !output.status.success() {
            // Native stderr can contain routes or addresses; never expose it as
            // a service error, and never interpret partial stdout as success.
            return Err(io::Error::other("forward_nat_command_failed"));
        }
        String::from_utf8(output.stdout).map_err(|_| invalid())
    }
}

fn prepared_input(input: &[u8]) -> io::Result<File> {
    if input.len() > 4096 {
        return Err(invalid());
    }
    let mut descriptors = [-1; 2];
    #[cfg(target_os = "linux")]
    let result = unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    let result = unsafe { libc::pipe(descriptors.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // Own both ends before any fallible operation, including fcntl on macOS.
    let read = unsafe { File::from_raw_fd(descriptors[0]) };
    let mut write = unsafe { File::from_raw_fd(descriptors[1]) };
    for descriptor in [read.as_raw_fd(), write.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let flags = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // Prefill before spawning. Nonblocking mode proves this exact bounded
    // input fits the pipe; capacity failure returns without launching a child.
    write.write_all(input)?;
    drop(write);
    Ok(read)
}

pub(crate) struct Owner<S: System> {
    system: S,
    file: ScopedJournal<Record>,
    root: PathBuf,
    uid: u32,
    record: Record,
    recovering: bool,
}
impl<S: System> Owner<S> {
    pub(crate) fn open(root: &Path, boot: &str, uid: u32, system: S) -> io::Result<Self> {
        if !valid_boot(boot) {
            return Err(invalid());
        }
        validate_root(root, uid)?;
        let private = root.join("forward-nat");
        match fs::DirBuilder::new().mode(0o700).create(&private) {
            Ok(()) => File::open(root)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
        validate_private(&private, uid)?;
        // The enclosing ordinary/member runtime root isolates this namespace;
        // the boot seal separately fences ephemeral native interface indices.
        let scope = SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 1,
            session_id: "00000000-0000-4000-8000-000000000001".into(),
            connection_generation: 1,
        };
        let mut file = ScopedJournal::open_named(&private, scope, uid, "forward-nat.json")?;
        let saved: Option<Record> = file.load()?;
        if saved.as_ref().is_some_and(|saved| !saved.valid()) {
            return Err(invalid());
        }
        let record = match saved {
            Some(saved) if saved.boot.eq_ignore_ascii_case(boot) => saved,
            old => {
                let fresh = Record {
                    boot: boot.into(),
                    token: random_token()?,
                    committed: None,
                    pending: None,
                };
                if old.is_some() {
                    // Kernel rules are ephemeral across boots. Never replay an
                    // old index into native inspection or deletion.
                    file.save_state(&fresh)?;
                }
                fresh
            }
        };
        let recovering = record.has_resources();
        Ok(Self {
            system,
            file,
            root: root.into(),
            uid,
            record,
            recovering,
        })
    }
    pub(crate) fn refresh(&mut self, name: &str, index: u32) -> io::Result<()> {
        self.validate_storage()?;
        self.system.begin_operation();
        if self.is_recovering() {
            return Err(io::Error::other("forward_nat_cleanup_pending"));
        }
        if !valid_name(name) || !valid_index(index) {
            return Err(invalid());
        }
        let after = self
            .system
            .discover(name, index)?
            .map(normalized)
            .transpose()?;
        if after
            .as_ref()
            .is_some_and(|plan| plan.egress.name != name || plan.egress.index != index)
        {
            return Err(invalid());
        }
        if after == self.record.committed {
            if let Some(plan) = after {
                if self.system.inspect(&self.record.token, &plan)? != Presence::Exact {
                    return Err(io::Error::other("forward_nat_native_drift"));
                }
            }
            return Ok(());
        }
        if after.is_none() {
            return self.cleanup();
        }
        let before = self.record.committed.clone();
        let mut intent = self.record.clone();
        if before.is_none() {
            intent.token = random_token()?;
        }
        intent.pending = Some(Pending {
            before: before.clone(),
            after: after.clone(),
        });
        self.persist(intent)?;
        self.system
            .replace(&self.record.token, before.as_ref(), after.as_ref())?;
        if self
            .system
            .inspect(&self.record.token, after.as_ref().expect("new plan"))?
            != Presence::Exact
        {
            return Err(io::Error::other("forward_nat_readback_failed"));
        }
        let mut committed = self.record.clone();
        committed.committed = after;
        committed.pending = None;
        self.persist(committed)
    }
    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        self.validate_storage()?;
        self.system.begin_operation();
        if !self.has_resources() {
            self.recovering = false;
            return Ok(());
        }
        if self.record.pending.is_none() {
            let mut intent = self.record.clone();
            intent.pending = Some(Pending {
                before: intent.committed.clone(),
                after: None,
            });
            self.persist(intent)?;
        }
        let pending = self
            .record
            .pending
            .as_ref()
            .expect("cleanup intent")
            .clone();
        let mut matched = None;
        let mut absent = false;
        // A failed mutation can leave either complete side, or no owned set.
        // OwnedPartial is adapter proof for a strictly owned interrupted delete.
        for expected in [pending.after.as_ref(), pending.before.as_ref()]
            .into_iter()
            .flatten()
        {
            match self.system.inspect(&self.record.token, expected)? {
                Presence::Absent => {
                    absent = true;
                    break;
                }
                Presence::Exact | Presence::OwnedPartial => {
                    matched = Some(expected.clone());
                    break;
                }
                Presence::Conflict => (),
            }
        }
        if let Some(expected) = matched {
            self.system
                .replace(&self.record.token, Some(&expected), None)?;
            if self.system.inspect(&self.record.token, &expected)? != Presence::Absent {
                return Err(io::Error::other("forward_nat_cleanup_readback_failed"));
            }
        } else if !absent {
            return Err(io::Error::other("forward_nat_cleanup_conflict"));
        }
        let mut clean = self.record.clone();
        clean.committed = None;
        clean.pending = None;
        self.persist(clean)?;
        self.recovering = false;
        Ok(())
    }
    pub(crate) fn has_resources(&self) -> bool {
        self.record.has_resources()
    }
    pub(crate) fn is_recovering(&self) -> bool {
        self.recovering || self.record.pending.is_some()
    }
    fn validate_storage(&self) -> io::Result<()> {
        validate_root(&self.root, self.uid)?;
        validate_private(&self.root.join("forward-nat"), self.uid)?;
        self.file.load()?;
        Ok(())
    }
    fn persist(&mut self, record: Record) -> io::Result<()> {
        self.validate_storage()?;
        self.file.save_state(&record)?;
        self.record = record;
        Ok(())
    }
}

fn validate_root(root: &Path, uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_private(root: &Path, uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        fs,
        os::unix::fs::{symlink, MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        rc::Rc,
    };
    const BOOT: &str = "11111111-2222-4333-8444-555555555555";
    const NEXT_BOOT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    fn plan() -> Plan {
        Plan {
            max_mss: None,
            egress: Egress {
                name: "utun4".into(),
                index: 4,
                address: "10.241.0.1".parse().unwrap(),
            },
            sources: vec![Source {
                name: "bridge100".into(),
                index: 20,
                network: "192.168.64.0/24".into(),
                host_address: "192.168.64.1".parse().unwrap(),
            }],
        }
    }
    #[test]
    fn verified_private_virtual_network_can_be_translated() {
        assert!(validate_plan(&plan()));
    }
    #[test]
    fn broad_or_public_network_and_unchecked_identity_are_rejected() {
        let mut p = plan();
        p.sources[0].network = "0.0.0.0/0".into();
        assert!(!validate_plan(&p));
        p = plan();
        p.sources[0].network = "192.168.0.0/16".into();
        p.sources[0].index = 0;
        assert!(!validate_plan(&p));
        p = plan();
        p.sources[0].network = "8.8.8.0/24".into();
        p.sources[0].host_address = "8.8.8.1".parse().unwrap();
        assert!(!validate_plan(&p));
        p = plan();
        p.egress.name = "utun4\npass all".into();
        assert!(!validate_plan(&p));
    }

    #[test]
    fn validation_rejects_noncanonical_cidrs_outside_hosts_and_excess_sources() {
        for network in [
            "192.168.64.7/24",
            "192.168.64.0/32",
            "10.0.0.0/7",
            "172.0.0.0/11",
            "192.168.64.0/33",
        ] {
            let mut p = plan();
            p.sources[0].network = network.into();
            assert!(!validate_plan(&p), "{network}");
        }
        for host in ["192.168.65.1", "192.168.64.0", "192.168.64.255"] {
            let mut p = plan();
            p.sources[0].host_address = host.parse().unwrap();
            assert!(!validate_plan(&p));
        }
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "192.168.64.2",
        ] {
            let mut p = plan();
            p.egress.address = address.parse().unwrap();
            assert!(!validate_plan(&p));
        }
        let mut p = plan();
        p.egress.index = u32::MAX;
        assert!(!validate_plan(&p));
        let mut p = plan();
        p.sources = vec![p.sources[0].clone(); 17];
        assert!(!validate_plan(&p));
        let mut p = plan();
        p.sources.clear();
        assert!(!validate_plan(&p));
        let mut p = plan();
        p.egress.address = "203.0.113.7".parse().unwrap();
        assert!(validate_plan(&p));
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Live {
        Absent,
        Rules(String, Plan),
        Partial(String, Plan),
        Foreign,
    }
    struct Native {
        desired: Option<Plan>,
        live: Live,
        writes: usize,
        reads: usize,
        lose_ack: bool,
        fail_before: bool,
        corrupt_readback: bool,
        leave_partial: bool,
    }
    #[derive(Clone)]
    struct FakeSystem {
        native: Rc<RefCell<Native>>,
        journal: PathBuf,
    }
    impl System for FakeSystem {
        fn discover(&mut self, _name: &str, _index: u32) -> io::Result<Option<Plan>> {
            Ok(self.native.borrow().desired.clone())
        }
        fn inspect(&mut self, token: &str, expected: &Plan) -> io::Result<Presence> {
            let mut native = self.native.borrow_mut();
            native.reads += 1;
            Ok(match &native.live {
                Live::Absent => Presence::Absent,
                Live::Rules(t, p) if t == token && p == expected => Presence::Exact,
                Live::Partial(t, p) if t == token && p == expected => Presence::OwnedPartial,
                _ => Presence::Conflict,
            })
        }
        fn replace(
            &mut self,
            token: &str,
            before: Option<&Plan>,
            after: Option<&Plan>,
        ) -> io::Result<()> {
            // Removing write-ahead persistence must fail before any fake native change.
            let saved: serde_json::Value =
                serde_json::from_slice(&fs::read(&self.journal)?).unwrap();
            assert!(
                !saved["state"]["pending"].is_null(),
                "native mutation without durable intent"
            );
            let mut native = self.native.borrow_mut();
            let matches = match (&native.live, before) {
                (Live::Absent, None) => true,
                (Live::Rules(t, p), Some(expected)) => t == token && p == expected,
                (Live::Partial(t, p), Some(expected)) if after.is_none() => {
                    t == token && p == expected
                }
                _ => false,
            };
            if !matches {
                return Err(io::Error::other("fake_compare_conflict"));
            }
            if std::mem::take(&mut native.fail_before) {
                return Err(io::Error::other("fake_before_apply"));
            }
            native.writes += 1;
            native.live = match after {
                Some(p) => Live::Rules(token.into(), p.clone()),
                None => Live::Absent,
            };
            if std::mem::take(&mut native.leave_partial) {
                native.live = Live::Partial(token.into(), before.unwrap().clone());
                return Err(io::Error::other("fake_partial_cleanup"));
            }
            if std::mem::take(&mut native.corrupt_readback) {
                native.live = Live::Foreign;
            }
            if std::mem::take(&mut native.lose_ack) {
                return Err(io::Error::other("fake_lost_ack"));
            }
            Ok(())
        }
    }
    fn fixture() -> (tempfile::TempDir, FakeSystem) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let system = FakeSystem {
            native: Rc::new(RefCell::new(Native {
                desired: Some(plan()),
                live: Live::Absent,
                writes: 0,
                reads: 0,
                lose_ack: false,
                fail_before: false,
                corrupt_readback: false,
                leave_partial: false,
            })),
            journal: dir.path().join("forward-nat/forward-nat.json"),
        };
        (dir, system)
    }
    fn owner(root: &Path, system: FakeSystem) -> Owner<FakeSystem> {
        Owner::open(root, BOOT, unsafe { libc::geteuid() }, system).unwrap()
    }
    fn saved(system: &FakeSystem) -> serde_json::Value {
        serde_json::from_slice(&fs::read(&system.journal).unwrap()).unwrap()
    }
    fn token(system: &FakeSystem) -> String {
        match &system.native.borrow().live {
            Live::Rules(t, _) | Live::Partial(t, _) => t.clone(),
            _ => panic!("no owned rules"),
        }
    }

    #[test]
    fn durable_intent_readback_and_idempotent_refresh_own_only_the_new_rules() {
        let (dir, system) = fixture();
        let mut owner = owner(dir.path(), system.clone());
        owner.refresh("utun4", 4).unwrap();
        assert!(owner.has_resources());
        assert!(!owner.is_recovering());
        assert!(valid_token(&token(&system)));
        assert!(saved(&system)["state"]["pending"].is_null());
        assert_eq!(
            saved(&system)["state"]["committed"]["egress"]["address"],
            "10.241.0.1"
        );
        assert_eq!(
            fs::metadata(dir.path().join("forward-nat")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&system.journal).unwrap().mode() & 0o777, 0o600);
        let before = fs::read(&system.journal).unwrap();
        owner.refresh("utun4", 4).unwrap();
        assert_eq!(system.native.borrow().writes, 1);
        assert_eq!(fs::read(&system.journal).unwrap(), before);
        system.native.borrow_mut().live = Live::Foreign;
        assert!(owner.refresh("utun4", 4).is_err());
        assert!(owner.cleanup().is_err());
        assert_eq!(system.native.borrow().live, Live::Foreign);
        assert!(owner.has_resources());
    }
    #[test]
    fn saved_lost_ack_requires_cleanup_before_restart_and_rotates_the_next_token() {
        let (dir, system) = fixture();
        let first_token;
        {
            let mut owner = owner(dir.path(), system.clone());
            system.native.borrow_mut().lose_ack = true;
            assert!(owner.refresh("utun4", 4).is_err());
            assert!(owner.has_resources());
            first_token = token(&system);
            assert!(!saved(&system)["state"]["pending"].is_null());
        }
        let mut owner = owner(dir.path(), system.clone());
        assert!(owner.is_recovering());
        assert!(owner.refresh("utun4", 4).is_err());
        assert_eq!(system.native.borrow().writes, 1);
        owner.cleanup().unwrap();
        owner.cleanup().unwrap();
        assert!(!owner.has_resources());
        assert!(!owner.is_recovering());
        assert_eq!(system.native.borrow().live, Live::Absent);
        owner.refresh("utun4", 4).unwrap();
        assert_ne!(token(&system), first_token);
    }
    #[test]
    fn plan_changes_are_write_ahead_and_cleanup_accepts_either_interrupted_side() {
        for apply in [false, true] {
            let (dir, system) = fixture();
            let mut owner = owner(dir.path(), system.clone());
            owner.refresh("utun4", 4).unwrap();
            let active_token = token(&system);
            let mut updated = plan();
            updated.sources[0].network = "192.168.65.0/24".into();
            updated.sources[0].host_address = "192.168.65.1".parse().unwrap();
            {
                let mut native = system.native.borrow_mut();
                native.desired = Some(updated);
                native.fail_before = !apply;
                native.lose_ack = apply;
            }
            assert!(owner.refresh("utun4", 4).is_err());
            assert_eq!(token(&system), active_token);
            owner.cleanup().unwrap();
            assert_eq!(system.native.borrow().live, Live::Absent);
            assert!(!owner.has_resources());
        }
    }
    #[test]
    fn readback_conflict_and_partial_cleanup_keep_recovery_authority_until_exact_removal() {
        let (dir, system) = fixture();
        let mut owner = owner(dir.path(), system.clone());
        system.native.borrow_mut().corrupt_readback = true;
        assert!(owner.refresh("utun4", 4).is_err());
        assert!(owner.cleanup().is_err());
        assert_eq!(system.native.borrow().live, Live::Foreign);
        let t = saved(&system)["state"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        system.native.borrow_mut().live = Live::Rules(t, plan());
        system.native.borrow_mut().leave_partial = true;
        assert!(owner.cleanup().is_err());
        assert!(owner.has_resources());
        assert!(matches!(system.native.borrow().live, Live::Partial(..)));
        owner.cleanup().unwrap();
        assert_eq!(system.native.borrow().live, Live::Absent);
        assert!(!owner.has_resources());
    }
    #[test]
    fn absent_after_lost_cleanup_ack_is_safe_to_finish_without_second_mutation() {
        let (dir, system) = fixture();
        let mut owner = owner(dir.path(), system.clone());
        owner.refresh("utun4", 4).unwrap();
        system.native.borrow_mut().lose_ack = true;
        assert!(owner.cleanup().is_err());
        assert!(owner.has_resources());
        let writes = system.native.borrow().writes;
        owner.cleanup().unwrap();
        assert_eq!(system.native.borrow().writes, writes);
        assert!(!owner.has_resources());
    }
    #[test]
    fn reboot_discards_ephemeral_authority_without_native_queries() {
        let (dir, system) = fixture();
        {
            let mut owner = owner(dir.path(), system.clone());
            owner.refresh("utun4", 4).unwrap();
        }
        let reads = system.native.borrow().reads;
        let writes = system.native.borrow().writes;
        let owner = Owner::open(
            dir.path(),
            NEXT_BOOT,
            unsafe { libc::geteuid() },
            system.clone(),
        )
        .unwrap();
        assert!(!owner.has_resources());
        assert!(!owner.is_recovering());
        assert_eq!(system.native.borrow().reads, reads);
        assert_eq!(system.native.borrow().writes, writes);
        assert_eq!(saved(&system)["state"]["boot"], NEXT_BOOT);
    }
    #[test]
    fn foreign_root_cannot_adopt_even_identical_native_rules() {
        let (first, system) = fixture();
        let mut a = owner(first.path(), system.clone());
        a.refresh("utun4", 4).unwrap();
        let original = system.native.borrow().live.clone();
        let second = tempfile::tempdir().unwrap();
        let other = FakeSystem {
            native: system.native.clone(),
            journal: second.path().join("forward-nat/forward-nat.json"),
        };
        let mut b = owner(second.path(), other);
        assert!(b.refresh("utun4", 4).is_err());
        assert!(b.cleanup().is_err());
        assert_eq!(system.native.borrow().live, original);
        a.cleanup().unwrap();
        assert_eq!(system.native.borrow().live, Live::Absent);
    }
    #[test]
    fn unprotected_roots_and_symlinked_children_do_not_confer_ownership() {
        let (dir, system) = fixture();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Owner::open(dir.path(), BOOT, unsafe { libc::geteuid() }, system.clone()).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Owner::open(
            dir.path(),
            BOOT,
            unsafe { libc::geteuid() } + 1,
            system.clone()
        )
        .is_err());
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), dir.path().join("forward-nat")).unwrap();
        assert!(Owner::open(dir.path(), BOOT, unsafe { libc::geteuid() }, system.clone()).is_err());
        fs::remove_file(dir.path().join("forward-nat")).unwrap();
        fs::create_dir(dir.path().join("forward-nat")).unwrap();
        fs::set_permissions(
            dir.path().join("forward-nat"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(Owner::open(dir.path(), BOOT, unsafe { libc::geteuid() }, system).is_err());
    }
    #[test]
    fn discovered_mismatched_egress_and_journal_permission_change_prevent_native_write() {
        let (dir, system) = fixture();
        let mut owner = owner(dir.path(), system.clone());
        assert!(owner.refresh("utun5", 5).is_err());
        assert_eq!(system.native.borrow().writes, 0);
        owner.refresh("utun4", 4).unwrap();
        fs::set_permissions(&system.journal, fs::Permissions::from_mode(0o644)).unwrap();
        system.native.borrow_mut().desired = None;
        assert!(owner.refresh("utun4", 4).is_err());
        assert_eq!(system.native.borrow().writes, 1);
    }
    #[test]
    fn normalized_source_order_does_not_rewrite_the_native_set() {
        let (dir, system) = fixture();
        let second = Source {
            name: "bridge101".into(),
            index: 21,
            network: "192.168.65.0/24".into(),
            host_address: "192.168.65.1".parse().unwrap(),
        };
        system
            .native
            .borrow_mut()
            .desired
            .as_mut()
            .unwrap()
            .sources
            .push(second);
        let mut owner = owner(dir.path(), system.clone());
        owner.refresh("utun4", 4).unwrap();
        system
            .native
            .borrow_mut()
            .desired
            .as_mut()
            .unwrap()
            .sources
            .reverse();
        owner.refresh("utun4", 4).unwrap();
        assert_eq!(system.native.borrow().writes, 1);
        system.native.borrow_mut().desired = None;
        owner.refresh("utun4", 4).unwrap();
        assert!(!owner.has_resources());
    }
    #[test]
    fn native_commands_prefill_bounded_input_and_sanitize_failed_output() {
        let mut commands = NativeCommands::default();
        let input = "x".repeat(4096);
        assert_eq!(commands.run("/bin/cat", &[], Some(&input)).unwrap(), input);
        assert_eq!(commands.run("/bin/cat", &[], None).unwrap(), "");
        assert!(commands
            .run("/bin/cat", &[], Some(&"x".repeat(4097)))
            .is_err());
        let error = commands
            .run(
                "/bin/sh",
                &[
                    "-c".into(),
                    "printf secret-output; printf secret-error >&2; exit 7".into(),
                ],
                None,
            )
            .unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }
    #[test]
    fn native_command_timeout_also_bounds_a_child_which_never_reads_input() {
        let mut commands = NativeCommands::default();
        let started = std::time::Instant::now();
        let error = commands
            .run("/bin/sleep", &["3".into()], Some(&"x".repeat(4096)))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
    #[test]
    fn native_commands_share_one_operation_deadline_across_sequential_commands() {
        let mut commands = NativeCommands::default();
        commands.begin_operation();
        let started = std::time::Instant::now();
        commands.run("/bin/sleep", &["0.65".into()], None).unwrap();
        let error = commands
            .run("/bin/sleep", &["0.65".into()], None)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < std::time::Duration::from_millis(1700));
    }
    #[test]
    fn mss_bounds_reject_invalid_native_mtu_and_legacy_records_remain_readable() {
        let legacy = serde_json::to_value(plan()).unwrap();
        assert!(legacy.get("max_mss").is_none());
        assert_eq!(
            serde_json::from_value::<Plan>(legacy).unwrap().max_mss,
            None
        );
        for mss in [536, 1240, 65495] {
            let mut p = plan();
            p.max_mss = Some(mss);
            assert!(validate_plan(&p));
        }
        for mss in [0, 535, 65496, 65535] {
            let mut p = plan();
            p.max_mss = Some(mss);
            assert!(!validate_plan(&p), "{mss}");
        }
    }
}
