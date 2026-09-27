//! Linux member ownership is independent of macOS utun naming.
use super::redundancy::SocketIdentity;
use crate::member_network::journal::ScopedJournal;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::dispatcher::TunnelSlot;
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum MemberTransport {
    WireGuard,
    AmneziaWg3,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum NativeProof {
    Kernel { alias: String },
    Userspace(SocketIdentity),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LinuxIdentity {
    pub boot: String,
    pub interface: String,
    pub index: u32,
    pub proof: NativeProof,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    boot: String,
    transport: MemberTransport,
    alias: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Phase {
    Starting(Intent),
    Owned {
        intent: Intent,
        identity: LinuxIdentity,
        stopping: bool,
    },
    Closed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    slot: TunnelSlot,
    phase: Phase,
}

pub(super) struct LinuxOwner {
    store: ScopedJournal<Record>,
    slot: TunnelSlot,
    state: Option<Phase>,
    // Only the instance which persisted Starting may capture its launch result.
    // Reopening a Starting record cannot adopt a same-named resource.
    launching: bool,
    pub scope: SessionScope,
}
impl LinuxOwner {
    pub(super) fn launch(
        &mut self,
        transport: MemberTransport,
        boot: &str,
        launch: impl FnOnce(&str) -> io::Result<LinuxIdentity>,
    ) -> io::Result<()> {
        let alias = self.begin(transport, boot)?;
        let identity = match launch(&alias) {
            Ok(identity) => identity,
            Err(error) => {
                self.launching = false;
                return Err(error);
            }
        };
        self.capture(identity)
    }
    #[cfg(target_os = "linux")]
    pub(super) fn open_root(
        root: &Path,
        scope: SessionScope,
        slot: TunnelSlot,
    ) -> io::Result<Self> {
        Self::open_for_owner(root, scope, slot, 0)
    }
    pub(super) fn open_for_owner(
        root: &Path,
        scope: SessionScope,
        slot: TunnelSlot,
        uid: u32,
    ) -> io::Result<Self> {
        let store = ScopedJournal::<Record>::open_named(
            root,
            scope.clone(),
            uid,
            "redundant-linux-member.json",
        )?;
        let record = store.load()?;
        if record
            .as_ref()
            .is_some_and(|r| r.slot != slot || !valid_phase(&r.phase, slot))
        {
            return Err(invalid());
        }
        Ok(Self {
            store,
            slot,
            state: record.map(|r| r.phase),
            launching: false,
            scope,
        })
    }
    fn save(&mut self, phase: Phase) -> io::Result<()> {
        self.store.save_state(&Record {
            slot: self.slot,
            phase: phase.clone(),
        })?;
        self.state = Some(phase);
        Ok(())
    }
    pub(super) fn ensure_fresh(&self) -> io::Result<()> {
        if self.cleanup_pending() {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    pub(super) fn begin(&mut self, transport: MemberTransport, boot: &str) -> io::Result<String> {
        self.ensure_fresh()?;
        if !valid_boot(boot) {
            return Err(invalid());
        }
        // Local opaque marker only: no configuration, key or credential input.
        let mut nonce = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(serde_json::to_vec(&(&self.scope, self.slot, boot)).map_err(io::Error::other)?);
        hash.update(nonce);
        let alias = format!("nlm-owner-{:x}", hash.finalize());
        let phase = Phase::Starting(Intent {
            boot: boot.into(),
            transport,
            alias: alias.clone(),
        });
        if let Err(error) = self.save(phase.clone()) {
            // An fsync error may occur after rename: never allow a second launch.
            self.state = Some(phase);
            return Err(error);
        }
        self.launching = true;
        Ok(alias)
    }
    pub(super) fn capture(&mut self, identity: LinuxIdentity) -> io::Result<()> {
        let Some(Phase::Starting(intent)) = &self.state else {
            return Err(invalid());
        };
        if !self.launching || !valid_identity(&identity, intent, self.slot) {
            return Err(invalid());
        }
        let mut next = Phase::Owned {
            intent: intent.clone(),
            identity,
            stopping: false,
        };
        self.launching = false;
        if let Err(error) = self.save(next.clone()) {
            // Capture proved this exact fresh native resource, even if its
            // journal write failed. Keep that proof for startup cleanup only;
            // a restarted process still has only the durable Starting record.
            if let Phase::Owned { stopping, .. } = &mut next {
                *stopping = true;
            }
            self.state = Some(next);
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn identity(&self) -> Option<&LinuxIdentity> {
        match &self.state {
            Some(Phase::Owned { identity, .. }) => Some(identity),
            _ => None,
        }
    }
    pub(super) fn cleanup_pending(&self) -> bool {
        matches!(self.state, Some(Phase::Starting(_) | Phase::Owned { .. }))
    }
    pub(super) fn stopping(&self) -> bool {
        matches!(
            self.state,
            Some(Phase::Owned { stopping: true, .. } | Phase::Closed)
        )
    }
    pub(super) fn owned(&self, actual: &LinuxIdentity) -> io::Result<MemberTransport> {
        match &self.state {
            Some(Phase::Owned {
                intent, identity, ..
            }) if identity == actual && valid_identity(identity, intent, self.slot) => {
                Ok(intent.transport)
            }
            _ => Err(invalid()),
        }
    }
    pub(super) fn stop_owned(
        &mut self,
        boot: &str,
        mut inspect: impl FnMut(&LinuxIdentity) -> io::Result<Option<LinuxIdentity>>,
        mut remove: impl FnMut(&LinuxIdentity) -> io::Result<()>,
    ) -> io::Result<()> {
        if !valid_boot(boot) {
            return Err(invalid());
        }
        let (intent, identity) = match &self.state {
            Some(Phase::Starting(_)) => return Err(invalid()),
            Some(Phase::Owned {
                intent, identity, ..
            }) => (intent.clone(), identity.clone()),
            None | Some(Phase::Closed) => return Ok(()),
        };
        let stopping = Phase::Owned {
            intent,
            identity: identity.clone(),
            stopping: true,
        };
        let persisted = self.save(stopping.clone());
        // A full/unavailable journal cannot keep our verified tunnel running.
        // Preserve the stop fence and exact proof in memory even on write error.
        self.state = Some(stopping);
        if identity.boot == boot {
            if let Some(actual) = inspect(&identity)? {
                self.owned(&actual)?;
                remove(&identity)?;
                // Success from delete is not an acknowledgement of absence.
                if inspect(&identity)?.is_some() {
                    return Err(io::Error::other("member_cleanup_pending"));
                }
            }
        }
        // A successful native shutdown does not acknowledge a failed write.
        // Keep the proof/pending state until a later durable cleanup succeeds.
        persisted?;
        self.save(Phase::Closed)
    }
}

fn valid_boot(boot: &str) -> bool {
    !boot.is_empty() && boot.len() <= 128 && !boot.chars().any(char::is_control)
}
fn valid_intent(intent: &Intent) -> bool {
    valid_boot(&intent.boot)
        && intent
            .alias
            .strip_prefix("nlm-owner-")
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn valid_identity(identity: &LinuxIdentity, intent: &Intent, slot: TunnelSlot) -> bool {
    use nelomai_client_tunnel::TunnelTransport;
    let transport = match intent.transport {
        MemberTransport::WireGuard => TunnelTransport::WireGuard,
        MemberTransport::AmneziaWg3 => TunnelTransport::AmneziaWg3,
    };
    valid_intent(intent)
        && identity.boot == intent.boot
        && identity.index > 0
        && identity.interface
            == super::redundancy::ResourceMode::Member(slot).linux_interface(transport)
        && match (&identity.proof, intent.transport) {
            (NativeProof::Kernel { alias }, MemberTransport::WireGuard) => alias == &intent.alias,
            (NativeProof::Userspace(socket), MemberTransport::AmneziaWg3) => socket.inode > 0,
            _ => false,
        }
}
fn valid_phase(phase: &Phase, slot: TunnelSlot) -> bool {
    match phase {
        Phase::Starting(intent) => valid_intent(intent),
        Phase::Owned {
            intent, identity, ..
        } => valid_identity(identity, intent, slot),
        Phase::Closed => true,
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "linux_member_owner_mismatch",
    )
}

// Called with symlink_metadata for allowlisted absolute paths only. Match the
// Linux native command policy and reject symlinks as well as writable binaries.
pub(super) fn trusted_ip_file(regular: bool, uid: u32, mode: u32) -> bool {
    regular && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0
}

// Command construction is shared with fake tests; they never execute `ip`.
pub(super) fn kernel_create_command(
    ip: &str,
    interface: &str,
    alias: &str,
) -> std::process::Command {
    let mut command = std::process::Command::new(ip);
    command
        .args([
            "link",
            "add",
            "name",
            interface,
            "alias",
            alias,
            "up",
            "type",
            "wireguard",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}
