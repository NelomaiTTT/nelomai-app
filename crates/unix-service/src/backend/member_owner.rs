//! Durable userspace identity. A name alone never authorizes adoption/cleanup.
use super::macos_launch::{LaunchFailure, LaunchReceipt, VerifiedLaunch};
use super::redundancy::SocketIdentity;
use crate::member_network::journal::ScopedJournal;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::dispatcher::TunnelSlot;
use serde::{Deserialize, Serialize};
use std::{io, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum MemberTransport {
    WireGuard,
    AmneziaWg3,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UserspaceIdentity {
    pub boot: String,
    pub interface: String,
    pub index: u32,
    pub socket: SocketIdentity,
}
impl UserspaceIdentity {
    pub(super) fn valid(&self) -> bool {
        !self.boot.is_empty()
            && self.boot.len() <= 128
            && !self.boot.chars().any(char::is_control)
            && self.index > 0
            && self.socket.inode > 0
            && self.interface.strip_prefix("utun").is_some_and(|s| {
                !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())
            })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    slot: TunnelSlot,
    phase: Phase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Phase {
    Starting(LaunchReceipt),
    Owned {
        transport: MemberTransport,
        identity: UserspaceIdentity,
        stopping: bool,
    },
    Closed,
}

pub(super) struct MemberOwner {
    store: ScopedJournal<Record>,
    slot: TunnelSlot,
    state: Option<Phase>,
    pub(super) scope: SessionScope,
}
impl MemberOwner {
    #[cfg(target_os = "macos")]
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
        let store =
            ScopedJournal::<Record>::open_named(root, scope.clone(), uid, "redundant-member.json")?;
        let record = store.load()?;
        if record.as_ref().is_some_and(|r| {
            r.slot != slot
                || matches!(&r.phase, Phase::Owned { identity, .. } if !identity.valid())
                || matches!(&r.phase, Phase::Starting(receipt) if !receipt.valid())
        }) {
            return Err(invalid());
        }
        Ok(Self {
            store,
            slot,
            state: record.map(|r| r.phase),
            scope,
        })
    }
    fn save(&mut self, state: Phase) -> io::Result<()> {
        self.store.save_state(&Record {
            slot: self.slot,
            phase: state.clone(),
        })?;
        self.state = Some(state);
        Ok(())
    }
    pub(super) fn begin(&mut self, receipt: LaunchReceipt) -> io::Result<()> {
        self.ensure_fresh()?;
        if !receipt.valid() {
            return Err(invalid());
        }
        self.save(Phase::Starting(receipt))
    }
    /// Outer errors are journal/ownership failures; inner errors retain the
    /// launcher's original error. This closure runs once, only after a fresh
    /// begin. No retirement capability escapes to recovery or a later attempt.
    pub(super) fn launch_attempt<T, E>(
        &mut self,
        receipt: LaunchReceipt,
        launch: impl FnOnce(&LaunchReceipt) -> Result<T, LaunchFailure<E>>,
    ) -> io::Result<Result<T, E>> {
        self.begin(receipt.clone())?;
        match launch(&receipt) {
            Ok(value) => Ok(Ok(value)),
            Err(LaunchFailure::SpawnedOrUnknown(error)) => Ok(Err(error)),
            Err(LaunchFailure::NotSpawned(error)) => {
                // Never use mere absence as evidence. Verify both the live
                // attempt and its still-current durable receipt before saving.
                if self.receipt() != Some(&receipt)
                    || !matches!(self.store.load()?, Some(Record {slot, phase:Phase::Starting(saved)})
                        if slot == self.slot && saved == receipt)
                {
                    return Err(invalid());
                }
                self.save(Phase::Closed)?;
                Ok(Err(error))
            }
        }
    }
    pub(super) fn ensure_fresh(&self) -> io::Result<()> {
        if self.cleanup_pending() {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    pub(super) fn cleanup_pending(&self) -> bool {
        matches!(self.state, Some(Phase::Starting(_) | Phase::Owned { .. }))
    }
    pub(super) fn receipt(&self) -> Option<&LaunchReceipt> {
        match &self.state {
            Some(Phase::Starting(receipt)) => Some(receipt),
            _ => None,
        }
    }
    /// The caller supplies a newly read kernel boot UUID, never journal text.
    /// A different boot retires only an uncaptured launch: no old interface or
    /// socket is inspected/deleted. This says nothing about persistent DNS,
    /// files or pair network journals; their scoped cleanup remains separate.
    pub(super) fn retire_starting_after_boot(&mut self, current_boot: &str) -> io::Result<bool> {
        if !valid_boot_uuid(current_boot) {
            return Err(invalid());
        }
        let Some(receipt) = self.receipt() else {
            return Ok(false);
        };
        if !valid_boot_uuid(&receipt.boot) {
            return Err(invalid());
        }
        if receipt.boot.eq_ignore_ascii_case(current_boot) {
            return Ok(false);
        }
        // save updates memory only after persistence succeeds. A write failure
        // retains Starting authority and stops the caller before any effects.
        self.save(Phase::Closed)?;
        Ok(true)
    }
    pub(super) fn capture_proven(
        &mut self,
        proof: VerifiedLaunch,
        cleanup_only: bool,
    ) -> io::Result<()> {
        let identity = proof.into_identity(self.receipt().ok_or_else(invalid)?)?;
        self.capture_identity(identity, cleanup_only)
    }
    #[cfg(test)]
    pub(super) fn capture(&mut self, identity: UserspaceIdentity) -> io::Result<()> {
        self.capture_identity(identity, false)
    }
    fn capture_identity(
        &mut self,
        identity: UserspaceIdentity,
        cleanup_only: bool,
    ) -> io::Result<()> {
        if !identity.valid() {
            return Err(invalid());
        }
        let Some(receipt) = self.receipt() else {
            return Err(invalid());
        };
        if identity.boot != receipt.boot {
            return Err(invalid());
        }
        let transport = receipt.transport;
        let saved = self.save(Phase::Owned {
            transport,
            identity: identity.clone(),
            stopping: cleanup_only,
        });
        if saved.is_err() {
            // Durable Starting can be re-proven after a crash. Keep live proof
            // even if the first Owned write fails, but grant cleanup only.
            self.state = Some(Phase::Owned {
                transport,
                identity,
                stopping: true,
            });
        }
        saved
    }
    pub(super) fn identity(&self) -> Option<&UserspaceIdentity> {
        match &self.state {
            Some(Phase::Owned { identity, .. }) => Some(identity),
            _ => None,
        }
    }
    pub(super) fn owned(&self, actual: &UserspaceIdentity) -> io::Result<MemberTransport> {
        match &self.state {
            Some(Phase::Owned {
                transport,
                identity,
                ..
            }) if identity == actual && identity.valid() => Ok(*transport),
            _ => Err(invalid()),
        }
    }
    pub(super) fn stopping(&self) -> bool {
        matches!(
            self.state,
            Some(Phase::Closed | Phase::Owned { stopping: true, .. })
        )
    }
    pub(super) fn interrupted_launch(&self) -> bool {
        matches!(self.state, Some(Phase::Starting(_)))
    }
    /// Read-only recovery: no new Start, DNS restoration or interface deletion.
    /// `inspect` returns None only when BOTH recorded interface and socket are
    /// absent. An ambiguous resource is an error, never cleanup authority.
    pub(super) fn recover(
        &self,
        boot: &str,
        inspect: impl FnOnce(&UserspaceIdentity) -> io::Result<Option<UserspaceIdentity>>,
    ) -> io::Result<Option<MemberTransport>> {
        if self.interrupted_launch() {
            return Err(invalid());
        }
        let Some(identity) = self.identity() else {
            return Ok(None);
        };
        if identity.boot != boot {
            return Ok(None);
        }
        inspect(identity)?
            .map(|actual| self.owned(&actual))
            .transpose()
    }
    pub(super) fn begin_stop(&mut self) -> io::Result<()> {
        match &self.state {
            Some(Phase::Owned {
                transport,
                identity,
                ..
            }) => self.save(Phase::Owned {
                transport: *transport,
                identity: identity.clone(),
                stopping: true,
            }),
            None | Some(Phase::Closed) => self.save(Phase::Closed),
            _ => Err(invalid()),
        }
    }
    pub(super) fn stop_owned(
        &mut self,
        boot: &str,
        mut inspect: impl FnMut(&UserspaceIdentity) -> io::Result<Option<UserspaceIdentity>>,
        mut remove: impl FnMut(&UserspaceIdentity) -> io::Result<()>,
    ) -> io::Result<()> {
        let persisted = self.begin_stop();
        // Existing in-memory ownership is enough to turn OUR tunnel off even
        // when persisting Stop failed. Keep proof/pending state for later retry.
        if self.recover(boot, &mut inspect)?.is_some() {
            remove(self.identity().expect("verified owned member"))?;
            if self.recover(boot, &mut inspect)?.is_some() {
                return Err(io::Error::other("member_cleanup_pending"));
            }
        }
        persisted?;
        self.finish_stop()
    }
    // Native caller must verify the recorded resource is gone first. A launch
    // with no captured identity cannot be forgotten based on name alone.
    pub(super) fn finish_stop(&mut self) -> io::Result<()> {
        if !self.stopping() {
            return Err(invalid());
        }
        self.save(Phase::Closed)
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "member_owner_mismatch")
}

fn valid_boot_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        && bytes.iter().any(|b| *b != b'0' && *b != b'-')
}
