//! Additive private-engine messages. Transport authentication still happens in
//! the dispatcher; scope equality and generations are checked again by the
//! serialized session owner, never by a prior UI status check.
use super::{session::SessionSnapshot, SessionScope, Slot};
use crate::{DesktopTunnelOptions, TunnelConfiguration};
use nelomai_contracts::{RedundantHealthProbe, RedundantRoleResponse, RuntimeSlot};
use serde::{Deserialize, Serialize};
use std::io;

const MAX_CONFIGURATION: usize = 512 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub slot: Slot,
    pub lease_id: String,
    #[serde(
        serialize_with = "serialize_configuration",
        deserialize_with = "deserialize_configuration"
    )]
    pub configuration: TunnelConfiguration,
    pub probe: RedundantHealthProbe,
}
impl Member {
    pub fn validate(&self) -> io::Result<()> {
        let ip = self.probe.target_ipv4;
        if !uuid(&self.lease_id)
            || self.configuration.expose().is_empty()
            || self.configuration.as_bytes().len() > MAX_CONFIGURATION
            || self.configuration.expose().contains('\0')
            || ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || ip.is_broadcast()
            || !(1000..=8000).contains(&self.probe.timeout_ms)
            || !dns_name(&self.probe.query_name)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Start {
        scope: SessionScope,
        primary: Member,
        role_generation: u64,
        membership_generation: u64,
        warm_stop_v1: bool,
        options: DesktopTunnelOptions,
    },
    Attach {
        scope: SessionScope,
        member: Member,
        expected_revision: u64,
        expected_network_epoch: u64,
        expected_membership_generation: u64,
        membership_generation: u64,
    },
    StageCandidate {
        scope: SessionScope,
        member: Member,
        expected_revision: u64,
        expected_network_epoch: u64,
        expected_membership_generation: u64,
    },
    RemoveStandby {
        scope: SessionScope,
        slot: Slot,
        lease_id: String,
        expected_revision: u64,
        expected_network_epoch: u64,
        expected_membership_generation: u64,
    },
    /// Local inactive shutdown only. Server CURRENT identity remains until
    /// acquire(replace_lease_id)+commit acknowledges a replacement.
    RetireInactive {
        scope: SessionScope,
        slot: Slot,
        lease_id: String,
        expected_revision: u64,
        expected_network_epoch: u64,
        expected_membership_generation: u64,
    },
    CommitCandidate {
        scope: SessionScope,
        slot: Slot,
        expected_revision: u64,
        expected_network_epoch: u64,
        session: nelomai_contracts::RedundantSessionView,
    },
    Status {
        scope: SessionScope,
    },
    /// Freeze the local role before durable server Stop; native close follows
    /// explicit Stop or the helper driver's bounded monotonic deadline.
    PrepareStop {
        scope: SessionScope,
    },
    /// Freeze only the exact still-stalled native role observed by lifecycle.
    PrepareRecoveryStop {
        scope: SessionScope,
        expected_revision: u64,
        expected_network_epoch: u64,
    },
    Stop {
        scope: SessionScope,
    },
    NetworkChanged {
        scope: SessionScope,
    },
    ConfirmRole {
        scope: SessionScope,
        expected_revision: u64,
        expected_network_epoch: u64,
        response: RedundantRoleResponse,
    },
}
impl Command {
    pub fn scope(&self) -> &SessionScope {
        match self {
            Self::Start { scope, .. }
            | Self::Attach { scope, .. }
            | Self::StageCandidate { scope, .. }
            | Self::RemoveStandby { scope, .. }
            | Self::CommitCandidate { scope, .. }
            | Self::Status { scope }
            | Self::Stop { scope }
            | Self::RetireInactive { scope, .. }
            | Self::PrepareStop { scope }
            | Self::PrepareRecoveryStop { scope, .. }
            | Self::NetworkChanged { scope }
            | Self::ConfirmRole { scope, .. } => scope,
        }
    }
    pub fn is_start(&self) -> bool {
        matches!(self, Self::Start { .. })
    }
    pub fn validate(&self, runtime: RuntimeSlot) -> io::Result<()> {
        if !self.scope().validate() || self.scope().runtime != runtime {
            return Err(invalid());
        }
        match self {
            Self::PrepareRecoveryStop {
                expected_revision,
                expected_network_epoch,
                ..
            } => {
                if *expected_revision == 0 || *expected_network_epoch == 0 {
                    return Err(invalid());
                }
            }
            Self::Start {
                primary,
                role_generation,
                membership_generation,
                options,
                ..
            } => {
                primary.validate()?;
                if *role_generation > i64::MAX as u64 || *membership_generation > i64::MAX as u64 {
                    return Err(invalid());
                }
                options.validate().map_err(|_| invalid())?;
            }
            Self::Attach {
                member,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
                membership_generation,
                ..
            } => {
                member.validate()?;
                if *expected_revision == 0
                    || *expected_network_epoch == 0
                    || membership_generation < expected_membership_generation
                    || *membership_generation > i64::MAX as u64
                {
                    return Err(invalid());
                }
            }
            Self::StageCandidate {
                member,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
                ..
            } => {
                member.validate()?;
                if *expected_revision == 0
                    || *expected_network_epoch == 0
                    || *expected_membership_generation > i64::MAX as u64
                {
                    return Err(invalid());
                }
            }
            Self::CommitCandidate {
                scope,
                expected_revision,
                expected_network_epoch,
                session,
                ..
            } => {
                if *expected_revision == 0
                    || *expected_network_epoch == 0
                    || session.session_id != scope.session_id
                    || session.role_generation > i64::MAX as u64
                    || session.membership_generation > i64::MAX as u64
                {
                    return Err(invalid());
                }
            }
            Self::RemoveStandby {
                lease_id,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
                ..
            }
            | Self::RetireInactive {
                lease_id,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
                ..
            } => {
                if !uuid(lease_id)
                    || *expected_revision == 0
                    || *expected_network_epoch == 0
                    || *expected_membership_generation > i64::MAX as u64
                {
                    return Err(invalid());
                }
            }
            Self::ConfirmRole {
                scope,
                expected_revision,
                expected_network_epoch,
                response,
            } => {
                if *expected_revision == 0
                    || *expected_network_epoch == 0
                    || response.session.session_id != scope.session_id
                    || !uuid(&response.local_active_lease_id)
                    || response.session.role_generation > i64::MAX as u64
                    || response.session.membership_generation > i64::MAX as u64
                {
                    return Err(invalid());
                }
            }
            _ => (),
        }
        Ok(())
    }
}

/// Contains no native paths, keys, configuration, tokens or backend handles.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub session: SessionSnapshot,
    pub leases: [Option<String>; 2],
    pub current_leases: [Option<String>; 2],
    pub standby_failed: bool,
    /// Sticky total-loss observation. Status reads and invalidation do not
    /// acknowledge it; only current recovery evidence or a new validated
    /// epoch/committed membership clears it. Not restart/adoption authority.
    pub stalled: bool,
    pub primary_ready: bool,
    pub standby_ready: bool,
    pub cleanup_pending: bool,
    pub warm_stop_v1: bool,
}
pub(crate) fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.is_ascii()
        && s == s.to_ascii_lowercase()
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && p.as_bytes()[0].is_ascii_alphanumeric()
                && p.as_bytes()[p.len() - 1].is_ascii_alphanumeric()
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn serialize_configuration<S: serde::Serializer>(
    c: &TunnelConfiguration,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(c.expose())
}
fn deserialize_configuration<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<TunnelConfiguration, D::Error> {
    let value = TunnelConfiguration::new(String::deserialize(d)?);
    if value.as_bytes().len() > MAX_CONFIGURATION
        || value.expose().is_empty()
        || value.expose().contains('\0')
    {
        return Err(serde::de::Error::custom("invalid_member_configuration"));
    }
    Ok(value)
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid_redundant_command")
}
