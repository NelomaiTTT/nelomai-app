//! Shared carrier identity and retained storage compatibility schema.
#![allow(dead_code)] // Retained journal compatibility is validated during recovery.

use crate::member_owner::InterfaceProof;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::dispatcher::EngineIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub scope: SessionScope,
    pub addresses: Vec<ipnet::IpNet>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    pub boot_id: [u8; 16],
    pub runtime: EngineIdentity,
    pub network_epoch: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Prepared,
    Created,
    Configured,
    Closing,
    Stopped,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressRow {
    pub address: ipnet::IpNet,
    pub skip_as_source: bool,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WeakHostRow {
    pub send: bool,
    pub receive: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum RowValue {
    Address(Option<AddressRow>),
    WeakHost(WeakHostRow),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RowState {
    pub baseline: RowValue,
    pub current: RowValue,
    pub pending: Option<RowValue>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    #[serde(deserialize_with = "decode_version")]
    pub version: u32,
    pub intent: Intent,
    pub provenance: Provenance,
    pub generation: u64,
    pub phase: Phase,
    pub proof: Option<InterfaceProof>,
    pub rows: Option<[RowState; 2]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CarrierKey {
    pub name: String,
    pub guid: [u8; 16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CarrierError {
    #[error("carrier_invalid")]
    Invalid,
    #[error("carrier_conflict")]
    Conflict,
    #[error("carrier_pending_cleanup")]
    Pending,
    #[error("carrier_retired")]
    Retired,
    #[error("carrier_native")]
    Native,
    #[error("carrier_journal")]
    Journal,
    #[error("carrier_deadline")]
    Deadline,
}
pub(crate) type Result<T> = std::result::Result<T, CarrierError>;
pub(crate) trait CarrierJournal {
    /// Keyed by the full scope-derived carrier identity, under the serialized
    /// privileged owner. Native storage must authenticate private ancestry,
    /// runtime, boot and epoch; no IPC path or unprotected storage fallback.
    fn load(&mut self, key: &CarrierKey) -> Result<Option<Record>>;
    /// Atomic, durable CAS. An error may mean a committed write with lost ACK.
    fn compare_exchange(
        &mut self,
        key: &CarrierKey,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()>;
}
pub(crate) fn carrier_key(scope: &SessionScope) -> Result<CarrierKey> {
    if !scope.validate() {
        return Err(CarrierError::Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(b"nelomai-member-carrier/v1\0"); // Disjoint from member/guard domains.
    hash.update([match scope.runtime {
        nelomai_contracts::RuntimeSlot::Stable => 0,
        nelomai_contracts::RuntimeSlot::Latest => 1,
    }]);
    hash.update(scope.runtime_generation.to_be_bytes());
    hash.update(scope.session_id.as_bytes());
    hash.update(scope.connection_generation.to_be_bytes());
    let digest = hash.finalize();
    let mut guid: [u8; 16] = digest[..16].try_into().expect("SHA256 prefix");
    guid[6] = (guid[6] & 0x0f) | 0x80;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    let suffix: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(CarrierKey {
        name: format!("nelomai-carrier-{suffix}"),
        guid,
    })
}
fn decode_version<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u32, D::Error> {
    let version = u32::deserialize(d)?;
    if version != VERSION {
        return Err(serde::de::Error::custom("carrier_unknown_version"));
    }
    Ok(version)
}
fn validate_intent(intent: &Intent, provenance: &Provenance) -> Result<()> {
    let r = &provenance.runtime;
    if !intent.scope.validate()
        || intent.addresses.len() != 1
        || !matches!(intent.addresses[0], ipnet::IpNet::V4(a) if a.prefix_len() == 32
            && !a.addr().is_unspecified() && !a.addr().is_loopback() && !a.addr().is_multicast()
            && !a.addr().is_broadcast() && !a.addr().is_link_local()
            && a.addr().octets()[0] != 0 && a.addr().octets()[0] < 240)
        || provenance.boot_id == [0; 16]
        || provenance.network_epoch == 0
        || r.slot != intent.scope.runtime
        || r.runtime_contract_version == 0
        || [&r.runtime_version, &r.container_version]
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        || r.manifest_sha256.len() != 64
        || !r
            .manifest_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CarrierError::Invalid);
    }
    Ok(())
}
fn desired_rows(intent: &Intent) -> [RowValue; 2] {
    [
        RowValue::Address(Some(AddressRow {
            address: intent.addresses[0],
            skip_as_source: false,
            preferred_lifetime: u32::MAX,
            valid_lifetime: u32::MAX,
        })),
        RowValue::WeakHost(WeakHostRow {
            send: true,
            receive: true,
        }),
    ]
}
/// Structural validation is pure and precedes journal effects. This retained
/// logical schema is not a Windows ABI. No boot/epoch migration grants native trust.
pub(crate) fn validate_record_shape(record: &Record) -> Result<()> {
    validate_intent(&record.intent, &record.provenance)?;
    if record.version != VERSION || record.generation == 0 {
        return Err(CarrierError::Invalid);
    }
    match (record.proof, &record.rows) {
        (None, None)
            if matches!(
                record.phase,
                Phase::Prepared | Phase::Closing | Phase::Stopped
            ) =>
        {
            return Ok(())
        }
        (Some(proof), Some(rows)) if record.phase != Phase::Prepared => {
            if proof.index == 0
                || proof.luid == 0
                || proof.guid != carrier_key(&record.intent.scope)?.guid
                || rows[0].baseline != RowValue::Address(None)
                || !matches!(rows[1].baseline, RowValue::WeakHost(_))
            {
                return Err(CarrierError::Invalid);
            }
            let goal = desired_rows(&record.intent);
            let mut pending = 0;
            for (i, row) in rows.iter().enumerate() {
                if row.current != row.baseline && row.current != goal[i] {
                    return Err(CarrierError::Invalid);
                }
                if let Some(value) = &row.pending {
                    pending += 1;
                    if value == &row.current
                        || (value != &goal[i] && value != &row.baseline)
                        || (record.phase == Phase::Created && value != &goal[i])
                    {
                        return Err(CarrierError::Invalid);
                    }
                }
                if record.phase == Phase::Configured
                    && (row.current != goal[i] || row.pending.is_some())
                    || record.phase == Phase::Stopped
                        && (row.current != row.baseline || row.pending.is_some())
                {
                    return Err(CarrierError::Invalid);
                }
            }
            if pending > 1 {
                return Err(CarrierError::Invalid);
            }
        }
        _ => return Err(CarrierError::Invalid),
    }
    Ok(())
}
#[cfg(test)]
#[path = "member_carrier_tests.rs"]
mod tests;
