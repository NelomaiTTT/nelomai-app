//! Portable C-only row comparison. Success is a factual match, never an
//! ownership, native-effect, or address-readiness grant.
//!
//! The caller must independently authenticate the actual Runtime/Calling,
//! original registry and full SDK before/after universe, source/protected Pair,
//! native/session pins, and the original RowOwner creation provenance at the
//! effect seam. Durable creation metadata cannot reconstruct an opaque ACK.

use crate::member_carrier_rows::{
    same_address, same_owned, Binding, Error, Phase, Record, Result, Role, Snapshot, Target,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    Observe,
    Delete,
    Stopped,
}

/// Compare complete validated portable rows under the narrower C-only policy.
/// Readonly interface observations and valid DAD transitions are not policy
/// changes; address scope and creation timestamp remain replacement fences.
/// No input is modified and no creation history or capability is issued.
pub(crate) fn compare(
    binding: &Binding,
    saved: &Record,
    actual: &Snapshot,
    stage: Stage,
) -> Result<()> {
    binding.validate()?;
    saved.validate()?;
    actual.validate(binding)?;
    if binding.role != Role::Carrier || saved.binding != *binding {
        return Err(Error::Conflict);
    }

    let baseline = &saved.baseline.interface.policy;
    if saved.baseline.address.is_some()
        || baseline.weak_host_send
        || baseline.weak_host_receive
        || baseline.forwarding
        || baseline.advertising
        || saved.current.interface.policy != *baseline
        || actual.interface.policy != *baseline
    {
        return Err(Error::Conflict);
    }

    match stage {
        Stage::Observe => {} // Record::validate restricts phases and stopped state.
        Stage::Delete => {
            if saved.phase != Phase::Closing
                || saved.creation.is_none()
                || !matches!(
                    saved.pending.as_ref().map(|p| &p.target),
                    Some(Target::Delete)
                )
            {
                return Err(Error::Conflict);
            }
        }
        Stage::Stopped => {
            return if saved.phase == Phase::Stopped
                && saved.pending.is_none()
                && saved.current.address.is_none()
                && actual.address.is_none()
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
    }

    let Some(pending) = &saved.pending else {
        return if same_owned(&saved.current, actual) {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    };

    let matches = match &pending.target {
        Target::Interface(policy) => {
            // Even an unapplied weak-host change is outside the C-only path.
            // The permitted target equals before/baseline, so both sides use
            // the same complete ownership comparison.
            *policy == *baseline && same_owned(&pending.before, actual)
        }
        Target::Create(policy) => {
            // With no creation ACK, only before/desired-policy facts may be
            // observed. This neither adopts the observed stamp nor grants a
            // later delete; Delete above requires original saved history and
            // an exact Closing/Delete intent, plus caller-owned live provenance.
            same_owned(&pending.before, actual)
                || actual
                    .address
                    .as_ref()
                    .is_some_and(|a| a.policy == *policy && a.observed.creation_timestamp > 0)
        }
        Target::Delete => {
            saved.phase == Phase::Closing
                && saved.creation.as_ref().is_some_and(|creation| {
                    pending.before.address.as_ref().is_some_and(|before| {
                        same_address(creation, before)
                            && (same_owned(&pending.before, actual) || actual.address.is_none())
                    })
                })
        }
    };
    if matches {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

#[cfg(test)]
#[path = "member_carrier_coordinator_rows_tests.rs"]
mod tests;
