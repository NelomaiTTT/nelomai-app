//! Shared desktop redundancy policy. Native ownership and I/O belong to helpers.

mod health;
mod probes;

pub use health::{
    BackendHealth, FailoverDecision, RedundantHealthMonitor, SlotObservation, StandbyProbeState,
};
pub use probes::{ProbeBatch, ProbeSchedule, ProbeTicket};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}
