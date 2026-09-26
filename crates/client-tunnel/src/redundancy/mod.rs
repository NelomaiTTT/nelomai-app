//! Shared desktop redundancy policy. Native ownership and I/O belong to helpers.

mod dns_probe;
mod health;
pub mod network;
mod probe_socket;
mod probes;
pub mod route_plan;
mod scope;
pub use scope::SessionScope;

pub use dns_probe::{DnsProbe, ProbeDatagram, ProbePoll};
pub use probe_socket::NativeProbeSocket;

pub use health::{
    BackendHealth, FailoverDecision, RedundantHealthMonitor, SlotObservation, StandbyProbeState,
};
pub use probes::{ProbeBatch, ProbeSchedule, ProbeTicket};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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
