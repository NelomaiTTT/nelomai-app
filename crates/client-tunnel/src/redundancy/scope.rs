use nelomai_contracts::RuntimeSlot;
use serde::{Deserialize, Serialize};

/// Not the server role generation: this fences the local Start intent as well
/// as Stable/Latest's independently authenticated device session generations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionScope {
    pub runtime: RuntimeSlot,
    pub runtime_generation: u64,
    pub session_id: String,
    pub connection_generation: u64,
}
impl SessionScope {
    pub fn validate(&self) -> bool {
        let bytes = self.session_id.as_bytes();
        self.runtime_generation > 0
            && self.runtime_generation <= i64::MAX as u64
            && self.connection_generation > 0
            && bytes.len() == 36
            && bytes.iter().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            })
    }
}
