//! Native route/DNS operations for the session owner, separate from either slot.
//! This module does not start tunnels or activate the feature on its own.
#[cfg(any(target_os = "macos", test))]
pub mod factory;
#[cfg(test)]
mod factory_tests;
pub mod journal;
#[cfg(any(target_os = "linux", test))]
pub mod linux;
#[cfg(any(target_os = "macos", test))]
pub mod macos;
pub mod members;
pub mod session;
