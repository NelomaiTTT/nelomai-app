mod backend;
mod defender;
mod defender_layout;
mod elevation;
mod install;
mod ipc;
pub(crate) mod member_boot;
mod member_carrier_assembly;
mod member_carrier_bootstrap;
mod member_carrier_control;
mod member_carrier_coordinator;
mod member_carrier_coordinator_rows;
mod member_carrier_creator;
mod member_carrier_creators;
mod member_carrier_factory;
mod member_carrier_guard;
mod member_carrier_guard_attestor;
mod member_carrier_guard_gate;
mod member_carrier_key_authority;
mod member_carrier_keys;
mod member_carrier_lifecycle_gate;
mod member_carrier_member_controller;
mod member_carrier_member_gate;
mod member_carrier_members;
mod member_carrier_module;
mod member_carrier_module_terminal_read;
mod member_carrier_network;
mod member_carrier_network_baseline;
mod member_carrier_network_gate;
mod member_carrier_network_owner;
mod member_carrier_original_read;
mod member_carrier_pair_io;
mod member_carrier_pair_store;
mod member_carrier_payload;
mod member_carrier_preload;
mod member_carrier_probe_gate;
mod member_carrier_probes;
mod member_carrier_provider;
mod member_carrier_ready;
mod member_carrier_recovery;
mod member_carrier_recovery_guard;
mod member_carrier_rows;
mod member_carrier_runtime;
mod member_carrier_startup;
mod member_carrier_terminal_graph;
mod member_carrier_terminal_release;
mod member_carrier_wintun;
mod member_carrier_wintun_lock;
mod member_carrier_wintun_package;
mod member_dns;
mod member_files;
mod member_guard;
pub mod member_metrics;
mod member_native_deadline;
pub(crate) mod member_owner;
mod member_pair;
pub(crate) mod member_physical;
pub mod member_routes;
mod member_session;
mod ringlogger;
mod routes;
mod service;

pub use defender::configure_exclusion;
pub use elevation::{repair_defender_exclusion, repair_installation, RepairError};
pub(crate) use install::record_service_diagnostic;
pub use install::{install, uninstall, uninstall_from_bundle, uninstall_staged, InstallOptions};
pub use ipc::{dispatcher_exchange, NamedPipeTransport};
pub use service::{
    run_amneziawg_service, run_amneziawg_slot_service, run_engine_mode, run_manager_service,
    run_wireguard_service,
};

use crate::ServiceError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub(crate) fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn platform_error(context: &str, error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(format!("{context}: {error}"))
}
