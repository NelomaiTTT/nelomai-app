mod backend;
mod defender;
mod defender_layout;
mod elevation;
mod install;
mod ipc;
pub(crate) mod member_boot;
mod member_carrier_guard;
mod member_carrier_key_authority;
mod member_carrier_keys;
mod member_carrier_module;
mod member_carrier_payload;
mod member_carrier_preload;
mod member_carrier_rows;
mod member_carrier_wintun;
mod member_carrier_wintun_lock;
mod member_carrier_wintun_package;
mod member_dns;
mod member_files;
mod member_guard;
pub mod member_metrics;
mod member_owner;
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
pub use install::{install, uninstall, InstallOptions};
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
