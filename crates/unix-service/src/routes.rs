#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux;
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos;

use crate::ServiceError;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub(crate) use linux::{ip_command, LinuxOrdinaryRoutes, SystemRouteBackend};
#[cfg(target_os = "macos")]
pub(crate) use macos::{endpoint_route_summary, verify_endpoint_routes, SystemRouteBackend};

const ROUTE_STATE_FILE: &str = "routes-state.json";
const ROUTE_STATE_FORMAT: u16 = 1;
const MAX_STATE_SIZE: u64 = 4 * 1024 * 1024;
const MAX_ROUTES: usize = 16_384;

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct OwnedRoute {
    pub destination: String,
    pub interface_identifier: String,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
}

impl fmt::Debug for OwnedRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedRoute(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteScope {
    Unscoped,
    #[cfg(any(target_os = "macos", test))]
    InterfaceScoped,
}

#[derive(Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct OwnedRouteState {
    pub format_version: u16,
    pub policy_hash: Option<String>,
    pub routes: Vec<OwnedRoute>,
    #[serde(default)]
    pub pending_routes: Vec<OwnedRoute>,
}

impl fmt::Debug for OwnedRouteState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedRouteState")
            .field("format_version", &self.format_version)
            .field("policy_hash_present", &self.policy_hash.is_some())
            .field("routes_count", &self.routes.len())
            .field("pending_routes_count", &self.pending_routes.len())
            .finish()
    }
}

pub(crate) trait RouteBackend {
    type Egress;

    fn discover_egress(&self) -> Result<Self::Egress, ServiceError>;
    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError>;
    fn fingerprint_material(&self, egress: &Self::Egress, local_networks: &[Ipv4Net]) -> String;
    fn route_presence(
        &self,
        routes: &[OwnedRoute],
    ) -> Result<Vec<Option<RouteScope>>, ServiceError>;
}

pub(crate) struct RouteManager<B> {
    backend: B,
    state_path: PathBuf,
    state: OwnedRouteState,
}

impl<B: RouteBackend> RouteManager<B> {
    pub(crate) fn new(
        runtime_directory: impl AsRef<Path>,
        backend: B,
    ) -> Result<Self, ServiceError> {
        let state_path = runtime_directory.as_ref().join(ROUTE_STATE_FILE);
        let state = load_state(&state_path)?;
        Ok(Self {
            backend,
            state_path,
            state,
        })
    }

    /// Older versions installed gateway routes in the shared OS table. The old
    /// journal records their values, but cannot distinguish a matching foreign
    /// replacement. Only retire the journal after those values have disappeared.
    pub(crate) fn cleanup(&mut self) -> Result<(), ServiceError> {
        if self.has_routes() {
            let rows: Vec<_> = self
                .state
                .routes
                .iter()
                .chain(&self.state.pending_routes)
                .cloned()
                .collect();
            let live = self.backend.route_presence(&rows)?;
            if live.len() != rows.len() || live.iter().any(Option::is_some) {
                return Err(ServiceError::Backend(
                    "network_route_ownership_unconfirmed".into(),
                ));
            }
        }
        remove_state(&self.state_path)?;
        self.state.routes.clear();
        self.state.pending_routes.clear();
        self.state.policy_hash = None;
        Ok(())
    }

    pub(crate) fn has_routes(&self) -> bool {
        !self.state.routes.is_empty() || !self.state.pending_routes.is_empty()
    }

    pub(crate) fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        let egress = self.backend.discover_egress()?;
        let mut local_networks = self.backend.local_networks(&egress)?;
        local_networks.sort_unstable();
        local_networks.dedup();
        let material = self.backend.fingerprint_material(&egress, &local_networks);
        let digest = Sha256::digest(material.as_bytes());
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

fn load_state(path: &Path) -> Result<OwnedRouteState, ServiceError> {
    if !path.exists() {
        return Ok(OwnedRouteState {
            format_version: ROUTE_STATE_FORMAT,
            ..OwnedRouteState::default()
        });
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ServiceError::Backend("route_state_read_failed".to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_STATE_SIZE
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    let bytes =
        fs::read(path).map_err(|_| ServiceError::Backend("route_state_read_failed".to_string()))?;
    let state: OwnedRouteState = serde_json::from_slice(&bytes)
        .map_err(|_| ServiceError::Backend("route_state_invalid".to_string()))?;
    if state.format_version != ROUTE_STATE_FORMAT
        || state
            .routes
            .len()
            .saturating_add(state.pending_routes.len())
            > MAX_ROUTES
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    Ok(state)
}

fn remove_state(path: &Path) -> Result<(), ServiceError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ServiceError::Backend(
            "route_state_remove_failed".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeBackend {
        installed: RefCell<Vec<String>>,
    }

    impl RouteBackend for FakeBackend {
        type Egress = ();

        fn discover_egress(&self) -> Result<Self::Egress, ServiceError> {
            Ok(())
        }

        fn local_networks(&self, _egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError> {
            Ok(vec!["192.168.1.0/24".parse().unwrap()])
        }

        fn fingerprint_material(
            &self,
            _egress: &Self::Egress,
            local_networks: &[Ipv4Net],
        ) -> String {
            format!("fake\0{local_networks:?}")
        }

        fn route_presence(
            &self,
            routes: &[OwnedRoute],
        ) -> Result<Vec<Option<RouteScope>>, ServiceError> {
            Ok(routes
                .iter()
                .map(|r| {
                    self.installed
                        .borrow()
                        .contains(&r.destination)
                        .then_some(RouteScope::Unscoped)
                })
                .collect())
        }
    }

    #[test]
    fn legacy_committed_and_pending_rows_never_grant_authority_to_delete() {
        use std::os::unix::fs::PermissionsExt;
        for pending in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(ROUTE_STATE_FILE);
            let route = OwnedRoute {
                destination: "203.0.113.0/24".into(),
                interface_identifier: "en0".into(),
                gateway: Some("192.168.1.1".into()),
                metric: None,
            };
            let mut state = OwnedRouteState {
                format_version: 1,
                ..Default::default()
            };
            if pending {
                state.pending_routes.push(route.clone());
            } else {
                state.routes.push(route.clone());
            }
            fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let backend = FakeBackend::default();
            backend
                .installed
                .borrow_mut()
                .push(route.destination.clone());
            let mut manager = RouteManager::new(dir.path(), backend).unwrap();
            assert_eq!(
                manager.cleanup().unwrap_err().code(),
                "network_route_ownership_unconfirmed"
            );
            assert_eq!(&*manager.backend.installed.borrow(), &[route.destination]);
            assert!(path.exists());
            manager.backend.installed.borrow_mut().clear();
            manager.cleanup().unwrap();
            assert!(!manager.has_routes());
            assert!(!path.exists());
        }
    }

    #[test]
    fn physical_network_fingerprint_is_stable_and_opaque() {
        let directory = tempfile::tempdir().unwrap();
        let manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();

        let fingerprint = manager.physical_network_fingerprint().unwrap();

        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!fingerprint.contains("192.168.1.0"));
    }

    #[test]
    fn state_file_with_group_permissions_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join(ROUTE_STATE_FILE);
        fs::write(
            &state_path,
            br#"{"format_version":1,"policy_hash":null,"routes":[]}"#,
        )
        .unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o640)).unwrap();

        let error = match RouteManager::new(directory.path(), FakeBackend::default()) {
            Ok(_) => panic!("unsafe state permissions must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code(), "route_state_invalid");
    }
}
