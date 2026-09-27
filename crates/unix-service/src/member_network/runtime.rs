//! Platform composition under the existing engine mutation lock.
use super::{
    actor::PairFactory,
    driver::{open_session_store, SessionNativePair},
    journal::ScopedJournal,
    runtime_directory::RuntimeDirectory,
};
use nelomai_client_tunnel::redundancy::{
    control::SessionControl,
    protocol::Command,
    session::{SessionSnapshot, SessionState},
    SessionScope,
};
use nelomai_contracts::RuntimeSlot;
use std::{
    io,
    path::{Path, PathBuf},
};

#[cfg(target_os = "macos")]
type Pair = super::factory::MacPair;
#[cfg(target_os = "linux")]
type Pair = super::factory::LinuxPair;
#[cfg(target_os = "macos")]
type Network = super::macos::MacNetwork<super::macos::NativeMacCommands>;
#[cfg(target_os = "linux")]
type Network = super::linux::LinuxNetwork<super::linux::NativeLinuxCommands>;
type Native =
    SessionNativePair<crate::PlatformBackend, Network, super::journal::FileNetworkJournal>;

pub struct NativePairFactory {
    directory: RuntimeDirectory,
    runtime: RuntimeSlot,
    binaries: PathBuf,
}
impl NativePairFactory {
    pub fn new(root: &Path, runtime: RuntimeSlot, binaries: &Path) -> io::Result<Self> {
        Ok(Self {
            directory: RuntimeDirectory::open(root)?,
            runtime,
            binaries: binaries.into(),
        })
    }
    fn open_pair(&self, root: &Path, scope: SessionScope) -> io::Result<Pair> {
        #[cfg(target_os = "macos")]
        let result = super::factory::open_mac_pair(
            root,
            scope,
            &self.binaries.join("wireguard-go"),
            &self.binaries.join("amneziawg-go"),
        );
        #[cfg(target_os = "linux")]
        let result =
            super::factory::open_linux_pair(root, scope, &self.binaries.join("amneziawg-go"));
        result.map_err(|_| failed())
    }
}
impl PairFactory for NativePairFactory {
    type Native = Native;
    type Store = ScopedJournal<SessionSnapshot>;
    fn recover(&mut self) -> Result<(), crate::ServiceError> {
        self.directory
            .recover(|root, scope| {
                #[cfg(target_os = "macos")]
                let (boot, system) = (
                    crate::backend::macos_boot_identity().map_err(|_| failed())?,
                    super::macos::MacNetwork {
                        commands: super::macos::NativeMacCommands,
                    },
                );
                #[cfg(target_os = "linux")]
                let (boot, system) = (
                    crate::backend::linux_boot_identity().map_err(|_| failed())?,
                    super::linux::LinuxNetwork::new(super::linux::NativeLinuxCommands::new()?, [])?,
                );
                if super::factory::cleanup_previous_boot(root, scope.clone(), &boot, 0, system)? {
                    return Ok(());
                }
                self.open_pair(root, scope.clone())?
                    .close(scope)
                    .map_err(|_| failed())
            })
            .map_err(|_| crate::ServiceError::Backend("member_recovery_failed".into()))
    }
    fn prepare(
        &mut self,
        command: &Command,
        now: u64,
    ) -> io::Result<SessionControl<Native, Self::Store>> {
        command.validate(self.runtime)?;
        let Command::Start {
            scope,
            primary,
            role_generation,
            membership_generation,
            ..
        } = command
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redundant_start_required",
            ));
        };
        crate::parse_configuration(primary.configuration.expose()).map_err(|_| failed())?;
        let initial = SessionState::new(
            scope.clone(),
            primary.slot,
            *role_generation,
            *membership_generation,
        )
        .map_err(|_| failed())?;
        self.recover().map_err(|_| failed())?;
        let root = self.directory.create(scope)?;
        // Bootstrap must precede the role journal: SessionDirectory refuses to
        // adopt nonempty unsealed directories, including a lone role snapshot.
        let pair = self.open_pair(&root, scope.clone())?;
        let store = open_session_store(&root, scope.clone(), &initial.snapshot())?;
        let native = SessionNativePair::new(scope.clone(), pair)?;
        SessionControl::prepare(self.runtime, command, native, store, now)
    }
}
fn failed() -> io::Error {
    io::Error::other("member_runtime_factory_failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn unauthenticated_runtime_and_nonstart_never_create_pair_files() {
        let root = tempfile::Builder::new()
            .prefix("native-factory-")
            .tempdir()
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory =
            RuntimeDirectory::for_owner(root.path(), unsafe { libc::geteuid() }).unwrap();
        let mut factory = NativePairFactory {
            directory,
            runtime: RuntimeSlot::Latest,
            binaries: root.path().join("do-not-run"),
        };
        let scope = SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 10,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 1,
        };
        let command:Command=serde_json::from_value(serde_json::json!({"action":"start","scope":scope,"primary":{"slot":"A","lease_id":"22222222-2222-4222-8222-222222222222","configuration":"secret fake","probe":{"kind":"dns_a","target_ipv4":"9.9.9.9","query_name":"example.com","timeout_ms":2000}},"role_generation":0,"membership_generation":0,"warm_stop_v1":false,"options":nelomai_client_tunnel::DesktopTunnelOptions::default()})).unwrap();
        let error = factory.prepare(&command, 0).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(factory.prepare(&Command::Stop { scope }, 0).is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
