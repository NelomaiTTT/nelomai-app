//! Installed trust/selection inputs. Packaging provisions these explicitly;
//! absent inputs block startup rather than selecting a compiled runtime.
use nelomai_client_api::RuntimeTarget;
use nelomai_contracts::{verify_container_manifest, RuntimeSlot, VerifiedContainerManifest};
use serde::Deserialize;
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

pub struct InstalledRuntimeSelection {
    manifest: VerifiedContainerManifest,
    target: RuntimeTarget,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSelection {
    schema_version: u32,
    slot: RuntimeSlot,
}
fn blocked() -> io::Error {
    io::Error::other("runtime_startup_blocked: verified installed manifest, selection and pinned Ed25519 trust are required")
}
fn read_bounded(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| blocked())?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| blocked())?;
    if bytes.len() > max {
        return Err(blocked());
    }
    Ok(bytes)
}
impl InstalledRuntimeSelection {
    pub fn load(
        resources: &Path,
        selection: &Path,
        pinned_raw_key: Option<&[u8]>,
        platform: &str,
        architecture: &str,
    ) -> io::Result<Self> {
        let key = pinned_raw_key
            .filter(|key| key.len() == 32)
            .ok_or_else(blocked)?;
        let bytes = read_bounded(&resources.join("container-manifest-v1.json"), 1024 * 1024)?;
        let signature = read_bounded(&resources.join("container-manifest-v1.sig"), 64)?;
        let manifest = verify_container_manifest(&bytes, &signature, key, platform, architecture)
            .map_err(|_| blocked())?;
        let selected: SavedSelection =
            serde_json::from_slice(&read_bounded(selection, 4096)?).map_err(|_| blocked())?;
        if selected.schema_version != 1 {
            return Err(blocked());
        }
        let identity = manifest
            .identity(selected.slot, None)
            .map_err(|_| blocked())?;
        Ok(Self {
            manifest,
            target: RuntimeTarget::from_identity(&identity),
        })
    }
    pub fn manifest(&self) -> &VerifiedContainerManifest {
        &self.manifest
    }
    pub fn target(&self) -> &RuntimeTarget {
        &self.target
    }
}
