//! Signed runtime-v1 metadata contracts.
//!
//! Contract-version fields are positive integers on the wire. `runtime-v1`
//! names this protocol revision; it is not a serialized contract identifier.
//! All three signatures use plain Ed25519 over the domain bytes followed by
//! the exact canonical JSON bytes (not Ed25519ph): container manifests use
//! [`CONTAINER_MANIFEST_SIGNATURE_DOMAIN`], platform manifests use
//! [`RUNTIME_MANIFEST_SIGNATURE_DOMAIN`], and release-set roots use
//! [`RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN`]. Canonical JSON is sorted-key
//! UTF-8 without insignificant whitespace, matching the Python release
//! serializer.
//!
//! Verification here authenticates and validates metadata only. It does not
//! open archives, read payload files, or prove that payload bytes match the
//! signed sizes and hashes. Packaging and installation consumers must perform
//! those separate checks before using a runtime.

use std::{collections::HashSet, fmt};

use caseless::Caseless;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const COMPILED_RUNTIME_CONTRACT_VERSION: u32 = 1;
pub const CONTAINER_MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"nelomai-container-manifest-v1\0";
pub const RUNTIME_MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"nelomai-runtime-manifest-v1\0";
pub const RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN: &[u8] = b"nelomai-runtime-release-set-v1\0";

const FORMAT_VERSION_V1: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_RUNTIME_FILES: usize = 4096;
const MAX_STRING_BYTES: usize = 1024;
const MAX_RUNTIME_VERSION_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSlot {
    Latest,
    Stable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub slot: RuntimeSlot,
    pub runtime_version: String,
    pub runtime_contract_version: u32,
    pub container_version: String,
    pub session_generation: Option<u64>,
}

impl RuntimeIdentity {
    /// Applies the panel-compatible positive integer bounds. This validates a
    /// persisted identity, not whether the current binary can execute that
    /// contract revision; manifest verification enforces compiled support.
    pub fn validate(&self) -> Result<(), RuntimeManifestError> {
        validate_runtime_version(&self.runtime_version)?;
        validate_runtime_version(&self.container_version)?;
        if self.runtime_contract_version == 0 || self.runtime_contract_version > i32::MAX as u32 {
            return Err(RuntimeManifestError::InvalidField);
        }
        if self
            .session_generation
            .is_some_and(|generation| generation == 0 || generation > i64::MAX as u64)
        {
            return Err(RuntimeManifestError::InvalidSessionGeneration);
        }
        Ok(())
    }
}

/// Packaging role used by installers to apply file-specific policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFileRole {
    /// A directly launched helper or tunnel executable.
    Executable,
    /// A dynamically loaded runtime library such as a tunnel DLL.
    SharedLibrary,
    /// A non-executable file consumed by the runtime.
    Resource,
    /// License or attribution text shipped with the runtime.
    License,
    /// Build/provenance metadata shipped for diagnostics.
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFileV1 {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub role: RuntimeFileRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifactManifestV1 {
    pub format_version: u32,
    pub runtime_version: String,
    pub source_commit: String,
    pub platform: String,
    pub architecture: String,
    pub contract_version: u32,
    pub files: Vec<RuntimeFileV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSlotManifestV1 {
    pub slot: RuntimeSlot,
    pub manifest: RuntimeArtifactManifestV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerManifestV1 {
    pub format_version: u32,
    pub container_version: String,
    pub release_set_id: String,
    pub minimum_runtime_contract: u32,
    pub maximum_runtime_contract: u32,
    /// SHA-256 of the distinct stable release-set root's exact canonical
    /// bytes, never of a platform manifest and never embedded in that root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_release_set_sha256: Option<String>,
    /// SHA-256 of the stable platform manifest selected for this container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_platform_manifest_sha256: Option<String>,
    pub slots: Vec<RuntimeSlotManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReleaseArtifactV1 {
    pub platform: String,
    pub architecture: String,
    pub archive_name: String,
    pub archive_sha256: String,
    pub manifest_name: String,
    pub manifest_sha256: String,
    pub signature_name: String,
    pub signature_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReleaseSetManifestV1 {
    pub format_version: u32,
    pub release_set_id: String,
    pub runtime_version: String,
    pub source_commit: String,
    pub artifacts: Vec<RuntimeReleaseArtifactV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeManifestError {
    InputTooLarge,
    InvalidSignature,
    InvalidJson,
    NonCanonicalJson,
    UnsupportedFormatVersion,
    InvalidContractRange,
    UnsupportedContract,
    WrongTarget,
    InvalidPath,
    DuplicatePath,
    InvalidDigest,
    DigestMismatch,
    InvalidSlots,
    InvalidStableDigests,
    InvalidReleaseSet,
    InvalidSessionGeneration,
    InvalidField,
}

impl fmt::Display for RuntimeManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "runtime manifest exceeds the input limit",
            Self::InvalidSignature => "runtime manifest signature is invalid",
            Self::InvalidJson => "runtime manifest JSON is invalid",
            Self::NonCanonicalJson => "runtime manifest JSON is not canonical",
            Self::UnsupportedFormatVersion => "runtime manifest format is unsupported",
            Self::InvalidContractRange => "runtime contract range is invalid",
            Self::UnsupportedContract => "runtime contract is unsupported",
            Self::WrongTarget => "runtime manifest target does not match the container",
            Self::InvalidPath => "runtime manifest path is not portable and relative",
            Self::DuplicatePath => "runtime manifest contains colliding paths",
            Self::InvalidDigest => "runtime manifest digest is invalid",
            Self::DigestMismatch => "runtime manifest digest does not match",
            Self::InvalidSlots => "runtime container slots are invalid",
            Self::InvalidStableDigests => "runtime stable digest linkage is invalid",
            Self::InvalidReleaseSet => "runtime release set is incomplete or duplicated",
            Self::InvalidSessionGeneration => "runtime session generation must be positive",
            Self::InvalidField => "runtime manifest field is invalid",
        })
    }
}

impl std::error::Error for RuntimeManifestError {}

/// Authenticated container metadata. Fields cannot be mutated after verification.
#[derive(Debug, Clone)]
pub struct VerifiedContainerManifest {
    manifest: ContainerManifestV1,
    latest_index: usize,
    stable_index: Option<usize>,
}

impl VerifiedContainerManifest {
    pub fn manifest(&self) -> &ContainerManifestV1 {
        &self.manifest
    }

    pub fn latest(&self) -> &RuntimeArtifactManifestV1 {
        &self.manifest.slots[self.latest_index].manifest
    }

    /// Returns only a distinct selectable stable runtime. An equal-version
    /// stable slot remains visible through `manifest()` as packaging evidence.
    pub fn stable(&self) -> Option<&RuntimeArtifactManifestV1> {
        self.stable_index
            .map(|index| &self.manifest.slots[index].manifest)
    }

    pub fn selected(&self, slot: RuntimeSlot) -> Option<&RuntimeArtifactManifestV1> {
        match slot {
            RuntimeSlot::Latest => Some(self.latest()),
            RuntimeSlot::Stable => self.stable(),
        }
    }

    /// Builds an identity from the exact signed manifest selected by `slot`.
    /// No session generation is invented: callers pass `None` for unenrolled
    /// sessions and an existing positive generation otherwise.
    pub fn identity(
        &self,
        slot: RuntimeSlot,
        session_generation: Option<u64>,
    ) -> Result<RuntimeIdentity, RuntimeManifestError> {
        let selected = self
            .selected(slot)
            .ok_or(RuntimeManifestError::InvalidSlots)?;
        let identity = RuntimeIdentity {
            slot,
            runtime_version: selected.runtime_version.clone(),
            runtime_contract_version: selected.contract_version,
            container_version: self.manifest.container_version.clone(),
            session_generation,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn stable_release_set_sha256(&self) -> Option<&str> {
        self.manifest.stable_release_set_sha256.as_deref()
    }

    pub fn stable_platform_manifest_sha256(&self) -> Option<&str> {
        self.manifest.stable_platform_manifest_sha256.as_deref()
    }
}

/// Authenticated platform-manifest metadata and the digest of its exact bytes.
#[derive(Debug, Clone)]
pub struct VerifiedRuntimeArtifactManifest {
    manifest: RuntimeArtifactManifestV1,
    sha256: String,
}

impl VerifiedRuntimeArtifactManifest {
    pub fn manifest(&self) -> &RuntimeArtifactManifestV1 {
        &self.manifest
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Authenticated release-set metadata and the digest of its exact root bytes.
#[derive(Debug, Clone)]
pub struct VerifiedRuntimeReleaseSetManifest {
    manifest: RuntimeReleaseSetManifestV1,
    sha256: String,
}

impl VerifiedRuntimeReleaseSetManifest {
    pub fn manifest(&self) -> &RuntimeReleaseSetManifestV1 {
        &self.manifest
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn artifact(
        &self,
        platform: &str,
        architecture: &str,
    ) -> Option<&RuntimeReleaseArtifactV1> {
        self.manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.platform == platform && artifact.architecture == architecture)
    }
}

pub fn verify_container_manifest(
    bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    platform: &str,
    architecture: &str,
) -> Result<VerifiedContainerManifest, RuntimeManifestError> {
    verify_signature_first(
        bytes,
        signature,
        public_key,
        CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
    )?;
    let manifest: ContainerManifestV1 = parse_canonical(bytes)?;
    validate_container(manifest, platform, architecture)
}

pub fn verify_runtime_artifact_manifest(
    bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    platform: &str,
    architecture: &str,
) -> Result<VerifiedRuntimeArtifactManifest, RuntimeManifestError> {
    verify_signature_first(
        bytes,
        signature,
        public_key,
        RUNTIME_MANIFEST_SIGNATURE_DOMAIN,
    )?;
    let manifest: RuntimeArtifactManifestV1 = parse_canonical(bytes)?;
    validate_artifact(&manifest, platform, architecture)?;
    Ok(VerifiedRuntimeArtifactManifest {
        manifest,
        sha256: sha256_hex(bytes),
    })
}

pub fn verify_runtime_release_set_manifest(
    bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    expected_sha256: &str,
) -> Result<VerifiedRuntimeReleaseSetManifest, RuntimeManifestError> {
    verify_signature_first(
        bytes,
        signature,
        public_key,
        RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN,
    )?;
    if !valid_sha256(expected_sha256) {
        return Err(RuntimeManifestError::InvalidDigest);
    }
    let sha256 = sha256_hex(bytes);
    if sha256 != expected_sha256 {
        return Err(RuntimeManifestError::DigestMismatch);
    }
    let manifest: RuntimeReleaseSetManifestV1 = parse_canonical(bytes)?;
    validate_release_set(&manifest)?;
    Ok(VerifiedRuntimeReleaseSetManifest { manifest, sha256 })
}

fn verify_signature_first(
    bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    domain: &[u8],
) -> Result<(), RuntimeManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(RuntimeManifestError::InputTooLarge);
    }
    let key_bytes: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| RuntimeManifestError::InvalidSignature)?;
    let key =
        VerifyingKey::from_bytes(key_bytes).map_err(|_| RuntimeManifestError::InvalidSignature)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| RuntimeManifestError::InvalidSignature)?;
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    key.verify_strict(&message, &signature)
        .map_err(|_| RuntimeManifestError::InvalidSignature)
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, RuntimeManifestError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| RuntimeManifestError::InvalidJson)?;
    let serialized = serde_json::to_value(&value).map_err(|_| RuntimeManifestError::InvalidJson)?;
    if canonical_json(&serialized) != bytes {
        return Err(RuntimeManifestError::NonCanonicalJson);
    }
    Ok(value)
}

fn canonical_json(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut Vec<u8>) {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(true) => output.extend_from_slice(b"true"),
            Value::Bool(false) => output.extend_from_slice(b"false"),
            Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
            Value::String(string) => output.extend_from_slice(
                serde_json::to_string(string)
                    .expect("serializing a JSON string cannot fail")
                    .as_bytes(),
            ),
            Value::Array(items) => {
                output.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(item, output);
                }
                output.push(b']');
            }
            Value::Object(fields) => {
                output.push(b'{');
                let mut fields: Vec<_> = fields.iter().collect();
                fields.sort_unstable_by(|left, right| left.0.cmp(right.0));
                for (index, (key, value)) in fields.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(
                        serde_json::to_string(key)
                            .expect("serializing a JSON key cannot fail")
                            .as_bytes(),
                    );
                    output.push(b':');
                    write(value, output);
                }
                output.push(b'}');
            }
        }
    }

    let mut output = Vec::new();
    write(value, &mut output);
    output
}

fn validate_container(
    manifest: ContainerManifestV1,
    platform: &str,
    architecture: &str,
) -> Result<VerifiedContainerManifest, RuntimeManifestError> {
    if manifest.format_version != FORMAT_VERSION_V1 {
        return Err(RuntimeManifestError::UnsupportedFormatVersion);
    }
    validate_runtime_version(&manifest.container_version)?;
    validate_text(&manifest.release_set_id)?;
    if manifest.minimum_runtime_contract == 0
        || manifest.maximum_runtime_contract == 0
        || manifest.minimum_runtime_contract > manifest.maximum_runtime_contract
    {
        return Err(RuntimeManifestError::InvalidContractRange);
    }
    if !(manifest.minimum_runtime_contract..=manifest.maximum_runtime_contract)
        .contains(&COMPILED_RUNTIME_CONTRACT_VERSION)
    {
        return Err(RuntimeManifestError::UnsupportedContract);
    }
    if manifest.slots.is_empty() || manifest.slots.len() > 2 {
        return Err(RuntimeManifestError::InvalidSlots);
    }

    let mut latest_index = None;
    let mut stable_slot_index = None;
    for (index, slot) in manifest.slots.iter().enumerate() {
        validate_artifact(&slot.manifest, platform, architecture)?;
        match slot.slot {
            RuntimeSlot::Latest if latest_index.replace(index).is_some() => {
                return Err(RuntimeManifestError::InvalidSlots)
            }
            RuntimeSlot::Stable if stable_slot_index.replace(index).is_some() => {
                return Err(RuntimeManifestError::InvalidSlots)
            }
            _ => {}
        }
    }
    let latest_index = latest_index.ok_or(RuntimeManifestError::InvalidSlots)?;
    let distinct_stable_index = stable_slot_index.filter(|index| {
        manifest.slots[*index].manifest.runtime_version
            != manifest.slots[latest_index].manifest.runtime_version
    });

    let stable_digests = (
        manifest.stable_release_set_sha256.as_deref(),
        manifest.stable_platform_manifest_sha256.as_deref(),
    );
    match (distinct_stable_index, stable_digests) {
        (Some(_), (Some(root), Some(platform_manifest)))
            if valid_sha256(root) && valid_sha256(platform_manifest) => {}
        (None, (None, None)) => {}
        _ => return Err(RuntimeManifestError::InvalidStableDigests),
    }

    Ok(VerifiedContainerManifest {
        manifest,
        latest_index,
        stable_index: distinct_stable_index,
    })
}

fn validate_artifact(
    manifest: &RuntimeArtifactManifestV1,
    platform: &str,
    architecture: &str,
) -> Result<(), RuntimeManifestError> {
    if manifest.format_version != FORMAT_VERSION_V1 {
        return Err(RuntimeManifestError::UnsupportedFormatVersion);
    }
    if manifest.contract_version != COMPILED_RUNTIME_CONTRACT_VERSION {
        return Err(RuntimeManifestError::UnsupportedContract);
    }
    validate_runtime_version(&manifest.runtime_version)?;
    validate_source_commit(&manifest.source_commit)?;
    validate_text(&manifest.platform)?;
    validate_text(&manifest.architecture)?;
    if manifest.platform != platform || manifest.architecture != architecture {
        return Err(RuntimeManifestError::WrongTarget);
    }
    if manifest.files.is_empty() || manifest.files.len() > MAX_RUNTIME_FILES {
        return Err(RuntimeManifestError::InvalidField);
    }
    let mut paths = HashSet::with_capacity(manifest.files.len());
    for file in &manifest.files {
        let alias = portable_path_alias(&file.path)?;
        if !paths.insert(alias) {
            return Err(RuntimeManifestError::DuplicatePath);
        }
        if !valid_sha256(&file.sha256) {
            return Err(RuntimeManifestError::InvalidDigest);
        }
    }
    Ok(())
}

fn validate_release_set(
    manifest: &RuntimeReleaseSetManifestV1,
) -> Result<(), RuntimeManifestError> {
    if manifest.format_version != FORMAT_VERSION_V1 {
        return Err(RuntimeManifestError::UnsupportedFormatVersion);
    }
    validate_text(&manifest.release_set_id)?;
    validate_runtime_version(&manifest.runtime_version)?;
    validate_source_commit(&manifest.source_commit)?;
    if manifest.artifacts.len() != 4 {
        return Err(RuntimeManifestError::InvalidReleaseSet);
    }

    let expected: HashSet<(&str, &str)> = [
        ("linux", "x86_64"),
        ("windows", "x86_64"),
        ("macos", "aarch64"),
        ("android", "aarch64"),
    ]
    .into_iter()
    .collect();
    let mut actual = HashSet::with_capacity(4);
    for artifact in &manifest.artifacts {
        validate_text(&artifact.platform)?;
        validate_text(&artifact.architecture)?;
        if !actual.insert((artifact.platform.as_str(), artifact.architecture.as_str())) {
            return Err(RuntimeManifestError::InvalidReleaseSet);
        }
        validate_asset_name(&artifact.archive_name)?;
        validate_asset_name(&artifact.manifest_name)?;
        validate_asset_name(&artifact.signature_name)?;
        for digest in [
            &artifact.archive_sha256,
            &artifact.manifest_sha256,
            &artifact.signature_sha256,
        ] {
            if !valid_sha256(digest) {
                return Err(RuntimeManifestError::InvalidDigest);
            }
        }
    }
    if actual != expected {
        return Err(RuntimeManifestError::InvalidReleaseSet);
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), RuntimeManifestError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(RuntimeManifestError::InvalidField);
    }
    Ok(())
}

/// Accepts exactly the panel wire subset
/// `N.N.N` followed by at most one `-suffix` or `+suffix`. The suffix may
/// contain ASCII alphanumerics, dots, and hyphens. In particular, a version
/// cannot contain both prerelease and build suffixes.
fn validate_runtime_version(value: &str) -> Result<(), RuntimeManifestError> {
    if value.is_empty() || value.len() > MAX_RUNTIME_VERSION_BYTES || !value.is_ascii() {
        return Err(RuntimeManifestError::InvalidField);
    }
    let suffix_start = value.bytes().position(|byte| matches!(byte, b'-' | b'+'));
    let (core, suffix) = match suffix_start {
        Some(index) => (&value[..index], Some(&value[index + 1..])),
        None => (value, None),
    };
    let mut components = core.split('.');
    let valid_core = (0..3).all(|_| {
        components.next().is_some_and(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
    }) && components.next().is_none();
    let valid_suffix = suffix.is_none_or(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    });
    if !valid_core || !valid_suffix {
        return Err(RuntimeManifestError::InvalidField);
    }
    Ok(())
}

fn validate_source_commit(value: &str) -> Result<(), RuntimeManifestError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeManifestError::InvalidField);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_asset_name(value: &str) -> Result<(), RuntimeManifestError> {
    portable_path_alias(value)?;
    if value.contains('/') {
        return Err(RuntimeManifestError::InvalidPath);
    }
    Ok(())
}

fn portable_path_alias(path: &str) -> Result<String, RuntimeManifestError> {
    if path.is_empty()
        || path.len() > MAX_STRING_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(|character| character.is_control())
    {
        return Err(RuntimeManifestError::InvalidPath);
    }

    let mut aliases = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.ends_with(['.', ' '])
            || segment
                .chars()
                .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return Err(RuntimeManifestError::InvalidPath);
        }
        let alias: String = segment.nfkc().default_case_fold().collect();
        let base = alias.split('.').next().unwrap_or_default();
        let reserved = matches!(base, "con" | "prn" | "aux" | "nul")
            || (base.len() == 4
                && (base.starts_with("com") || base.starts_with("lpt"))
                && matches!(base.as_bytes()[3], b'1'..=b'9'));
        if reserved {
            return Err(RuntimeManifestError::InvalidPath);
        }
        aliases.push(alias);
    }
    Ok(aliases.join("/"))
}
