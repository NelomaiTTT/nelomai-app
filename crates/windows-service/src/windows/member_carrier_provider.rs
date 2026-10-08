//! Read-only native provider facts. Never creator, runtime, or effect authority.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid(&'static str),
    Conflict(&'static str),
    Native(&'static str, u32),
    Changed,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Portable comparison input, not a capability or proof of ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expected {
    pub guid: [u8; 16],
    pub luid: u64,
    pub index: u32,
    pub name: String,
    pub description: String,
    pub if_type: u32,
    pub tunnel_type: i32,
}
/// Closed DATA comparison schema, never caller-supplied success or ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderKind {
    Wintun,
    WireGuardNt,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedProvider {
    pub identity: Expected,
    pub kind: ProviderKind,
}
/// The property key that produced this reading, not an inferred adapter name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivateName {
    pub kind: ProviderKind,
    pub value: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Interface {
    pub identity: Expected,
    pub role_flags: u8,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DriverMetadata {
    pub provider: String,
    pub version: String,
    pub date_filetime: u64,
    pub inf: String,
    pub matching_device_id: String,
    pub driver_key: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Presence {
    Present,
    Phantom,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Device {
    pub instance: String,
    pub devinst: u32,
    pub presence: Presence,
    pub class_guid: [u8; 16],
    pub status: u32,
    pub problem: u32,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub service: String,
    pub description: String,
    pub name: String,
    /// Actual DEVPKEY_WireGuard_Name; absence is separately queried. `name`
    /// remains the private Wintun property for existing strict consumers.
    pub wireguard_name: Option<PrivateName>,
    /// Independently queried standard PnP FriendlyName; absence is explicit.
    pub standard_name: Option<String>,
    pub netcfg_instance_id: String,
    pub net_luid_index: u32,
    pub if_type: u32,
    pub driver: DriverMetadata,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observed {
    pub by_luid: Interface,
    pub by_index: Interface,
    pub by_guid: Interface,
    pub interfaces: Vec<Interface>,
    pub devices: Vec<Device>,
}
/// Concrete observations only. Even a valid observation cannot authorize adoption,
/// DLL loading, creation, session effects, or cleanup of an existing adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub interface: Expected,
    pub instance: Device,
}

const MAX_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const MAX_NODES: u32 = 65_536;
const MAX_INTERFACES: usize = 4096;
const NET_CLASS: [u8; 16] = [
    0x4d, 0x36, 0xe9, 0x72, 0xe3, 0x25, 0x11, 0xce, 0xbf, 0xc1, 0x08, 0, 0x2b, 0xe1, 0x03, 0x18,
];
const DRIVER_DATE: u64 = 132_785_568_000_000_000; // 2021-10-13 00:00 UTC.
                                                  // Main's current independently retained signed36555129204 runtime DLL/INF:
                                                  // DriverVer=05/06/2026,1.1.0.0. Not native observation or runtime authority.
const WIREGUARD_DRIVER_DATE: u64 = 134_224_992_000_000_000;
const PROBLEM_OR_TRANSITION: u32 = 0x8044_8420;

fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.encode_utf16().count() <= max && !value.chars().any(char::is_control)
}
fn validate_expected(want: &Expected) -> Result<()> {
    // SDK ifdef.h: Reserved24, NetLuidIndex24, IfType16. Not an ownership check.
    if want.guid == [0; 16]
        || want.index == 0
        || want.if_type != 53
        || want.tunnel_type != 0
        || want.luid & 0xff_ffff != 0
        || (want.luid >> 24) & 0xff_ffff == 0
        || want.luid >> 48 != 53
        || !text(&want.name, 127)
        || !want.name.is_ascii()
        || want.name.trim() != want.name
        || !text(&want.description, 256)
    {
        return Err(Error::Invalid("expected interface identity"));
    }
    Ok(())
}
fn validate_row(want: &Expected, row: &Interface) -> Result<()> {
    if &row.identity != want || row.role_flags & 0x83 != 0 {
        return Err(Error::Conflict("interface identity/virtual role"));
    }
    Ok(())
}
fn collides(want: &Expected, row: &Interface) -> bool {
    row.identity.guid == want.guid
        || row.identity.luid == want.luid
        || row.identity.index == want.index
        || row.identity.name.eq_ignore_ascii_case(&want.name)
}
fn validate_interfaces(want: &Expected, seen: &Observed) -> Result<()> {
    for row in [&seen.by_luid, &seen.by_index, &seen.by_guid] {
        validate_row(want, row)?;
    }
    if seen.interfaces.len() > MAX_INTERFACES {
        return Err(Error::Invalid("interface table bound"));
    }
    let matches = seen
        .interfaces
        .iter()
        .filter(|row| collides(want, row))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Error::Conflict("missing/extra/reused interface"));
    }
    validate_row(want, matches[0])
}
fn inf_name(inf: &str) -> bool {
    // Installed published INF basename, for main's independently authenticated
    // package comparison; never a caller-selected file to load or execute.
    let lower = inf.to_ascii_lowercase();
    lower
        .strip_prefix("oem")
        .and_then(|s| s.strip_suffix(".inf"))
        .is_some_and(|s| !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()))
}
fn validate_device(want: &Expected, devices: &[Device]) -> Result<()> {
    validate_provider_device(want, ProviderKind::Wintun, devices)
}
fn validate_provider_device(want: &Expected, kind: ProviderKind, devices: &[Device]) -> Result<()> {
    // This is the WHOLE related set, not a filter which hides mismatches.
    if devices.len() != 1 {
        return Err(Error::Conflict("missing/extra/legacy provider instances"));
    }
    let d = &devices[0];
    let (prefix, hardware, version, date, private_name) = match kind {
        ProviderKind::Wintun => {
            if d.wireguard_name.is_some() {
                return Err(Error::Conflict("WireGuard private property on Wintun"));
            }
            (
                "SWD\\Wintun\\",
                "Wintun",
                "0.14.0.0",
                DRIVER_DATE,
                d.name.as_str(),
            )
        }
        ProviderKind::WireGuardNt => {
            let name = d
                .wireguard_name
                .as_ref()
                .filter(|n| n.kind == ProviderKind::WireGuardNt)
                .ok_or(Error::Conflict("missing/wrong WireGuard private property"))?;
            if !d.name.is_empty() {
                return Err(Error::Conflict("ambiguous dual private names"));
            }
            (
                "SWD\\WireGuard\\",
                "WireGuard",
                "1.1.0.0",
                WIREGUARD_DRIVER_DATE,
                name.value.as_str(),
            )
        }
    };
    let suffix = d
        .instance
        .get(..prefix.len())
        .filter(|s| s.eq_ignore_ascii_case(prefix))
        .and_then(|_| d.instance.get(prefix.len()..))
        .ok_or(Error::Conflict("non-SWD expected provider instance"))?;
    if parse_guid(suffix)? != want.guid
        || parse_guid(&d.netcfg_instance_id)? != want.guid
        || d.class_guid != NET_CLASS
        || d.devinst == 0
        || d.net_luid_index == 0
        || d.net_luid_index > 0xff_ffff
        || u64::from(d.net_luid_index) != (want.luid >> 24) & 0xff_ffff
        || d.if_type != 53
        || d.hardware_ids.len() != 1
        || !d.hardware_ids[0].eq_ignore_ascii_case(hardware)
        // SW_DEVICE_CREATE_INFO: the software bus adds SWD\Generic itself.
        // Wintun's measured shape, and WG's driver-required SW_DEVICE_CREATE
        // schema + SDK Generic ID. Mixed WG Windows execution remains UNRUN:
        // extra IDs/GenericRaw/null-driver nodes conservatively deny.
        || d.compatible_ids.len() != 1
        || !d.compatible_ids[0].eq_ignore_ascii_case("SWD\\Generic")
        || !d.service.eq_ignore_ascii_case(hardware)
        || private_name != want.name
        || !crate::member_interface_description::matches_requested(
            &d.description,
            &want.description,
        )
        || d.driver.provider != "WireGuard LLC"
        || d.driver.version != version
        || d.driver.date_filetime != date
        || !inf_name(&d.driver.inf)
        || !d.driver.matching_device_id.eq_ignore_ascii_case(hardware)
        || !text(&d.driver.driver_key, MAX_BYTES / 2)
    {
        return Err(Error::Conflict("provider/driver/interface crossbinding"));
    }
    // CM_Locate_DevNodeW(NORMAL) additionally proves presence natively.
    // DN_DRIVER_LOADED2 + DN_STARTED8; reject HAS_PROBLEM, PRIVATE_PROBLEM,
    // BOOT_LOG_PROB, BAD_PARTIAL, WILL_BE_REMOVED and pending NEED_TO_ENUM.
    if d.presence != Presence::Present
        || d.status & 0xa != 0xa
        || d.status & PROBLEM_OR_TRANSITION != 0
        || d.problem != 0
    {
        return Err(Error::Conflict("non-live/problem/removing instance"));
    }
    Ok(())
}
fn validate_provider(
    want: &Expected,
    kind: ProviderKind,
    before: &Observed,
    after: &Observed,
) -> Result<Observation> {
    validate_expected(want)?;
    validate_interfaces(want, before)?;
    validate_provider_device(want, kind, &before.devices)?;
    validate_provider_device(want, kind, &after.devices)?;
    validate_interfaces(want, after)?;
    // Compare stable identity/role and ALL queried device metadata. Interface
    // traffic counters and unrelated interface churn are not identity evidence.
    if before.devices != after.devices
        || before.by_luid != after.by_luid
        || before.by_index != after.by_index
        || before.by_guid != after.by_guid
    {
        return Err(Error::Changed);
    }
    Ok(Observation {
        interface: after.by_luid.identity.clone(),
        instance: after.devices[0].clone(),
    })
}
fn words(kind: u32, expected: u32, bytes: &[u8]) -> Result<Vec<u16>> {
    if kind != expected || bytes.is_empty() || bytes.len() > MAX_BYTES || bytes.len() % 2 != 0 {
        return Err(Error::Invalid("property type/byte bound"));
    }
    // Decode copied bytes, never cast a Vec<u8> to an aligned WCHAR/FILETIME.
    Ok(bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect())
}
fn wide_value(words: &[u16]) -> Result<String> {
    let value = String::from_utf16(words).map_err(|_| Error::Invalid("invalid UTF16"))?;
    if !text(&value, MAX_BYTES / 2) {
        return Err(Error::Invalid("empty/control string"));
    }
    Ok(value)
}
fn string_property(kind: u32, expected: u32, bytes: &[u8]) -> Result<String> {
    let w = words(kind, expected, bytes)?;
    if w.last() != Some(&0) || w[..w.len() - 1].contains(&0) {
        return Err(Error::Invalid("string termination/tail"));
    }
    wide_value(&w[..w.len() - 1])
}
fn private_name_property(
    provider: ProviderKind,
    raw: Option<(u32, Vec<u8>)>,
) -> Result<Option<PrivateName>> {
    raw.map(|(kind, bytes)| {
        Ok(PrivateName {
            kind: provider,
            value: string_property(kind, 18, &bytes)?, // SDK DEVPROP_TYPE_STRING.
        })
    })
    .transpose()
}
type RawProperty = Option<(u32, Vec<u8>)>;
fn private_names(
    wintun: RawProperty,
    wireguard: RawProperty,
) -> Result<(Option<PrivateName>, Option<PrivateName>)> {
    let wintun = private_name_property(ProviderKind::Wintun, wintun)?;
    let wireguard = private_name_property(ProviderKind::WireGuardNt, wireguard)?;
    if wintun.is_some() && wireguard.is_some() {
        return Err(Error::Conflict("ambiguous dual private names"));
    }
    Ok((wintun, wireguard))
}
fn multi_property(kind: u32, expected: u32, bytes: &[u8]) -> Result<Vec<String>> {
    let w = words(kind, expected, bytes)?;
    if w.len() < 2 || !w.ends_with(&[0, 0]) {
        return Err(Error::Invalid("multi-string termination"));
    }
    if w == [0, 0] {
        return Ok(vec![]);
    }
    w[..w.len() - 2]
        .split(|c| *c == 0)
        .map(wide_value)
        .collect()
}
fn filetime_property(kind: u32, bytes: &[u8]) -> Result<u64> {
    if kind != 16 {
        return Err(Error::Invalid("FILETIME property type"));
    }
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::Invalid("FILETIME byte length"))?,
    ))
}
fn dword_property(kind: u32, bytes: &[u8]) -> Result<u32> {
    if kind != 4 {
        return Err(Error::Invalid("DWORD registry type"));
    }
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::Invalid("DWORD byte length"))?,
    ))
}
fn parse_guid(s: &str) -> Result<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 38
        || b[0] != b'{'
        || b[37] != b'}'
        || [9, 14, 19, 24].iter().any(|&i| b[i] != b'-')
    {
        return Err(Error::Invalid("full braced GUID"));
    }
    let digits = b[1..37]
        .iter()
        .enumerate()
        .filter(|(i, _)| ![8, 13, 18, 23].contains(i))
        .map(|(_, b)| *b)
        .collect::<Vec<_>>();
    fn nibble(b: u8) -> Result<u8> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(Error::Invalid("GUID hex")),
        }
    }
    let mut guid = [0; 16];
    for (out, pair) in guid.iter_mut().zip(digits.chunks_exact(2)) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(guid)
}
fn fixed_string(words: &[u16]) -> Result<String> {
    if words.len() > MAX_BYTES / 2 {
        return Err(Error::Invalid("fixed string bound"));
    }
    let end = words
        .iter()
        .position(|w| *w == 0)
        .ok_or(Error::Invalid("fixed string missing NUL"))?;
    if words[end..].iter().any(|w| *w != 0) {
        return Err(Error::Invalid("fixed string tail"));
    }
    wide_value(&words[..end])
}

trait Queries {
    fn interfaces(&mut self, want: &Expected) -> Result<Observed>;
    fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot>;
    fn table(&mut self) -> Result<Vec<Interface>>;
    fn stack(&mut self) -> Result<Vec<StackEdge>>;
}

/// Entire ALLCLASSES scan: all Net-class nodes plus every related non-Net node.
/// No caller-supplied classification, completeness bit, or foreign allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceSnapshot {
    nodes: Vec<Device>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackEdge {
    higher: u32,
    lower: u32,
}

/// Name/GUID comparison only. It carries no creator or mutation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AbsenceTarget {
    guid: [u8; 16],
    name: String,
}

fn target(want: &Expected) -> AbsenceTarget {
    AbsenceTarget {
        guid: want.guid,
        name: want.name.clone(),
    }
}
fn validate_target(target: &AbsenceTarget) -> Result<()> {
    validate_target_parts(target.guid, &target.name)
}
fn validate_target_parts(guid: [u8; 16], name: &str) -> Result<()> {
    if guid == [0; 16]
        || name.len() > 127
        || !name.is_ascii()
        || !text(name, 127)
        || name.trim() != name
    {
        return Err(Error::Invalid("absence name/GUID"));
    }
    Ok(())
}
fn inspect_absent_queries(target: &AbsenceTarget, query: &mut impl Queries) -> Result<()> {
    validate_target(target)?;
    inspect_absence_queries(std::slice::from_ref(target), query)
}
fn inspect_mixed_absent_queries(
    wants: &[ExpectedProvider],
    target: &AbsenceTarget,
    query: &mut impl Queries,
) -> Result<Vec<Observation>> {
    validate_target(target)?;
    if wants.len() > 3 {
        return Err(Error::Invalid("device universe bound"));
    }
    if wants.iter().any(|w| {
        w.identity.guid == target.guid || w.identity.name.eq_ignore_ascii_case(&target.name)
    }) {
        return Err(Error::Conflict("absence target in expected universe"));
    }
    // Keep the actual mixed validator's exact universe, independent per-key
    // lookups, complete tables, stack and double reads. Target absence is an
    // additional factual predicate on those SAME reads, never a filtered set.
    inspect_mixed_queries(wants, None, &mut MixedAbsenceQueries { target, query })
}
struct MixedAbsenceQueries<'a, Q> {
    target: &'a AbsenceTarget,
    query: &'a mut Q,
}
impl<Q: Queries> Queries for MixedAbsenceQueries<'_, Q> {
    fn interfaces(&mut self, want: &Expected) -> Result<Observed> {
        let seen = self.query.interfaces(want)?;
        validate_absence_table(std::slice::from_ref(self.target), &seen.interfaces)?;
        Ok(seen)
    }
    fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
        // Include the absent target in native ALLCLASSES retention so a
        // target-related non-Net node cannot disappear from the full snapshot.
        let mut scan_targets = targets.to_vec();
        scan_targets.push(self.target.clone());
        let snapshot = self.query.device_snapshot(&scan_targets)?;
        for device in &snapshot.nodes {
            if pnp_collision(self.target, device, parse_guid(&device.netcfg_instance_id)?) {
                return Err(Error::Conflict("name/GUID present in PnP"));
            }
        }
        Ok(snapshot)
    }
    fn table(&mut self) -> Result<Vec<Interface>> {
        let rows = self.query.table()?;
        validate_absence_table(std::slice::from_ref(self.target), &rows)?;
        Ok(rows)
    }
    fn stack(&mut self) -> Result<Vec<StackEdge>> {
        self.query.stack()
    }
}
fn mib_provider_signal(row: &Interface) -> bool {
    // The existing Wintun contract uses IF_TYPE_PROP_VIRTUAL (53). MIB has
    // no authenticated provider field, so unknown type-53 rows are conflicts,
    // not silently classified as a different provider. Text is extra denial
    // evidence only; never permission to accept a row.
    row.identity.if_type == 53 || mib_provider_text(row)
}
fn mib_provider_text(row: &Interface) -> bool {
    provider_text(&row.identity.name) || provider_text(&row.identity.description)
}
fn provider_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["wintun", "wireguard", "amneziawg", "awg"]
        .iter()
        .any(|signal| lower.contains(signal))
}
fn validate_universe_table(wants: &[Expected], rows: &[Interface], foreign: &[u32]) -> Result<()> {
    validate_table(rows)?;
    for row in rows {
        if mib_provider_signal(row) || wants.iter().any(|want| collides(want, row)) {
            if foreign.contains(&row.identity.index) {
                continue;
            }
            let matches = wants
                .iter()
                .filter(|want| collides(want, row))
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                #[cfg(all(test, windows))]
                eprintln!(
                    "actual native provider denied MIB identity={:?} wanted={wants:?}",
                    row.identity
                );
                return Err(Error::Conflict("extra/unknown MIB provider row"));
            }
            validate_row(matches[0], row).inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!(
                    "actual native provider denied MIB identity={:?} wanted={:?}: {_error:?}",
                    row.identity, matches[0]
                );
            })?;
        }
    }
    Ok(())
}
fn device_related(targets: &[AbsenceTarget], d: &Device) -> Result<bool> {
    Ok(
        related_targets(targets, &d.instance, &d.hardware_ids, &d.compatible_ids,
        Some(&d.service), Some(&d.netcfg_instance_id), Some(&d.name))?
        || related_targets(targets, &d.instance, &d.hardware_ids, &d.compatible_ids,
            Some(&d.service), Some(&d.netcfg_instance_id), d.standard_name.as_deref())?
        // Any present private WintunName is denial evidence, including a foreign
        // spelling. Native parsing rejects a present empty/malformed property.
        || !d.name.is_empty()
        || d.wireguard_name.is_some()
        || d.driver.provider.eq_ignore_ascii_case("WireGuard LLC")
        || [&d.instance, &d.service, &d.description, &d.driver.provider,
            &d.driver.matching_device_id, &d.driver.inf]
            .into_iter().chain(d.hardware_ids.iter()).chain(d.compatible_ids.iter())
            .chain(d.standard_name.iter())
            .any(|s| provider_text(s)),
    )
}
fn pnp_collision(t: &AbsenceTarget, d: &Device, guid: [u8; 16]) -> bool {
    t.guid == guid
        || d.name.eq_ignore_ascii_case(&t.name)
        || d.wireguard_name
            .as_ref()
            .is_some_and(|n| n.value.eq_ignore_ascii_case(&t.name))
        || d.standard_name
            .as_ref()
            .is_some_and(|s| s.eq_ignore_ascii_case(&t.name))
}
fn validate_foreign_metadata(d: &Device) -> Result<()> {
    if d.class_guid != NET_CLASS
        || d.devinst == 0
        || !text(&d.instance, 199)
        || !text(&d.description, 256)
        || !text(&d.service, 256)
        || !d.name.is_empty()
        || d.wireguard_name.is_some()
        || d.standard_name.as_ref().is_some_and(|s| !text(s, 256))
        || d.hardware_ids.is_empty()
        || d.hardware_ids
            .iter()
            .chain(&d.compatible_ids)
            .any(|s| !text(s, MAX_BYTES / 2))
        || parse_guid(&d.netcfg_instance_id)? == [0; 16]
        || d.net_luid_index == 0
        || d.net_luid_index > 0xff_ffff
        || d.if_type == 0
        || d.if_type > u32::from(u16::MAX)
        || !text(&d.driver.provider, 256)
        || !text(&d.driver.version, 256)
        || d.driver.date_filetime == 0
        || !text(&d.driver.inf, 256)
        || d.driver.inf.contains(['/', '\\'])
        || !d.driver.inf.to_ascii_lowercase().ends_with(".inf")
        || !text(&d.driver.driver_key, MAX_BYTES / 2)
        || !d
            .hardware_ids
            .iter()
            .chain(&d.compatible_ids)
            .any(|s| s.eq_ignore_ascii_case(&d.driver.matching_device_id))
    {
        return Err(Error::Conflict("foreign provider/driver/live crossbinding"));
    }
    Ok(())
}
fn validate_foreign_row(d: &Device, row: &Interface) -> Result<()> {
    validate_foreign_metadata(d)?;
    let r = &row.identity;
    if parse_guid(&d.netcfg_instance_id)? != r.guid
        || d.if_type != r.if_type
        || r.luid != (u64::from(d.if_type) << 48) | (u64::from(d.net_luid_index) << 24)
        || row.role_flags & 0x82 != 0
        || (d.if_type == 53 && row.role_flags & 1 != 0)
        || mib_provider_text(row)
    {
        return Err(Error::Conflict("foreign provider/driver/live crossbinding"));
    }
    Ok(())
}
fn validate_foreign(d: &Device, row: &Interface) -> Result<()> {
    validate_foreign_row(d, row)?;
    if d.presence != Presence::Present
        || d.status & 0xa != 0xa
        || d.status & PROBLEM_OR_TRANSITION != 0
        || d.problem != 0
    {
        return Err(Error::Conflict("foreign non-live/problem instance"));
    }
    Ok(())
}
fn validate_stack(rows: &[Interface], edges: &[StackEdge]) -> Result<()> {
    use std::collections::{HashMap, HashSet};
    if edges.len() > MAX_INTERFACES {
        return Err(Error::Invalid("stack table bound"));
    }
    let indices = rows
        .iter()
        .map(|r| (r.identity.index, r))
        .collect::<HashMap<_, _>>();
    let mut lower = HashMap::new();
    for edge in edges {
        if !indices.contains_key(&edge.higher)
            || !indices.contains_key(&edge.lower)
            || lower.insert(edge.higher, edge.lower).is_some()
        {
            return Err(Error::Conflict("unresolved/aliased interface stack"));
        }
        let higher = indices[&edge.higher];
        let lower_row = indices[&edge.lower];
        if higher.role_flags & 2 != 0
            && (higher.identity.if_type != lower_row.identity.if_type
                || higher.identity.tunnel_type != lower_row.identity.tunnel_type)
        {
            return Err(Error::Conflict("filter stack type change"));
        }
    }
    let mut checked = HashSet::new();
    for start in lower.keys() {
        let mut path = HashSet::new();
        let mut next = *start;
        while let Some(index) = lower.get(&next) {
            if checked.contains(&next) {
                break;
            }
            if !path.insert(next) {
                return Err(Error::Conflict("interface stack cycle"));
            }
            next = *index;
        }
        checked.extend(path);
    }
    Ok(())
}
fn explain_filters(rows: &[Interface], edges: &[StackEdge], foreign: &mut Vec<u32>) -> Result<()> {
    // validate_stack has already bounded/resolved the unique acyclic graph.
    // This set starts with independently crossbound bases, never owned Wintun.
    let mut explained = foreign
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let lower = edges
        .iter()
        .map(|e| (e.higher, e.lower))
        .collect::<std::collections::HashMap<_, _>>();
    let by_index = rows
        .iter()
        .map(|r| (r.identity.index, r))
        .collect::<std::collections::HashMap<_, _>>();
    for row in rows
        .iter()
        .filter(|r| r.identity.if_type == 53 && r.role_flags & 2 != 0)
    {
        let mut current = row;
        let mut path = vec![];
        while current.role_flags & 2 != 0 && !explained.contains(&current.identity.index) {
            if current.role_flags & 0x83 != 2 || mib_provider_text(current) {
                return Err(Error::Conflict("foreign filter role/provider signal"));
            }
            path.push(current.identity.index);
            let index = lower
                .get(&current.identity.index)
                .ok_or(Error::Conflict("unexplained filter stack"))?;
            current = by_index[index];
            if current.identity.if_type != row.identity.if_type
                || current.identity.tunnel_type != row.identity.tunnel_type
            {
                return Err(Error::Conflict("foreign filter lineage type change"));
            }
        }
        if !explained.contains(&current.identity.index) {
            return Err(Error::Conflict("filter without foreign base crossbinding"));
        }
        foreign.extend(path.iter().copied());
        explained.extend(path);
    }
    Ok(())
}
fn validate_snapshot(
    wants: Option<&[ExpectedProvider]>,
    rundown: Option<&ExpectedProvider>,
    targets: &[AbsenceTarget],
    rows: &[Interface],
    snapshot: &DeviceSnapshot,
    edges: &[StackEdge],
) -> Result<Vec<Device>> {
    validate_table(rows)?;
    validate_stack(rows, edges)?;
    if snapshot.nodes.len() > MAX_INTERFACES {
        return Err(Error::Invalid("device snapshot bound"));
    }
    if wants.is_none() {
        validate_absence_table(targets, rows)?;
    }
    let mut related = vec![];
    let mut foreign = vec![];
    let (mut guids, mut devinsts, mut instances) = (
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    for d in &snapshot.nodes {
        let guid = parse_guid(&d.netcfg_instance_id)?;
        if guid == [0; 16]
            || !guids.insert(guid)
            || !devinsts.insert(d.devinst)
            || !instances.insert(d.instance.to_ascii_lowercase())
        {
            return Err(Error::Conflict("aliased PnP snapshot"));
        }
        if wants.is_none() && targets.iter().any(|t| pnp_collision(t, d, guid)) {
            return Err(Error::Conflict("name/GUID present in PnP"));
        }
        let matching_row = rows.iter().find(|r| r.identity.guid == guid);
        if d.presence == Presence::Phantom {
            // Never a live-provider allowance: only independent complete
            // negative PnP facts with no related signal and no matching MIB.
            if device_related(targets, d)? || d.status != 0 || d.problem != 0 {
                return Err(Error::Conflict("related/colliding phantom device"));
            }
            validate_foreign_metadata(d)?;
            if let Some(row) = matching_row {
                // Windows can retain a RAS-style MIB identity for a phantom.
                // Never use a nonpresent node to explain a possible Wintun.
                if row.identity.if_type == 53 {
                    return Err(Error::Conflict("phantom provider MIB row"));
                }
                validate_foreign_row(d, row)?;
            }
            continue;
        }
        let is_related = device_related(targets, d)?;
        if !is_related && d.if_type != 53 {
            // Unrelated non-tunnel PnP nodes need no live provider row.
            // Any row that is present must still crossbind exactly.
            if let Some(row) = matching_row {
                validate_foreign_row(d, row)?;
            } else {
                validate_foreign_metadata(d)?;
            }
            continue;
        }
        let Some(row) = matching_row else {
            #[cfg(all(windows, test))]
            eprintln!(
                "actual native PnP without exact MIB row: device={d:?}; rows={:?}",
                rows.iter()
                    .map(|r| (
                        r.identity.guid,
                        r.identity.index,
                        r.identity.luid,
                        r.identity.if_type
                    ))
                    .collect::<Vec<_>>()
            );
            return Err(Error::Conflict("PnP without exact MIB row"));
        };
        if is_related {
            related.push(d.clone());
        } else {
            validate_foreign(d, row)?;
            if row.identity.if_type == 53 && edges.iter().any(|e| e.higher == row.identity.index) {
                return Err(Error::Conflict("foreign base has lower stack"));
            }
            foreign.push(row.identity.index);
        }
    }
    let owned = if let Some(wants) = wants {
        // Standard-name collisions cannot disguise a different expected GUID.
        for d in &related {
            let guid = parse_guid(&d.netcfg_instance_id)?;
            if targets
                .iter()
                .any(|t| pnp_collision(t, d, guid) && t.guid != guid)
            {
                return Err(Error::Conflict("foreign PnP name reuse"));
            }
        }
        bind_devices(wants, &related, rundown)?;
        wants.iter().map(|w| w.identity.clone()).collect()
    } else {
        if targets.is_empty() && !related.is_empty() {
            return Err(Error::Conflict("nonempty Wintun universe"));
        }
        let mut owned = vec![];
        for d in &related {
            let guid = parse_guid(&d.netcfg_instance_id)?;
            let row = rows.iter().find(|r| r.identity.guid == guid).unwrap();
            validate_expected(&row.identity)?;
            validate_device(&row.identity, std::slice::from_ref(d))?;
            owned.push(row.identity.clone());
        }
        let strict = owned
            .iter()
            .cloned()
            .map(|identity| ExpectedProvider {
                identity,
                kind: ProviderKind::Wintun,
            })
            .collect::<Vec<_>>();
        bind_devices(&strict, &related, None)?;
        owned
    };
    explain_filters(rows, edges, &mut foreign)?;
    validate_universe_table(&owned, rows, &foreign)?;
    Ok(related)
}
fn stable_rows(
    rows: &[Interface],
    snapshot: &DeviceSnapshot,
    edges: &[StackEdge],
) -> Result<Vec<Interface>> {
    let guids = snapshot
        .nodes
        .iter()
        .map(|d| parse_guid(&d.netcfg_instance_id))
        .collect::<Result<std::collections::HashSet<_>>>()?;
    let indices = edges
        .iter()
        .flat_map(|e| [e.higher, e.lower])
        .collect::<std::collections::HashSet<_>>();
    Ok(rows
        .iter()
        .filter(|r| {
            mib_provider_signal(r)
                || guids.contains(&r.identity.guid)
                || indices.contains(&r.identity.index)
        })
        .cloned()
        .collect())
}
fn validate_absence_table(targets: &[AbsenceTarget], rows: &[Interface]) -> Result<()> {
    validate_table(rows)?;
    for row in rows {
        if targets
            .iter()
            .any(|t| row.identity.guid == t.guid || row.identity.name.eq_ignore_ascii_case(&t.name))
        {
            return Err(Error::Conflict("name/GUID present in MIB"));
        }
    }
    Ok(())
}
fn validate_table(rows: &[Interface]) -> Result<()> {
    if rows.len() > MAX_INTERFACES {
        return Err(Error::Invalid("interface table bound"));
    }
    let (mut guids, mut luids, mut indices, mut names) = (
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    for row in rows {
        let r = &row.identity;
        if r.guid == [0; 16]
            || r.index == 0
            || r.if_type == 0
            || r.if_type > u32::from(u16::MAX)
            || r.luid & 0xff_ffff != 0
            // NetLuidIndex zero occurs in real loopback/filter interfaces.
            // Require the complete LUID's type/layout and uniqueness here;
            // validate_expected/device retain Wintun's stricter nonzero index.
            || r.luid >> 48 != u64::from(r.if_type)
            || !text(&r.name, 256)
            || !text(&r.description, 256)
        {
            return Err(Error::Invalid("malformed MIB table identity"));
        }
        if !guids.insert(r.guid)
            || !luids.insert(r.luid)
            || !indices.insert(r.index)
            || !names.insert(r.name.to_ascii_lowercase())
        {
            return Err(Error::Conflict("duplicate/aliased MIB table identity"));
        }
    }
    Ok(())
}
fn inspect_absence_queries(targets: &[AbsenceTarget], query: &mut impl Queries) -> Result<()> {
    let before = query.table()?;
    // Validate the MIB before any later error can mask a direct collision.
    validate_absence_table(targets, &before).inspect_err(|_error| {
        #[cfg(all(windows, test))]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            eprintln!(
                "actual native MIB absence denied; matching rows (guid,name,luid,index,type,role_flags)={:?}",
                before.iter().filter(|r| targets.iter().any(|t| r.identity.guid == t.guid || r.identity.name.eq_ignore_ascii_case(&t.name)))
                    .take(8).map(|r| (&r.identity.guid, &r.identity.name, r.identity.luid,
                        r.identity.index, r.identity.if_type, r.role_flags)).collect::<Vec<_>>()
            );
            match query.device_snapshot(targets) {
                Ok(snapshot) => eprintln!(
                    "actual native MIB absence denied; PnP (presence,status,problem,guid,name)={:?}",
                    snapshot.nodes.iter().filter(|d| device_related(targets, d).unwrap_or(true))
                        .take(8).map(|d| (&d.presence, d.status, d.problem, &d.netcfg_instance_id, &d.name))
                        .collect::<Vec<_>>()
                ),
                Err(diagnostic) => eprintln!("actual native MIB absence denied; PnP query: {diagnostic:?}"),
            }
        }
    })?;
    let devices_before = query.device_snapshot(targets)?;
    let stack_before = query.stack()?;
    validate_snapshot(None, None, targets, &before, &devices_before, &stack_before)?;
    let devices_after = query.device_snapshot(targets)?;
    let after = query.table()?;
    let stack_after = query.stack()?;
    validate_snapshot(None, None, targets, &after, &devices_after, &stack_after)?;
    if devices_before != devices_after || stack_before != stack_after {
        return Err(Error::Changed);
    }
    // Unrelated physical-interface churn is not a conflict. Compare the whole
    // related MIB set, not traffic counters or an assumed atomic snapshot.
    if stable_rows(&before, &devices_before, &stack_before)?
        != stable_rows(&after, &devices_after, &stack_after)?
    {
        return Err(Error::Changed);
    }
    Ok(())
}

fn related_targets(
    targets: &[AbsenceTarget],
    instance: &str,
    ids: &[String],
    compatible: &[String],
    service: Option<&str>,
    cfg: Option<&str>,
    name: Option<&str>,
) -> Result<bool> {
    let upper = instance.to_ascii_uppercase();
    // Parse even unrelated NetCfg values and even with zero comparison
    // targets. A malformed/unknown queried reading cannot imply absence.
    let guid = cfg.map(parse_guid).transpose()?;
    Ok(upper == "SWD\\WINTUN"
        || upper.starts_with("SWD\\WINTUN\\")
        || upper == "ROOT\\WINTUN"
        || upper.starts_with("ROOT\\WINTUN\\")
        || provider_text(instance)
        || ids.iter().chain(compatible).any(|id| provider_text(id))
        || service.is_some_and(provider_text)
        || name.is_some_and(provider_text)
        || targets.iter().any(|t| {
            guid == Some(t.guid) || name.is_some_and(|name| name.eq_ignore_ascii_case(&t.name))
        }))
}
fn inspect_mixed_queries(
    wants: &[ExpectedProvider],
    rundown: Option<&ExpectedProvider>,
    query: &mut impl Queries,
) -> Result<Vec<Observation>> {
    if wants.len() > 3 {
        return Err(Error::Invalid("device universe bound"));
    }
    if wants.is_empty() {
        inspect_absence_queries(&[], query)?;
        return Ok(vec![]);
    }
    for (i, expected) in wants.iter().enumerate() {
        let want = &expected.identity;
        validate_expected(want)?;
        if wants[..i].iter().any(|other| {
            collides(
                &other.identity,
                &Interface {
                    identity: want.clone(),
                    role_flags: 0,
                },
            )
        }) {
            return Err(Error::Conflict("aliased device universe"));
        }
    }
    let mut before = Vec::with_capacity(wants.len());
    for expected in wants {
        let want = &expected.identity;
        let row = query.interfaces(want)?;
        validate_interfaces(want, &row)?;
        before.push(row);
    }
    let targets = wants
        .iter()
        .map(|w| target(&w.identity))
        .collect::<Vec<_>>();
    let devices_before = query.device_snapshot(&targets)?;
    let stack_before = query.stack()?;
    for row in &before {
        validate_snapshot(
            Some(wants),
            rundown,
            &targets,
            &row.interfaces,
            &devices_before,
            &stack_before,
        )?;
        if stable_rows(&row.interfaces, &devices_before, &stack_before)?
            != stable_rows(&before[0].interfaces, &devices_before, &stack_before)?
        {
            return Err(Error::Changed);
        }
    }
    let related_before = validate_snapshot(
        Some(wants),
        rundown,
        &targets,
        &before[0].interfaces,
        &devices_before,
        &stack_before,
    )?;
    let bound_before = bind_devices(wants, &related_before, rundown)?;
    let devices_after = query.device_snapshot(&targets)?;
    let mut observations = Vec::with_capacity(wants.len());
    let mut final_rows = Vec::with_capacity(wants.len());
    for (i, expected) in wants.iter().enumerate() {
        let want = &expected.identity;
        before[i].devices = bound_before[i].iter().cloned().collect();
        final_rows.push(query.interfaces(want)?);
    }
    let stack_after = query.stack()?;
    if devices_before != devices_after || stack_before != stack_after {
        return Err(Error::Changed);
    }
    for (i, expected) in wants.iter().enumerate() {
        let want = &expected.identity;
        let after = &mut final_rows[i];
        let related_after = validate_snapshot(
            Some(wants),
            rundown,
            &targets,
            &after.interfaces,
            &devices_after,
            &stack_after,
        )?;
        let bound_after = bind_devices(wants, &related_after, rundown)?;
        if stable_rows(&before[i].interfaces, &devices_before, &stack_before)?
            != stable_rows(&after.interfaces, &devices_after, &stack_after)?
            || stable_rows(&before[0].interfaces, &devices_before, &stack_before)?
                != stable_rows(&after.interfaces, &devices_after, &stack_after)?
        {
            return Err(Error::Changed);
        }
        if bound_before[i].is_none() || bound_after[i].is_none() {
            if bound_before[i].is_some() != bound_after[i].is_some() || rundown != Some(expected) {
                return Err(Error::Changed);
            }
            validate_interfaces(want, after)?;
            continue; // Exact residual comparison only, never a live Observation.
        }
        after.devices = bound_after[i].iter().cloned().collect();
        observations.push(validate_provider(want, expected.kind, &before[i], after)?);
    }
    Ok(observations)
}

/// Cleanup-only namespace comparison. A partial original SCM owner supplies
/// its immutable binding separately; SDK facts here can never become an
/// ExpectedProvider returned to the caller or an ownership/lifecycle grant.
/// Only stable factual presence is returned, with full pre/post SDK reads.
fn inspect_mixed_partial_queries(
    wants: &[ExpectedProvider],
    target: &AbsenceTarget,
    kind: ProviderKind,
    original: Option<&ExpectedProvider>,
    deleted: bool,
    query: &mut impl Queries,
) -> Result<bool> {
    validate_target_parts(target.guid, &target.name)?;
    if wants.len() > 2
        || wants.iter().any(|w| {
            w.identity.guid == target.guid || w.identity.name.eq_ignore_ascii_case(&target.name)
        })
    {
        return Err(Error::Conflict("partial namespace aliases original"));
    }
    if original.is_some_and(|p| {
        p.kind != kind || p.identity.guid != target.guid || p.identity.name != target.name
    }) {
        return Err(Error::Conflict("partial original binding"));
    }
    let select = |rows: &[Interface]| -> Result<Option<ExpectedProvider>> {
        validate_table(rows)?;
        let candidates = rows
            .iter()
            .filter(|row| {
                row.identity.guid == target.guid
                    || row.identity.name.eq_ignore_ascii_case(&target.name)
                    || original.is_some_and(|p| {
                        row.identity.index == p.identity.index
                            || row.identity.luid == p.identity.luid
                    })
            })
            .collect::<Vec<_>>();
        if candidates.len() > 1 {
            return Err(Error::Conflict("partial namespace collision"));
        }
        let Some(row) = candidates.first() else {
            return Ok(None);
        };
        if row.identity.guid != target.guid || row.identity.name != target.name {
            return Err(Error::Conflict("partial namespace collision"));
        }
        validate_expected(&row.identity)?;
        validate_row(&row.identity, row)?;
        let candidate = ExpectedProvider {
            identity: row.identity.clone(),
            kind,
        };
        if original.is_some_and(|p| p != &candidate) {
            return Err(Error::Conflict("partial original changed"));
        }
        Ok(Some(candidate))
    };
    let observed = select(&query.table()?)?;
    if let Some(partial) = &observed {
        let mut comparison = wants.to_vec();
        comparison.push(partial.clone());
        // Strict full MIB/PnP/stack validation, including all original live
        // providers and aliases. The partial candidate remains LOCAL DATA.
        inspect_mixed_queries(&comparison, deleted.then_some(original).flatten(), query)?;
    } else {
        // A missing MIB row alone is not absence: independently scan both PnP
        // universes with the exact target included, even when wants is empty.
        inspect_mixed_absent_queries(wants, target, query)?;
    }
    if select(&query.table()?)? != observed {
        return Err(Error::Changed);
    }
    Ok(observed.is_some())
}
fn inspect_all_queries(wants: &[Expected], query: &mut impl Queries) -> Result<Vec<Observation>> {
    if wants.len() > 3 {
        return Err(Error::Invalid("device universe bound"));
    }
    let strict = wants
        .iter()
        .cloned()
        .map(|identity| ExpectedProvider {
            identity,
            kind: ProviderKind::Wintun,
        })
        .collect::<Vec<_>>();
    inspect_mixed_queries(&strict, None, query)
}
fn bind_devices(
    wants: &[ExpectedProvider],
    devices: &[Device],
    rundown: Option<&ExpectedProvider>,
) -> Result<Vec<Option<Device>>> {
    let missing = rundown.is_some_and(|original| {
        wants.contains(original)
            && !devices.iter().any(|device| {
                parse_guid(&device.netcfg_instance_id).ok() == Some(original.identity.guid)
            })
    });
    if devices.len() != wants.len() - usize::from(missing) {
        return Err(Error::Conflict("incomplete/extra device universe"));
    }
    let mut bound = Vec::with_capacity(wants.len());
    for expected in wants {
        let want = &expected.identity;
        let mut matches = vec![];
        for device in devices {
            if parse_guid(&device.netcfg_instance_id)? == want.guid {
                matches.push(device.clone());
            }
        }
        if matches.is_empty() && rundown == Some(expected) {
            bound.push(None);
            continue;
        }
        validate_provider_device(want, expected.kind, &matches)?;
        bound.push(Some(matches.remove(0)));
    }
    #[cfg(all(windows, test))]
    if let Some(original) = rundown.filter(|original| wants.contains(original)) {
        eprintln!(
            "actual native partial rundown target PnP guid={:?} present={}",
            original.identity.guid, !missing
        );
    }
    Ok(bound)
}
fn returned_bytes(mut bytes: Vec<u8>, required: u32) -> Result<Vec<u8>> {
    if required == 0 || required as usize > bytes.len() || required as usize > MAX_BYTES {
        return Err(Error::Invalid("native returned byte count"));
    }
    bytes.truncate(required as usize);
    Ok(bytes)
}
fn network_guid_read(value: Result<Option<String>>) -> Result<String> {
    let value = value?.ok_or(Error::Invalid("missing network NetCfgInstanceId"))?;
    if parse_guid(&value)? == [0; 16] {
        return Err(Error::Invalid("zero network NetCfgInstanceId"));
    }
    Ok(value)
}

/// Real read-only SetupAPI/Configuration Manager/IP Helper queries.
/// No Wintun DLL load/export, device or registry writes, PowerShell, or file
/// fallback. The caller must hold its own retained creator/runtime authority.
#[cfg(windows)]
pub(crate) mod native {
    use super::super::member_carrier_wintun::Identity;
    use super::*;
    use std::{mem::size_of, ptr};
    use windows_sys::{
        core::{GUID, PCWSTR},
        Win32::{
            Devices::{DeviceAndDriverInstallation::*, Properties::*},
            Foundation::{
                GetLastError, DEVPROPKEY, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA,
                ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS, INVALID_HANDLE_VALUE,
            },
            NetworkManagement::{
                IpHelper::{
                    ConvertInterfaceGuidToLuid, ConvertInterfaceIndexToLuid,
                    ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex, FreeMibTable,
                    GetIfEntry2, GetIfStackTable, GetIfTable2, MIB_IFSTACK_ROW, MIB_IFSTACK_TABLE,
                    MIB_IF_ROW2, MIB_IF_TABLE2,
                },
                Ndis::NET_LUID_LH,
            },
            System::Registry::{
                RegCloseKey, RegQueryValueExW, HKEY, KEY_QUERY_VALUE, REG_MULTI_SZ, REG_SZ,
            },
        },
    };

    // Audited Wintun 0.14.1 api/adapter.c: DEVPROPID_FIRST_USABLE(2)+1.
    const WINTUN_NAME: DEVPROPKEY = DEVPROPKEY {
        fmtid: GUID::from_u128(0x3361c968_2f2e_4660_b47e_699cdc4c32b9),
        pid: 3,
    };
    // Primary WireGuard-NT 1.1 api/adapter.{h,c}, pinned upstream commit
    // fef7bc4377a4f49ffa7c30841b48808fda578cad: FIRST_USABLE(2)+1.
    const WIREGUARD_NAME: DEVPROPKEY = DEVPROPKEY {
        fmtid: GUID::from_u128(0x65726957_7547_7261_644e_616d654b6579),
        pid: 3,
    };
    const INSTANCE_WORDS: usize = 200; // SDK MAX_DEVICE_ID_LEN, includes NUL.

    /// Whole observed Wintun universe, still factual, NOT original ownership.
    /// The caller supplies only identities freshly obtained from retained
    /// creators; this observer itself cannot establish that provenance.
    pub(crate) fn inspect_all(identities: &[Identity]) -> Result<Vec<Observation>> {
        if identities.len() > 3 {
            return Err(Error::Invalid("device universe bound"));
        }
        let wants = identities
            .iter()
            .map(|identity| Expected {
                guid: identity.guid,
                luid: identity.luid,
                index: identity.index,
                name: identity.name.clone(),
                description: identity.description.clone(),
                if_type: identity.if_type,
                tunnel_type: identity.tunnel_type,
            })
            .collect::<Vec<_>>();
        inspect_all_queries(&wants, &mut NativeQueries)
    }

    /// Explicit identities AND closed provider kinds, from main's future
    /// original registry. This DATA reader establishes no creator provenance.
    /// Returns all concrete observations in caller order, with the same full
    /// PnP/MIB/stack reads as the strict Wintun entry point. No factory selection.
    pub(crate) fn inspect_mixed(wants: &[ExpectedProvider]) -> Result<Vec<Observation>> {
        let result = inspect_mixed_queries(wants, None, &mut NativeQueries);
        #[cfg(test)]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            if let Err(error) = &result {
                eprintln!("actual native complete provider census: {error:?}");
            }
        }
        result
    }

    /// Service-only cleanup comparison, never a provider/Running proof. Caller
    /// supplies the exact immutable binding from its SAME original partial SCM
    /// owner; all MIB/PnP/stack reads remain independent and strictly bounded.
    pub(crate) fn inspect_mixed_partial(
        wants: &[ExpectedProvider],
        guid: [u8; 16],
        name: &str,
        kind: ProviderKind,
        original: Option<&ExpectedProvider>,
        deleted: bool,
    ) -> Result<bool> {
        inspect_mixed_partial_queries(
            wants,
            &AbsenceTarget {
                guid,
                name: name.into(),
            },
            kind,
            original,
            deleted,
            &mut NativeQueries,
        )
    }

    /// Fresh name/GUID absence alongside an exact explicit mixed live universe.
    /// All identities/kinds are comparison facts only, not creator provenance
    /// or ownership/effect authority. Every full PnP/MIB read checks the target;
    /// zero wants still require a strictly empty related universe. Read-only.
    pub(crate) fn inspect_mixed_absent(
        wants: &[ExpectedProvider],
        guid: [u8; 16],
        name: &str,
    ) -> Result<Vec<Observation>> {
        validate_target_parts(guid, name)?;
        inspect_mixed_absent_queries(
            wants,
            &AbsenceTarget {
                guid,
                name: name.into(),
            },
            &mut NativeQueries,
        )
    }

    /// Fresh bounded name/GUID absence comparison for a separately validated
    /// receipt Context/Binding. Pass its canonical GUID and exact native name.
    /// No lookup-not-found shortcut, cached observation, registry root, creator
    /// claim or effect permission. The caller must authenticate current Context,
    /// runtime/provider and SAME retained lock before/through these reads.
    pub(crate) fn inspect_absent(guid: [u8; 16], name: &str) -> Result<()> {
        // Bound borrowed input before allocating the comparison name.
        validate_target_parts(guid, name)?;
        inspect_absent_queries(
            &AbsenceTarget {
                guid,
                name: name.into(),
            },
            &mut NativeQueries,
        )
    }

    fn last(api: &'static str) -> Error {
        Error::Native(api, unsafe { GetLastError() })
    }
    fn status(api: &'static str, code: u32) -> Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(Error::Native(api, code))
        }
    }
    fn guid_bytes(g: &GUID) -> [u8; 16] {
        let mut b = [0; 16];
        b[..4].copy_from_slice(&g.data1.to_be_bytes());
        b[4..6].copy_from_slice(&g.data2.to_be_bytes());
        b[6..8].copy_from_slice(&g.data3.to_be_bytes());
        b[8..].copy_from_slice(&g.data4);
        b
    }
    fn guid(b: [u8; 16]) -> GUID {
        GUID::from_u128(u128::from_be_bytes(b))
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    struct InfoSet(HDEVINFO);
    impl Drop for InfoSet {
        fn drop(&mut self) {
            unsafe {
                SetupDiDestroyDeviceInfoList(self.0);
            }
        }
    }
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    struct Table(*mut MIB_IF_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    FreeMibTable(self.0.cast());
                }
            }
        }
    }
    struct StackTable(*mut MIB_IFSTACK_TABLE);
    impl Drop for StackTable {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    FreeMibTable(self.0.cast());
                }
            }
        }
    }

    fn stack() -> Result<Vec<StackEdge>> {
        let mut table = StackTable(ptr::null_mut());
        status("GetIfStackTable", unsafe { GetIfStackTable(&mut table.0) })?;
        if table.0.is_null() {
            return Err(Error::Invalid("null interface stack table"));
        }
        let count = unsafe { (*table.0).NumEntries } as usize;
        if count > MAX_INTERFACES {
            return Err(Error::Invalid("stack table bound"));
        }
        // Access the SDK-aligned Table member, including any header padding.
        let rows = unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!((*table.0).Table).cast::<MIB_IFSTACK_ROW>(),
                count,
            )
        };
        Ok(rows
            .iter()
            .map(|r| StackEdge {
                higher: r.HigherLayerInterfaceIndex,
                lower: r.LowerLayerInterfaceIndex,
            })
            .collect())
    }

    fn row(luid: u64, index: u32) -> Result<Interface> {
        // GetIfEntry2 prefers LUID, so index queries MUST start with LUID=0.
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: NET_LUID_LH { Value: luid },
            InterfaceIndex: index,
            ..Default::default()
        };
        status("GetIfEntry2", unsafe { GetIfEntry2(&mut row) })?;
        interface(&row)
    }
    fn interface(row: &MIB_IF_ROW2) -> Result<Interface> {
        Ok(Interface {
            identity: Expected {
                guid: guid_bytes(&row.InterfaceGuid),
                // Reading the Value member of the native SDK union is aligned.
                luid: unsafe { row.InterfaceLuid.Value },
                index: row.InterfaceIndex,
                name: fixed_string(&row.Alias)?,
                description: fixed_string(&row.Description)?,
                if_type: row.Type,
                tunnel_type: row.TunnelType,
            },
            role_flags: row.InterfaceAndOperStatusFlags._bitfield,
        })
    }
    fn interfaces(want: &Expected) -> Result<Observed> {
        let by_luid = row(want.luid, 0)?;
        let by_index = row(0, want.index)?;
        let mut from_guid = NET_LUID_LH::default();
        status("ConvertInterfaceGuidToLuid", unsafe {
            ConvertInterfaceGuidToLuid(&guid(want.guid), &mut from_guid)
        })?;
        if unsafe { from_guid.Value } != want.luid {
            return Err(Error::Conflict("GUID to LUID"));
        }
        let by_guid = row(unsafe { from_guid.Value }, 0)?;
        let mut from_index = NET_LUID_LH::default();
        status("ConvertInterfaceIndexToLuid", unsafe {
            ConvertInterfaceIndexToLuid(want.index, &mut from_index)
        })?;
        if unsafe { from_index.Value } != want.luid {
            return Err(Error::Conflict("index to LUID"));
        }
        let luid = NET_LUID_LH { Value: want.luid };
        let mut to_guid = GUID::default();
        let mut to_index = 0;
        status("ConvertInterfaceLuidToGuid", unsafe {
            ConvertInterfaceLuidToGuid(&luid, &mut to_guid)
        })?;
        status("ConvertInterfaceLuidToIndex", unsafe {
            ConvertInterfaceLuidToIndex(&luid, &mut to_index)
        })?;
        if guid_bytes(&to_guid) != want.guid || to_index != want.index {
            return Err(Error::Conflict("LUID reverse binding"));
        }
        Ok(Observed {
            by_luid,
            by_index,
            by_guid,
            interfaces: table()?,
            devices: vec![],
        })
    }
    pub(crate) fn table() -> Result<Vec<Interface>> {
        let mut table = Table(ptr::null_mut());
        status("GetIfTable2", unsafe { GetIfTable2(&mut table.0) })?;
        if table.0.is_null() {
            return Err(Error::Invalid("null interface table"));
        }
        let count = unsafe { (*table.0).NumEntries } as usize;
        if count > MAX_INTERFACES {
            return Err(Error::Invalid("interface enumeration bound"));
        }
        // Windows owns an aligned variable-length MIB_IF_TABLE2 allocation;
        // Table's lifetime spans this bounded slice. No byte-buffer casts.
        let rows = unsafe {
            std::slice::from_raw_parts(ptr::addr_of!((*table.0).Table).cast::<MIB_IF_ROW2>(), count)
        };
        let mut interfaces = Vec::with_capacity(count);
        for r in rows {
            interfaces.push(interface(r)?);
        }
        validate_table(&interfaces)?;
        Ok(interfaces)
    }

    fn property(
        set: &InfoSet,
        d: &SP_DEVINFO_DATA,
        key: &DEVPROPKEY,
        optional: bool,
    ) -> Result<Option<(u32, Vec<u8>)>> {
        let mut bytes = vec![0; MAX_BYTES];
        let (mut kind, mut size) = (0, 0);
        if unsafe {
            SetupDiGetDevicePropertyW(
                set.0,
                d,
                key,
                &mut kind,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut size,
                0,
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            if optional && code == ERROR_NOT_FOUND {
                return Ok(None);
            }
            return Err(Error::Native("SetupDiGetDevicePropertyW", code));
        }
        Ok(Some((kind, returned_bytes(bytes, size)?)))
    }
    fn string(set: &InfoSet, d: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> Result<String> {
        let (kind, bytes) = property(set, d, key, false)?
            .ok_or(Error::Invalid("missing required device property"))?;
        string_property(kind, DEVPROP_TYPE_STRING, &bytes)
    }
    fn optional_string(
        set: &InfoSet,
        d: &SP_DEVINFO_DATA,
        key: &DEVPROPKEY,
    ) -> Result<Option<String>> {
        property(set, d, key, true)?
            .map(|(kind, b)| string_property(kind, DEVPROP_TYPE_STRING, &b))
            .transpose()
    }
    fn registry_property(
        set: &InfoSet,
        d: &SP_DEVINFO_DATA,
        prop: SETUP_DI_REGISTRY_PROPERTY,
    ) -> Result<Option<(u32, Vec<u8>)>> {
        let mut bytes = vec![0; MAX_BYTES];
        let (mut kind, mut size) = (0, 0);
        if unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set.0,
                d,
                prop,
                &mut kind,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut size,
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            if code == ERROR_INVALID_DATA {
                return Ok(None);
            }
            return Err(Error::Native("SetupDiGetDeviceRegistryPropertyW", code));
        }
        Ok(Some((kind, returned_bytes(bytes, size)?)))
    }
    fn ids(
        set: &InfoSet,
        d: &SP_DEVINFO_DATA,
        prop: SETUP_DI_REGISTRY_PROPERTY,
    ) -> Result<Vec<String>> {
        match registry_property(set, d, prop)? {
            Some((kind, b)) => multi_property(kind, REG_MULTI_SZ, &b),
            None => Ok(vec![]),
        }
    }
    fn open_key(set: &InfoSet, d: &SP_DEVINFO_DATA) -> Result<Key> {
        let key = unsafe {
            SetupDiOpenDevRegKey(set.0, d, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE)
        };
        if key == INVALID_HANDLE_VALUE || key.is_null() {
            return Err(last("SetupDiOpenDevRegKey QUERY_VALUE"));
        }
        Ok(Key(key))
    }
    fn value(key: &Key, name: PCWSTR, optional: bool) -> Result<Option<(u32, Vec<u8>)>> {
        let mut bytes = vec![0; MAX_BYTES];
        let mut kind = 0;
        let mut size = bytes.len() as u32;
        let code = unsafe {
            RegQueryValueExW(
                key.0,
                name,
                ptr::null(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        if optional && code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        status("RegQueryValueExW", code)?;
        Ok(Some((kind, returned_bytes(bytes, size)?)))
    }
    fn key_string(key: &Key, name: PCWSTR, optional: bool) -> Result<Option<String>> {
        value(key, name, optional)?
            .map(|(kind, b)| string_property(kind, REG_SZ, &b))
            .transpose()
    }
    fn key_dword(key: &Key, name: PCWSTR) -> Result<u32> {
        let (kind, b) = value(key, name, false)?.ok_or(Error::Invalid("missing DWORD"))?;
        dword_property(kind, &b)
    }
    fn instance(set: &InfoSet, d: &SP_DEVINFO_DATA) -> Result<String> {
        let mut buf = [0; INSTANCE_WORDS];
        let mut size = 0;
        if unsafe {
            SetupDiGetDeviceInstanceIdW(set.0, d, buf.as_mut_ptr(), buf.len() as u32, &mut size)
        } == 0
        {
            return Err(last("SetupDiGetDeviceInstanceIdW"));
        }
        if size == 0 || size as usize > buf.len() {
            return Err(Error::Invalid("instance char count"));
        }
        // RequiredSize includes exactly one terminator; tail within that count
        // must not be accepted as part of a shorter instance identity.
        let b = buf[..size as usize]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>();
        string_property(DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING, &b)
    }
    fn live(instance: &str, d: &SP_DEVINFO_DATA) -> Result<(Presence, u32, u32)> {
        let mut located = 0;
        let normal = unsafe {
            CM_Locate_DevNodeW(
                &mut located,
                wide(instance).as_ptr(),
                CM_LOCATE_DEVNODE_NORMAL,
            )
        };
        let presence = match normal {
            CR_SUCCESS => Presence::Present,
            CR_NO_SUCH_DEVNODE => {
                status("CM_Locate_DevNodeW PHANTOM", unsafe {
                    CM_Locate_DevNodeW(
                        &mut located,
                        wide(instance).as_ptr(),
                        CM_LOCATE_DEVNODE_PHANTOM,
                    )
                })?;
                Presence::Phantom
            }
            code => return Err(Error::Native("CM_Locate_DevNodeW NORMAL", code)),
        };
        if located != d.DevInst {
            return Err(Error::Conflict("reused device instance"));
        }
        let mut buf = [0; INSTANCE_WORDS];
        status("CM_Get_Device_IDW", unsafe {
            CM_Get_Device_IDW(located, buf.as_mut_ptr(), buf.len() as u32, 0)
        })?;
        if !fixed_string(&buf)?.eq_ignore_ascii_case(instance) {
            return Err(Error::Conflict("CM/SetupAPI instance"));
        }
        let (mut flags, mut problem) = (0, 0);
        let status_code = unsafe { CM_Get_DevNode_Status(&mut flags, &mut problem, located, 0) };
        match presence {
            Presence::Present => status("CM_Get_DevNode_Status", status_code)?,
            Presence::Phantom => {
                if status_code != CR_NO_SUCH_DEVNODE {
                    return Err(Error::Native("phantom CM_Get_DevNode_Status", status_code));
                }
                let mut now = 0;
                let code = unsafe {
                    CM_Locate_DevNodeW(&mut now, wide(instance).as_ptr(), CM_LOCATE_DEVNODE_NORMAL)
                };
                if code != CR_NO_SUCH_DEVNODE {
                    return Err(Error::Changed);
                }
                flags = 0;
                problem = 0;
            }
        }
        Ok((presence, flags, problem))
    }
    fn device_snapshot(targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
        // No PRESENT filter: phantom, legacy, stub and wrong-class related
        // nodes must never be hidden from the exactly-one predicate.
        let raw = unsafe {
            SetupDiGetClassDevsW(ptr::null(), ptr::null(), ptr::null_mut(), DIGCF_ALLCLASSES)
        };
        if raw == INVALID_HANDLE_VALUE as isize || raw == 0 {
            return Err(last("SetupDiGetClassDevsW ALLCLASSES"));
        }
        let set = InfoSet(raw);
        let mut found = vec![];
        for index in 0..MAX_NODES {
            let mut d = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut d) } == 0 {
                if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                    return Ok(DeviceSnapshot { nodes: found });
                }
                return Err(last("SetupDiEnumDeviceInfo"));
            }
            let instance = instance(&set, &d)?;
            let hardware_ids = ids(&set, &d, SPDRP_HARDWAREID)?;
            let compatible_ids = ids(&set, &d, SPDRP_COMPATIBLEIDS)?;
            let service = optional_string(&set, &d, &DEVPKEY_Device_Service)?;
            // Query BOTH fixed private keys, retaining their actual provenance
            // and native property type. Never reinterpret WG text as Wintun.
            let (name, wireguard_name) = private_names(
                property(&set, &d, &WINTUN_NAME, true)?,
                property(&set, &d, &WIREGUARD_NAME, true)?,
            )?;
            let friendly_name = optional_string(&set, &d, &DEVPKEY_Device_FriendlyName)?;
            // Read each network device's real software key, including foreign
            // providers, to detect re-use of the requested NetCfgInstanceId.
            let key = if guid_bytes(&d.ClassGuid) == NET_CLASS {
                Some(open_key(&set, &d)?)
            } else {
                None
            };
            let cfg = key
                .as_ref()
                .map(|k| {
                    network_guid_read(key_string(k, windows_sys::w!("NetCfgInstanceId"), false))
                })
                .transpose()?;
            let related = related_targets(
                targets,
                &instance,
                &hardware_ids,
                &compatible_ids,
                service.as_deref(),
                cfg.as_deref(),
                name.as_ref().map(|n| n.value.as_str()),
            )? || related_targets(
                targets,
                &instance,
                &hardware_ids,
                &compatible_ids,
                service.as_deref(),
                cfg.as_deref(),
                friendly_name.as_deref(),
            )?;
            // Full negative evidence is mandatory for every Net-class node.
            // Either private name is related, even with no target names.
            if !related && key.is_none() && name.is_none() && wireguard_name.is_none() {
                continue;
            }
            if found.len() >= MAX_INTERFACES {
                return Err(Error::Invalid("full device snapshot bound"));
            }
            let key = match key {
                Some(k) => k,
                None => open_key(&set, &d)?,
            };
            let netcfg_instance_id = key_string(&key, windows_sys::w!("NetCfgInstanceId"), false)?
                .ok_or(Error::Invalid("missing NetCfgInstanceId"))?;
            if cfg.as_ref().is_some_and(|c| c != &netcfg_instance_id) {
                return Err(Error::Changed);
            }
            let (presence_before, status_before, problem_before) = live(&instance, &d)?;
            let net_luid_index = key_dword(&key, windows_sys::w!("NetLuidIndex"))?;
            let if_type = key_dword(&key, windows_sys::w!("*IfType"))?;
            let (kind, b) = property(&set, &d, &DEVPKEY_Device_DriverDate, false)?
                .ok_or(Error::Invalid("missing driver date"))?;
            let date_filetime = filetime_property(kind, &b)?;
            let driver = DriverMetadata {
                provider: string(&set, &d, &DEVPKEY_Device_DriverProvider)?,
                version: string(&set, &d, &DEVPKEY_Device_DriverVersion)?,
                date_filetime,
                inf: string(&set, &d, &DEVPKEY_Device_DriverInfPath)?,
                matching_device_id: string(&set, &d, &DEVPKEY_Device_MatchingDeviceId)?,
                driver_key: string(&set, &d, &DEVPKEY_Device_Driver)?,
            };
            // Cross-check unified service/driver properties against SetupAPI's
            // registry view, without RegGetValue's implicit NUL repair.
            for (prop, expected) in [
                (SPDRP_SERVICE, service.as_deref()),
                (SPDRP_DRIVER, Some(driver.driver_key.as_str())),
            ] {
                let (kind, b) = registry_property(&set, &d, prop)?
                    .ok_or(Error::Invalid("missing service/driver property"))?;
                if Some(string_property(kind, REG_SZ, &b)?.as_str()) != expected {
                    return Err(Error::Changed);
                }
            }
            let description = string(&set, &d, &DEVPKEY_Device_DeviceDesc)?;
            let (presence, flags, problem) = live(&instance, &d)?;
            if presence != presence_before
                || flags != status_before
                || problem != problem_before
                || self::instance(&set, &d)? != instance
            {
                return Err(Error::Changed);
            }
            found.push(Device {
                instance,
                devinst: d.DevInst,
                presence,
                class_guid: guid_bytes(&d.ClassGuid),
                status: flags,
                problem,
                hardware_ids,
                compatible_ids,
                service: service.ok_or(Error::Invalid("missing device service"))?,
                description,
                // An absent private property is a queried negative fact. A
                // present empty/invalid property fails optional_string above.
                // Related devices still require the original exact private name.
                name: name.map(|n| n.value).unwrap_or_default(),
                wireguard_name,
                standard_name: friendly_name,
                netcfg_instance_id,
                net_luid_index,
                if_type,
                driver,
            });
        }
        Err(Error::Invalid("device enumeration incomplete/bound"))
    }
    struct NativeQueries;
    impl Queries for NativeQueries {
        fn interfaces(&mut self, want: &Expected) -> Result<Observed> {
            interfaces(want)
        }
        fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
            device_snapshot(targets)
        }
        fn table(&mut self) -> Result<Vec<Interface>> {
            table()
        }
        fn stack(&mut self) -> Result<Vec<StackEdge>> {
            stack()
        }
    }
    const _: () = {
        assert!(size_of::<NET_LUID_LH>() == 8);
        assert!(size_of::<GUID>() == 16);
        assert!(size_of::<MIB_IFSTACK_ROW>() == 8);
        assert!(std::mem::offset_of!(MIB_IFSTACK_TABLE, Table) == 4);
        assert!(std::mem::offset_of!(MIB_IF_ROW2, InterfaceIndex) == 8);
        assert!(std::mem::offset_of!(MIB_IF_ROW2, InterfaceGuid) == 12);
        assert!(DEVPROP_TYPE_FILETIME == 16);
        assert!(DEVPROP_TYPE_STRING == 18);
        assert!(REG_SZ == 1 && REG_MULTI_SZ == 7);
        assert!(DN_DRIVER_LOADED | DN_STARTED == 0xa);
        assert!(
            DN_HAS_PROBLEM
                | DN_PRIVATE_PROBLEM
                | DN_BOOT_LOG_PROB
                | DN_BAD_PARTIAL
                | DN_WILL_BE_REMOVED
                | DN_NEED_TO_ENUM
                == PROBLEM_OR_TRANSITION
        );
    };
}

#[cfg(test)]
#[path = "member_carrier_provider_tests.rs"]
mod tests;
