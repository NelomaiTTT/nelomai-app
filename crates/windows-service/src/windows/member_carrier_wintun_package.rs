//! Read-only, before-Wintun-load package observations. Not module/load authority.
#![allow(dead_code)] // Disconnected until main composes authenticated runtime authority.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid(&'static str),
    Unsupported(&'static str),
    Native(&'static str, u32),
    Changed,
    MaintenanceRequired,
}
type Result<T> = std::result::Result<T, Error>;
const MAX_SOURCE: usize = 32 * 1024 * 1024;
const MAX_INF: usize = 64 * 1024;
const MAX_RESOURCE: usize = 16 * 1024 * 1024;
const DRIVER_VERSION: u64 = 14 << 32;
// 2021-10-13 00:00 UTC, the stamped INF date (not DLL 0.14.1 version).
const DRIVER_DATE: u64 = 132_785_568_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Package {
    inf: Vec<u8>,
    cat: Vec<u8>,
    sys: Vec<u8>,
}

// An intentionally closed schema, not an INF installer or permissive projection.
// Only the audited native amd64 0.14.1 package's stamped INF is supported.
const INF_SCHEMA: &[(&str, &[&str])] = &[
    (
        "version",
        &[
            "signature=\"$Windows NT$\"",
            "class=net",
            "classguid={4d36e972-e325-11ce-bfc1-08002be10318}",
            "provider=%wintun.companyname%",
            "catalogfile.nt=wintun.cat",
            "pnplockdown=1",
            "driverver=10/13/2021,0.14.0.0",
        ],
    ),
    (
        "manufacturer",
        &["%wintun.companyname%=%wintun.name%,ntamd64"],
    ),
    ("sourcedisksnames", &["1=%wintun.diskdesc%,\"\",,"]),
    ("sourcedisksfiles", &["wintun.sys=1"]),
    (
        "destinationdirs",
        &["defaultdestdir=12", "wintun.copyfiles.sys=12"],
    ),
    ("wintun.copyfiles.sys", &["wintun.sys,,,0x00004002"]),
    (
        "wintun.ntamd64",
        &["%wintun.devicedesc%=wintun.install,wintun"],
    ),
    (
        "wintun.install",
        &[
            "characteristics=0x1",
            "addreg=wintun.ndi",
            "addproperty=wintun.properties",
            "copyfiles=wintun.copyfiles.sys",
            "*iftype=53",
            "*mediatype=19",
            "*physicalmediatype=0",
            "enabledhcp=0",
        ],
    ),
    (
        "wintun.properties",
        &["devicevendorwebsite,,,,\"https://www.wintun.net/\""],
    ),
    (
        "wintun.install.services",
        &["addservice=wintun,2,wintun.service,wintun.eventlog"],
    ),
    (
        "wintun.ndi",
        &[
            "hkr,ndi,service,0,wintun",
            "hkr,ndi\\interfaces,upperrange,,\"ndis5\"",
            "hkr,ndi\\interfaces,lowerrange,,\"nolower\"",
        ],
    ),
    (
        "wintun.service",
        &[
            "displayname=%wintun.name%",
            "description=%wintun.devicedesc%",
            "servicetype=1",
            "starttype=3",
            "errorcontrol=1",
            "servicebinary=%12%\\wintun.sys",
        ],
    ),
    (
        "wintun.eventlog",
        &[
            "hkr,,eventmessagefile,0x00020000,\"%11%\\IoLogMsg.dll;%12%\\wintun.sys\"",
            "hkr,,typessupported,0x00010001,7",
        ],
    ),
    (
        "strings",
        &[
            "wintun.name=\"Wintun\"",
            "wintun.diskdesc=\"Wintun Driver Install Disk\"",
            "wintun.devicedesc=\"Wintun Userspace Tunnel\"",
            "wintun.companyname=\"WireGuard LLC\"",
        ],
    ),
];
fn parse_inf(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_INF {
        return Err(Error::Invalid("INF bound"));
    }
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        if bytes.len() % 2 != 0 {
            return Err(Error::Invalid("UTF16 INF length"));
        }
        String::from_utf16(
            &bytes[2..]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error::Invalid("UTF16 INF"))?
    } else {
        std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
            .map_err(|_| Error::Invalid("UTF8 INF"))?
            .to_owned()
    };
    if !text.is_ascii() || text.contains('\0') {
        return Err(Error::Invalid("INF characters"));
    }
    let mut sections = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut current = None;
    for line in text.lines() {
        let mut quoted = false;
        let mut row = String::new();
        for c in line.chars() {
            if c == '"' {
                quoted = !quoted;
                row.push(c);
            } else if c == ';' && !quoted {
                break;
            } else if quoted {
                row.push(c);
            } else if !c.is_ascii_whitespace() {
                row.push(c.to_ascii_lowercase());
            }
        }
        if quoted {
            return Err(Error::Invalid("INF quote"));
        }
        if row.is_empty() {
            continue;
        }
        if row.starts_with('[') && row.ends_with(']') {
            let name = row[1..row.len() - 1].to_owned();
            if sections.insert(name.clone(), vec![]).is_some() {
                return Err(Error::Invalid("duplicate INF section"));
            }
            current = Some(name);
        } else {
            sections
                .get_mut(
                    current
                        .as_ref()
                        .ok_or(Error::Invalid("INF outside section"))?,
                )
                .ok_or(Error::Invalid("INF section"))?
                .push(row);
        }
    }
    if sections.len() != INF_SCHEMA.len() {
        return Err(Error::Unsupported("INF sections"));
    }
    for (section, expected) in INF_SCHEMA {
        let mut actual = sections
            .remove(*section)
            .ok_or(Error::Unsupported("INF platform/section"))?;
        let mut expected = expected.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        actual.sort();
        expected.sort();
        if actual != expected {
            return Err(Error::Unsupported("INF directive/version/provider"));
        }
    }
    Ok(())
}

fn slice(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    bytes
        .get(offset..offset.checked_add(size).ok_or(Error::Invalid("overflow"))?)
        .ok_or(Error::Invalid("truncated binary"))
}
fn u16_at(bytes: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        slice(bytes, p, 2)?
            .try_into()
            .map_err(|_| Error::Invalid("u16"))?,
    ))
}
fn u32_at(bytes: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        slice(bytes, p, 4)?
            .try_into()
            .map_err(|_| Error::Invalid("u32"))?,
    ))
}
fn pe_header(bytes: &[u8]) -> Result<usize> {
    if bytes.len() > MAX_SOURCE || slice(bytes, 0, 2)? != b"MZ" {
        return Err(Error::Invalid("PE bound/magic"));
    }
    let p = u32_at(bytes, 0x3c)? as usize;
    if slice(bytes, p, 4)? != b"PE\0\0"
        || u16_at(bytes, p + 4)? != 0x8664
        || u16_at(bytes, p + 24)? != 0x20b
        || u16_at(bytes, p + 20)? != 240
    {
        return Err(Error::Unsupported("native AMD64 PE32+ required"));
    }
    slice(bytes, p + 24, 240)?;
    Ok(p)
}
struct Pe<'a> {
    bytes: &'a [u8],
    sections: Vec<(u32, u32, usize)>,
}
impl<'a> Pe<'a> {
    fn new(bytes: &'a [u8], p: usize) -> Result<Self> {
        let count = u16_at(bytes, p + 6)? as usize;
        if count == 0 || count > 96 {
            return Err(Error::Invalid("PE sections"));
        }
        let mut sections = vec![];
        for i in 0..count {
            let s = p + 24 + 240 + i * 40;
            slice(bytes, s, 40)?;
            let rva = u32_at(bytes, s + 12)?;
            let size = u32_at(bytes, s + 16)?;
            let raw = u32_at(bytes, s + 20)? as usize;
            slice(bytes, raw, size as usize)?;
            let end = rva
                .checked_add(size)
                .ok_or(Error::Invalid("PE RVA overflow"))?;
            for &(other, other_end, _) in &sections {
                if rva < other_end && other < end {
                    return Err(Error::Invalid("overlapping PE sections"));
                }
            }
            sections.push((rva, end, raw));
        }
        Ok(Self { bytes, sections })
    }
    fn rva(&self, rva: u32, len: usize) -> Result<&'a [u8]> {
        let end = u64::from(rva) + len as u64;
        for &(start, limit, raw) in &self.sections {
            if rva >= start && end <= u64::from(limit) {
                return slice(self.bytes, raw + (rva - start) as usize, len);
            }
        }
        Err(Error::Invalid("unmapped PE RVA"))
    }
}
fn directory(bytes: &[u8], offset: usize) -> Result<Vec<(u32, u32)>> {
    slice(bytes, offset, 16)?;
    let names = u16_at(bytes, offset + 12)? as usize;
    let ids = u16_at(bytes, offset + 14)? as usize;
    if names + ids == 0 || names + ids > 128 {
        return Err(Error::Invalid("resource directory bound"));
    }
    let mut rows = vec![];
    for i in 0..names + ids {
        let key = u32_at(bytes, offset + 16 + i * 8)?;
        if (key >> 31 != 0) != (i < names) || rows.iter().any(|(k, _)| *k == key) {
            return Err(Error::Invalid("resource key"));
        }
        rows.push((key, u32_at(bytes, offset + 20 + i * 8)?));
    }
    Ok(rows)
}
fn extract_package(bytes: &[u8]) -> Result<Package> {
    let p = pe_header(bytes)?;
    let pe = Pe::new(bytes, p)?;
    if u32_at(bytes, p + 24 + 108)? != 16 {
        return Err(Error::Unsupported("PE directories"));
    }
    let rva = u32_at(bytes, p + 24 + 112 + 16)?;
    let size = u32_at(bytes, p + 24 + 112 + 20)? as usize;
    if size == 0 || size > MAX_RESOURCE {
        return Err(Error::Invalid("resource bound"));
    }
    let r = pe.rva(rva, size)?;
    let (_, type_dir) = directory(r, 0)?
        .into_iter()
        .find(|(key, _)| *key == 10)
        .ok_or(Error::Invalid("no RCDATA"))?;
    if type_dir >> 31 != 1 {
        return Err(Error::Invalid("RCDATA directory"));
    }
    let mut found = std::collections::BTreeMap::new();
    for (key, lang_dir) in directory(r, (type_dir & 0x7fffffff) as usize)? {
        if key >> 31 != 1 || lang_dir >> 31 != 1 {
            return Err(Error::Unsupported("named resources required"));
        }
        let off = (key & 0x7fffffff) as usize;
        let len = u16_at(r, off)? as usize;
        if len == 0 || len > 64 {
            return Err(Error::Invalid("resource name"));
        }
        let name = String::from_utf16(
            &slice(r, off + 2, len * 2)?
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error::Invalid("resource UTF16"))?
        .to_ascii_lowercase();
        if ![
            "wintun.inf",
            "wintun.cat",
            "wintun.sys",
            "wintun-arm64.inf",
            "wintun-arm64.cat",
            "wintun-arm64.sys",
            "setupapihost-arm64.dll",
        ]
        .contains(&name.as_str())
        {
            return Err(Error::Unsupported("unknown RCDATA"));
        }
        let langs = directory(r, (lang_dir & 0x7fffffff) as usize)?;
        if langs.len() != 1 || ![0, 1033].contains(&langs[0].0) || langs[0].1 >> 31 != 0 {
            return Err(Error::Unsupported("resource language"));
        }
        let ent = langs[0].1 as usize;
        let data_rva = u32_at(r, ent)?;
        let data_len = u32_at(r, ent + 4)? as usize;
        if data_len == 0
            || data_len > MAX_RESOURCE
            || u32_at(r, ent + 12)? != 0
            || ![0, 1200].contains(&u32_at(r, ent + 8)?)
        {
            return Err(Error::Invalid("resource data entry"));
        }
        // Require data inside this same resource range, not an arbitrary executable section.
        let relative = data_rva
            .checked_sub(rva)
            .ok_or(Error::Invalid("resource data RVA"))? as usize;
        let data = slice(r, relative, data_len)?.to_vec();
        if found.insert(name, data).is_some() {
            return Err(Error::Invalid("duplicate resource name"));
        }
    }
    let extras = [
        "wintun-arm64.inf",
        "wintun-arm64.cat",
        "wintun-arm64.sys",
        "setupapihost-arm64.dll",
    ]
    .iter()
    .filter(|n| found.contains_key(**n))
    .count();
    if extras != 0 && extras != 4 {
        return Err(Error::Invalid("partial ARM64 resource group"));
    }
    // Pinned amd64 sources may contain an unused ARM64 helper group. Native
    // machine/process checks below prohibit taking that DriverInstall branch.
    let mut take = |n| found.remove(n).ok_or(Error::Invalid("missing resource"));
    let package = Package {
        inf: take("wintun.inf")?,
        cat: take("wintun.cat")?,
        sys: take("wintun.sys")?,
    };
    parse_inf(&package.inf)?;
    pe_header(&package.sys)?;
    Ok(package)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    volume: u32,
    id: u64,
    size: u64,
    modified: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observed {
    stamp: Stamp,
    bytes: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    date: u64,
    version: u64,
    provider: String,
    published_inf: String,
    store_inf: String,
    store_cat: String,
    store_sys: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Device {
    instance: String,
    status: u32,
    problem: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Inventory {
    native_amd64_win10_plus: bool,
    candidates: Vec<Candidate>,
    // Includes ALL relevant instances, not just DIGCF_PRESENT.
    devices: Vec<Device>,
    service_type: u32,
    service_start: u32,
    service_state: u32,
    pending_maintenance: bool,
    pending: PendingSnapshot,
    system_sys: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct PendingSnapshot {
    queues: [Option<Vec<u8>>; 2],
    files: Vec<(String, Stamp)>,
}

// Private native boundary. No successful defaults, metadata-to-authority constructors,
// filesystem fallback, or deserializable proof. Tests replace only this boundary.
trait Kernel {
    type Pin;
    fn source(&mut self) -> Result<Observed>;
    fn inventory(&mut self) -> Result<Inventory>;
    fn open(&mut self, path: &str) -> Result<Self::Pin>;
    fn read(&mut self, pin: &Self::Pin) -> Result<Observed>;
    fn signatures(&mut self, pins: &[Self::Pin; 5]) -> Result<()>;
}
struct Checked<K: Kernel> {
    kernel: K,
    source: Observed,
    inventory: Inventory,
    files: [Observed; 5],
    pins: [K::Pin; 5],
    valid: bool,
}
fn validate_inventory(i: &Inventory) -> Result<&Candidate> {
    if !i.native_amd64_win10_plus {
        return Err(Error::Unsupported("OS/native machine"));
    }
    if !i.devices.is_empty()
        || i.candidates.len() != 1
        || i.service_type != 1
        || i.service_start != 3
        || i.service_state != 1
        || i.pending_maintenance
    {
        return Err(Error::MaintenanceRequired);
    }
    let c = &i.candidates[0];
    // Upstream iterates/removes EVERY older compatible node before choosing the
    // newest. A matching node plus an older/newer/duplicate node is NOT safe.
    if c.date != DRIVER_DATE || c.version != DRIVER_VERSION || c.provider != "WireGuard LLC" {
        return Err(Error::MaintenanceRequired);
    }
    Ok(c)
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn wide_z(words: &[u16]) -> Result<String> {
    if words.len() > 32768 {
        return Err(Error::Invalid("UTF16 bound"));
    }
    let end = words
        .iter()
        .position(|w| *w == 0)
        .ok_or(Error::Invalid("unterminated UTF16"))?;
    String::from_utf16(&words[..end]).map_err(|_| Error::Invalid("invalid UTF16"))
}
fn multi_sz(words: &[u16]) -> Result<Vec<String>> {
    if words.len() < 2 || words.len() > 32768 || !words.ends_with(&[0, 0]) {
        return Err(Error::Invalid("MULTI_SZ termination/bound"));
    }
    if words == [0, 0] {
        return Ok(vec![]);
    }
    let mut result = vec![];
    let mut pos = 0;
    while pos < words.len() - 1 {
        let end = words[pos..]
            .iter()
            .position(|w| *w == 0)
            .ok_or(Error::Invalid("MULTI_SZ item"))?;
        if end == 0 {
            return Err(Error::Invalid("empty MULTI_SZ item/trailing data"));
        }
        result.push(wide_z(&words[pos..pos + end + 1])?);
        pos += end + 1;
    }
    if pos != words.len() - 1 {
        return Err(Error::Invalid("MULTI_SZ length"));
    }
    Ok(result)
}
fn pending_deletions(
    bytes: &[u8],
    protected: &[String],
    audited_star_flags: bool,
    mut prove_file: impl FnMut(&str) -> Result<()>,
) -> Result<bool> {
    if bytes.len() < 4 || bytes.len() > 65536 || bytes.len() % 2 != 0 {
        return Err(Error::Invalid("pending rename length"));
    }
    let words = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    if words == [0, 0] {
        return Ok(false);
    }
    let mut pos = 0;
    let mut pairs = 0;
    while pos < words.len() {
        // Windows deletion pairs already end in two NULs. An additional
        // MULTI_SZ sentinel is accepted, but empty sources/trailing data aren't.
        if pos == words.len() - 1 && words[pos] == 0 {
            break;
        }
        let mut next = || -> Result<String> {
            let end = words[pos..]
                .iter()
                .position(|w| *w == 0)
                .ok_or(Error::Invalid("pending rename termination"))?;
            let item = String::from_utf16(&words[pos..pos + end])
                .map_err(|_| Error::Invalid("pending rename UTF16"))?;
            pos += end + 1;
            Ok(item)
        };
        let source = next()?;
        if pos == words.len() {
            return Err(Error::Invalid("pending rename orphan source"));
        }
        // Don't use ordinary MULTI_SZ parsing: it discards empty destinations.
        let end = words[pos..]
            .iter()
            .position(|w| *w == 0)
            .ok_or(Error::Invalid("pending destination termination"))?;
        let destination = String::from_utf16(&words[pos..pos + end])
            .map_err(|_| Error::Invalid("pending destination UTF16"))?;
        pos += end + 1;
        pairs += 1;
        if pairs > 128 || source.is_empty() {
            return Err(Error::Invalid("pending pair bound/source"));
        }
        // All renames/replacements remain maintenance: no destination/ancestor
        // normalization or assumption about an as-yet nonexistent target.
        if !destination.is_empty() {
            return Ok(true);
        }
        if source.starts_with('*') && !audited_star_flags {
            return Ok(true);
        }
        let Some(path) = pending_retired_path(&source) else {
            return Ok(true);
        };
        let lower = path.to_ascii_lowercase();
        if lower.contains("wintun")
            || lower.contains("nelomai")
            || protected.iter().any(|p| {
                let p = p.to_ascii_lowercase();
                lower == p || lower.strip_prefix(&p).is_some_and(|s| s.starts_with('\\'))
            })
            || prove_file(path).is_err()
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn pending_retired_path(source: &str) -> Option<&str> {
    // On the audited installed SMSS, '*' plus one flag WCHAR is removed
    // before opening a pending source. Accept ONLY observed flags 0/1, not
    // arbitrary '*X' prefixes or a general NT-path-to-DOS conversion.
    let source = source
        .strip_prefix("*0")
        .or_else(|| source.strip_prefix("*1"))
        .unwrap_or(source);
    let path = source.strip_prefix(r"\??\")?;
    let b = path.as_bytes();
    if !path.is_ascii() || b.len() < 4 || !b[0].is_ascii_alphabetic() || b[1..3] != *b":\\" {
        return None;
    }
    for component in path[3..].split('\\') {
        if component.is_empty()
            || component.ends_with(['.', ' '])
            || !component
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._- ()".contains(&b))
            || matches!(
                component.split('.').next()?.to_ascii_lowercase().as_str(),
                "con"
                    | "prn"
                    | "aux"
                    | "nul"
                    | "com1"
                    | "com2"
                    | "com3"
                    | "com4"
                    | "com5"
                    | "com6"
                    | "com7"
                    | "com8"
                    | "com9"
                    | "lpt1"
                    | "lpt2"
                    | "lpt3"
                    | "lpt4"
                    | "lpt5"
                    | "lpt6"
                    | "lpt7"
                    | "lpt8"
                    | "lpt9"
            )
        {
            return None;
        }
    }
    let name = path.rsplit('\\').next()?.to_ascii_lowercase();
    let retired_dll = name.rsplit_once(".dll.").is_some_and(|(base, n)| {
        !base.is_empty() && !n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit())
    });
    (name.ends_with(".tmp") || retired_dll).then_some(path)
}
fn pending_installation_root(source: &str) -> Option<&str> {
    let suffix = r"\runtime\engines\latest\0.3.3\wintun.dll";
    source
        .len()
        .checked_sub(suffix.len())
        .filter(|n| {
            source
                .get(*n..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        })
        .map(|n| &source[..n])
}
fn driver_detail_words(required: usize, id_offset: usize, capacity: usize) -> Result<usize> {
    // RequiredSize ends at the variable HardwareID buffer, not C tail padding.
    // Actual Win32 empty-ID replies are offsetof(HardwareID)+one WCHAR NUL.
    // cbSize supplied TO SetupAPI remains the FULL sizeof SDK structure.
    let tail = required
        .checked_sub(id_offset)
        .ok_or(Error::Invalid("driver detail prefix"))?;
    if required > capacity || tail < 2 || tail % 2 != 0 {
        return Err(Error::Invalid("driver detail bound"));
    }
    Ok(tail / 2)
}
fn service_query_buffer() -> Vec<u64> {
    // QueryServiceConfigW's RPC contract caps this array at8192 bytes; the
    // 64KiB SetupAPI/registry buffer is NOT legal for this different API.
    vec![0; 8 * 1024 / std::mem::size_of::<u64>()]
}
fn driver_ids(words: &[u16], offset: usize, length: usize) -> Result<Vec<String>> {
    if words.len() > 32768 || offset > words.len() {
        return Err(Error::Invalid("driver IDs bound"));
    }
    let mut ids = vec![];
    if offset > 1 {
        let primary = words
            .get(..offset)
            .ok_or(Error::Invalid("primary ID bound"))?;
        if primary.last() != Some(&0) || primary[..primary.len() - 1].contains(&0) {
            return Err(Error::Invalid("primary ID termination"));
        }
        ids.push(wide_z(primary)?);
    } else if words.first() != Some(&0) {
        return Err(Error::Invalid("missing primary ID sentinel"));
    }
    if length > 0 {
        let end = offset
            .checked_add(length)
            .ok_or(Error::Invalid("compatible ID overflow"))?;
        ids.extend(multi_sz(
            words
                .get(offset..end)
                .ok_or(Error::Invalid("compatible ID bound"))?,
        )?);
    }
    Ok(ids)
}
fn related_device(instance: &str, ids: &[String], service: Option<&str>) -> bool {
    let upper = instance.to_ascii_uppercase();
    upper == "SWD\\WINTUN"
        || upper.starts_with("SWD\\WINTUN\\")
        || upper == "ROOT\\WINTUN"
        || upper.starts_with("ROOT\\WINTUN\\")
        || ids.iter().any(|s| s.eq_ignore_ascii_case("Wintun"))
        || service.is_some_and(|s| s.eq_ignore_ascii_case("Wintun"))
}
fn trust_status(code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Native("WinVerifyTrust", code as u32))
    }
}
#[derive(Debug, PartialEq, Eq)]
struct SharePolicy {
    read: bool,
    write: bool,
    delete: bool,
}
fn share_policy(directory: bool) -> SharePolicy {
    SharePolicy {
        read: true,
        write: directory,
        delete: false,
    }
}
fn check<K: Kernel>(mut kernel: K) -> Result<Checked<K>> {
    let source = kernel.source()?;
    let package = extract_package(&source.bytes)?;
    let inventory = kernel.inventory()?;
    let c = validate_inventory(&inventory)?;
    let pins = [
        kernel.open(&c.published_inf)?,
        kernel.open(&c.store_inf)?,
        kernel.open(&c.store_cat)?,
        kernel.open(&c.store_sys)?,
        kernel.open(&inventory.system_sys)?,
    ];
    let files = [
        kernel.read(&pins[0])?,
        kernel.read(&pins[1])?,
        kernel.read(&pins[2])?,
        kernel.read(&pins[3])?,
        kernel.read(&pins[4])?,
    ];
    for (file, expected) in files.iter().zip([
        &package.inf,
        &package.inf,
        &package.cat,
        &package.sys,
        &package.sys,
    ]) {
        if file.bytes != *expected || file.stamp.size != file.bytes.len() as u64 {
            return Err(Error::Changed);
        }
    }
    kernel.signatures(&pins)?;
    let mut checked = Checked {
        kernel,
        source,
        inventory,
        files,
        pins,
        valid: true,
    };
    checked.reattest()?;
    Ok(checked)
}
impl<K: Kernel> Checked<K> {
    fn reattest(&mut self) -> Result<()> {
        if !self.valid {
            return Err(Error::Changed);
        }
        self.valid = false;
        self.refresh()?;
        self.valid = true;
        Ok(())
    }
    fn refresh(&mut self) -> Result<()> {
        // Fresh failures invalidate the caller's observation; no cached success.
        if self.kernel.source()? != self.source || self.kernel.inventory()? != self.inventory {
            return Err(Error::Changed);
        }
        for (pin, expected) in self.pins.iter().zip(&self.files) {
            if self.kernel.read(pin)? != *expected {
                return Err(Error::Changed);
            }
        }
        self.kernel.signatures(&self.pins)?;
        for (pin, expected) in self.pins.iter().zip(&self.files) {
            if self.kernel.read(pin)? != *expected {
                return Err(Error::Changed);
            }
        }
        if self.kernel.inventory()? != self.inventory || self.kernel.source()? != self.source {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

/// Actual Windows queries; nothing in this module loads Wintun as executable,
/// calls a Wintun export, registers a device, installs/removes a package, changes
/// the SCM, writes a registry value, or creates the upstream private namespace.
#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        mem::{offset_of, size_of},
        os::windows::{
            fs::{FileExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Component, Path, PathBuf},
        ptr,
    };
    use windows_sys::{
        core::w,
        Wdk::System::SystemServices::RtlGetVersion,
        Win32::{
            Devices::DeviceAndDriverInstallation::*,
            Foundation::{
                GetLastError, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
                FILETIME,
            },
            Security::{Cryptography::Catalog::*, WinTrust::*},
            Storage::FileSystem::*,
            System::{
                Registry::*,
                Services::*,
                SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW, OSVERSIONINFOW},
                Threading::{GetCurrentProcess, IsWow64Process2},
            },
        },
    };

    // Independent source pin for the audited 0.14.1 amd64 DLL in the 00:56
    // installed-package evidence. INF/SYS version is separately 0.14.0.0.
    const AUDITED_DLL_SHA256: [u8; 32] = [
        0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18, 0x85,
        0xc1, 0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3, 0x22, 0x0d,
        0xaf, 0xce,
    ];
    const BUFFER: usize = 64 * 1024;
    const MAX_NODES: u32 = 16_384;
    fn last(op: &'static str) -> Error {
        Error::Native(op, unsafe { GetLastError() })
    }
    fn io(op: &'static str, e: std::io::Error) -> Error {
        Error::Native(op, e.raw_os_error().unwrap_or(-1) as u32)
    }
    fn wide(s: &str) -> Result<Vec<u16>> {
        if s.contains('\0') || s.encode_utf16().count() > 32767 {
            return Err(Error::Invalid("native path/string"));
        }
        Ok(s.encode_utf16().chain([0]).collect())
    }
    fn ft(t: FILETIME) -> u64 {
        (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
    }
    fn native_platform() -> Result<bool> {
        let mut os = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        let status = unsafe { RtlGetVersion(&mut os) };
        if status != 0 {
            return Err(Error::Native("RtlGetVersion", status as u32));
        }
        if os.dwMajorVersion != 10 || os.dwMinorVersion != 0 || os.dwBuildNumber < 10240 {
            return Ok(false);
        }
        let (mut process, mut machine) = (0, 0);
        if unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut machine) } == 0 {
            return Err(last("IsWow64Process2"));
        }
        Ok(process == 0 && machine == 0x8664 && cfg!(target_arch = "x86_64"))
    }
    fn os_directory(system: bool) -> Result<PathBuf> {
        let mut b = [0u16; 32768];
        let n = unsafe {
            if system {
                GetSystemDirectoryW(b.as_mut_ptr(), b.len() as u32)
            } else {
                GetWindowsDirectoryW(b.as_mut_ptr(), b.len() as u32)
            }
        } as usize;
        if n == 0 {
            return Err(last("Get OS directory"));
        }
        if n >= b.len() {
            return Err(Error::Invalid("OS directory bound"));
        }
        Ok(PathBuf::from(wide_z(&b[..n + 1])?))
    }
    fn clean_absolute(path: &Path) -> Result<()> {
        let mut c = path.components();
        match c.next() {
            Some(Component::Prefix(p)) if matches!(p.kind(), std::path::Prefix::Disk(_)) => {}
            _ => return Err(Error::Unsupported("local DOS path required")),
        }
        if c.next() != Some(Component::RootDir) || c.any(|c| !matches!(c, Component::Normal(_))) {
            return Err(Error::Invalid("noncanonical native path"));
        }
        // Alternate data streams, device paths, trailing-dot/space aliases rejected.
        for part in path.components().filter_map(|c| {
            if let Component::Normal(p) = c {
                Some(p)
            } else {
                None
            }
        }) {
            let s = part.to_str().ok_or(Error::Invalid("non-Unicode path"))?;
            if s.contains(':') || s.ends_with(['.', ' ']) {
                return Err(Error::Invalid("aliased native path"));
            }
        }
        Ok(())
    }
    fn same_path(a: &Path, b: &Path) -> bool {
        a.to_str()
            .zip(b.to_str())
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
    }
    fn final_path(file: &File) -> Result<PathBuf> {
        let mut b = [0u16; 32768];
        let n = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                b.as_mut_ptr(),
                b.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return Err(last("GetFinalPathNameByHandleW"));
        }
        if n >= b.len() {
            return Err(Error::Invalid("final path bound"));
        }
        let text = wide_z(&b[..n + 1])?;
        let text = text
            .strip_prefix("\\\\?\\")
            .ok_or(Error::Invalid("final DOS path"))?;
        let path = PathBuf::from(text);
        clean_absolute(&path)?;
        Ok(path)
    }
    fn stamp(file: &File, directory: bool) -> Result<Stamp> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(last("GetFileInformationByHandle"));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || (!directory && info.nNumberOfLinks != 1)
        {
            return Err(Error::Invalid("reparse/type/link count"));
        }
        Ok(Stamp {
            volume: info.dwVolumeSerialNumber,
            id: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            modified: ft(info.ftLastWriteTime),
        })
    }
    fn readonly_open(path: &Path, directory: bool) -> Result<File> {
        clean_absolute(path)?;
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let file = OpenOptions::new()
            .read(true)
            // Attribute/security-only ancestor handles permit normal directory
            // activity. Payload handles retain GENERIC_READ and deny write/delete.
            .access_mode(if directory {
                FILE_READ_ATTRIBUTES | READ_CONTROL
            } else {
                windows_sys::Win32::Foundation::GENERIC_READ
            })
            .share_mode({
                let policy = share_policy(directory);
                (u32::from(policy.read) * FILE_SHARE_READ)
                    | (u32::from(policy.write) * FILE_SHARE_WRITE)
                    | (u32::from(policy.delete) * FILE_SHARE_DELETE)
            })
            .custom_flags(flags)
            .open(path)
            .map_err(|e| io("open readonly pin", e))?;
        stamp(&file, directory)?;
        if !same_path(&final_path(&file)?, path) {
            return Err(Error::Changed);
        }
        Ok(file)
    }
    struct Pin {
        file: File,
        path: PathBuf,
        parents: Vec<(File, PathBuf, Stamp)>,
    }
    impl Pin {
        fn open(path: &Path) -> Result<Self> {
            clean_absolute(path)?;
            let mut ancestors = path.ancestors().skip(1).collect::<Vec<_>>();
            ancestors.reverse();
            let mut parents = vec![];
            for path in ancestors {
                let file = readonly_open(path, true)?;
                let observed = stamp(&file, true)?;
                parents.push((file, path.to_owned(), observed));
            }
            let file = readonly_open(path, false)?;
            Ok(Self {
                file,
                path: path.to_owned(),
                parents,
            })
        }
        fn observe(&self) -> Result<Observed> {
            for (file, path, expected) in &self.parents {
                // Directory size/mtime changes from unrelated OS activity are not
                // identity replacement. Reparse/type/identity remain mandatory.
                let held = stamp(file, true)?;
                let reopened = readonly_open(path, true)?;
                let now = stamp(&reopened, true)?;
                if held.volume != expected.volume
                    || held.id != expected.id
                    || now.volume != expected.volume
                    || now.id != expected.id
                {
                    return Err(Error::Changed);
                }
            }
            let current = readonly_open(&self.path, false)?;
            if stamp(&current, false)? != stamp(&self.file, false)? {
                return Err(Error::Changed);
            }
            observe(&self.file)
        }
    }
    fn observe(file: &File) -> Result<Observed> {
        let before = stamp(file, false)?;
        let length = usize::try_from(before.size).map_err(|_| Error::Invalid("file size"))?;
        if length == 0 || length > MAX_SOURCE {
            return Err(Error::Invalid("file bound"));
        }
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < length {
            let count = file
                .seek_read(&mut bytes[offset..], offset as u64)
                .map_err(|e| io("read retained file", e))?;
            if count == 0 {
                return Err(Error::Changed);
            }
            offset += count;
        }
        if stamp(file, false)? != before {
            return Err(Error::Changed);
        }
        Ok(Observed {
            stamp: before,
            bytes,
        })
    }

    struct InfoSet(HDEVINFO);
    impl InfoSet {
        fn from(handle: HDEVINFO) -> Result<Self> {
            if handle == -1 {
                Err(last("SetupAPI inventory set"))
            } else {
                Ok(Self(handle))
            }
        }
    }
    impl Drop for InfoSet {
        fn drop(&mut self) {
            unsafe { SetupDiDestroyDeviceInfoList(self.0) };
        }
    }
    fn candidates(root: &Path) -> Result<Vec<Candidate>> {
        let set = InfoSet::from(unsafe {
            SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, ptr::null_mut())
        })?;
        // This changes only query-list configuration in our private, in-memory
        // HDEVINFO. No synthetic device/property setters or global enumeration writes.
        let mut params = SP_DEVINSTALL_PARAMS_W {
            cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
            ..Default::default()
        };
        if unsafe { SetupDiGetDeviceInstallParamsW(set.0, ptr::null(), &mut params) } == 0 {
            return Err(last("SetupDiGetDeviceInstallParamsW"));
        }
        let inf_dir = root.join("Inf");
        let driver_path = wide(inf_dir.to_str().ok_or(Error::Invalid("INF root"))?)?;
        if driver_path.len() > params.DriverPath.len() {
            return Err(Error::Invalid("INF root bound"));
        }
        params.DriverPath.fill(0);
        params.DriverPath[..driver_path.len()].copy_from_slice(&driver_path);
        params.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
        if unsafe { SetupDiSetDeviceInstallParamsW(set.0, ptr::null(), &params) } == 0 {
            return Err(last("SetupDiSetDeviceInstallParamsW query config"));
        }
        if unsafe { SetupDiBuildDriverInfoList(set.0, ptr::null_mut(), SPDIT_CLASSDRIVER) } == 0 {
            return Err(last("SetupDiBuildDriverInfoList"));
        }
        let mut found = vec![];
        for index in 0..MAX_NODES {
            let mut node = SP_DRVINFO_DATA_V2_W {
                cbSize: size_of::<SP_DRVINFO_DATA_V2_W>() as u32,
                ..Default::default()
            };
            if unsafe {
                SetupDiEnumDriverInfoW(set.0, ptr::null(), SPDIT_CLASSDRIVER, index, &mut node)
            } == 0
            {
                if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                    found.sort_by(|a: &Candidate, b| a.published_inf.cmp(&b.published_inf));
                    return Ok(found);
                }
                return Err(last("SetupDiEnumDriverInfoW"));
            }
            let mut storage = vec![0u64; BUFFER / 8];
            let detail = storage.as_mut_ptr().cast::<SP_DRVINFO_DETAIL_DATA_W>();
            unsafe { (*detail).cbSize = size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32 };
            let mut required = 0;
            if unsafe {
                SetupDiGetDriverInfoDetailW(
                    set.0,
                    ptr::null(),
                    &node,
                    detail,
                    BUFFER as u32,
                    &mut required,
                )
            } == 0
            {
                return Err(last("SetupDiGetDriverInfoDetailW"));
            }
            let id_offset = offset_of!(SP_DRVINFO_DETAIL_DATA_W, HardwareID);
            let word_count = driver_detail_words(required as usize, id_offset, BUFFER)?;
            // Backing allocation is initialized and larger than the FULL SDK
            // struct. Read all static fields but never count its C tail padding
            // as returned ID data or require Windows to include that padding.
            let info = unsafe { ptr::read(detail) };
            if info.cbSize != size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32 {
                return Err(Error::Invalid("driver detail cbSize"));
            }
            let words = unsafe {
                std::slice::from_raw_parts(
                    storage.as_ptr().cast::<u8>().add(id_offset).cast::<u16>(),
                    word_count,
                )
            };
            let ids = driver_ids(
                words,
                info.CompatIDsOffset as usize,
                info.CompatIDsLength as usize,
            )?;
            if !ids.iter().any(|id| id.eq_ignore_ascii_case("Wintun")) {
                continue;
            }
            if found.len() >= 64 {
                return Err(Error::Invalid("compatible candidates bound"));
            }
            let published = PathBuf::from(wide_z(&info.InfFileName)?);
            clean_absolute(&published)?;
            let filename = published
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(Error::Invalid("published INF name"))?
                .to_ascii_lowercase();
            let number = filename
                .strip_prefix("oem")
                .and_then(|s| s.strip_suffix(".inf"))
                .ok_or(Error::Unsupported("published OEM INF"))?;
            if number.is_empty()
                || !number.bytes().all(|b| b.is_ascii_digit())
                || !published.parent().is_some_and(|p| same_path(p, &inf_dir))
            {
                return Err(Error::Invalid("published INF location"));
            }
            let source = wide(published.to_str().ok_or(Error::Invalid("published INF"))?)?;
            let mut buffer = [0u16; 32768];
            let mut needed = 0;
            if unsafe {
                SetupGetInfDriverStoreLocationW(
                    source.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut needed,
                )
            } == 0
            {
                return Err(last("SetupGetInfDriverStoreLocationW"));
            }
            if needed == 0 || needed as usize > buffer.len() {
                return Err(Error::Invalid("driverstore location bound"));
            }
            let store = PathBuf::from(wide_z(&buffer[..needed as usize])?);
            clean_absolute(&store)?;
            let directory = store.parent().ok_or(Error::Invalid("driverstore parent"))?;
            let repo = os_directory(true)?
                .join("DriverStore")
                .join("FileRepository");
            if !store
                .file_name()
                .is_some_and(|s| s.eq_ignore_ascii_case("wintun.inf"))
                || !directory.parent().is_some_and(|p| same_path(p, &repo))
                || !directory
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.to_ascii_lowercase().starts_with("wintun.inf_amd64_"))
            {
                return Err(Error::Unsupported("driverstore platform/location"));
            }
            let path = |p: PathBuf| {
                p.to_str()
                    .map(str::to_owned)
                    .ok_or(Error::Invalid("native Unicode path"))
            };
            found.push(Candidate {
                date: ft(node.DriverDate),
                version: node.DriverVersion,
                provider: wide_z(&node.ProviderName)?,
                published_inf: path(published)?,
                store_inf: path(store.clone())?,
                store_cat: path(directory.join("wintun.cat"))?,
                store_sys: path(directory.join("wintun.sys"))?,
            });
        }
        Err(Error::Invalid("driver enumeration bound"))
    }
    fn property(
        set: &InfoSet,
        device: &SP_DEVINFO_DATA,
        property: SETUP_DI_REGISTRY_PROPERTY,
        expected_type: u32,
    ) -> Result<Option<Vec<u16>>> {
        let mut bytes = vec![0u8; BUFFER];
        let (mut kind, mut required) = (0, 0);
        if unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set.0,
                device,
                property,
                &mut kind,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut required,
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            if error == ERROR_INVALID_DATA {
                return Ok(None);
            }
            return Err(Error::Native("SetupDiGetDeviceRegistryPropertyW", error));
        }
        if kind != expected_type
            || required == 0
            || required as usize > bytes.len()
            || required % 2 != 0
        {
            return Err(Error::Invalid("device property type/bound"));
        }
        Ok(Some(
            bytes[..required as usize]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect(),
        ))
    }
    fn devices() -> Result<Vec<Device>> {
        // ALLCLASSES without PRESENT: includes legacy ROOT\NET, SWD stubs,
        // phantom/problem instances and unusual class/service bindings.
        let set = InfoSet::from(unsafe {
            SetupDiGetClassDevsW(ptr::null(), ptr::null(), ptr::null_mut(), DIGCF_ALLCLASSES)
        })?;
        let mut found = vec![];
        for index in 0..MAX_NODES {
            let mut device = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut device) } == 0 {
                if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                    found.sort_by(|a: &Device, b| a.instance.cmp(&b.instance));
                    return Ok(found);
                }
                return Err(last("SetupDiEnumDeviceInfo"));
            }
            let mut name = [0u16; 4096];
            let mut needed = 0;
            if unsafe {
                SetupDiGetDeviceInstanceIdW(
                    set.0,
                    &device,
                    name.as_mut_ptr(),
                    name.len() as u32,
                    &mut needed,
                )
            } == 0
            {
                return Err(last("SetupDiGetDeviceInstanceIdW"));
            }
            if needed == 0 || needed as usize > name.len() {
                return Err(Error::Invalid("device instance bound"));
            }
            let instance = wide_z(&name[..needed as usize])?;
            let mut ids = vec![];
            for prop in [SPDRP_HARDWAREID, SPDRP_COMPATIBLEIDS] {
                if let Some(words) = property(&set, &device, prop, REG_MULTI_SZ)? {
                    ids.extend(multi_sz(&words)?);
                }
            }
            let service = property(&set, &device, SPDRP_SERVICE, REG_SZ)?
                .map(|s| wide_z(&s))
                .transpose()?;
            if !related_device(&instance, &ids, service.as_deref()) {
                continue;
            }
            let (mut status, mut problem) = (0, 0);
            let result =
                unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, device.DevInst, 0) };
            if result != CR_SUCCESS {
                return Err(Error::Native("CM_Get_DevNode_Status", result));
            }
            if found.len() >= 4096 {
                return Err(Error::Invalid("Wintun device bound"));
            }
            found.push(Device {
                instance,
                status,
                problem,
            });
        }
        Err(Error::Invalid("device enumeration bound"))
    }
    struct ServiceHandle(SC_HANDLE);
    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
    fn service(system_sys: &Path, windows_root: &Path) -> Result<(u32, u32, u32)> {
        let manager =
            ServiceHandle(unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) });
        if manager.0.is_null() {
            return Err(last("OpenSCManagerW"));
        }
        let service = ServiceHandle(unsafe {
            OpenServiceW(
                manager.0,
                w!("Wintun"),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
            )
        });
        if service.0.is_null() {
            return Err(last("OpenServiceW Wintun"));
        }
        let mut storage = service_query_buffer();
        let capacity = std::mem::size_of_val(storage.as_slice());
        let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        let mut needed = 0;
        if unsafe { QueryServiceConfigW(service.0, config, capacity as u32, &mut needed) } == 0 {
            return Err(last("QueryServiceConfigW"));
        }
        let config = unsafe { ptr::read(config) };
        let base = storage.as_ptr() as usize;
        let address = config.lpBinaryPathName as usize;
        if address < base || address >= base + capacity || address % 2 != 0 {
            return Err(Error::Invalid("service binary pointer"));
        }
        let words = unsafe {
            std::slice::from_raw_parts(config.lpBinaryPathName, (base + capacity - address) / 2)
        };
        let binary = wide_z(words)?;
        let binary = binary
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(&binary);
        let path = if binary
            .get(..12)
            .is_some_and(|s| s.eq_ignore_ascii_case("\\SystemRoot\\"))
        {
            windows_root.join(&binary[12..])
        } else {
            PathBuf::from(binary)
        };
        clean_absolute(&path)?;
        if !same_path(&path, system_sys) {
            return Err(Error::Changed);
        }
        let mut status = SERVICE_STATUS_PROCESS::default();
        if unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(last("QueryServiceStatusEx"));
        }
        if status.dwServiceType != config.dwServiceType {
            return Err(Error::Changed);
        }
        Ok((
            config.dwServiceType,
            config.dwStartType,
            status.dwCurrentState,
        ))
    }

    struct CatalogContext(isize);
    impl Drop for CatalogContext {
        fn drop(&mut self) {
            unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }
    fn wintrust(data: &mut WINTRUST_DATA) -> Result<()> {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | WTD_DISABLE_MD2_MD4;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        let status = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (data as *mut WINTRUST_DATA).cast(),
            )
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let close = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (data as *mut WINTRUST_DATA).cast(),
            )
        };
        trust_status(status)?;
        trust_status(close)
    }
    fn signed_file(pin: &Pin) -> Result<()> {
        let path = wide(pin.path.to_str().ok_or(Error::Invalid("signature path"))?)?;
        let mut info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: pin.file.as_raw_handle(),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
            ..Default::default()
        };
        wintrust(&mut data)
    }
    fn catalog_member(cat: &Pin, member: &Pin, context: &CatalogContext) -> Result<()> {
        let mut digest = [0u8; 64];
        let mut length = digest.len() as u32;
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                context.0,
                member.file.as_raw_handle(),
                &mut length,
                digest.as_mut_ptr(),
                0,
            )
        } == 0
        {
            return Err(last("CryptCATAdminCalcHashFromFileHandle2"));
        }
        if length != 32 {
            return Err(Error::Unsupported("catalog SHA256 hash required"));
        }
        let tag = digest[..length as usize]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        let (tag, cat_path, member_path) = (
            wide(&tag)?,
            wide(cat.path.to_str().ok_or(Error::Invalid("catalog path"))?)?,
            wide(member.path.to_str().ok_or(Error::Invalid("member path"))?)?,
        );
        let mut info = WINTRUST_CATALOG_INFO {
            cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: cat_path.as_ptr(),
            pcwszMemberTag: tag.as_ptr(),
            pcwszMemberFilePath: member_path.as_ptr(),
            hMemberFile: member.file.as_raw_handle(),
            pbCalculatedFileHash: digest.as_mut_ptr(),
            cbCalculatedFileHash: length,
            hCatAdmin: context.0,
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            dwUnionChoice: WTD_CHOICE_CATALOG,
            Anonymous: WINTRUST_DATA_0 {
                pCatalog: &mut info,
            },
            ..Default::default()
        };
        wintrust(&mut data)
    }
    struct Native<'a> {
        source: &'a File,
    }
    struct RegistryKey(HKEY);
    impl Drop for RegistryKey {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }
    fn audited_smss_flags(path: &Path) -> Result<bool> {
        // DATA ONLY, never executable/module/creator authority. Windows keeps
        // this exact image hardlinked to WinSxS, unlike our single-link payload
        // pins. Do NOT weaken Pin/stamp for packages or unrelated deletion proof.
        clean_absolute(path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| io("read SMSS format data", e))?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(last("SMSS data metadata"));
        }
        if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
            || info.nFileSizeHigh != 0
            || info.nFileSizeLow != 245176
            || info.nNumberOfLinks != 2
            || !same_path(&final_path(&file)?, path)
        {
            return Ok(false);
        }
        let mut bytes = vec![0; info.nFileSizeLow as usize];
        let mut pos = 0;
        while pos < bytes.len() {
            let n = file
                .seek_read(&mut bytes[pos..], pos as u64)
                .map_err(|e| io("SMSS data read", e))?;
            if n == 0 {
                return Err(Error::Changed);
            }
            pos += n;
        }
        Ok(hash(&bytes)
            == [
                0x0d, 0x05, 0xe8, 0x1c, 0x57, 0x1a, 0xa0, 0x3f, 0x1d, 0xde, 0x5e, 0x8f, 0xa4, 0x0c,
                0xef, 0x98, 0xb7, 0x7e, 0x8e, 0xca, 0x64, 0x82, 0x1a, 0xe4, 0xef, 0xab, 0x12, 0x19,
                0x83, 0xd8, 0x1d, 0xe6,
            ])
    }
    fn pending_maintenance(
        source: &File,
        root: &Path,
        system: &Path,
        candidates: &[Candidate],
    ) -> Result<(bool, PendingSnapshot)> {
        let mut handle = ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                w!("SYSTEM\\CurrentControlSet\\Control\\Session Manager"),
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &mut handle,
            )
        };
        if status != 0 {
            return Err(Error::Native("open pending rename inventory", status));
        }
        let key = RegistryKey(handle);
        let mut pending = false;
        let mut snapshot = PendingSnapshot::default();
        for (index, name) in [
            w!("PendingFileRenameOperations"),
            w!("PendingFileRenameOperations2"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut bytes = vec![0u8; BUFFER];
            let (mut kind, mut length) = (0, bytes.len() as u32);
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name,
                    ptr::null(),
                    &mut kind,
                    bytes.as_mut_ptr(),
                    &mut length,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                continue;
            }
            if status != 0 {
                return Err(Error::Native("read pending rename inventory", status));
            }
            if kind != REG_MULTI_SZ || length as usize > bytes.len() || length % 2 != 0 {
                return Err(Error::Invalid("pending rename type/bound"));
            }
            #[cfg(test)]
            println!(
                "WINTUN_PACKAGE_PENDING type={} bytes={} nonzero_bytes={}",
                kind,
                length,
                bytes[..length as usize].iter().filter(|b| **b != 0).count()
            );
            bytes.truncate(length as usize);
            if bytes != [0, 0, 0, 0] {
                // This narrowed policy is valid only for the independently
                // audited installed 0.3.3 layout; unknown layouts remain denied.
                let source_path = final_path(source)?;
                let source_text = source_path
                    .to_str()
                    .ok_or(Error::Invalid("source layout"))?;
                let install = pending_installation_root(source_text);
                if let Some(install) = install {
                    let mut protected = vec![install.to_owned()];
                    for path in [
                        root.join("INF"),
                        system.join("drivers"),
                        system.join("DriverStore"),
                        system.join("CatRoot"),
                        system.join("CatRoot2"),
                        system.join("config"),
                        root.join("WinSxS"),
                        root.join("servicing"),
                    ] {
                        clean_absolute(&path)?;
                        protected.push(
                            path.to_str()
                                .ok_or(Error::Invalid("protected path"))?
                                .to_owned(),
                        );
                    }
                    for c in candidates {
                        for path in [&c.published_inf, &c.store_inf, &c.store_cat, &c.store_sys] {
                            let path = Path::new(path);
                            clean_absolute(path)?;
                            protected.push(
                                path.parent()
                                    .ok_or(Error::Invalid("package parent"))?
                                    .to_str()
                                    .ok_or(Error::Invalid("package path"))?
                                    .to_owned(),
                            );
                        }
                    }
                    // Undocumented '*' flags are accepted ONLY on the exact
                    // SMSS data image whose source stripping was inspected.
                    // An OS update defaults to maintenance, never a guessed format.
                    let audited_flags =
                        audited_smss_flags(&system.join("smss.exe")).unwrap_or(false);
                    pending |= pending_deletions(&bytes, &protected, audited_flags, |path| {
                        // Actual existing regular SINGLE-link file, canonical DOS
                        // path and every non-reparse ancestor, NOT a basename or
                        // metadata assertion. Missing/denied/alias/directory fail.
                        let pin = Pin::open(Path::new(path))?;
                        let stamp = stamp(&pin.file, false)?;
                        snapshot.files.push((path.to_owned(), stamp));
                        Ok(())
                    })?;
                } else {
                    pending = true;
                }
            }
            snapshot.queues[index] = Some(bytes);
        }
        Ok((pending, snapshot))
    }
    impl Kernel for Native<'_> {
        type Pin = Pin;
        fn source(&mut self) -> Result<Observed> {
            let source = observe(self.source)?;
            if hash(&source.bytes) != AUDITED_DLL_SHA256 {
                return Err(Error::Changed);
            }
            Ok(source)
        }
        fn inventory(&mut self) -> Result<Inventory> {
            let native_amd64_win10_plus = native_platform()?;
            if !native_amd64_win10_plus {
                return Err(Error::Unsupported("native platform"));
            }
            let root = os_directory(false)?;
            let system_root = os_directory(true)?;
            let system = system_root.join("drivers").join("wintun.sys");
            let candidates = candidates(&root)?;
            let devices = devices()?;
            let (service_type, service_start, service_state) = service(&system, &root)?;
            let (pending_maintenance, pending) =
                pending_maintenance(self.source, &root, &system_root, &candidates)?;
            Ok(Inventory {
                native_amd64_win10_plus,
                candidates,
                devices,
                service_type,
                service_start,
                service_state,
                pending_maintenance,
                pending,
                system_sys: system
                    .to_str()
                    .ok_or(Error::Invalid("system path"))?
                    .to_owned(),
            })
        }
        fn open(&mut self, path: &str) -> Result<Pin> {
            Pin::open(Path::new(path))
        }
        fn read(&mut self, pin: &Pin) -> Result<Observed> {
            pin.observe()
        }
        fn signatures(&mut self, pins: &[Pin; 5]) -> Result<()> {
            // Direct embedded Authenticode + signed catalog and actual membership,
            // never GetAuthenticodeSignature text/JSON or a caller success flag.
            signed_file(&pins[2])?;
            signed_file(&pins[4])?;
            let mut raw = 0;
            if unsafe {
                CryptCATAdminAcquireContext2(&mut raw, ptr::null(), w!("SHA256"), ptr::null(), 0)
            } == 0
            {
                return Err(last("CryptCATAdminAcquireContext2"));
            }
            let context = CatalogContext(raw);
            for index in [0, 1, 3, 4] {
                catalog_member(&pins[2], &pins[index], &context)?;
            }
            Ok(())
        }
    }

    /// Non-Clone/non-serializable read-only observation owning retained installed
    /// file pins and borrowing the independently authenticated DLL source pin.
    /// No implementation of ModuleRuntimeAuthority, no load/create permission.
    pub(crate) struct CheckedExistingPackage<'a> {
        checked: Checked<Native<'a>>,
        // Borrowed source/runtime guard continuity must remain on the serialized
        // caller thread. This observation cannot be moved to a detached worker.
        not_send: std::marker::PhantomData<std::rc::Rc<()>>,
    }
    impl CheckedExistingPackage<'_> {
        pub(crate) fn reattest(&mut self) -> Result<()> {
            self.checked.reattest()
        }
    }
    /// Required main interface: borrow its authenticated retained read-only File
    /// (`WintunSource::file()`), bracket this call and each reattestation with
    /// `WintunSource::verify()`, retain the ORIGINAL source object and runtime lock.
    /// Main already verifies its signed manifest hash; this module additionally
    /// requires the independent audited 0.14.1 DLL hash. No source pathname accepted.
    ///
    /// # Safety
    /// Caller MUST retain independently authenticated Installation/current-exe,
    /// runtime MutationGuard continuity, signed full payload verification, the
    /// source's FILE_SHARE_READ-only/no-reparse/single-link ancestor pins, and
    /// serialize with its actual runtime/mutation lock before AND after this call
    /// and every reattestation. `File`/hash alone do not authenticate that context.
    /// This contract is a deliberately OPEN composition seam, not a safe path-only
    /// trust fallback or an assertion that later upstream maintenance is impossible.
    pub(crate) unsafe fn from_authenticated_source(
        source: &File,
    ) -> Result<CheckedExistingPackage<'_>> {
        check(Native { source }).map(|checked| CheckedExistingPackage {
            checked,
            not_send: std::marker::PhantomData,
        })
    }

    #[cfg(test)]
    mod installed_data_tests {
        use super::*;

        /// Explicit diagnostic: raw native query/parser/trust coverage ONLY.
        /// Does not construct CheckedExistingPackage/ModuleRuntimeAuthority and
        /// does NOT authenticate this test process as the installed runtime.
        /// No Wintun executable loading, exports or package/device writes.
        #[test]
        #[ignore = "requires separately authorized DESKTOP-1DGFU8K data-only hardware gate"]
        fn installed_cold_package_data_readback() {
            assert_eq!(
                std::env::var("COMPUTERNAME").as_deref(),
                Ok("DESKTOP-1DGFU8K")
            );
            // Independent child deadline: this diagnostic performs reads only,
            // so abort releases its own file/query/trust handles, no adoption or
            // compensating driver/device cleanup. Outer retained process also
            // supervises it. Never use this pattern around mutating native calls.
            let _deadline = std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_secs(30));
                std::process::abort();
            });
            println!("WINTUN_PACKAGE_BEGIN data_only=true deadline_seconds=30");
            let source = Pin::open(Path::new(
                "C:\\Program Files\\Nelomai\\runtime\\engines\\latest\\0.3.3\\wintun.dll",
            ))
            .expect("retain installed data-only source");
            let inventory = Native {
                source: &source.file,
            }
            .inventory()
            .expect("read cold inventory before validation");
            println!(
                "WINTUN_PACKAGE_INVENTORY candidates={} devices={} service_type={} service_start={} service_state={} pending_maintenance={}",
                inventory.candidates.len(), inventory.devices.len(),
                inventory.service_type, inventory.service_start, inventory.service_state,
                inventory.pending_maintenance,
            );
            for candidate in &inventory.candidates {
                println!(
                    "WINTUN_PACKAGE_CANDIDATE date={} version={} provider_matches={}",
                    candidate.date,
                    candidate.version,
                    candidate.provider == "WireGuard LLC"
                );
            }
            for device in &inventory.devices {
                println!(
                    "WINTUN_PACKAGE_DEVICE status={} problem={}",
                    device.status, device.problem
                );
            }
            let mut observed = check(Native {
                source: &source.file,
            })
            .expect("actual cold package data observations");
            observed
                .reattest()
                .expect("repeat exact native data observations");
            assert_eq!(observed.inventory.candidates.len(), 1);
            assert!(observed.inventory.devices.is_empty());
            println!(
                "WINTUN_PACKAGE_READBACK source_sha256={} candidate_date={} candidate_version={} service_type={} service_start={} service_state={} pending_maintenance={} devices={}",
                hex(&hash(&observed.source.bytes)),
                observed.inventory.candidates[0].date,
                observed.inventory.candidates[0].version,
                observed.inventory.service_type,
                observed.inventory.service_start,
                observed.inventory.service_state,
                observed.inventory.pending_maintenance,
                observed.inventory.devices.len(),
            );
            for (role, file) in [
                "published-inf",
                "store-inf",
                "store-cat",
                "store-sys",
                "system-sys",
            ]
            .into_iter()
            .zip(&observed.files)
            {
                println!(
                    "WINTUN_PACKAGE_FILE role={} sha256={} volume={} id={} bytes={}",
                    role,
                    hex(&hash(&file.bytes)),
                    file.stamp.volume,
                    file.stamp.id,
                    file.stamp.size
                );
            }
            println!("WINTUN_PACKAGE_SCOPE data_only=true runtime_authority=false executable_load=false device_effects=false");
        }
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_wintun_package_tests.rs"]
mod tests;
