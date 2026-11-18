use super::{DnsIntent, ServiceDns};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::{Boolean, CFType, CFTypeRef, TCFType},
    dictionary::{
        CFDictionary, CFDictionaryCreateMutableCopy, CFDictionaryRef, CFMutableDictionary,
    },
    string::{CFString, CFStringRef},
};
use std::{
    io,
    net::IpAddr,
    ptr, thread,
    time::{Duration, Instant},
};

const PREFS_BUSY: i32 = 3002; // kSCStatusPrefsBusy

#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    static kSCNetworkProtocolTypeDNS: CFStringRef;
    static kSCPropNetDNSServerAddresses: CFStringRef;
    fn SCError() -> i32;
    fn SCPreferencesCreate(allocator: CFTypeRef, name: CFStringRef, id: CFStringRef) -> CFTypeRef;
    fn SCPreferencesLock(prefs: CFTypeRef, wait: Boolean) -> Boolean;
    fn SCPreferencesUnlock(prefs: CFTypeRef) -> Boolean;
    fn SCPreferencesSynchronize(prefs: CFTypeRef);
    fn SCPreferencesGetValue(prefs: CFTypeRef, key: CFStringRef) -> CFTypeRef;
    fn SCPreferencesSetValue(prefs: CFTypeRef, key: CFStringRef, value: CFTypeRef) -> Boolean;
    fn SCPreferencesRemoveValue(prefs: CFTypeRef, key: CFStringRef) -> Boolean;
    fn SCPreferencesCommitChanges(prefs: CFTypeRef) -> Boolean;
    fn SCPreferencesApplyChanges(prefs: CFTypeRef) -> Boolean;
    fn SCNetworkSetCopyCurrent(prefs: CFTypeRef) -> CFTypeRef;
    fn SCNetworkSetCopyServices(set: CFTypeRef) -> CFArrayRef;
    fn SCNetworkServiceCopyAll(prefs: CFTypeRef) -> CFArrayRef;
    fn SCNetworkServiceGetEnabled(service: CFTypeRef) -> Boolean;
    fn SCNetworkServiceGetName(service: CFTypeRef) -> CFStringRef;
    fn SCNetworkServiceGetServiceID(service: CFTypeRef) -> CFStringRef;
    fn SCNetworkServiceCopyProtocol(service: CFTypeRef, protocol_type: CFStringRef) -> CFTypeRef;
    fn SCNetworkProtocolGetConfiguration(protocol: CFTypeRef) -> CFDictionaryRef;
    fn SCNetworkProtocolSetConfiguration(protocol: CFTypeRef, config: CFDictionaryRef) -> Boolean;
}

struct LockedPreferences(CFType);

impl LockedPreferences {
    fn open() -> io::Result<Self> {
        let name = CFString::new("Nelomai DNS recovery");
        let raw =
            unsafe { SCPreferencesCreate(ptr::null(), name.as_concrete_TypeRef(), ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::other("dns_preferences_unavailable"));
        }
        let prefs = unsafe { CFType::wrap_under_create_rule(raw) };
        let deadline = Instant::now() + super::START_TIMEOUT;
        while unsafe { SCPreferencesLock(raw, 0) } == 0 {
            if unsafe { SCError() } != PREFS_BUSY || Instant::now() >= deadline {
                return Err(io::Error::other("dns_preferences_lock_failed"));
            }
            thread::sleep(Duration::from_millis(25));
        }
        unsafe { SCPreferencesSynchronize(raw) };
        Ok(Self(prefs))
    }

    fn commit(&self) -> io::Result<()> {
        if unsafe { SCPreferencesCommitChanges(self.0.as_CFTypeRef()) } == 0 {
            return Err(io::Error::other("dns_commit_failed"));
        }
        Ok(())
    }

    fn apply(&self) -> io::Result<()> {
        if unsafe { SCPreferencesApplyChanges(self.0.as_CFTypeRef()) } == 0 {
            return Err(io::Error::other("dns_apply_failed"));
        }
        Ok(())
    }
}

impl Drop for LockedPreferences {
    fn drop(&mut self) {
        unsafe { SCPreferencesUnlock(self.0.as_CFTypeRef()) };
    }
}

pub(super) fn snapshot() -> io::Result<Vec<ServiceDns>> {
    let prefs = LockedPreferences::open()?;
    let services = network_services(&prefs, true)?;
    let key = server_addresses_key();
    let mut saved = Vec::new();
    for service in services.iter() {
        let native = service.as_CFTypeRef();
        if unsafe { SCNetworkServiceGetEnabled(native) } == 0 {
            continue;
        }
        let id =
            service_id(native).ok_or_else(|| io::Error::other("dns_service_id_unavailable"))?;
        let name = cf_string(unsafe { SCNetworkServiceGetName(native) })
            .ok_or_else(|| io::Error::other("dns_service_name_unavailable"))?;
        let protocol =
            dns_protocol(native).ok_or_else(|| io::Error::other("dns_protocol_unavailable"))?;
        let (servers, _) = read_protocol(&protocol, &key);
        let servers = servers.ok_or_else(|| io::Error::other("dns_server_list_unavailable"))?;
        saved.push(ServiceDns {
            id: Some(id),
            name,
            servers,
            search_domains: Vec::new(),
        });
    }
    if saved.is_empty() {
        return Err(io::Error::other("dns_network_services_unavailable"));
    }
    Ok(saved)
}

pub(super) fn apply(services: &[ServiceDns], intent: &DnsIntent) -> io::Result<()> {
    let prefs = LockedPreferences::open()?;
    let key = receipt_key(intent);
    if receipt(&prefs, &key)?.is_some() {
        return Err(io::Error::other("dns_receipt_already_committed"));
    }
    if stage_updates(&prefs, services, &intent.servers, Action::Apply)? {
        // The caller has persisted the intent. The receipt and the server
        // updates become visible together, including after a crash in Commit.
        stage_receipt(&prefs, &key, Receipt::Committed)?;
        prefs.commit()?;
        prefs.apply()?;
    }
    Ok(())
}

pub(super) fn restore(services: &[ServiceDns], intent: &DnsIntent) -> io::Result<()> {
    let prefs = LockedPreferences::open()?;
    let key = receipt_key(intent);
    match receipt(&prefs, &key)? {
        None => return Ok(()),
        Some(Receipt::Committed) => {
            if commit_restore(&prefs, &key, services, &intent.servers)? {
                prefs.apply()?;
            }
        }
        Some(Receipt::RestorePendingApply) => prefs.apply()?,
    }
    if unsafe { SCPreferencesRemoveValue(prefs.0.as_CFTypeRef(), key.as_concrete_TypeRef()) } == 0 {
        return Err(io::Error::other("dns_receipt_remove_failed"));
    }
    prefs.commit()
}

fn commit_restore(
    prefs: &LockedPreferences,
    key: &CFString,
    services: &[ServiceDns],
    applied: &[IpAddr],
) -> io::Result<bool> {
    if !stage_updates(prefs, services, applied, Action::Restore)? {
        return Ok(false);
    }
    // A restart before Apply must only signal the committed settings. An
    // external writer may already have updated the server list again.
    stage_receipt(prefs, key, Receipt::RestorePendingApply)?;
    prefs.commit()?;
    Ok(true)
}

enum Receipt {
    Committed,
    RestorePendingApply,
}

fn receipt_key(intent: &DnsIntent) -> CFString {
    CFString::new(&format!(
        "ru.nelomai.tunnel.dns-receipt.{}",
        URL_SAFE_NO_PAD.encode(intent.token)
    ))
}

fn receipt(prefs: &LockedPreferences, key: &CFString) -> io::Result<Option<Receipt>> {
    let raw = unsafe { SCPreferencesGetValue(prefs.0.as_CFTypeRef(), key.as_concrete_TypeRef()) };
    if raw.is_null() {
        return Ok(None);
    }
    let value = unsafe { CFType::wrap_under_get_rule(raw) };
    match value
        .downcast::<CFString>()
        .map(|state| state.to_string())
        .as_deref()
    {
        Some("committed") => Ok(Some(Receipt::Committed)),
        Some("restore-pending-apply") => Ok(Some(Receipt::RestorePendingApply)),
        _ => Err(io::Error::other("dns_receipt_invalid")),
    }
}

fn stage_receipt(prefs: &LockedPreferences, key: &CFString, state: Receipt) -> io::Result<()> {
    let value = CFString::new(match state {
        Receipt::Committed => "committed",
        Receipt::RestorePendingApply => "restore-pending-apply",
    });
    if unsafe {
        SCPreferencesSetValue(
            prefs.0.as_CFTypeRef(),
            key.as_concrete_TypeRef(),
            value.as_CFTypeRef(),
        )
    } == 0
    {
        return Err(io::Error::other("dns_receipt_stage_failed"));
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    Apply,
    Restore,
}

/// All comparisons and writes share the system preference lock. Matches use
/// the stable service ID, so a rename or network location change does not
/// change ownership. Only the address property is written.
fn stage_updates(
    prefs: &LockedPreferences,
    saved: &[ServiceDns],
    addresses: &[IpAddr],
    action: Action,
) -> io::Result<bool> {
    let native_services = network_services(prefs, action == Action::Apply)?;
    let key = server_addresses_key();
    let addresses = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let (mut changed, mut found) = (false, 0);
    for service in native_services.iter() {
        let native = service.as_CFTypeRef();
        if action == Action::Apply && unsafe { SCNetworkServiceGetEnabled(native) } == 0 {
            continue;
        }
        let Some(protocol) = dns_protocol(native) else {
            if action == Action::Apply {
                return Err(io::Error::other("dns_protocol_unavailable"));
            }
            continue;
        };
        let id = service_id(native);
        let Some(saved) = saved.iter().find(|saved| id.is_some() && saved.id == id) else {
            if action == Action::Apply {
                return Err(io::Error::other("dns_service_changed_during_start"));
            }
            continue;
        };
        found += 1;
        let (current, config) = read_protocol(&protocol, &key);
        let (before, after) = match action {
            Action::Apply => (saved.servers.as_slice(), addresses.as_slice()),
            Action::Restore => (addresses.as_slice(), saved.servers.as_slice()),
        };
        // An unreadable value cannot match what we wrote. Treat it like any
        // other external edit so cleanup can still restore the other services.
        if current.as_deref() != Some(before) {
            if action == Action::Apply {
                return Err(io::Error::other("dns_changed_during_start"));
            }
            continue;
        }
        if before != after {
            stage_servers(&protocol, config, &key, after)?;
            changed = true;
        }
    }
    if action == Action::Apply && found != saved.len() {
        return Err(io::Error::other("dns_service_changed_during_start"));
    }
    Ok(changed)
}

fn network_services(prefs: &LockedPreferences, current_only: bool) -> io::Result<CFArray<CFType>> {
    let raw = prefs.0.as_CFTypeRef();
    let services = if current_only {
        let current = unsafe { SCNetworkSetCopyCurrent(raw) };
        if current.is_null() {
            return Err(io::Error::other("dns_network_set_unavailable"));
        }
        let current = unsafe { CFType::wrap_under_create_rule(current) };
        unsafe { SCNetworkSetCopyServices(current.as_CFTypeRef()) }
    } else {
        unsafe { SCNetworkServiceCopyAll(raw) }
    };
    if services.is_null() {
        return Err(io::Error::other("dns_network_services_unavailable"));
    }
    Ok(unsafe { CFArray::wrap_under_create_rule(services) })
}

fn service_id(service: CFTypeRef) -> Option<String> {
    cf_string(unsafe { SCNetworkServiceGetServiceID(service) })
}

fn cf_string(value: CFStringRef) -> Option<String> {
    (!value.is_null()).then(|| unsafe { CFString::wrap_under_get_rule(value) }.to_string())
}

fn dns_protocol(service: CFTypeRef) -> Option<CFType> {
    let protocol = unsafe { SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeDNS) };
    (!protocol.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(protocol) })
}

fn server_addresses_key() -> CFString {
    unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) }
}

fn read_protocol(protocol: &CFType, key: &CFString) -> (Option<Vec<String>>, CFDictionaryRef) {
    let config = unsafe { SCNetworkProtocolGetConfiguration(protocol.as_CFTypeRef()) };
    if config.is_null() {
        return (Some(Vec::new()), config);
    }
    let wrapped = unsafe { CFDictionary::<CFString, CFType>::wrap_under_get_rule(config) };
    (configured_servers(&wrapped, key), config)
}

fn stage_servers(
    protocol: &CFType,
    config: CFDictionaryRef,
    key: &CFString,
    addresses: &[String],
) -> io::Result<()> {
    let mut updated = if config.is_null() {
        CFMutableDictionary::<CFString, CFType>::new()
    } else {
        let copy = unsafe { CFDictionaryCreateMutableCopy(ptr::null(), 0, config) };
        if copy.is_null() {
            return Err(io::Error::other("dns_configuration_copy_failed"));
        }
        unsafe { CFMutableDictionary::<CFString, CFType>::wrap_under_create_rule(copy) }
    };
    if addresses.is_empty() {
        updated.remove(key.clone());
    } else {
        let servers = addresses
            .iter()
            .map(|address| CFString::new(address))
            .collect::<Vec<_>>();
        updated.set(key.clone(), CFArray::from_CFTypes(&servers).as_CFType());
    }
    let config = updated.to_immutable();
    if unsafe {
        SCNetworkProtocolSetConfiguration(protocol.as_CFTypeRef(), config.as_concrete_TypeRef())
    } == 0
    {
        return Err(io::Error::other("dns_stage_failed"));
    }
    Ok(())
}

fn configured_servers(
    config: &CFDictionary<CFString, CFType>,
    key: &CFString,
) -> Option<Vec<String>> {
    let Some(value) = config.find(key) else {
        return Some(Vec::new());
    };
    value
        .downcast::<CFArray>()?
        .iter()
        .map(|item| {
            let value = unsafe { CFType::wrap_under_get_rule(*item) };
            value
                .downcast::<CFString>()
                .map(|address| address.to_string())
        })
        .collect()
}

#[cfg(test)]
pub(super) fn set_test_servers(service_id_to_change: &str, addresses: &[String]) -> io::Result<()> {
    let prefs = LockedPreferences::open()?;
    let services = network_services(&prefs, false)?;
    let protocol = services
        .iter()
        .find(|service| service_id(service.as_CFTypeRef()).as_deref() == Some(service_id_to_change))
        .and_then(|service| dns_protocol(service.as_CFTypeRef()))
        .ok_or_else(|| io::Error::other("qa_dns_service_unavailable"))?;
    let key = server_addresses_key();
    let (_, config) = read_protocol(&protocol, &key);
    stage_servers(&protocol, config, &key, addresses)?;
    prefs.commit()?;
    prefs.apply()
}

#[cfg(test)]
pub(super) fn commit_restore_before_restart(
    services: &[ServiceDns],
    intent: &DnsIntent,
) -> io::Result<bool> {
    let prefs = LockedPreferences::open()?;
    let key = receipt_key(intent);
    assert!(matches!(receipt(&prefs, &key)?, Some(Receipt::Committed)));
    commit_restore(&prefs, &key, services, &intent.servers)
}

#[cfg(test)]
pub(super) fn update_after_holding_lock(
    services: &[ServiceDns],
    applied: &[IpAddr],
    ready: &std::path::Path,
) -> io::Result<()> {
    let prefs = LockedPreferences::open()?;
    std::fs::write(ready, [])?;
    thread::sleep(Duration::from_millis(200));
    if stage_updates(&prefs, services, applied, Action::Restore)? {
        prefs.commit()?;
        prefs.apply()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_servers_preserve_scoped_ipv6_and_native_spelling() {
        let key = server_addresses_key();
        let expected = ["fe80::1%en0", "2001:0DB8::1", "9.9.9.9"];
        let servers = expected.map(CFString::new);
        let mut config = CFMutableDictionary::new();
        config.set(key.clone(), CFArray::from_CFTypes(&servers).as_CFType());
        let actual = configured_servers(&config.to_immutable(), &key).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn missing_and_unreadable_server_lists_are_distinct() {
        let key = server_addresses_key();
        let config = CFMutableDictionary::new().to_immutable();
        assert_eq!(configured_servers(&config, &key), Some(Vec::new()));

        let mut config = CFMutableDictionary::new();
        config.set(key.clone(), CFString::new("9.9.9.9").as_CFType());
        assert_eq!(configured_servers(&config.to_immutable(), &key), None);

        let mut config = CFMutableDictionary::new();
        let addresses = [
            CFString::new("9.9.9.9").as_CFType(),
            CFArray::<CFString>::from_CFTypes(&[]).as_CFType(),
        ];
        config.set(key.clone(), CFArray::from_CFTypes(&addresses).as_CFType());
        assert_eq!(configured_servers(&config.to_immutable(), &key), None);
    }
}
