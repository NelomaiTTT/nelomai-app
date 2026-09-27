use nelomai_client_tunnel::redundancy::network::*;
use std::io;

struct DnsOnly {
    value: NetworkValue,
    writes: usize,
}
impl NetworkSystem for DnsOnly {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        assert!(
            matches!(key,ResourceKey::Dns(s) if s=="Wi-Fi"),
            "never inspect reused native indices after reboot"
        );
        Ok(Some(self.value.clone()))
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        assert_eq!(self.read(key)?.as_ref(), before);
        self.value = after.unwrap().clone();
        self.writes += 1;
        Ok(())
    }
}
struct Store {
    fail: bool,
}
impl NetworkJournalStore for Store {
    fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
        if self.fail {
            Err(io::Error::other("disk"))
        } else {
            Ok(())
        }
    }
}
fn dns(ip: &str) -> NetworkValue {
    NetworkValue::Dns(DnsValue {
        service: "Wi-Fi".into(),
        servers: vec![ip.parse().unwrap()],
    })
}
fn journal(pending: bool) -> NetworkJournal {
    serde_json::from_value(serde_json::json!({
        "owned":[
            {"original":dns("192.0.2.53"),"current":dns("9.9.9.9")},
            {"original":null,"current":{"Route":{"destination":"0.0.0.0/1","scope":"Global","interface":42,"gateway":null,"metric":0}}}
        ],"active":"A","stopping":false,
        "pending":if pending {serde_json::json!({"target":[{"original":dns("192.0.2.53"),"current":dns("77.88.8.8")}],"active":"B"})}else{serde_json::Value::Null}
    })).unwrap()
}
#[test]
fn reboot_cleanup_restores_only_exact_persistent_dns_never_old_routes() {
    for (pending, current, writes) in [
        (false, "9.9.9.9", 1),
        (false, "192.0.2.53", 0),
        (true, "77.88.8.8", 1),
        (true, "9.9.9.9", 1),
    ] {
        let saved = journal(pending).persistent_dns_cleanup().unwrap();
        let mut owner = NetworkOwner::recover(
            DnsOnly {
                value: dns(current),
                writes: 0,
            },
            Store { fail: false },
            saved,
        )
        .unwrap();
        assert!(owner.active().is_none());
        owner.cleanup().unwrap();
        assert!(!owner.has_resources());
        assert_eq!(owner.system_mut().value, dns("192.0.2.53"));
        assert_eq!(owner.system_mut().writes, writes);
    }
}
#[test]
fn reboot_cleanup_preserves_foreign_dns_and_waits_for_journal_writes() {
    for (current, fail) in [("203.0.113.53", false), ("9.9.9.9", true)] {
        let saved = journal(false).persistent_dns_cleanup().unwrap();
        let mut owner = NetworkOwner::recover(
            DnsOnly {
                value: dns(current),
                writes: 0,
            },
            Store { fail },
            saved,
        )
        .unwrap();
        assert!(owner.cleanup().is_err());
        assert_eq!(owner.system_mut().value, dns(current));
        assert_eq!(owner.system_mut().writes, 0);
    }
}

#[test]
fn windows_reboot_retirement_rejects_persistent_and_foreign_platform_resources() {
    assert!(NetworkJournal::default().windows_boot_resources_are_ephemeral());
    assert!(!journal(false).windows_boot_resources_are_ephemeral());
    for (scope, original, expected) in [
        (
            serde_json::json!({"WindowsInterface":42}),
            serde_json::Value::Null,
            true,
        ),
        (serde_json::json!("Global"), serde_json::Value::Null, false),
        (
            serde_json::json!({"Member":42}),
            serde_json::Value::Null,
            false,
        ),
        (
            serde_json::json!({"WindowsInterface":42}),
            serde_json::json!({"Route":{"destination":"0.0.0.0/1","scope":{"WindowsInterface":42},"interface":42,"gateway":null,"metric":9}}),
            false,
        ),
    ] {
        let owned = serde_json::json!({"original":original,"current":{"Route":{"destination":"0.0.0.0/1","scope":scope,"interface":42,"gateway":null,"metric":0}}});
        for pending in [false, true] {
            let saved:NetworkJournal=serde_json::from_value(serde_json::json!({
                "owned":if pending {serde_json::json!([])}else{serde_json::json!([owned.clone()])},
                "active":"A","stopping":false,"pending":if pending {serde_json::json!({"target":[owned.clone()],"active":"B"})}else{serde_json::Value::Null}
            })).unwrap();
            assert_eq!(saved.windows_boot_resources_are_ephemeral(), expected);
        }
    }
}
