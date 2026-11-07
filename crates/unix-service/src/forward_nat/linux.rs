//! Linux nftables NAT for verified private virtual ingress only.
use super::{
    valid_name, valid_token, validate_plan, Commands, Egress, Plan, Presence, Source, System,
};
use ipnet::Ipv4Net;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::Ipv4Addr,
};

pub(crate) struct Adapter<C> {
    commands: C,
}
impl<C: Commands> Adapter<C> {
    pub(crate) fn new(commands: C) -> Self {
        Self { commands }
    }

    fn run(&mut self, program: &str, args: &[&str], input: Option<&str>) -> io::Result<String> {
        self.commands
            .run(
                program,
                &args.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
                input,
            )
            .map_err(|error| io::Error::new(error.kind(), "linux_forward_nat_command_failed"))
    }
    fn ip_rows(&mut self, args: &[&str]) -> io::Result<Vec<Value>> {
        parse(&self.run("ip", args, None)?)?
            .as_array()
            .filter(|a| a.len() <= 32768)
            .cloned()
            .ok_or_else(invalid)
    }
    fn tables(&mut self) -> io::Result<Vec<Value>> {
        let listing = parse(&self.run("nft", &["-j", "-a", "-n", "list", "tables"], None)?)?;
        let mut tables = Vec::new();
        for item in entries(&listing)? {
            if item.as_object().is_none_or(|object| object.len() != 1) {
                return Err(invalid());
            }
            if item.get("metainfo").is_some() {
                continue;
            }
            let table = item.get("table").ok_or_else(invalid)?;
            string(table, "name")?;
            string(table, "family")?;
            tables.push(table.clone());
        }
        Ok(tables)
    }
    fn table(&mut self, token: &str) -> io::Result<Option<Value>> {
        let name = table_name(token)?;
        // Query errors are never absence. Listing tables succeeds even when our
        // table has never existed; only then request the complete owned table.
        let found = self
            .tables()?
            .iter()
            .filter(|table| {
                table.get("name").and_then(Value::as_str) == Some(name.as_str())
                    && table.get("family").and_then(Value::as_str) == Some("ip")
            })
            .count();
        match found {
            0 => Ok(None),
            1 => Ok(Some(parse(&self.run(
                "nft",
                &["-j", "-a", "-n", "list", "table", "ip", &name],
                None,
            )?)?)),
            _ => Err(invalid()),
        }
    }
    fn exact(&mut self, token: &str, plan: &Plan, actual: &Value) -> io::Result<bool> {
        // nft 1.0.9 JSON prints an ifindex as its current interface name even
        // with --numeric, or as a decimal string after the link disappears.
        // Resolve only the expected index match, with fresh name/index proof.
        let links = self.ip_rows(&["-j", "-d", "link", "show"])?;
        let mut names = HashMap::new();
        let mut indexes = HashSet::new();
        for link in &links {
            let index = number(link, "ifindex")?;
            if names.insert(string(link, "ifname")?, index).is_some() || !indexes.insert(index) {
                return Err(invalid());
            }
        }
        let mut normalized = actual.clone();
        let Some(rows) = normalized.get_mut("nftables").and_then(Value::as_array_mut) else {
            return Ok(false);
        };
        let mut rule_number = 0;
        for row in rows {
            let Some(rule) = row.get_mut("rule") else {
                continue;
            };
            let Some(source) = plan.sources.get(rule_number) else {
                return Ok(false);
            };
            rule_number += 1;
            let Some(expr) = rule.get_mut("expr").and_then(Value::as_array_mut) else {
                return Ok(false);
            };
            for expression in expr {
                let Some(matched) = expression.get_mut("match") else {
                    continue;
                };
                let (name, index) = match matched.pointer("/left/meta/key").and_then(Value::as_str)
                {
                    Some("iif") => (source.name.as_str(), source.index),
                    Some("oif") => (plan.egress.name.as_str(), plan.egress.index),
                    _ => continue,
                };
                let Some(display) = matched.get("right").and_then(Value::as_str) else {
                    continue;
                };
                let named = display == name && names.get(display) == Some(&index);
                let numeric = display == index.to_string()
                    && names.get(display).is_none_or(|current| *current == index);
                if named || numeric {
                    matched["right"] = json!(index);
                }
            }
        }
        Ok(exact_table(token, plan, &normalized))
    }
}
impl<C: Commands> System for Adapter<C> {
    fn begin_operation(&mut self) {
        self.commands.begin_operation();
    }
    fn discover(&mut self, name: &str, index: u32) -> io::Result<Option<Plan>> {
        if !valid_name(name) || index == 0 {
            return Err(invalid());
        }
        let links = self.ip_rows(&["-j", "-d", "link", "show"])?;
        let mut indexes = HashSet::new();
        let mut names = HashSet::new();
        for link in &links {
            if !indexes.insert(number(link, "ifindex")?) || !names.insert(string(link, "ifname")?) {
                return Err(invalid());
            }
        }
        let egress = links
            .iter()
            .find(|link| link.get("ifname").and_then(Value::as_str) == Some(name))
            .ok_or_else(invalid)?;
        if number(egress, "ifindex")? != index || !matches!(kind(egress), Some("wireguard" | "tun"))
        {
            return Err(invalid());
        }
        let addresses = self.ip_rows(&["-j", "-4", "address", "show"])?;
        let address_row = addresses
            .iter()
            .find(|row| row.get("ifname").and_then(Value::as_str) == Some(name))
            .ok_or_else(invalid)?;
        if number(address_row, "ifindex")? != index {
            return Err(invalid());
        }
        let ipv4 = ipv4_addresses(address_row)?;
        if ipv4.is_empty() {
            return Ok(None);
        }
        if ipv4.len() != 1 {
            return Err(invalid());
        }
        let vpn_ip = ipv4[0].0;
        if vpn_ip.is_unspecified()
            || vpn_ip.is_loopback()
            || vpn_ip.is_multicast()
            || vpn_ip.is_broadcast()
        {
            return Err(invalid());
        }
        let routes = self.ip_rows(&["-j", "-4", "route", "show", "table", "main"])?;
        let mut sources = Vec::new();
        for link in &links {
            let source_name = string(link, "ifname")?;
            let source_index = number(link, "ifindex")?;
            if source_index == index
                || !valid_name(source_name)
                || link.get("master").is_some()
                || !link
                    .get("flags")
                    .and_then(Value::as_array)
                    .is_some_and(|flags| flags.iter().any(|f| f == "UP"))
                || !virtual_ingress(link, &links)
            {
                continue;
            }
            let Some(row) = addresses
                .iter()
                .find(|row| row.get("ifname").and_then(Value::as_str) == Some(source_name))
            else {
                continue;
            };
            if number(row, "ifindex")? != source_index {
                return Err(invalid());
            }
            for (host_address, prefix, scope) in ipv4_addresses(row)? {
                if scope != "global" {
                    continue;
                }
                let network = Ipv4Net::new(host_address, prefix)
                    .map_err(|_| invalid())?
                    .trunc();
                if !network.network().is_private()
                    || !network.broadcast().is_private()
                    || network.prefix_len() == 32
                {
                    continue;
                }
                let connected = routes.iter().any(|route| {
                    route.get("dst").and_then(Value::as_str) == Some(network.to_string().as_str())
                        && route.get("dev").and_then(Value::as_str) == Some(source_name)
                        && route.get("scope").and_then(Value::as_str) == Some("link")
                        && matches!(route.get("protocol"), Some(Value::String(p)) if p == "kernel")
                        && route.get("gateway").is_none()
                        && route.get("via").is_none()
                        && route.get("type").is_none_or(|t| t == "unicast")
                });
                if connected {
                    sources.push(Source {
                        name: source_name.into(),
                        index: source_index,
                        network: network.to_string(),
                        host_address,
                    });
                }
            }
        }
        sources.sort_by(|a, b| {
            (&a.name, a.index, &a.network, a.host_address).cmp(&(
                &b.name,
                b.index,
                &b.network,
                b.host_address,
            ))
        });
        sources.dedup();
        if sources.is_empty() {
            return Ok(None);
        }
        let plan = Plan {
            max_mss: None,
            egress: Egress {
                name: name.into(),
                index,
                address: vpn_ip,
            },
            sources,
        };
        if !validate_plan(&plan) {
            return Err(invalid());
        }
        // A missing optional tool must fail before the owner saves native
        // mutation intent. Hosts without eligible virtual sources need no nft.
        self.tables()?;
        Ok(Some(plan))
    }
    fn inspect(&mut self, token: &str, plan: &Plan) -> io::Result<Presence> {
        table_name(token)?;
        if !validate_plan(plan) {
            return Err(invalid());
        }
        match self.table(token)? {
            None => Ok(Presence::Absent),
            Some(actual) => Ok(if self.exact(token, plan, &actual)? {
                Presence::Exact
            } else {
                Presence::Conflict
            }),
        }
    }
    fn replace(
        &mut self,
        token: &str,
        before: Option<&Plan>,
        after: Option<&Plan>,
    ) -> io::Result<()> {
        table_name(token)?;
        if [before, after]
            .into_iter()
            .flatten()
            .any(|p| !validate_plan(p))
        {
            return Err(invalid());
        }
        let current = self.table(token)?;
        let handle = match (before, current.as_ref()) {
            (None, None) => None,
            (Some(expected), Some(actual)) if self.exact(token, expected, actual)? => Some(
                entries(actual)?
                    .iter()
                    .find_map(|e| e.get("table")?.get("handle")?.as_u64())
                    .ok_or_else(invalid)?,
            ),
            _ => return Err(conflict()),
        };
        if before == after {
            return Ok(());
        }
        if let Some(plan) = after {
            if self
                .discover(&plan.egress.name, plan.egress.index)?
                .as_ref()
                != Some(plan)
            {
                return Err(conflict());
            }
        }
        let mut input = String::new();
        if let Some(handle) = handle {
            input.push_str(&format!("delete table ip handle {handle}\n"));
        }
        if let Some(plan) = after {
            input.push_str(&render(token, plan)?);
        }
        if input.len() > 4096 {
            return Err(invalid());
        }
        self.run("nft", &["--check", "-f", "-"], Some(&input))?;
        // Check the complete policy again after a slow native syntax check.
        let latest = self.table(token)?;
        match (before, latest.as_ref()) {
            (Some(plan), Some(actual))
                if self.exact(token, plan, actual)?
                    && entries(actual)?
                        .iter()
                        .find_map(|e| e.get("table")?.get("handle")?.as_u64())
                        == handle => {}
            (None, None) => (),
            _ => return Err(conflict()),
        }
        self.run("nft", &["-f", "-"], Some(&input))?;
        // The enclosing durable owner performs the post-write readback.
        Ok(())
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid_linux_forward_nat")
}
fn conflict() -> io::Error {
    io::Error::other("linux_forward_nat_conflict")
}
fn table_name(token: &str) -> io::Result<String> {
    if !valid_token(token) {
        return Err(invalid());
    }
    Ok(format!("nlm_vm_{token}"))
}
fn parse(text: &str) -> io::Result<Value> {
    if text.len() > 8 * 1024 * 1024 {
        return Err(invalid());
    }
    serde_json::from_str(text).map_err(|_| invalid())
}
fn entries(value: &Value) -> io::Result<&Vec<Value>> {
    if value.as_object().is_none_or(|o| o.len() != 1) {
        return Err(invalid());
    }
    value
        .get("nftables")
        .and_then(Value::as_array)
        .filter(|a| a.len() <= 32768)
        .ok_or_else(invalid)
}
fn string<'a>(value: &'a Value, field: &str) -> io::Result<&'a str> {
    value.get(field).and_then(Value::as_str).ok_or_else(invalid)
}
fn number(value: &Value, field: &str) -> io::Result<u32> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or_else(invalid)
}
fn kind(link: &Value) -> Option<&str> {
    link.get("linkinfo")?.get("info_kind")?.as_str()
}
fn virtual_port(link: &Value) -> bool {
    link.get("link_type").and_then(Value::as_str) == Some("ether")
        && (kind(link) == Some("veth")
            || (kind(link) == Some("tun")
                && link
                    .pointer("/linkinfo/info_data/type")
                    .and_then(Value::as_str)
                    == Some("tap")))
}
fn virtual_ingress(link: &Value, links: &[Value]) -> bool {
    if kind(link) == Some("veth") {
        return virtual_port(link);
    }
    if kind(link) != Some("bridge")
        || link.get("link_type").and_then(Value::as_str) != Some("ether")
    {
        return false;
    }
    let ports = links
        .iter()
        .filter(|p| {
            p.get("master").is_some_and(|m| {
                m.as_str() == link.get("ifname").and_then(Value::as_str)
                    || m.as_u64() == link.get("ifindex").and_then(Value::as_u64)
            })
        })
        .collect::<Vec<_>>();
    !ports.is_empty() && ports.into_iter().all(virtual_port)
}
fn ipv4_addresses(row: &Value) -> io::Result<Vec<(Ipv4Addr, u8, String)>> {
    let mut result = Vec::new();
    for address in row
        .get("addr_info")
        .and_then(Value::as_array)
        .filter(|a| a.len() <= 256)
        .ok_or_else(invalid)?
    {
        if address.get("family").and_then(Value::as_str) != Some("inet") {
            continue;
        }
        let local = string(address, "local")?.parse().map_err(|_| invalid())?;
        let prefix = address
            .get("prefixlen")
            .and_then(Value::as_u64)
            .filter(|n| *n <= 32)
            .ok_or_else(invalid)? as u8;
        result.push((local, prefix, string(address, "scope")?.into()));
    }
    Ok(result)
}
fn expressions(plan: &Plan, source: &Source) -> Value {
    let prefix: Ipv4Net = source.network.parse().expect("validated prefix");
    let meta_match =
        |key, right: Value| json!({"match":{"op":"==","left":{"meta":{"key":key}},"right":right}});
    json!([
        meta_match("iif", json!(source.index)), meta_match("iifname", json!(source.name)),
        {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":prefix.network().to_string(),"len":prefix.prefix_len()}}}},
        meta_match("oif", json!(plan.egress.index)), meta_match("oifname", json!(plan.egress.name)),
        {"match":{"op":"!=","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":plan.egress.address.to_string()}},
        {"counter":{"packets":0,"bytes":0}}, {"masquerade":null}
    ])
}
fn exact_table(token: &str, plan: &Plan, actual: &Value) -> bool {
    let Ok(entries) = entries(actual) else {
        return false;
    };
    let name = format!("nlm_vm_{token}");
    let mut expected = vec![
        json!({"table":{"family":"ip","name":name,"comment":token}}),
        json!({"chain":{"family":"ip","table":name,"name":"postrouting","type":"nat","hook":"postrouting","prio":101,"policy":"accept"}}),
    ];
    expected.extend(plan.sources.iter().map(|source| json!({"rule":{"family":"ip","table":name,"chain":"postrouting","expr":expressions(plan,source)}})));
    let mut normalized = Vec::new();
    for entry in entries {
        let Some(object) = entry.as_object().filter(|o| o.len() == 1) else {
            return false;
        };
        if object.contains_key("metainfo") {
            continue;
        }
        let mut entry = entry.clone();
        let Some((kind, value)) = entry.as_object_mut().and_then(|o| o.iter_mut().next()) else {
            return false;
        };
        if !matches!(kind.as_str(), "table" | "chain" | "rule") {
            return false;
        }
        let Some(properties) = value.as_object_mut() else {
            return false;
        };
        if properties
            .remove("handle")
            .and_then(|v| v.as_u64())
            .is_none_or(|h| h == 0)
        {
            return false;
        }
        if kind == "rule" {
            let Some(expr) = properties.get_mut("expr").and_then(Value::as_array_mut) else {
                return false;
            };
            for expression in expr {
                if let Some(counter) = expression.get_mut("counter") {
                    if counter.as_object().is_none_or(|c| c.len() != 2)
                        || counter.get("packets").and_then(Value::as_u64).is_none()
                        || counter.get("bytes").and_then(Value::as_u64).is_none()
                    {
                        return false;
                    }
                    *counter = json!({"packets":0,"bytes":0});
                }
                if expression
                    .get("masquerade")
                    .is_some_and(|m| m.as_object().is_some_and(|o| o.is_empty()))
                {
                    expression["masquerade"] = Value::Null;
                }
            }
        }
        normalized.push(entry);
    }
    normalized == expected
}
fn render(token: &str, plan: &Plan) -> io::Result<String> {
    let name = table_name(token)?;
    if !validate_plan(plan) {
        return Err(invalid());
    }
    let mut text = format!("create table ip {name} {{ comment \"{token}\"; }}\nadd chain ip {name} postrouting {{ type nat hook postrouting priority 101; policy accept; }}\n");
    for source in &plan.sources {
        text.push_str(&format!("add rule ip {name} postrouting iif {} iifname \"{}\" ip saddr {} oif {} oifname \"{}\" ip saddr != {} counter masquerade\n",
                              source.index, source.name, source.network, plan.egress.index, plan.egress.name, plan.egress.address));
    }
    if text.len() > 4096 {
        return Err(invalid());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward_nat::{Egress, Source};
    use serde_json::{json, Value};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const TABLE: &str = "nlm_vm_0123456789abcdef0123456789abcdef";
    fn plan() -> Plan {
        Plan {
            max_mss: None,
            egress: Egress {
                name: "nlm-awga".into(),
                index: 3,
                address: "10.241.0.6".parse().unwrap(),
            },
            sources: vec![Source {
                name: "guest-side".into(),
                index: 8,
                network: "10.254.241.0/30".into(),
                host_address: "10.254.241.1".parse().unwrap(),
            }],
        }
    }
    fn owned_table() -> Value {
        json!({"nftables":[
            {"metainfo":{"json_schema_version":1,"version":"1.0.9"}},
            {"table":{"family":"ip","name":TABLE,"handle":7,"comment":TOKEN}},
            {"chain":{"family":"ip","table":TABLE,"name":"postrouting","handle":1,"type":"nat","hook":"postrouting","prio":101,"policy":"accept"}},
            {"rule":{"family":"ip","table":TABLE,"chain":"postrouting","handle":2,"expr":[
                {"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":8}},
                {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"guest-side"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.254.241.0","len":30}}}},
                {"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":3}},
                {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"nlm-awga"}},
                {"match":{"op":"!=","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.241.0.6"}},
                {"counter":{"packets":1,"bytes":60}},
                {"masquerade":null}
            ]}}
        ]})
    }
    struct Fake {
        links: Value,
        addresses: Value,
        routes: Value,
        table: Option<Value>,
        fail_listing: bool,
        listing_error_kind: io::ErrorKind,
        fail_check: bool,
        writes: Vec<String>,
        calls: Vec<String>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                links: json!([
                    {"ifindex":2,"ifname":"eth0","flags":["UP","LOWER_UP"],"link_type":"ether"},
                    {"ifindex":3,"ifname":"nlm-awga","flags":["UP","LOWER_UP"],"link_type":"none","linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}},
                    {"ifindex":8,"ifname":"guest-side","flags":["UP","LOWER_UP"],"link_type":"ether","linkinfo":{"info_kind":"veth"}}
                ]),
                addresses: json!([
                    {"ifindex":2,"ifname":"eth0","addr_info":[{"family":"inet","scope":"global","local":"192.168.1.2","prefixlen":24}]},
                    {"ifindex":3,"ifname":"nlm-awga","addr_info":[{"family":"inet","scope":"global","local":"10.241.0.6","prefixlen":32}]},
                    {"ifindex":8,"ifname":"guest-side","addr_info":[{"family":"inet","scope":"global","local":"10.254.241.1","prefixlen":30}]}
                ]),
                routes: json!([
                    {"dst":"192.168.1.0/24","dev":"eth0","scope":"link","protocol":"kernel"},
                    {"dst":"10.254.241.0/30","dev":"guest-side","scope":"link","protocol":"kernel"}
                ]),
                table: None,
                fail_listing: false,
                listing_error_kind: io::ErrorKind::Other,
                fail_check: false,
                writes: vec![],
                calls: vec![],
            }
        }
    }
    impl Commands for Fake {
        fn run(
            &mut self,
            program: &str,
            args: &[String],
            input: Option<&str>,
        ) -> io::Result<String> {
            self.calls.push(format!("{program} {}", args.join(" ")));
            if program == "ip" {
                let value = if args.iter().any(|a| a == "link") {
                    &self.links
                } else if args.iter().any(|a| a == "address") {
                    &self.addresses
                } else if args.iter().any(|a| a == "route") {
                    &self.routes
                } else {
                    panic!("unexpected ip call: {args:?}")
                };
                return Ok(value.to_string());
            }
            assert_eq!(program, "nft");
            if args.last().map(String::as_str) == Some("tables") {
                if self.fail_listing {
                    return Err(io::Error::new(
                        self.listing_error_kind,
                        "untrusted child diagnostic",
                    ));
                }
                return Ok(if self.table.is_some() {
                    json!({"nftables":[{"table":{"family":"ip","name":TABLE,"handle":7}}]})
                } else {
                    json!({"nftables":[]})
                }
                .to_string());
            }
            if args.iter().any(|a| a == "list") {
                return Ok(self.table.as_ref().unwrap().to_string());
            }
            let text = input.expect("nft transaction input");
            assert!(text.len() <= 4096);
            if args.iter().any(|a| a == "--check") {
                if self.fail_check {
                    return Err(io::Error::other("check failed"));
                }
            } else {
                self.writes.push(text.into());
            }
            Ok(String::new())
        }
    }

    #[test]
    fn linux_discovers_actual_veth_prefix_without_admitting_private_lan() {
        // Dropping the link-kind or connected-route check would admit eth0 here.
        let mut adapter = Adapter::new(Fake::new());
        assert_eq!(adapter.discover("nlm-awga", 3).unwrap(), Some(plan()));
        adapter.commands.routes = json!([]);
        assert_eq!(adapter.discover("nlm-awga", 3).unwrap(), None);
    }
    #[test]
    fn linux_bridge_requires_only_virtual_layer_two_ports() {
        let mut fake = Fake::new();
        fake.links[2]["linkinfo"]["info_kind"] = json!("bridge");
        fake.links.as_array_mut().unwrap().push(json!({"ifindex":9,"ifname":"vm-nic","master":"guest-side","link_type":"ether","linkinfo":{"info_kind":"tun","info_data":{"type":"tap"}}}));
        let mut adapter = Adapter::new(fake);
        assert_eq!(adapter.discover("nlm-awga", 3).unwrap(), Some(plan()));
        adapter.commands.links[3]["linkinfo"] = json!({"info_kind":"vlan"});
        assert_eq!(adapter.discover("nlm-awga", 3).unwrap(), None);
        adapter.commands.links[3]["linkinfo"] =
            json!({"info_kind":"tun","info_data":{"type":"tun"}});
        assert_eq!(adapter.discover("nlm-awga", 3).unwrap(), None);
    }
    #[test]
    fn linux_requires_original_egress_index_and_single_ipv4() {
        let mut adapter = Adapter::new(Fake::new());
        assert!(adapter.discover("nlm-awga", 99).is_err());
        adapter.commands.addresses[1]["addr_info"] = json!([]);
        assert_eq!(adapter.discover("nlm-awga", 3).unwrap(), None);
        adapter.commands.addresses[1]["addr_info"] = json!([
            {"family":"inet","scope":"global","local":"10.241.0.6","prefixlen":32},
            {"family":"inet","scope":"global","local":"10.241.0.7","prefixlen":32}]);
        assert!(adapter.discover("nlm-awga", 3).is_err());
    }
    #[test]
    fn linux_discovery_order_matches_durable_owner_normalization() {
        let mut fake = Fake::new();
        fake.links.as_array_mut().unwrap().push(json!({"ifindex":9,"ifname":"a-guest","flags":["UP"],"link_type":"ether","linkinfo":{"info_kind":"veth"}}));
        fake.addresses.as_array_mut().unwrap().push(json!({"ifindex":9,"ifname":"a-guest","addr_info":[{"family":"inet","scope":"global","local":"192.168.64.1","prefixlen":24}]}));
        fake.routes.as_array_mut().unwrap().push(
            json!({"dst":"192.168.64.0/24","dev":"a-guest","scope":"link","protocol":"kernel"}),
        );
        let found = Adapter::new(fake).discover("nlm-awga", 3).unwrap().unwrap();
        assert_eq!(
            found
                .sources
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["a-guest", "guest-side"]
        );
    }
    #[test]
    fn linux_accepts_only_complete_owned_nft_semantics_ignoring_counter_values() {
        let mut fake = Fake::new();
        fake.table = Some(owned_table());
        let mut adapter = Adapter::new(fake);
        assert_eq!(adapter.inspect(TOKEN, &plan()).unwrap(), Presence::Exact);
        for changed in [
            json!({"counter":{"packets":999,"bytes":999999}}),
            json!({"accept":null}),
        ] {
            adapter.commands.table.as_mut().unwrap()["nftables"][3]["rule"]["expr"][6] =
                changed.clone();
            let actual = adapter.inspect(TOKEN, &plan()).unwrap();
            assert_eq!(
                actual,
                if changed.get("counter").is_some() {
                    Presence::Exact
                } else {
                    Presence::Conflict
                }
            );
        }
    }
    #[test]
    fn linux_rejects_extra_rules_and_weakened_interface_or_subnet_matches() {
        for mutate in 0..5 {
            let mut table = owned_table();
            match mutate {
                0 => table["nftables"].as_array_mut().unwrap().push(json!({"rule":{"family":"ip","table":TABLE,"chain":"postrouting","handle":8,"expr":[{"accept":null}]}})),
                1 => table["nftables"][3]["rule"]["expr"][0]["match"]["right"] = json!(2),
                2 => table["nftables"][3]["rule"]["expr"][2]["match"]["right"]["prefix"]["len"] = json!(8),
                3 => table["nftables"][2]["chain"]["prio"] = json!(99),
                _ => table["nftables"][1]["table"]["comment"] = json!("foreign"),
            }
            let mut fake = Fake::new();
            fake.table = Some(table);
            assert_eq!(
                Adapter::new(fake).inspect(TOKEN, &plan()).unwrap(),
                Presence::Conflict
            );
        }
    }
    #[test]
    fn linux_accepts_native_interface_index_display_only_with_original_identity() {
        let mut fake = Fake::new();
        let mut table = owned_table();
        table["nftables"][3]["rule"]["expr"][0]["match"]["right"] = json!("guest-side");
        table["nftables"][3]["rule"]["expr"][3]["match"]["right"] = json!("nlm-awga");
        fake.table = Some(table);
        let mut adapter = Adapter::new(fake);
        assert_eq!(adapter.inspect(TOKEN, &plan()).unwrap(), Presence::Exact);
        adapter.commands.links[2]["ifindex"] = json!(9);
        assert_eq!(adapter.inspect(TOKEN, &plan()).unwrap(), Presence::Conflict);
        adapter.commands.table.as_mut().unwrap()["nftables"][3]["rule"]["expr"][0]["match"]
            ["right"] = json!("8");
        adapter.commands.links.as_array_mut().unwrap().remove(2);
        assert_eq!(adapter.inspect(TOKEN, &plan()).unwrap(), Presence::Exact);
        adapter
            .commands
            .links
            .as_array_mut()
            .unwrap()
            .push(json!({"ifname":"8","ifindex":9}));
        assert_eq!(adapter.inspect(TOKEN, &plan()).unwrap(), Presence::Conflict);
    }
    #[test]
    fn linux_list_failure_is_not_absence_and_invalid_token_never_runs_commands() {
        let mut fake = Fake::new();
        fake.fail_listing = true;
        let mut adapter = Adapter::new(fake);
        assert!(adapter.inspect(TOKEN, &plan()).is_err());
        let before = adapter.commands.calls.len();
        assert!(adapter.inspect("bad; delete ruleset", &plan()).is_err());
        assert_eq!(adapter.commands.calls.len(), before);
    }
    #[test]
    fn linux_missing_nft_is_read_only_discovery_failure_only_with_virtual_sources() {
        let mut fake = Fake::new();
        fake.fail_listing = true;
        fake.listing_error_kind = io::ErrorKind::NotFound;
        let mut adapter = Adapter::new(fake);
        let error = adapter.discover("nlm-awga", 3).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(adapter.commands.writes.is_empty());
        adapter.commands.routes = json!([]);
        adapter.commands.calls.clear();
        assert_eq!(adapter.discover("nlm-awga", 3).unwrap(), None);
        assert!(adapter.commands.calls.iter().all(|c| c.starts_with("ip ")));
    }
    #[test]
    fn linux_creates_only_checked_scoped_masquerade_with_no_forward_policy() {
        let mut adapter = Adapter::new(Fake::new());
        adapter.replace(TOKEN, None, Some(&plan())).unwrap();
        assert_eq!(adapter.commands.writes.len(), 1);
        let text = &adapter.commands.writes[0];
        assert!(text.contains("priority 101"));
        assert!(text.contains("iif 8 iifname \"guest-side\" ip saddr 10.254.241.0/30"));
        assert!(text.contains("oif 3 oifname \"nlm-awga\" ip saddr != 10.241.0.6"));
        assert!(text.contains("counter masquerade"));
        assert!(!text.contains("forward") && !text.contains("flush") && !text.contains("snat"));
        let check = adapter
            .commands
            .calls
            .iter()
            .position(|s| s.contains("--check"))
            .unwrap();
        let apply = adapter
            .commands
            .calls
            .iter()
            .rposition(|s| s == "nft -f -")
            .unwrap();
        assert!(check < apply);
    }
    #[test]
    fn linux_creates_chain_and_rules_as_explicit_commands_in_one_atomic_batch() {
        let mut adapter = Adapter::new(Fake::new());
        adapter.replace(TOKEN, None, Some(&plan())).unwrap();
        assert_eq!(adapter.commands.writes.len(), 1);
        let commands: Vec<_> = adapter.commands.writes[0].lines().collect();
        // nft 1.0.9 accepts nested children under CREATE TABLE but creates only
        // the table. Explicit children must follow its closed, exclusive create.
        assert_eq!(
            commands[0],
            format!("create table ip {TABLE} {{ comment \"{TOKEN}\"; }}")
        );
        assert_eq!(
            commands[1],
            format!("add chain ip {TABLE} postrouting {{ type nat hook postrouting priority 101; policy accept; }}")
        );
        assert_eq!(commands.len(), 2 + plan().sources.len());
        assert!(commands[2].starts_with(&format!("add rule ip {TABLE} postrouting ")));
        assert!(commands[2].ends_with("counter masquerade"));
    }
    #[test]
    fn linux_check_failure_or_foreign_table_never_applies_transaction() {
        let mut fake = Fake::new();
        fake.fail_check = true;
        let mut adapter = Adapter::new(fake);
        assert!(adapter.replace(TOKEN, None, Some(&plan())).is_err());
        assert!(adapter.commands.writes.is_empty());
        adapter.commands.fail_check = false;
        adapter.commands.table = Some(owned_table());
        assert!(adapter.replace(TOKEN, None, Some(&plan())).is_err());
        assert!(adapter.commands.writes.is_empty());
    }
}
