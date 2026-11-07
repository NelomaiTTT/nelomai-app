//! Scoped PF source NAT for native Apple virtual networks.
//! Kernel NAT states expire naturally; cleanup does not flush foreign states.
use super::{
    valid_name, valid_token, validate_plan, Commands, Egress, Plan, Presence, Source, System,
};
use ipnet::Ipv4Net;
use std::{collections::BTreeSet, io, net::Ipv4Addr};

const PF: &str = "/sbin/pfctl";
const MAX_OUTPUT: usize = 65536;

pub(crate) struct Adapter<C: Commands> {
    commands: C,
}
impl<C: Commands> Adapter<C> {
    pub(crate) fn new(commands: C) -> Self {
        Self { commands }
    }
    fn run(&mut self, program: &str, args: &[&str], input: Option<&str>) -> io::Result<String> {
        if input.is_some_and(|s| s.len() > 4096) {
            return Err(invalid());
        }
        let text = self.commands.run(
            program,
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            input,
        )?;
        if text.len() > MAX_OUTPUT || text.contains('\0') {
            return Err(invalid());
        }
        Ok(text)
    }
    fn layout(&mut self, token: &str, plan: &Plan) -> io::Result<Layout> {
        if !valid_token(token) || !validate_plan(plan) {
            return Err(invalid());
        }
        let anchor = anchor(token);
        let nat = self.run(PF, &["-a", &anchor, "-sn"], None)?;
        let tables = self.run(PF, &["-a", &anchor, "-s", "Tables"], None)?;
        let filters = self.run(PF, &["-a", &anchor, "-sr"], None)?;
        let children = self.run(PF, &["-a", &anchor, "-s", "Anchors"], None)?;
        let names = words(&tables);
        if !children.trim().is_empty() {
            return Ok(Layout::Conflict);
        }
        let expected_scrub = normalization_rules(token, plan)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let scrub_lines = filters
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(canonical_rule)
            .collect::<Vec<_>>();
        let actual_scrub = scrub_lines.iter().cloned().collect::<BTreeSet<_>>();
        // Exact known subsets may remain after interrupted cleanup. Additional
        // filters, duplicate rules or a different bridge are never ours.
        if actual_scrub.len() != scrub_lines.len() || !actual_scrub.is_subset(&expected_scrub) {
            return Ok(Layout::Conflict);
        }
        let scrub_present = !actual_scrub.is_empty();
        let scrub_complete = actual_scrub == expected_scrub;
        if nat.trim().is_empty() && names.is_empty() && !scrub_present {
            return Ok(Layout::Absent);
        }
        if names != vec![table(token)] {
            return Ok(Layout::Conflict);
        }
        let contents = self.run(
            PF,
            &["-a", &anchor, "-t", &table(token), "-T", "show"],
            None,
        )?;
        if table_entries(&contents)? != expected_entries(plan) {
            return Ok(Layout::Conflict);
        }
        if nat.trim().is_empty() {
            return Ok(Layout::OwnedPartial);
        }
        if canonical_rule(&nat) != canonical_rule(&rule(token, plan)) {
            return Ok(Layout::Conflict);
        }
        if !scrub_complete {
            return Ok(Layout::OwnedPartial);
        }
        Ok(Layout::Exact)
    }
    fn require_pf(&mut self, need_scrub: bool) -> io::Result<()> {
        let status = self.run(PF, &["-si"], None)?;
        if status
            .lines()
            .filter(|l| l.trim_start().starts_with("Status:"))
            .map(|l| l.split_whitespace().take(2).collect::<Vec<_>>())
            .collect::<Vec<_>>()
            != [vec!["Status:", "Enabled"]]
        {
            return Err(unsupported());
        }
        let nat = self.run(PF, &["-sn"], None)?;
        if !nat
            .lines()
            .any(|l| canonical_rule(l) == "nat-anchor \"com.apple/*\" all")
        {
            return Err(unsupported());
        }
        if need_scrub {
            let rules = self.run(PF, &["-sr"], None)?;
            if !rules.lines().any(|line| {
                canonical_rule(line) == "scrub-anchor \"com.apple/*\" all fragment reassemble"
            }) {
                return Err(unsupported());
            }
        }
        Ok(())
    }
}
#[derive(PartialEq, Eq)]
enum Layout {
    Absent,
    Exact,
    OwnedPartial,
    Conflict,
}
impl<C: Commands> System for Adapter<C> {
    fn begin_operation(&mut self) {
        self.commands.begin_operation();
    }
    fn discover(&mut self, name: &str, index: u32) -> io::Result<Option<Plan>> {
        if !valid_name(name) || !numbered(name, "utun") || index == 0 {
            return Err(invalid());
        }
        let text = self.run("/sbin/ifconfig", &["-v", "-a"], None)?;
        let mut blocks = Vec::<Vec<&str>>::new();
        for line in text.lines() {
            if !line.starts_with(char::is_whitespace) && line.contains(": flags=") {
                blocks.push(vec![line]);
            } else if let Some(block) = blocks.last_mut() {
                block.push(line);
            }
        }
        let matching = blocks
            .iter()
            .filter(|b| b[0].split_once(':').is_some_and(|(n, _)| n == name))
            .collect::<Vec<_>>();
        let [egress] = matching.as_slice() else {
            return Err(invalid());
        };
        if native_index(egress[0]) != Some(index)
            || !has_flag(egress[0], "UP")
            || !has_flag(egress[0], "RUNNING")
            || !has_flag(egress[0], "POINTOPOINT")
        {
            return Err(invalid());
        }
        let addresses = ipv4_addresses(egress);
        let [(address, _)] = addresses.as_slice() else {
            return Err(invalid());
        };
        if egress
            .iter()
            .filter(|l| l.trim_start().starts_with("inet "))
            .count()
            != addresses.len()
        {
            return Err(invalid());
        }
        let mut sources = Vec::new();
        for b in &blocks {
            let Some((bridge, _)) = b[0].split_once(':') else {
                continue;
            };
            if !numbered(bridge, "bridge")
                || !has_flag(b[0], "UP")
                || !has_flag(b[0], "RUNNING")
                || !b.iter().any(|l| l.trim() == "status: active")
            {
                continue;
            }
            let members = b
                .iter()
                .filter_map(|l| l.trim().strip_prefix("member: "))
                .collect::<Vec<_>>();
            if members.is_empty()
                || members.iter().any(|m| {
                    !m.split_whitespace()
                        .next()
                        .is_some_and(|n| numbered(n, "vmenet"))
                        || !has_flag(m, "VIRTIO")
                })
            {
                continue;
            }
            let addresses = ipv4_addresses(b);
            let [(host, mask)] = addresses.as_slice() else {
                continue;
            };
            if b.iter()
                .filter(|l| l.trim_start().starts_with("inet "))
                .count()
                != addresses.len()
            {
                continue;
            }
            let Some(prefix) = mask_prefix(*mask) else {
                continue;
            };
            let Ok(net) = Ipv4Net::new(*host, prefix) else {
                continue;
            };
            let Some(source_index) = native_index(b[0]) else {
                continue;
            };
            let source = Source {
                name: bridge.into(),
                index: source_index,
                network: net.trunc().to_string(),
                host_address: *host,
            };
            let proposed = Plan {
                max_mss: None,
                egress: Egress {
                    name: name.into(),
                    index,
                    address: *address,
                },
                sources: vec![source.clone()],
            };
            if validate_plan(&proposed) {
                sources.push(source);
            }
        }
        sources.sort_by(|a, b| a.name.cmp(&b.name));
        if sources.is_empty() {
            return Ok(None);
        }
        let plan = Plan {
            max_mss: Some(native_mss(egress[0])?),
            egress: Egress {
                name: name.into(),
                index,
                address: *address,
            },
            sources,
        };
        if !validate_plan(&plan) {
            return Err(invalid());
        }
        // Discover optional platform capability before Owner writes its intent.
        // replace() repeats this check immediately before a native install.
        self.require_pf(true)?;
        Ok(Some(plan))
    }
    fn inspect(&mut self, token: &str, plan: &Plan) -> io::Result<Presence> {
        Ok(match self.layout(token, plan)? {
            Layout::Absent => Presence::Absent,
            Layout::Exact => Presence::Exact,
            Layout::OwnedPartial => Presence::OwnedPartial,
            Layout::Conflict => Presence::Conflict,
        })
    }
    fn replace(
        &mut self,
        token: &str,
        before: Option<&Plan>,
        after: Option<&Plan>,
    ) -> io::Result<()> {
        let plan = before.or(after).ok_or_else(invalid)?;
        let existing = self.layout(token, plan)?;
        match (before, after, &existing) {
            (None, Some(_), Layout::Absent)
            | (Some(_), _, Layout::Exact)
            | (Some(_), None, Layout::OwnedPartial) => (),
            (Some(_), None, Layout::Absent) => return Ok(()),
            _ => return Err(io::Error::other("forward_nat_changed")),
        }
        let own_anchor = anchor(token);
        if let Some(next) = after {
            if !validate_plan(next) {
                return Err(invalid());
            }
            self.require_pf(next.max_mss.is_some())?;
            if self
                .discover(&next.egress.name, next.egress.index)?
                .as_ref()
                != Some(next)
            {
                return Err(io::Error::other("forward_nat_identity_changed"));
            }
            let body = ruleset(token, next);
            self.run(
                PF,
                &["-n", "-p", "/dev/null", "-a", &own_anchor, "-f", "-"],
                Some(&body),
            )?;
            // Capability, identity and syntax checks can take several native
            // calls. Do not replace changes made to this anchor meanwhile.
            if self.layout(token, plan)? != existing {
                return Err(io::Error::other("forward_nat_changed"));
            }
            self.run(PF, &["-a", &own_anchor, "-f", "-"], Some(&body))?;
            if self.inspect(token, next)? != Presence::Exact {
                return Err(io::Error::other("forward_nat_readback_failed"));
            }
        } else {
            // A scoped empty load removes BOTH NAT and normalization. Flushing
            // only NAT would leave the owned scrub rule behind after Stop.
            self.run(PF, &["-a", &own_anchor, "-f", "-"], Some(""))?;
            let table_result = self.run(
                PF,
                &["-a", &own_anchor, "-t", &table(token), "-T", "kill"],
                None,
            );
            if self.inspect(token, plan)? == Presence::Absent {
                return Ok(());
            }
            table_result?;
            return Err(io::Error::other("forward_nat_cleanup_pending"));
        }
        Ok(())
    }
}
fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}
fn native_index(line: &str) -> Option<u32> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let i = fields.iter().position(|s| *s == "index")?;
    fields.get(i + 1)?.parse().ok().filter(|n| *n > 0)
}
fn native_mss(header: &str) -> io::Result<u16> {
    let fields = header.split_whitespace().collect::<Vec<_>>();
    let at = fields
        .iter()
        .position(|field| *field == "mtu")
        .ok_or_else(invalid)?;
    let mtu: u32 = fields
        .get(at + 1)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    if !(576..=65535).contains(&mtu) {
        return Err(invalid());
    }
    Ok((mtu - 40) as u16)
}
fn has_flag(line: &str, flag: &str) -> bool {
    line.split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|f| f == flag))
}
fn ipv4_addresses(lines: &[&str]) -> Vec<(Ipv4Addr, u32)> {
    lines
        .iter()
        .filter_map(|l| {
            let f = l.split_whitespace().collect::<Vec<_>>();
            if f.first() != Some(&"inet") {
                return None;
            }
            let address = f.get(1)?.parse().ok()?;
            let i = f.iter().position(|s| *s == "netmask")?;
            let mask = u32::from_str_radix(f.get(i + 1)?.strip_prefix("0x")?, 16).ok()?;
            Some((address, mask))
        })
        .collect()
}
fn mask_prefix(mask: u32) -> Option<u8> {
    let prefix = mask.leading_ones();
    (mask == u32::MAX.checked_shl(32 - prefix).unwrap_or(0)).then_some(prefix as u8)
}
fn anchor(token: &str) -> String {
    format!("com.apple/nlm_vm_{token}")
}
fn table(token: &str) -> String {
    format!("nlm_{}", &token[..24])
}
fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_owned).collect()
}
fn expected_entries(plan: &Plan) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for s in &plan.sources {
        values.insert(s.network.clone());
        values.insert(format!("!{}", s.host_address));
    }
    values
}
fn table_entries(text: &str) -> io::Result<BTreeSet<String>> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let value = line.split_whitespace().collect::<String>();
            let (negative, ip) = match value.strip_prefix('!') {
                Some(ip) => (true, ip),
                None => (false, value.as_str()),
            };
            let net = ip
                .parse::<Ipv4Net>()
                .or_else(|_| {
                    ip.parse::<Ipv4Addr>()
                        .map(|a| Ipv4Net::new(a, 32).expect("host prefix"))
                })
                .map_err(|_| invalid())?;
            if net != net.trunc() {
                return Err(invalid());
            }
            let value = if net.prefix_len() == 32 {
                net.addr().to_string()
            } else {
                net.to_string()
            };
            Ok(format!("{}{value}", if negative { "!" } else { "" }))
        })
        .collect()
}
fn rule(token: &str, plan: &Plan) -> String {
    format!(
        "nat on {} inet from <{}> to any tag NLM_{}_{} -> {}",
        plan.egress.name,
        table(token),
        token,
        plan.egress.index,
        plan.egress.address
    )
}
fn canonical_rule(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
fn normalization_rules(token: &str, plan: &Plan) -> Vec<String> {
    let Some(mss) = plan.max_mss else {
        return Vec::new();
    };
    let mut rules = vec![format!(
        "scrub out on {} inet proto tcp from <{}> to any max-mss {mss} fragment reassemble",
        plan.egress.name,
        table(token)
    )];
    // Replies have already passed reverse NAT when routed out to the VM.
    // This also caps other incoming TCP to these VMs while the VPN is active;
    // it does not normalize all incoming traffic on the host VPN interface.
    let bridges = plan
        .sources
        .iter()
        .map(|source| source.name.as_str())
        .collect::<BTreeSet<_>>();
    rules.extend(bridges.into_iter().map(|bridge| format!(
        "scrub out on {bridge} inet proto tcp from any to <{}> max-mss {mss} fragment reassemble", table(token)
    )));
    rules
}
fn ruleset(token: &str, plan: &Plan) -> String {
    let entries = plan
        .sources
        .iter()
        .map(|s| s.network.clone())
        .chain(plan.sources.iter().map(|s| format!("!{}", s.host_address)))
        .collect::<Vec<_>>()
        .join(", ");
    let scrub = normalization_rules(token, plan)
        .into_iter()
        .map(|rule| format!("{rule}\n"))
        .collect::<String>();
    format!(
        "table <{}> {{ {entries} }}\n{scrub}{}\n",
        table(token),
        rule(token, plan)
    )
}
fn invalid() -> io::Error {
    io::Error::other("invalid_forward_nat_state")
}
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "forward_nat_pf_hook_unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward_nat::{Egress, Source};
    use std::collections::VecDeque;
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const INTERFACES: &str = "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280 index 19\n\tinet 10.241.0.1 --> 10.241.0.1 netmask 0xffffffff\nbridge107: flags=8a63<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500 index 21\n\tinet 172.29.73.1 netmask 0xffffff00 broadcast 172.29.73.255\n\tmember: vmenet3 flags=20803<LEARNING,DISCOVER,PRIVATE,VIRTIO>\n\tstatus: active\n";
    const NAT: &str = "nat on utun4 inet from <nlm_0123456789abcdef01234567> to any tag NLM_0123456789abcdef0123456789abcdef_19 -> 10.241.0.1\n";
    fn plan() -> Plan {
        Plan {
            max_mss: None,
            egress: Egress {
                name: "utun4".into(),
                index: 19,
                address: "10.241.0.1".parse().unwrap(),
            },
            sources: vec![Source {
                name: "bridge107".into(),
                index: 21,
                network: "172.29.73.0/24".into(),
                host_address: "172.29.73.1".parse().unwrap(),
            }],
        }
    }
    struct Fake {
        output: VecDeque<String>,
        calls: Vec<(String, Vec<String>, Option<String>)>,
    }
    impl Fake {
        fn new(output: &[&str]) -> Self {
            Self {
                output: output.iter().map(|s| s.to_string()).collect(),
                calls: vec![],
            }
        }
    }
    impl Commands for Fake {
        fn run(&mut self, p: &str, a: &[String], input: Option<&str>) -> io::Result<String> {
            self.calls
                .push((p.into(), a.to_vec(), input.map(str::to_owned)));
            self.output
                .pop_front()
                .ok_or_else(|| io::Error::other("unexpected command"))
        }
    }
    #[test]
    fn discovery_derives_changed_subnet_and_fences_reused_egress_index() {
        let mut a = Adapter::new(Fake::new(&[
            INTERFACES,
            "Status: Enabled\n",
            "nat-anchor \"com.apple/*\" all\n",
            "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
        ]));
        assert_eq!(a.discover("utun4", 19).unwrap(), Some(mss_plan()));
        let mut a = Adapter::new(Fake::new(&[INTERFACES]));
        assert!(a.discover("utun4", 20).is_err());
    }
    #[test]
    fn discovery_does_not_share_a_bridge_with_a_physical_member_or_ambiguous_address() {
        for bad in [
            INTERFACES.replace("vmenet3", "en0"),
            INTERFACES.replace("PRIVATE,VIRTIO", "PRIVATE"),
            INTERFACES.replace(
                "\tstatus: active",
                "\tinet 172.29.74.1 netmask 0xffffff00\n\tstatus: active",
            ),
        ] {
            let mut a = Adapter::new(Fake::new(&[&bad]));
            assert!(a.discover("utun4", 19).unwrap().is_none());
        }
    }
    #[test]
    fn inspect_requires_exact_nat_table_and_no_foreign_children() {
        let mut a = Adapter::new(Fake::new(&[
            NAT,
            "nlm_0123456789abcdef01234567\n",
            "",
            "",
            "172.29.73.0/24\n!172.29.73.1\n",
        ]));
        assert_eq!(a.inspect(TOKEN, &plan()).unwrap(), Presence::Exact);
        let mut a = Adapter::new(Fake::new(&[NAT, "foreign\n", "", ""]));
        assert_eq!(a.inspect(TOKEN, &plan()).unwrap(), Presence::Conflict);
        let mut a = Adapter::new(Fake::new(&[
            NAT,
            "nlm_0123456789abcdef01234567\n",
            "",
            "",
            "172.29.73.0/24\n",
        ]));
        assert_eq!(a.inspect(TOKEN, &plan()).unwrap(), Presence::Conflict);
    }
    #[test]
    fn install_refuses_matching_preexisting_rules_instead_of_adopting_them() {
        let mut a = Adapter::new(Fake::new(&[
            NAT,
            "nlm_0123456789abcdef01234567\n",
            "",
            "",
            "172.29.73.0/24\n!172.29.73.1\n",
        ]));
        assert!(a.replace(TOKEN, None, Some(&plan())).is_err());
        assert!(a
            .commands
            .calls
            .iter()
            .all(|(_, args, input)| input.is_none() && !args.iter().any(|s| s == "-F")));
    }
    #[test]
    fn install_requires_live_enabled_pf_and_wildcard_nat_hook() {
        for (status, hook) in [
            ("Status: Disabled\n", "nat-anchor \"com.apple/*\" all\n"),
            (
                "Status: Enabled for 1 days\n",
                "nat-anchor \"other/*\" all\n",
            ),
        ] {
            let mut a = Adapter::new(Fake::new(&["", "", "", "", status, hook]));
            assert!(a.replace(TOKEN, None, Some(&plan())).is_err());
            assert!(a.commands.calls.iter().all(|(_, _, input)| input.is_none()));
        }
    }
    #[test]
    fn install_uses_excluded_host_table_and_private_anchor_only() {
        let mut a = Adapter::new(Fake::new(&[
            "",
            "",
            "",
            "",
            "Status: Enabled\n",
            "nat-anchor \"com.apple/*\" all\n",
            "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
            INTERFACES,
            "Status: Enabled\n",
            "nat-anchor \"com.apple/*\" all\n",
            "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
            "",
            "",
            "",
            "",
            "",
            "",
            NAT,
            "nlm_0123456789abcdef01234567\n",
            SCRUB,
            "",
            "172.29.73.0/24\n!172.29.73.1\n",
        ]));
        a.replace(TOKEN, None, Some(&mss_plan())).unwrap();
        let input = a
            .commands
            .calls
            .iter()
            .filter_map(|(_, _, i)| i.as_ref())
            .next_back()
            .unwrap();
        assert!(
            input.contains("table <nlm_0123456789abcdef01234567> { 172.29.73.0/24, !172.29.73.1 }")
        );
        assert!(input.contains("from <nlm_0123456789abcdef01234567>"));
        assert!(!input.contains("nat pass"));
        assert!(a
            .commands
            .calls
            .iter()
            .filter(|(_, _, input)| input.is_some())
            .all(|(_, args, _)| args
                .windows(2)
                .any(|a| a == ["-a", "com.apple/nlm_vm_0123456789abcdef0123456789abcdef"])));
    }
    #[test]
    fn foreign_anchor_change_during_syntax_check_is_never_overwritten() {
        struct Race {
            owned: bool,
            foreign: bool,
            loaded: bool,
            changed: &'static str,
        }
        impl Commands for Race {
            fn run(
                &mut self,
                program: &str,
                args: &[String],
                _: Option<&str>,
            ) -> io::Result<String> {
                if program == "/sbin/ifconfig" {
                    return Ok(INTERFACES.into());
                }
                if args == ["-si"] {
                    return Ok("Status: Enabled\n".into());
                }
                if args == ["-sn"] {
                    return Ok("nat-anchor \"com.apple/*\" all\n".into());
                }
                if args == ["-sr"] {
                    return Ok("scrub-anchor \"com.apple/*\" all fragment reassemble\n".into());
                }
                if args.iter().any(|arg| arg == "-n") {
                    self.foreign = true;
                    return Ok(String::new());
                }
                if args.iter().any(|arg| arg == "-f") {
                    // Model PF's replacement of the entire anchor, including
                    // a foreign row added after the initial ownership check.
                    self.loaded = true;
                    self.foreign = false;
                    self.owned = true;
                    return Ok(String::new());
                }
                let changed = |kind| self.foreign && self.changed == kind;
                let text = match args.get(2).map(String::as_str) {
                    Some("-sn") if changed("nat") => "nat on en0 from any to any -> 192.0.2.1\n",
                    Some("-sn") if self.owned => NAT,
                    Some("-sn") => "",
                    Some("-sr") if changed("filter") => "pass all\n",
                    Some("-sr") => "",
                    Some("-s") => match args.get(3).map(String::as_str) {
                        Some("Tables") if changed("table") => "foreign_table\n",
                        Some("Tables") if self.owned || changed("contents") => {
                            "nlm_0123456789abcdef01234567\n"
                        }
                        Some("Anchors") if changed("anchor") => "foreign_child\n",
                        Some("Tables" | "Anchors") => "",
                        _ => return Err(invalid()),
                    },
                    Some("-t") if changed("contents") => "172.29.74.0/24\n!172.29.74.1\n",
                    Some("-t") => "172.29.73.0/24\n!172.29.73.1\n",
                    _ => return Err(invalid()),
                };
                Ok(text.into())
            }
        }
        for owned in [false, true] {
            for changed in ["nat", "table", "filter", "anchor", "contents"] {
                let mut adapter = Adapter::new(Race {
                    owned,
                    foreign: false,
                    loaded: false,
                    changed,
                });
                let expected = plan();
                assert!(
                    adapter
                        .replace(TOKEN, owned.then_some(&expected), Some(&mss_plan()))
                        .is_err(),
                    "owned={owned} changed={changed}"
                );
                assert!(adapter.commands.foreign, "foreign {changed} was replaced");
                assert!(
                    !adapter.commands.loaded,
                    "native load overwrote foreign {changed}"
                );
            }
        }
    }
    #[test]
    fn cleanup_flushes_only_owned_nat_and_table_never_states_or_enable_references() {
        let mut a = Adapter::new(Fake::new(&[
            NAT,
            "nlm_0123456789abcdef01234567\n",
            "",
            "",
            "172.29.73.0/24\n!172.29.73.1\n",
            "",
            "",
            "",
            "",
            "",
            "",
        ]));
        a.replace(TOKEN, Some(&plan()), None).unwrap();
        assert!(a
            .commands
            .calls
            .iter()
            .any(|(_, a, input)| a.windows(2).any(|w| w == ["-f", "-"])
                && input.as_deref() == Some("")));
        assert!(a.commands.calls.iter().all(|(_, a, _)| !a
            .iter()
            .any(|s| ["all", "states", "-k", "-E", "-X", "-d"].contains(&s.as_str()))));
    }

    #[test]
    fn table_only_after_interrupted_cleanup_is_owned_partial_but_never_adopted() {
        let output = [
            "",
            "nlm_0123456789abcdef01234567\n",
            "",
            "",
            "172.29.73.0/24\n!172.29.73.1/32\n",
        ];
        let mut a = Adapter::new(Fake::new(&output));
        assert_eq!(a.inspect(TOKEN, &plan()).unwrap(), Presence::OwnedPartial);
        let mut a = Adapter::new(Fake::new(&output));
        assert!(a.replace(TOKEN, None, Some(&plan())).is_err());
        assert_eq!(a.commands.calls.len(), 5);
    }
    #[test]
    fn changing_egress_and_public_or_malformed_bridge_never_authorizes_install() {
        for bad in [
            INTERFACES.replace("10.241.0.1", "10.242.0.1"),
            INTERFACES.replace("172.29.73.1 netmask", "8.8.8.1 netmask"),
            INTERFACES.replace("inet 172.29.73.1", "inet invalid"),
        ] {
            let mut a = Adapter::new(Fake::new(&[
                "",
                "",
                "",
                "",
                "Status: Enabled\n",
                "nat-anchor \"com.apple/*\" all\n",
                "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
                &bad,
                "Status: Enabled\n",
                "nat-anchor \"com.apple/*\" all\n",
                "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
            ]));
            assert!(a.replace(TOKEN, None, Some(&mss_plan())).is_err());
            assert!(a.commands.calls.iter().all(|(_, _, input)| input.is_none()));
        }
    }
    #[test]
    fn foreign_nat_target_tag_filter_or_nested_anchor_blocks_cleanup() {
        for nat in [
            NAT.replace("10.241.0.1", "10.242.0.1"),
            NAT.replace("_19 ->", "_20 ->"),
            format!("{NAT}rdr on en0 proto tcp to any port 443 -> 127.0.0.1\n"),
        ] {
            let mut a = Adapter::new(Fake::new(&[
                &nat,
                "nlm_0123456789abcdef01234567\n",
                "",
                "",
                "172.29.73.0/24\n!172.29.73.1\n",
            ]));
            assert_eq!(a.inspect(TOKEN, &plan()).unwrap(), Presence::Conflict);
            let mut a = Adapter::new(Fake::new(&[
                &nat,
                "nlm_0123456789abcdef01234567\n",
                "",
                "",
                "172.29.73.0/24\n!172.29.73.1\n",
            ]));
            assert!(a.replace(TOKEN, Some(&plan()), None).is_err());
            assert!(a
                .commands
                .calls
                .iter()
                .all(|(_, a, _)| !a.iter().any(|s| s == "-F")));
        }
        for (filter, child) in [("pass all\n", ""), ("", "unknown_child\n")] {
            let mut a = Adapter::new(Fake::new(&[
                NAT,
                "nlm_0123456789abcdef01234567\n",
                filter,
                child,
            ]));
            assert_eq!(a.inspect(TOKEN, &plan()).unwrap(), Presence::Conflict);
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn generated_ruleset_passes_native_pf_syntax_without_opening_the_pf_device() {
        use std::io::Write;
        for expected in [plan(), mss_plan()] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(ruleset(TOKEN, &expected).as_bytes())
                .unwrap();
            let output = crate::process::output_with_timeout(
                std::process::Command::new(PF)
                    .args(["-n", "-p", "/dev/null", "-v", "-a", &anchor(TOKEN), "-f"])
                    .arg(file.path()),
                std::time::Duration::from_secs(3),
            )
            .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|l| canonical_rule(l) == rule(TOKEN, &expected)));
            if expected.max_mss.is_some() {
                assert!(SCRUB
                    .lines()
                    .all(|expected| String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .any(|line| line == expected)));
            }
        }
    }
    #[test]
    fn fresh_owner_detects_unavailable_pf_before_persisting_any_nat_intent() {
        use std::os::unix::fs::PermissionsExt;
        for (status, hook) in [
            ("Status: Disabled\n", "nat-anchor \"com.apple/*\" all\n"),
            (
                "Status: Enabled for 1 days\n",
                "nat-anchor \"custom/*\" all\n",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let adapter = Adapter::new(Fake::new(&[INTERFACES, status, hook]));
            let mut owner = crate::forward_nat::Owner::open(
                root.path(),
                "01234567-89ab-cdef-0123-456789abcdef",
                unsafe { libc::geteuid() },
                adapter,
            )
            .unwrap();
            let error = owner.refresh("utun4", 19).unwrap_err();
            assert!(!owner.has_resources());
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(!root.path().join("forward-nat/forward-nat.json").exists());
            assert!(owner
                .system
                .commands
                .calls
                .iter()
                .all(|(program, a, input)| input.is_none()
                    && (program != PF
                        || !a
                            .iter()
                            .any(|s| ["-a", "-f", "-F", "-T"].contains(&s.as_str())))));
        }
    }
    #[test]
    fn discovery_without_eligible_vmnet_skips_every_pf_command() {
        let no_vmnet = INTERFACES.replace("vmenet3", "en0");
        let mut adapter = Adapter::new(Fake::new(&[&no_vmnet]));
        assert_eq!(adapter.discover("utun4", 19).unwrap(), None);
        assert_eq!(adapter.commands.calls.len(), 1);
        assert_eq!(adapter.commands.calls[0].0, "/sbin/ifconfig");
    }
    const SCRUB: &str = "scrub out on utun4 inet proto tcp from <nlm_0123456789abcdef01234567> to any max-mss 1240 fragment reassemble\nscrub out on bridge107 inet proto tcp from any to <nlm_0123456789abcdef01234567> max-mss 1240 fragment reassemble\n";
    fn mss_plan() -> Plan {
        let mut p = plan();
        p.max_mss = Some(1240);
        p
    }
    #[test]
    fn discovery_derives_mss_from_verified_native_egress_mtu() {
        for (mtu, mss) in [(1280, 1240), (1500, 1460), (9000, 8960)] {
            let native = INTERFACES.replacen("mtu 1280", &format!("mtu {mtu}"), 1);
            let mut a = Adapter::new(Fake::new(&[
                &native,
                "Status: Enabled\n",
                "nat-anchor \"com.apple/*\" all\n",
                "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
            ]));
            assert_eq!(a.discover("utun4", 19).unwrap().unwrap().max_mss, Some(mss));
        }
        for mtu in [575, 65536] {
            let native = INTERFACES.replacen("mtu 1280", &format!("mtu {mtu}"), 1);
            let mut a = Adapter::new(Fake::new(&[
                &native,
                "Status: Enabled\n",
                "nat-anchor \"com.apple/*\" all\n",
                "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
            ]));
            assert!(a.discover("utun4", 19).is_err());
        }
    }
    #[test]
    fn scrub_is_scoped_to_own_vm_table_and_utun_and_requires_both_exact_readbacks() {
        let generated = ruleset(TOKEN, &mss_plan());
        assert!(generated.contains("scrub out on utun4 inet proto tcp from <nlm_0123456789abcdef01234567> to any max-mss 1240"));
        assert!(!generated.contains("scrub in"));
        assert!(!generated.contains("scrub all"));
        let mut a = Adapter::new(Fake::new(&[
            NAT,
            "nlm_0123456789abcdef01234567\n",
            SCRUB,
            "",
            "172.29.73.0/24\n!172.29.73.1\n",
        ]));
        assert_eq!(a.inspect(TOKEN, &mss_plan()).unwrap(), Presence::Exact);
        for (nat, scrub) in [(NAT, ""), ("", SCRUB)] {
            let mut a = Adapter::new(Fake::new(&[
                nat,
                "nlm_0123456789abcdef01234567\n",
                scrub,
                "",
                "172.29.73.0/24\n!172.29.73.1\n",
            ]));
            assert_eq!(
                a.inspect(TOKEN, &mss_plan()).unwrap(),
                Presence::OwnedPartial
            );
        }
        for bad in [
            SCRUB.replace("1240", "1460"),
            format!("{SCRUB}pass all\n"),
            SCRUB.replace("out on utun4", "in on utun4"),
        ] {
            let mut a = Adapter::new(Fake::new(&[
                NAT,
                "nlm_0123456789abcdef01234567\n",
                &bad,
                "",
                "172.29.73.0/24\n!172.29.73.1\n",
            ]));
            assert_eq!(a.inspect(TOKEN, &mss_plan()).unwrap(), Presence::Conflict);
        }
    }
    #[test]
    fn missing_live_scrub_hook_is_unsupported_before_fresh_owner_has_resources() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let adapter = Adapter::new(Fake::new(&[
            INTERFACES,
            "Status: Enabled\n",
            "nat-anchor \"com.apple/*\" all\n",
            "anchor \"com.apple/*\" all\n",
        ]));
        let mut owner = crate::forward_nat::Owner::open(
            root.path(),
            "01234567-89ab-cdef-0123-456789abcdef",
            unsafe { libc::geteuid() },
            adapter,
        )
        .unwrap();
        let e = owner.refresh("utun4", 19).unwrap_err();
        assert!(!owner.has_resources());
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }
    #[test]
    fn cleanup_removes_exact_owned_scrub_and_nat_with_no_global_rule_or_state_flush() {
        let mut a = Adapter::new(Fake::new(&[
            NAT,
            "nlm_0123456789abcdef01234567\n",
            SCRUB,
            "",
            "172.29.73.0/24\n!172.29.73.1\n",
            "",
            "",
            "",
            "",
            "",
            "",
        ]));
        a.replace(TOKEN, Some(&mss_plan()), None).unwrap();
        assert!(a.commands.calls.iter().any(|(_, args, input)| args
            == &["-a", &anchor(TOKEN), "-f", "-"].map(str::to_string)
            && input.as_deref() == Some("")));
        assert!(a.commands.calls.iter().all(|(_, args, _)| !args
            .iter()
            .any(|s| ["-F", "-k", "-E", "-X", "-d"].contains(&s.as_str()))));
    }
    const BOTH_SCRUBS: &str = "scrub out on utun4 inet proto tcp from <nlm_0123456789abcdef01234567> to any max-mss 1240 fragment reassemble\nscrub out on bridge107 inet proto tcp from any to <nlm_0123456789abcdef01234567> max-mss 1240 fragment reassemble\n";
    #[test]
    fn reverse_mss_clamp_uses_each_verified_virtual_bridge_without_host_inbound_rule() {
        let mut expected = mss_plan();
        expected.sources[0].name = "bridge205".into();
        expected.sources[0].index = 25;
        let generated = ruleset(TOKEN, &expected);
        assert!(generated.contains("scrub out on bridge205 inet proto tcp from any to <nlm_0123456789abcdef01234567> max-mss 1240"));
        assert!(!generated.contains("bridge107"));
        assert!(!generated.contains("scrub in"));
        assert!(!generated.contains("scrub out on utun4 inet proto tcp from any"));
        assert_eq!(
            generated
                .lines()
                .filter(|line| line.starts_with("scrub "))
                .count(),
            2
        );
        expected.sources.push(Source {
            name: "bridge205".into(),
            index: 25,
            network: "172.29.74.0/24".into(),
            host_address: "172.29.74.1".parse().unwrap(),
        });
        assert_eq!(
            ruleset(TOKEN, &expected)
                .lines()
                .filter(|line| line.starts_with("scrub out on bridge205 "))
                .count(),
            1
        );
    }
    #[test]
    fn reverse_mss_readback_requires_complete_set_but_known_subsets_remain_cleanup_only() {
        let output = [
            NAT,
            "nlm_0123456789abcdef01234567\n",
            BOTH_SCRUBS,
            "",
            "172.29.73.0/24\n!172.29.73.1\n",
        ];
        let mut a = Adapter::new(Fake::new(&output));
        assert_eq!(a.inspect(TOKEN, &mss_plan()).unwrap(), Presence::Exact);
        for partial in BOTH_SCRUBS.lines() {
            let mut a = Adapter::new(Fake::new(&[
                NAT,
                "nlm_0123456789abcdef01234567\n",
                partial,
                "",
                "172.29.73.0/24\n!172.29.73.1\n",
            ]));
            assert_eq!(
                a.inspect(TOKEN, &mss_plan()).unwrap(),
                Presence::OwnedPartial
            );
        }
        for wrong in [
            BOTH_SCRUBS.replace("bridge107", "bridge205"),
            format!("{BOTH_SCRUBS}pass all\n"),
            format!("{BOTH_SCRUBS}{BOTH_SCRUBS}"),
        ] {
            let mut a = Adapter::new(Fake::new(&[
                NAT,
                "nlm_0123456789abcdef01234567\n",
                &wrong,
                "",
                "172.29.73.0/24\n!172.29.73.1\n",
            ]));
            assert_eq!(a.inspect(TOKEN, &mss_plan()).unwrap(), Presence::Conflict);
        }
    }
}
