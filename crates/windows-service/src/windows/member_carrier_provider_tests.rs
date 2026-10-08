use super::*;

#[test]
fn partial_service_namespace_accepts_only_exact_sdk_facts_without_returning_a_provider() {
    for known in [false, true] {
        let (wants, mut query) = mixed_fixture();
        let target = target(&wants[2].identity);
        assert_eq!(
            inspect_mixed_partial_queries(
                &wants[..2],
                &target,
                wants[2].kind,
                known.then_some(&wants[2]),
                &mut query
            ),
            Ok(true)
        );
        // Full mixed SDK validation remains mandatory. Only factual presence
        // escapes, never an adoptable provider or Running proof.
        assert_eq!(query.next, query.reads.len());
    }
    let (wants, mut query) = mixed_absence_fixture();
    assert_eq!(
        inspect_mixed_partial_queries(
            &wants,
            &mixed_absence_target(),
            ProviderKind::Wintun,
            None,
            &mut query
        ),
        Ok(false)
    );
}

#[test]
fn partial_service_namespace_does_not_replace_known_original_or_relax_wrong_kind() {
    for fault in 0..4 {
        let (wants, mut query) = mixed_fixture();
        let mut partial = target(&wants[2].identity);
        let mut kind = wants[2].kind;
        match fault {
            0 => partial.guid = wants[0].identity.guid,
            1 => partial.name = wants[0].identity.name.clone(),
            2 => partial.name = "different partial name".into(),
            _ => kind = ProviderKind::WireGuardNt,
        }
        assert!(
            inspect_mixed_partial_queries(&wants[..2], &partial, kind, None, &mut query).is_err(),
            "{fault}"
        );
    }
    for field in 0..7 {
        let (wants, mut query) = mixed_fixture();
        let mut captured = wants[2].clone();
        match field {
            0 => captured.identity.index += 1,
            1 => captured.identity.luid += 1,
            2 => captured.identity.description.push('x'),
            3 => captured.identity.if_type += 1,
            4 => captured.identity.tunnel_type += 1,
            5 => captured.identity.name.push('x'),
            _ => captured.kind = ProviderKind::WireGuardNt,
        }
        assert!(
            inspect_mixed_partial_queries(
                &wants[..2],
                &target(&wants[2].identity),
                wants[2].kind,
                Some(&captured),
                &mut query
            )
            .is_err(),
            "captured field {field}"
        );
    }
}

#[test]
fn partial_service_namespace_keeps_full_mib_pnp_stack_and_final_stability_checks() {
    for fault in 0..8 {
        let (wants, mut query) = mixed_fixture();
        let partial = target(&wants[2].identity);
        match fault {
            0 => query.source.tables[1].last_mut().unwrap().identity.index += 1,
            1 => query.reads[4]
                .interfaces
                .last_mut()
                .unwrap()
                .identity
                .name
                .push('x'),
            2 => query.source.nodes[0].last_mut().unwrap().problem = 22,
            3 => query.source.nodes[1].last_mut().unwrap().presence = Presence::Phantom,
            4 => {
                let extra = query.source.nodes[0].last().unwrap().clone();
                query.source.nodes[0].push(extra);
            }
            5 => {
                query.source.nodes[0].last_mut().unwrap().wireguard_name = Some(PrivateName {
                    kind: ProviderKind::WireGuardNt,
                    value: partial.name.clone(),
                })
            }
            6 => {
                query.source.nodes[1].last_mut().unwrap().driver.version = "foreign version".into()
            }
            _ => query.source.tables[0].last_mut().unwrap().identity.guid = [0x88; 16],
        }
        assert!(
            inspect_mixed_partial_queries(&wants[..2], &partial, wants[2].kind, None, &mut query)
                .is_err(),
            "fault {fault}"
        );
    }
    // A target not found in MIB still requires BOTH independently queried PnP
    // snapshots, including non-Net/phantom/name-collision facts.
    for phase in 0..2 {
        let (wants, mut query) = mixed_absence_fixture();
        query.source.nodes[phase][0].standard_name = Some(mixed_absence_target().name);
        assert!(inspect_mixed_partial_queries(
            &wants,
            &mixed_absence_target(),
            ProviderKind::Wintun,
            None,
            &mut query
        )
        .is_err());
    }
}

fn mixed_absence_target() -> AbsenceTarget {
    AbsenceTarget {
        guid: [0x42; 16],
        name: "Nelomai fresh member".into(),
    }
}
fn mixed_absence_fixture() -> (Vec<ExpectedProvider>, MixedScript) {
    let (mut wants, mut q) = mixed_fixture();
    // Exact C + WG live universe, no AWG original yet. Keep every independently
    // crossbound foreign base/filter in the full tables and PnP snapshots.
    wants.pop();
    q.reads.remove(5);
    q.reads.remove(2);
    for read in &mut q.reads {
        read.interfaces.remove(9);
    }
    for rows in &mut q.source.tables {
        rows.remove(9);
    }
    for nodes in &mut q.source.nodes {
        nodes.remove(4);
    }
    (wants, q)
}
#[test]
fn mixed_live_c_and_wireguard_allow_a_fresh_unique_absence_target() {
    // Break: strict Wintun-only absence rejects a complete explicitly tracked
    // WG original. Actual production validation; only OS reads are replaced.
    let (wants, mut q) = mixed_absence_fixture();
    assert_eq!(
        inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).map(|_| ()),
        Ok(())
    );
}

#[test]
fn mixed_absence_rejects_target_collision_in_explicit_wants_before_queries() {
    // Break: caller omits a fresh lookup but labels an expected original absent.
    for member in 0..2 {
        for by_name in [false, true] {
            let (wants, mut q) = mixed_absence_fixture();
            let mut target = mixed_absence_target();
            if by_name {
                target.name = wants[member].identity.name.to_ascii_uppercase();
            } else {
                target.guid = wants[member].identity.guid;
            }
            assert_eq!(
                inspect_mixed_absent_queries(&wants, &target, &mut q),
                Err(Error::Conflict("absence target in expected universe"))
            );
            assert!(q.source.events.is_empty());
        }
    }
}
#[test]
fn mixed_absence_checks_target_in_every_complete_mib_read() {
    // Break: checking only expected rows/one table, hiding a full-table target.
    for read in 0..4 {
        for by_name in [false, true] {
            let (wants, mut q) = mixed_absence_fixture();
            let target = mixed_absence_target();
            if by_name {
                q.reads[read].interfaces[0].identity.name = target.name.to_ascii_uppercase();
            } else {
                q.reads[read].interfaces[0].identity.guid = target.guid;
            }
            assert_eq!(
                inspect_mixed_absent_queries(&wants, &target, &mut q),
                Err(Error::Conflict("name/GUID present in MIB")),
                "read {read}"
            );
        }
    }
}
#[test]
fn mixed_absence_checks_both_pnp_reads_for_private_and_standard_name_collisions() {
    // Break: only comparing MIB aliases or only the private property of the
    // selected provider; target check must see all retained PnP facts first.
    for phase in 0..2 {
        for field in 0..4 {
            let (wants, mut q) = mixed_absence_fixture();
            let target = mixed_absence_target();
            let node = &mut q.source.nodes[phase][0];
            match field {
                0 => node.name = target.name.to_ascii_uppercase(),
                1 => {
                    node.wireguard_name = Some(PrivateName {
                        kind: ProviderKind::WireGuardNt,
                        value: target.name.to_ascii_uppercase(),
                    })
                }
                2 => node.standard_name = Some(target.name.to_ascii_uppercase()),
                _ => node.netcfg_instance_id = "{42424242-4242-4242-4242-424242424242}".into(),
            }
            assert_eq!(
                inspect_mixed_absent_queries(&wants, &target, &mut q),
                Err(Error::Conflict("name/GUID present in PnP")),
                "{phase}/{field}"
            );
        }
    }
}
#[test]
fn mixed_absence_supplies_the_absent_target_to_both_actual_full_pnp_scans() {
    // Break: default Net-only retention hides target-related non-Net nodes.
    let (wants, mut q) = mixed_absence_fixture();
    let target = mixed_absence_target();
    assert_eq!(
        inspect_mixed_absent_queries(&wants, &target, &mut q).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        q.source.requested_targets,
        [
            vec![
                AbsenceTarget {
                    guid: GUID,
                    name: "Nelomai VIP".into()
                },
                AbsenceTarget {
                    guid: [
                        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x81, 0x23, 0x45, 0x67,
                        0x89, 0xab, 0xcd, 0xee
                    ],
                    name: "Nelomai WG".into()
                },
                target.clone()
            ],
            vec![
                AbsenceTarget {
                    guid: GUID,
                    name: "Nelomai VIP".into()
                },
                AbsenceTarget {
                    guid: [
                        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x81, 0x23, 0x45, 0x67,
                        0x89, 0xab, 0xcd, 0xee
                    ],
                    name: "Nelomai WG".into()
                },
                target
            ],
        ]
    );
}
#[test]
fn mixed_absence_zero_wants_checks_the_target_against_full_foreign_facts() {
    // Break: zero comparison inputs return early, or do not check fresh target.
    for phase in 0..2 {
        let mut q = foreign_query(true);
        q.nodes[phase][0].standard_name = Some("Nelomai fresh member".into());
        assert_eq!(
            inspect_mixed_absent_queries(&[], &mixed_absence_target(), &mut q),
            Err(Error::Conflict("name/GUID present in PnP"))
        );
    }
}

#[test]
fn mixed_absence_accepts_exact_c_wg_awg_and_preserves_read_order() {
    // Break: projecting a complete C/A/B universe down to only its WG member.
    let (wants, mut q) = mixed_fixture();
    let observed = inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).unwrap();
    assert_eq!(
        observed.iter().map(|o| &o.interface).collect::<Vec<_>>(),
        wants.iter().map(|w| &w.identity).collect::<Vec<_>>()
    );
    assert_eq!(
        q.source.events,
        [
            "interfaces",
            "interfaces",
            "interfaces",
            "snapshot",
            "stack",
            "snapshot",
            "interfaces",
            "interfaces",
            "interfaces",
            "stack"
        ]
    );
    let (wants, mut q) = mixed_absence_fixture();
    assert_eq!(
        inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        q.source.events,
        [
            "interfaces",
            "interfaces",
            "snapshot",
            "stack",
            "snapshot",
            "interfaces",
            "interfaces",
            "stack"
        ]
    );
}

#[test]
fn mixed_absence_denies_stable_pnp_and_mib_collisions_without_relying_on_changed() {
    // Break: detecting only mutation, while a stable foreign source name/GUID
    // collision is accepted as independent non-provider evidence.
    for by_name in [false, true] {
        let (wants, mut q) = mixed_absence_fixture();
        let mut target = mixed_absence_target();
        if by_name {
            for read in &mut q.reads {
                read.interfaces[0].identity.name = target.name.to_ascii_uppercase();
            }
        } else {
            target.guid = q.reads[0].interfaces[0].identity.guid;
        }
        assert_eq!(
            inspect_mixed_absent_queries(&wants, &target, &mut q),
            Err(Error::Conflict("name/GUID present in MIB"))
        );
        let (wants, mut q) = mixed_absence_fixture();
        for nodes in &mut q.source.nodes {
            nodes[0].standard_name = Some("NELOMAI FRESH MEMBER".into());
        }
        assert_eq!(
            inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q),
            Err(Error::Conflict("name/GUID present in PnP"))
        );
    }
}

#[test]
fn mixed_absence_target_pnp_check_includes_problem_phantom_nonnet_and_dual_names() {
    // Break: checking absence only on live Net nodes of the selected kind.
    for phase in 0..2 {
        for field in 0..5 {
            let (wants, mut q) = mixed_absence_fixture();
            let target = mixed_absence_target();
            let node = &mut q.source.nodes[phase][0];
            node.wireguard_name = Some(PrivateName {
                kind: ProviderKind::WireGuardNt,
                value: target.name.clone(),
            });
            match field {
                0 => {
                    node.presence = Presence::Phantom;
                    node.status = 0;
                }
                1 => node.problem = 22,
                2 => node.class_guid = [7; 16],
                3 => node.name = "Other private Wintun name".into(),
                _ => node.wireguard_name.as_mut().unwrap().kind = ProviderKind::Wintun,
            }
            assert_eq!(
                inspect_mixed_absent_queries(&wants, &target, &mut q),
                Err(Error::Conflict("name/GUID present in PnP")),
                "{phase}/{field}"
            );
        }
    }
}

#[test]
fn mixed_absence_rejects_missing_extra_alias_problem_and_phantom_originals() {
    // Break: absence checking relaxes the actual mixed universe's full binding.
    for phase in 0..2 {
        for field in 0..15 {
            let (wants, mut q) = mixed_absence_fixture();
            let nodes = &mut q.source.nodes[phase];
            match field {
                0 => {
                    nodes.remove(3);
                }
                1 => nodes.push(nodes[3].clone()),
                2 => nodes[3].devinst = nodes[2].devinst,
                3 => nodes[3].netcfg_instance_id = nodes[2].netcfg_instance_id.clone(),
                4 => nodes[3].problem = 22,
                5 => {
                    nodes[3].presence = Presence::Phantom;
                    nodes[3].status = 0;
                }
                6 => nodes[3].status |= 0x40000,
                7 => nodes[3].wireguard_name = None,
                8 => nodes[3].wireguard_name.as_mut().unwrap().kind = ProviderKind::Wintun,
                9 => nodes[3].class_guid = [7; 16],
                10 => nodes[0].service = "AmneziaWG".into(),
                11 => {
                    nodes[0].wireguard_name = Some(PrivateName {
                        kind: ProviderKind::WireGuardNt,
                        value: "Unknown WG".into(),
                    })
                }
                12 => nodes[0].driver.provider = "WireGuard LLC".into(),
                13 => nodes[3].driver.version = "1.1.1.0".into(),
                _ => nodes[3].netcfg_instance_id = "malformed".into(),
            }
            q.source.nodes[1 - phase] = q.source.nodes[phase].clone();
            assert!(
                inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).is_err(),
                "{phase}/{field}"
            );
        }
    }
    let (wants, mut q) = mixed_fixture();
    // A complete third original omitted by the caller is still an extra.
    assert!(inspect_mixed_absent_queries(&wants[..2], &mixed_absence_target(), &mut q).is_err());
}

#[test]
fn mixed_absence_rejects_a_fourth_fully_shaped_current_wireguard_original() {
    // Break: an otherwise valid extra WG can be explained as generic foreign.
    let (wants, mut q) = mixed_fixture();
    let mut node = q.source.nodes[0][3].clone();
    node.devinst = 999;
    node.netcfg_instance_id = "{00000000-0000-0000-0000-000000000001}".into();
    node.instance = format!("SWD\\WireGuard\\{}", node.netcfg_instance_id);
    node.net_luid_index = 999;
    node.wireguard_name.as_mut().unwrap().value = "Extra WG".into();
    let mut row = q.reads[1].by_luid.clone();
    row.identity.guid = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    row.identity.index = 999;
    row.identity.luid = (53 << 48) | (999 << 24);
    row.identity.name = "Extra WG".into();
    for nodes in &mut q.source.nodes {
        nodes.push(node.clone());
    }
    for read in &mut q.reads {
        read.interfaces.push(row.clone());
    }
    assert!(inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).is_err());
}

#[test]
fn mixed_absence_rejects_stale_full_tables_index_reuse_and_each_key_binding() {
    // Break: an absence wrapper skips independent LUID/index/GUID continuity.
    for read in 0..4 {
        for field in 0..9 {
            let (wants, mut q) = mixed_absence_fixture();
            let seen = &mut q.reads[read];
            match field {
                0 => seen.by_luid.identity.index += 100,
                1 => seen.by_index.identity.guid = [7; 16],
                2 => seen.by_guid.identity.luid += 1 << 24,
                3 => seen.interfaces[0].identity.index = wants[0].identity.index,
                4 => seen.interfaces[0].identity.luid = wants[1].identity.luid,
                5 => {
                    seen.interfaces.remove(8);
                }
                6 => seen.interfaces[0].identity.guid = [0; 16],
                7 => seen.interfaces[0].identity.description = "Changed foreign metadata".into(),
                _ => seen.interfaces[8].role_flags ^= 0x10,
            }
            assert!(
                inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).is_err(),
                "{read}/{field}"
            );
        }
    }
}

#[test]
fn mixed_absence_never_explains_an_orphan_or_related_filter_as_a_foreign_stack() {
    // Break: preserving a stack success bit instead of the real full graph.
    for phase in 0..2 {
        for field in 0..5 {
            let (wants, mut q) = mixed_absence_fixture();
            match field {
                0 => q.source.stacks[phase].clear(),
                1 => q.source.stacks[phase][0].lower = wants[1].identity.index,
                2 => q.source.stacks[phase][0].lower = 999,
                3 => q.source.stacks[phase][1].lower = 39,
                _ => q.source.stacks[phase].push(q.source.stacks[phase][0]),
            }
            q.source.stacks[1 - phase] = q.source.stacks[phase].clone();
            assert!(
                inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).is_err(),
                "{phase}/{field}"
            );
        }
    }
}

#[test]
fn mixed_absence_propagates_every_os_error_in_live_and_zero_wants_paths() {
    // Break: failed or missing reads become successful absence or stale facts.
    for n in 1..=8 {
        let (wants, mut q) = mixed_absence_fixture();
        q.source.fail = Some(n);
        assert_eq!(
            inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.source.events.len(), n);
    }
    for n in 1..=10 {
        let (wants, mut q) = mixed_fixture();
        q.source.fail = Some(n);
        assert_eq!(
            inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.source.events.len(), n);
    }
    for n in 1..=6 {
        let mut q = AbsenceScript::empty();
        q.fail = Some(n);
        assert_eq!(
            inspect_mixed_absent_queries(&[], &mixed_absence_target(), &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.events.len(), n);
    }
}

#[test]
fn mixed_absence_denies_before_after_metadata_and_valid_graph_mutations() {
    // Break: successful independent absence checks replace full continuity.
    for field in 0..7 {
        let (wants, mut q) = mixed_absence_fixture();
        let node = &mut q.source.nodes[1][3];
        match field {
            0 => node.devinst += 100,
            1 => node.driver.inf = "oem99.inf".into(),
            2 => node.driver.driver_key = "{4d36e972-e325-11ce-bfc1-08002be10318}\\0099".into(),
            3 => node.status ^= 0x2000,
            4 => node.service = "WIREGUARD".into(),
            5 => node.hardware_ids[0] = "WIREGUARD".into(),
            _ => q.source.stacks[1][1].lower = 24, // Still a resolved acyclic graph.
        }
        assert_eq!(
            inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q),
            Err(Error::Changed),
            "field {field}"
        );
    }
    for read in 0..4 {
        let (wants, mut q) = mixed_absence_fixture();
        q.reads[read].interfaces[0].identity.description = "Changed foreign description".into();
        assert_eq!(
            inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q),
            Err(Error::Changed)
        );
    }
}

#[test]
fn mixed_absence_zero_wants_is_full_empty_related_universe_without_adopting_wintun() {
    // Break: use old target-only absence's inferred Wintun universe for zero.
    let mut q = AbsenceScript::empty();
    assert_eq!(
        inspect_mixed_absent_queries(&[], &mixed_absence_target(), &mut q).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        q.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
    assert_eq!(
        q.requested_targets,
        [vec![mixed_absence_target()], vec![mixed_absence_target()]]
    );
    let mut q = foreign_query(true);
    assert_eq!(
        inspect_mixed_absent_queries(&[], &mixed_absence_target(), &mut q).map(|_| ()),
        Ok(())
    );
    for member in 0..3 {
        let (_, source) = mixed_fixture();
        let mut q = AbsenceScript::empty();
        q.tables = [
            vec![source.reads[member].by_luid.clone()],
            vec![source.reads[member].by_luid.clone()],
        ];
        q.nodes = [
            vec![source.source.nodes[0][2 + member].clone()],
            vec![source.source.nodes[1][2 + member].clone()],
        ];
        assert!(inspect_mixed_absent_queries(&[], &mixed_absence_target(), &mut q).is_err());
    }
    // The old strict target-only API retains its preexisting Wintun behavior.
    let mut q = AbsenceScript::empty();
    q.tables = [observed().interfaces, observed().interfaces];
    q.nodes = [observed().devices, observed().devices];
    assert_eq!(
        inspect_absent_queries(&mixed_absence_target(), &mut q),
        Ok(())
    );
}

#[test]
fn mixed_absence_bounds_targets_aliases_and_invalid_expected_inputs_before_reading() {
    // Break: unbounded/malformed comparisons enter an OS query or aliases hide
    // duplicates. These are comparison facts, never trusted owner assertions.
    for (guid, name) in [
        ([0; 16], "Fresh".into()),
        ([1; 16], String::new()),
        ([1; 16], " Leading".into()),
        ([1; 16], "Trailing ".into()),
        ([1; 16], "bad\0name".into()),
        ([1; 16], "кириллица".into()),
        ([1; 16], "x".repeat(128)),
    ] {
        let (wants, mut q) = mixed_absence_fixture();
        assert!(
            inspect_mixed_absent_queries(&wants, &AbsenceTarget { guid, name }, &mut q).is_err()
        );
        assert!(q.source.events.is_empty());
    }
    for field in 0..5 {
        let (mut wants, mut q) = mixed_absence_fixture();
        match field {
            0 => wants = vec![wants[0].clone(); 4],
            1 => wants[1] = wants[0].clone(),
            2 => wants[0].identity.guid = [0; 16],
            3 => wants[0].identity.luid = 0,
            _ => wants[0].identity.tunnel_type = 1,
        }
        assert!(inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).is_err());
        assert!(q.source.events.is_empty());
    }
    let (mut wants, mut q) = mixed_absence_fixture();
    wants[1].kind = ProviderKind::Wintun;
    assert!(inspect_mixed_absent_queries(&wants, &mixed_absence_target(), &mut q).is_err());
}

#[test]
fn mixed_absence_missing_full_snapshot_or_stack_never_implies_absence() {
    // Break: treat unavailable ALLCLASSES or graph reads as empty defaults.
    struct MissingRead {
        source: MixedScript,
        snapshot: bool,
    }
    impl Queries for MissingRead {
        fn interfaces(&mut self, want: &Expected) -> Result<Observed> {
            self.source.interfaces(want)
        }
        fn table(&mut self) -> Result<Vec<Interface>> {
            self.source.table()
        }
        fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
            if self.snapshot {
                Err(Error::Invalid("missing full snapshot"))
            } else {
                self.source.device_snapshot(targets)
            }
        }
        fn stack(&mut self) -> Result<Vec<StackEdge>> {
            Err(Error::Invalid("missing full stack"))
        }
    }
    for snapshot in [false, true] {
        let (wants, source) = mixed_absence_fixture();
        assert!(inspect_mixed_absent_queries(
            &wants,
            &mixed_absence_target(),
            &mut MissingRead { source, snapshot }
        )
        .is_err());
    }
}

// Synthetic C/WG/AWG schema fixtures. WG runtime DLL/INF facts were supplied
// from main's independently retained signed36555129204 stream, not measured
// Windows PnP observations by this worker. Actual mixed native execution UNRUN.
struct MixedScript {
    source: AbsenceScript,
    reads: Vec<Observed>,
    next: usize,
}
impl Queries for MixedScript {
    fn interfaces(&mut self, _: &Expected) -> Result<Observed> {
        self.source.event("interfaces")?;
        let seen = self.reads.get(self.next).cloned().ok_or(Error::Changed)?;
        self.next += 1;
        Ok(seen)
    }
    fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
        self.source.device_snapshot(targets)
    }
    fn table(&mut self) -> Result<Vec<Interface>> {
        self.source.table()
    }
    fn stack(&mut self) -> Result<Vec<StackEdge>> {
        self.source.stack()
    }
}
fn mixed_fixture() -> (Vec<ExpectedProvider>, MixedScript) {
    let mut wants = vec![];
    let mut rows = vec![];
    let mut devices = vec![];
    for i in 0..3u32 {
        let mut identity = expected();
        identity.guid[15] = 0xef - i as u8;
        identity.luid += u64::from(i) << 24;
        identity.index = 117 + i;
        identity.name = ["Nelomai VIP", "Nelomai WG", "Nelomai AWG"][i as usize].into();
        identity.description =
            ["Nelomai Tunnel", "Nelomai WG Tunnel", "Nelomai AWG Tunnel"][i as usize].into();
        let row = Interface {
            identity: identity.clone(),
            role_flags: 16,
        };
        let mut d = observed().devices.remove(0);
        d.devinst += i;
        d.net_luid_index += i;
        d.netcfg_instance_id = format!("{{12345678-9abc-def0-8123-456789abcd{:02x}}}", 0xef - i);
        d.instance = format!(
            "SWD\\{}\\{}",
            if i == 1 { "WireGuard" } else { "Wintun" },
            d.netcfg_instance_id
        );
        d.description = identity.description.clone();
        d.name = identity.name.clone();
        d.driver.driver_key = format!("{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{:04}", 42 + i);
        d.driver.inf = format!("oem{}.inf", 42 + i);
        let kind = if i == 1 {
            ProviderKind::WireGuardNt
        } else {
            ProviderKind::Wintun
        };
        if i == 1 {
            d.name.clear();
            d.wireguard_name = Some(PrivateName {
                kind,
                value: identity.name.clone(),
            });
            d.standard_name = Some(identity.description.clone());
            d.hardware_ids = vec!["WireGuard".into()];
            d.service = "WireGuard".into();
            d.driver.matching_device_id = "WireGuard".into();
            d.driver.version = "1.1.0.0".into();
            d.driver.date_filetime = 134_224_992_000_000_000;
        }
        wants.push(ExpectedProvider { identity, kind });
        devices.push(d);
        rows.push(row);
    }
    let reads = rows
        .iter()
        .map(|row| Observed {
            by_luid: row.clone(),
            by_index: row.clone(),
            by_guid: row.clone(),
            interfaces: rows.clone(),
            devices: vec![],
        })
        .collect::<Vec<_>>();
    let mut source = foreign_query(true);
    for phase in 0..2 {
        source.tables[phase].extend(rows.clone());
        source.nodes[phase].extend(devices.clone());
    }
    let mut reads = [reads.clone(), reads].concat();
    for read in &mut reads {
        read.interfaces = source.tables[0].clone();
    }
    (
        wants,
        MixedScript {
            source,
            reads,
            next: 0,
        },
    )
}
#[test]
fn mixed_c_wireguard_awg_returns_every_concrete_observation_in_caller_order() {
    // Break: validating an expected WG-NT as Wintun, or hiding it as foreign.
    let (wants, mut q) = mixed_fixture();
    // The driver key is opaque metadata from the same node, not parsed identity.
    for nodes in &mut q.source.nodes {
        for node in nodes {
            node.driver.driver_key = "opaque-driver-key\\12345".into();
        }
    }
    let got = inspect_mixed_queries(&wants, &mut q).unwrap();
    assert_eq!(got.len(), 3);
    assert!(got
        .iter()
        .all(|o| o.instance.driver.driver_key == "opaque-driver-key\\12345"));
    assert_eq!(
        got.iter()
            .map(|o| o.interface.name.as_str())
            .collect::<Vec<_>>(),
        ["Nelomai VIP", "Nelomai WG", "Nelomai AWG"]
    );
    assert_eq!(got[0].instance.name, "Nelomai VIP");
    assert_eq!(got[1].instance.name, "");
    assert_eq!(
        got[1].instance.wireguard_name.as_ref().unwrap().value,
        "Nelomai WG"
    );
    assert_eq!(got[1].instance.driver.version, "1.1.0.0");
    assert_eq!(got[2].instance.name, "Nelomai AWG");
    // FriendlyName is cosmetic; the private name and native bindings identify
    // the original. Its independently collected value still must be stable.
    for friendly in [
        None,
        Some("Different Tunnel".into()),
        Some("Nelomai WG Tunnel #2".into()),
    ] {
        let (wants, mut q) = mixed_fixture();
        for nodes in &mut q.source.nodes {
            nodes[3].standard_name = friendly.clone();
        }
        let got = inspect_mixed_queries(&wants, &mut q).unwrap();
        assert_eq!(got[1].instance.standard_name, friendly);
    }
}

#[test]
fn expected_non_native_tunnel_protocol_never_becomes_a_provider_match() {
    // Break: caller and MIB agreeing on an unsupported tunnel protocol is not
    // permission to bless an otherwise matching closed Wintun/WG schema.
    for member in 0..3 {
        let (mut wants, mut q) = mixed_fixture();
        wants[member].identity.tunnel_type = 1;
        for read in &mut q.reads {
            read.interfaces[7 + member].identity.tunnel_type = 1;
        }
        for read in [member, 3 + member] {
            q.reads[read].by_luid.identity.tunnel_type = 1;
            q.reads[read].by_index.identity.tunnel_type = 1;
            q.reads[read].by_guid.identity.tunnel_type = 1;
        }
        assert!(
            inspect_mixed_queries(&wants, &mut q).is_err(),
            "member {member}"
        );
    }
}

#[test]
fn actual_native_private_property_decoder_rejects_dual_names_even_when_equal() {
    // Break: the native ALLCLASSES reader accepts two private properties and
    // lets downstream code choose a preferred name. Exercise its real decoder.
    for second in ["Nelomai WG", "Different"] {
        assert!(private_names(
            Some((18, bytes("Nelomai WG\0"))),
            Some((18, bytes(&format!("{second}\0"))))
        )
        .is_err());
    }
}

#[test]
fn native_private_name_bytes_retain_key_provenance_and_require_string_kind() {
    // Break: re-tagging WG as Wintun or accepting unknown native kind/UTF16.
    let (wintun, wireguard) = private_names(None, Some((18, bytes("Nelomai WG\0")))).unwrap();
    assert_eq!(wintun, None);
    assert_eq!(
        wireguard,
        Some(PrivateName {
            kind: ProviderKind::WireGuardNt,
            value: "Nelomai WG".into()
        })
    );
    let (wintun, wireguard) = private_names(Some((18, bytes("Nelomai VIP\0"))), None).unwrap();
    assert_eq!(wintun.unwrap().kind, ProviderKind::Wintun);
    assert_eq!(wireguard, None);
    assert_eq!(private_names(None, None), Ok((None, None)));
    for kind in [0, 1, 7, 16, 0x2012, u32::MAX] {
        for wg in [false, true] {
            let raw = Some((kind, bytes("Name\0")));
            assert!(if wg {
                private_names(None, raw)
            } else {
                private_names(raw, None)
            }
            .is_err());
        }
    }
    for raw in [
        vec![],
        vec![65],
        bytes("\0"),
        bytes("Name"),
        bytes("A\0B\0"),
        vec![0, 0xd8, 0, 0],
        vec![0; 65538],
    ] {
        for wg in [false, true] {
            let raw = Some((18, raw.clone()));
            assert!(if wg {
                private_names(None, raw)
            } else {
                private_names(raw, None)
            }
            .is_err());
        }
    }
}

#[test]
fn mixed_expected_kind_is_required_and_cannot_crossbind_private_names() {
    // Break: using an automatic provider classifier in place of expected kind.
    for member in 0..3 {
        let (mut wants, mut q) = mixed_fixture();
        wants[member].kind = if member == 1 {
            ProviderKind::Wintun
        } else {
            ProviderKind::WireGuardNt
        };
        assert!(inspect_mixed_queries(&wants, &mut q).is_err());
    }
    for field in 0..6 {
        let (wants, mut q) = mixed_fixture();
        for nodes in &mut q.source.nodes {
            let d = &mut nodes[3];
            match field {
                0 => d.wireguard_name = None,
                1 => d.wireguard_name.as_mut().unwrap().value.clear(),
                2 => d.wireguard_name.as_mut().unwrap().value = "Nelomai AWG".into(),
                3 => d.wireguard_name.as_mut().unwrap().kind = ProviderKind::Wintun,
                4 => d.name = "Nelomai WG".into(), // Even equal dual names deny.
                _ => {
                    d.name = d.wireguard_name.take().unwrap().value;
                }
            }
        }
        assert!(
            inspect_mixed_queries(&wants, &mut q).is_err(),
            "field {field}"
        );
    }
    for member in [2, 4] {
        let (wants, mut q) = mixed_fixture();
        for nodes in &mut q.source.nodes {
            nodes[member].wireguard_name = Some(PrivateName {
                kind: ProviderKind::WireGuardNt,
                value: nodes[member].name.clone(),
            });
        }
        assert!(inspect_mixed_queries(&wants, &mut q).is_err());
    }
}

#[test]
fn mixed_wireguard_closed_metadata_rejects_wrong_egos_versions_dates_and_states() {
    // Break: admitting a same-GUID node under only partial provider metadata.
    for phase in 0..2 {
        for field in 0..25 {
            let (wants, mut q) = mixed_fixture();
            let d = &mut q.source.nodes[phase][3];
            match field {
                0 => d.instance = "ROOT\\WireGuard\\0001".into(),
                1 => d.instance = format!("SWD\\Wintun\\{}", d.netcfg_instance_id),
                2 => d.instance = "SWD\\WireGuard\\{12345678-9abc-def0-8123-456789abcdef}".into(),
                3 => d.netcfg_instance_id = GUID_TEXT.into(),
                4 => d.hardware_ids = vec!["Wintun".into()],
                5 => d.hardware_ids.push("WireGuard".into()),
                6 => d.compatible_ids.clear(),
                7 => d.compatible_ids.push("SWD\\GenericRaw".into()),
                8 => d.service = "Wintun".into(),
                9 => d.driver.provider = "Other vendor".into(),
                10 => d.driver.provider = "WireGuard LLC Extra".into(),
                11 => d.driver.version = "1.1.1.0".into(),
                12 => d.driver.version = "0.14.0.0".into(),
                13 => d.driver.date_filetime += 1,
                14 => d.driver.matching_device_id = "Wintun".into(),
                15 => d.driver.inf = "path\\oem43.inf".into(),
                16 => d.driver.driver_key.clear(),
                17 => d.net_luid_index += 1,
                18 => d.if_type = 6,
                19 => d.class_guid = [7; 16],
                20 => d.devinst = 0,
                21 => d.description = "Unrequested Tunnel".into(),
                22 => {
                    d.presence = Presence::Phantom;
                    d.status = 0;
                }
                23 => d.problem = 22,
                _ => d.status = 0,
            }
            // Stable malformed facts must deny independently of changed reads.
            q.source.nodes[1 - phase] = q.source.nodes[phase].clone();
            assert!(
                inspect_mixed_queries(&wants, &mut q).is_err(),
                "{phase}/{field}"
            );
        }
        for flag in [0x20, 0x400, 0x8000, 0x40000, 0x400000, 0x80000000] {
            let (wants, mut q) = mixed_fixture();
            for nodes in &mut q.source.nodes {
                nodes[3].status |= flag;
            }
            assert!(
                inspect_mixed_queries(&wants, &mut q).is_err(),
                "flag {flag:x}"
            );
        }
    }
}

#[test]
fn mixed_unknown_extra_missing_or_reused_interfaces_and_devices_cannot_be_hidden() {
    // Break: dropping extra related nodes/rows or replacing index/GUID bindings.
    for field in 0..8 {
        let (wants, mut q) = mixed_fixture();
        for nodes in &mut q.source.nodes {
            match field {
                0 => {
                    nodes.remove(3);
                }
                1 => nodes.push(nodes[3].clone()),
                2 => nodes[0].standard_name = Some("Nelomai WG".into()),
                3 => {
                    nodes[0].wireguard_name = Some(PrivateName {
                        kind: ProviderKind::WireGuardNt,
                        value: "Unknown".into(),
                    })
                }
                4 => nodes[0].hardware_ids.push("AmneziaWG".into()),
                5 => nodes[0].netcfg_instance_id = nodes[3].netcfg_instance_id.clone(),
                6 => nodes[0].devinst = nodes[3].devinst,
                _ => nodes[0].driver.provider = "WireGuard LLC".into(),
            }
        }
        assert!(
            inspect_mixed_queries(&wants, &mut q).is_err(),
            "field {field}"
        );
    }
    for field in 0..6 {
        let (wants, mut q) = mixed_fixture();
        for read in &mut q.reads {
            let mut extra = read.interfaces[8].clone();
            extra.identity.guid = [7; 16];
            extra.identity.index = 200;
            extra.identity.luid = (53 << 48) | (200 << 24);
            extra.identity.name = "Unknown".into();
            match field {
                0 => read.interfaces.push(extra),
                1 => {
                    read.interfaces.remove(8);
                }
                2 => read.interfaces[0].identity.index = wants[1].identity.index,
                3 => read.interfaces[0].identity.luid = wants[1].identity.luid,
                4 => read.interfaces[0].identity.name = wants[1].identity.name.clone(),
                _ => read.interfaces[0].identity.guid = wants[1].identity.guid,
            }
        }
        assert!(
            inspect_mixed_queries(&wants, &mut q).is_err(),
            "MIB {field}"
        );
    }
}

#[test]
fn mixed_extra_current_version_wireguard_is_never_a_foreign_exemption() {
    // Break: a fourth complete, current-version WG node becomes foreign.
    let (wants, mut q) = mixed_fixture();
    let mut node = q.source.nodes[0][3].clone();
    node.devinst = 999;
    node.netcfg_instance_id = "{00000000-0000-0000-0000-000000000001}".into();
    node.instance = format!("SWD\\WireGuard\\{}", node.netcfg_instance_id);
    node.net_luid_index = 999;
    node.wireguard_name.as_mut().unwrap().value = "Extra WG".into();
    let mut row = q.reads[1].by_luid.clone();
    row.identity.guid = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    row.identity.index = 999;
    row.identity.luid = (53 << 48) | (999 << 24);
    row.identity.name = "Extra WG".into();
    for nodes in &mut q.source.nodes {
        nodes.push(node.clone());
    }
    for read in &mut q.reads {
        read.interfaces.push(row.clone());
    }
    assert!(inspect_mixed_queries(&wants, &mut q).is_err());
}

#[test]
fn mixed_each_target_read_and_full_snapshot_must_agree_before_and_after() {
    // Break: comparing only target rows while ignoring per-target full tables.
    for read in 0..6 {
        let (wants, mut q) = mixed_fixture();
        q.reads[read].interfaces[0].identity.description = "Changed foreign description".into();
        assert_eq!(
            inspect_mixed_queries(&wants, &mut q),
            Err(Error::Changed),
            "read {read}"
        );
        for key in 0..3 {
            let (wants, mut q) = mixed_fixture();
            let row = match key {
                0 => &mut q.reads[read].by_luid,
                1 => &mut q.reads[read].by_index,
                _ => &mut q.reads[read].by_guid,
            };
            row.identity.index += 100;
            assert!(inspect_mixed_queries(&wants, &mut q).is_err());
        }
    }
    for field in 0..8 {
        let (wants, mut q) = mixed_fixture();
        let d = &mut q.source.nodes[1][3];
        match field {
            0 => d.driver.inf = "oem99.inf".into(),
            1 => d.driver.driver_key = "{4d36e972-e325-11ce-bfc1-08002be10318}\\0099".into(),
            2 => d.devinst += 100,
            3 => d.status ^= 0x2000,
            4 => d.instance = d.instance.to_ascii_uppercase(),
            5 => d.hardware_ids[0] = "WIREGUARD".into(),
            6 => d.service = "WIREGUARD".into(),
            _ => d.driver.matching_device_id = "WIREGUARD".into(),
        }
        assert_eq!(
            inspect_mixed_queries(&wants, &mut q),
            Err(Error::Changed),
            "field {field}"
        );
    }
    let (wants, mut q) = mixed_fixture();
    q.source.stacks[1].pop();
    assert!(inspect_mixed_queries(&wants, &mut q).is_err());
    // An otherwise valid graph change is a Changed reading too.
    let (wants, mut q) = mixed_fixture();
    q.source.stacks[1][1].lower = 24;
    assert_eq!(inspect_mixed_queries(&wants, &mut q), Err(Error::Changed));
}

#[test]
fn mixed_filters_cannot_derive_foreign_allowance_from_expected_wireguard() {
    let (wants, mut q) = mixed_fixture();
    for edges in &mut q.source.stacks {
        edges[0].lower = wants[1].identity.index;
    }
    assert!(inspect_mixed_queries(&wants, &mut q).is_err());
}

#[test]
fn old_wintun_api_never_hides_untracked_wireguard_or_awg() {
    // Break: old caller presents only C and the observer treats WG as foreign.
    let (wants, mut q) = mixed_fixture();
    q.reads = vec![q.reads[0].clone(), q.reads[3].clone()];
    assert!(inspect_all_queries(&[wants[0].identity.clone()], &mut q).is_err());
    for phase in 0..2 {
        let (wants, q) = mixed_fixture();
        let mut empty = AbsenceScript::empty();
        empty.tables[phase] = vec![q.reads[1].by_luid.clone()];
        empty.nodes[phase] = vec![q.source.nodes[phase][3].clone()];
        assert!(inspect_all_queries(&[], &mut empty).is_err());
        let mut empty = AbsenceScript::empty();
        empty.tables[phase] = vec![q.reads[1].by_luid.clone()];
        empty.nodes[phase] = vec![q.source.nodes[phase][3].clone()];
        assert!(inspect_absent_queries(&target(&wants[0].identity), &mut empty).is_err());
    }
}

#[test]
fn mixed_bound_alias_and_every_os_boundary_failure_fail_without_default_success() {
    let (wants, q) = mixed_fixture();
    for n in 1..=10 {
        let (_, mut q) = mixed_fixture();
        q.source.fail = Some(n);
        assert_eq!(
            inspect_mixed_queries(&wants, &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.source.events.len(), n);
    }
    for invalid in [vec![wants[0].clone(); 4], vec![wants[0].clone(); 2]] {
        let (_, mut q) = mixed_fixture();
        assert!(inspect_mixed_queries(&invalid, &mut q).is_err());
        assert!(q.source.events.is_empty());
    }
    let mut q = q;
    let got = inspect_mixed_queries(&wants, &mut q).unwrap();
    assert_eq!(got.len(), 3);
    assert_eq!(
        q.source.events,
        [
            "interfaces",
            "interfaces",
            "interfaces",
            "snapshot",
            "stack",
            "snapshot",
            "interfaces",
            "interfaces",
            "interfaces",
            "stack"
        ]
    );
    let mut q = AbsenceScript::empty();
    assert_eq!(inspect_mixed_queries(&[], &mut q), Ok(vec![]));
    assert_eq!(
        q.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
}

#[test]
fn mixed_order_and_windows_description_disambiguation_preserve_actual_observations() {
    let (mut wants, mut q) = mixed_fixture();
    wants.swap(0, 2);
    q.reads.swap(0, 2);
    q.reads.swap(3, 5);
    // PnP requested description remains unsuffixed, actual MIB #2 is retained.
    wants[1].identity.description = "Nelomai WG Tunnel #2".into();
    for read in &mut q.reads {
        read.interfaces[8].identity.description = "Nelomai WG Tunnel #2".into();
    }
    for read in [1, 4] {
        q.reads[read].by_luid.identity.description = "Nelomai WG Tunnel #2".into();
        q.reads[read].by_index.identity.description = "Nelomai WG Tunnel #2".into();
        q.reads[read].by_guid.identity.description = "Nelomai WG Tunnel #2".into();
    }
    let got = inspect_mixed_queries(&wants, &mut q).unwrap();
    assert_eq!(
        got.iter()
            .map(|o| o.interface.name.as_str())
            .collect::<Vec<_>>(),
        ["Nelomai AWG", "Nelomai WG", "Nelomai VIP"]
    );
    assert_eq!(got[1].interface.description, "Nelomai WG Tunnel #2");
    assert_eq!(got[1].instance.description, "Nelomai WG Tunnel");
}

#[test]
fn zero_input_cannot_explain_wireguard_text_as_an_unrelated_foreign_provider() {
    // Break: treating WireGuard/AWG signals on a non-type53 foreign node/row
    // as an independently explained foreign allowance. Both reads must deny.
    for phase in 0..2 {
        for signal in ["WireGuard", "AmneziaWG", "AWG"] {
            for field in 0..4 {
                let mut q = foreign_query(false);
                for rows in &mut q.tables {
                    for row in rows {
                        row.identity.if_type = 6;
                        row.identity.luid = (6 << 48) | (row.identity.luid & 0x0000_ffff_ffff_ffff);
                    }
                }
                for nodes in &mut q.nodes {
                    for d in nodes {
                        d.if_type = 6;
                    }
                }
                match field {
                    0 => q.nodes[phase][0].description = format!("{signal} adapter"),
                    1 => q.nodes[phase][0].service = signal.into(),
                    2 => q.tables[phase][0].identity.description = format!("{signal} adapter"),
                    _ => {
                        q.nodes[phase][0].hardware_ids = vec![signal.into()];
                        q.nodes[phase][0].driver.matching_device_id = signal.into();
                    }
                }
                q.nodes[1 - phase] = q.nodes[phase].clone();
                q.tables[1 - phase] = q.tables[phase].clone();
                assert!(
                    inspect_all_queries(&[], &mut q).is_err(),
                    "{signal}/{phase}/{field}"
                );
            }
        }
    }
}

// Literal MIB identities measured on 01Oct. PnP metadata below is synthetic:
// actual foreign PnP facts have not been collected by this code agent.
fn measured_foreign_bases() -> Vec<Interface> {
    vec![
        Interface {
            identity: Expected {
                guid: [
                    0xde, 0x71, 0x50, 0xbd, 0x36, 0x75, 0x4f, 0xc7, 0xab, 0xb5, 0x5d, 0x8a, 0x80,
                    0x9e, 0x34, 0x32,
                ],
                luid: 14_918_723_521_478_656,
                index: 24,
                name: "VPN - VPN Client".into(),
                description: "VPN Client Adapter - VPN".into(),
                if_type: 53,
                tunnel_type: 0,
            },
            role_flags: 16,
        },
        Interface {
            identity: Expected {
                guid: [
                    0x9a, 0xca, 0xea, 0x0b, 0x7f, 0x04, 0x4b, 0xe3, 0x8e, 0x88, 0x6b, 0x06, 0x69,
                    0x81, 0xcc, 0x0d,
                ],
                luid: 14_918_723_555_033_088,
                index: 19,
                name: "Подключение по локальной сети 2".into(),
                description: "WireSock Virtual Adapter".into(),
                if_type: 53,
                tunnel_type: 0,
            },
            role_flags: 16,
        },
    ]
}
fn foreign_nodes() -> Vec<Device> {
    measured_foreign_bases()
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let mut d = observed().devices.remove(0);
            d.instance = format!("ROOT\\FOREIGN\\{i:04}");
            d.devinst = 500 + i as u32;
            d.hardware_ids = vec![format!("SyntheticForeign{i}")];
            d.compatible_ids = vec![]; // Explicit queried absence in the fixture.
            d.service = format!("ForeignService{i}");
            d.name.clear(); // No private WintunName property.
            d.description = row.identity.description.clone();
            d.netcfg_instance_id = if i == 0 {
                "{de7150bd-3675-4fc7-abb5-5d8a809e3432}"
            } else {
                "{9acaea0b-7f04-4be3-8e88-6b066981cc0d}"
            }
            .into();
            d.net_luid_index = ((row.identity.luid >> 24) & 0xff_ffff) as u32;
            d.driver.provider = "Synthetic foreign vendor".into();
            d.driver.version = "1.2.3.4".into();
            d.driver.matching_device_id = d.hardware_ids[0].clone();
            d.driver.driver_key =
                format!("{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{:04}", 100 + i);
            d
        })
        .collect()
}

#[test]
fn full_foreign_pnp_crossbinding_explains_measured_type53_bases_for_zero_input() {
    // Break caught: rejecting independently crossbound non-Wintun bases solely
    // because MIB Type=53. No type/name exemption can satisfy the orphan tests.
    let mut q = AbsenceScript::empty();
    q.tables = [measured_foreign_bases(), measured_foreign_bases()];
    q.nodes = [foreign_nodes(), foreign_nodes()];
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
}

#[test]
fn full_foreign_pnp_crossbinding_coexists_with_strict_owned_original() {
    let mut q = Universe {
        rows: vec![observed()],
        calls: 0,
        extra: false,
    };
    q.rows[0].interfaces.extend(measured_foreign_bases());
    q.rows[0].devices.extend(foreign_nodes());
    let got = inspect_all_queries(std::slice::from_ref(&expected()), &mut q)
        .unwrap()
        .remove(0);
    assert_eq!(
        got.instance.instance,
        "SWD\\WINTUN\\{12345678-9ABC-DEF0-8123-456789ABCDEF}"
    );
}
#[test]
fn multi_original_reads_must_agree_on_the_complete_foreign_interface_facts() {
    let mut q = universe();
    q.rows[0].devices.extend(foreign_nodes());
    for seen in &mut q.rows {
        seen.interfaces.extend(measured_foreign_bases());
    }
    // Each per-target pair is individually stable, but the complete tables
    // disagree within the same before/after universe observation.
    q.rows[1].interfaces[2].identity.description = "Different foreign description".into();
    let wants = q
        .rows
        .iter()
        .map(|r| r.by_luid.identity.clone())
        .collect::<Vec<_>>();
    assert_eq!(inspect_all_queries(&wants, &mut q), Err(Error::Changed));
}

fn measured_filters() -> Vec<Interface> {
    // Entire identities from main's GetIfTable2 output, not a name whitelist.
    let values = [
        (
            36,
            14_918_173_765_664_768,
            [
                0x11, 0x2f, 0x9a, 0x1e, 0xbd, 0x24, 0x11, 0xf1, 0x98, 0x16, 0x80, 0x6e, 0x6f, 0x6e,
                0x69, 0x63,
            ],
            "VPN - VPN Client-WFP Native MAC Layer LightWeight Filter-0000",
            "VPN Client Adapter - VPN-WFP Native MAC Layer LightWeight Filter-0000",
        ),
        (
            37,
            14_918_173_782_441_984,
            [
                0xce, 0x94, 0xce, 0xac, 0x38, 0xc7, 0x11, 0xf1, 0x97, 0xcc, 0x88, 0xd8, 0x2e, 0xec,
                0xb5, 0xc5,
            ],
            "VPN - VPN Client-WireSock VPN Client Filter Driver-0000",
            "VPN Client Adapter - VPN-WireSock VPN Client Filter Driver-0000",
        ),
        (
            38,
            14_918_173_799_219_200,
            [
                0x11, 0x2f, 0x9a, 0x1f, 0xbd, 0x24, 0x11, 0xf1, 0x98, 0x16, 0x80, 0x6e, 0x6f, 0x6e,
                0x69, 0x63,
            ],
            "VPN - VPN Client-QoS Packet Scheduler-0000",
            "VPN Client Adapter - VPN-QoS Packet Scheduler-0000",
        ),
        (
            39,
            14_918_173_815_996_416,
            [
                0x11, 0x2f, 0x9a, 0x20, 0xbd, 0x24, 0x11, 0xf1, 0x98, 0x16, 0x80, 0x6e, 0x6f, 0x6e,
                0x69, 0x63,
            ],
            "VPN - VPN Client-WFP 802.3 MAC Layer LightWeight Filter-0000",
            "VPN Client Adapter - VPN-WFP 802.3 MAC Layer LightWeight Filter-0000",
        ),
        (
            41,
            14_918_173_832_773_632,
            [
                0xce, 0x94, 0xce, 0xcc, 0x38, 0xc7, 0x11, 0xf1, 0x97, 0xcc, 0x88, 0xd8, 0x2e, 0xec,
                0xb5, 0xc5,
            ],
            "Подключение по локальной сети 2-WireSock VPN Client Filter Driver-0000",
            "WireSock Virtual Adapter-WireSock VPN Client Filter Driver-0000",
        ),
    ];
    values
        .into_iter()
        .map(|(index, luid, guid, name, description)| Interface {
            identity: Expected {
                index,
                luid,
                guid,
                name: name.into(),
                description: description.into(),
                if_type: 53,
                tunnel_type: 0,
            },
            role_flags: 18,
        })
        .collect()
}
fn measured_stack() -> Vec<StackEdge> {
    vec![
        StackEdge {
            higher: 36,
            lower: 24,
        },
        StackEdge {
            higher: 37,
            lower: 36,
        },
        StackEdge {
            higher: 38,
            lower: 37,
        },
        StackEdge {
            higher: 39,
            lower: 38,
        },
        StackEdge {
            higher: 41,
            lower: 19,
        },
    ]
}
fn foreign_query(filters: bool) -> AbsenceScript {
    let mut q = AbsenceScript::empty();
    let mut rows = measured_foreign_bases();
    if filters {
        rows.extend(measured_filters());
    }
    q.tables = [rows.clone(), rows];
    q.nodes = [foreign_nodes(), foreign_nodes()];
    if filters {
        q.stacks = [measured_stack(), measured_stack()];
    }
    q
}
#[test]
fn literal_measured_filter_chain_requires_complete_native_foreign_base_evidence() {
    let mut q = foreign_query(true);
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
    assert_eq!(
        q.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
    assert_eq!(q.requested_targets, [vec![], vec![]]);
}
#[test]
fn foreign_mib_wintun_text_never_bypasses_related_denial_by_crossbound_guid() {
    for phase in 0..2 {
        for description in [false, true] {
            let mut q = foreign_query(false);
            if description {
                q.tables[phase][0].identity.description = "Wintun Tunnel".into();
            } else {
                q.tables[phase][0].identity.name = "Wintun".into();
            }
            q.tables[1 - phase] = q.tables[phase].clone(); // Stable forbidden text, not just Changed.
            assert!(inspect_all_queries(&[], &mut q).is_err());
        }
    }
}
#[test]
fn filter_lineage_rejects_orphans_cycles_aliases_role_and_type_changes() {
    for phase in 0..2 {
        for kind in 0..12 {
            let mut q = foreign_query(true);
            match kind {
                0 => q.stacks[phase].clear(),
                1 => {
                    q.stacks[phase].remove(1);
                }
                2 => q.stacks[phase][0].lower = 999,
                3 => q.stacks[phase][1].lower = 39,
                4 => q.stacks[phase].push(StackEdge {
                    higher: 36,
                    lower: 19,
                }),
                5 => q.stacks[phase].push(q.stacks[phase][0]),
                6 => q.tables[phase][2].role_flags = 16,
                7 => q.tables[phase][2].role_flags |= 1,
                8 => q.tables[phase][2].role_flags |= 0x80,
                9 => {
                    q.tables[phase][2].identity.if_type = 6;
                    q.tables[phase][2].identity.luid = (6 << 48) | (20 << 24);
                }
                10 => q.tables[phase][2].identity.tunnel_type = 1,
                _ => q.tables[phase][2].identity.name = "Wintun filter".into(),
            }
            // A stable bad graph/role must also deny, rather than only churn.
            q.tables[1 - phase] = q.tables[phase].clone();
            q.stacks[1 - phase] = q.stacks[phase].clone();
            assert!(
                inspect_all_queries(&[], &mut q).is_err(),
                "phase {phase} kind {kind}"
            );
        }
    }
}
#[test]
fn filter_cannot_derive_foreign_permission_from_an_owned_wintun_base() {
    let mut q = foreign_query(true);
    let own = observed();
    for phase in 0..2 {
        q.tables[phase].push(own.by_luid.clone());
        q.nodes[phase].extend(own.devices.clone());
        q.stacks[phase][0].lower = 17;
    }
    // Exact absence may coexist with an original, but its filters are never
    // negative evidence for a foreign provider.
    assert!(inspect_absent_queries(
        &AbsenceTarget {
            guid: [8; 16],
            name: "other".into()
        },
        &mut q
    )
    .is_err());
}
#[test]
fn stable_alternate_stack_is_valid_but_a_changed_stack_is_not_stable_evidence() {
    let mut q = foreign_query(true);
    q.stacks[1][0].lower = 19; // Both foreign bases have the same measured type.
    assert_eq!(inspect_all_queries(&[], &mut q), Err(Error::Changed));
    q = foreign_query(true);
    q.stacks[0][0].lower = 19;
    q.stacks[1] = q.stacks[0].clone();
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
}
#[test]
fn foreign_crossbinding_requires_metadata_and_exact_rows_but_live_state_only_for_type53() {
    // Break: an unrelated non-tunnel PnP problem or absent MIB row blocks
    // the empty, target-absence, or live owned provider census.
    for missing_row in [false, true] {
        for census in 0..3 {
            let mut q = foreign_query(false);
            for phase in 0..2 {
                let d = &mut q.nodes[phase][0];
                d.if_type = 6;
                d.status = 2;
                d.problem = 31;
                if missing_row {
                    q.tables[phase].remove(0);
                } else {
                    q.tables[phase][0].identity.if_type = 6;
                    q.tables[phase][0].identity.luid =
                        (6 << 48) | (u64::from(d.net_luid_index) << 24);
                }
            }
            match census {
                0 => assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![])),
                1 => assert_eq!(inspect_absent_queries(&absence_target(), &mut q), Ok(())),
                _ => {
                    for phase in 0..2 {
                        q.tables[phase].extend(observed().interfaces);
                        q.nodes[phase].extend(observed().devices);
                    }
                    let got = inspect_all_queries(
                        std::slice::from_ref(&expected()),
                        &mut FullQueries { source: q },
                    )
                    .unwrap()
                    .remove(0);
                    assert_eq!(got.instance.name, "Nelomai VIP");
                }
            }
        }
    }
    // Missing MIB never excuses malformed metadata, provider signals, or
    // a target GUID collision on the unrelated non-tunnel branch.
    for field in 0..3 {
        let mut q = foreign_query(false);
        for phase in 0..2 {
            q.tables[phase].remove(0);
            let d = &mut q.nodes[phase][0];
            d.if_type = 6;
            d.status = 2;
            d.problem = 31;
            match field {
                0 => d.driver.version.clear(),
                1 => d.hardware_ids.push("Wintun".into()),
                _ => d.netcfg_instance_id = GUID_TEXT.into(),
            }
        }
        assert!(
            inspect_absent_queries(&absence_target(), &mut q).is_err(),
            "missing MIB field {field}"
        );
    }
    for phase in 0..2 {
        for field in 0..24 {
            let mut q = foreign_query(false);
            let d = &mut q.nodes[phase][0];
            match field {
                0 => d.netcfg_instance_id = "bad".into(),
                1 => d.net_luid_index += 1,
                2 => d.if_type = 6,
                3 => d.class_guid = [1; 16],
                4 => d.hardware_ids.clear(),
                5 => d.service.clear(),
                6 => d.driver.provider.clear(),
                7 => d.driver.version.clear(),
                8 => d.driver.date_filetime = 0,
                9 => d.driver.inf.clear(),
                10 => d.driver.driver_key.clear(),
                11 => d.driver.matching_device_id = "Other".into(),
                12 => d.devinst = 0,
                13 => d.instance.clear(),
                14 => d.description.clear(),
                15 => d.status = 2,
                16 => d.problem = 22,
                17 => d.status |= 0x40000,
                18 => d.net_luid_index = 0,
                19 => d.net_luid_index = 0x1000000,
                20 => d.standard_name = Some("bad\0".into()),
                21 => d.compatible_ids = vec!["bad\0".into()],
                22 => d.driver.inf = "../evil.inf".into(),
                _ => d.hardware_ids[0].clear(),
            }
            assert!(
                inspect_all_queries(&[], &mut q).is_err(),
                "phase {phase} field {field}"
            );
        }
    }
}
#[test]
fn foreign_orphan_same_guid_alias_and_missing_complete_query_fail_closed() {
    for phase in 0..2 {
        for kind in 0..5 {
            let mut q = foreign_query(false);
            match kind {
                0 => q.nodes[phase].clear(),
                1 => q.tables[phase].clear(),
                2 => q.nodes[phase].push(q.nodes[phase][0].clone()),
                3 => {
                    q.nodes[phase][1].netcfg_instance_id =
                        q.nodes[phase][0].netcfg_instance_id.clone()
                }
                _ => q.tables[phase][1].identity.guid = q.tables[phase][0].identity.guid,
            }
            assert!(inspect_all_queries(&[], &mut q).is_err());
        }
    }
}
#[test]
fn foreign_related_signals_never_turn_into_an_allowance() {
    for phase in 0..2 {
        for field in 0..9 {
            let mut q = foreign_query(false);
            let d = &mut q.nodes[phase][0];
            match field {
                0 => d.instance = "SWD\\Wintun\\x".into(),
                1 => d.instance = "ROOT\\WINTUN\\x".into(),
                2 => d.hardware_ids.push("Wintun".into()),
                3 => d.compatible_ids.push("Wintun".into()),
                4 => d.service = "Wintun".into(),
                5 => d.name = "Foreign private WintunName".into(),
                6 => d.driver.matching_device_id = "Wintun".into(),
                7 => d.driver.provider = "WireGuard LLC".into(),
                _ => d.description = "Wintun".into(),
            }
            assert!(inspect_all_queries(&[], &mut q).is_err());
        }
    }
}
#[test]
fn changed_valid_foreign_metadata_is_not_a_stable_negative_observation() {
    for field in 0..6 {
        let mut q = foreign_query(false);
        let d = &mut q.nodes[1][0];
        match field {
            0 => d.driver.provider = "Another vendor".into(),
            1 => d.driver.version = "2.0.0.0".into(),
            2 => d.driver.inf = "oem43.inf".into(),
            3 => d.devinst += 100,
            4 => d.standard_name = Some("Another friendly name".into()),
            _ => d.status ^= 0x2000,
        }
        assert_eq!(inspect_all_queries(&[], &mut q), Err(Error::Changed));
    }
}
#[test]
fn standard_pnp_wintun_text_is_negative_evidence_even_without_targets() {
    let mut q = foreign_query(false);
    for nodes in &mut q.nodes {
        nodes[0].standard_name = Some("Foreign Wintun adapter".into());
    }
    assert!(inspect_all_queries(&[], &mut q).is_err());
}

struct FullQueries {
    source: AbsenceScript,
}
impl Queries for FullQueries {
    fn interfaces(&mut self, want: &Expected) -> Result<Observed> {
        self.source.event("interfaces")?;
        let rows = self.source.tables[self.source.table_reads].clone();
        self.source.table_reads += 1;
        let row = rows
            .iter()
            .find(|r| r.identity == *want)
            .cloned()
            .ok_or(Error::Native("full fixture interface lookup", 1168))?;
        Ok(Observed {
            by_luid: row.clone(),
            by_index: row.clone(),
            by_guid: row,
            interfaces: rows,
            devices: vec![],
        })
    }
    fn table(&mut self) -> Result<Vec<Interface>> {
        self.source.table()
    }
    fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
        self.source.device_snapshot(targets)
    }
    fn stack(&mut self) -> Result<Vec<StackEdge>> {
        self.source.stack()
    }
}
fn owned_foreign_query() -> FullQueries {
    let mut q = foreign_query(true);
    for phase in 0..2 {
        q.tables[phase].extend(observed().interfaces);
        q.nodes[phase].extend(observed().devices);
    }
    FullQueries { source: q }
}
#[test]
fn full_owned_query_explains_foreign_filters_and_preserves_every_original_predicate() {
    let mut q = owned_foreign_query();
    let got = inspect_all_queries(std::slice::from_ref(&expected()), &mut q)
        .unwrap()
        .remove(0);
    assert_eq!(got.instance.driver.provider, "WireGuard LLC");
    assert_eq!(got.instance.name, "Nelomai VIP");
    assert_eq!(
        q.source.events,
        [
            "interfaces",
            "snapshot",
            "stack",
            "snapshot",
            "interfaces",
            "stack"
        ]
    );
    assert_eq!(
        q.source.requested_targets,
        [vec![absence_target()], vec![absence_target()]]
    );
    for field in 0..7 {
        let mut q = owned_foreign_query();
        for phase in 0..2 {
            let d = &mut q.source.nodes[phase][2];
            match field {
                0 => d.driver.provider = "Foreign vendor".into(),
                1 => d.hardware_ids = vec!["Foreign".into()],
                2 => d.compatible_ids.clear(),
                3 => d.name = "Other".into(),
                4 => d.instance = "ROOT\\WINTUN\\0001".into(),
                5 => d.status = 0,
                _ => d.net_luid_index += 1,
            }
        }
        assert!(
            inspect_all_queries(std::slice::from_ref(&expected()), &mut q).is_err(),
            "field {field}"
        );
    }
}
#[test]
fn full_owned_query_rejects_foreign_guid_name_reuse_and_filters_on_original() {
    for field in 0..4 {
        let mut q = owned_foreign_query();
        for phase in 0..2 {
            match field {
                0 => q.source.nodes[phase][0].netcfg_instance_id = GUID_TEXT.into(),
                1 => q.source.nodes[phase][0].standard_name = Some("nelomai vip".into()),
                2 => q.source.tables[phase][0].identity.name = "nelomai vip".into(),
                _ => q.source.stacks[phase][0].lower = 17,
            }
        }
        assert!(
            inspect_all_queries(std::slice::from_ref(&expected()), &mut q).is_err(),
            "field {field}"
        );
    }
}
#[test]
fn every_full_foreign_query_error_propagates_in_empty_absence_and_owned_paths() {
    for n in 1..=6 {
        let mut q = foreign_query(true);
        q.fail = Some(n);
        assert_eq!(
            inspect_all_queries(&[], &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.events.len(), n);
        let mut q = foreign_query(true);
        q.fail = Some(n);
        assert_eq!(
            inspect_absent_queries(&absence_target(), &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.events.len(), n);
        let mut q = owned_foreign_query();
        q.source.fail = Some(n);
        assert_eq!(
            inspect_all_queries(std::slice::from_ref(&expected()), &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.source.events.len(), n);
    }
}
#[test]
fn missing_full_snapshot_or_stack_query_never_defaults_to_success() {
    struct MissingQuery {
        source: AbsenceScript,
        missing_snapshot: bool,
    }
    impl Queries for MissingQuery {
        fn interfaces(&mut self, _: &Expected) -> Result<Observed> {
            panic!("empty input")
        }
        fn table(&mut self) -> Result<Vec<Interface>> {
            self.source.table()
        }
        fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
            if self.missing_snapshot {
                Err(Error::Invalid("missing full snapshot"))
            } else {
                self.source.device_snapshot(targets)
            }
        }
        fn stack(&mut self) -> Result<Vec<StackEdge>> {
            Err(Error::Invalid("missing stack query"))
        }
    }
    for missing_snapshot in [false, true] {
        let mut q = MissingQuery {
            source: foreign_query(true),
            missing_snapshot,
        };
        assert!(inspect_all_queries(&[], &mut q).is_err());
    }
}
#[test]
fn full_foreign_snapshot_and_graph_bounds_never_truncate_into_success() {
    for phase in 0..2 {
        let mut q = foreign_query(true);
        q.stacks[phase] = vec![
            StackEdge {
                higher: 36,
                lower: 24
            };
            4097
        ];
        assert_eq!(
            inspect_all_queries(&[], &mut q),
            Err(Error::Invalid("stack table bound"))
        );
        let mut q = foreign_query(true);
        q.nodes[phase] = vec![foreign_nodes().remove(0); 4097];
        assert_eq!(
            inspect_all_queries(&[], &mut q),
            Err(Error::Invalid("device snapshot bound"))
        );
    }
}
#[test]
fn complete_4096_row_filter_graph_accepts_and_missing_last_edge_denies() {
    let mut q = AbsenceScript::empty();
    let base = measured_foreign_bases().remove(0);
    let mut rows = vec![base];
    let mut edges = vec![];
    let mut lower = 24;
    for i in 0..4095u32 {
        let mut row = measured_filters().remove(0);
        row.identity.guid = u128::from(i + 1).to_be_bytes();
        row.identity.index = 100 + i;
        row.identity.luid = (53 << 48) | (u64::from(i + 1) << 24);
        row.identity.name = format!("Synthetic filter {i}");
        edges.push(StackEdge {
            higher: row.identity.index,
            lower,
        });
        lower = row.identity.index;
        rows.push(row);
    }
    q.tables = [rows.clone(), rows];
    q.nodes = [
        vec![foreign_nodes().remove(0)],
        vec![foreign_nodes().remove(0)],
    ];
    q.stacks = [edges.clone(), edges];
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
    q.events.clear();
    q.table_reads = 0;
    q.device_reads = 0;
    q.stack_reads = 0;
    q.stacks[0].pop();
    q.stacks[1] = q.stacks[0].clone();
    assert!(inspect_all_queries(&[], &mut q).is_err());
}
#[test]
fn complete_4096_node_foreign_snapshot_accepts_but_an_unexplained_last_row_denies() {
    let mut q = AbsenceScript::empty();
    let template = foreign_nodes().remove(0);
    let mut rows = vec![];
    let mut nodes = vec![];
    for i in 1..=4096u32 {
        let mut row = measured_foreign_bases().remove(0);
        row.identity.guid = u128::from(i).to_be_bytes();
        row.identity.index = i;
        row.identity.luid = (53 << 48) | (u64::from(i) << 24);
        row.identity.name = format!("Synthetic foreign interface {i}");
        let mut node = template.clone();
        node.instance = format!("ROOT\\FOREIGN\\{i:04}");
        node.devinst = i;
        node.netcfg_instance_id = format!("{{00000000-0000-0000-0000-{i:012x}}}");
        node.net_luid_index = i;
        node.driver.driver_key = format!("{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{:04}", i - 1);
        rows.push(row);
        nodes.push(node);
    }
    q.tables = [rows.clone(), rows];
    q.nodes = [nodes.clone(), nodes];
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
    q.events.clear();
    q.table_reads = 0;
    q.device_reads = 0;
    q.stack_reads = 0;
    q.nodes[0].pop();
    q.nodes[1] = q.nodes[0].clone();
    assert!(inspect_all_queries(&[], &mut q).is_err());
}
#[test]
fn every_foreign_transition_flag_and_graph_participant_role_change_denies() {
    for flag in [0x20, 0x400, 0x8000, 0x40000, 0x400000, 0x80000000] {
        let mut q = foreign_query(true);
        for nodes in &mut q.nodes {
            nodes[0].status |= flag;
        }
        assert!(inspect_all_queries(&[], &mut q).is_err(), "flag {flag:x}");
    }
    let mut q = foreign_query(true);
    q.tables[1][2].role_flags = 2; // Valid filter role, changed media-connected bit.
    assert_eq!(inspect_all_queries(&[], &mut q), Err(Error::Changed));
    let mut q = foreign_query(true);
    q.stacks[0].push(StackEdge {
        higher: 24,
        lower: 19,
    });
    q.stacks[1] = q.stacks[0].clone();
    assert!(inspect_all_queries(&[], &mut q).is_err());
}
#[test]
fn independent_foreign_standard_name_and_guid_reuse_deny_exact_absence() {
    for phase in 0..2 {
        for field in 0..3 {
            let mut q = foreign_query(false);
            match field {
                0 => q.nodes[phase][0].standard_name = Some("nelomai vip".into()),
                1 => q.nodes[phase][0].netcfg_instance_id = GUID_TEXT.into(),
                _ => q.nodes[phase][0].name = "Nelomai VIP".into(),
            }
            assert!(inspect_absent_queries(&absence_target(), &mut q).is_err());
        }
    }
    let mut q = foreign_query(false);
    assert_eq!(inspect_absent_queries(&absence_target(), &mut q), Ok(()));
}

#[test]
fn stable_independently_confirmed_foreign_phantom_without_mib_is_negative_evidence() {
    // Break: requiring live status from an independently confirmed nonpresent
    // unrelated PnP record makes the carrier unavailable on normal Windows.
    let mut q = foreign_query(false);
    for phase in 0..2 {
        q.tables[phase].remove(0);
        let d = &mut q.nodes[phase][0];
        d.presence = Presence::Phantom;
        d.status = 0;
        d.problem = 0;
    }
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
    q.events.clear();
    q.table_reads = 0;
    q.device_reads = 0;
    q.stack_reads = 0;
    q.tables = [measured_foreign_bases(), measured_foreign_bases()];
    // A phantom cannot authenticate the live row with that same GUID/LUID.
    assert!(inspect_all_queries(&[], &mut q).is_err());
}

#[test]
fn phantom_negative_facts_reject_related_missing_changed_and_requested_reuse() {
    for field in 0..9 {
        let mut q = foreign_query(false);
        for phase in 0..2 {
            q.tables[phase].remove(0);
            let d = &mut q.nodes[phase][0];
            d.presence = Presence::Phantom;
            d.status = 0;
            d.problem = 0;
            match field {
                0 => d.hardware_ids = vec!["Wintun".into()],
                1 => d.name = "unexpected private WintunName".into(),
                2 => d.service = "Wintun".into(),
                3 => d.driver.provider = "WireGuard LLC".into(),
                4 => d.driver.matching_device_id = "unknown".into(),
                5 => d.driver.version.clear(),
                6 => d.standard_name = Some("Nelomai VIP".into()),
                7 => d.netcfg_instance_id = GUID_TEXT.into(),
                _ => {
                    if phase == 1 {
                        d.presence = Presence::Present;
                    }
                }
            }
        }
        assert!(
            inspect_absent_queries(&absence_target(), &mut q).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn actual_ras_phantom_can_crossbind_nonprovider_mib_without_live_permission() {
    let row = Interface {
        identity: Expected {
            guid: [
                0xc0, 0xb5, 0xf6, 0x74, 0xca, 0x8e, 0x4e, 0x7e, 0x84, 0xd0, 0xde, 0x5a, 0x7f, 0x26,
                0x23, 0xf8,
            ],
            luid: 6_474_474_236_936_192,
            index: 22,
            name: "Подключение по локальной сети* 11".into(),
            description: "RAS Async Adapter".into(),
            if_type: 23,
            tunnel_type: 0,
        },
        role_flags: 0,
    };
    let node = Device {
        instance: "SW\\{EEAB7790-C514-11D1-B42B-00805FC1270E}\\ASYNCMAC".into(),
        devinst: 187,
        presence: Presence::Phantom,
        class_guid: NET_CLASS,
        status: 0,
        problem: 0,
        hardware_ids: vec!["SW\\{eeab7790-c514-11d1-b42b-00805fc1270e}".into()],
        compatible_ids: vec![],
        service: "AsyncMac".into(),
        description: "RAS Async Adapter".into(),
        name: String::new(),
        wireguard_name: None,
        standard_name: Some("RAS Async Adapter".into()),
        netcfg_instance_id: "{C0B5F674-CA8E-4E7E-84D0-DE5A7F2623F8}".into(),
        net_luid_index: 32769,
        if_type: 23,
        driver: DriverMetadata {
            provider: "Microsoft".into(),
            version: "10.0.26100.1".into(),
            date_filetime: 127_953_216_000_000_000,
            inf: "netrasa.inf".into(),
            matching_device_id: "SW\\{eeab7790-c514-11d1-b42b-00805fc1270e}".into(),
            driver_key: "{4d36e972-e325-11ce-bfc1-08002be10318}\\0016".into(),
        },
    };
    let mut q = AbsenceScript::empty();
    q.tables = [vec![row.clone()], vec![row]];
    q.nodes = [vec![node.clone()], vec![node]];
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
    q.events.clear();
    q.table_reads = 0;
    q.device_reads = 0;
    q.stack_reads = 0;
    for phase in 0..2 {
        q.nodes[phase][0].if_type = 53;
        q.tables[phase][0].identity.if_type = 53;
        q.tables[phase][0].identity.luid = (53 << 48) | (32769 << 24);
    }
    assert!(inspect_all_queries(&[], &mut q).is_err());
}

const GUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];
const GUID_TEXT: &str = "{12345678-9abc-def0-8123-456789abcdef}";
struct Universe {
    rows: Vec<Observed>,
    calls: usize,
    extra: bool,
}
impl Queries for Universe {
    fn stack(&mut self) -> Result<Vec<StackEdge>> {
        self.calls += 1;
        Ok(vec![])
    }
    fn table(&mut self) -> Result<Vec<Interface>> {
        self.calls += 1;
        Ok(self
            .rows
            .iter()
            .flat_map(|r| r.interfaces.clone())
            .collect())
    }
    fn interfaces(&mut self, want: &Expected) -> Result<Observed> {
        self.calls += 1;
        self.rows
            .iter()
            .find(|r| r.by_luid.identity == *want)
            .cloned()
            .ok_or(Error::Changed)
    }
    fn device_snapshot(&mut self, _: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
        self.calls += 1;
        let mut d = self
            .rows
            .iter()
            .flat_map(|r| r.devices.clone())
            .collect::<Vec<_>>();
        if self.extra {
            d.push(observed().devices[0].clone());
        }
        Ok(DeviceSnapshot { nodes: d })
    }
}
fn universe() -> Universe {
    let a = observed();
    let mut b = observed();
    let mut identity = expected();
    identity.guid[15] ^= 1;
    identity.luid += 1 << 24;
    identity.index += 1;
    identity.name = "Nelomai member".into();
    let row = Interface {
        identity: identity.clone(),
        role_flags: 0x10,
    };
    b.by_luid = row.clone();
    b.by_index = row.clone();
    b.by_guid = row.clone();
    b.interfaces = vec![a.by_luid.clone(), row];
    let d = &mut b.devices[0];
    d.devinst += 1;
    d.instance = "SWD\\WINTUN\\{12345678-9ABC-DEF0-8123-456789ABCDEE}".into();
    d.netcfg_instance_id = "{12345678-9abc-def0-8123-456789abcdee}".into();
    d.net_luid_index += 1;
    d.name = identity.name;
    let mut a = a;
    a.interfaces = b.interfaces.clone();
    Universe {
        rows: vec![a, b],
        calls: 0,
        extra: false,
    }
}
#[test]
fn carrier_and_addressless_awg_are_attested_as_one_exact_device_universe() {
    let mut q = universe();
    let wants = q
        .rows
        .iter()
        .map(|r| r.by_luid.identity.clone())
        .collect::<Vec<_>>();
    let actual = inspect_all_queries(&wants, &mut q).unwrap();
    assert_eq!(actual.len(), 2);
    assert_eq!(actual[0].interface, wants[0]);
    assert_eq!(actual[1].interface, wants[1]);
}
#[test]
fn owned_universe_never_hides_extra_duplicate_or_missing_native_devices() {
    let mut q = universe();
    let wants = q
        .rows
        .iter()
        .map(|r| r.by_luid.identity.clone())
        .collect::<Vec<_>>();
    q.extra = true;
    assert!(inspect_all_queries(&wants, &mut q).is_err());
    let mut q = universe();
    q.rows[1].devices.clear();
    assert!(inspect_all_queries(&wants, &mut q).is_err());
    let mut q = universe();
    assert!(inspect_all_queries(&[wants[0].clone(), wants[0].clone()], &mut q).is_err());
    assert_eq!(q.calls, 0);
}
fn expected() -> Expected {
    Expected {
        guid: GUID,
        luid: (53 << 48) | (0x123456 << 24),
        index: 17,
        name: "Nelomai VIP".into(),
        description: "Nelomai Tunnel".into(),
        if_type: 53,
        tunnel_type: 0,
    }
}
fn observed() -> Observed {
    let interface = Interface {
        identity: expected(),
        role_flags: 0x10,
    };
    Observed {
        by_luid: interface.clone(),
        by_index: interface.clone(),
        by_guid: interface.clone(),
        interfaces: vec![interface],
        devices: vec![Device {
            instance: "SWD\\WINTUN\\{12345678-9ABC-DEF0-8123-456789ABCDEF}".into(),
            devinst: 123,
            presence: Presence::Present,
            class_guid: [
                0x4d, 0x36, 0xe9, 0x72, 0xe3, 0x25, 0x11, 0xce, 0xbf, 0xc1, 0x08, 0, 0x2b, 0xe1,
                0x03, 0x18,
            ],
            status: 0x200a,
            problem: 0,
            hardware_ids: vec!["Wintun".into()],
            compatible_ids: vec!["SWD\\Generic".into()],
            service: "Wintun".into(),
            description: "Nelomai Tunnel".into(),
            name: "Nelomai VIP".into(),
            wireguard_name: None,
            standard_name: None,
            netcfg_instance_id: GUID_TEXT.into(),
            net_luid_index: 0x123456,
            if_type: 53,
            driver: DriverMetadata {
                provider: "WireGuard LLC".into(),
                version: "0.14.0.0".into(),
                date_filetime: 132_785_568_000_000_000,
                inf: "oem42.inf".into(),
                matching_device_id: "Wintun".into(),
                driver_key: "{4d36e972-e325-11ce-bfc1-08002be10318}\\0042".into(),
            },
        }],
    }
}
fn bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn actual_software_bus_generic_id_is_required_not_ignored() {
    // Actual two-original Wintun0.14.1 observations, 01Oct02:47UTC. Windows
    // SW_DEVICE_CREATE_INFO adds this least-specific software-bus ID itself.
    let mut seen = observed();
    seen.devices[0].compatible_ids = vec!["SWD\\Generic".into()];
    let result = validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).unwrap();
    assert_eq!(result.instance.compatible_ids, ["SWD\\Generic"]);
    for ids in [
        vec![],
        vec!["SWD\\GenericRaw"],
        vec!["Other"],
        vec!["SWD\\Generic", "SWD\\Generic"],
        vec!["SWD\\Generic", "SWD\\GenericRaw"],
        vec!["SWD\\Generic", "Other"],
        vec!["SWD\\GenericX"],
    ] {
        seen.devices[0].compatible_ids = ids.into_iter().map(str::to_owned).collect();
        assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
    }
}

#[test]
fn pnp_description_and_original_mib_duplicate_suffix_are_separate_exact_fields() {
    let mut want = expected();
    want.description = "Nelomai Tunnel #2".into();
    let mut seen = observed();
    for row in [
        &mut seen.by_luid,
        &mut seen.by_index,
        &mut seen.by_guid,
        &mut seen.interfaces[0],
    ] {
        row.identity.description = "Nelomai Tunnel #2".into();
    }
    // The device property still has precisely the requested, unsuffixed type.
    let result = validate_provider(&want, ProviderKind::Wintun, &seen, &seen).unwrap();
    assert_eq!(result.interface.description, "Nelomai Tunnel #2");
    assert_eq!(result.instance.description, "Nelomai Tunnel");
    seen.devices[0].description = "Foreign Tunnel".into();
    assert!(validate_provider(&want, ProviderKind::Wintun, &seen, &seen).is_err());
}

#[test]
fn exact_native_facts_return_concrete_instance_and_metadata() {
    let seen = observed();
    let result = validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).unwrap();
    assert_eq!(result.interface.guid, GUID);
    assert_eq!(
        result.instance.instance,
        "SWD\\WINTUN\\{12345678-9ABC-DEF0-8123-456789ABCDEF}"
    );
    assert_eq!(result.instance.driver.inf, "oem42.inf");
    assert_eq!(result.instance.net_luid_index, 0x123456);
}

#[test]
fn reused_interface_guid_index_luid_name_description_type_are_rejected() {
    for field in 0..7 {
        for selector in 0..4 {
            let mut seen = observed();
            let row = match selector {
                0 => &mut seen.by_luid,
                1 => &mut seen.by_index,
                2 => &mut seen.by_guid,
                _ => &mut seen.interfaces[0],
            };
            match field {
                0 => row.identity.guid[15] ^= 1,
                1 => row.identity.index += 1,
                2 => row.identity.luid ^= 1 << 24,
                3 => row.identity.name.push('x'),
                4 => row.identity.description.push('x'),
                5 => row.identity.if_type = 6,
                _ => row.identity.tunnel_type = 1,
            }
            assert!(
                validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err(),
                "field {field}, selector {selector}"
            );
        }
    }
}

#[test]
fn missing_duplicate_or_colliding_table_rows_fail() {
    let mut seen = observed();
    seen.interfaces.clear();
    assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
    for field in 0..4 {
        let mut seen = observed();
        let mut foreign = seen.interfaces[0].clone();
        foreign.identity.guid[15] ^= 1;
        foreign.identity.luid += 1 << 24;
        foreign.identity.index += 1;
        foreign.identity.name = "Foreign".into();
        match field {
            0 => foreign.identity.guid = GUID,
            1 => foreign.identity.luid = expected().luid,
            2 => foreign.identity.index = 17,
            _ => foreign.identity.name = "nelomai vip".into(),
        }
        seen.interfaces.push(foreign);
        assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
    }
}

#[test]
fn unknown_zero_malformed_expected_identity_and_physical_roles_fail() {
    for field in 0..9 {
        let mut want = expected();
        match field {
            0 => want.guid = [0; 16],
            1 => want.luid = 0,
            2 => want.index = 0,
            3 => want.name.clear(),
            4 => want.description.clear(),
            5 => want.name.push('\0'),
            6 => want.luid |= 1,
            7 => want.luid = (6 << 48) | (0x123456 << 24),
            _ => want.luid = 53 << 48,
        }
        assert!(validate_provider(&want, ProviderKind::Wintun, &observed(), &observed()).is_err());
    }
    for flag in [1, 2, 0x80] {
        let mut seen = observed();
        seen.by_index.role_flags |= flag;
        assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
    }
}

#[test]
fn expected_name_scope_matches_the_carrier_ascii_binding_contract() {
    for name in [
        " Nelomai VIP".to_owned(),
        "Nelomai VIP ".to_owned(),
        "Nélomai VIP".to_owned(),
        "x".repeat(128),
    ] {
        let mut want = expected();
        want.name = name;
        let mut seen = observed();
        seen.by_luid.identity = want.clone();
        seen.by_index.identity = want.clone();
        seen.by_guid.identity = want.clone();
        seen.interfaces[0].identity = want.clone();
        seen.devices[0].name = want.name.clone();
        assert!(validate_provider(&want, ProviderKind::Wintun, &seen, &seen).is_err());
    }
}

#[test]
fn legacy_foreign_malformed_or_inexact_instance_is_rejected() {
    for instance in [
        "ROOT\\NET\\0001",
        "ROOT\\Wintun\\0001",
        "SWD\\Wintun",
        "SWD\\Wintun\\0001",
        "SWD\\Wintun\\{12345678-9abc-def0-8123-456789abcdee}",
        "SWD\\Wintun\\{12345678-9abc-def0-8123-456789abcdef}\\extra",
        "SWD\\WintunExtra\\{12345678-9abc-def0-8123-456789abcdef}",
    ] {
        let mut seen = observed();
        seen.devices[0].instance = instance.into();
        assert!(
            validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err(),
            "{instance}"
        );
    }
}

#[test]
fn wrong_driver_service_provider_version_date_binding_or_properties_fail() {
    for field in 0..20 {
        let mut seen = observed();
        let d = &mut seen.devices[0];
        match field {
            0 => d.service = "Other".into(),
            1 => d.driver.provider = "WireGuard".into(),
            2 => d.driver.version = "0.14.1.0".into(),
            3 => d.driver.date_filetime += 1,
            4 => d.netcfg_instance_id = "{12345678-9abc-def0-8123-456789abcdee}".into(),
            5 => d.net_luid_index += 1,
            6 => d.if_type = 6,
            7 => d.class_guid[15] ^= 1,
            8 => d.hardware_ids.clear(),
            9 => d.hardware_ids.push("Other".into()),
            10 => d.compatible_ids.push("Other".into()),
            11 => d.driver.matching_device_id = "Other".into(),
            12 => d.name.push('x'),
            13 => d.description.push('x'),
            14 => d.driver.inf = "C:\\oem42.inf".into(),
            15 => d.driver.inf = "wintun.inf".into(),
            16 => d.driver.driver_key.push('\0'),
            17 => d.devinst = 0,
            18 => d.net_luid_index |= 1 << 24,
            _ => d.driver.provider.push('\0'),
        }
        assert!(
            validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn phantom_nonstarted_problem_removal_missing_and_duplicate_devices_fail() {
    for (status, problem) in [(0, 0), (2, 0), (8, 0), (0x40a, 0), (0xa, 22), (0x4000a, 0)] {
        let mut seen = observed();
        seen.devices[0].status = status;
        seen.devices[0].problem = problem;
        assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
    }
    let mut seen = observed();
    seen.devices.clear();
    assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
    let mut seen = observed();
    seen.devices.push(seen.devices[0].clone());
    assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
    seen.devices[1].instance = "ROOT\\NET\\0001".into();
    assert!(validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err());
}

#[test]
fn private_boot_resource_and_pending_reenumeration_problems_are_not_live_facts() {
    for flag in [0x8000, 0x80000000, 0x400000, 0x20] {
        let mut seen = observed();
        seen.devices[0].status |= flag;
        assert!(
            validate_provider(&expected(), ProviderKind::Wintun, &seen, &seen).is_err(),
            "status flag {flag:#x}"
        );
    }
}

#[test]
fn reread_changes_in_interface_or_device_facts_are_rejected() {
    for field in 0..5 {
        let before = observed();
        let mut after = before.clone();
        match field {
            0 => after.by_luid.identity.guid[0] ^= 1,
            1 => after.devices[0].devinst += 1,
            2 => after.devices[0].driver.inf = "oem43.inf".into(),
            3 => after.devices[0].status ^= 0x2000,
            _ => {
                after.devices[0].driver.driver_key =
                    "{4d36e972-e325-11ce-bfc1-08002be10318}\\0043".into()
            }
        }
        assert!(validate_provider(&expected(), ProviderKind::Wintun, &before, &after).is_err());
    }
}

#[test]
fn guid_decoding_requires_full_braced_guid_and_preserves_all_bytes() {
    assert_eq!(parse_guid(GUID_TEXT).unwrap(), GUID);
    assert_eq!(
        parse_guid("{12345678-9ABC-DEF0-8123-456789ABCDEF}").unwrap(),
        GUID
    );
    for s in [
        "12345678-9abc-def0-8123-456789abcdef",
        "{12345678-9abc-def0-8123-456789abcdef}x",
        "{12345678_9abc-def0-8123-456789abcdef}",
        "{12345678-9abc-def0-8123-456789abcdeg}",
        "",
    ] {
        assert!(parse_guid(s).is_err());
    }
}

#[test]
fn strict_property_strings_reject_wrong_types_missing_nuls_invalid_utf16_and_tails() {
    assert_eq!(
        string_property(18, 18, &bytes("WireGuard LLC\0")).unwrap(),
        "WireGuard LLC"
    );
    assert_eq!(string_property(1, 1, &bytes("Wintun\0")).unwrap(), "Wintun");
    for data in [
        bytes("Wintun"),
        bytes("Wintun\0junk"),
        bytes("Wintun\0\0"),
        bytes("\0"),
        vec![0, 0xd8, 0, 0],
        vec![1, 0, 0],
    ] {
        assert!(string_property(18, 18, &data).is_err());
    }
    assert!(string_property(25, 18, &bytes("Wintun\0")).is_err());
    assert!(string_property(1, 18, &bytes("Wintun\0")).is_err());
    assert!(string_property(18, 18, &vec![0; 65538]).is_err());
}

#[test]
fn strict_multi_strings_reject_early_termination_tails_and_wrong_types() {
    assert_eq!(
        multi_property(7, 7, &bytes("Wintun\0\0")).unwrap(),
        vec!["Wintun"]
    );
    assert_eq!(
        multi_property(7, 7, &bytes("\0\0")).unwrap(),
        Vec::<String>::new()
    );
    for s in [
        "Wintun\0",
        "Wintun\0\0junk\0\0",
        "Wintun\0\0\0",
        "\0",
        "\0x\0\0",
    ] {
        assert!(multi_property(7, 7, &bytes(s)).is_err(), "{s:?}");
    }
    assert!(multi_property(1, 7, &bytes("Wintun\0\0")).is_err());
}

#[test]
fn scalar_properties_use_exact_type_length_and_safe_byte_decoding() {
    assert_eq!(
        filetime_property(16, &132_785_568_000_000_000u64.to_le_bytes()).unwrap(),
        132_785_568_000_000_000
    );
    assert_eq!(
        dword_property(4, &0x123456u32.to_le_bytes()).unwrap(),
        0x123456
    );
    for len in [0, 4, 7, 9, 16] {
        assert!(filetime_property(16, &vec![0; len]).is_err());
    }
    assert!(filetime_property(9, &[0; 8]).is_err());
    for len in [0, 2, 3, 5, 8] {
        assert!(dword_property(4, &vec![0; len]).is_err());
    }
    assert!(dword_property(1, &[0; 4]).is_err());
    // Subslice deliberately starts at an odd address; no unaligned pointer cast.
    let bytes = [0xff, 0x56, 0x34, 0x12, 0];
    assert_eq!(dword_property(4, &bytes[1..]).unwrap(), 0x123456);
}

#[test]
fn fixed_interface_strings_reject_nonzero_tail_and_invalid_utf16() {
    assert_eq!(fixed_string(&[65, 0, 0]).unwrap(), "A");
    for words in [&[65][..], &[65, 0, 66][..], &[0xd800, 0][..], &[0][..]] {
        assert!(fixed_string(words).is_err());
    }
}

// The query seam exercises the real sequencing/validation code. Each response
// is a whole observation, and every injected error must survive as an error.
struct Script {
    events: Vec<&'static str>,
    fail: Option<usize>,
    changed: bool,
}
impl Queries for Script {
    fn stack(&mut self) -> Result<Vec<StackEdge>> {
        self.events.push("stack");
        if self.fail == Some(self.events.len()) {
            return Err(Error::Native("script stack", 5));
        }
        Ok(vec![])
    }
    fn table(&mut self) -> Result<Vec<Interface>> {
        Err(Error::Invalid("unexpected table query"))
    }
    fn interfaces(&mut self, _: &Expected) -> Result<Observed> {
        self.events.push("interfaces");
        if self.fail == Some(self.events.len()) {
            return Err(Error::Native("script interface", 5));
        }
        let mut seen = observed();
        seen.devices.clear();
        if self.changed && self.events.len() == 5 {
            seen.by_index.identity.luid += 1 << 24;
        }
        Ok(seen)
    }
    fn device_snapshot(&mut self, _: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
        self.events.push("snapshot");
        if self.fail == Some(self.events.len()) {
            return Err(Error::Native("script device", 5));
        }
        Ok(DeviceSnapshot {
            nodes: observed().devices,
        })
    }
}
#[test]
fn native_query_sequence_brackets_two_device_reads_with_real_interface_queries() {
    let mut q = Script {
        events: vec![],
        fail: None,
        changed: false,
    };
    assert_eq!(
        inspect_all_queries(std::slice::from_ref(&expected()), &mut q)
            .unwrap()
            .remove(0)
            .instance
            .driver
            .version,
        "0.14.0.0"
    );
    assert_eq!(
        q.events,
        [
            "interfaces",
            "snapshot",
            "stack",
            "snapshot",
            "interfaces",
            "stack"
        ]
    );
}
#[test]
fn every_query_error_and_changed_final_binding_propagate_without_fallback() {
    for n in 1..=6 {
        let mut q = Script {
            events: vec![],
            fail: Some(n),
            changed: false,
        };
        assert!(matches!(
            inspect_all_queries(std::slice::from_ref(&expected()), &mut q),
            Err(Error::Native(_, 5))
        ));
        assert_eq!(q.events.len(), n);
    }
    let mut q = Script {
        events: vec![],
        fail: None,
        changed: true,
    };
    assert!(inspect_all_queries(std::slice::from_ref(&expected()), &mut q).is_err());
    let mut q = Script {
        events: vec![],
        fail: None,
        changed: false,
    };
    let mut want = expected();
    want.index = 0;
    assert!(inspect_all_queries(std::slice::from_ref(&want), &mut q).is_err());
    assert!(q.events.is_empty());
}
#[test]
fn returned_byte_count_never_accepts_zero_overflow_or_spare_capacity_as_data() {
    assert_eq!(
        returned_bytes(vec![65, 0, 0, 0, 0xff, 0xff], 4).unwrap(),
        vec![65, 0, 0, 0]
    );
    assert!(returned_bytes(vec![0; 4], 0).is_err());
    assert!(returned_bytes(vec![0; 4], 5).is_err());
    assert!(returned_bytes(vec![0; 65538], 65538).is_err());
}
#[test]
fn classification_includes_legacy_other_classes_service_hardware_and_reused_guids() {
    for (instance, ids, compat, service, cfg, name) in [
        ("SWD\\Wintun\\anything", vec![], vec![], None, None, None),
        ("ROOT\\WINTUN\\anything", vec![], vec![], None, None, None),
        (
            "ROOT\\NET\\0001",
            vec!["Wintun".into()],
            vec![],
            None,
            None,
            None,
        ),
        (
            "USB\\Foreign",
            vec![],
            vec!["WINTUN".into()],
            None,
            None,
            None,
        ),
        ("USB\\Foreign", vec![], vec![], Some("wintun"), None, None),
        ("USB\\Foreign", vec![], vec![], None, Some(GUID_TEXT), None),
        (
            "USB\\Foreign",
            vec![],
            vec![],
            None,
            None,
            Some("nelomai vip"),
        ),
    ] {
        assert!(related_targets(
            &[target(&expected())],
            instance,
            &ids,
            &compat,
            service,
            cfg,
            name
        )
        .unwrap());
    }
    assert!(!related_targets(
        &[target(&expected())],
        "USB\\Unrelated",
        &[],
        &[],
        None,
        None,
        None
    )
    .unwrap());
    assert!(related_targets(
        &[target(&expected())],
        "USB\\Unrelated",
        &[],
        &[],
        None,
        Some("bad GUID"),
        None
    )
    .is_err());
}

// Real portable query orchestration, with only OS reads replaced. The fixtures
// deliberately include foreign/malformed/phantom nodes rather than filtering
// them into an expected provider set in the test double.
struct AbsenceScript {
    events: Vec<&'static str>,
    tables: [Vec<Interface>; 2],
    nodes: [Vec<Device>; 2],
    stacks: [Vec<StackEdge>; 2],
    stack_reads: usize,
    fail: Option<usize>,
    table_reads: usize,
    device_reads: usize,
    requested_targets: Vec<Vec<AbsenceTarget>>,
}
impl AbsenceScript {
    fn empty() -> Self {
        Self {
            events: vec![],
            tables: [vec![], vec![]],
            nodes: [vec![], vec![]],
            stacks: [vec![], vec![]],
            stack_reads: 0,
            fail: None,
            table_reads: 0,
            device_reads: 0,
            requested_targets: vec![],
        }
    }
    fn event(&mut self, name: &'static str) -> Result<()> {
        self.events.push(name);
        if self.fail == Some(self.events.len()) {
            return Err(Error::Native("absence read", 5));
        }
        Ok(())
    }
}
impl Queries for AbsenceScript {
    fn stack(&mut self) -> Result<Vec<StackEdge>> {
        self.event("stack")?;
        let edges = self.stacks[self.stack_reads].clone();
        self.stack_reads += 1;
        Ok(edges)
    }
    fn interfaces(&mut self, _: &Expected) -> Result<Observed> {
        panic!("absence must not look up an existing interface")
    }
    fn table(&mut self) -> Result<Vec<Interface>> {
        self.event("table")?;
        let rows = self.tables[self.table_reads].clone();
        self.table_reads += 1;
        Ok(rows)
    }
    fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
        self.requested_targets.push(targets.to_vec());
        self.event("snapshot")?;
        let nodes = self.nodes[self.device_reads].clone();
        self.device_reads += 1;
        Ok(DeviceSnapshot { nodes })
    }
}
fn absence_target() -> AbsenceTarget {
    AbsenceTarget {
        guid: GUID,
        name: "Nelomai VIP".into(),
    }
}

#[test]
fn empty_universe_requires_two_full_mib_and_two_pnp_reads() {
    // Break caught: return success (or reject) without querying for zero input.
    let mut q = AbsenceScript::empty();
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
    assert_eq!(
        q.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
}

#[test]
fn zero_input_rejects_foreign_legacy_phantom_and_extra_wintun_sentinels() {
    // Break caught: an empty target filter makes a populated universe empty.
    for phase in 0..2 {
        for kind in 0..5 {
            let mut q = AbsenceScript::empty();
            let mut node = observed().devices.remove(0);
            match kind {
                0 => node.instance = "ROOT\\WINTUN\\0001".into(),
                1 => node.driver.provider = "Foreign".into(),
                2 => {
                    node.status = 0;
                    node.problem = 22;
                }
                3 => node.class_guid = [7; 16],
                _ => q.nodes[phase].push(node.clone()),
            }
            q.nodes[phase].push(node);
            assert!(inspect_all_queries(&[], &mut q).is_err());
            assert!(!q.events.is_empty());
        }
        let mut q = AbsenceScript::empty();
        q.tables[phase] = observed().interfaces;
        assert!(inspect_all_queries(&[], &mut q).is_err());
        assert!(!q.events.is_empty());
    }
}

#[test]
fn every_empty_universe_query_error_propagates_without_default_success() {
    // Break caught: treating failed/incomplete discovery as an empty universe.
    for n in 1..=6 {
        let mut q = AbsenceScript::empty();
        q.fail = Some(n);
        assert_eq!(
            inspect_all_queries(&[], &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.events.len(), n);
    }
}

#[test]
fn exact_absence_requires_fresh_tables_and_accepts_only_unrelated_interfaces() {
    // Break caught: substituting a successful GUID lookup failure for full reads.
    let mut q = AbsenceScript::empty();
    let mut row = observed().interfaces.remove(0);
    row.identity.guid = [9; 16];
    row.identity.name = "Ethernet".into();
    row.identity.if_type = 6;
    row.identity.luid = (6 << 48) | (7 << 24);
    row.identity.description = "Ethernet controller".into();
    q.tables = [vec![row.clone()], vec![row]];
    assert_eq!(inspect_absent_queries(&absence_target(), &mut q), Ok(()));
    assert_eq!(
        q.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
    // The discovery boundary must receive BOTH requested canonical identity
    // fields, or a foreign provider with only a colliding PnP name/GUID hides.
    assert_eq!(
        q.requested_targets,
        [
            vec![AbsenceTarget {
                guid: GUID,
                name: "Nelomai VIP".into()
            }],
            vec![AbsenceTarget {
                guid: GUID,
                name: "Nelomai VIP".into()
            }],
        ]
    );
}

#[test]
fn exact_absence_rejects_name_or_guid_reuse_independently_of_provider() {
    // Break caught: provider filtering before testing foreign identity reuse.
    for phase in 0..2 {
        for collision in 0..2 {
            let mut q = AbsenceScript::empty();
            let mut row = observed().interfaces.remove(0);
            row.identity.if_type = 6;
            row.identity.luid = (6 << 48) | (7 << 24);
            row.identity.description = "Foreign".into();
            if collision == 0 {
                row.identity.name = "Foreign".into();
            } else {
                row.identity.guid = [9; 16];
                row.identity.name = "nelomai vip".into();
            }
            q.tables[phase].push(row);
            assert!(inspect_absent_queries(&absence_target(), &mut q).is_err());
        }
        let mut q = AbsenceScript::empty();
        let mut node = observed().devices.remove(0);
        node.instance = "USB\\Foreign".into();
        node.hardware_ids.clear();
        node.service = "Foreign".into();
        node.driver.provider = "Foreign".into();
        q.nodes[phase].push(node);
        assert!(inspect_absent_queries(&absence_target(), &mut q).is_err());
    }
}

#[test]
fn malformed_absence_targets_are_rejected_before_any_query() {
    for (guid, name) in [
        ([0; 16], "Nelomai VIP"),
        (GUID, ""),
        (GUID, " bad"),
        (GUID, "bad "),
        (GUID, "Nélomai"),
        (GUID, "bad\0"),
        (GUID, "bad\n"),
    ] {
        let mut q = AbsenceScript::empty();
        assert!(inspect_absent_queries(
            &AbsenceTarget {
                guid,
                name: name.into()
            },
            &mut q
        )
        .is_err());
        assert!(q.events.is_empty());
    }
}

#[test]
fn empty_target_classification_keeps_all_wintun_signals_and_parses_foreign_cfg() {
    for (instance, ids, compatible, service) in [
        ("SWD\\Wintun\\anything", vec![], vec![], None),
        ("ROOT\\WINTUN\\anything", vec![], vec![], None),
        ("USB\\Foreign", vec!["Wintun".into()], vec![], None),
        ("USB\\Foreign", vec![], vec!["WINTUN".into()], None),
        ("USB\\Foreign", vec![], vec![], Some("wintun")),
    ] {
        assert_eq!(
            related_targets(&[], instance, &ids, &compatible, service, None, None),
            Ok(true)
        );
    }
    assert_eq!(
        related_targets(&[], "USB\\Other", &[], &[], None, Some(GUID_TEXT), None),
        Ok(false)
    );
    assert!(related_targets(&[], "USB\\Other", &[], &[], None, Some("bad GUID"), None).is_err());
    for (cfg, name) in [(Some(GUID_TEXT), None), (None, Some("nelomai vip"))] {
        assert_eq!(
            related_targets(&[absence_target()], "USB\\Other", &[], &[], None, cfg, name),
            Ok(true)
        );
    }
}

#[test]
fn nonempty_universe_rejects_extra_mib_only_provider_rows_in_both_reads() {
    // Break caught: validate only target collisions, hiding extra type53 rows.
    for final_read in [false, true] {
        let mut q = Script {
            events: vec![],
            fail: None,
            changed: false,
        };
        // A scripted complete table must not be projected to only its target.
        struct ExtraRow<'a> {
            q: &'a mut Script,
            final_read: bool,
        }
        impl Queries for ExtraRow<'_> {
            fn interfaces(&mut self, want: &Expected) -> Result<Observed> {
                let mut seen = self.q.interfaces(want)?;
                if (self.q.events.len() == 5) == self.final_read {
                    let mut extra = seen.interfaces[0].clone();
                    extra.identity.guid = [7; 16];
                    extra.identity.index = 100;
                    extra.identity.luid = (53 << 48) | (100 << 24);
                    extra.identity.name = "Foreign Wintun".into();
                    seen.interfaces.push(extra);
                }
                Ok(seen)
            }
            fn table(&mut self) -> Result<Vec<Interface>> {
                self.q.table()
            }
            fn device_snapshot(&mut self, targets: &[AbsenceTarget]) -> Result<DeviceSnapshot> {
                self.q.device_snapshot(targets)
            }
            fn stack(&mut self) -> Result<Vec<StackEdge>> {
                self.q.stack()
            }
        }
        assert!(inspect_all_queries(
            std::slice::from_ref(&expected()),
            &mut ExtraRow {
                q: &mut q,
                final_read
            }
        )
        .is_err());
    }
}

#[test]
fn unrelated_exact_original_can_coexist_with_absence_but_unknown_nodes_cannot() {
    let mut q = AbsenceScript::empty();
    q.tables = [observed().interfaces, observed().interfaces];
    q.nodes = [observed().devices, observed().devices];
    let target = AbsenceTarget {
        guid: [8; 16],
        name: "nelomai-b".into(),
    };
    assert_eq!(inspect_absent_queries(&target, &mut q), Ok(()));
    assert_eq!(
        q.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
    for phase in 0..2 {
        for field in 0..6 {
            let mut q = AbsenceScript::empty();
            q.tables = [observed().interfaces, observed().interfaces];
            q.nodes = [observed().devices, observed().devices];
            let d = &mut q.nodes[phase][0];
            match field {
                0 => d.status = 0,
                1 => d.problem = 22,
                2 => d.driver.provider = "Foreign".into(),
                3 => d.netcfg_instance_id = "malformed".into(),
                4 => d.name.clear(),
                _ => d.instance = "ROOT\\WINTUN\\0001".into(),
            }
            assert!(inspect_absent_queries(&target, &mut q).is_err());
        }
    }
}

#[test]
fn every_target_absence_read_failure_propagates_and_related_rereads_must_agree() {
    for n in 1..=6 {
        let mut q = AbsenceScript::empty();
        q.fail = Some(n);
        assert_eq!(
            inspect_absent_queries(&absence_target(), &mut q),
            Err(Error::Native("absence read", 5))
        );
        assert_eq!(q.events.len(), n);
    }
    let target = AbsenceTarget {
        guid: [8; 16],
        name: "nelomai-b".into(),
    };
    let mut q = AbsenceScript::empty();
    q.tables = [observed().interfaces, observed().interfaces];
    q.nodes = [observed().devices, observed().devices];
    // Both snapshots satisfy the provider predicate but aren't the same node.
    q.nodes[1][0].devinst += 1;
    assert_eq!(inspect_absent_queries(&target, &mut q), Err(Error::Changed));
    let mut q = AbsenceScript::empty();
    q.tables = [observed().interfaces, observed().interfaces];
    q.nodes = [observed().devices, observed().devices];
    q.tables[1][0].role_flags ^= 0x10;
    assert_eq!(inspect_absent_queries(&target, &mut q), Err(Error::Changed));
}

#[test]
fn system_table_accepts_actual_unique_loopback_and_filter_luids_with_zero_index_component() {
    // Break caught: imposing Wintun's nonzero NetLuidIndex contract on every
    // system row. Literal GetIfTable2 facts from DESKTOP-1DGFU8K, 01Oct03:19.
    // Full LUID/GUID/index uniqueness is still mandatory; no creator authority.
    let rows = vec![
        Interface {
            identity: Expected {
                guid: [0x5f, 0xff, 0xa4, 0xd8, 0x29, 0xde, 0x11, 0xeb, 0x96, 0x69, 0x80, 0x6e, 0x6f, 0x6e, 0x69, 0x63],
                luid: 6_755_399_441_055_744,
                index: 1,
                name: "Loopback Pseudo-Interface 1".into(),
                description: "Software Loopback Interface 1".into(),
                if_type: 24,
                tunnel_type: 0,
            },
            role_flags: 0,
        },
        Interface {
            identity: Expected {
                guid: [0x11, 0x2f, 0x9b, 0x6a, 0xbd, 0x24, 0x11, 0xf1, 0x98, 0x16, 0x88, 0xd8, 0x2e, 0xec, 0xb5, 0xc5],
                luid: 1_688_849_860_263_936,
                index: 28,
                name: "vSwitch (Default Switch)-Hyper-V Virtual Switch Extension Filter-0000".into(),
                description: "Hyper-V Virtual Switch Extension Adapter-Hyper-V Virtual Switch Extension Filter-0000".into(),
                if_type: 6,
                tunnel_type: 0,
            },
            role_flags: 2,
        },
    ];
    let mut query = AbsenceScript::empty();
    query.tables = [rows.clone(), rows.clone()];
    assert_eq!(inspect_all_queries(&[], &mut query), Ok(vec![]));
    assert_eq!(
        query.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
    let mut aliased = rows;
    aliased.push(aliased[0].clone());
    assert!(validate_table(&aliased).is_err());
    let mut wintun = expected();
    wintun.luid = 53 << 48;
    assert!(validate_expected(&wintun).is_err());
}

#[test]
fn malformed_unrelated_mib_readings_cannot_prove_absence() {
    // Break caught: decode strings but silently accept unknown scalar identity
    // or duplicate/colliding physical rows in a supposedly complete table.
    for phase in 0..2 {
        for field in 0..10 {
            let mut q = AbsenceScript::empty();
            let mut row = observed().interfaces.remove(0);
            row.identity.guid = [8; 16];
            row.identity.if_type = 6;
            row.identity.luid = (6 << 48) | (9 << 24);
            row.identity.name = "Ethernet".into();
            row.identity.description = "Ethernet controller".into();
            match field {
                0 => row.identity.guid = [0; 16],
                1 => row.identity.index = 0,
                2 => row.identity.luid = 0,
                3 => row.identity.name.clear(),
                4 => row.identity.description.clear(),
                5 => row.identity.if_type = 0,
                6 => row.identity.luid |= 1,
                7 => row.identity.luid = (7 << 48) | (9 << 24),
                8 => row.identity.name.push('\0'),
                _ => q.tables[phase].push(row.clone()),
            }
            q.tables[phase].push(row);
            assert!(
                inspect_absent_queries(&absence_target(), &mut q).is_err(),
                "phase {phase}, field {field}"
            );
        }
    }
}

#[test]
fn full_table_and_related_node_count_bounds_are_not_truncated_to_success() {
    for phase in 0..2 {
        let mut q = AbsenceScript::empty();
        q.tables[phase] = vec![observed().interfaces.remove(0); 4097];
        assert!(inspect_all_queries(&[], &mut q).is_err());
        let mut q = AbsenceScript::empty();
        q.nodes[phase] = vec![observed().devices.remove(0); 4097];
        assert!(inspect_all_queries(&[], &mut q).is_err());
    }
    let mut q = AbsenceScript::empty();
    let wants = vec![expected(); 4];
    assert!(inspect_all_queries(&wants, &mut q).is_err());
    assert!(q.events.is_empty());
    let mut q = AbsenceScript::empty();
    let target = AbsenceTarget {
        guid: GUID,
        name: "x".repeat(128),
    };
    assert!(inspect_absent_queries(&target, &mut q).is_err());
    assert!(q.events.is_empty());
}

#[test]
fn every_network_key_guid_read_is_required_even_without_a_matching_target() {
    // Break caught: missing/access-denied/malformed foreign Net-key readings
    // disappear through an optional-value default before classification.
    assert_eq!(
        network_guid_read(Ok(Some(GUID_TEXT.into()))),
        Ok(GUID_TEXT.into())
    );
    assert_eq!(
        network_guid_read(Err(Error::Native("SetupDiOpenDevRegKey QUERY_VALUE", 5))),
        Err(Error::Native("SetupDiOpenDevRegKey QUERY_VALUE", 5))
    );
    assert_eq!(
        network_guid_read(Err(Error::Native("RegQueryValueExW", 2))),
        Err(Error::Native("RegQueryValueExW", 2))
    );
    assert!(network_guid_read(Ok(None)).is_err());
    for cfg in [
        "",
        "bad GUID",
        "{12345678-9abc-def0-8123-456789abcdef}tail",
        "{00000000-0000-0000-0000-000000000000}",
    ] {
        assert!(network_guid_read(Ok(Some(cfg.into()))).is_err(), "{cfg}");
    }
    assert!(network_guid_read(string_property(4, 1, &bytes("bad\0")).map(Some)).is_err());
    assert!(network_guid_read(string_property(1, 1, &bytes("unterminated")).map(Some)).is_err());
}

#[test]
fn completely_unrelated_node_still_cannot_hide_malformed_cfg_with_a_global_scan() {
    // Break caught: skip cfg parsing on a provider signal or zero-target branch.
    for targets in [vec![], vec![absence_target()]] {
        for (instance, ids, service) in [
            ("SWD\\Wintun\\x", vec![], None),
            ("USB\\Other", vec!["Other".into()], Some("Other")),
        ] {
            assert!(
                related_targets(&targets, instance, &ids, &[], service, Some("bad"), None).is_err()
            );
        }
    }
}

#[test]
fn unrelated_physical_table_churn_does_not_become_provider_identity_evidence() {
    let mut q = AbsenceScript::empty();
    let mut row = observed().interfaces.remove(0);
    row.identity.if_type = 6;
    row.identity.luid = (6 << 48) | (17 << 24);
    row.identity.guid = [9; 16];
    row.identity.name = "Ethernet".into();
    row.identity.description = "Ethernet controller".into();
    q.tables[1].push(row);
    assert_eq!(inspect_all_queries(&[], &mut q), Ok(vec![]));
    assert_eq!(
        q.events,
        ["table", "snapshot", "stack", "snapshot", "table", "stack"]
    );
    assert_eq!(q.requested_targets, [vec![], vec![]]);
}
