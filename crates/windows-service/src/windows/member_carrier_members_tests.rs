use super::*;
use crate::member_carrier::{Intent as CarrierIntent, Provenance};
use crate::member_carrier_native_ownership::Binding;
#[cfg(not(windows))]
use crate::member_carrier_provider::Expected;
use crate::member_owner::{InterfaceProof, ProcessProof};
#[cfg(windows)]
use crate::windows::member_carrier_provider::Expected;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};

#[test]
fn exact_standby_stop_receipt_can_be_registered_without_retiring_live_inventory() {
    use crate::{
        member_carrier_guard as guard, member_carrier_pair as pair, member_owner as owner,
    };
    use nelomai_client_tunnel::redundancy::Slot;
    let (ctx, intent, proof, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    let state = |slot| {
        let mut intent = intent.clone();
        intent.slot = slot;
        pair::MemberState {
            owner: owner::Record {
                intent,
                phase: owner::Phase::Running,
                proof: Some(proof),
                retired_proof: None,
                previous_config_sha256: None,
            },
            lease_id: if slot == TunnelSlot::A {
                "22222222-2222-4222-8222-222222222222"
            } else {
                "33333333-3333-4333-8333-333333333333"
            }
            .into(),
            probe: nelomai_contracts::RedundantHealthProbe {
                kind: nelomai_contracts::HealthProbeKind::DnsA,
                target_ipv4: "1.1.1.1".parse().unwrap(),
                query_name: "example.com".into(),
                timeout_ms: 2000,
            },
            endpoint: "192.0.2.1".parse().unwrap(),
            allowed: vec!["0.0.0.0/0".parse().unwrap()],
            peer: [3; 32],
        }
    };
    let mut b = state(TunnelSlot::B);
    b.owner.proof.as_mut().unwrap().interface.guid = ctx.bindings[2].guid;
    b.owner.proof.as_mut().unwrap().interface.index += 1;
    b.owner.proof.as_mut().unwrap().interface.luid += 1;
    let current = pair::Record {
        version: 2,
        scope: ctx.intent.scope.clone(),
        provenance: ctx.provenance.clone(),
        revision: 10,
        phase: pair::Phase::Running,
        addresses: ctx.intent.addresses.clone(),
        dns: vec![],
        carrier: Some(owner::InterfaceProof {
            guid: ctx.bindings[0].guid,
            index: 7,
            luid: 90,
        }),
        members: [Some(state(TunnelSlot::A)), Some(b)],
        active: Some(Slot::A),
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: guard::Model::empty(ctx.intent.scope.clone()).unwrap(),
        pending_guard: None,
        pending: Some(pair::Effect::MemberStop(Slot::B)),
        network: None,
        stop_stage: 0,
        operation: Some(pair::Operation::Retire(Slot::B)),
    };
    current.validate().unwrap();
    retirement_registration(
        &ctx,
        crate::member_carrier_native_ownership::Phase::Preparing,
        &current,
        1,
    )
    .unwrap();
    let health = ReadHealth::default();
    health
        .forward(|| {
            retirement_registration(
                &ctx,
                crate::member_carrier_native_ownership::Phase::Preparing,
                &current,
                1,
            )
        })
        .unwrap();
    assert!(!health.revoked.get());
    let mut completed = current.clone();
    completed.members[1] = None;
    completed.pending = None;
    completed.operation = None;
    completed_retirement_registration(
        &ctx,
        crate::member_carrier_native_ownership::Phase::Preparing,
        &completed,
        1,
    )
    .unwrap();
    for fault in 0..9 {
        let mut wrong = completed.clone();
        let mut native = crate::member_carrier_native_ownership::Phase::Preparing;
        let mut index = 1;
        match fault {
            0 => native = crate::member_carrier_native_ownership::Phase::Closing,
            1 => index = 0,
            2 => index = 2,
            3 => wrong.members[1] = current.members[1].clone(),
            4 => wrong.operation = current.operation,
            5 => wrong.pending = current.pending,
            6 => wrong.provenance.network_epoch += 1,
            7 => wrong.carrier = None,
            _ => wrong.members[0].as_mut().unwrap().owner.phase = owner::Phase::Stopped,
        }
        assert!(
            completed_retirement_registration(&ctx, native, &wrong, index).is_err(),
            "completed fault {fault}"
        );
    }
    for fault in 0..11 {
        let mut wrong = current.clone();
        let mut native = crate::member_carrier_native_ownership::Phase::Preparing;
        let mut target = 1;
        match fault {
            0 => native = crate::member_carrier_native_ownership::Phase::Closing,
            1 => target = 0,
            2 => target = 2,
            3 => wrong.operation = Some(pair::Operation::Retire(Slot::A)),
            4 => wrong.pending = Some(pair::Effect::MemberStop(Slot::A)),
            5 => wrong.active = None,
            6 => wrong.stop_stage = 4,
            7 => wrong.provenance.network_epoch += 1,
            8 => wrong.phase = pair::Phase::Closing,
            9 => wrong.members[0].as_mut().unwrap().owner.phase = owner::Phase::Prepared,
            _ => wrong.members[1] = None,
        }
        assert!(
            retirement_registration(&ctx, native, &wrong, target).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn key_absence_keeps_all_other_owners_but_closing_requires_full_empty_universe() {
    let (ctx, _, _, a) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    assert_eq!(
        key_provider_inputs(&ctx, &[], &[a.clone()], false, &ctx.bindings[2]),
        Ok(vec![a.clone()])
    );
    assert!(key_provider_inputs(&ctx, &[], &[a.clone()], false, &ctx.bindings[1]).is_err());
    assert!(key_provider_inputs(&ctx, &[], &[a.clone()], true, &ctx.bindings[2]).is_err());
    assert_eq!(
        key_provider_inputs(&ctx, &[], &[], true, &ctx.bindings[1]),
        Ok(vec![])
    );
    let mut foreign = ctx.bindings[2].clone();
    foreign.name.push_str("-foreign");
    assert!(key_provider_inputs(&ctx, &[], &[a], false, &foreign).is_err());
}

#[test]
fn package_projection_accounts_for_c_and_awg_wintun_but_not_wireguard_nt() {
    let devices = ["Wintun", "WireGuard", "Wintun"]
        .iter()
        .enumerate()
        .map(|(i, kind)| PackageDevice {
            instance: format!(r"SWD\{kind}\{{00000000-0000-0000-0000-{:012x}}}", i + 1),
            status: 8,
            problem: 0,
        })
        .collect::<Vec<_>>();
    let kinds = [
        ProviderKind::Wintun,
        ProviderKind::WireGuardNt,
        ProviderKind::Wintun,
    ];
    assert_eq!(
        package_devices(&kinds, &devices),
        Ok(vec![devices[0].clone(), devices[2].clone()])
    );
    assert_eq!(package_devices(&[], &[]), Ok(vec![]));
    assert_eq!(package_devices(&kinds[1..2], &devices[1..2]), Ok(vec![]));
    for fault in 0..6 {
        let mut kinds = kinds.to_vec();
        let mut devices = devices.clone();
        match fault {
            0 => {
                devices.pop();
            }
            1 => kinds[2] = ProviderKind::WireGuardNt,
            2 => devices[2].instance = devices[0].instance.clone(),
            3 => devices[2].problem = 22,
            4 => devices[2].status = 0,
            _ => devices[2].instance = "ROOT\\Wintun\\Legacy".into(),
        }
        assert!(package_devices(&kinds, &devices).is_err(), "fault {fault}");
    }
}

#[test]
fn one_member_or_full_provider_read_failure_irreversibly_revokes_forward_observations() {
    let health = ReadHealth::default();
    assert_eq!(health.forward(|| Ok(4)), Ok(4));
    assert_eq!(
        health.forward::<()>(|| Err(Error::Native)),
        Err(Error::Native)
    );
    let calls = Cell::new(0);
    assert_eq!(
        health.forward(|| {
            calls.set(1);
            Ok(4)
        }),
        Err(Error::Conflict)
    );
    assert_eq!(calls.get(), 0);
    // Factual cleanup is still possible, but it cannot rearm forward reads.
    assert_eq!(health.cleanup(|| Ok(9)), Ok(9));
    assert_eq!(health.forward(|| Ok(4)), Err(Error::Conflict));
}

#[test]
fn unwind_and_cleanup_entry_cannot_rearm_full_inventory_reads() {
    let health = ReadHealth::default();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        health.forward::<()>(|| panic!("unknown native read outcome"))
    }));
    assert!(panic.is_err());
    assert_eq!(health.forward(|| Ok(1)), Err(Error::Conflict));
    let cleanup = ReadHealth::default();
    assert_eq!(
        cleanup.cleanup::<()>(|| Err(Error::Native)),
        Err(Error::Native)
    );
    assert_eq!(cleanup.forward(|| Ok(1)), Err(Error::Conflict));
}

#[test]
fn ignored_nested_read_failure_still_denies_outer_read_and_all_later_readers() {
    let health = ReadHealth::default();
    assert_eq!(
        health.forward(|| {
            assert_eq!(health.forward(|| Ok(7)), Err(Error::Conflict));
            Ok(8)
        }),
        Err(Error::Conflict)
    );
    assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
}

#[test]
fn initial_phase_query_failure_or_unwind_revokes_before_any_provider_query() {
    for unwind in [false, true] {
        let health = ReadHealth::default();
        let queries = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            health.observe(
                || {
                    if unwind {
                        panic!("phase read unavailable")
                    }
                    Err(Error::Native)
                },
                |_| {
                    queries.set(1);
                    Ok(4)
                },
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Native));
        }
        assert_eq!(queries.get(), 0);
        assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
    }
}

#[test]
fn cleanup_must_not_ignore_a_reentrant_forward_or_cleanup_read_failure() {
    for nested_cleanup in [false, true] {
        let health = ReadHealth::default();
        assert_eq!(
            health.cleanup(|| {
                let inner = if nested_cleanup {
                    health.cleanup(|| Ok(7))
                } else {
                    health.forward(|| Ok(7))
                };
                assert_eq!(inner, Err(Error::Conflict));
                Ok(8)
            }),
            Err(Error::Conflict)
        );
        assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
        // A later factual cleanup retry is allowed, never a forward rearm.
        assert_eq!(health.cleanup(|| Ok(10)), Ok(10));
    }
}

fn fixture(
    slot: TunnelSlot,
    transport: TunnelTransport,
) -> (Context, Intent, NativeProof, ExpectedProvider) {
    let scope = SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    };
    let context = Context {
        intent: CarrierIntent { scope: scope.clone(), addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: Provenance { boot_id: [8; 16], network_epoch: 1,
            runtime: EngineIdentity { slot: RuntimeSlot::Stable, runtime_version: "0.3.3".into(),
                container_version: "0.3.3".into(), runtime_contract_version: 1, manifest_sha256: "a".repeat(64) } },
        bindings: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| {
            let id = match role { Role::RoleCarrier => 1, Role::MemberA => 2, Role::MemberB => 3 };
            Binding { role, guid: [id; 16], name: format!("member-{id}"),
                registry_path: format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{id:02x}{id:02x}{id:02x}{id:02x}-{id:02x}{id:02x}-{id:02x}{id:02x}-{id:02x}{id:02x}-{id:02x}{id:02x}{id:02x}{id:02x}{id:02x}{id:02x}}}") }
        }),
    };
    let index = if slot == TunnelSlot::A { 1 } else { 2 };
    let proof = NativeProof {
        process: ProcessProof {
            pid: 20,
            creation_time: 30,
        },
        interface: InterfaceProof {
            index: 70 + index as u32,
            luid: (53_u64 << 48) | ((index as u64 + 1) << 24),
            guid: context.bindings[index].guid,
        },
    };
    let intent = Intent {
        scope,
        slot,
        transport,
        engine: crate::test_engine_path("engine.exe"),
        config_sha256: [9; 32],
    };
    let provider = ExpectedProvider {
        kind: if transport == TunnelTransport::WireGuard {
            ProviderKind::WireGuardNt
        } else {
            ProviderKind::Wintun
        },
        identity: Expected {
            guid: proof.interface.guid,
            luid: proof.interface.luid,
            index: proof.interface.index,
            name: context.bindings[index].name.clone(),
            description: "Nelomai member Tunnel".into(),
            if_type: 53,
            tunnel_type: 0,
        },
    };
    (context, intent, proof, provider)
}

#[test]
fn actual_member_comparison_maps_only_its_own_role_and_protocol_provider() {
    for slot in [TunnelSlot::A, TunnelSlot::B] {
        for transport in [TunnelTransport::WireGuard, TunnelTransport::AmneziaWg3] {
            let (ctx, intent, proof, provider) = fixture(slot, transport);
            assert_eq!(
                validate_member_binding(&ctx, &intent, &proof, &provider).unwrap(),
                if slot == TunnelSlot::A { 0 } else { 1 }
            );
        }
    }
}

#[test]
fn equal_numbers_foreign_scope_carrier_role_or_wrong_provider_do_not_match_member() {
    for fault in 0..13 {
        let (mut ctx, mut intent, mut proof, mut provider) =
            fixture(TunnelSlot::A, TunnelTransport::WireGuard);
        match fault {
            0 => intent.scope.connection_generation += 1,
            1 => intent.slot = TunnelSlot::B,
            2 => ctx.bindings[1].role = Role::RoleCarrier,
            3 => ctx.bindings[1].guid = ctx.bindings[0].guid,
            4 => provider.identity.guid = ctx.bindings[0].guid,
            5 => provider.identity.index += 1,
            6 => provider.identity.luid += 1,
            7 => provider.identity.name = ctx.bindings[2].name.clone(),
            8 => provider.kind = ProviderKind::Wintun,
            9 => proof.process.pid = 0,
            10 => proof.process.creation_time = 0,
            11 => provider.identity.if_type = 6,
            _ => provider.identity.tunnel_type = 1,
        }
        assert!(
            validate_member_binding(&ctx, &intent, &proof, &provider).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn complete_mixed_provider_inputs_keep_exact_carrier_then_both_native_members() {
    let (ctx, _, _, a) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    let (_, _, _, b) = fixture(TunnelSlot::B, TunnelTransport::AmneziaWg3);
    let c = ExpectedProvider {
        kind: ProviderKind::Wintun,
        identity: Expected {
            guid: ctx.bindings[0].guid,
            luid: 53_u64 << 48 | 1 << 24,
            index: 70,
            name: ctx.bindings[0].name.clone(),
            description: "Nelomai carrier Tunnel".into(),
            if_type: 53,
            tunnel_type: 0,
        },
    };
    for (carrier, members) in [
        (vec![], vec![]),
        (vec![c.clone()], vec![]),
        (vec![c.clone()], vec![a.clone()]),
        (vec![c.clone()], vec![a.clone(), b.clone()]),
        (vec![], vec![b.clone()]),
    ] {
        let expected = carrier.iter().chain(&members).cloned().collect::<Vec<_>>();
        assert_eq!(
            complete_provider_inputs(&ctx, &carrier, &members),
            Ok(expected)
        );
    }
    for fault in 0..9 {
        let mut carrier = vec![c.clone()];
        let mut members = vec![a.clone(), b.clone()];
        match fault {
            0 => carrier.push(c.clone()),
            1 => members.push(a.clone()),
            2 => carrier[0].kind = ProviderKind::WireGuardNt,
            3 => members[0] = c.clone(),
            4 => members[1] = a.clone(),
            5 => members[1].identity.luid = carrier[0].identity.luid,
            6 => members[1].identity.index = carrier[0].identity.index,
            7 => members[1].identity.guid = [7; 16],
            _ => members[1].identity.name = ctx.bindings[0].name.clone(),
        }
        assert!(
            complete_provider_inputs(&ctx, &carrier, &members).is_err(),
            "fault {fault}"
        );
    }
}

#[cfg(windows)]
#[test]
fn native_inventory_requires_actual_owner_read_and_same_runtime_source_pins() {
    // Compilation contract only: no Windows effect or hardware read runs here.
    fn compose(
        runtime: &crate::windows::member_carrier_key_authority::RuntimeRead,
        image: &crate::windows::member_carrier_module::native::OriginalImage,
        context: Context,
        carrier: std::rc::Rc<crate::windows::member_carrier_payload::native::WintunSource>,
        source: std::rc::Rc<crate::windows::member_carrier_payload::native::MemberSource>,
        controller: &mut crate::member_original::RetainedMember<
            crate::windows::member_files::MemberFiles,
            crate::windows::member_owner::NativeMemberIo<crate::windows::member_files::MemberFiles>,
        >,
    ) -> Result<()> {
        let mut inventory = native::MemberInventory::retain(runtime, context.clone(), carrier)?;
        let _universe =
            crate::windows::member_carrier_wintun::native::OriginalUniverse::new(runtime, image)
                .map_err(|_| Error::Conflict)?
                .with_members(inventory.read_pin())
                .map_err(|_| Error::Conflict)?;
        let original = controller.original_read().map_err(|_| Error::Conflict)?;
        inventory.register(source, original)?;
        let _facts = inventory.read_all()?;
        let running = controller
            .snapshot()
            .map_err(|_| Error::Conflict)?
            .ok_or(Error::Conflict)?;
        // Main publishes actual protected Closing before this point. Sampling
        // releases the inventory borrow before independent observer queries.
        let _live =
            inventory.inspect_closing_full(&context, runtime, image, |live| Ok(live.to_vec()))?;
        let (_, receipt) = controller.stop(&running).map_err(|_| Error::Conflict)?;
        let receipt = std::rc::Rc::new(receipt);
        // Actual durable carrier Closing publication belongs to the coordinator
        // before these calls. This function is a type contract, never invoked.
        inventory.closed(0, &receipt)?;
        inventory.closed(0, &receipt)?;
        inventory.read_pin().inspect_retired_bindings_full(
            &context,
            runtime,
            image,
            |history| {
                assert_eq!(history.len(), 1);
                Ok(())
            },
        )?;
        Ok(())
    }
    let _contract = compose;
}

// Only the journal/native boundary is simulated. Start, Stop ACK issuance,
// SAME-owner retention, receipt verification and the history reader are real.
#[derive(Default)]
struct HistoryState {
    record: Option<crate::member_owner::Record>,
    digest: Option<[u8; 32]>,
    running: bool,
    original: bool,
    original_created: bool,
    absence_error: bool,
    absence_reads: usize,
    original_error: bool,
    original_panic: bool,
    fail_after_stop: bool,
    observed: Option<NativeProof>,
    lost_running_ack: bool,
    panic_running_ack: bool,
}
type HistoryShared = std::rc::Rc<std::cell::RefCell<HistoryState>>;
struct HistoryDisk(HistoryShared);
struct HistoryIo(HistoryShared, NativeProof);
impl crate::member_owner::Journal for HistoryDisk {
    fn load(
        &mut self,
        _: TunnelSlot,
    ) -> crate::member_owner::Result<Option<crate::member_owner::Record>> {
        Ok(self.0.borrow().record.clone())
    }
    fn compare_exchange(
        &mut self,
        _: TunnelSlot,
        expected: Option<&crate::member_owner::Record>,
        desired: &crate::member_owner::Record,
    ) -> crate::member_owner::Result<()> {
        let mut state = self.0.borrow_mut();
        if state.record.as_ref() != expected {
            return Err(crate::member_owner::OwnerError::Conflict);
        }
        state.record = Some(desired.clone());
        if desired.phase == crate::member_owner::Phase::Running {
            assert!(!state.panic_running_ack, "lost Running ACK unwind");
            if state.lost_running_ack {
                return Err(crate::member_owner::OwnerError::Journal);
            }
        }
        Ok(())
    }
}
impl crate::member_owner::MemberIo for HistoryIo {
    fn inspect(
        &mut self,
        _: &Intent,
        retained: Option<&NativeProof>,
    ) -> crate::member_owner::Result<crate::member_owner::Observation> {
        let mut state = self.0.borrow_mut();
        let observed = state.observed.unwrap_or(self.1);
        if !state.running {
            state.absence_reads += 1;
            if state.absence_error {
                return Err(crate::member_owner::OwnerError::Native);
            }
        }
        Ok(crate::member_owner::Observation {
            config_sha256: state.digest,
            service: state
                .running
                .then_some(crate::member_owner::ServiceObservation {
                    exact_spec: true,
                    process: Some(observed.process),
                }),
            alternative_service_present: false,
            interface: state.running.then_some(observed.interface),
            retained_interfaces: if state.running && retained.is_some() {
                vec![observed.interface]
            } else {
                vec![]
            },
        })
    }
    fn inspect_original(
        &mut self,
        intent: &Intent,
        proof: &NativeProof,
    ) -> crate::member_owner::Result<crate::member_owner::Observation> {
        assert!(
            !self.0.borrow().original_panic,
            "original native query unwind"
        );
        if self.0.borrow().original_error {
            return Err(crate::member_owner::OwnerError::Native);
        }
        if !self.0.borrow().original {
            return Err(crate::member_owner::OwnerError::Retired);
        }
        self.inspect(intent, Some(proof))
    }
    fn revoke_original(&mut self) {
        self.0.borrow_mut().original = false;
    }
    fn inspect_original_for_cleanup(
        &mut self,
        intent: &Intent,
        proof: &NativeProof,
    ) -> crate::member_owner::Result<crate::member_owner::Observation> {
        assert!(
            !self.0.borrow().original_panic,
            "cleanup original native query unwind"
        );
        if !self.0.borrow().original_created || self.0.borrow().original_error {
            return Err(crate::member_owner::OwnerError::Retired);
        }
        self.inspect(intent, Some(proof))
    }
    fn write_private_config(
        &mut self,
        intent: &Intent,
        expected: Option<[u8; 32]>,
        _: &str,
    ) -> crate::member_owner::Result<()> {
        let mut state = self.0.borrow_mut();
        if state.digest != expected {
            return Err(crate::member_owner::OwnerError::Conflict);
        }
        state.digest = Some(intent.config_sha256);
        Ok(())
    }
    fn start_fresh(
        &mut self,
        _: &Intent,
        _: Option<&NativeProof>,
    ) -> crate::member_owner::Result<()> {
        self.0.borrow_mut().running = true;
        self.0.borrow_mut().original = true;
        self.0.borrow_mut().original_created = true;
        Ok(())
    }
    fn stop_slot(
        &mut self,
        _: &Intent,
        _: Option<&NativeProof>,
        _: &crate::member_owner::Observation,
    ) -> crate::member_owner::Result<()> {
        let mut state = self.0.borrow_mut();
        state.running = false;
        state.original = false;
        state.original_created = false;
        state.absence_error = state.fail_after_stop;
        Ok(())
    }
    fn rebind(
        &mut self,
        _: &Intent,
        _: &NativeProof,
        _: &crate::member_owner::Observation,
    ) -> crate::member_owner::Result<()> {
        Err(crate::member_owner::OwnerError::Native)
    }
}
type ActualLiveEntry = (
    RetainedEntry<HistoryDisk, HistoryIo, std::rc::Rc<()>>,
    HistoryShared,
    crate::member_original::RetainedMember<HistoryDisk, HistoryIo>,
    crate::member_owner::Record,
);

type PendingFixture = (
    Context,
    PendingEntry<HistoryDisk, HistoryIo, std::rc::Rc<()>>,
    HistoryShared,
    crate::member_original::RetainedMember<HistoryDisk, HistoryIo>,
);
fn pending_fixture() -> PendingFixture {
    let (context, intent, proof, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    let state = HistoryShared::default();
    let owner = crate::member_owner::MemberOwner::from_trusted_engine(
        intent.scope,
        intent.slot,
        intent.transport,
        intent.engine,
        "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\n[Peer]\nPublicKey = test\n",
        HistoryDisk(state.clone()),
        HistoryIo(state.clone(), proof),
    )
    .unwrap();
    let controller = crate::member_original::RetainedMember::new(owner);
    let pending = PendingEntry {
        source: std::rc::Rc::new(()),
        original: controller.pending_read().unwrap(),
        captured: None,
        #[cfg(windows)]
        partial: None,
        closed: None,
    };
    (context, pending, state, controller)
}

#[test]
fn partial_pending_inventory_separates_unknown_service_from_live_providers() {
    // Break: querying a lost-ACK original as Running prevents its separate
    // SAME-SCM cleanup. The exclusion itself is DATA only; native callers must
    // additionally authenticate the opaque PartialCleanup pin for this entry.
    let (context, entry, state, mut owner) = pending_fixture();
    state.borrow_mut().lost_running_ack = true;
    assert!(owner.start_with_prior(None).is_err());
    let mut entries = [Some(entry), None];
    assert_eq!(
        read_pending_members_excluding(
            &context,
            &mut entries,
            [false; 2],
            (true, false, &[0][..]),
            |_, _| Ok(()),
            |_, _| panic!("partial metadata must never become a live SDK provider")
        ),
        Ok(vec![])
    );
    let (published, state_b, mut owner_b, running_b) =
        actual_live_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
    state_b.borrow_mut().fail_after_stop = true;
    assert!(owner_b.stop(&running_b).is_err());
    assert_eq!(
        read_closing_members_with(
            &context,
            &mut [None, Some(published)],
            &[1],
            |_, _| Ok(()),
            |_, _| panic!("stopped SDK reader"),
            |original| original.read_for_cleanup()
        ),
        Ok(vec![])
    );
    // Default Closing has NOT been relaxed; no opaque partial owner here.
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            true,
            false,
            |_, _| Ok(()),
            |_, _| unreachable!()
        ),
        Err(Error::Pending)
    );
}

#[test]
fn partial_pending_inventory_cannot_exclude_live_history_wrong_slot_or_forward_channel() {
    for fault in 0..5 {
        let (context, mut entry, state, mut owner) = pending_fixture();
        state.borrow_mut().lost_running_ack = true;
        assert!(owner.start_with_prior(None).is_err());
        let mut registered = [false; 2];
        let mut channel = (true, false, &[0][..]);
        match fault {
            0 => channel.0 = false,
            1 => channel.1 = true,
            2 => channel.2 = &[2],
            3 => registered[0] = true,
            _ => entry.captured = Some(fixture(TunnelSlot::A, TunnelTransport::WireGuard).3),
        }
        assert!(
            read_pending_members_excluding(
                &context,
                &mut [Some(entry), None],
                registered,
                channel,
                |_, _| Ok(()),
                |_, _| unreachable!()
            )
            .is_err(),
            "{fault}"
        );
    }
}

#[test]
fn pending_registration_retains_original_before_lost_postflight_without_live_reader() {
    let (context, pending, state, mut controller) = pending_fixture();
    let source = pending.source.clone();
    let same = pending.original.read_pin();
    let mut entries = [None, None];
    let calls = Cell::new(0);
    assert_eq!(
        retain_pending(
            &context,
            &mut entries,
            source.clone(),
            pending.original,
            std::rc::Rc::ptr_eq,
            |_, _| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err(Error::Native)
                } else {
                    Ok(())
                }
            }
        ),
        Err(Error::Native)
    );
    assert!(entries[0].as_ref().unwrap().original.same_original(&same));
    retain_pending(
        &context,
        &mut entries,
        source,
        same,
        std::rc::Rc::ptr_eq,
        |_, _| Ok(()),
    )
    .unwrap();
    let running = controller.start_with_prior(None).unwrap();
    state.borrow_mut().original_error = true;
    assert!(controller.original_read().is_err());
    state.borrow_mut().original_error = false;
    let (_, closed) = controller.stop(&running).unwrap();
    let closed = std::rc::Rc::new(closed);
    publish_pending_closed(&context, &mut entries, 0, &closed, |_, _| Ok(())).unwrap();
    assert!(std::rc::Rc::ptr_eq(
        entries[0].as_ref().unwrap().closed.as_ref().unwrap(),
        &closed
    ));
    assert!(entries[0].as_ref().unwrap().captured.is_none());
}

#[test]
fn pending_cleanup_accepts_only_same_original_closed_ack_after_start_error_or_unwind() {
    for unwind in [false, true] {
        let (context, pending, state, mut controller) = pending_fixture();
        let mut entries = [None, None];
        retain_pending(
            &context,
            &mut entries,
            pending.source,
            pending.original,
            std::rc::Rc::ptr_eq,
            |_, _| Ok(()),
        )
        .unwrap();
        state.borrow_mut().lost_running_ack = !unwind;
        state.borrow_mut().panic_running_ack = unwind;
        let start = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            controller.start_with_prior(None)
        }));
        if unwind {
            assert!(start.is_err());
        } else {
            assert!(start.unwrap().is_err());
        }
        assert!(controller.original_read().is_err());
        assert_eq!(
            entries[0].as_mut().unwrap().original.read_for_cleanup(),
            Err(crate::member_owner::OwnerError::Pending)
        );
        let current = controller.snapshot().unwrap().unwrap();
        state.borrow_mut().lost_running_ack = false;
        state.borrow_mut().panic_running_ack = false;
        let (_, receipt) = controller.stop(&current).unwrap();
        let receipt = std::rc::Rc::new(receipt);
        publish_pending_closed(&context, &mut entries, 0, &receipt, |_, _| Ok(())).unwrap();
        publish_pending_closed(&context, &mut entries, 0, &receipt, |_, _| Ok(())).unwrap();
    }
}

#[test]
fn pending_entry_rejects_foreign_owner_source_scope_and_closed_receipt_even_with_equal_json() {
    let (context, pending, _, mut controller) = pending_fixture();
    let (foreign_context, foreign, _, mut other) = pending_fixture();
    assert_eq!(context, foreign_context);
    assert_eq!(pending.original.intent(), foreign.original.intent());
    let source = pending.source.clone();
    let same = pending.original.read_pin();
    let mut entries = [None, None];
    retain_pending(
        &context,
        &mut entries,
        source.clone(),
        pending.original,
        std::rc::Rc::ptr_eq,
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(retain_pending(
        &context,
        &mut entries,
        source.clone(),
        foreign.original,
        std::rc::Rc::ptr_eq,
        |_, _| Ok(())
    )
    .is_err());
    assert!(retain_pending(
        &context,
        &mut entries,
        std::rc::Rc::new(()),
        same.read_pin(),
        std::rc::Rc::ptr_eq,
        |_, _| Ok(())
    )
    .is_err());
    let mut changed = context.clone();
    changed.intent.scope.connection_generation += 1;
    assert!(retain_pending(
        &changed,
        &mut entries,
        source,
        same,
        std::rc::Rc::ptr_eq,
        |_, _| Ok(())
    )
    .is_err());
    let running = controller.start_with_prior(None).unwrap();
    let other_running = other.start_with_prior(None).unwrap();
    assert_eq!(running, other_running);
    let (_, foreign) = other.stop(&other_running).unwrap();
    assert!(publish_pending_closed(
        &context,
        &mut entries,
        0,
        &std::rc::Rc::new(foreign),
        |_, _| Ok(())
    )
    .is_err());
    let (_, exact) = controller.stop(&running).unwrap();
    let exact = std::rc::Rc::new(exact);
    let calls = Cell::new(0);
    assert_eq!(
        publish_pending_closed(&context, &mut entries, 0, &exact, |_, _| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(Error::Native)
            } else {
                Ok(())
            }
        }),
        Err(Error::Native)
    );
    assert!(std::rc::Rc::ptr_eq(
        entries[0].as_ref().unwrap().closed.as_ref().unwrap(),
        &exact
    ));
    publish_pending_closed(&context, &mut entries, 0, &exact, |_, _| Ok(())).unwrap();
    assert!(publish_pending_closed(&changed, &mut entries, 0, &exact, |_, _| Ok(())).is_err());
    assert!(publish_pending_closed(&context, &mut entries, 1, &exact, |_, _| Ok(())).is_err());
}

#[test]
fn pending_unknown_is_not_live_or_absent_until_exact_stop_and_full_empty_queries() {
    let (context, pending, state, mut controller) = pending_fixture();
    let mut entries = [None, None];
    retain_pending(
        &context,
        &mut entries,
        pending.source,
        pending.original,
        std::rc::Rc::ptr_eq,
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            false,
            false,
            |_, _| Ok(()),
            |_, _| panic!("no proof before Start")
        ),
        Ok(vec![])
    );
    state.borrow_mut().lost_running_ack = true;
    assert!(controller.start_with_prior(None).is_err());
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            true,
            false,
            |_, _| Ok(()),
            |_, _| panic!("unknown must not adopt SDK lookup")
        ),
        Err(Error::Pending)
    );
    state.borrow_mut().lost_running_ack = false;
    let current = controller.snapshot().unwrap().unwrap();
    let (_, closed) = controller.stop(&current).unwrap();
    let closed = std::rc::Rc::new(closed);
    publish_pending_closed(&context, &mut entries, 0, &closed, |_, _| Ok(())).unwrap();
    let full_queries = Cell::new(0);
    inspect_mixed_closing_with(
        || {
            Ok((
                vec![1],
                vec![],
                read_terminal_closed_bindings(
                    &context,
                    &mut [None, None],
                    &mut entries,
                    |_, _| Ok(()),
                )?,
            ))
        },
        |live| {
            assert!(live.is_empty());
            full_queries.set(full_queries.get() + 1);
            Ok(())
        },
        |live, history, _| {
            assert!(live.is_empty());
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].proof.interface.guid, [2; 16]);
            assert_eq!(history[0].proof.interface.index, 71);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(full_queries.get(), 2);
    state.borrow_mut().absence_error = true;
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            true,
            true,
            |_, _| Ok(()),
            |_, _| unreachable!()
        ),
        Err(Error::Pending)
    );
}

#[test]
fn pending_committed_original_has_exact_mixed_identity_and_only_captured_closed_history() {
    let (context, pending, state, mut controller) = pending_fixture();
    let (_, _, _, provider) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    let mut entries = [None, None];
    retain_pending(
        &context,
        &mut entries,
        pending.source,
        pending.original,
        std::rc::Rc::ptr_eq,
        |_, _| Ok(()),
    )
    .unwrap();
    let running = controller.start_with_prior(None).unwrap();
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            false,
            false,
            |_, _| Ok(()),
            |_, proof| {
                assert_eq!(Some(*proof), running.proof);
                Ok(provider.clone())
            }
        ),
        Ok(vec![provider.clone()])
    );
    state.borrow_mut().original_error = true;
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            true,
            false,
            |_, _| Ok(()),
            |_, _| unreachable!()
        ),
        Err(Error::Pending)
    );
    state.borrow_mut().original_error = false;
    let (_, receipt) = controller.stop(&running).unwrap();
    publish_pending_closed(
        &context,
        &mut entries,
        0,
        &std::rc::Rc::new(receipt),
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            true,
            false,
            |_, _| Ok(()),
            |_, _| unreachable!()
        ),
        Ok(vec![])
    );
    assert_eq!(
        read_pending_members(
            &context,
            &mut entries,
            [false; 2],
            true,
            true,
            |_, _| Ok(()),
            |_, _| unreachable!()
        ),
        Ok(vec![provider])
    );
}

#[test]
fn mixed_closing_exact_a_history_and_live_b_query_only_live_on_both_sides() {
    let (a, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (b, _, _, _) = actual_live_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
    let (context, _, _, expected_a) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    let expected_b = b.provider.clone();
    let mut entries = [Some(a), Some(b)];
    let mut pending = [None, None];
    let queries = Cell::new(0);
    inspect_mixed_closing_with(
        || {
            let live = read_closing_members(
                &context,
                &mut entries,
                |_, _| Ok(()),
                |_, proof| {
                    assert_eq!(proof.interface.guid, context.bindings[2].guid);
                    Ok(expected_b.clone())
                },
            )?;
            let closed =
                read_mixed_closed_bindings(&context, &mut entries, &mut pending, |_, _| Ok(()))?;
            Ok((vec![1], live, closed))
        },
        |live| {
            assert_eq!(live, &[expected_b.clone()]);
            queries.set(queries.get() + 1);
            Ok(())
        },
        |live, closed, _| {
            assert_eq!(live, &[expected_b.clone()]);
            assert_eq!(closed.len(), 1);
            let comparison = closed[0].comparison_provider(&context)?;
            assert_eq!(comparison.identity.guid, expected_a.identity.guid);
            assert_eq!(comparison.identity.index, expected_a.identity.index);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(queries.get(), 2);
    let (a, sa, mut oa, ra) = actual_live_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (b, sb, mut ob, rb) = actual_live_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
    for (state, owner, record) in [(&sa, &mut oa, &ra), (&sb, &mut ob, &rb)] {
        state.borrow_mut().fail_after_stop = true;
        assert!(owner.stop(record).is_err());
        assert_eq!(
            owner.snapshot().unwrap().unwrap().phase,
            crate::member_owner::Phase::Stopping
        );
    }
    // Both stopped SDK readers must stay out; native callers independently
    // attest each retained opaque cleanup pin before selecting these slots.
    assert_eq!(
        read_closing_members_with(
            &context,
            &mut [Some(a), Some(b)],
            &[0, 1],
            |_, _| Ok(()),
            |_, _| panic!("stopped SDK reader"),
            |original| original.read_for_cleanup()
        ),
        Ok(vec![])
    );
}

#[test]
fn terminal_members_require_actual_closed_originals_not_live_or_missing_ack() {
    let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    let (a, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (b, _) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
    let mut entries = [Some(a), Some(b)];
    let mut pending = [None, None];
    let history =
        read_terminal_closed_bindings(&context, &mut entries, &mut pending, |_, _| Ok(())).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].intent.slot, TunnelSlot::A);
    assert_eq!(history[1].intent.slot, TunnelSlot::B);
    let (a, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (b, _, _, _) = actual_live_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
    let mut entries = [Some(a), Some(b)];
    assert!(
        read_terminal_closed_bindings(&context, &mut entries, &mut pending, |_, _| Ok(())).is_err()
    );
    let (context, entry, _, _) = pending_fixture();
    let mut entries = [None, None];
    let mut pending = [Some(entry), None];
    assert!(
        read_terminal_closed_bindings(&context, &mut entries, &mut pending, |_, _| Ok(())).is_err()
    );
    let (mut a, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (foreign, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    a.closed = foreign.closed;
    let mut entries = [Some(a), None];
    let mut pending = [None, None];
    assert!(
        read_terminal_closed_bindings(&context, &mut entries, &mut pending, |_, _| Ok(())).is_err()
    );
}

#[test]
fn mixed_closing_pending_stop_retires_real_proof_without_ever_capturing_sdk_history() {
    let (context, entry, state, mut member) = pending_fixture();
    let mut pending = [Some(entry), None];
    state.borrow_mut().lost_running_ack = true;
    assert!(member.start_with_prior(None).is_err());
    let running = member.snapshot().unwrap().unwrap();
    state.borrow_mut().lost_running_ack = false;
    let (_, receipt) = member.stop(&running).unwrap();
    publish_pending_closed(
        &context,
        &mut pending,
        0,
        &std::rc::Rc::new(receipt),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(pending[0].as_ref().unwrap().captured.is_none());
    let mut registered = [None, None];
    let closed =
        read_mixed_closed_bindings(&context, &mut registered, &mut pending, |_, _| Ok(())).unwrap();
    assert_eq!(closed.len(), 1);
    assert_eq!(Some(closed[0].proof), running.proof);
    closed[0].comparison_provider(&context).unwrap();
}

#[test]
fn final_empty_inventory_preserves_genuine_pending_retired_proof_without_sdk_lookup() {
    let (context, entry, state, mut member) = pending_fixture();
    let mut pending = [Some(entry), None];
    state.borrow_mut().lost_running_ack = true;
    assert!(member.start_with_prior(None).is_err());
    state.borrow_mut().lost_running_ack = false;
    let current = member.snapshot().unwrap().unwrap();
    let (_, receipt) = member.stop(&current).unwrap();
    publish_pending_closed(
        &context,
        &mut pending,
        0,
        &std::rc::Rc::new(receipt),
        |_, _| Ok(()),
    )
    .unwrap();
    let queries = Cell::new(0);
    inspect_mixed_closing_with(
        || {
            Ok((
                vec![1],
                vec![],
                read_terminal_closed_bindings(
                    &context,
                    &mut [None, None],
                    &mut pending,
                    |_, _| Ok(()),
                )?,
            ))
        },
        |live| {
            assert!(live.is_empty());
            queries.set(queries.get() + 1);
            Ok(())
        },
        |live, history, _| {
            assert!(live.is_empty());
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].proof.interface.guid, [2; 16]);
            assert_eq!(history[0].proof.interface.index, 71);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(queries.get(), 2);
}

#[test]
fn mixed_closing_rechecks_receipt_absence_source_revision_and_live_only_sdk() {
    for fault in 0..6 {
        let (a, state) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
        let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
        let mut entries = [Some(a), None];
        let mut pending = [None, None];
        let reads = Cell::new(0);
        let sdk = Cell::new(0);
        let result = inspect_mixed_closing_with(
            || {
                reads.set(reads.get() + 1);
                let history =
                    read_mixed_closed_bindings(&context, &mut entries, &mut pending, |_, _| {
                        if fault == 2 && reads.get() > 1 {
                            Err(Error::Native)
                        } else {
                            Ok(())
                        }
                    })?;
                Ok((
                    vec![if fault == 3 && reads.get() > 1 { 2 } else { 1 }],
                    vec![],
                    history,
                ))
            },
            |live| {
                assert!(live.is_empty());
                sdk.set(sdk.get() + 1);
                if fault == 4 && sdk.get() == 2 {
                    Err(Error::Native)
                } else {
                    Ok(fault != 5 || sdk.get() == 1)
                }
            },
            |_, _, _| {
                match fault {
                    0 => state.borrow_mut().absence_error = true,
                    1 => state.borrow_mut().running = true,
                    _ => {}
                }
                Ok(())
            },
        );
        assert!(result.is_err(), "fault {fault}");
    }
}

#[test]
fn mixed_closing_foreign_equal_receipt_and_unknown_live_never_enter_history() {
    let (mut a, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (foreign, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    a.closed = foreign.closed;
    let mut entries = [Some(a), None];
    let mut pending = [None, None];
    assert!(
        read_mixed_closed_bindings(&context, &mut entries, &mut pending, |_, _| Ok(())).is_err()
    );
    let (context, entry, state, mut member) = pending_fixture();
    state.borrow_mut().lost_running_ack = true;
    assert!(member.start_with_prior(None).is_err());
    let mut pending = [Some(entry), None];
    let mut entries = [None, None];
    let queries = Cell::new(0);
    assert_eq!(
        inspect_mixed_closing_with(
            || {
                let live = read_pending_members(
                    &context,
                    &mut pending,
                    [false; 2],
                    true,
                    false,
                    |_, _| Ok(()),
                    |_, _| unreachable!(),
                )?;
                let closed = read_mixed_closed_bindings(
                    &context,
                    &mut entries,
                    &mut pending,
                    |_, _| Ok(()),
                )?;
                Ok((vec![1], live, closed))
            },
            |_| {
                queries.set(queries.get() + 1);
                Ok(())
            },
            |_, _, _| Ok(())
        ),
        Err(Error::Pending)
    );
    assert_eq!(queries.get(), 0);
}

#[test]
fn mixed_closing_callback_error_unwind_or_caught_reentry_never_rearms_inventory() {
    for fault in 0..3 {
        let (a, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
        let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
        let mut entries = [Some(a), None];
        let mut pending = [None, None];
        let health = ReadHealth::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            health.cleanup(|| {
                inspect_mixed_closing_with(
                    || {
                        Ok((
                            vec![1],
                            vec![],
                            read_mixed_closed_bindings(
                                &context,
                                &mut entries,
                                &mut pending,
                                |_, _| Ok(()),
                            )?,
                        ))
                    },
                    |live| {
                        assert!(live.is_empty());
                        Ok(())
                    },
                    |_, _, _| match fault {
                        0 => Err(Error::Native),
                        1 => panic!("mixed Closing callback unwind"),
                        _ => {
                            assert!(health.cleanup(|| Ok(())).is_err());
                            Ok(())
                        }
                    },
                )
            })
        }));
        if fault == 1 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(health.forward(|| Ok(())).is_err());
        assert!(health.cleanup(|| Ok(())).is_ok());
    }
}
fn actual_live_entry(slot: TunnelSlot, transport: TunnelTransport) -> ActualLiveEntry {
    let (_, intent, proof, provider) = fixture(slot, transport);
    let state = HistoryShared::default();
    let config =
        "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\nDNS = 9.9.9.9\n[Peer]\nPublicKey = test\n";
    let config = if transport == TunnelTransport::AmneziaWg3 {
        config.replace("[Peer]", "Jc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n[Peer]")
    } else {
        config.to_owned()
    };
    let owner = crate::member_owner::MemberOwner::from_trusted_engine(
        intent.scope,
        slot,
        transport,
        intent.engine,
        &config,
        HistoryDisk(state.clone()),
        HistoryIo(state.clone(), proof),
    )
    .unwrap();
    let mut controller = crate::member_original::RetainedMember::new(owner);
    let running = controller.start_with_prior(None).unwrap();
    let original = controller.original_read().unwrap();
    (
        RetainedEntry {
            source: std::rc::Rc::new(()),
            original,
            provider,
            closed: None,
        },
        state,
        controller,
        running,
    )
}

fn actual_closed_entry(
    slot: TunnelSlot,
    transport: TunnelTransport,
) -> (
    RetainedEntry<HistoryDisk, HistoryIo, std::rc::Rc<()>>,
    HistoryShared,
) {
    let (mut entry, state, mut controller, running) = actual_live_entry(slot, transport);
    let (_, receipt) = controller.stop(&running).unwrap();
    entry.closed = Some(std::rc::Rc::new(receipt));
    (entry, state)
}

#[test]
fn sealed_generation_retirement_keeps_old_originals_without_reopening_the_old_journal() {
    let (context, _, _, _) = fixture(TunnelSlot::B, TunnelTransport::WireGuard);
    let (mut entry, state, mut controller, running) =
        actual_live_entry(TunnelSlot::B, TunnelTransport::WireGuard);
    let (_, receipt) = controller.stop(&running).unwrap();
    let receipt = std::rc::Rc::new(receipt);
    entry.closed = Some(receipt.clone());
    let original = controller.seal_closed_generation(&receipt).unwrap();
    let source = std::rc::Rc::downgrade(&entry.source);
    let mut entries = [None, Some(entry)];
    let mut pending = [None, None];
    let mut retired = Vec::new();
    retire_closed_entries(
        &context,
        1,
        &mut entries,
        &mut pending,
        &mut retired,
        &original,
        &receipt,
    )
    .unwrap();
    assert!(entries[1].is_none());
    assert_eq!(retired.len(), 1);
    assert!(source.upgrade().is_some());
    let reads = state.borrow().absence_reads;
    state.borrow_mut().record = Some(running);
    state.borrow_mut().absence_error = true;
    // This checks only the SAME immutable seal. Current native absence still
    // belongs to the independent Source/SDK gate, never this historic reader.
    retire_closed_entries(
        &context,
        1,
        &mut entries,
        &mut pending,
        &mut retired,
        &original,
        &receipt,
    )
    .unwrap();
    assert_eq!(retired.len(), 1);
    assert_eq!(state.borrow().absence_reads, reads);
}

#[test]
fn sealed_generation_retirement_rejects_equal_foreign_original_and_unclosed_entry() {
    let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    for foreign in [false, true] {
        let (mut entry, _, mut controller, running) =
            actual_live_entry(TunnelSlot::A, TunnelTransport::WireGuard);
        let (_, receipt) = controller.stop(&running).unwrap();
        let receipt = std::rc::Rc::new(receipt);
        let original = controller.seal_closed_generation(&receipt).unwrap();
        if foreign {
            let (other, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
            entry = other;
        }
        // Missing publication on THIS inventory, or an equal foreign owner.
        let mut entries = [Some(entry), None];
        let mut pending = [None, None];
        let mut retired = Vec::new();
        assert!(retire_closed_entries(
            &context,
            0,
            &mut entries,
            &mut pending,
            &mut retired,
            &original,
            &receipt
        )
        .is_err());
        assert!(entries[0].is_some());
        assert!(retired.is_empty());
    }
}

#[test]
fn sealed_generation_retirement_retains_pending_only_original_and_rejects_foreign_pending() {
    for foreign in [false, true] {
        let (context, mut pending, state, mut controller) = pending_fixture();
        let running = controller.start_with_prior(None).unwrap();
        let (_, receipt) = controller.stop(&running).unwrap();
        let receipt = std::rc::Rc::new(receipt);
        pending.closed = Some(receipt.clone());
        let original = controller.seal_closed_generation(&receipt).unwrap();
        if foreign {
            let (_, mut other, _, mut foreign_controller) = pending_fixture();
            let current = foreign_controller.start_with_prior(None).unwrap();
            let (_, foreign_receipt) = foreign_controller.stop(&current).unwrap();
            other.closed = Some(std::rc::Rc::new(foreign_receipt));
            pending = other;
        }
        let source = std::rc::Rc::downgrade(&pending.source);
        let mut entries = [None, None];
        let mut pending = [Some(pending), None];
        let mut retired = Vec::new();
        let result = retire_closed_entries(
            &context,
            0,
            &mut entries,
            &mut pending,
            &mut retired,
            &original,
            &receipt,
        );
        assert_eq!(result.is_err(), foreign);
        assert_eq!(pending[0].is_some(), foreign);
        assert_eq!(retired.len(), usize::from(!foreign));
        assert!(source.upgrade().is_some());
        if !foreign {
            assert!(retired[0].entry.is_none());
            assert!(retired[0].pending.is_some());
            let before = state.borrow().absence_reads;
            state.borrow_mut().record = Some(running);
            state.borrow_mut().absence_error = true;
            retire_closed_entries(
                &context,
                0,
                &mut entries,
                &mut pending,
                &mut retired,
                &original,
                &receipt,
            )
            .unwrap();
            assert_eq!(state.borrow().absence_reads, before);
        }
    }
}

#[test]
fn sealed_generation_postflight_failure_and_unwind_revoke_forward_but_keep_history_roots() {
    for unwind in [false, true] {
        let health = ReadHealth::default();
        let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
        let (mut entry, _, mut controller, running) =
            actual_live_entry(TunnelSlot::A, TunnelTransport::WireGuard);
        let (_, receipt) = controller.stop(&running).unwrap();
        let receipt = std::rc::Rc::new(receipt);
        entry.closed = Some(receipt.clone());
        let original = controller.seal_closed_generation(&receipt).unwrap();
        let source = std::rc::Rc::downgrade(&entry.source);
        let mut entries = [Some(entry), None];
        let mut pending = [None, None];
        let mut retired = Vec::new();
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _flight = RetirementFlight {
                health: &health,
                complete: false,
            };
            health
                .forward(|| {
                    retire_closed_entries(
                        &context,
                        0,
                        &mut entries,
                        &mut pending,
                        &mut retired,
                        &original,
                        &receipt,
                    )
                })
                .unwrap();
            if unwind {
                panic!("native generation postflight interrupted");
            }
            Err::<(), _>(Error::Native)
        }));
        if unwind {
            assert!(attempt.is_err());
        } else {
            assert_eq!(attempt.unwrap(), Err(Error::Native));
        }
        assert!(health.forward(|| Ok(())).is_err());
        assert_eq!(retired.len(), 1);
        assert!(retired[0].entry.is_some());
        assert!(source.upgrade().is_some());
        original.read_history(&receipt).unwrap();
        health.cleanup(|| Ok(())).unwrap();
    }
}

#[test]
fn closing_observation_reads_live_actual_owners_and_mixed_actual_closures() {
    for closed_b in [false, true] {
        let (a, _, _a_controller, _) = actual_live_entry(TunnelSlot::A, TunnelTransport::WireGuard);
        let (mut b, _, mut b_controller, b_running) =
            actual_live_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
        if closed_b {
            let (_, receipt) = b_controller.stop(&b_running).unwrap();
            b.closed = Some(std::rc::Rc::new(receipt));
        }
        let sources = [a.source.clone(), b.source.clone()];
        let providers = [a.provider.clone(), b.provider.clone()];
        let mut entries = [Some(a), Some(b)];
        let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
        let reads = Cell::new(0);
        let health = ReadHealth::default();
        let actual = health
            .cleanup(|| {
                inspect_closing_with(
                    || {
                        reads.set(reads.get() + 1);
                        Ok((
                            vec![3],
                            read_closing_members(
                                &context,
                                &mut entries,
                                |source, _| {
                                    if sources.iter().any(|held| std::rc::Rc::ptr_eq(held, source))
                                    {
                                        Ok(())
                                    } else {
                                        Err(Error::Conflict)
                                    }
                                },
                                |source, proof| {
                                    let index = sources
                                        .iter()
                                        .position(|held| std::rc::Rc::ptr_eq(held, source))
                                        .ok_or(Error::Conflict)?;
                                    assert_eq!(proof.interface.guid, [2 + index as u8; 16]);
                                    Ok(providers[index].clone())
                                },
                            )?,
                        ))
                    },
                    |live| {
                        Ok(live
                            .iter()
                            .map(|p| p.identity.name.clone())
                            .collect::<Vec<_>>())
                    },
                )
            })
            .unwrap();
        assert_eq!(
            actual,
            if closed_b {
                vec!["member-2"]
            } else {
                vec!["member-2", "member-3"]
            }
        );
        assert_eq!(reads.get(), 2);
        for entry in entries.iter_mut().flatten() {
            assert!(entry.original.read().is_err());
        }
        assert_eq!(health.forward(|| Ok(7)), Err(Error::Conflict));
        // Final FULL EMPTY history remains stricter than the restoration read.
        assert!(read_terminal_closed_bindings(
            &context,
            &mut entries,
            &mut [None, None],
            |_, _| Ok(())
        )
        .is_err());
    }
}

#[test]
fn closing_live_queries_deny_source_durable_native_identity_reuse_and_provider_drift() {
    for after in [false, true] {
        for fault in 0..9 {
            let (a, a_state, _controller, running) =
                actual_live_entry(TunnelSlot::A, TunnelTransport::WireGuard);
            let source = a.source.clone();
            let captured = a.provider.clone();
            let (_, _, proof, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
            let mut entries = [Some(a), None];
            let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
            let samples = Cell::new(0);
            let callbacks = Cell::new(0);
            let health = ReadHealth::default();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                health.cleanup(|| {
                    inspect_closing_with(
                        || {
                            samples.set(samples.get() + 1);
                            let bad = !after || samples.get() == 2;
                            if bad {
                                match fault {
                                    1 => a_state.borrow_mut().record = None,
                                    2 => a_state.borrow_mut().original_error = true,
                                    3 => a_state.borrow_mut().original_panic = true,
                                    4 => {
                                        let mut reused = proof;
                                        reused.process.creation_time += 1;
                                        a_state.borrow_mut().observed = Some(reused);
                                    }
                                    5 => a_state.borrow_mut().digest = Some([1; 32]),
                                    6 => a_state.borrow_mut().running = false,
                                    _ => {}
                                }
                            }
                            Ok((
                                vec![3],
                                read_closing_members(
                                    &context,
                                    &mut entries,
                                    |actual, _| {
                                        if !std::rc::Rc::ptr_eq(actual, &source)
                                            || bad && fault == 0
                                        {
                                            Err(Error::Conflict)
                                        } else {
                                            Ok(())
                                        }
                                    },
                                    |_, _| {
                                        let mut seen = captured.clone();
                                        if bad && fault == 7 {
                                            seen.identity.description.push_str("-foreign");
                                        }
                                        if bad && fault == 8 {
                                            seen.identity.index += 1;
                                        }
                                        Ok(seen)
                                    },
                                )?,
                            ))
                        },
                        |live| {
                            assert_eq!(live.len(), 1);
                            callbacks.set(callbacks.get() + 1);
                            Ok(7)
                        },
                    )
                })
            }));
            if fault == 3 {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err(), "after {after}, fault {fault}");
            }
            assert_eq!(callbacks.get(), usize::from(after));
            assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
            a_state.borrow_mut().record = Some(running);
            a_state.borrow_mut().original_error = false;
            a_state.borrow_mut().original_panic = false;
            assert!(entries[0].as_mut().unwrap().original.read().is_err());
        }
    }
}

#[test]
fn closing_mixed_never_treats_missing_foreign_or_reappeared_closure_as_live() {
    for fault in 0..5 {
        let (a, _, _controller, _) = actual_live_entry(TunnelSlot::A, TunnelTransport::WireGuard);
        let (mut b, b_state) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
        let (foreign, _) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
        match fault {
            0 => b.closed = None,
            1 => b.closed = foreign.closed,
            2 => b_state.borrow_mut().running = true,
            3 => b_state.borrow_mut().record = None,
            _ => b_state.borrow_mut().absence_error = true,
        }
        let a_provider = a.provider.clone();
        let mut entries = [Some(a), Some(b)];
        let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
        let health = ReadHealth::default();
        let callbacks = Cell::new(0);
        assert!(
            health
                .cleanup(|| inspect_closing_with(
                    || Ok((
                        vec![3],
                        read_closing_members(
                            &context,
                            &mut entries,
                            |_, _| Ok(()),
                            |_, _| Ok(a_provider.clone())
                        )?
                    )),
                    |_| {
                        callbacks.set(1);
                        Ok(7)
                    },
                ))
                .is_err(),
            "fault {fault}"
        );
        assert_eq!(callbacks.get(), 0);
        assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
        assert!(entries[0].as_mut().unwrap().original.read().is_err());
    }
}

#[test]
fn closing_callback_denies_revision_change_error_unwind_and_caught_reentry() {
    for fault in 0..4 {
        let health = ReadHealth::default();
        let samples = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            health.cleanup(|| {
                inspect_closing_with(
                    || {
                        samples.set(samples.get() + 1);
                        Ok((
                            vec![if fault == 0 && samples.get() == 2 {
                                4
                            } else {
                                3
                            }],
                            vec![],
                        ))
                    },
                    |live| {
                        assert!(live.is_empty());
                        match fault {
                            1 => Err(Error::Native),
                            2 => panic!("closing full native callback unwind"),
                            3 => {
                                assert_eq!(health.cleanup(|| Ok(8)), Err(Error::Conflict));
                                Ok(7)
                            }
                            _ => Ok(7),
                        }
                    },
                )
            })
        }));
        if fault == 2 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err(), "fault {fault}");
        }
        assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
    }
}

#[test]
fn all_actual_registered_closures_and_sources_are_reverified_before_and_after_callback() {
    for failed_index in 0..2 {
        for after in [false, true] {
            let (a, a_state) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
            let (b, b_state) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
            let sources = [a.source.clone(), b.source.clone()];
            let states = [a_state, b_state];
            let mut entries = [Some(a), Some(b)];
            let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
            let source_reads = [Cell::new(0), Cell::new(0)];
            let health = ReadHealth::default();
            let callbacks = Cell::new(0);
            let initial_reads = [
                states[0].borrow().absence_reads,
                states[1].borrow().absence_reads,
            ];
            if !after {
                states[failed_index].borrow_mut().absence_error = true;
            }
            let result = health.cleanup(|| {
                inspect_mixed_closing_with(
                    || {
                        let history = read_terminal_closed_bindings(
                            &context,
                            &mut entries,
                            &mut [None, None],
                            |source, _| {
                                let index = sources
                                    .iter()
                                    .position(|held| std::rc::Rc::ptr_eq(held, source))
                                    .ok_or(Error::Conflict)?;
                                source_reads[index].set(source_reads[index].get() + 1);
                                Ok(())
                            },
                        )?;
                        Ok((vec![3], vec![], history))
                    },
                    |live| {
                        assert!(live.is_empty());
                        Ok(())
                    },
                    |live, retired, _| {
                        assert!(live.is_empty());
                        assert_eq!(retired.len(), 2);
                        callbacks.set(1);
                        states[failed_index].borrow_mut().absence_error = true;
                        Ok(7)
                    },
                )
            });
            assert!(result.is_err(), "owner {failed_index}, after {after}");
            assert_eq!(callbacks.get(), usize::from(after));
            if after {
                assert!(
                    states[failed_index].borrow().absence_reads >= initial_reads[failed_index] + 2
                );
                assert!(source_reads[failed_index].get() >= 3);
            }
            assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
            states[failed_index].borrow_mut().absence_error = false;
            assert_eq!(
                health
                    .cleanup(|| read_terminal_closed_bindings(
                        &context,
                        &mut entries,
                        &mut [None, None],
                        |_, _| Ok(())
                    ))
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
        }
    }
}

#[test]
fn missing_or_foreign_equal_actual_receipt_never_enters_retired_inventory_callback() {
    for foreign in [false, true] {
        let (a, _) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
        let (mut b, _) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
        let (other_b, _) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
        b.closed = if foreign { other_b.closed } else { None };
        let mut entries = [Some(a), Some(b)];
        let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
        let health = ReadHealth::default();
        let queries = Cell::new(0);
        let callbacks = Cell::new(0);
        assert!(health
            .cleanup(|| inspect_mixed_closing_with(
                || Ok((
                    vec![3],
                    vec![],
                    read_terminal_closed_bindings(
                        &context,
                        &mut entries,
                        &mut [None, None],
                        |_, _| Ok(())
                    )?
                )),
                |_| {
                    queries.set(1);
                    Ok(())
                },
                |_, _, _| {
                    callbacks.set(1);
                    Ok(7)
                },
            ))
            .is_err());
        assert_eq!(queries.get(), 0);
        assert_eq!(callbacks.get(), 0);
        assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
    }
}

#[test]
fn actual_retired_history_queries_each_owner_and_source_on_both_sides_of_callback() {
    let (a, a_state) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
    let (b, b_state) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
    let sources = [a.source.clone(), b.source.clone()];
    let mut entries = [Some(a), Some(b)];
    let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
    let initial_reads = [
        a_state.borrow().absence_reads,
        b_state.borrow().absence_reads,
    ];
    let source_reads = [Cell::new(0), Cell::new(0)];
    let health = ReadHealth::default();
    let facts = health
        .cleanup(|| {
            inspect_mixed_closing_with(
                || {
                    let history = read_terminal_closed_bindings(
                        &context,
                        &mut entries,
                        &mut [None, None],
                        |source, _| {
                            let index = sources
                                .iter()
                                .position(|held| std::rc::Rc::ptr_eq(held, source))
                                .ok_or(Error::Conflict)?;
                            source_reads[index].set(source_reads[index].get() + 1);
                            Ok(())
                        },
                    )?;
                    Ok((vec![3], vec![], history))
                },
                |live| {
                    assert!(live.is_empty());
                    Ok(())
                },
                |live, retired, _| {
                    assert!(live.is_empty());
                    assert_eq!(retired.len(), 2);
                    retired
                        .iter()
                        .map(|p| p.comparison_provider(&context).map(|p| p.identity.name))
                        .collect::<Result<Vec<_>>>()
                },
            )
        })
        .unwrap();
    assert_eq!(facts, ["member-2", "member-3"]);
    assert!(a_state.borrow().absence_reads >= initial_reads[0] + 2);
    assert!(b_state.borrow().absence_reads >= initial_reads[1] + 2);
    assert_eq!([source_reads[0].get(), source_reads[1].get()], [4, 4]);
    for entry in entries.iter_mut().flatten() {
        assert!(entry.original.read().is_err());
    }
    assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
}

#[test]
fn callback_durable_stop_or_actual_source_change_denies_retired_result() {
    for index in 0..2 {
        for durable in [false, true] {
            let (a, a_state) = actual_closed_entry(TunnelSlot::A, TunnelTransport::WireGuard);
            let (b, b_state) = actual_closed_entry(TunnelSlot::B, TunnelTransport::AmneziaWg3);
            let sources = [a.source.clone(), b.source.clone()];
            let states = [a_state, b_state];
            let source_changed = [Cell::new(false), Cell::new(false)];
            let mut entries = [Some(a), Some(b)];
            let (context, _, _, _) = fixture(TunnelSlot::A, TunnelTransport::WireGuard);
            let health = ReadHealth::default();
            assert!(
                health
                    .cleanup(|| inspect_mixed_closing_with(
                        || {
                            let history = read_terminal_closed_bindings(
                                &context,
                                &mut entries,
                                &mut [None, None],
                                |source, _| {
                                    let n = sources
                                        .iter()
                                        .position(|held| std::rc::Rc::ptr_eq(held, source))
                                        .ok_or(Error::Conflict)?;
                                    if source_changed[n].get() {
                                        return Err(Error::Conflict);
                                    }
                                    Ok(())
                                },
                            )?;
                            Ok((vec![3], vec![], history))
                        },
                        |live| {
                            assert!(live.is_empty());
                            Ok(())
                        },
                        |_, history, _| {
                            assert_eq!(history.len(), 2);
                            if durable {
                                states[index].borrow_mut().record = None;
                            } else {
                                source_changed[index].set(true);
                            }
                            Ok(7)
                        },
                    ))
                    .is_err(),
                "owner {index}, durable {durable}"
            );
            assert_eq!(health.forward(|| Ok(9)), Err(Error::Conflict));
        }
    }
}
