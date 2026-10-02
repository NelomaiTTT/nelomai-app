use super::*;
#[test]
fn uncaptured_physical_plan_is_not_an_empty_capture() {
    let plans = PhysicalPlans::<u32>::default();
    assert!(plans.current().is_err());
    assert!(plans.accepts_saved(Some(&[])).is_err());
    assert!(plans.accepts_saved(None).is_ok());
}

#[test]
fn physical_capture_attach_retire_keep_exact_current_and_prior_obligations() {
    let mut plans = PhysicalPlans::default();
    plans.retain(3, vec![11u32]).unwrap();
    assert_eq!(plans.current().unwrap(), vec![11]);
    assert!(plans.accepts_saved(Some(&[11])).is_err());
    plans.begin_publication().unwrap();
    plans.accepts_saved(Some(&[11])).unwrap();
    plans.ack_publication().unwrap();
    plans.retain(8, vec![11, 22]).unwrap();
    assert_eq!(plans.current().unwrap(), vec![11, 22]);
    plans.accepts_saved(Some(&[11])).unwrap();
    assert!(plans.accepts_saved(Some(&[11, 22])).is_err());
    plans.begin_publication().unwrap();
    plans.ack_publication().unwrap();
    plans.retain(13, vec![22]).unwrap();
    assert_eq!(plans.current().unwrap(), vec![22]);
    assert_eq!(plans.obligations(), vec![11, 22]);
    assert!(plans.accepts_saved(Some(&[11, 22, 33])).is_err());
    plans.begin_publication().unwrap();
    plans.ack_publication().unwrap();
    assert!(plans.accepts_saved(Some(&[11, 22])).is_err());
    plans.accepts_saved(Some(&[22])).unwrap();
}

#[test]
fn physical_lost_publication_ack_retains_capture_but_refuses_next_plan() {
    let mut plans = PhysicalPlans::default();
    plans.retain(3, vec![11u32]).unwrap();
    plans.begin_publication().unwrap();
    // Publication may have applied but did not ACK. Equal bytes are facts,
    // not permission to continue or overwrite the retained capture.
    plans.accepts_saved(Some(&[11])).unwrap();
    assert!(plans.retain(8, vec![22]).is_err());
    assert_eq!(plans.current().unwrap(), vec![11]);
    assert_eq!(plans.obligations(), vec![11]);
}

#[test]
fn physical_same_or_stale_capture_denies_even_equal_paths() {
    let mut plans = PhysicalPlans::default();
    plans.retain(3, vec![11u32]).unwrap();
    plans.begin_publication().unwrap();
    plans.ack_publication().unwrap();
    assert!(plans.retain(3, vec![11]).is_err());
    assert!(plans.retain(2, vec![11]).is_err());
    assert_eq!(plans.current().unwrap(), vec![11]);
}

#[test]
fn physical_capture_before_publication_cannot_be_replaced_or_adopt_saved_target() {
    let mut plans = PhysicalPlans::default();
    plans.retain(3, vec![11u32]).unwrap();
    assert!(plans.retain(8, vec![22]).is_err());
    assert!(plans.accepts_saved(Some(&[11])).is_err());
    assert!(plans.ack_publication().is_err());
    assert_eq!(plans.current().unwrap(), vec![11]);
    assert_eq!(plans.obligations(), vec![11]);
}

#[test]
fn physical_equal_paths_do_not_erase_unacknowledged_new_span_capture() {
    let mut plans = PhysicalPlans::default();
    plans.retain(3, vec![11u32]).unwrap();
    plans.begin_publication().unwrap();
    plans.ack_publication().unwrap();
    plans.retain(8, vec![11]).unwrap();
    assert!(plans.retain(13, vec![22]).is_err());
    assert_eq!(plans.current().unwrap(), vec![11]);
    assert_eq!(plans.obligations(), vec![11]);
}

#[test]
fn physical_capture_bound_failure_keeps_actual_prior_capture_and_publication() {
    let mut plans = PhysicalPlans::default();
    plans.retain(3, vec![11u32]).unwrap();
    plans.begin_publication().unwrap();
    plans.ack_publication().unwrap();
    assert!(plans.retain(8, vec![22; 32769]).is_err());
    assert_eq!(plans.current().unwrap(), vec![11]);
    assert_eq!(plans.obligations(), vec![11]);
    plans.accepts_saved(Some(&[11])).unwrap();
}

#[test]
fn physical_capture_remains_retained_when_owner_postflight_or_reentry_fails() {
    let plans = RefCell::new(PhysicalPlans::default());
    let fence = EffectFence::default();
    {
        let _call = fence.enter(false).unwrap();
        plans.borrow_mut().retain(3, vec![11u32]).unwrap();
        assert!(fence.enter(false).is_err());
        assert!(fence.require(false).is_err());
    }
    assert_eq!(plans.borrow().current().unwrap(), vec![11]);
    assert!(fence.enter(false).is_err());
}
#[test]
fn every_actual_dns_attempt_is_retained_before_sdk_failure_or_unwind() {
    let count = Cell::new(0);
    begin_dns_effect(&count).unwrap();
    assert_eq!(count.get(), 1);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        begin_dns_effect(&count).unwrap();
        panic!("SDK did not return ACK");
    }))
    .is_err());
    assert_eq!(count.get(), 2);
    count.set(32768);
    assert!(begin_dns_effect(&count).is_err());
    assert_eq!(count.get(), 32768);
}
use crate::member_dns::{OwnedInterface, Settings};
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, rc::Rc};

fn snapshot() -> dns::Snapshot {
    dns::Snapshot {
        interface: OwnedInterface {
            scope: nelomai_client_tunnel::redundancy::SessionScope {
                runtime: RuntimeSlot::Stable,
                session_id: "11111111-1111-4111-8111-111111111111".into(),
                runtime_generation: 1,
                connection_generation: 1,
            },
            guid: [1; 16],
            luid: 12,
            index: 13,
        },
        settings: Settings {
            version: 1,
            flags: 0,
            domain: None,
            name_server: None,
            search_list: None,
            registration_enabled: 0,
            register_adapter_name: 0,
            enable_llmnr: 0,
            query_adapter_name: 0,
            profile_name_server: None,
        },
    }
}
struct World {
    actual: dns::Snapshot,
    saved: Option<DnsRecord>,
    fail_save: usize,
    saves: usize,
    writes: usize,
    fail_write: bool,
    retained_ack: Option<dns::Snapshot>,
    fail_after_ack: bool,
}
#[derive(Clone)]
struct Io(Rc<RefCell<World>>);
impl DnsSystem for Io {
    fn read(&mut self) -> io::Result<dns::Snapshot> {
        Ok(self.0.borrow().actual.clone())
    }
    fn exchange(
        &mut self,
        before: &dns::Snapshot,
        after: &dns::Snapshot,
    ) -> io::Result<dns::Snapshot> {
        let mut w = self.0.borrow_mut();
        if &w.actual != before {
            return Err(conflict());
        }
        w.writes += 1;
        w.actual = after.clone();
        if w.fail_write {
            return Err(conflict());
        }
        w.retained_ack = Some(w.actual.clone());
        if w.fail_after_ack {
            return Err(conflict());
        }
        Ok(w.actual.clone())
    }
    fn retained_ack(&mut self) -> io::Result<Option<dns::Snapshot>> {
        Ok(self.0.borrow().retained_ack.clone())
    }
}
impl DnsJournal for Io {
    fn save(&mut self, value: Option<&DnsRecord>) -> io::Result<()> {
        let mut w = self.0.borrow_mut();
        w.saves += 1;
        if w.saves == w.fail_save {
            return Err(conflict());
        }
        w.saved = value.cloned();
        Ok(())
    }
}
fn owner(fail_save: usize) -> (DnsOwner<Io, Io>, Rc<RefCell<World>>) {
    let w = Rc::new(RefCell::new(World {
        actual: snapshot(),
        saved: None,
        fail_save,
        saves: 0,
        writes: 0,
        fail_write: false,
        retained_ack: None,
        fail_after_ack: false,
    }));
    (DnsOwner::fresh(Io(w.clone()), Io(w.clone())), w)
}
#[test]
fn dns_ack_survives_failed_commit_and_restores_original_baseline() {
    let (mut o, w) = owner(3);
    assert!(o.select(&["8.8.8.8".parse().unwrap()]).is_err());
    assert_eq!(
        w.borrow().actual.settings.name_server.as_deref(),
        Some("8.8.8.8")
    );
    assert!(o.select(&["1.1.1.1".parse().unwrap()]).is_err());
    o.cleanup().unwrap();
    assert_eq!(w.borrow().actual, snapshot());
    assert_eq!(w.borrow().writes, 2);
    assert!(w.borrow().saved.is_none());
}
#[test]
fn failed_pending_publication_never_writes_and_can_cleanup() {
    let (mut o, w) = owner(2);
    assert!(o.select(&["8.8.8.8".parse().unwrap()]).is_err());
    assert_eq!(w.borrow().writes, 0);
    o.cleanup().unwrap();
    assert_eq!(w.borrow().actual, snapshot());
}
#[test]
fn uncertain_dns_write_is_not_adopted_from_matching_metadata() {
    let (mut o, w) = owner(0);
    w.borrow_mut().fail_write = true;
    assert!(o.select(&["8.8.8.8".parse().unwrap()]).is_err());
    w.borrow_mut().fail_write = false;
    assert!(o.cleanup().is_err());
    assert_eq!(w.borrow().writes, 1);
    assert!(w.borrow().saved.as_ref().unwrap().pending.is_some());
}
#[test]
fn foreign_dns_change_is_never_overwritten() {
    let (mut o, w) = owner(0);
    o.select(&["8.8.8.8".parse().unwrap()]).unwrap();
    w.borrow_mut().actual.settings.name_server = Some("1.1.1.1".into());
    assert!(o.cleanup().is_err());
    assert_eq!(w.borrow().writes, 1);
}
#[test]
fn acknowledged_dns_effect_survives_source_postflight_failure_for_cleanup_only() {
    let (mut o, w) = owner(0);
    w.borrow_mut().fail_after_ack = true;
    assert!(o.select(&["8.8.8.8".parse().unwrap()]).is_err());
    assert_eq!(w.borrow().writes, 1);
    w.borrow_mut().fail_after_ack = false;
    o.cleanup().unwrap();
    assert_eq!(w.borrow().actual, snapshot());
    assert_eq!(w.borrow().writes, 2);
}
#[test]
fn serialized_failure_and_unwind_irreversibly_fence_forward_only() {
    let fence = EffectFence::default();
    {
        let _call = fence.enter(false).unwrap();
        assert!(fence.enter(false).is_err());
    }
    assert!(fence.enter(false).is_err());
    fence.enter(true).unwrap().finish();
    assert!(fence.enter(false).is_err());
    let other = EffectFence::default();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _call = other.enter(false).unwrap();
        panic!("test");
    }));
    assert!(other.enter(false).is_err());
    other.enter(true).unwrap().finish();
}
#[test]
fn retained_route_requires_latest_original_sdk_ack_not_equal_pending_row() {
    use crate::member_routes::{NativeProof, Row};
    use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
    let row = Row::static_route(
        RouteValue {
            destination: "9.9.9.9/32".parse().unwrap(),
            scope: RouteScope::WindowsInterface(13),
            interface: 13,
            gateway: None,
            metric: 3,
        },
        NativeProof {
            index: 13,
            luid: 12,
        },
    );
    let mut attempts = vec![RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: true,
    }];
    assert_eq!(retained_route(&attempts, &row).unwrap(), Some(row.clone()));
    attempts.push(RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: false,
    });
    assert!(retained_route(&attempts, &row).is_err());
    attempts.last_mut().unwrap().acknowledged = true;
    attempts.last_mut().unwrap().deleting = true;
    assert!(retained_route(&attempts, &row).unwrap().is_none());
}
#[test]
fn dns_preflight_rejects_unsupported_servers_without_publication_or_effects() {
    let (mut o, w) = owner(0);
    assert!(o.preflight(&["2001:db8::53".parse().unwrap()]).is_err());
    assert!(o.preflight(&["8.8.8.8".parse().unwrap()]).is_ok());
    assert_eq!(w.borrow().writes, 0);
    assert_eq!(w.borrow().saves, 0);
}
#[test]
fn swallowed_cleanup_reentry_taints_outer_call_but_next_cleanup_can_retry() {
    let fence = EffectFence::default();
    {
        let _outer = fence.enter(true).unwrap();
        assert!(fence.enter(true).is_err());
        assert!(fence.require(true).is_err());
    }
    let next = fence.enter(true).unwrap();
    fence.require(true).unwrap();
    next.finish();
    assert!(fence.enter(false).is_err());
}
