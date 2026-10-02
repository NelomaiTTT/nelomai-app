use super::*;
use std::{cell::Cell, rc::Rc};

struct Resource {
    value: u64,
    dropped: Rc<Cell<u32>>,
}
impl Drop for Resource {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
fn resource(value: u64, dropped: &Rc<Cell<u32>>) -> Resource {
    Resource {
        value,
        dropped: dropped.clone(),
    }
}

#[test]
fn successful_native_close_is_exactly_once_and_read_pins_keep_original_resource() {
    // Break caught: duplicate raw close or drop of original module/source while
    // a creator inventory still needs the actual close acknowledgement.
    let dropped = Rc::new(Cell::new(0));
    let closes = Cell::new(0);
    let owner = OriginalReceipt::acknowledged(resource(7, &dropped));
    let read = owner.read_pin();
    assert_eq!(read.live_resource().unwrap().value, 7);
    owner
        .close(|r| {
            assert_eq!(r.value, 7);
            closes.set(closes.get() + 1);
        })
        .unwrap();
    assert_eq!(closes.get(), 1);
    assert_eq!(dropped.get(), 0);
    assert!(matches!(read.live_resource(), Err(Error::Retired)));
    let closed = read.take_closed().unwrap();
    assert!(read.verify_closed(&closed).is_ok());
    assert!(matches!(read.take_closed(), Err(Error::Retired)));
    drop(read);
    assert_eq!(dropped.get(), 0);
    drop(closed);
    assert_eq!(dropped.get(), 1);
}

#[test]
fn equal_numeric_resources_are_not_the_same_original_close_ack() {
    let dropped = Rc::new(Cell::new(0));
    let a = OriginalReceipt::acknowledged(resource(17, &dropped));
    let b = OriginalReceipt::acknowledged(resource(17, &dropped));
    let ar = a.read_pin();
    let br = b.read_pin();
    a.close(|_| {}).unwrap();
    b.close(|_| {}).unwrap();
    let ack = ar.take_closed().unwrap();
    assert!(ar.verify_closed(&ack).is_ok());
    assert!(matches!(br.verify_closed(&ack), Err(Error::Conflict)));
}

#[test]
fn unclosed_drop_does_not_release_pins_or_fabricate_closure() {
    // Caller may lose its effect owner, but cannot implicitly close/adopt by
    // metadata or unload code beneath a still-open original resource.
    let dropped = Rc::new(Cell::new(0));
    let owner = OriginalReceipt::acknowledged(resource(7, &dropped));
    let read = owner.read_pin();
    assert!(matches!(read.take_closed(), Err(Error::Pending)));
    drop(owner);
    assert_eq!(read.live_resource().unwrap().value, 7);
    drop(read);
    assert_eq!(dropped.get(), 0);
}

#[test]
fn unknown_native_close_outcome_never_rearms_live_read_or_close_receipt() {
    let dropped = Rc::new(Cell::new(0));
    let owner = OriginalReceipt::acknowledged(resource(7, &dropped));
    let read = owner.read_pin();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.close(|_| panic!("unknown native return"))
    }));
    assert!(result.is_err());
    assert!(matches!(read.live_resource(), Err(Error::Pending)));
    assert!(matches!(read.take_closed(), Err(Error::Pending)));
    drop(read);
    assert_eq!(dropped.get(), 0);
}

#[test]
fn pending_close_is_observable_before_the_actual_native_call_returns() {
    let dropped = Rc::new(Cell::new(0));
    let owner = OriginalReceipt::acknowledged(resource(7, &dropped));
    let read = owner.read_pin();
    owner
        .close(|_| {
            assert!(matches!(read.live_resource(), Err(Error::Pending)));
            assert!(matches!(read.take_closed(), Err(Error::Pending)));
        })
        .unwrap();
    assert!(read.take_closed().is_ok());
}

#[test]
fn each_derived_read_pin_retains_the_same_actual_acknowledged_resource() {
    let dropped = Rc::new(Cell::new(0));
    let owner = OriginalReceipt::acknowledged(resource(7, &dropped));
    let a = owner.read_pin();
    let b = a.read_pin();
    owner.close(|_| {}).unwrap();
    let closed = a.take_closed().unwrap();
    assert!(b.verify_closed(&closed).is_ok());
    drop(a);
    drop(closed);
    assert_eq!(dropped.get(), 0);
    drop(b);
    assert_eq!(dropped.get(), 1);
}

#[test]
fn original_ack_is_observer_retained_before_any_fallible_post_create_step() {
    // Break: retaining registry proof only after capture loses actual-create
    // provenance precisely when the first native/provider observation fails.
    let dropped = Rc::new(Cell::new(0));
    let mut retained = None;
    let owner = OriginalReceipt::acknowledged_then(resource(19, &dropped), |read| {
        retained = Some(read);
    });
    let read = retained.as_ref().unwrap();
    assert_eq!(read.live_resource().unwrap().value, 19);
    // Simulate fallible post-create capture without permitting adoption/close.
    let observed: Result<()> = Err(Error::Native);
    assert!(observed.is_err());
    assert_eq!(dropped.get(), 0);
    owner.close(|r| assert_eq!(r.value, 19)).unwrap();
    let closed = read.take_closed().unwrap();
    assert!(read.verify_closed(&closed).is_ok());
}

#[test]
fn observer_unwind_never_implicitly_closes_or_releases_actual_new_ack() {
    let dropped = Rc::new(Cell::new(0));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OriginalReceipt::acknowledged_then(resource(29, &dropped), |read| {
            assert_eq!(read.live_resource().unwrap().value, 29);
            panic!("unknown publication outcome");
        })
    }));
    assert!(result.is_err());
    assert_eq!(dropped.get(), 0);
}
