use super::*;

#[test]
fn module_terminal_original_match_requires_each_same_rc_and_exact_record() {
    let candidate = Rc::new(1);
    let load = Rc::new(2);
    let pair = Rc::new(3);
    let expected = vec![4, 5];
    let original = OriginalRefs {
        candidate: &candidate,
        load: &load,
        pair: &pair,
        expected: &expected,
    };
    assert!(original.matches(&OriginalRefs {
        candidate: &candidate.clone(),
        load: &load.clone(),
        pair: &pair.clone(),
        expected: &expected.clone(),
    }));
    assert!(!original.matches(&OriginalRefs {
        candidate: &Rc::new(1),
        ..original
    }));
    assert!(!original.matches(&OriginalRefs {
        load: &Rc::new(2),
        ..original
    }));
    assert!(!original.matches(&OriginalRefs {
        pair: &Rc::new(3),
        ..original
    }));
    assert!(!original.matches(&OriginalRefs {
        expected: &vec![4, 6],
        ..original
    }));
}

#[test]
fn module_terminal_original_match_is_pure_and_does_not_rearm_a_failed_reader() {
    let candidate = Rc::new(1);
    let load = Rc::new(2);
    let pair = Rc::new(3);
    let expected = vec![4];
    let original = OriginalRefs {
        candidate: &candidate,
        load: &load,
        pair: &pair,
        expected: &expected,
    };
    let read = RetainedRead::<_, u32>::new(candidate.clone());
    assert!(read
        .read(&candidate, &mut Io::empty(), |_| Err(ReadError::Boundary))
        .is_err());
    assert!(original.matches(&original));
    assert!(read.failed.get());
    assert!(read
        .read(&candidate, &mut Io::empty(), |_| panic!(
            "pure match cannot rearm"
        ))
        .is_err());
}

#[test]
fn module_terminal_initial_protocol_retains_actual_creator_publication() {
    let original = Rc::new(7);
    let read = RetainedRead::new(original.clone());
    let mut io = Io::empty();
    io.records[9] = Some(vec![9]);
    read.read(&original, &mut io, |facts| {
        assert_eq!(facts.records[9], Some(vec![9]));
        Ok(())
    })
    .unwrap();
}

#[test]
fn module_terminal_initial_protocol_never_infers_creator_absence() {
    let original = Rc::new(7);
    let read = RetainedRead::new(original.clone());
    let mut io = Io::empty();
    io.records[9] = None;
    assert_eq!(
        read.read(&original, &mut io, |_| Ok(())),
        Err(ReadError::Changed)
    );
    assert!(read.failed.get());
}

#[test]
fn module_terminal_creator_bytes_cannot_replace_actual_publisher_verification() {
    for bytes in [Vec::new(), vec![99]] {
        let original = Rc::new(7);
        let read = RetainedRead::new(original.clone());
        let mut io = Io::empty();
        io.records[9] = Some(bytes.clone());
        assert_eq!(
            read.read(&original, &mut io, |_| panic!("foreign creator")),
            Err(ReadError::Changed)
        );
        assert_eq!(read.records.borrow().as_ref().unwrap()[9], Some(bytes));
        assert!(read.facts.borrow().is_none());
    }
    // Both before and after the factual callback, exact matching bytes cannot
    // replace a failed original publisher/ACK boundary. No retry after repair.
    for at in [4, 13] {
        let original = Rc::new(at);
        let read = RetainedRead::new(original.clone());
        let mut io = BoundaryFault {
            io: Io::empty(),
            at,
            calls: 0,
        };
        assert_eq!(
            read.read(&original, &mut io, |_| Ok(())),
            Err(ReadError::Boundary)
        );
        assert_eq!(io.calls, at);
        assert_eq!(read.records.borrow().as_ref().unwrap()[9], Some(vec![9]));
        assert_eq!(read.facts.borrow().is_some(), at == 13);
        assert_eq!(
            read.read(&original, &mut Io::empty(), |_| panic!(
                "publisher repair cannot rearm"
            )),
            Err(ReadError::Denied)
        );
    }
}

// Only external IO is doubled. The real retained policy owns the root and
// snapshots, performs comparison, controls callback order and poisons errors.
struct Io {
    records: [Option<Vec<u8>>; 10],
    snapshot: u32,
    fail: bool,
}
impl Io {
    fn empty() -> Self {
        Self {
            records: [
                Some(vec![1]),
                Some(vec![2]),
                None,
                None,
                Some(vec![4]),
                None,
                None,
                None,
                None,
                Some(vec![9]),
            ],
            snapshot: 0,
            fail: false,
        }
    }
}
impl ReadIo for Io {
    type Snapshot = u32;
    fn fence(&mut self) -> ReadResult<()> {
        if self.fail {
            Err(ReadError::Boundary)
        } else {
            Ok(())
        }
    }
    fn records(&mut self) -> ReadResult<[Option<Vec<u8>>; 10]> {
        Ok(self.records.clone())
    }
    fn verify_initial(&mut self, bytes: &[u8]) -> ReadResult<()> {
        if bytes == [4] {
            Ok(())
        } else {
            Err(ReadError::Changed)
        }
    }
    fn verify_creator(&mut self, bytes: &[u8]) -> ReadResult<()> {
        if bytes == [9] {
            Ok(())
        } else {
            Err(ReadError::Changed)
        }
    }
    fn native_empty(&mut self) -> ReadResult<()> {
        self.fence()
    }
    fn paths_absent(&mut self) -> ReadResult<()> {
        self.fence()
    }
    fn snapshot(&mut self) -> ReadResult<u32> {
        Ok(self.snapshot)
    }
    fn verify_empty_snapshot(&mut self, s: &u32) -> ReadResult<()> {
        if *s == 0 {
            Ok(())
        } else {
            Err(ReadError::Changed)
        }
    }
}

#[test]
fn module_terminal_read_retains_original_and_complete_facts_before_callback() {
    let original = Rc::new(7);
    let read = RetainedRead::new(original.clone());
    read.read(&original, &mut Io::empty(), |facts| {
        assert!(read.facts.borrow().is_some());
        assert_eq!(facts.records[4], Some(vec![4]));
        assert_eq!(facts.snapshot, 0);
        Ok(())
    })
    .unwrap();
    assert!(Rc::ptr_eq(&original, &read.original));
}

#[test]
fn module_terminal_read_callback_error_cannot_erase_receipt_or_rearm() {
    let original = Rc::new(7);
    let read = RetainedRead::new(original.clone());
    assert_eq!(
        read.read(&original, &mut Io::empty(), |_| Err(ReadError::Boundary)),
        Err(ReadError::Boundary)
    );
    assert!(read.facts.borrow().is_some());
    assert_eq!(
        read.read(&original, &mut Io::empty(), |_| Ok(())),
        Err(ReadError::Denied)
    );
}

#[test]
fn module_terminal_read_rejects_equal_foreign_root_before_observations() {
    let original = Rc::new(7);
    let read = RetainedRead::<_, u32>::new(original.clone());
    assert_eq!(
        read.read(&Rc::new(7), &mut Io::empty(), |_| panic!(
            "foreign callback"
        )),
        Err(ReadError::Denied)
    );
    assert!(read.records.borrow().is_none());
    assert!(read.read(&original, &mut Io::empty(), |_| Ok(())).is_err());
}

#[test]
fn module_terminal_read_rejects_every_effect_kind_and_missing_publication() {
    for index in [2, 3, 5, 6, 7, 8] {
        let original = Rc::new(index);
        let read = RetainedRead::<_, u32>::new(original.clone());
        let mut io = Io::empty();
        io.records[index] = Some(vec![99]);
        assert_eq!(
            read.read(&original, &mut io, |_| panic!("effect callback")),
            Err(ReadError::Changed)
        );
        assert!(read.records.borrow().is_some());
        assert!(read.read(&original, &mut Io::empty(), |_| Ok(())).is_err());
    }
    for index in [0, 1, 4, 9] {
        let original = Rc::new(index);
        let read = RetainedRead::<_, u32>::new(original.clone());
        let mut io = Io::empty();
        io.records[index] = None;
        assert!(read
            .read(&original, &mut io, |_| panic!("missing ACK callback"))
            .is_err());
    }
}

#[test]
fn module_terminal_read_rejects_foreign_initial_ack_and_nonempty_guard() {
    for (initial, snapshot) in [(vec![8], 0), (vec![4], 1)] {
        let original = Rc::new(7);
        let read = RetainedRead::<_, u32>::new(original.clone());
        let mut io = Io::empty();
        io.records[4] = Some(initial);
        io.snapshot = snapshot;
        assert_eq!(
            read.read(&original, &mut io, |_| panic!("foreign facts callback")),
            Err(ReadError::Changed)
        );
        assert!(read.read(&original, &mut Io::empty(), |_| Ok(())).is_err());
    }
}

#[test]
fn module_terminal_read_unwind_and_swallowed_reentry_poison_retained_facts() {
    let original = Rc::new(7);
    let read = RetainedRead::new(original.clone());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = read.read(&original, &mut Io::empty(), |_| panic!("postflight unwind"));
    }))
    .is_err());
    assert!(read.facts.borrow().is_some());
    assert!(!read.busy.get());
    assert!(read.read(&original, &mut Io::empty(), |_| Ok(())).is_err());

    let read = RetainedRead::new(original.clone());
    assert_eq!(
        read.read(&original, &mut Io::empty(), |_| {
            assert_eq!(
                read.read(&original, &mut Io::empty(), |_| Ok(())),
                Err(ReadError::Busy)
            );
            Ok(())
        }),
        Err(ReadError::Denied)
    );
    assert!(read.facts.borrow().is_some());
    assert!(read.read(&original, &mut Io::empty(), |_| Ok(())).is_err());
}

struct ChangingIo {
    io: Io,
    reads: u32,
    change: usize,
}
impl ReadIo for ChangingIo {
    type Snapshot = u32;
    fn fence(&mut self) -> ReadResult<()> {
        self.io.fence()
    }
    fn records(&mut self) -> ReadResult<[Option<Vec<u8>>; 10]> {
        self.reads += 1;
        if self.reads == 2 {
            self.io.records[self.change] = Some(vec![88]);
        }
        self.io.records()
    }
    fn verify_initial(&mut self, b: &[u8]) -> ReadResult<()> {
        self.io.verify_initial(b)
    }
    fn verify_creator(&mut self, b: &[u8]) -> ReadResult<()> {
        self.io.verify_creator(b)
    }
    fn native_empty(&mut self) -> ReadResult<()> {
        self.io.native_empty()
    }
    fn paths_absent(&mut self) -> ReadResult<()> {
        self.io.paths_absent()
    }
    fn snapshot(&mut self) -> ReadResult<u32> {
        self.io.snapshot()
    }
    fn verify_empty_snapshot(&mut self, s: &u32) -> ReadResult<()> {
        self.io.verify_empty_snapshot(s)
    }
}

#[test]
fn module_terminal_read_all_ten_postflight_records_must_be_exact() {
    for change in 0..10 {
        let original = Rc::new(change);
        let read = RetainedRead::new(original.clone());
        let mut io = ChangingIo {
            io: Io::empty(),
            reads: 0,
            change,
        };
        assert!(read.read(&original, &mut io, |_| Ok(())).is_err());
        assert!(read.facts.borrow().is_some());
        assert!(read.failed.get());
    }
}

#[test]
fn module_terminal_read_drop_never_retries_io_or_replaces_the_original() {
    let original = Rc::new(7);
    {
        let read = RetainedRead::new(original.clone());
        let mut io = Io::empty();
        io.fail = true;
        assert!(read.read(&original, &mut io, |_| Ok(())).is_err());
        assert!(read.records.borrow().is_none());
        assert_eq!(Rc::strong_count(&original), 2);
    }
    assert_eq!(Rc::strong_count(&original), 1);
}

struct BoundaryFault {
    io: Io,
    at: usize,
    calls: usize,
}
impl BoundaryFault {
    fn step(&mut self) -> ReadResult<()> {
        self.calls += 1;
        if self.calls == self.at {
            Err(ReadError::Boundary)
        } else {
            Ok(())
        }
    }
}
impl ReadIo for BoundaryFault {
    type Snapshot = u32;
    fn fence(&mut self) -> ReadResult<()> {
        self.step()
    }
    fn records(&mut self) -> ReadResult<[Option<Vec<u8>>; 10]> {
        self.step()?;
        self.io.records()
    }
    fn verify_initial(&mut self, bytes: &[u8]) -> ReadResult<()> {
        self.step()?;
        self.io.verify_initial(bytes)
    }
    fn verify_creator(&mut self, bytes: &[u8]) -> ReadResult<()> {
        self.step()?;
        self.io.verify_creator(bytes)
    }
    fn native_empty(&mut self) -> ReadResult<()> {
        self.step()
    }
    fn paths_absent(&mut self) -> ReadResult<()> {
        self.step()
    }
    fn snapshot(&mut self) -> ReadResult<u32> {
        self.step()?;
        self.io.snapshot()
    }
    fn verify_empty_snapshot(&mut self, snapshot: &u32) -> ReadResult<()> {
        self.step()?;
        self.io.verify_empty_snapshot(snapshot)
    }
}

// Break: accepting a failed native/protected/source/timing boundary or retrying
// it after the caller repairs external facts. Seventeen independently fallible
// observations are required by the production policy; every failure is sticky.
#[test]
fn module_terminal_read_each_external_boundary_failure_denies_without_retry() {
    for at in 1..=17 {
        let original = Rc::new(at);
        let read = RetainedRead::new(original.clone());
        let mut io = BoundaryFault {
            io: Io::empty(),
            at,
            calls: 0,
        };
        assert_eq!(
            read.read(&original, &mut io, |_| Ok(())),
            Err(ReadError::Boundary),
            "boundary {at}"
        );
        assert!(read.failed.get());
        let stopped_at = io.calls;
        assert_eq!(
            read.read(&original, &mut io, |_| Ok(())),
            Err(ReadError::Denied)
        );
        assert_eq!(io.calls, stopped_at);
        if at >= 8 {
            assert!(read.facts.borrow().is_some());
        }
    }
}

struct RegistryIo {
    names: Vec<String>,
    present: Option<&'static str>,
    unavailable: bool,
}
impl RegistryRead for RegistryIo {
    type Key = u32;
    fn interfaces(&mut self) -> ReadResult<u32> {
        if self.unavailable {
            Err(ReadError::Boundary)
        } else {
            Ok(1)
        }
    }
    fn name(&mut self, _: &u32) -> ReadResult<String> {
        if self.names.len() == 1 {
            Ok(self.names[0].clone())
        } else {
            Ok(self.names.remove(0))
        }
    }
    fn open(&mut self, _: &u32, child: &str) -> ReadResult<Option<u32>> {
        Ok(self.present.filter(|p| *p == child).map(|_| 2))
    }
}
const CHILDREN: [&str; 3] = [
    "{00000000-0000-0000-0000-000000000001}",
    "{00000000-0000-0000-0000-000000000002}",
    "{00000000-0000-0000-0000-000000000003}",
];
fn registry_io() -> RegistryIo {
    RegistryIo {
        names: vec![
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces".into(),
        ],
        present: None,
        unavailable: false,
    }
}

#[test]
fn module_terminal_registry_reads_exact_three_absent_children_of_current_parent() {
    read_registry_absent(&mut registry_io(), &CHILDREN).unwrap();
    for child in CHILDREN {
        let mut io = registry_io();
        io.present = Some(child);
        assert_eq!(
            read_registry_absent(&mut io, &CHILDREN),
            Err(ReadError::Changed)
        );
    }
}

#[test]
fn module_terminal_registry_parent_drift_unknown_and_path_escape_deny() {
    let mut io = registry_io();
    io.names.push(
        r"\registry\machine\system\controlset002\services\tcpip\parameters\interfaces".into(),
    );
    assert_eq!(
        read_registry_absent(&mut io, &CHILDREN),
        Err(ReadError::Changed)
    );
    for parent in [
        r"\registry\user\system\controlset001\services\tcpip\parameters\interfaces",
        r"\registry\machine\system\controlset000\services\tcpip\parameters\interfaces",
    ] {
        let mut io = registry_io();
        io.names = vec![parent.into()];
        assert_eq!(
            read_registry_absent(&mut io, &CHILDREN),
            Err(ReadError::Changed)
        );
    }
    let mut io = registry_io();
    io.unavailable = true;
    assert_eq!(
        read_registry_absent(&mut io, &CHILDREN),
        Err(ReadError::Boundary)
    );
    let mut escape = CHILDREN;
    escape[1] = r"{00000000-0000-0000-0000-000000000002}\other";
    assert_eq!(
        read_registry_absent(&mut registry_io(), &escape),
        Err(ReadError::Changed)
    );
}
