//! Addressed Windows routes, not policy discovery or probe isolation.
//!
//! The privileged owner must hold its mutation lock and persist NetworkOwner
//! intent before CAS. IP Helper has no atomic compare-and-swap against external
//! writers; every failure (including lost acknowledgements) needs owner readback.
//! Compatible static metadata is not ownership: never adopt a preexisting row.

use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::network::{
    NetworkSystem, NetworkValue, ResourceKey, RouteScope, RouteValue,
};
use std::io;

pub const MAX_TABLE_ROWS: usize = 65_536;

/// Privileged, live owner evidence only; deliberately no serde/IPC support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeProof {
    pub index: u32,
    pub luid: u64,
}

pub trait IdentityCheck {
    /// Revalidate the captured member identity, never discover/adopt by index.
    fn verify(&mut self, index: u32) -> io::Result<NativeProof>;
}
impl<F: FnMut(u32) -> io::Result<NativeProof>> IdentityCheck for F {
    fn verify(&mut self, index: u32) -> io::Result<NativeProof> {
        self(index)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub route: RouteValue,
    pub luid: u64,
    pub protocol: i32,
    pub origin: i32,
    pub site_prefix_length: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    /// Loopback, AutoconfigureAddress, Publish, Immortal (raw BOOLEAN values).
    pub flags: [u8; 4],
}
impl Row {
    pub fn static_route(route: RouteValue, proof: NativeProof) -> Self {
        Self {
            route,
            luid: proof.luid,
            protocol: 3,
            origin: 0,
            site_prefix_length: 0,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            flags: [0; 4],
        }
    }
}

pub trait RowIo {
    /// Return ALL rows at destination+index, including foreign metadata and
    /// duplicate next hops. Query/malformed-data errors must not become absence.
    fn read(&mut self, destination: IpNet, index: u32) -> io::Result<Vec<Row>>;
    fn create(&mut self, row: &Row) -> io::Result<()>;
    fn delete(&mut self, row: &Row) -> io::Result<()>;
    fn set(&mut self, row: &Row) -> io::Result<()>;
}
/// Existing absent-interface cleanup seam. The owner must positively attest
/// exact native absence before AND after enumerating the addressed key. This
/// can prove an owned row vanished, never authorize writes to a missing/reused
/// interface or deletion of a foreign/stale row still present there.
#[cfg_attr(not(windows), allow(dead_code))] // Native caller; portable fake tests below.
pub(crate) fn read_absent_route(
    rows: &mut impl RowIo,
    key: &ResourceKey,
    mut confirm_absent: impl FnMut() -> io::Result<bool>,
) -> io::Result<Option<NetworkValue>> {
    let (destination, index) = route_key(key)?;
    if !confirm_absent()? {
        return Err(conflict());
    }
    if !rows.read(destination, index)?.is_empty() || !confirm_absent()? {
        return Err(conflict());
    }
    Ok(None)
}

pub struct MemberRoutes<R, I> {
    rows: R,
    identity: I,
}
impl<R: RowIo, I: IdentityCheck> MemberRoutes<R, I> {
    /// Construction has no native effects. Identity is checked on every access.
    pub fn new(rows: R, identity: I) -> Self {
        Self { rows, identity }
    }

    fn verify(&mut self, index: u32, expected: Option<NativeProof>) -> io::Result<NativeProof> {
        let proof = self.identity.verify(index)?;
        if proof.index != index
            || index == 0
            || proof.luid == 0
            || expected.is_some_and(|p| p != proof)
        {
            return Err(conflict());
        }
        Ok(proof)
    }
    fn read_proven(&mut self, destination: IpNet, proof: NativeProof) -> io::Result<Option<Row>> {
        self.verify(proof.index, Some(proof))?;
        let rows = self.rows.read(destination, proof.index);
        self.verify(proof.index, Some(proof))?;
        let rows = rows?;
        if rows.len() > 1 {
            return Err(conflict());
        }
        let row = rows.into_iter().next();
        if let Some(r) = &row {
            validate_route(&r.route, destination, proof.index)?;
            if r != &Row::static_route(r.route.clone(), proof) {
                return Err(conflict());
            }
        }
        Ok(row)
    }
    fn write(
        &mut self,
        proof: NativeProof,
        row: &Row,
        op: fn(&mut R, &Row) -> io::Result<()>,
    ) -> io::Result<()> {
        self.verify(proof.index, Some(proof))?;
        let result = op(&mut self.rows, row);
        // Even an error may have applied. Never suppress a lost identity/ACK.
        self.verify(proof.index, Some(proof))?;
        result
    }
}
impl<R: RowIo, I: IdentityCheck> NetworkSystem for MemberRoutes<R, I> {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        let (destination, index) = route_key(key)?;
        let proof = self.verify(index, None)?;
        Ok(self
            .read_proven(destination, proof)?
            .map(|r| NetworkValue::Route(r.route)))
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        let (destination, index) = route_key(key)?;
        let before = route_value(before, destination, index)?;
        let after = route_value(after, destination, index)?;
        let proof = self.verify(index, None)?;
        let current = self.read_proven(destination, proof)?;
        if current.as_ref().map(|r| &r.route) != before {
            return Err(conflict());
        }
        if before == after {
            return Ok(());
        }
        let desired = after.map(|r| Row::static_route(r.clone(), proof));
        match (current.as_ref(), desired.as_ref()) {
            (None, Some(new)) => self.write(proof, new, R::create),
            (Some(old), None) => self.write(proof, old, R::delete),
            (Some(old), Some(new)) if old.route.gateway == new.route.gateway => {
                self.write(proof, new, R::set)
            }
            (Some(old), Some(new)) => {
                self.write(proof, old, R::delete)?;
                // A gateway is part of the native key, unlike the stable journal
                // key. An intervening writer must not gain a second next hop.
                if self.read_proven(destination, proof)?.is_some() {
                    return Err(conflict());
                }
                self.write(proof, new, R::create)
            }
            (None, None) => Ok(()),
        }
    }
}

pub(crate) fn conflict() -> io::Error {
    io::Error::other("member_route_identity_or_ownership_conflict")
}
fn route_key(key: &ResourceKey) -> io::Result<(IpNet, u32)> {
    match key {
        ResourceKey::Route(destination, RouteScope::WindowsInterface(index))
            if *index != 0 && *destination == destination.trunc() =>
        {
            Ok((*destination, *index))
        }
        _ => Err(conflict()),
    }
}
fn route_value(
    value: Option<&NetworkValue>,
    destination: IpNet,
    index: u32,
) -> io::Result<Option<&RouteValue>> {
    match value {
        None => Ok(None),
        Some(NetworkValue::Route(r)) => {
            validate_route(r, destination, index)?;
            Ok(Some(r))
        }
        _ => Err(conflict()),
    }
}
pub(crate) fn validate_route(r: &RouteValue, destination: IpNet, index: u32) -> io::Result<()> {
    if index == 0
        || r.interface != index
        || r.scope != RouteScope::WindowsInterface(index)
        || r.destination != destination
        || destination != destination.trunc()
        || r.gateway.is_some_and(|g| {
            g.is_ipv4() != destination.addr().is_ipv4() || g.is_unspecified() || g.is_multicast()
        })
    {
        return Err(conflict());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct State {
        rows: Vec<Row>,
        writes: Vec<&'static str>,
        lost_ack: Option<&'static str>,
        fail_read: bool,
    }
    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<State>>);
    impl Fake {
        fn finish(&self, name: &'static str) -> io::Result<()> {
            let mut s = self.0.borrow_mut();
            s.writes.push(name);
            if s.lost_ack == Some(name) {
                s.lost_ack = None;
                return Err(io::Error::other("lost_ack"));
            }
            Ok(())
        }
    }
    impl RowIo for Fake {
        fn read(&mut self, destination: IpNet, index: u32) -> io::Result<Vec<Row>> {
            let s = self.0.borrow();
            if s.fail_read {
                return Err(io::Error::other("query_failed"));
            }
            Ok(s.rows
                .iter()
                .filter(|r| r.route.destination == destination && r.route.interface == index)
                .cloned()
                .collect())
        }
        fn create(&mut self, row: &Row) -> io::Result<()> {
            self.0.borrow_mut().rows.push(row.clone());
            self.finish("create")
        }
        fn delete(&mut self, row: &Row) -> io::Result<()> {
            self.0.borrow_mut().rows.retain(|r| r != row);
            self.finish("delete")
        }
        fn set(&mut self, row: &Row) -> io::Result<()> {
            self.0.borrow_mut().rows[0] = row.clone();
            self.finish("set")
        }
    }
    const PROOF: NativeProof = NativeProof {
        index: 7,
        luid: 700,
    };
    fn proof(_: u32) -> io::Result<NativeProof> {
        Ok(PROOF)
    }
    fn route(v6: bool) -> RouteValue {
        RouteValue {
            destination: if v6 { "2001:db8::/32" } else { "10.0.0.0/8" }
                .parse()
                .unwrap(),
            scope: RouteScope::WindowsInterface(7),
            interface: 7,
            gateway: None,
            metric: 20,
        }
    }
    fn value(r: &RouteValue) -> NetworkValue {
        NetworkValue::Route(r.clone())
    }
    type FakeRoutes = MemberRoutes<Fake, fn(u32) -> io::Result<NativeProof>>;
    fn setup(r: Option<RouteValue>) -> (FakeRoutes, Fake) {
        let f = Fake::default();
        if let Some(r) = r {
            f.0.borrow_mut().rows.push(Row::static_route(r, PROOF));
        }
        (
            MemberRoutes::new(f.clone(), proof as fn(u32) -> io::Result<NativeProof>),
            f,
        )
    }
    #[test]
    fn absent_member_row_requires_positive_identity_empty_rows_and_second_absence() {
        let key = value(&route(false)).key();
        let mut rows = Fake::default();
        assert_eq!(
            read_absent_route(&mut rows, &key, || Ok(true)).unwrap(),
            None
        );
        assert!(read_absent_route(&mut rows, &key, || Ok(false)).is_err());
        assert!(read_absent_route(&mut rows, &key, || Err(
            io::ErrorKind::PermissionDenied.into()
        ))
        .is_err());
        let mut calls = 0;
        assert!(read_absent_route(&mut rows, &key, || {
            calls += 1;
            Ok(calls == 1)
        })
        .is_err());
        rows.0.borrow_mut().fail_read = true;
        assert!(read_absent_route(&mut rows, &key, || Ok(true)).is_err());
        rows.0.borrow_mut().fail_read = false;
        rows.0
            .borrow_mut()
            .rows
            .push(Row::static_route(route(false), PROOF));
        assert!(read_absent_route(&mut rows, &key, || Ok(true)).is_err());
        assert!(rows.0.borrow().writes.is_empty());
    }
    #[test]
    fn network_owner_promotes_after_owned_interface_rows_vanish_without_recreating_them() {
        use nelomai_client_tunnel::redundancy::{network::NetworkOwner, Slot};
        struct System {
            normal: MemberRoutes<Fake, Box<dyn FnMut(u32) -> io::Result<NativeProof>>>,
            rows: Fake,
            absent: Rc<RefCell<bool>>,
        }
        impl NetworkSystem for System {
            fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
                if route_key(key)?.1 == 7 && *self.absent.borrow() {
                    return read_absent_route(&mut self.rows, key, || Ok(*self.absent.borrow()));
                }
                self.normal.read(key)
            }
            fn compare_exchange(
                &mut self,
                key: &ResourceKey,
                before: Option<&NetworkValue>,
                after: Option<&NetworkValue>,
            ) -> io::Result<()> {
                if route_key(key)?.1 == 7 && *self.absent.borrow() {
                    return if before.is_none() && after.is_none() && self.read(key)?.is_none() {
                        Ok(())
                    } else {
                        Err(conflict())
                    };
                }
                self.normal.compare_exchange(key, before, after)
            }
        }
        for foreign in [false, true] {
            let rows = Fake::default();
            let absent = Rc::new(RefCell::new(false));
            let check = absent.clone();
            let normal = MemberRoutes::new(
                rows.clone(),
                Box::new(move |index| {
                    if index == 7 && *check.borrow() {
                        return Err(conflict());
                    }
                    Ok(NativeProof {
                        index,
                        luid: u64::from(index) * 100,
                    })
                }) as Box<dyn FnMut(u32) -> io::Result<NativeProof>>,
            );
            let mut owner = NetworkOwner::fresh(
                System {
                    normal,
                    rows: rows.clone(),
                    absent: absent.clone(),
                },
                Journal,
            );
            let a = route(false);
            let mut b = a.clone();
            b.interface = 8;
            b.scope = RouteScope::WindowsInterface(8);
            b.metric = 200;
            owner.select(Slot::A, vec![value(&a), value(&b)]).unwrap();
            *absent.borrow_mut() = true;
            rows.0.borrow_mut().rows.retain(|r| r.route.interface != 7);
            if foreign {
                rows.0.borrow_mut().rows.push(Row::static_route(
                    a.clone(),
                    NativeProof {
                        index: 7,
                        luid: 999,
                    },
                ));
            }
            rows.0.borrow_mut().writes.clear();
            b.metric = 20;
            let result = owner.select(Slot::B, vec![value(&b)]);
            if foreign {
                assert!(result.is_err());
                assert!(rows.0.borrow().writes.is_empty());
            } else {
                result.unwrap();
                assert_eq!(owner.active(), Some(Slot::B));
                assert_eq!(
                    rows.0.borrow().rows,
                    vec![Row::static_route(
                        b,
                        NativeProof {
                            index: 8,
                            luid: 800
                        }
                    )]
                );
                assert_eq!(rows.0.borrow().writes, ["set"]);
            }
        }
    }
    #[test]
    fn create_read_delete_both_families() {
        for v6 in [false, true] {
            let r = value(&route(v6));
            let key = r.key();
            let (mut m, f) = setup(None);
            assert_eq!(m.read(&key).unwrap(), None);
            m.compare_exchange(&key, None, Some(&r)).unwrap();
            assert_eq!(m.read(&key).unwrap(), Some(r.clone()));
            m.compare_exchange(&key, Some(&r), None).unwrap();
            assert_eq!(m.read(&key).unwrap(), None);
            assert_eq!(f.0.borrow().writes, ["create", "delete"]);
        }
    }
    #[test]
    fn metric_replacement_uses_set_gateway_replacement_delete_create() {
        let old = route(false);
        let (mut m, f) = setup(Some(old.clone()));
        let mut new = old.clone();
        new.metric = 50;
        m.compare_exchange(&value(&old).key(), Some(&value(&old)), Some(&value(&new)))
            .unwrap();
        assert_eq!(f.0.borrow().writes, ["set"]);
        let mut next = new.clone();
        next.gateway = Some("10.0.0.1".parse().unwrap());
        m.compare_exchange(&value(&old).key(), Some(&value(&new)), Some(&value(&next)))
            .unwrap();
        assert_eq!(f.0.borrow().writes, ["set", "delete", "create"]);
    }
    #[test]
    fn expected_absence_never_adopts_even_identical_static_row() {
        let r = value(&route(false));
        let (mut m, f) = setup(Some(route(false)));
        assert!(m.compare_exchange(&r.key(), None, Some(&r)).is_err());
        assert!(f.0.borrow().writes.is_empty());
    }
    #[test]
    fn duplicate_rows_and_distinct_next_hops_are_ambiguous() {
        for different in [false, true] {
            let r = route(false);
            let (mut m, f) = setup(Some(r.clone()));
            let mut other = r.clone();
            if different {
                other.gateway = Some("10.0.0.1".parse().unwrap());
            }
            f.0.borrow_mut().rows.push(Row::static_route(other, PROOF));
            assert!(m.read(&value(&r).key()).is_err());
            assert!(m
                .compare_exchange(&value(&r).key(), Some(&value(&r)), None)
                .is_err());
            assert!(f.0.borrow().writes.is_empty());
        }
    }
    #[test]
    fn foreign_metadata_and_recycled_luid_are_never_owned() {
        for n in 0..10 {
            let r = route(false);
            let (mut m, f) = setup(Some(r.clone()));
            {
                let mut s = f.0.borrow_mut();
                let row = &mut s.rows[0];
                match n {
                    0 => row.protocol = 2,
                    1 => row.origin = 2,
                    2 => row.site_prefix_length = 1,
                    3 => row.valid_lifetime = 30,
                    4 => row.preferred_lifetime = 30,
                    5..=8 => row.flags[n - 5] = 1,
                    _ => row.luid += 1,
                }
            }
            assert!(m.read(&value(&r).key()).is_err(), "metadata {n}");
            assert!(m
                .compare_exchange(&value(&r).key(), Some(&value(&r)), None)
                .is_err());
            assert!(f.0.borrow().writes.is_empty());
        }
    }
    #[test]
    fn lost_ack_requires_readback_not_blind_retry() {
        let r = value(&route(false));
        let (mut m, f) = setup(None);
        f.0.borrow_mut().lost_ack = Some("create");
        assert!(m.compare_exchange(&r.key(), None, Some(&r)).is_err());
        assert_eq!(m.read(&r.key()).unwrap(), Some(r.clone()));
        assert!(m.compare_exchange(&r.key(), None, Some(&r)).is_err());
        assert_eq!(f.0.borrow().writes, ["create"]);
    }
    #[test]
    fn gateway_delete_lost_ack_does_not_continue_creating() {
        let old = route(false);
        let mut new = old.clone();
        new.gateway = Some("10.0.0.1".parse().unwrap());
        let (mut m, f) = setup(Some(old.clone()));
        f.0.borrow_mut().lost_ack = Some("delete");
        assert!(m
            .compare_exchange(&value(&old).key(), Some(&value(&old)), Some(&value(&new)))
            .is_err());
        assert_eq!(m.read(&value(&old).key()).unwrap(), None);
        assert_eq!(f.0.borrow().writes, ["delete"]);
    }
    #[test]
    fn missing_interface_and_query_failure_are_not_absence() {
        let f = Fake::default();
        let mut m = MemberRoutes::new(f.clone(), |_| Err(io::Error::other("missing_interface")));
        let r = value(&route(false));
        assert!(m.read(&r.key()).is_err());
        assert!(m.compare_exchange(&r.key(), None, Some(&r)).is_err());
        assert!(f.0.borrow().writes.is_empty());
        let (mut m, f) = setup(None);
        f.0.borrow_mut().fail_read = true;
        assert!(m.read(&r.key()).is_err());
    }
    #[test]
    fn wrong_family_noncanonical_and_wrong_scope_have_no_effects() {
        for n in 0..4 {
            let (mut m, f) = setup(None);
            let mut r = route(false);
            match n {
                0 => r.gateway = Some("::1".parse().unwrap()),
                1 => r.scope = RouteScope::Member(7),
                2 => r.destination = "10.1.1.1/8".parse().unwrap(),
                _ => r.interface = 8,
            }
            let r = value(&r);
            assert!(m.compare_exchange(&r.key(), None, Some(&r)).is_err());
            assert!(f.0.borrow().writes.is_empty());
        }
    }
    #[test]
    fn identity_change_after_read_is_not_published() {
        let f = Fake::default();
        let mut calls = 0;
        let mut m = MemberRoutes::new(f.clone(), move |_| {
            calls += 1;
            Ok(NativeProof {
                luid: if calls == 1 { 700 } else { 701 },
                ..PROOF
            })
        });
        assert!(m.read(&value(&route(false)).key()).is_err());
        assert!(f.0.borrow().writes.is_empty());
    }
    #[test]
    fn changed_identity_after_write_is_error_with_effect_retained_for_readback() {
        let f = Fake::default();
        let observed = f.clone();
        let mut m = MemberRoutes::new(f.clone(), move |_| {
            if observed.0.borrow().writes.is_empty() {
                Ok(PROOF)
            } else {
                Err(io::Error::other("interface_gone"))
            }
        });
        let r = value(&route(false));
        assert!(m.compare_exchange(&r.key(), None, Some(&r)).is_err());
        assert_eq!(f.0.borrow().writes, ["create"]);
        assert_eq!(f.0.borrow().rows.len(), 1);
        assert!(m.read(&r.key()).is_err()); // disappearance isn't proof of absence
    }
    #[test]
    fn wrong_expected_and_mismatched_resource_key_cannot_mutate() {
        let old = route(false);
        let (mut m, f) = setup(Some(old.clone()));
        let mut wrong = old.clone();
        wrong.metric += 1;
        assert!(m
            .compare_exchange(&value(&old).key(), Some(&value(&wrong)), None)
            .is_err());
        assert!(m
            .compare_exchange(&value(&route(true)).key(), Some(&value(&old)), None)
            .is_err());
        assert!(f.0.borrow().writes.is_empty());
        m.compare_exchange(&value(&old).key(), Some(&value(&old)), Some(&value(&old)))
            .unwrap();
        assert!(f.0.borrow().writes.is_empty());
    }
    #[test]
    fn unrelated_interface_and_destination_do_not_conflict() {
        let (mut m, f) = setup(None);
        let mut other_if = route(false);
        other_if.interface = 8;
        other_if.scope = RouteScope::WindowsInterface(8);
        let other_dest = route(true);
        f.0.borrow_mut().rows = vec![
            Row::static_route(other_if, PROOF),
            Row::static_route(other_dest, PROOF),
        ];
        let r = value(&route(false));
        m.compare_exchange(&r.key(), None, Some(&r)).unwrap();
        assert_eq!(m.read(&r.key()).unwrap(), Some(r));
        assert_eq!(f.0.borrow().rows.len(), 3);
    }
    #[test]
    fn set_and_delete_lost_ack_remain_observable() {
        let old = route(false);
        let (mut m, f) = setup(Some(old.clone()));
        let mut new = old.clone();
        new.metric += 1;
        let key = value(&old).key();
        f.0.borrow_mut().lost_ack = Some("set");
        assert!(m
            .compare_exchange(&key, Some(&value(&old)), Some(&value(&new)))
            .is_err());
        assert_eq!(m.read(&key).unwrap(), Some(value(&new)));
        f.0.borrow_mut().lost_ack = Some("delete");
        assert!(m.compare_exchange(&key, Some(&value(&new)), None).is_err());
        assert_eq!(m.read(&key).unwrap(), None);
    }
    #[derive(Default)]
    struct Journal;
    impl nelomai_client_tunnel::redundancy::network::NetworkJournalStore for Journal {
        fn save(
            &mut self,
            _: &nelomai_client_tunnel::redundancy::network::NetworkJournal,
        ) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn network_owner_resolves_create_lost_ack_and_partial_gateway_cleanup() {
        use nelomai_client_tunnel::redundancy::network::NetworkOwner;
        let (m, f) = setup(None);
        let mut owner = NetworkOwner::fresh(m, Journal);
        let r = value(&route(false));
        f.0.borrow_mut().lost_ack = Some("create");
        assert!(owner.prepare(vec![r.clone()]).is_err());
        assert!(f.0.borrow().rows.is_empty());
        owner.prepare(vec![r.clone()]).unwrap();
        let mut next = route(false);
        next.gateway = Some("10.0.0.1".parse().unwrap());
        f.0.borrow_mut().lost_ack = Some("delete");
        assert!(owner.prepare(vec![value(&next)]).is_err());
        owner.cleanup().unwrap();
        assert!(!owner.has_resources());
        assert!(f.0.borrow().rows.is_empty());
    }
}
