//! Original BFE engines for the one-TUN owner; same v2 codec/arbitration checks.
use super::member_carrier_guard::{
    validate_arbitration_with_keys, NativeApi, TerminalNativeApi, Wfp,
};
use crate::{
    member_carrier_guard::{Action, GuardError, Key, Result, SessionKind, Snapshot},
    member_worker_guard::{keys, Model, Plan},
};
use std::{collections::BTreeMap, io};

pub(crate) struct Guard {
    io: Wfp,
    pub current: Model,
    ids: BTreeMap<Key, u64>,
    failed: bool,
    closed: bool,
    plan: Option<Plan>,
}
fn denied(_: impl std::fmt::Debug) -> GuardError {
    GuardError::Conflict
}
impl Guard {
    pub(crate) fn open(model: Model) -> Result<Self> {
        if model.interface.is_some() {
            return Err(GuardError::Invalid);
        }
        let io = Wfp::open_worker(model.scope.clone())?;
        let mut guard = Self {
            io,
            current: model,
            ids: BTreeMap::new(),
            failed: false,
            closed: false,
            plan: None,
        };
        let expected = guard.current.snapshot()?;
        guard.transaction(SessionKind::StaticBase, true, |g| {
            if g.read(SessionKind::StaticBase)? != expected {
                return Err(GuardError::Conflict);
            }
            Ok(())
        })?;
        Ok(guard)
    }
    fn transaction<T>(
        &mut self,
        kind: SessionKind,
        readonly: bool,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        if let Err(error) = self.io.begin(kind, readonly) {
            self.failed = true;
            let _ = self.io.close(SessionKind::DynamicPermits);
            return Err(error);
        }
        let mut transaction = WorkerTransaction {
            guard: self,
            kind,
            finished: false,
        };
        let value = action(transaction.guard)?;
        transaction.guard.io.commit(kind)?;
        transaction.finished = true;
        Ok(value)
    }

    fn read(&mut self, kind: SessionKind) -> Result<Snapshot> {
        let mut actual = Model::empty(self.current.scope.clone()).snapshot()?;
        let k = keys(&self.current.scope)?;
        actual.sublayer = self.io.sublayer(kind, k.sublayer)?;
        for key in k.filters {
            if let Some(filter) = self.io.filter(kind, key, k.sublayer)? {
                if self.ids.get(&key) != Some(&filter.id) {
                    return Err(GuardError::Conflict);
                }
                actual.filters.push(filter.policy);
            }
        }
        actual.filters.sort_by_key(|f| f.key);
        Ok(actual)
    }
    fn priority(&mut self, kind: SessionKind, snapshot: &Snapshot) -> Result<()> {
        if snapshot.sublayer.is_some() {
            let filters = self.io.arbitration(kind)?;
            // No SCM-member exceptions: the worker's crypto sockets use the
            // physical interface, outside this exact TUN's filter conditions.
            validate_arbitration_with_keys(
                &self.current.scope,
                snapshot,
                &self.ids,
                &filters,
                &[],
                &keys(&self.current.scope)?,
            )?;
        }
        Ok(())
    }
    pub(crate) fn verify(&mut self, authorize: impl FnOnce() -> io::Result<()>) -> Result<()> {
        if self.closed || self.failed {
            return Err(GuardError::Conflict);
        }
        authorize().map_err(denied)?;
        let expected = self.current.snapshot()?;
        self.transaction(SessionKind::StaticBase, true, |g| {
            let actual = g.read(SessionKind::StaticBase)?;
            if actual != expected {
                return Err(GuardError::Conflict);
            }
            g.priority(SessionKind::StaticBase, &actual)
        })
    }
    pub(crate) fn transition(
        &mut self,
        mut desired: Model,
        mut save: impl FnMut(&Model, Option<&Plan>) -> io::Result<()>,
        mut authorize: impl FnMut() -> io::Result<()>,
    ) -> Result<()> {
        if self.closed || self.failed || desired.scope != self.current.scope {
            return Err(GuardError::Conflict);
        }
        desired.snapshot()?;
        if desired.interface.is_some() {
            desired.weight = self.current.weight;
        }
        let mut plan = Plan::new(self.current.clone(), desired.clone())?;
        self.failed = true;
        self.plan = Some(plan.clone());
        save(&self.current, Some(&plan)).map_err(denied)?;
        let mut withdrawn = self.current.clone();
        withdrawn.admitted = false;
        let mut base = desired.clone();
        base.admitted = false;
        for (kind, mut next) in [
            (SessionKind::DynamicPermits, withdrawn),
            (SessionKind::StaticBase, base),
            (SessionKind::DynamicPermits, desired),
        ] {
            authorize().map_err(denied)?;
            if next.interface.is_some() {
                next.weight = self.current.weight;
            }
            let expected = self.current.snapshot()?;
            self.transaction(kind, false, |g| {
                if g.read(kind)? != expected {
                    return Err(GuardError::Conflict);
                }
                g.priority(kind, &expected)?;
                let mut target = next.snapshot()?;
                let k = keys(&next.scope)?;
                if expected.sublayer.is_none() && target.sublayer.is_some() {
                    g.io.add_sublayer(target.sublayer.as_ref().ok_or(GuardError::Invalid)?)?;
                    let sub =
                        g.io.sublayer(kind, k.sublayer)?
                            .ok_or(GuardError::Conflict)?;
                    next.weight = Some(sub.weight);
                    target = next.snapshot()?;
                    // Capture assigned priority while the creating transaction
                    // is still locked, before its commit can lose ACK.
                    plan.bind_created_weight(sub.weight)?;
                    g.plan = Some(plan.clone());
                    save(&g.current, Some(&plan)).map_err(denied)?;
                }
                for old in &expected.filters {
                    if !target.filters.contains(old) {
                        if (old.action == Action::Permit) != (kind == SessionKind::DynamicPermits) {
                            return Err(GuardError::Invalid);
                        }
                        g.io.delete_filter(kind, old.key)?;
                        g.ids.remove(&old.key);
                    }
                }
                for new in &target.filters {
                    if !expected.filters.contains(new) {
                        let id = g.io.add_filter(kind, new)?;
                        if g.ids.insert(new.key, id).is_some() {
                            return Err(GuardError::Conflict);
                        }
                    }
                }
                if target.sublayer.is_none() && expected.sublayer.is_some() {
                    g.io.delete_sublayer(k.sublayer)?;
                }
                let actual = g.read(kind)?;
                if actual != target {
                    return Err(GuardError::Conflict);
                }
                g.priority(kind, &actual)?;
                authorize().map_err(denied)
            })?;
            let target = next.snapshot()?;
            self.transaction(SessionKind::StaticBase, true, |g| {
                let actual = g.read(SessionKind::StaticBase)?;
                if actual != target {
                    return Err(GuardError::Conflict);
                }
                g.priority(SessionKind::StaticBase, &actual)
            })?;
            self.current = next;
            save(&self.current, Some(&plan)).map_err(denied)?;
            authorize().map_err(denied)?;
        }
        save(&self.current, None).map_err(denied)?;
        self.plan = None;
        self.failed = false;
        Ok(())
    }
    pub(crate) fn close(&mut self) -> Result<()> {
        if self.closed || self.current.interface.is_some() {
            return Err(GuardError::Conflict);
        }
        self.io.enter_terminal_lane();
        for kind in [SessionKind::DynamicPermits, SessionKind::StaticBase] {
            let ack = self.io.close_terminal_engine(kind)?;
            self.io.verify_engine_inert(kind, &ack)?;
        }
        self.closed = true;
        Ok(())
    }
    pub(crate) fn verify_terminal(&self) -> Result<()> {
        if !self.closed || self.current.interface.is_some() || self.plan.is_some() {
            return Err(GuardError::Conflict);
        }
        for kind in [SessionKind::DynamicPermits, SessionKind::StaticBase] {
            let ack = self.io.engine_close_ack(kind)?;
            self.io.verify_engine_inert(kind, &ack)?;
        }
        Ok(())
    }
}

struct WorkerTransaction<'a> {
    guard: &'a mut Guard,
    kind: SessionKind,
    finished: bool,
}
impl Drop for WorkerTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.guard.failed = true;
            if self.guard.io.abort(self.kind).is_err() {
                let _ = self.guard.io.close(self.kind);
            }
            let _ = self.guard.io.close(SessionKind::DynamicPermits);
        }
    }
}
