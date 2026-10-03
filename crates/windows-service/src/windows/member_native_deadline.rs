//! Hard supervisor for ONLY this actual authenticated engine process.
//!
//! This is NOT native effect authority: integrating G must already hold the
//! actual runtime/actor/slot owner, exact protected pending intent and static
//! blocks before entering run. Killing this process leaves an UNKNOWN native
//! outcome, never a close/create/effect ACK or cleanup completion. Recovery must
//! independently reconcile those exact durable/native obligations. Existing
//! diagnostic parent routes <=30s / child watchdog <=60s are not changed here.
#![allow(dead_code)] // Main declares/integrates the four new files after review.

use super::member_carrier_key_authority::RuntimeRead;
use crate::member_carrier::{CarrierError, Result};
use crate::member_carrier_native_ownership::Context;
use crate::member_native_deadline::{self as policy, Factory, Kernel};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{DuplicateHandle, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetProcessId, GetProcessTimes, SetEvent,
    TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE,
};

const UNKNOWN_OUTCOME_EXIT: u32 = 0x4e44_4c4e;
static CURRENT_SUPERVISOR: Mutex<policy::OwnerRegistry> =
    Mutex::new(policy::OwnerRegistry::empty());
#[derive(Clone, Copy, Eq, PartialEq)]
struct CurrentIdentity {
    pid: u32,
    creation: u64,
}

/// A NEW current-process cleanup watchdog. It is not the dead creator's
/// NativeDeadline, RuntimeRead, Source or native receipt. Its constructor only
/// accepts the actual signed, protected recovery entry; no target-PID API.
pub(crate) struct NativeColdDeadline {
    entry: Rc<super::member_carrier_recovery::native::NativeFactoryRecoveryEntry>,
    owner: Rc<policy::ProcessOwner<'static>>,
    context: Context,
    timing: crate::member_cold_deadline::ColdCall<Context, CurrentFactory>,
    completed: std::cell::Cell<bool>,
}
impl NativeColdDeadline {
    pub(crate) fn new(
        entry: Rc<super::member_carrier_recovery::native::NativeFactoryRecoveryEntry>,
        context: Context,
    ) -> std::io::Result<Self> {
        entry.require_bounded_cleanup_execution()?;
        entry.inspect(|facts| {
            if facts.context.as_ref() != Some(&context) {
                return Err(std::io::Error::other("cold_deadline_context"));
            }
            Ok(())
        })?;
        let owner = Rc::new(
            policy::ProcessOwner::acquire(&CURRENT_SUPERVISOR)
                .map_err(|_| std::io::Error::other("cold_deadline_owner"))?,
        );
        let process =
            capture_current().map_err(|_| std::io::Error::other("cold_deadline_capture"))?;
        let identity = process_identity(&process)
            .map_err(|_| std::io::Error::other("cold_deadline_identity"))?;
        if identity.pid != unsafe { GetCurrentProcessId() } {
            return Err(std::io::Error::other("cold_deadline_current"));
        }
        entry.require_bounded_cleanup_execution()?;
        Ok(Self {
            entry,
            owner,
            context: context.clone(),
            completed: std::cell::Cell::new(false),
            timing: crate::member_cold_deadline::ColdCall::new(
                context,
                CurrentFactory {
                    process: Arc::new(process),
                    identity,
                },
            ),
        })
    }
    fn authenticate(&self) -> std::io::Result<()> {
        self.owner
            .verify()
            .map_err(|_| std::io::Error::other("cold_deadline_owner"))?;
        self.entry.require_bounded_cleanup_execution()?;
        self.entry.inspect(|facts| {
            if facts.context.as_ref() != Some(&self.context) {
                return Err(std::io::Error::other("cold_deadline_context"));
            }
            Ok(())
        })
    }
    pub(crate) fn run<T>(&self, call: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
        let result = self.timing.run(&self.context, || self.authenticate(), call);
        if result.is_ok() {
            self.completed.set(true);
        } else {
            self.owner.uncertain();
        }
        result
    }
    /// Timing/authentication only. The independent non-WFP/dead-creator/full
    /// protected Guard gate remains mandatory INSIDE every effect bracket.
    pub(crate) fn with_current_call<T>(
        &self,
        scope: &nelomai_client_tunnel::redundancy::SessionScope,
        read: impl FnOnce() -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        if *scope != self.context.intent.scope {
            self.owner.uncertain();
            return Err(std::io::Error::other("cold_deadline_scope"));
        }
        self.timing.with_call(&self.context, || {
            self.authenticate()?;
            let result = read()?;
            self.authenticate()?;
            Ok(result)
        })
    }
}
impl Drop for NativeColdDeadline {
    fn drop(&mut self) {
        if !self.completed.get() {
            self.owner.uncertain();
        }
    }
}

/// Runtime/actor pins remain !Send/!Sync on the actual owner thread. No public
/// constructor from PID, handles, paths, signature bits or Context equality.
pub(crate) struct NativeDeadline {
    owner: Rc<policy::ProcessOwner<'static>>,
    runtime: RuntimeRead,
    context: Context,
    deadline: policy::Deadline<Context, CurrentFactory>,
    forward_closed: std::cell::Cell<bool>,
}
pub(crate) struct NativeDeadlineReadPin {
    owner: Rc<policy::ProcessOwner<'static>>,
    runtime: RuntimeRead,
    policy: policy::ReadPin<Context>,
}
pub(crate) struct NativeTransactionCallPin {
    owner: Rc<policy::ProcessOwner<'static>>,
    runtime: RuntimeRead,
    context: Context,
    policy: policy::TransactionCallPin<Context>,
}
impl NativeTransactionCallPin {
    pub(crate) fn verify(&self, owner: &NativeDeadline, context: &Context) -> Result<()> {
        if !Rc::ptr_eq(&self.owner, &owner.owner)
            || !self.runtime.same_original_runtime(&owner.runtime)
            || context != &self.context
            || context != &owner.context
        {
            return Err(CarrierError::Conflict);
        }
        owner
            .deadline
            .verify_transaction_call(&self.policy, context)
            .map_err(denied)
    }
}
impl NativeDeadline {
    /// Actual SAME installed signed current engine and protected claim are
    /// checked by RuntimeRead. Initial authentication is not itself supervised:
    /// no authority exists to terminate a process until this gate succeeds.
    pub(crate) fn new(runtime: &RuntimeRead, context: &Context) -> Result<Self> {
        runtime.verify(context)?;
        let pin = runtime.read_pin()?;
        if !pin.same_original_runtime(runtime) {
            return Err(CarrierError::Conflict);
        }
        let owner = Rc::new(policy::ProcessOwner::acquire(&CURRENT_SUPERVISOR).map_err(denied)?);
        let process = capture_current().map_err(|_| CarrierError::Native)?;
        let identity = process_identity(&process).map_err(|_| CarrierError::Native)?;
        if identity.pid != unsafe { GetCurrentProcessId() } {
            return Err(CarrierError::Conflict);
        }
        pin.verify(context)?;
        Ok(Self {
            owner,
            runtime: pin,
            context: context.clone(),
            forward_closed: std::cell::Cell::new(false),
            deadline: policy::Deadline::new(
                context.clone(),
                CurrentFactory {
                    process: Arc::new(process),
                    identity,
                },
            ),
        })
    }
    pub(crate) fn read_pin(&self) -> Result<NativeDeadlineReadPin> {
        let mut attempt = ReadAttempt {
            owner: self,
            succeeded: false,
        };
        self.runtime.verify(&self.context)?;
        self.verify_lease()?;
        let pin = NativeDeadlineReadPin {
            owner: self.owner.clone(),
            runtime: self.runtime.read_pin()?,
            policy: self.deadline.pin().map_err(denied)?,
        };
        attempt.succeeded = true;
        Ok(pin)
    }
    /// Wrap the actual synchronous native call; includes reauthentication while
    /// the watchdog is armed. A returned native error or failed post-ACK current
    /// claim check permanently revokes forward. A normally returned operation
    /// error with authenticated postflight and positive SAME watchdog rundown
    /// may retain cleanup-only timing eligibility; this grants no effect rights.
    /// Retain every opaque native return ACK in the actual owner immediately
    /// INSIDE call, before returning to our post-ACK RuntimeRead verification.
    /// That check or watchdog rundown may fail and discard T. The closure can
    /// borrow !Send owner state; a retained receipt remains a recovery obligation,
    /// not forward authority or a successful supervisor completion.
    pub(crate) fn run<T>(&self, context: &Context, call: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.forward_closed.get() {
            return Err(CarrierError::Retired);
        }
        let mut attempt = ReadAttempt {
            owner: self,
            succeeded: false,
        };
        let returned_with_authenticated_postflight = std::cell::Cell::new(false);
        let outcome = match self.deadline.run(context, || {
            self.owner.verify().map_err(denied)?;
            self.runtime.verify(context)?;
            let value = call();
            self.runtime.verify(context)?;
            returned_with_authenticated_postflight.set(true);
            value
        }) {
            Ok(value) => Ok(value),
            Err(policy::Failure::Native(error)) => Err(error),
            Err(policy::Failure::Supervisor(error)) => Err(denied(error)),
        };
        if outcome.is_err() {
            self.forward_closed.set(true);
        }
        if outcome.is_err()
            && returned_with_authenticated_postflight.get()
            && self.deadline.cleanup_eligible()
        {
            self.owner.retain_cleanup_only().map_err(denied)?;
            attempt.succeeded = true;
        } else {
            attempt.succeeded = outcome.is_ok();
        }
        outcome
    }
    /// Actual forward operation entry bound to its ORIGINAL protected Pair ACK.
    /// Pre-entry is factual only; native G must still independently authorize
    /// each SDK/WFP/row/socket effect under Calling. Native ACK retention remains
    /// the callback owner's obligation, even when a later read/rundown fails.
    pub(crate) fn run_intent<T>(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
        expected: &crate::member_carrier_pair::Record,
        effect: crate::member_carrier_pair::Effect,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if self.forward_closed.get() {
            return Err(CarrierError::Retired);
        }
        let mut attempt = ReadAttempt {
            owner: self,
            succeeded: false,
        };
        intent
            .verify_forward_entry(&self.runtime, context, expected, effect)
            .map_err(|_| CarrierError::Conflict)?;
        let authenticated_return = std::cell::Cell::new(false);
        let outcome = self.run(context, || {
            intent
                .inspect_effect(&self.runtime, self, expected, effect, |_| Ok(()))
                .map_err(|_| CarrierError::Conflict)?;
            let value = call();
            // Err is not an absence ACK. Reauthenticate after normal return
            // before retaining SAME-supervisor cleanup-only eligibility.
            intent
                .inspect_effect(&self.runtime, self, expected, effect, |_| Ok(()))
                .map_err(|_| CarrierError::Conflict)?;
            authenticated_return.set(true);
            value
        });
        attempt.succeeded =
            outcome.is_ok() || (authenticated_return.get() && self.deadline.cleanup_eligible());
        outcome
    }
    /// Separate, SAME-supervisor cleanup-only entry. An opaque ORIGINAL Pair
    /// publication ACK for precise current Closing stage, actual RuntimeRead/
    /// KeyLock/private bytes and native receipt phase precede watchdog arming.
    /// G must STILL prove original SDK handles, bases, endpoint/port/network
    /// ownership at EVERY effect; this method never supplies that permission.
    pub(crate) fn run_cleanup<T>(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.run_authenticated_cleanup(context, || self.verify_cleanup_entry(context, intent), call)
    }
    /// Final factual read/release timing under the SAME actual terminal Pair
    /// ACK and fully restored native key record. Every native release still
    /// requires its independent opaque owner/resource gate; this is not one.
    pub(crate) fn run_terminal_cleanup<T>(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
        expected: &crate::member_carrier_pair::Record,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.run_authenticated_cleanup(
            context,
            || {
                self.owner.verify_cleanup().map_err(denied)?;
                intent
                    .verify_terminal_entry(&self.runtime, context, expected)
                    .map_err(|_| CarrierError::Conflict)?;
                let raw = self.runtime.record(
                    context,
                    super::member_session::RecordKind::NativeCarrierReceipts,
                )?;
                let record = crate::member_carrier_native_ownership::Record::decode(&raw)?;
                super::member_carrier_runtime::validate_terminal_stage(
                    &record,
                    context,
                    &context.bindings[0],
                    1,
                )?;
                intent
                    .verify_terminal_entry(&self.runtime, context, expected)
                    .map_err(|_| CarrierError::Conflict)?;
                if self.runtime.record(
                    context,
                    super::member_session::RecordKind::NativeCarrierReceipts,
                )? != raw
                {
                    return Err(CarrierError::Conflict);
                }
                self.owner.verify_cleanup().map_err(denied)
            },
            call,
        )
    }
    /// SDK-free factual Startup branch selection. NativeReceipt absence is
    /// neither inspected nor accepted as authority: the only publication here
    /// is the SAME opaque current Pair Stopped ACK. Actual owner/Runtime,
    /// private bytes, watchdog Calling and positive rundown remain mandatory.
    /// This does NOT authorize Source/Retired/native effects or final release.
    ///
    /// # Safety
    /// `call` must be read-only apart from retaining the actual Startup's
    /// original invocation witness. It must not query native resource SDKs or
    /// perform native/storage effects. Resource cleanup/unload still needs the
    /// independent original C/G/native receipts in run_terminal_cleanup.
    pub(crate) unsafe fn run_terminal_selection<T>(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
        expected: &crate::member_carrier_pair::Record,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.run_authenticated_cleanup(
            context,
            || {
                self.verify_cleanup_runtime_entry(&self.runtime, context)?;
                intent
                    .verify_terminal_entry(&self.runtime, context, expected)
                    .map_err(|_| CarrierError::Conflict)?;
                self.verify_cleanup_runtime_entry(&self.runtime, context)
            },
            || {
                let pin = self.read_pin()?;
                pin.verify_call(self, context)?;
                let result = call();
                // A returned callback Err still needs actual same Calling
                // postflight; an unwind cannot complete the owning selector.
                pin.verify_call(self, context)?;
                result
            },
        )
    }
    /// SDK-free selection of the original module-only lineage under an exact
    /// Closing9/10/12 or Stopped12 Pair ACK. No native receipt absence, resource
    /// SDK read/effect, unload or DATA retirement is authorized by this runner.
    ///
    /// # Safety
    /// Callback retains ONLY actual no-constructor Startup/Assembly/loader
    /// originals. It must not query resource SDKs or perform storage/native effects.
    pub(crate) unsafe fn run_module_only_read_selection<T>(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
        expected: &crate::member_carrier_pair::Record,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.run_authenticated_cleanup(
            context,
            || {
                self.verify_cleanup_runtime_entry(&self.runtime, context)?;
                intent
                    .verify_module_only_read_entry(&self.runtime, context, expected)
                    .map_err(|_| CarrierError::Conflict)?;
                self.verify_cleanup_runtime_entry(&self.runtime, context)
            },
            || {
                let pin = self.read_pin()?;
                pin.verify_call(self, context)?;
                let result = call();
                pin.verify_call(self, context)?;
                result
            },
        )
    }
    /// Bounded factual read for an actual acknowledged module-only attempt.
    /// SAME owning Startup/candidate/loader ACK and current original Pair are
    /// authenticated, not NativeReceipt absence or the Never-effect ledger.
    /// This cannot authorize native effects, unload, deletion or final release.
    ///
    /// # Safety
    /// `call` must query ONLY the actual module-only full read universe under
    /// its SAME outer Pair inspect bracket. No SDK create/close/unload, storage
    /// mutation, imported observation or resource disposition may occur.
    pub(crate) unsafe fn run_module_only_terminal_read<T>(
        &self,
        entry: &super::member_carrier_startup::native::NativeModuleOnlyReadEntry<'_>,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let context = entry.context();
        self.run_authenticated_cleanup(
            context,
            || entry.verify(self),
            || {
                let pin = self.read_pin()?;
                pin.verify_call(self, context)?;
                let result = call();
                pin.verify_call(self, context)?;
                result
            },
        )
    }
    /// One independently authorized original own-reference release. Timing is
    /// NOT native authority: supplier must perform fresh full no-constructor
    /// SDK/private/BFE preflight, preserve native ACK and SDK-free postflight.
    ///
    /// # Safety
    /// SAME retained issuer/original loader/current Stopped Pair bracket MUST
    /// span this entire call. No constructor, other native effect or DATA write.
    pub(crate) unsafe fn run_no_constructor_module_release<T>(
        &self,
        proof: &super::member_carrier_startup::native::NativeNoConstructorReleaseProof,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let context = proof.context();
        self.run_authenticated_cleanup(
            context,
            || proof.verify_entry(self),
            || {
                let pin = self.read_pin()?;
                pin.verify_call(self, context)?;
                let result = call();
                pin.verify_call(self, context)?;
                result
            },
        )
    }
    /// Bounded readonly verification before any carrier/module/key attempt.
    /// A missing native receipt alone NEVER opens this channel: the SAME actual
    /// factory history and precise protected Closing ACK must authenticate it.
    ///
    /// # Safety
    /// `call` must be readonly. It must invoke the actual uncaptured full native
    /// absence verification, not perform a create/configure/close/unload effect.
    /// Original resource gates remain mandatory and forward stays revoked.
    pub(crate) unsafe fn run_uncaptured_read<T>(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
        expected: &crate::member_carrier_pair::Record,
        never: &super::member_carrier_member_controller::native::NativeNeverMemberEffects,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.run_authenticated_cleanup(
            context,
            || never.verify_uncaptured_cleanup_entry(self, intent, expected, context),
            call,
        )
    }
    /// Separate bounded no-C repeated-Stop reader, under the SAME actual
    /// never-effect ledger and original Stopped publication ACK. Missing
    /// NativeCarrierReceipts or caller-provided EMPTY data never grants entry.
    ///
    /// # Safety
    /// `call` must perform ONLY the actual never ledger's full terminal absence
    /// verification inside this Calling. No native or private write is allowed.
    pub(crate) unsafe fn run_uncaptured_terminal_read<T>(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
        expected: &crate::member_carrier_pair::Record,
        never: &super::member_carrier_member_controller::native::NativeNeverMemberEffects,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.run_authenticated_cleanup(
            context,
            || never.verify_uncaptured_terminal_entry(self, intent, expected, context),
            call,
        )
    }
    fn run_authenticated_cleanup<T>(
        &self,
        context: &Context,
        authenticate: impl Fn() -> Result<()>,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.forward_closed.set(true);
        let mut attempt = ReadAttempt {
            owner: self,
            succeeded: false,
        };
        if context != &self.context || !self.deadline.cleanup_eligible() {
            return Err(CarrierError::Retired);
        }
        self.owner.retain_cleanup_only().map_err(denied)?;
        authenticate().inspect_err(|error| {
            #[cfg(test)]
            super::member_carrier_factory_test_os::trace_native("cleanup authentication", error);
            #[cfg(not(test))]
            let _ = error;
        })?;
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step(
            "cleanup pre-entry authentication completed",
        );
        let authenticated_return = std::cell::Cell::new(false);
        let outcome = match self.deadline.run_cleanup(context, || {
            authenticate().inspect_err(|error| {
                #[cfg(test)]
                super::member_carrier_factory_test_os::trace_native(
                    "cleanup authentication",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            #[cfg(test)]
            super::member_carrier_factory_test_os::trace_step(
                "cleanup Calling authentication completed",
            );
            let result = call().inspect_err(|error| {
                #[cfg(test)]
                super::member_carrier_factory_test_os::trace_native("cleanup callback", error);
                #[cfg(not(test))]
                let _ = error;
            });
            authenticate().inspect_err(|error| {
                #[cfg(test)]
                super::member_carrier_factory_test_os::trace_native(
                    "cleanup authentication",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            authenticated_return.set(true);
            result
        }) {
            Ok(value) => Ok(value),
            Err(policy::Failure::Native(error)) => Err(error),
            Err(policy::Failure::Supervisor(error)) => Err(denied(error)),
        };
        attempt.succeeded =
            outcome.is_ok() || (authenticated_return.get() && self.deadline.cleanup_eligible());
        outcome
    }
    /// Before-Pair read-only lane, authenticated by SAME original Never ledger
    /// and acknowledged initial journal plus actual protected Pair absence.
    /// # Safety
    /// Only full native/private/key/service/BFE absence observations may run.
    /// No create, write, close, module effect or manufactured Pair is allowed.
    pub(crate) unsafe fn run_pre_pair_terminal_read<T>(
        &self,
        context: &Context,
        initial: &Rc<super::member_carrier_assembly::native::NativeInitialAssemblyNoCRead>,
        never: &super::member_carrier_member_controller::native::NativeNeverMemberEffects,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.run_authenticated_cleanup(
            context,
            || never.verify_pre_pair_entry(self, initial, context),
            call,
        )
    }
    fn verify_cleanup_entry(
        &self,
        context: &Context,
        intent: &super::member_carrier_pair_store::native_store::NativePairIntentRead,
    ) -> Result<()> {
        use crate::member_carrier_native_ownership::{Phase, Record};
        self.owner.verify_cleanup().map_err(denied)?;
        if context != &self.context || !self.deadline.cleanup_eligible() {
            return Err(CarrierError::Conflict);
        }
        intent
            .verify_cleanup_entry(&self.runtime, context)
            .map_err(|_| CarrierError::Conflict)?;
        let raw = self
            .runtime
            .record(
                context,
                super::member_session::RecordKind::NativeCarrierReceipts,
            )
            .map_err(|_| CarrierError::Conflict)?;
        let native = Record::decode(&raw).map_err(|_| CarrierError::Conflict)?;
        if native.context != *context || !matches!(native.phase, Phase::Closing | Phase::Stopped) {
            return Err(CarrierError::Conflict);
        }
        intent
            .verify_cleanup_entry(&self.runtime, context)
            .map_err(|_| CarrierError::Conflict)?;
        if self
            .runtime
            .record(
                context,
                super::member_session::RecordKind::NativeCarrierReceipts,
            )
            .map_err(|_| CarrierError::Conflict)?
            != raw
        {
            return Err(CarrierError::Conflict);
        }
        self.owner.verify_cleanup().map_err(denied)
    }
    /// Pre-entry factual authentication only. Does not mint a Calling pin or
    /// grant SDK rights while idle after a normally returned operation error.
    pub(crate) fn verify_cleanup_runtime_entry(
        &self,
        runtime: &RuntimeRead,
        context: &Context,
    ) -> Result<()> {
        if !self.forward_closed.get()
            || context != &self.context
            || !self.runtime.same_original_runtime(runtime)
            || !self.deadline.cleanup_eligible()
        {
            return Err(CarrierError::Conflict);
        }
        self.owner.verify_cleanup().map_err(denied)?;
        runtime.verify(context)?;
        self.owner.verify_cleanup().map_err(denied)?;
        if !self.deadline.cleanup_eligible() {
            return Err(CarrierError::Retired);
        }
        Ok(())
    }
    /// Irreversible storage-only cleanup selection of this SAME quiescent
    /// supervisor/runtime. Does not mint Calling, SDK or disposal authority.
    /// Original pre-Pair inventory is authenticated separately by the caller.
    pub(crate) fn begin_original_cleanup_storage(
        &self,
        runtime: &RuntimeRead,
        context: &Context,
    ) -> Result<()> {
        self.forward_closed.set(true);
        if context != &self.context
            || !self.runtime.same_original_runtime(runtime)
            || !self.deadline.cleanup_eligible()
        {
            return Err(CarrierError::Conflict);
        }
        self.owner.retain_cleanup_only().map_err(denied)?;
        self.verify_cleanup_runtime_entry(runtime, context)
    }
    fn verify_lease(&self) -> Result<()> {
        if self.forward_closed.get() {
            if !self.deadline.cleanup_eligible() {
                return Err(CarrierError::Retired);
            }
            self.owner.verify_cleanup().map_err(denied)
        } else {
            self.owner.verify().map_err(denied)
        }
    }
    /// Cancellation is permanent. If an actual call is still in flight, the
    /// watchdog may terminate only this SAME current engine to fail closed.
    pub(crate) fn cancel(&self) -> Result<()> {
        self.owner.uncertain();
        self.deadline.cancel().map_err(denied)
    }
    /// Bookkeeping only AFTER the SAME native whole release. It does not make
    /// this old Runtime/Calling lifetime live again, and the global owner stays
    /// held until the last actual read-pin/root alias drops.
    pub(crate) fn allow_terminal_drop<T, G>(
        &self,
        root: &super::member_carrier_terminal_release::native::NativeTerminalReleaseRoot<T, G>,
        ack: &super::member_carrier_module::native::NativeModuleReleased<T, G>,
    ) -> Result<()>
    where
        G: super::member_carrier_terminal_release::native::NativeTerminalResourceGate<T>,
    {
        self.owner
            .verified_terminal_drop(|| {
                if !self.deadline.cleanup_eligible() || !self.forward_closed.get() {
                    return Err(policy::Error::Revoked);
                }
                root.verify_supervisor_terminal_drop(self, ack)
                    .map_err(|_| policy::Error::Native)?;
                if !self.deadline.cleanup_eligible() {
                    return Err(policy::Error::Revoked);
                }
                Ok(())
            })
            .map_err(denied)
    }

    /// Bookkeeping for a DIFFERENT actual completed no-constructor loader +
    /// canonical owning disposition. Never a ZeroEffect or native permission.
    pub(crate) fn allow_module_only_terminal_drop(
        &self,
        outcome: &super::member_carrier_startup::native::NativeModuleOnlyOutcome,
    ) -> Result<()> {
        self.owner
            .verified_terminal_drop(|| {
                if !self.deadline.cleanup_eligible() || !self.forward_closed.get() {
                    return Err(policy::Error::Revoked);
                }
                outcome
                    .verify_supervisor_terminal_drop(self)
                    .map_err(|_| policy::Error::Native)?;
                if !self.deadline.cleanup_eligible() {
                    return Err(policy::Error::Revoked);
                }
                Ok(())
            })
            .map_err(denied)
    }

    /// The original no-effect Startup has no DLL/module ACK to supply. Its
    /// private typed outcome instead binds the SAME Never ledger, full native
    /// terminal read, watchdog rundown and actual owning-raw disposal. This
    /// only permits final owner bookkeeping, never a forward rearm or SDK call.
    pub(crate) fn allow_zero_effect_terminal_drop(
        &self,
        outcome: &super::member_carrier_startup::native::NativeZeroEffectOutcome,
    ) -> Result<()> {
        self.owner
            .verified_terminal_drop(|| {
                if !self.deadline.cleanup_eligible() || !self.forward_closed.get() {
                    return Err(policy::Error::Revoked);
                }
                outcome
                    .verify_supervisor_terminal_drop(self)
                    .map_err(|_| policy::Error::Native)?;
                if !self.deadline.cleanup_eligible() {
                    return Err(policy::Error::Revoked);
                }
                Ok(())
            })
            .map_err(denied)
    }
    pub(crate) fn allow_pre_pair_terminal_drop(
        &self,
        outcome: &super::member_carrier_startup::native::NativePrePairOutcome,
    ) -> Result<()> {
        self.owner
            .verified_terminal_drop(|| {
                if !self.deadline.cleanup_eligible() || !self.forward_closed.get() {
                    return Err(policy::Error::Revoked);
                }
                outcome
                    .verify_supervisor_terminal_drop(self)
                    .map_err(|_| policy::Error::Native)?;
                if !self.deadline.cleanup_eligible() {
                    return Err(policy::Error::Revoked);
                }
                Ok(())
            })
            .map_err(denied)
    }
}
impl NativeDeadlineReadPin {
    /// Full native authentication happens before issuing the transaction-local
    /// sequence pin; its later raw-lock checks perform no Runtime/backend IO.
    pub(crate) fn transaction_pin(
        &self,
        owner: &NativeDeadline,
        context: &Context,
    ) -> Result<NativeTransactionCallPin> {
        self.verify_call(owner, context)?;
        let policy = owner
            .deadline
            .transaction_pin(&self.policy, context)
            .map_err(denied)?;
        Ok(NativeTransactionCallPin {
            owner: self.owner.clone(),
            runtime: self.runtime.read_pin()?,
            context: context.clone(),
            policy,
        })
    }
    pub(crate) fn verify_runtime(
        &self,
        owner: &NativeDeadline,
        runtime: &RuntimeRead,
        context: &Context,
    ) -> Result<()> {
        let mut attempt = ReadAttempt {
            owner,
            succeeded: false,
        };
        if !self.runtime.same_original_runtime(runtime) {
            return Err(CarrierError::Conflict);
        }
        self.verify(owner, context)?;
        runtime.verify(context)?;
        attempt.succeeded = true;
        Ok(())
    }
    /// Timing/retention only: independent native/WFP/network authority is still
    /// mandatory. An idle valid owner/pin cannot authorize an unsupervised call.
    pub(crate) fn verify_call(&self, owner: &NativeDeadline, context: &Context) -> Result<()> {
        let mut attempt = ReadAttempt {
            owner,
            succeeded: false,
        };
        self.verify(owner, context)?;
        owner
            .deadline
            .verify_call(&self.policy, context)
            .map_err(denied)?;
        self.runtime.verify(context)?;
        // Runtime read itself may have exhausted the same native budget.
        owner
            .deadline
            .verify_call(&self.policy, context)
            .map_err(denied)?;
        attempt.succeeded = true;
        Ok(())
    }
    pub(crate) fn verify(&self, owner: &NativeDeadline, context: &Context) -> Result<()> {
        let mut attempt = ReadAttempt {
            owner,
            succeeded: false,
        };
        if !Rc::ptr_eq(&self.owner, &owner.owner)
            || !self.runtime.same_original_runtime(&owner.runtime)
        {
            return Err(CarrierError::Conflict);
        }
        self.runtime.verify(context)?;
        owner.verify_lease()?;
        owner
            .deadline
            .verify_pin(&self.policy, context)
            .map_err(denied)?;
        self.runtime.verify(context)?;
        attempt.succeeded = true;
        Ok(())
    }
}
struct ReadAttempt<'a> {
    owner: &'a NativeDeadline,
    succeeded: bool,
}
impl Drop for ReadAttempt<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.owner.owner.uncertain();
            let _ = self.owner.deadline.cancel();
        }
    }
}
fn denied(error: policy::Error) -> CarrierError {
    match error {
        policy::Error::Deadline => CarrierError::Deadline,
        policy::Error::Revoked | policy::Error::Cancelled => CarrierError::Retired,
        policy::Error::Scope | policy::Error::Reentrant => CarrierError::Conflict,
        _ => CarrierError::Native,
    }
}

// Only this private factory can build the real process-targeting kernel. Worker
// sharing uses std OwnedHandle's Send/Sync guarantees: kernel objects support
// these waits/signals/queries concurrently, and Arc retains each actual object
// until the tracked worker joins. No unsafe Send/Sync runtime/actor bypass.
struct CurrentFactory {
    process: Arc<OwnedHandle>,
    identity: CurrentIdentity,
}
struct CurrentKernel {
    process: Arc<OwnedHandle>,
    identity: CurrentIdentity,
    ready: OwnedHandle,
    stop: OwnedHandle,
}
impl Factory for CurrentFactory {
    type Kernel = CurrentKernel;
    fn create(&mut self) -> policy::Result<CurrentKernel> {
        if process_identity(&self.process)? != self.identity {
            return Err(policy::Error::Worker);
        }
        Ok(CurrentKernel {
            process: self.process.clone(),
            identity: self.identity,
            ready: event()?,
            stop: event()?,
        })
    }
}
impl Kernel for CurrentKernel {
    fn now_ms(&self) -> u64 {
        unsafe { GetTickCount64() }
    }
    fn signal_ready(&self) -> policy::Result<()> {
        signal(&self.ready)
    }
    fn wait_ready(&self, timeout_ms: u32) -> policy::Result<policy::Wait> {
        wait(&self.ready, timeout_ms)
    }
    fn signal_stop(&self) -> policy::Result<()> {
        signal(&self.stop)
    }
    fn wait_stop(&self, timeout_ms: u32) -> policy::Result<policy::Wait> {
        wait(&self.stop, timeout_ms)
    }
    fn terminate_current(&self) -> policy::Result<()> {
        // This handle was duplicated ONLY from GetCurrentProcess, never opened
        // by PID/name. It still references that exact kernel object even after
        // exit/PID recycling. This call is not driver/global/thread termination.
        if process_identity(&self.process)? != self.identity {
            return Err(policy::Error::Worker);
        }
        if unsafe { TerminateProcess(self.process.as_raw_handle(), UNKNOWN_OUTCOME_EXIT) } == 0 {
            return Err(policy::Error::Worker);
        }
        Ok(())
    }
}
fn capture_current() -> policy::Result<OwnedHandle> {
    let current = unsafe { GetCurrentProcess() };
    let mut actual = ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            current,
            current,
            current,
            &mut actual,
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            0,
        )
    } == 0
        || actual.is_null()
    {
        return Err(policy::Error::Worker);
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(actual) })
}
fn process_identity(process: &OwnedHandle) -> policy::Result<CurrentIdentity> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    let pid = unsafe { GetProcessId(process.as_raw_handle()) };
    if pid == 0
        || unsafe {
            GetProcessTimes(
                process.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        || exited.dwHighDateTime != 0
        || exited.dwLowDateTime != 0
        || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
    {
        return Err(policy::Error::Worker);
    }
    let creation = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
    if creation == 0 {
        return Err(policy::Error::Worker);
    }
    Ok(CurrentIdentity { pid, creation })
}
fn event() -> policy::Result<OwnedHandle> {
    // Unnamed, non-inheritable manual-reset event, initially unsignaled. No
    // external name/ACL/PID can attach to or select this worker's objects.
    let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if handle.is_null() {
        return Err(policy::Error::Worker);
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn signal(handle: &OwnedHandle) -> policy::Result<()> {
    if unsafe { SetEvent(handle.as_raw_handle()) } == 0 {
        Err(policy::Error::Worker)
    } else {
        Ok(())
    }
}
fn wait(handle: &OwnedHandle, timeout_ms: u32) -> policy::Result<policy::Wait> {
    decode_wait(unsafe { WaitForSingleObject(handle.as_raw_handle(), timeout_ms) })
}
fn decode_wait(value: u32) -> policy::Result<policy::Wait> {
    match value {
        WAIT_OBJECT_0 => Ok(policy::Wait::Signaled),
        WAIT_TIMEOUT => Ok(policy::Wait::Timeout),
        _ => Err(policy::Error::Worker),
    }
}

#[cfg(test)]
#[path = "member_native_deadline_tests.rs"]
mod tests;
