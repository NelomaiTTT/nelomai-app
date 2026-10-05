// Included inside the actual Wintun native module: no raw ACK data constructor.
use crate::windows::{
    member_carrier_creators as creators, member_carrier_key_authority::RuntimeRead,
    member_carrier_module::native::OriginalImage, member_carrier_provider,
};

/// Actual original adapter ACK + original signed image + SAME actual runtime
/// serialized lease. No mutable effect access or adoption by a lookup identity.
pub(crate) struct OriginalWintun {
    original: OriginalAdapterRead,
    runtime: RuntimeRead,
    image: OriginalImage,
    scope: creators::Scope,
}
/// Terminal effect fence, not supplied by metadata or a close-state bit.
/// # Safety
/// Reattest the SAME active outer Pair Stopped pin, Runtime/Calling sequence
/// and THIS actual full Retired callback before/after the effect. Never enter
/// another Pair, Source or SDK inventory callback recursively. No defaults.
pub(crate) unsafe trait NativeOriginalReferenceFence {
    fn verify_original_terminal(&self, scope: &creators::Scope) -> creators::Result<()>;
}
pub(crate) struct OriginalUniverse {
    runtime: RuntimeRead,
    image: OriginalImage,
    members: Option<crate::windows::member_carrier_members::native::MemberInventoryRead>,
}
/// Real source/runtime/SAME-lease pins prepared BEFORE a native effect. Its
/// constructor grants NO create permission and takes no lookup-derived ACK.
pub(crate) struct PreparedOriginal {
    runtime: RuntimeRead,
    image: OriginalImage,
    scope: creators::Scope,
}
/// Actual independently observed original registry for KEY-only authority.
/// It grants no module/session/close rights and cannot invent an original ACK.
pub(crate) struct OriginalKeyInventory {
    observer: creators::Observer<OriginalWintun>,
    runtime: RuntimeRead,
    image: OriginalImage,
    members: Option<crate::windows::member_carrier_members::native::MemberInventoryRead>,
}
/// Complete actual original set for post-create package refresh. This is not
/// cleanup permission; poisoned/pending/retiring registry observations deny it.
pub(crate) struct OriginalPackageInventory {
    observer: creators::Observer<OriginalWintun>,
    runtime: RuntimeRead,
    image: OriginalImage,
    context: receipt::Context,
}
/// Only factual reads under an actual current protected Closing record. Cannot
/// convert back into forward permission or issue original end/close effects.
pub(crate) struct OriginalCleanupPackage<'a>(&'a mut OriginalPackageInventory);
impl OriginalPackageInventory {
    pub(crate) fn new(
        observer: creators::Observer<OriginalWintun>,
        runtime: &RuntimeRead,
        image: &OriginalImage,
    ) -> creators::Result<Self> {
        image.verify_runtime(runtime).map_err(original_error)?;
        let context = observer.context().clone();
        runtime.verify(&context).map_err(original_error)?;
        Ok(Self {
            observer,
            runtime: runtime.read_pin().map_err(original_error)?,
            image: image.read_pin().map_err(original_error)?,
            context,
        })
    }
    pub(crate) fn from_producer(
        producer: &creators::Producer<OriginalWintun>,
        runtime: &RuntimeRead,
        image: &OriginalImage,
    ) -> creators::Result<Self> {
        producer
            .original_universe()
            .matches_original_runtime_image(runtime, image)?;
        Self::new(producer.observer(), runtime, image)
    }
    pub(crate) fn matches_source(
        &self,
        source: &std::rc::Rc<crate::windows::member_carrier_payload::native::WintunSource>,
    ) -> bool {
        self.image.matches_source(source)
    }
    pub(crate) fn cleanup_devices(&mut self) -> OriginalCleanupPackage<'_> {
        OriginalCleanupPackage(self)
    }
    fn observe_for(
        &mut self,
        cleanup: bool,
    ) -> std::result::Result<
        (
            Option<u32>,
            Vec<crate::windows::member_carrier_wintun_package::Device>,
        ),
        crate::windows::member_carrier_wintun_package::Error,
    > {
        use crate::windows::member_carrier_wintun_package::{Device, Error as PackageError};
        let read = || -> std::result::Result<Vec<u8>, PackageError> {
            let (bytes, fresh) = self
                .runtime
                .record_with_fresh(
                    &self.context,
                    crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                )
                .map_err(|_| PackageError::Changed)?;
            let record = receipt::Record::decode(&bytes).map_err(|_| PackageError::Changed)?;
            let expected = if cleanup {
                receipt::Phase::Closing
            } else {
                receipt::Phase::Preparing
            };
            if record.context != self.context || record.phase != expected || !cleanup && !fresh {
                return Err(PackageError::Changed);
            }
            Ok(bytes)
        };
        let before_record = read()?;
        // The protected read authenticates this SAME runtime/context. Each
        // driver query below independently verifies the original image/source/
        // runtime BEFORE and AFTER its SDK call. Keep those complete fences;
        // separate image/runtime reads immediately outside them add no facts.
        let before = self
            .image
            .running_driver_version(&self.runtime)
            .map_err(|_| PackageError::Changed)?;
        let observations = if cleanup {
            self.observer.observe_all_for_cleanup(&self.context)
        } else {
            self.observer.observe_all(&self.context)
        }
        .map_err(|_| PackageError::Changed)?;
        // This observer reads every SAME raw original identity/close receipt
        // before and again after the complete C+member PnP/MIB/SCM universe.
        // Preserve its full census and completed raw-original revalidation;
        // the package independently observes originals around ALL trust checks.
        let kinds = observations
            .complete
            .iter()
            .map(|(kind, _)| *kind)
            .collect::<Vec<_>>();
        let devices = observations
            .complete
            .iter()
            .map(|(_, o)| Device {
                instance: o.instance.instance.clone(),
                status: o.instance.status,
                problem: o.instance.problem,
            })
            .collect::<Vec<_>>();
        let devices = crate::windows::member_carrier_members::package_devices(&kinds, &devices)
            .map_err(|_| PackageError::Changed)?;
        if before
            != self
                .image
                .running_driver_version(&self.runtime)
                .map_err(|_| PackageError::Changed)?
        {
            return Err(PackageError::Changed);
        }
        if before_record != read()? {
            return Err(PackageError::Changed);
        }
        Ok((before, devices))
    }
}
// SAFETY: production full original registry (no lookup-derived handles) queries
// SAME retained raw ACK identities and full independent PnP/MIB universe. Actual
// running version is read through SAME original HMODULE/source/serialized lease
// before/after. LoadedWintun enforces pointer equality to its original Source Rc
// at both sides. Current protected Preparing bytes/freshness are reread; any
// lost ACK/poison/unknown denies. This supplies factual reads, never effects.
unsafe impl crate::windows::member_carrier_wintun_package::OriginalDevices
    for OriginalPackageInventory
{
    fn observe(
        &mut self,
    ) -> std::result::Result<
        (
            Option<u32>,
            Vec<crate::windows::member_carrier_wintun_package::Device>,
        ),
        crate::windows::member_carrier_wintun_package::Error,
    > {
        self.observe_for(false)
    }
}
// SAFETY: same actual pins/universe as above, explicitly current Closing bytes
// on both sides. Poison remains set. Only actual once-close receipts can remove
// retained originals from the COMPLETE independent factual universe. Missing ACK
// cannot be called absent. No cleanup-effect authority is supplied by this type.
unsafe impl crate::windows::member_carrier_wintun_package::OriginalDevices
    for OriginalCleanupPackage<'_>
{
    fn observe(
        &mut self,
    ) -> std::result::Result<
        (
            Option<u32>,
            Vec<crate::windows::member_carrier_wintun_package::Device>,
        ),
        crate::windows::member_carrier_wintun_package::Error,
    > {
        self.0.observe_for(true)
    }
}
impl OriginalKeyInventory {
    pub(crate) fn new(
        observer: creators::Observer<OriginalWintun>,
        runtime: &RuntimeRead,
        image: &OriginalImage,
    ) -> creators::Result<Self> {
        image.verify_runtime(runtime).map_err(original_error)?;
        Ok(Self {
            observer,
            runtime: runtime.read_pin().map_err(original_error)?,
            image: image.read_pin().map_err(original_error)?,
            members: None,
        })
    }
    pub(crate) fn from_producer(
        producer: &creators::Producer<OriginalWintun>,
        runtime: &RuntimeRead,
        image: &OriginalImage,
    ) -> creators::Result<Self> {
        producer
            .original_universe()
            .matches_original_runtime_image(runtime, image)?;
        let mut inventory = Self::new(producer.observer(), runtime, image)?;
        inventory.members = producer
            .original_universe()
            .members
            .as_ref()
            .map(|m| m.read_pin());
        Ok(inventory)
    }
    fn inspect_target(
        &self,
        context: &receipt::Context,
        binding: &receipt::Binding,
        cleanup: bool,
    ) -> creators::Result<()> {
        let Some(members) = &self.members else {
            if cleanup
                && !member_carrier_provider::native::inspect_all(&[])
                    .map_err(original_error)?
                    .is_empty()
            {
                return Err(creators::Error::Conflict);
            }
            return member_carrier_provider::native::inspect_absent(binding.guid, &binding.name)
                .map_err(original_error);
        };
        let observe = || {
            if cleanup {
                self.observer.observe_all_for_cleanup(context)
            } else {
                self.observer.observe_all(context)
            }
        };
        #[cfg(test)]
        crate::windows::member_carrier_factory_test_os::trace_step(
            "key target full before census begin",
        );
        let before = observe()?;
        #[cfg(test)]
        crate::windows::member_carrier_factory_test_os::trace_step(
            "key target full before census end",
        );
        if before.context != *context
            || before.originals.iter().any(|o| {
                o.scope.binding != context.bindings[0]
                    || o.identity.guid == binding.guid
                    || o.identity.name.eq_ignore_ascii_case(&binding.name)
            })
        {
            return Err(creators::Error::Conflict);
        }
        let carrier = before
            .originals
            .iter()
            .map(|o| member_carrier_provider::ExpectedProvider {
                kind: member_carrier_provider::ProviderKind::Wintun,
                identity: o.provider.interface.clone(),
            })
            .collect::<Vec<_>>();
        #[cfg(test)]
        crate::windows::member_carrier_factory_test_os::trace_step(
            "key target independent mixed read begin",
        );
        members
            .inspect_full(context, &self.runtime, &self.image, |member_facts| {
                let inputs = crate::windows::member_carrier_members::key_provider_inputs(
                    context,
                    &carrier,
                    member_facts,
                    cleanup,
                    binding,
                )?;
                member_carrier_provider::native::inspect_mixed_absent(
                    &inputs,
                    binding.guid,
                    &binding.name,
                )
                .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                Ok(())
            })
            .map_err(original_error)?;
        #[cfg(test)]
        crate::windows::member_carrier_factory_test_os::trace_step(
            "key target independent mixed read end",
        );
        if before != observe()? {
            return Err(creators::Error::Conflict);
        }
        #[cfg(test)]
        crate::windows::member_carrier_factory_test_os::trace_step(
            "key target full after census end",
        );
        Ok(())
    }
    fn recheck(
        &self,
        context: &receipt::Context,
        binding: &receipt::Binding,
    ) -> creators::Result<()> {
        #[cfg(test)]
        crate::windows::member_carrier_factory_test_os::trace_step("key inventory recheck begin");
        self.runtime.verify(context).map_err(original_error)?;
        self.image
            .verify_runtime(&self.runtime)
            .map_err(original_error)?;
        let read = || -> creators::Result<Vec<u8>> {
            let bytes = self
                .runtime
                .record(
                    context,
                    crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                )
                .map_err(original_error)?;
            let record = receipt::Record::decode(&bytes).map_err(original_error)?;
            if record.context != *context || !context.bindings.contains(binding) {
                return Err(creators::Error::Conflict);
            }
            Ok(bytes)
        };
        let before = read()?;
        match receipt::Record::decode(&before)
            .map_err(original_error)?
            .phase
        {
            receipt::Phase::Closing => {
                // A poisoned creator cannot grant forward permission. Only a
                // never-attempted role or completed exact original close plus
                // independently EMPTY full native universe permits key cleanup
                // to proceed to its separate current HKEY/storage CAS gate.
                self.observer
                    .assert_no_creator_for_key_cleanup(context, binding)?;
                self.inspect_target(context, binding, true)?;
                self.observer
                    .assert_no_creator_for_key_cleanup(context, binding)?;
            }
            receipt::Phase::Preparing => {
                self.image
                    .verify_live_runtime(&self.runtime)
                    .map_err(original_error)?;
                let state = self.observer.snapshot(context)?;
                let index = context
                    .bindings
                    .iter()
                    .position(|b| b == binding)
                    .ok_or(creators::Error::Conflict)?;
                let target_checked = if state[index] == creators::State::Intent {
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::trace_step(
                        "key inventory private Never begin",
                    );
                    self.observer.assert_never_attempted(context, binding)?;
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::trace_step(
                        "key inventory private Never end",
                    );
                    // The same full original SDK query now checks the target
                    // on EVERY MIB/PnP read. Raw C, member originals, runtime/
                    // image and protected revision already fence that whole
                    // query. No second complete census is needed here.
                    self.members.is_some()
                } else {
                    self.observer.assert_absent(context, binding)?;
                    false
                };
                if self.members.is_none() {
                    // The legacy target reader has no before/after census;
                    // keep its existing independent full-universe query.
                    let universe = self.observer.observe_all(context)?;
                    if universe.originals.iter().any(|o| {
                        o.identity.guid == binding.guid
                            || o.identity.name.eq_ignore_ascii_case(&binding.name)
                    }) {
                        return Err(creators::Error::Conflict);
                    }
                }
                if !target_checked {
                    self.inspect_target(context, binding, false)?;
                }
                self.image
                    .verify_live_runtime(&self.runtime)
                    .map_err(original_error)?;
            }
            receipt::Phase::Stopped => return Err(creators::Error::Conflict),
        }
        self.image
            .verify_runtime(&self.runtime)
            .map_err(original_error)?;
        if before != read()? {
            return Err(creators::Error::Conflict);
        }
        self.runtime.verify(context).map_err(original_error)?;
        #[cfg(test)]
        crate::windows::member_carrier_factory_test_os::trace_step("key inventory recheck end");
        Ok(())
    }
}
impl crate::windows::member_carrier_key_authority::OriginalCreatorInventory
    for OriginalKeyInventory
{
    fn inspect_absence(
        &mut self,
        context: &receipt::Context,
        binding: &receipt::Binding,
    ) -> crate::member_carrier::Result<(bool, bool, bool)> {
        if self.members.is_none() {
            // Preserve the legacy reader's original two complete rounds.
            self.recheck(context, binding)
                .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
        }
        // This succeeds only after complete native MIB/PnP target absence AND
        // private Never/exact original closure, with actual raw originals,
        // member receipts, image/runtime/current revision checked on both sides.
        // No saved record or numeric identity constructs an owning receipt.
        self.recheck(context, binding)
            .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
        Ok((true, true, true))
    }
}
fn original_error(_: impl std::fmt::Debug) -> creators::Error {
    creators::Error::Conflict
}
impl PreparedOriginal {
    pub(crate) fn new(
        runtime: &RuntimeRead,
        image: &OriginalImage,
        scope: creators::Scope,
    ) -> creators::Result<Self> {
        let prepared = Self {
            runtime: runtime.read_pin().map_err(original_error)?,
            image: image.read_pin().map_err(original_error)?,
            scope,
        };
        let context = &prepared.scope.context;
        let read = || -> creators::Result<Vec<u8>> {
            prepared
                .image
                .verify_live_runtime(&prepared.runtime)
                .map_err(original_error)?;
            if !prepared.runtime.fresh(context).map_err(original_error)? {
                return Err(creators::Error::Conflict);
            }
            let bytes = prepared
                .runtime
                .record(
                    context,
                    crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                )
                .map_err(original_error)?;
            let record = receipt::Record::decode(&bytes).map_err(original_error)?;
            receipt::validate_carrier_create_stage(
                &record,
                context,
                &prepared.scope.binding,
                prepared.scope.generation,
            )
            .map_err(original_error)?;
            prepared
                .image
                .verify_live_runtime(&prepared.runtime)
                .map_err(original_error)?;
            if !prepared.runtime.fresh(context).map_err(original_error)? {
                return Err(creators::Error::Conflict);
            }
            Ok(bytes)
        };
        if read()? != read()? {
            return Err(creators::Error::Changed);
        }
        Ok(prepared)
    }
    /// Called immediately after SAME real native NEW-create ACK. Field moves
    /// ONLY: no allocation, auth, PnP, DLL read, journal or fallible query here.
    /// Registry acknowledgement retains this original before it validates or
    /// publishes it; a later failure poisons authority but cannot lose its pins.
    pub(crate) fn acknowledge(self, original: OriginalAdapterRead) -> OriginalWintun {
        OriginalWintun {
            original,
            runtime: self.runtime,
            image: self.image,
            scope: self.scope,
        }
    }
}
impl OriginalWintun {
    fn verify(&self, scope: &creators::Scope) -> creators::Result<()> {
        if *scope != self.scope {
            return Err(creators::Error::Conflict);
        }
        let (context, binding, generation) = self.original.creation();
        if *context != scope.context
            || *binding != scope.binding
            || generation != scope.generation
            || generation == 0
        {
            return Err(creators::Error::Conflict);
        }
        self.runtime.verify(context).map_err(original_error)?;
        if self
            .image
            .cleanup_read_module_for_runtime(&self.runtime)
            .map_err(original_error)?
            != self.original.original_module()
        {
            return Err(creators::Error::Conflict);
        }
        Ok(())
    }
    /// Opaque receipt can exist only after consuming this original Adapter in
    /// NativeKernel.close and its native void close call returning once. This
    /// takes no destructive action and supplies no permission to perform one.
    pub(crate) fn take_closed(&self) -> creators::Result<OriginalAdapterClosed> {
        self.verify(&self.scope)?;
        self.original.take_closed().map_err(original_error)
    }
    pub(crate) fn release_closed_reference_in_terminal(
        &self,
        scope: &creators::Scope,
        closed: &OriginalAdapterClosed,
        fence: &impl NativeOriginalReferenceFence,
        retain: impl FnOnce(std::rc::Rc<OriginalAdapterModuleReleased>) -> creators::Result<()>,
    ) -> creators::Result<()> {
        fence.verify_original_terminal(scope)?;
        self.verify(scope)?;
        self.original
            .verify_closed(closed)
            .map_err(original_error)?;
        self.original
            .release_closed_module_reference_with_pin(closed, |ack| {
                retain(ack).map_err(|_| Error::Conflict)?;
                fence
                    .verify_original_terminal(scope)
                    .map_err(|_| Error::Conflict)
            })
            .map_err(original_error)?;
        self.verify(scope)?;
        fence.verify_original_terminal(scope)
    }
    /// Factual ACK comparison while the owning DLL is still independently
    /// Calling-pinned. No closed raw adapter query or new native effect.
    pub(crate) fn verify_closed_reference_in_terminal(
        &self,
        scope: &creators::Scope,
        closed: &OriginalAdapterClosed,
        ack: &OriginalAdapterModuleReleased,
    ) -> creators::Result<()> {
        self.verify(scope)?;
        ack.verify_original(&self.original, closed)
            .map_err(original_error)?;
        self.verify(scope)
    }
}
impl OriginalUniverse {
    /// Match actual opaque original pins, never metadata-only contexts.
    pub(crate) fn matches_original_runtime_image(
        &self,
        runtime: &RuntimeRead,
        image: &OriginalImage,
    ) -> creators::Result<()> {
        self.image.verify_runtime(runtime).map_err(original_error)?;
        image.verify_runtime(runtime).map_err(original_error)?;
        if !self.runtime.same_original_runtime(runtime)
            || self.image.cleanup_read_module().map_err(original_error)?
                != image.cleanup_read_module().map_err(original_error)?
        {
            return Err(creators::Error::Conflict);
        }
        self.image.verify_runtime(runtime).map_err(original_error)?;
        image.verify_runtime(runtime).map_err(original_error)?;
        if let Some(members) = &self.members {
            members
                .matches_original_runtime_image(runtime, image)
                .map_err(original_error)?;
        }
        Ok(())
    }
    pub(crate) fn new(runtime: &RuntimeRead, image: &OriginalImage) -> creators::Result<Self> {
        image.verify_runtime(runtime).map_err(original_error)?;
        Ok(Self {
            runtime: runtime.read_pin().map_err(original_error)?,
            image: image.read_pin().map_err(original_error)?,
            members: None,
        })
    }
    /// Attach actual service-owner readers, never cloned proof metadata or
    /// Wintun ACKs for WG/AWG. Native provider still queries the FULL universe.
    pub(crate) fn with_members(
        mut self,
        members: crate::windows::member_carrier_members::native::MemberInventoryRead,
    ) -> creators::Result<Self> {
        if self.members.is_some() {
            return Err(creators::Error::Conflict);
        }
        members
            .matches_original_runtime_image(&self.runtime, &self.image)
            .map_err(original_error)?;
        self.members = Some(members);
        Ok(self)
    }
    /// SAME actual retained service readers; not a constructor from identities.
    /// Full provider verification remains mandatory around every row use.
    pub(crate) fn member_read_pin(
        &self,
    ) -> creators::Result<crate::windows::member_carrier_members::native::MemberInventoryRead> {
        let members = self.members.as_ref().ok_or(creators::Error::Conflict)?;
        members
            .matches_original_runtime_image(&self.runtime, &self.image)
            .map_err(original_error)?;
        Ok(members.read_pin())
    }
    fn verify(&self, context: &receipt::Context) -> creators::Result<()> {
        // Bind the supplied context first. The complete original-image read
        // then authenticates this SAME runtime/context on both sides of the
        // actual mapping/source query; an extra outer reread adds no facts.
        self.runtime.verify(context).map_err(original_error)?;
        self.image
            .verify_runtime(&self.runtime)
            .map_err(original_error)
    }
}

// SAFETY: constructors accept only the opaque ACK retained immediately after
// real native NEW-create, original loaded image and authenticated RuntimeRead.
// Reads call that SAME raw adapter's LUID function, not Carrier.capture or an
// inventory callback. Every read is source/module/runtime/SAME lease bracketed.
// Close receipt is privately produced by the exact native once-close state.
// Unclosed Drop leaks its native reference, never implicit close/adoption/unload.
unsafe impl creators::OriginalNative for OriginalWintun {
    type Provider = member_carrier_provider::Observation;
    type CloseReceipt = OriginalAdapterClosed;
    type Universe = OriginalUniverse;
    fn original_identity(
        &self,
        scope: &creators::Scope,
    ) -> creators::Result<creators::OriginalIdentity> {
        self.verify(scope)?;
        let luid = self.original.original_luid().map_err(original_error)?;
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: NET_LUID_LH { Value: luid },
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut row) } != 0 {
            return Err(creators::Error::Native);
        }
        virtual_role(row.InterfaceAndOperStatusFlags._bitfield).map_err(original_error)?;
        let identity = creators::Identity {
            guid: guid_bytes(&row.InterfaceGuid),
            luid: unsafe { row.InterfaceLuid.Value },
            index: row.InterfaceIndex,
            name: wide_string(&row.Alias).map_err(original_error)?,
            description: wide_string(&row.Description).map_err(original_error)?,
            if_type: row.Type,
            tunnel_type: row.TunnelType,
        };
        let resource = self.original.0.live_resource().map_err(original_error)?;
        if identity.guid != scope.binding.guid
            || identity.name != scope.binding.name
            || identity.luid != luid
            || identity.index == 0
            || identity.if_type != 53
            || identity.tunnel_type != 0
            || !crate::member_interface_description::matches_requested(
                &format!("{} Tunnel", resource.tunnel_type),
                &identity.description,
            )
        {
            return Err(creators::Error::Conflict);
        }
        let mut index_row = MIB_IF_ROW2 {
            InterfaceIndex: identity.index,
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut index_row) } != 0 {
            return Err(creators::Error::Native);
        }
        virtual_role(index_row.InterfaceAndOperStatusFlags._bitfield).map_err(original_error)?;
        if unsafe { index_row.InterfaceLuid.Value } != luid
            || guid_bytes(&index_row.InterfaceGuid) != identity.guid
            || wide_string(&index_row.Alias).map_err(original_error)? != identity.name
            || wide_string(&index_row.Description).map_err(original_error)? != identity.description
            || index_row.Type != identity.if_type
            || index_row.TunnelType != identity.tunnel_type
            || self.original.original_luid().map_err(original_error)? != luid
        {
            return Err(creators::Error::Changed);
        }
        self.verify(scope)?;
        Ok(creators::OriginalIdentity {
            scope: scope.clone(),
            identity,
        })
    }
    fn verify_close_receipt(
        &self,
        scope: &creators::Scope,
        ack: &Self::CloseReceipt,
    ) -> creators::Result<()> {
        self.verify(scope)?;
        self.original.verify_closed(ack).map_err(original_error)?;
        self.verify(scope)
    }
}

// SAFETY: one COMPLETE factual native provider query for all original inputs,
// even zero originals. No per-device owned filter, cached provider bit or
// lookup-derived ownership. Creator registry separately reads each raw ACK.
unsafe impl creators::NativeUniverse<OriginalWintun> for OriginalUniverse {
    fn inspect_universe(
        &self,
        context: &receipt::Context,
        originals: &[creators::OriginalIdentity],
        absent: Option<&receipt::Binding>,
    ) -> creators::Result<creators::UniverseObservation<member_carrier_provider::Observation>> {
        self.verify(context)?;
        if originals.len() > 3
            || originals.iter().any(|o| o.scope.context != *context)
            || absent.is_some_and(|binding| !context.bindings.contains(binding))
        {
            return Err(creators::Error::Conflict);
        }
        let targets = originals
            .iter()
            .map(|o| Identity {
                guid: o.identity.guid,
                luid: o.identity.luid,
                index: o.identity.index,
                name: o.identity.name.clone(),
                description: o.identity.description.clone(),
                if_type: o.identity.if_type,
                tunnel_type: o.identity.tunnel_type,
            })
            .collect::<Vec<_>>();
        let complete = if let Some(members) = &self.members {
            // C is the sole raw Wintun creator in the integrated topology;
            // A/B must originate in their actual SCM/process owners instead.
            if originals
                .iter()
                .any(|o| o.scope.binding != context.bindings[0])
            {
                return Err(creators::Error::Conflict);
            }
            let carrier = targets
                .iter()
                .cloned()
                .map(|identity| member_carrier_provider::ExpectedProvider {
                    identity: member_carrier_provider::Expected {
                        guid: identity.guid,
                        luid: identity.luid,
                        index: identity.index,
                        name: identity.name,
                        description: identity.description,
                        if_type: identity.if_type,
                        tunnel_type: identity.tunnel_type,
                    },
                    kind: member_carrier_provider::ProviderKind::Wintun,
                })
                .collect::<Vec<_>>();
            let before = self
                .runtime
                .record(
                    context,
                    crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                )
                .map_err(original_error)?;
            let record = receipt::Record::decode(&before).map_err(original_error)?;
            if record.context != *context {
                return Err(creators::Error::Conflict);
            }
            if absent.is_some() && record.phase != receipt::Phase::Preparing {
                return Err(creators::Error::Conflict);
            }
            let inspect = |member_facts: &[member_carrier_provider::ExpectedProvider]| {
                let complete = crate::windows::member_carrier_members::complete_provider_inputs(
                    context,
                    &carrier,
                    member_facts,
                )?;
                let facts = if let Some(binding) = absent {
                    member_carrier_provider::native::inspect_mixed_absent(
                        &complete,
                        binding.guid,
                        &binding.name,
                    )
                } else {
                    member_carrier_provider::native::inspect_mixed(&complete)
                }
                .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                if facts.len() != complete.len() {
                    return Err(crate::member_carrier::CarrierError::Conflict);
                }
                Ok(complete
                    .iter()
                    .map(|input| input.kind)
                    .zip(facts)
                    .collect::<Vec<_>>())
            };
            let facts = match record.phase {
                receipt::Phase::Closing => {
                    members.inspect_closing_full(context, &self.runtime, &self.image, inspect)
                }
                receipt::Phase::Preparing => {
                    members.inspect_full(context, &self.runtime, &self.image, inspect)
                }
                receipt::Phase::Stopped => {
                    crate::windows::member_carrier_runtime::inspect_terminal_universe(
                        &record,
                        context,
                        originals.len(),
                        || {
                            // No historical identities enter live SDK inputs.
                            // SAME original member close receipts and FULL mixed
                            // SDK emptiness bracket this callback independently.
                            members.inspect_terminal_bindings_full(
                                context,
                                &self.runtime,
                                &self.image,
                                |_| Ok(Vec::new()),
                            )
                        },
                    )
                }
            }
            .map_err(original_error)?;
            if self
                .runtime
                .record(
                    context,
                    crate::windows::member_session::RecordKind::NativeCarrierReceipts,
                )
                .map_err(original_error)?
                != before
            {
                return Err(creators::Error::Conflict);
            }
            facts
        } else {
            // Legacy strict path does not learn to accept an unowned WG device.
            let facts = if let Some(binding) = absent {
                let complete = targets
                    .iter()
                    .map(|identity| member_carrier_provider::ExpectedProvider {
                        identity: member_carrier_provider::Expected {
                            guid: identity.guid,
                            luid: identity.luid,
                            index: identity.index,
                            name: identity.name.clone(),
                            description: identity.description.clone(),
                            if_type: identity.if_type,
                            tunnel_type: identity.tunnel_type,
                        },
                        kind: member_carrier_provider::ProviderKind::Wintun,
                    })
                    .collect::<Vec<_>>();
                member_carrier_provider::native::inspect_mixed_absent(
                    &complete,
                    binding.guid,
                    &binding.name,
                )
                .map_err(original_error)?
            } else {
                member_carrier_provider::native::inspect_all(&targets).map_err(original_error)?
            };
            facts
                .into_iter()
                .map(|fact| (member_carrier_provider::ProviderKind::Wintun, fact))
                .collect::<Vec<_>>()
        };
        self.verify(context)?;
        if complete.len() < originals.len() || complete.len() > 3 {
            return Err(creators::Error::Conflict);
        }
        let observations = originals
            .iter()
            .zip(
                complete
                    .iter()
                    .take(originals.len())
                    .map(|(_, fact)| fact.clone()),
            )
            .map(|(o, provider)| creators::Observation {
                scope: o.scope.clone(),
                identity: creators::Identity {
                    guid: provider.interface.guid,
                    luid: provider.interface.luid,
                    index: provider.interface.index,
                    name: provider.interface.name.clone(),
                    description: provider.interface.description.clone(),
                    if_type: provider.interface.if_type,
                    tunnel_type: provider.interface.tunnel_type,
                },
                provider,
            })
            .collect();
        Ok(creators::UniverseObservation {
            context: context.clone(),
            originals: observations,
            complete,
        })
    }
}

// SAFETY: fresh full native PnP/MIB absence reads bracketed by independent actual
// runtime/original source/SAME serialized lease. No registry recursion or effect.
unsafe impl creators::NativeAbsence for OriginalUniverse {
    fn inspect_absence(
        &mut self,
        scope: &creators::Scope,
    ) -> creators::Result<creators::AbsenceFacts> {
        self.verify(&scope.context)?;
        if scope.generation == 0 || !scope.context.bindings.contains(&scope.binding) {
            return Err(creators::Error::Conflict);
        }
        member_carrier_provider::native::inspect_absent(scope.binding.guid, &scope.binding.name)
            .map_err(original_error)?;
        self.verify(&scope.context)?;
        Ok(creators::AbsenceFacts {
            scope: scope.clone(),
            matches: vec![],
        })
    }
}
