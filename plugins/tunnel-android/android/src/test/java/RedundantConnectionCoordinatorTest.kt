package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RedundantConnectionCoordinatorTest {
    @Test
    fun v2RecoveryEnvelopeNeverEntersLegacyVpnRecovery() {
        val envelope = AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = transaction(),
        )

        assertFalse(shouldEnterLegacyVpnRecovery(RecoveryStoreResult.Success(envelope)))
        assertFalse(shouldEnterLegacyVpnRecovery(RecoveryStoreResult.Failure("recovery_record_corrupt")))
    }

    @Test
    fun deferredVpnOwnerRecoversV2BeforeLegacyAndFailsClosedWhenUnavailable() {
        var legacyCalls = 0
        val owner = FakeVpnOwner(recoverResult = true)

        assertTrue(routeVpnProcessRecovery(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(1, owner.resumeCalls)
        assertEquals(0, owner.recoverCalls)
        assertEquals(0, legacyCalls)
        assertFalse(routeVpnProcessRecovery(
            RecoveryStoreResult.Success(v2Envelope()), null, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
        assertTrue(routeVpnProcessRevoke(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
    }

    @Test
    fun stickyRestartUsesV2OwnerResumeBeforeLegacyAndStaysRestartableWhenUnavailable() {
        var legacyCalls = 0
        val owner = FakeVpnOwner(recoverResult = true)

        assertTrue(routeVpnStickyRestart(
            RecoveryStoreResult.Success(v2Envelope()), owner, { legacyCalls += 1 },
        ))
        assertEquals(1, owner.resumeCalls)
        assertEquals(0, legacyCalls)
        assertFalse(routeVpnStickyRestart(
            RecoveryStoreResult.Success(v2Envelope()), null, { legacyCalls += 1 },
        ))
        assertEquals(0, legacyCalls)
    }

    @Test
    fun processDeathRecoveryStartsTheLocallyActiveMemberBeforeCanonicalActive() {
        val store = store(transaction(localActiveLeaseId = "lease-a"))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store, FakePanel(), native)

        coordinator.recover()

        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(listOf("lease-a"), native.activated)
    }

    @Test
    fun ownerReportsRunningOnlyAfterNativeRecoveryHasStarted() {
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), FakeNative())

        assertFalse(coordinator.isRunning())
        assertTrue(coordinator.recover())
        assertTrue(coordinator.isRunning())
    }

    @Test
    fun reserveStatusMovesCalmlyFromWarmingToReadyAndFailover() {
        val states = mutableListOf<RedundantReserveState?>()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            FakeNative(),
            nowMs = { 20_000L },
            onReserveStateChanged = states::add,
        )

        assertTrue(coordinator.recover())
        assertEquals(RedundantReserveState.WARMING, coordinator.reserveState())
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                health = BackendHealth.READY,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = 0L,
            ),
        )))
        assertEquals(RedundantReserveState.READY, coordinator.reserveState())
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertEquals(RedundantReserveState.FAILOVER, coordinator.reserveState())
        assertEquals(
            listOf(
                RedundantReserveState.WARMING,
                RedundantReserveState.READY,
                RedundantReserveState.FAILOVER,
            ),
            states,
        )
        assertEquals(
            "Подключено через резервный сервер",
            redundantNotificationContent(coordinator.reserveState()),
        )
    }

    @Test
    fun recoveryRequiresAndActivatesTheLocalActiveConfigurationWhileStandbyIsBestEffort() {
        val native = FakeNative(startFailures = setOf("lease-b"))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertTrue(coordinator.recover())
        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(listOf("lease-a"), native.activated)

        val missingActive = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(configurations = mapOf("lease-b" to "standby".toByteArray())),
            FakeNative(),
        )
        assertFalse(missingActive.recover())
    }

    @Test
    fun aSingleSlotFailureDoesNotInvokeLegacyStalledStop() {
        val native = FakeNative(usable = setOf("lease-b"))
        var legacyStops = 0
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            native,
            onAllSlotsStalled = { legacyStops += 1 },
        )

        coordinator.slotFailed("lease-a", "primary_unhealthy")

        assertEquals(0, legacyStops)
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun failedInactiveStandbySchedulesReplacementWithoutReactivatingPrimary() {
        var nowMs = 4_000_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            nowMs = { nowMs },
        )

        assertTrue(coordinator.slotFailed("lease-b", "standby_unhealthy"))
        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
        assertTrue(native.activated.isEmpty())
        assertEquals(0, panel.roleCalls)

        nowMs += 60_000
        assertTrue(coordinator.tick())
        assertEquals(listOf("lease-b"), panel.acquireReplaceLeaseIds)
        assertEquals("lease-a", coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun revokeClearsDesiredActiveBeforeQueuingOneSessionStop() {
        val store = store(transaction())
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(store, panel, FakeNative()) {
            error("both slots are not stalled")
        }

        coordinator.revoke()
        coordinator.revoke()

        assertEquals(null, (store.read() as RecoveryStoreResult.Success).value.redundantTransaction)
        assertEquals(1, panel.stopCalls)
    }

    @Test
    fun revokeFencePersistsStopWithoutTouchingNativeOrPanel() {
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            operationId = { "stop-1" },
        )

        assertTrue(coordinator.fenceRevoke())

        val fenced = requireNotNull(coordinator.status())
        assertFalse(fenced.desiredActive)
        assertEquals("stop-1", fenced.stopOperationId)
        assertEquals(RedundantStopState.PENDING, fenced.retry.stopState)
        assertEquals(0, native.stopCalls)
        assertEquals(0, panel.stopCalls)
    }

    @Test
    fun pendingStopReplaysSameOperationAfterFailureAndClearsOnlyAfterBothAcknowledgements() {
        val store = store(transaction())
        val panel = FakePanel(stopResults = ArrayDeque(listOf(false, true)))
        val native = FakeNative(stopResults = ArrayDeque(listOf(true, true)))
        val first = RedundantConnectionCoordinator(store, panel, native, operationId = { "stop-1" })

        assertFalse(first.revoke())
        val pending = requireNotNull(first.status())
        assertFalse(pending.desiredActive)
        assertEquals("stop-1", pending.stopOperationId)
        assertEquals(RedundantStopState.PENDING, pending.retry.stopState)

        val replayed = RedundantConnectionCoordinator(store, panel, native)
        assertTrue(replayed.resume())
        assertEquals(2, panel.stopCalls)
        assertEquals(2, native.stopCalls)
        assertEquals(null, replayed.status())
        assertTrue(replayed.start(transaction(), mapOf("lease-a" to "active".toByteArray())))
    }

    @Test
    fun roleRebaseAdoptsCanonicalGenerationsWithoutRollingBackLocalDataplaneActive() {
        val panel = FakePanel(role = RedundantRoleResponse(
            action = "rebase",
            localActiveLeaseId = "lease-a",
            session = session(activeLeaseId = "lease-b", roleGeneration = 7, membershipGeneration = 3),
        ))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative()) {}

        coordinator.reportLocalRole("primary_unhealthy")

        val transaction = requireNotNull(coordinator.status())
        assertEquals("lease-a", transaction.localActiveLeaseId)
        assertEquals(7, transaction.roleGeneration)
        assertEquals(3, transaction.membershipGeneration)
        assertEquals(2, panel.roleCalls)
        assertFalse(transaction.retry.roleObservationPending)
    }

    @Test
    fun failedOldPrimaryIsReplacedAfterSixtySecondsWithoutFailback() {
        var nowMs = 1_000_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            nowMs = { nowMs },
        )

        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-b"), native.activated)

        nowMs += 59_999
        assertTrue(coordinator.tick())
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)

        nowMs += 1
        assertTrue(coordinator.tick())
        assertEquals(1, panel.acquireOperationIds.size)
        assertEquals(listOf("lease-a"), panel.acquireReplaceLeaseIds)
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-b"), native.activated)
        assertTrue(native.events.indexOf("stop:lease-a") < native.events.indexOf("start:candidate"))
    }

    @Test
    fun periodicTickConsumesNativeHealthAndSwitchesWithoutLegacyStall() {
        val native = FakeNative(healthSnapshots = ArrayDeque(listOf(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        ))))
        var legacyStops = 0
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            FakePanel(),
            native,
            onAllSlotsStalled = { legacyStops += 1 },
        )

        assertTrue(coordinator.tick())

        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
        assertEquals(listOf("lease-b"), native.activated)
        assertEquals(0, legacyStops)
    }

    @Test
    fun validatedNetworkHandoffRebindsBothMembersBeforeStabilization() {
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), FakePanel(), native)

        assertTrue(coordinator.onUnderlyingNetworkChanged(validated = true))

        assertEquals(listOf("lease-a", "lease-b"), native.rebound)
    }

    @Test
    fun replacementDeadlineSurvivesCoordinatorRecreation() {
        var nowMs = 2_000_000L
        val store = store(transaction())
        val panel = FakePanel()
        val first = RedundantConnectionCoordinator(store, panel, FakeNative(), nowMs = { nowMs })

        assertTrue(first.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        val pending = requireNotNull(first.status()).retry
        assertTrue(pending.acquirePending)
        assertEquals("lease-a", pending.acquireReplaceLeaseId)

        nowMs += 59_000
        assertTrue(RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            nowMs = { nowMs },
        ).tick())
        assertTrue(panel.acquireOperationIds.isEmpty())

        nowMs += 1_000
        assertTrue(RedundantConnectionCoordinator(
            store,
            panel,
            FakeNative(),
            nowMs = { nowMs },
        ).tick())
        assertEquals(listOf("lease-a"), panel.acquireReplaceLeaseIds)
    }

    @Test
    fun recoveredFormerPrimaryCancelsReplacementBeforeDeadline() {
        var nowMs = 2_500_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            native,
            nowMs = { nowMs },
        )

        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertTrue(requireNotNull(coordinator.status()).retry.acquirePending)

        nowMs += 15_000L
        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
            healthSlot(index = 1, active = true, health = BackendHealth.READY),
        )))
        val recovered = requireNotNull(coordinator.status())
        assertFalse(recovered.retry.acquirePending)
        assertEquals(null, recovered.retry.acquireOperationId)
        assertEquals(null, recovered.retry.acquireReplaceLeaseId)
        assertEquals(null, recovered.retry.nextRetryAtUnix)

        nowMs += 60_000L
        assertTrue(coordinator.tick())
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals("lease-b", coordinator.status()?.localActiveLeaseId)
    }

    @Test
    fun disablingStandbyCancelsScheduledReplacementForTheSession() {
        var nowMs = 3_000_000L
        val panel = FakePanel()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction()),
            panel,
            FakeNative(),
            nowMs = { nowMs },
        )

        assertTrue(coordinator.onHealthObservations(listOf(
            healthSlot(index = 0, active = true, hardFailure = true),
            healthSlot(index = 1, health = BackendHealth.READY),
        )))
        assertTrue(coordinator.releaseStandby())
        val released = requireNotNull(coordinator.status())
        assertFalse(released.standbyDesired)
        assertFalse(released.retry.acquirePending)
        assertEquals(null, released.retry.nextRetryAtUnix)

        nowMs += 60_000
        assertTrue(coordinator.tick())
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals(listOf("lease-a"), panel.releasedLeaseIds)
    }

    @Test
    fun disablingADegradedSingleMemberSessionNeedsNoSyntheticMemberRelease() {
        val panel = FakePanel()
        val single = transaction().copy(slotBLeaseId = null)
        val coordinator = RedundantConnectionCoordinator(store(single), panel, FakeNative())

        assertTrue(coordinator.releaseStandby())
        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertTrue(panel.releasedLeaseIds.isEmpty())
        assertEquals(null, coordinator.reserveState())
    }

    @Test
    fun failedStandbyReleaseIsRetriedByTickWithoutReenablingStandby() {
        val panel = FakePanel(releaseFailures = ArrayDeque(listOf(true, false)))
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative())

        assertFalse(coordinator.releaseStandby())
        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertTrue(coordinator.tick())

        val released = requireNotNull(coordinator.status())
        assertFalse(released.standbyDesired)
        assertEquals(null, released.slotBLeaseId)
        assertEquals(listOf("lease-b", "lease-b"), panel.releaseAttempts)
        assertTrue(panel.acquireOperationIds.isEmpty())
    }

    @Test
    fun standbyReleaseConflictRebasesGenerationsBeforeRetryingExactInactiveMember() {
        val panel = FakePanel(
            recoveredSession = session(
                activeLeaseId = "lease-a",
                roleGeneration = 7,
                membershipGeneration = 4,
            ),
            releaseFailureCodes = ArrayDeque(listOf("session_membership_conflict")),
        )
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, FakeNative())

        assertFalse(coordinator.releaseStandby())
        val rebased = requireNotNull(coordinator.status())
        assertFalse(rebased.standbyDesired)
        assertEquals(7L, rebased.roleGeneration)
        assertEquals(4L, rebased.membershipGeneration)

        assertTrue(coordinator.tick())
        assertEquals(listOf("lease-b", "lease-b"), panel.releaseAttempts)
        assertEquals(null, coordinator.status()?.slotBLeaseId)
    }

    @Test
    fun recoveryWithDisabledStandbyStartsOnlyActiveAndDrainsCanonicalInactive() {
        val disabled = transaction().copy(standbyDesired = false)
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(disabled), panel, native)

        assertTrue(coordinator.recover())

        assertEquals(listOf("lease-a"), native.started)
        assertEquals(listOf("lease-a"), native.activated)
        assertEquals(listOf("lease-b"), panel.releaseAttempts)
        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertEquals(null, coordinator.status()?.slotBLeaseId)
    }

    @Test
    fun acquireResponseDisablingStandbyCancelsWorkAndZeroesUnusedConfiguration() {
        val panel = FakePanel(acquiredSession = session(
            activeLeaseId = "lease-a",
            roleGeneration = 2,
            membershipGeneration = 2,
            standbyDesired = false,
        ))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, native)

        assertFalse(coordinator.acquireAndCommitStandby("acquire-disabled"))

        assertFalse(requireNotNull(coordinator.status()).standbyDesired)
        assertFalse(requireNotNull(coordinator.status()).retry.acquirePending)
        assertTrue(panel.candidateConfigurations.single().all { it == 0.toByte() })
        assertFalse(native.started.contains("candidate"))
    }

    @Test
    fun roleObservationIsDurableBeforeActivationAndReplayedAfterProcessDeath() {
        val store = store(transaction())
        val panel = FakePanel(roleFailures = ArrayDeque(listOf(true, false)))
        val native = FakeNative(usable = setOf("lease-b"))
        val first = RedundantConnectionCoordinator(store, panel, native)

        assertTrue(first.slotFailed("lease-a", "primary_unhealthy"))
        val pending = requireNotNull(first.status())
        assertTrue(pending.retry.roleObservationPending)
        assertEquals("lease-b", pending.retry.pendingRoleLeaseId)
        assertEquals("primary_unhealthy", pending.retry.pendingRoleReason)

        assertTrue(RedundantConnectionCoordinator(store, panel, native).reportLocalRole("ignored"))
        assertFalse(requireNotNull(first.status()).retry.roleObservationPending)
    }

    @Test
    fun recoveryDrainsPendingRoleObservationAfterProcessRecreation() {
        val pending = transaction(localActiveLeaseId = "lease-b").copy(
            retry = AndroidRedundantRetryState(
                roleObservationPending = true,
                pendingRoleLeaseId = "lease-b",
                pendingRoleReason = "primary_unhealthy",
            ),
        )
        val store = store(pending)
        val panel = FakePanel(role = RedundantRoleResponse(
            action = "rebase",
            localActiveLeaseId = "lease-b",
            session = session(activeLeaseId = "lease-a", roleGeneration = 7, membershipGeneration = 3),
        ))

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).recover())
        val recovered = requireNotNull(RedundantConnectionCoordinator(store, panel, FakeNative()).status())
        assertEquals("lease-b", recovered.localActiveLeaseId)
        assertEquals(7, recovered.roleGeneration)
        assertEquals(3, recovered.membershipGeneration)
        assertFalse(recovered.retry.roleObservationPending)
        assertEquals(2, panel.roleCalls)
    }

    @Test
    fun acquireIdentityIsDurableBeforeRequestAndReplayedWithTheSameOperation() {
        val store = store(transaction())
        val panel = FakePanel(acquireFailures = ArrayDeque(listOf(true, false)))
        val coordinator = RedundantConnectionCoordinator(store, panel, FakeNative())

        assertFalse(coordinator.acquireAndCommitStandby("acquire-1"))
        val pending = requireNotNull(coordinator.status())
        assertEquals("acquire-1", pending.retry.acquireOperationId)
        assertTrue(pending.retry.acquirePending)

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).acquireAndCommitStandby("different"))
        assertEquals(listOf("acquire-1", "acquire-1"), panel.acquireOperationIds)
    }

    @Test
    fun recoveryDrainsPendingAcquireWithItsOriginalOperationAndInactiveReplaceLease() {
        val store = store(transaction())
        val panel = FakePanel(acquireFailures = ArrayDeque(listOf(true, false)))
        val first = RedundantConnectionCoordinator(store, panel, FakeNative())

        assertFalse(first.acquireAndCommitStandby("acquire-1", replaceLeaseId = "lease-b"))
        assertEquals("lease-b", requireNotNull(first.status()).retry.acquireReplaceLeaseId)

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).recover())
        assertEquals(listOf("acquire-1", "acquire-1"), panel.acquireOperationIds)
        assertEquals(listOf("lease-b", "lease-b"), panel.acquireReplaceLeaseIds)
    }

    @Test
    fun degradedSessionAcquiresIntoEmptySlotAndReplaysNullReplacement() {
        val store = store(transaction().copy(slotBLeaseId = null))
        val panel = FakePanel(acquireFailures = ArrayDeque(listOf(true, false)))
        val first = RedundantConnectionCoordinator(store, panel, FakeNative())

        assertFalse(first.acquireAndCommitStandby("acquire-empty"))
        val pending = requireNotNull(first.status()).retry
        assertTrue(pending.acquirePending)
        assertEquals("acquire-empty", pending.acquireOperationId)
        assertEquals(null, pending.acquireReplaceLeaseId)

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).acquireAndCommitStandby("different"))
        assertEquals(listOf("acquire-empty", "acquire-empty"), panel.acquireOperationIds)
        assertEquals(listOf(null, null), panel.acquireReplaceLeaseIds)
    }

    @Test
    fun replacementCommitUsesCanonicalActiveAndGenerationsReturnedByAcquire() {
        var nowMs = 1_000_000L
        val acquired = session(
            activeLeaseId = "lease-b",
            roleGeneration = 8,
            membershipGeneration = 4,
        )
        val panel = FakePanel(acquiredSession = acquired)
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction(localActiveLeaseId = "lease-b")),
            panel,
            native,
            nowMs = { nowMs },
        )

        assertTrue(coordinator.acquireAndCommitStandby("replace-a", replaceLeaseId = "lease-a"))
        assertEquals(0, panel.commitCalls)
        native.healthSnapshots += listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs,
            ),
            healthSlot(index = 1, health = BackendHealth.READY),
        )
        nowMs += 15_000L
        assertTrue(coordinator.tick())

        val committed = panel.commitTransactions.single()
        assertEquals("lease-b", committed.localActiveLeaseId)
        assertEquals(8, committed.roleGeneration)
        assertEquals(4, committed.membershipGeneration)
    }

    @Test
    fun unvalidatedNetworkCannotCommitAnOtherwiseReadyCandidate() {
        var nowMs = 1_000_000L
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store(transaction(localActiveLeaseId = "lease-a").copy(slotBLeaseId = null)),
            panel,
            native,
            nowMs = { nowMs },
        )
        assertTrue(coordinator.acquireAndCommitStandby("acquire-1"))
        assertTrue(coordinator.onUnderlyingNetworkChanged(validated = false))
        native.healthSnapshots.addLast(listOf(
            healthSlot(index = 0, health = BackendHealth.READY),
            healthSlot(
                index = 1,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
        ))

        assertTrue(coordinator.tick())

        assertEquals(0, panel.commitCalls)
        assertTrue(requireNotNull(coordinator.status()).retry.acquirePending)
    }

    @Test
    fun processDeathReplaysCandidateTransportAndWaitsForFreshReadiness() {
        var nowMs = 1_000_000L
        val pending = transaction(localActiveLeaseId = "lease-b").copy(
            candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.A,
            retry = AndroidRedundantRetryState(
                acquirePending = true,
                acquireOperationId = "acquire-1",
                acquireReplaceLeaseId = "lease-a",
            ),
        )
        val store = store(pending)
        val panel = FakePanel(acquiredSession = session(
            activeLeaseId = "lease-b",
            roleGeneration = 8,
            membershipGeneration = 4,
        ))
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(
            store,
            panel,
            native,
            nowMs = { nowMs },
        )

        assertTrue(coordinator.recover())
        assertEquals(listOf("acquire-1"), panel.acquireOperationIds)
        assertEquals(listOf("lease-a"), panel.acquireReplaceLeaseIds)
        assertTrue(native.events.indexOf("stop:lease-a") < native.events.indexOf("start:candidate"))
        assertEquals(0, panel.commitCalls)

        native.healthSnapshots.addLast(listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs,
            ),
            healthSlot(index = 1, health = BackendHealth.READY),
        ))
        assertTrue(coordinator.tick())
        assertEquals(0, panel.commitCalls)

        nowMs += 15_000L
        native.healthSnapshots.addLast(listOf(
            healthSlot(
                index = 0,
                handshakeFresh = true,
                consecutiveProbeSuccesses = 3,
                stableSinceMs = nowMs - 15_000L,
            ),
            healthSlot(index = 1, health = BackendHealth.READY),
        ))
        assertTrue(coordinator.tick())
        assertEquals(1, panel.commitCalls)
        assertFalse(requireNotNull(coordinator.status()).retry.acquirePending)
    }

    @Test
    fun disabledStandbyFencesPersistedCandidateReplay() {
        val pending = transaction().copy(
            standbyDesired = false,
            candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.B,
            retry = AndroidRedundantRetryState(
                nextRetryAtUnix = 1,
                acquirePending = true,
                acquireOperationId = "acquire-1",
                acquireReplaceLeaseId = "lease-b",
            ),
        )
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(pending), panel, native)

        assertTrue(coordinator.tick())

        val fenced = requireNotNull(coordinator.status())
        assertFalse(fenced.retry.acquirePending)
        assertEquals(null, fenced.candidateLeaseId)
        assertEquals(null, fenced.candidateSlot)
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertFalse(native.started.contains("candidate"))
    }

    @Test
    fun recoveryFinalizesCandidateAlreadyCommittedRemotelyWithoutAnotherAcquire() {
        val pending = transaction().copy(
            candidateLeaseId = "candidate",
            candidateSlot = RedundantSlot.B,
            retry = AndroidRedundantRetryState(
                acquirePending = true,
                acquireOperationId = "acquire-1",
                acquireReplaceLeaseId = "lease-b",
            ),
        )
        val store = store(pending)
        val panel = FakePanel(
            recoveredSession = session(
                activeLeaseId = "lease-a",
                roleGeneration = 3,
                membershipGeneration = 3,
                slotBLeaseId = "candidate",
            ),
            acquireFailures = ArrayDeque(listOf(true)),
            commitFailures = ArrayDeque(listOf(true)),
        )

        assertTrue(RedundantConnectionCoordinator(store, panel, FakeNative()).recover())
        val recovered = requireNotNull(RedundantConnectionCoordinator(store, panel, FakeNative()).status())
        assertFalse(recovered.retry.acquirePending)
        assertEquals(null, recovered.retry.acquireOperationId)
        assertEquals(null, recovered.retry.acquireReplaceLeaseId)
        assertEquals(null, recovered.candidateLeaseId)
        assertEquals(null, recovered.candidateSlot)
        assertTrue(panel.acquireOperationIds.isEmpty())
        assertEquals(0, panel.commitCalls)
    }

    @Test
    fun duplicateStopAndRecoveryCallbacksAreIdempotent() {
        val panel = FakePanel()
        val native = FakeNative()
        val coordinator = RedundantConnectionCoordinator(store(transaction()), panel, native) {}

        coordinator.recover()
        coordinator.recover()
        coordinator.revoke()
        coordinator.revoke()

        assertEquals(listOf("lease-a", "lease-b"), native.started)
        assertEquals(1, panel.stopCalls)
    }

    private fun store(transaction: AndroidRedundantTransaction): AndroidRecoveryStore {
        val backend = CoordinatorRecordBackend()
        backend.write(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope(
            formatVersion = ANDROID_RECOVERY_FORMAT,
            intent = AndroidConnectionIntent.empty(1),
            leaseTransaction = null,
            redundantTransaction = transaction,
        )))
        return AndroidRecoveryStore(backend, CoordinatorBootIdentity())
    }

    private fun v2Envelope() = AndroidRecoveryEnvelope(
        formatVersion = ANDROID_RECOVERY_FORMAT,
        intent = AndroidConnectionIntent.empty(1),
        leaseTransaction = null,
        redundantTransaction = transaction(),
    )

    private fun transaction(localActiveLeaseId: String? = "lease-a") = AndroidRedundantTransaction(
        desiredActive = true,
        template = AndroidIntentTemplate(
            deviceId = "11111111-1111-4111-8111-111111111111",
            accountScope = "account",
            layer = "stray",
            ticConnectionMode = "dynamic",
            routeMode = "standalone",
            egressMode = "ipv4",
            allowAlternate = true,
        ),
        sessionId = "22222222-2222-4222-8222-222222222222",
        slotALeaseId = "lease-a",
        slotBLeaseId = "lease-b",
        localActiveLeaseId = localActiveLeaseId,
        standbyDesired = true,
        roleGeneration = 1,
        membershipGeneration = 1,
        startOperationId = "start-operation",
        startRequestFingerprint = "fingerprint",
    )

    private fun session(
        activeLeaseId: String,
        roleGeneration: Long,
        membershipGeneration: Long,
        slotBLeaseId: String = "lease-b",
        standbyDesired: Boolean = true,
    ) = BackgroundRedundantSession(
        sessionId = "22222222-2222-4222-8222-222222222222",
        state = "connected",
        activeLeaseId = activeLeaseId,
        slotALeaseId = "lease-a",
        slotBLeaseId = slotBLeaseId,
        standbyDesired = standbyDesired,
        roleGeneration = roleGeneration,
        membershipGeneration = membershipGeneration,
        reason = null,
    )

    private fun healthSlot(
        index: Int,
        active: Boolean = false,
        health: BackendHealth = BackendHealth.WARMING,
        hardFailure: Boolean = false,
        handshakeFresh: Boolean = false,
        consecutiveProbeSuccesses: Int = 0,
        stableSinceMs: Long? = null,
    ) = SlotObservation(
        index = index,
        active = active,
        health = health,
        hardFailure = hardFailure,
        handshakeFresh = handshakeFresh,
        consecutiveProbeSuccesses = consecutiveProbeSuccesses,
        stableSinceMs = stableSinceMs,
    )
}

private class CoordinatorRecordBackend : EncryptedRecordBackend {
    var record: ByteArray? = null
    override fun read(): ByteArray? = record?.copyOf()
    override fun write(plaintext: ByteArray): Boolean {
        record = plaintext.copyOf()
        return true
    }
}

private class CoordinatorBootIdentity : BootIdentityProvider {
    override fun bootCount(): Long = 1
}

private class FakeNative(
    private val usable: Set<String> = setOf("lease-a", "lease-b"),
    private val startFailures: Set<String> = emptySet(),
    private val stopResults: ArrayDeque<Boolean> = ArrayDeque(),
    val healthSnapshots: ArrayDeque<List<SlotObservation>> = ArrayDeque(),
) : RedundantConnectionNative {
    val started = mutableListOf<String>()
    val activated = mutableListOf<String>()
    val rebound = mutableListOf<String>()
    val events = mutableListOf<String>()
    var stopCalls = 0
    override fun start(
        leaseId: String,
        slot: RedundantSlot,
        configuration: ByteArray,
        healthProbe: BackgroundRedundantHealthProbe?,
    ): Boolean {
        started += leaseId
        events += "start:$leaseId"
        return leaseId !in startFailures
    }
    override fun activate(leaseId: String): Boolean = (leaseId in usable).also {
        if (it) activated += leaseId
    }
    override fun stopSlot(leaseId: String): Boolean = (leaseId in usable).also {
        if (it) events += "stop:$leaseId"
    }
    override fun stop(): Boolean {
        stopCalls += 1
        return stopResults.removeFirstOrNull() ?: true
    }
    override fun isUsable(leaseId: String): Boolean = leaseId in usable
    override fun rebind(leaseId: String): Boolean = (leaseId in usable).also {
        if (it) rebound += leaseId
    }
    override fun healthObservations(): List<SlotObservation> =
        healthSnapshots.removeFirstOrNull() ?: emptyList()
}

private class FakePanel(
    private val role: RedundantRoleResponse? = null,
    private val configurations: Map<String, ByteArray>? = null,
    private val recoveredSession: BackgroundRedundantSession? = null,
    private val acquiredSession: BackgroundRedundantSession? = null,
    private val stopResults: ArrayDeque<Boolean> = ArrayDeque(),
    private val roleFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val acquireFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val commitFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val releaseFailures: ArrayDeque<Boolean> = ArrayDeque(),
    private val releaseFailureCodes: ArrayDeque<String> = ArrayDeque(),
) : RedundantConnectionPanel {
    var stopCalls = 0
    var roleCalls = 0
    var commitCalls = 0
    val acquireOperationIds = mutableListOf<String>()
    val acquireReplaceLeaseIds = mutableListOf<String?>()
    val commitTransactions = mutableListOf<AndroidRedundantTransaction>()
    val candidateConfigurations = mutableListOf<ByteArray>()
    val releasedLeaseIds = mutableListOf<String>()
    val releaseAttempts = mutableListOf<String>()
    override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse =
        RedundantRecoveryResponse(
            session = recoveredSession ?: BackgroundRedundantSession(
                sessionId = transaction.sessionId,
                state = "connected",
                activeLeaseId = "lease-b",
                slotALeaseId = "lease-a",
                slotBLeaseId = "lease-b",
                standbyDesired = true,
                roleGeneration = 2,
                membershipGeneration = 2,
                reason = null,
            ),
            configurations = configurations ?: mapOf(
                "lease-a" to "PrivateKey = only-in-memory-a".toByteArray(),
                "lease-b" to "PrivateKey = only-in-memory-b".toByteArray(),
            ),
        )
    override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse {
        roleCalls += 1
        if (roleFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        return if (role?.action == "rebase" && roleCalls > 1) {
            RedundantRoleResponse("accepted", transaction.localActiveLeaseId!!, role.session)
        } else {
            role ?: RedundantRoleResponse("accepted", transaction.localActiveLeaseId!!, session())
        }
    }
    override fun releaseStandby(
        transaction: AndroidRedundantTransaction,
        inactiveLeaseId: String,
    ): BackgroundRedundantSession {
        releaseAttempts += inactiveLeaseId
        releaseFailureCodes.removeFirstOrNull()?.let { throw BackgroundConnectionException(it) }
        if (releaseFailures.removeFirstOrNull() == true) {
            throw BackgroundConnectionException("offline")
        }
        return BackgroundRedundantSession(
        sessionId = transaction.sessionId,
        state = "connected",
        activeLeaseId = transaction.localActiveLeaseId,
        slotALeaseId = transaction.slotALeaseId.takeIf { it != inactiveLeaseId },
        slotBLeaseId = transaction.slotBLeaseId.takeIf { it != inactiveLeaseId },
        standbyDesired = false,
        roleGeneration = transaction.roleGeneration,
        membershipGeneration = transaction.membershipGeneration + 1,
        reason = null,
        ).also { releasedLeaseIds += inactiveLeaseId }
    }
    override fun acquireStandby(
        transaction: AndroidRedundantTransaction,
        operationId: String,
        replaceLeaseId: String?,
    ): BackgroundRedundantCandidate {
        acquireOperationIds += operationId
        acquireReplaceLeaseIds += replaceLeaseId
        if (acquireFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        val configuration = "candidate-config".toByteArray().also(candidateConfigurations::add)
        return BackgroundRedundantCandidate(
            acquiredSession ?: session(activeLeaseId = transaction.localActiveLeaseId!!),
            "candidate",
            if (replaceLeaseId == transaction.slotALeaseId) RedundantSlot.A else RedundantSlot.B,
            QuickConnectionArgs(),
            configuration,
            BackgroundRedundantHealthProbe("dns_a", "8.8.8.8", "nelomai.ru", 4_000),
        )
    }
    override fun commitCandidate(
        transaction: AndroidRedundantTransaction,
        candidateLeaseId: String,
    ): BackgroundRedundantSession {
        commitCalls += 1
        commitTransactions += transaction
        if (commitFailures.removeFirstOrNull() == true) throw BackgroundConnectionException("offline")
        return session(
            activeLeaseId = transaction.localActiveLeaseId!!,
            roleGeneration = transaction.roleGeneration,
            membershipGeneration = transaction.membershipGeneration + 1,
            slotALeaseId = if (transaction.retry.acquireReplaceLeaseId == transaction.slotALeaseId) {
                candidateLeaseId
            } else {
                transaction.slotALeaseId
            },
            slotBLeaseId = if (transaction.retry.acquireReplaceLeaseId == transaction.slotBLeaseId ||
                transaction.slotBLeaseId == null
            ) {
                candidateLeaseId
            } else {
                transaction.slotBLeaseId
            },
        )
    }
    override fun stop(transaction: AndroidRedundantTransaction): Boolean {
        stopCalls += 1
        return stopResults.removeFirstOrNull() ?: true
    }
    private fun session(
        activeLeaseId: String = "lease-a",
        roleGeneration: Long = 2,
        membershipGeneration: Long = 2,
        slotALeaseId: String? = "lease-a",
        slotBLeaseId: String? = "lease-b",
    ) = BackgroundRedundantSession(
        sessionId = "22222222-2222-4222-8222-222222222222",
        state = "connected",
        activeLeaseId = activeLeaseId,
        slotALeaseId = slotALeaseId,
        slotBLeaseId = slotBLeaseId,
        standbyDesired = true,
        roleGeneration = roleGeneration,
        membershipGeneration = membershipGeneration,
        reason = null,
    )
}

private class FakeVpnOwner(private val recoverResult: Boolean) : RedundantVpnProcessOwner {
    var recoverCalls = 0
    var resumeCalls = 0
    override fun recover(): Boolean {
        recoverCalls += 1
        return recoverResult
    }
    override fun resume(): Boolean {
        resumeCalls += 1
        return recoverResult
    }
    override fun revoke(): Boolean = true
}
