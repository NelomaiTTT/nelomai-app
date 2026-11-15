package ru.nelomai.tunnel

import android.content.Intent
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.NetworkInfo
import android.os.Bundle
import android.os.Looper
import android.os.ResultReceiver
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork
import org.robolectric.shadows.ShadowNetworkInfo
import org.robolectric.util.ReflectionHelpers
import ru.nelomai.runtime.v1.RuntimeVpnHostV1
import java.time.Duration
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class OwnedRedundantPolicyServiceTest {
    private enum class RouteChangeRace {
        NONE, STOP, LOOKUP_BEFORE_WORK, LOOKUP_DURING_ESTABLISH, WIFI_RETURN,
        LOOKUP_DURING_REBIND, UNREADABLE_LOGOUT, UNREADABLE_RECOVERY, UNREADABLE_ROUTE_PREFLIGHT,
        STANDBY_IN_FLIGHT, UNREADABLE_AFTER_NATIVE_REPLACEMENT, STARTUP_PENDING,
        RESAMPLED_NETWORK_CALLBACK, OFFLINE_AFTER_REBIND_FAILURE,
        OFFLINE_PENDING_SWITCH, RESAMPLED_TUN_REPLACEMENT, RESAMPLED_TUN_REPLACEMENT_AFTER_LOSS,
        RESAMPLED_TUN_REPLACEMENT_AFTER_PLUGIN_LOSS, RESAMPLED_TUN_REPLACEMENT_AFTER_MANUAL_REBIND,
    }

    private enum class InterruptedStartupSwitch { ACTIVATION_FAILED, COMMIT_FAILED }
    private enum class PluginUpdateBlock { RECOVERY_READ, STOP_LOOKUP }
    private enum class StartFailureReply { INITIAL_FENCE, RETRIED_FENCE, CANCELLED_DURING_RETRY }

    @Test
    fun queuedStartupTickCannotUseOldNetworkProofAfterPhysicalCallback() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false)

    @Test
    fun queuedStartupTickCannotUseOldNetworkProofAfterPluginCallback() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = true)

    @Test
    @Config(shadows = [StartupVpnNetworkShadow::class])
    fun pluginPublishesPendingUpdateBeforeChangingVpnNetworks() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = true, checkPluginOrdering = true)

    @Test
    @Config(shadows = [StartupVpnNetworkShadow::class])
    fun physicalNetworkUpdateSurvivesAndroidReportingFailure() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, failAndroidNetworkUpdate = true)

    @Test
    @Config(shadows = [StartupVpnNetworkShadow::class])
    fun pluginNetworkUpdateSurvivesAndroidReportingFailure() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = true, failAndroidNetworkUpdate = true)

    @Test
    fun networkCallbackDuringReadinessCommitInvalidatesOldProof() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, callbackDuringCommit = true)

    @Test
    fun unreadableRecoveryDoesNotExtendStartupWhileNetworkUpdateIsPending() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, unreadableAtDeadline = true)

    @Test
    fun unreadableRecoveryDoesNotLoseFailedClientStart() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, unreadableAtDeadline = true,
            clientStartFailure = true)

    @Test
    fun failedClientStartKeepsDurableStopWhenPanelIsUnavailable() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, clientStartFailure = true,
            panelStopUnavailable = true)

    @Test
    fun clientStartFailureIsReportedAfterPersistingStop() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, clientStartFailure = true,
            panelStopUnavailable = true, startFailureReply = StartFailureReply.INITIAL_FENCE)

    @Test
    fun failedStartReplySurvivesTemporaryFailureOfBothStopRecords() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, clientStartFailure = true,
            unreadableAtDeadline = true, panelStopUnavailable = true, startFailureReply = StartFailureReply.RETRIED_FENCE)

    @Test
    fun explicitCancellationWinsWhileFailedStartWaitsForStopRecords() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, clientStartFailure = true,
            unreadableAtDeadline = true, panelStopUnavailable = true, startFailureReply = StartFailureReply.CANCELLED_DURING_RETRY)

    @Test
    fun deferredPluginNetworkReturnWorksBeforeTunOptionsAreInstalled() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = true,
            pluginUpdateBlock = PluginUpdateBlock.RECOVERY_READ, pluginUpdateWithoutOptions = true)

    @Test
    fun recoveredTimeoutIsRecordedAfterTemporaryStopLookup() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, unreadableAtDeadline = true,
            stopLookupDuringPublication = true)

    @Test
    fun startupHealthTimerResumesAfterTemporaryStopLookup() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = false, temporaryStopLookup = true)

    @Test
    fun pluginNetworkLossIsPreservedAcrossUnreadableRecovery() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = true, pluginUpdateBlock = PluginUpdateBlock.RECOVERY_READ)

    @Test
    fun pluginNetworkLossIsPreservedAcrossTemporaryStopLookup() =
        queuedStartupTickWaitsForNetworkUpdate(pluginCallback = true, pluginUpdateBlock = PluginUpdateBlock.STOP_LOOKUP)

    private fun queuedStartupTickWaitsForNetworkUpdate(
        pluginCallback: Boolean,
        callbackDuringCommit: Boolean = false,
        unreadableAtDeadline: Boolean = false,
        clientStartFailure: Boolean = false,
        panelStopUnavailable: Boolean = false,
        stopLookupDuringPublication: Boolean = false,
        temporaryStopLookup: Boolean = false,
        pluginUpdateBlock: PluginUpdateBlock? = null,
        checkPluginOrdering: Boolean = false,
        startFailureReply: StartFailureReply? = null,
        pluginUpdateWithoutOptions: Boolean = false,
        failAndroidNetworkUpdate: Boolean = false,
    ) {
        val mustKeepStop = unreadableAtDeadline || panelStopUnavailable
        val expiryCases = when {
            mustKeepStop -> listOf(true)
            pluginUpdateWithoutOptions || failAndroidNetworkUpdate -> listOf(false)
            else -> listOf(false, true)
        }
        for (expiresWhileQueued in expiryCases) {
            val host = Robolectric.buildService(VpnService::class.java).create()
            val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
                override val service = host.get()
                override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) =
                    service.Builder().also(beforeEstablish)
            })
            var elapsedMs = 100_000L
            val probe = BackgroundRedundantHealthProbe("dns_a", "192.0.2.1", "example.test", 4000)
            val retryStopWrite = startFailureReply != null && startFailureReply != StartFailureReply.INITIAL_FENCE
            var stopWriteAvailable = !retryStopWrite
            var beforePanelStop: () -> Unit = {}
            var failureBeforePanelStopCompleted: String? = null
            val tombstoneBackend = AndroidRedundantCancelTombstoneBackend(host.get().applicationContext)
            val tombstones = if (mustKeepStop) RedundantCancelTombstoneStore(
                object : RedundantCancelTombstoneBackend by tombstoneBackend {
                    override fun compareAndWrite(expected: String?, value: String): Boolean =
                        stopWriteAvailable && tombstoneBackend.compareAndWrite(expected, value)
                },
            ) else null
            val unavailablePanel = if (panelStopUnavailable) object : RedundantConnectionPanel {
                override fun recover(transaction: AndroidRedundantTransaction): RedundantRecoveryResponse =
                    error("unexpected recovery")
                override fun reportRole(transaction: AndroidRedundantTransaction, reason: String): RedundantRoleResponse =
                    error("unexpected role report")
                override fun stop(transaction: AndroidRedundantTransaction): Boolean {
                    beforePanelStop()
                    return false
                }
            } else null
            var stopAtStartFailure: String? = null
            var reportedFailure: String? = null
            fun captureFailure(code: String?) {
                assertNull("A Start must receive only one terminal reply", reportedFailure)
                reportedFailure = code
                stopAtStartFailure = (tombstones?.read() as? RecoveryStoreResult.Success)?.value?.startOperationId
            }
            val startReceiver = if (startFailureReply != null) object : ResultReceiver(null) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    captureFailure(resultData?.getString(EXTRA_ERROR_CODE))
                }
            } else null
            lateinit var f: OwnedRedundantPolicyTest.Fixture
            f = OwnedRedundantPolicyTest.Fixture(panelOverride = unavailablePanel,
                initialHealthProbes = mapOf("lease-a" to probe),
                monotonicMs = { elapsedMs },
                startupNetworkUpdatePending = { service.startupNetworkUpdatePending(f.coordinator) },
                onPrimaryFailed = {
                    when {
                        clientStartFailure -> ReflectionHelpers.callInstanceMethod<Unit>(
                            service, "failRedundantClientStart",
                            ReflectionHelpers.ClassParameter.from(String::class.java, "operation"),
                            ReflectionHelpers.ClassParameter.from(RedundantConnectionCoordinator::class.java, f.coordinator),
                            ReflectionHelpers.ClassParameter.from(ResultReceiver::class.java, startReceiver),
                            ReflectionHelpers.ClassParameter.from(String::class.java, "redundant_start_failed"),
                        )
                        unreadableAtDeadline -> ReflectionHelpers.callInstanceMethod<Unit>(
                            service, "publishRedundantRecoveryReadiness",
                            ReflectionHelpers.ClassParameter.from(String::class.java, "operation"),
                            ReflectionHelpers.ClassParameter.from(RedundantVpnProcessOwner::class.java, f.coordinator),
                            ReflectionHelpers.ClassParameter.from(Boolean::class.javaPrimitiveType, false),
                        )
                    }
                })
            val jobs = mutableListOf<Runnable>()
            try {
                ReflectionHelpers.setField(service, "recoveryStore", f.store)
                if (tombstones != null) ReflectionHelpers.setField(service, "redundantCancelTombstones", tombstones)
                if (panelStopUnavailable) ReflectionHelpers.setField(service, "backgroundLogoutLifecycle",
                    BackgroundLogoutServiceLifecycle(logoutState = { BackgroundLogoutReadState.UNREADABLE },
                        recovery = f.store::read, beginRedundantStop = { error("unexpected logout") },
                        runLogout = {}, scheduleRetry = {}, stopIfIdle = {}))
                ReflectionHelpers.setField(service, "redundantWork", RedundantVpnWorkDispatcher(Executor { jobs += it }))
                val ownerSlot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(service, "redundantVpnOwnerSlot")
                ownerSlot.install(f.coordinator, "operation")
                val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
                val identity = RedundantPhysicalNetworkCallbackIdentity(generation, "operation", f.coordinator)
                val options = EffectiveAndroidTunnelOptions(splitSupported = true, excludeLocalNetworks = false)
                if (!pluginUpdateWithoutOptions) {
                    ownerSlot.updateRouteBaseline(f.coordinator, redundantVpnRouteBaseline(options, emptyList()), options)
                }
                val startGate = ReflectionHelpers.getField<RedundantStartOperationGate>(service, "redundantStartOperation")
                if (startFailureReply != null) {
                    assertTrue(startGate.begin("operation") { captureFailure("tunnel_start_cancelled") })
                }
                if (callbackDuringCommit) {
                    // A role already in the journal must not make a rejected new decision succeed.
                    assertTrue(f.store.updateRedundant("operation") {
                        it.copy(retry = it.retry.copy(roleObservationPending = true,
                            pendingRoleLeaseId = "lease-a", pendingRoleReason = "primary_ready"))
                    } is RecoveryStoreResult.Success)
                }
                val healthTick = ReflectionHelpers.getField<Runnable>(service, "redundantHealthTick")
                val looper = shadowOf(Looper.getMainLooper())
                fun deliver(state: PhysicalNetworkState) {
                    if (pluginCallback) {
                        ReflectionHelpers.callInstanceMethod<Unit>(service, "applyPluginPhysicalNetworks",
                            ReflectionHelpers.ClassParameter.from(List::class.java, state.networks))
                    } else {
                        ReflectionHelpers.callInstanceMethod<Unit>(service, "applyRedundantPhysicalNetworks",
                            ReflectionHelpers.ClassParameter.from(RedundantPhysicalNetworkCallbackIdentity::class.java, identity),
                            ReflectionHelpers.ClassParameter.from(EffectiveAndroidTunnelOptions::class.java, options),
                            ReflectionHelpers.ClassParameter.from(RedundantConnectionCoordinator::class.java, f.coordinator),
                            ReflectionHelpers.ClassParameter.from(PhysicalNetworkState::class.java, state))
                    }
                }
                f.backend.metricsOverride = {
                    val handshake = System.currentTimeMillis() - 1
                    (0..1).joinToString(prefix = "{\"slots\":[", postfix = "]}") { slot ->
                        """{"slot":$slot,"admitted":true,"closed":false,"latest_handshake_at_unix_ms":$handshake,"telemetry":{"tun_write_packets":0,"udp_send_packets":0,"udp_send_errors":0}}"""
                    }
                }
                assertTrue(f.coordinator.tick())
                val token = f.backend.probeDetails.entries.single { it.value.second == 0 }.key
                f.backend.probeStatuses[token] = NativeProbeStatus.SUCCEEDED
                if (temporaryStopLookup) {
                    val barrier = ReflectionHelpers.getField<RedundantStopLookupBarrier>(
                        service, "redundantStopLookupBarrier")
                    val lookup = barrier.begin()
                    healthTick.run()
                    assertTrue(jobs.isEmpty())
                    assertTrue(barrier.complete(lookup))
                    looper.idleFor(Duration.ofMillis(1_000))
                } else {
                    healthTick.run()
                }
                assertEquals(1, jobs.size)

                shadowOf(host.get().getSystemService(ConnectivityManager::class.java)).clearAllNetworks()
                val offline = PhysicalNetworkState(emptyList(), emptyList(), false, "offline")
                if (callbackDuringCommit) {
                    var reads = 0
                    f.record.beforeRead = {
                        // Work eligibility, tick setup, decision, then the locked commit pre-read.
                        if (++reads == 4) {
                            f.record.beforeRead = {}
                            deliver(offline)
                        }
                    }
                } else {
                    if (checkPluginOrdering) StartupVpnNetworkShadow.applications = 0
                    val barrier = ReflectionHelpers.getField<RedundantStopLookupBarrier>(
                        service, "redundantStopLookupBarrier")
                    val lookup = if (pluginUpdateBlock == PluginUpdateBlock.STOP_LOOKUP) barrier.begin() else null
                    deliver(if (pluginUpdateWithoutOptions) restoreWifi(host.get().applicationContext) else offline)
                    if (checkPluginOrdering) assertEquals(0, StartupVpnNetworkShadow.applications)
                    if (lookup != null) assertTrue(barrier.complete(lookup))
                    assertEquals(2, jobs.size)
                }
                if (expiresWhileQueued) elapsedMs += 30_000
                if (unreadableAtDeadline) f.record.beforeRead = { error("recovery unreadable") }
                jobs.removeAt(0).run()
                if (tombstones != null) {
                    if (stopLookupDuringPublication) {
                        val barrier = ReflectionHelpers.getField<RedundantStopLookupBarrier>(
                            service, "redundantStopLookupBarrier")
                        val lookup = barrier.begin()
                        looper.idle()
                        assertNull((tombstones.read() as? RecoveryStoreResult.Success)?.value)
                        assertTrue(barrier.complete(lookup))
                        healthTick.run()
                    }
                    looper.idle()
                    if (retryStopWrite) {
                        assertNull(reportedFailure)
                        assertNull((tombstones.read() as? RecoveryStoreResult.Success)?.value)
                        if (startFailureReply == StartFailureReply.CANCELLED_DURING_RETRY) {
                            assertTrue(startGate.cancel("operation"))
                        }
                        f.record.beforeRead = {}
                        stopWriteAvailable = true
                        beforePanelStop = {
                            looper.idle()
                            failureBeforePanelStopCompleted = reportedFailure
                        }
                        ReflectionHelpers.callInstanceMethod<Unit>(service, "retryPendingRedundantStop")
                        jobs.removeAt(jobs.lastIndex).run()
                        looper.idle()
                    }
                    if (startFailureReply != null) {
                        val expectedError = if (startFailureReply == StartFailureReply.CANCELLED_DURING_RETRY) {
                            "tunnel_start_cancelled"
                        } else "redundant_start_failed"
                        assertEquals(expectedError, reportedFailure)
                        assertEquals("operation", stopAtStartFailure)
                        if (retryStopWrite) {
                            assertEquals("Reply must not wait for panel Stop", expectedError, failureBeforePanelStopCompleted)
                        }
                    }
                    assertEquals("operation",
                        (tombstones.read() as? RecoveryStoreResult.Success)?.value?.startOperationId)
                    assertFalse(f.native.isUsable("lease-a"))
                    f.record.beforeRead = {}
                    assertTrue(ReflectionHelpers.callInstanceMethod<Boolean>(service, "redundantStartBlocked"))
                    continue
                }
                f.record.beforeRead = {}
                assertFalse("The already queued tick must not accept proof from the old network", f.coordinator.isRunning())
                assertEquals(!expiresWhileQueued, f.native.isUsable("lease-a"))
                assertEquals(1, jobs.size)
                if (pluginUpdateBlock == PluginUpdateBlock.RECOVERY_READ) {
                    f.record.beforeRead = { error("recovery unreadable") }
                }
                if (failAndroidNetworkUpdate) StartupVpnNetworkShadow.failNextApplication = true
                jobs.removeAt(0).run()
                if (failAndroidNetworkUpdate) assertFalse(StartupVpnNetworkShadow.failNextApplication)
                f.record.beforeRead = {}
                if (checkPluginOrdering && !expiresWhileQueued) {
                    assertEquals(1, StartupVpnNetworkShadow.applications)
                }
                if (!unreadableAtDeadline) assertFalse(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                looper.idle()
                if (pluginUpdateWithoutOptions) assertEquals(1, jobs.size)
                if (pluginUpdateBlock != null && jobs.isNotEmpty()) {
                    jobs.removeAt(0).run()
                    looper.idle()
                }
                if (!expiresWhileQueued) {
                    if (!pluginUpdateWithoutOptions) {
                        deliver(restoreWifi(host.get().applicationContext))
                        jobs.removeAt(0).run()
                        looper.idle()
                    }
                    assertTrue(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    elapsedMs += 4_000
                    healthTick.run()
                    jobs.removeAt(0).run()
                    assertFalse(f.coordinator.isRunning())
                    val newToken = requireNotNull(f.backend.latestProbeToken)
                    assertNotEquals(token, newToken)
                    f.backend.probeStatuses[newToken] = NativeProbeStatus.SUCCEEDED
                    healthTick.run()
                    jobs.removeAt(0).run()
                    assertTrue("A fresh probe on the new network must complete startup", f.coordinator.isRunning())
                }
            } finally {
                f.native.closeForStop()
                ReflectionHelpers.getField<android.os.Handler>(service, "restoreHandler").removeCallbacksAndMessages(null)
                ReflectionHelpers.getField<ExecutorService>(service, "redundantExecutor").shutdownNow()
                ReflectionHelpers.getField<ExecutorService>(service, "credentialExecutor").shutdownNow()
                host.destroy()
            }
        }
    }

    @Test fun removingLocalExclusionsReplacesTunWithoutReplacingTheSession() =
        refreshAfterLocalRouteChange(RouteChangeRace.NONE)

    @Test fun queuedLocalRouteRefreshCannotReplaceTunAfterStop() =
        refreshAfterLocalRouteChange(RouteChangeRace.STOP)

    @Test fun failedLocalRouteRefreshDefersRecoveryUntilStopLookupFinishes() =
        refreshAfterLocalRouteChange(RouteChangeRace.LOOKUP_DURING_ESTABLISH)

    @Test fun queuedRouteRefreshSurvivesTransientStopLookup() =
        refreshAfterLocalRouteChange(RouteChangeRace.LOOKUP_BEFORE_WORK)

    @Test fun networkReturnDuringReplacementReconcilesAgainstNewBaseline() =
        refreshAfterLocalRouteChange(RouteChangeRace.WIFI_RETURN)

    @Test fun returningNetworkWithEqualRoutesSurvivesLookupDuringRecoveryRead() =
        refreshAfterLocalRouteChange(RouteChangeRace.LOOKUP_DURING_REBIND)

    @Test fun routeUpdateSurvivesOneUnreadableLogoutState() =
        refreshAfterLocalRouteChange(RouteChangeRace.UNREADABLE_LOGOUT)

    @Test fun returningNetworkWithEqualRoutesSurvivesUnreadableRecovery() =
        refreshAfterLocalRouteChange(RouteChangeRace.UNREADABLE_RECOVERY)

    @Test fun routeUpdateSurvivesUnreadableRecoveryBeforeReplacement() {
        refreshAfterLocalRouteChange(RouteChangeRace.UNREADABLE_ROUTE_PREFLIGHT)
        refreshAfterLocalRouteChange(RouteChangeRace.UNREADABLE_ROUTE_PREFLIGHT, recoveryReadToFail = 2)
    }

    @Test fun routeUpdateSurvivesUnreadableRecoveryInsideNativePreparation() {
        // Native entry, first member preparation, and the last check before closing the TUN.
        for (read in listOf(3, 4, 6)) {
            refreshAfterLocalRouteChange(RouteChangeRace.UNREADABLE_ROUTE_PREFLIGHT, recoveryReadToFail = read)
        }
    }

    @Test fun routeUpdateWaitsForStandbyRequestWithoutRestartingVpn() =
        refreshAfterLocalRouteChange(RouteChangeRace.STANDBY_IN_FLIGHT)

    @Test fun closedReplacementTriggersRecoveryEvenIfTheNextReadWouldSucceed() =
        refreshAfterLocalRouteChange(RouteChangeRace.UNREADABLE_AFTER_NATIVE_REPLACEMENT)

    @Test fun routeChangeDuringStartupRebindsOnceAndRefreshesAfterReadiness() =
        refreshAfterLocalRouteChange(RouteChangeRace.STARTUP_PENDING)

    @Test fun transientRebindFailureDuringStartupCanRecoverOnSameNetwork() {
        refreshAfterLocalRouteChange(RouteChangeRace.STARTUP_PENDING, initialRebindFailures = setOf(0))
        refreshAfterLocalRouteChange(RouteChangeRace.STARTUP_PENDING, initialRebindFailures = setOf(1))
        refreshAfterLocalRouteChange(RouteChangeRace.STARTUP_PENDING, initialRebindFailures = setOf(0, 1))
    }

    @Test fun failedRebindDoesNotExtendStartupDeadline() =
        refreshAfterLocalRouteChange(RouteChangeRace.STARTUP_PENDING,
            initialRebindFailures = setOf(0, 1), expireStartup = true)

    @Test fun equalRoutesDoNotLoseTransientSocketRebindFailure() =
        refreshAfterLocalRouteChange(RouteChangeRace.STARTUP_PENDING,
            initialRebindFailures = setOf(0, 1), equalStartupRoutes = true)

    @Test fun resampledNetworkCallbackPreservesSuccessfulRebind() {
        refreshAfterLocalRouteChange(RouteChangeRace.RESAMPLED_NETWORK_CALLBACK)
        refreshAfterLocalRouteChange(RouteChangeRace.RESAMPLED_NETWORK_CALLBACK, lateCallback = true)
    }

    @Test fun offlineAfterFailedRebindWaitsForOriginalStartupDeadline() =
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_AFTER_REBIND_FAILURE)

    @Test fun pendingStartupSwitchWaitsForPhysicalNetwork() {
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_PENDING_SWITCH)
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_PENDING_SWITCH, expireStartup = true)
    }

    @Test fun pendingStartupSwitchNeedsFreshReserveProofAfterFailedRebind() {
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_PENDING_SWITCH, initialRebindFailures = setOf(1))
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_PENDING_SWITCH,
            initialRebindFailures = setOf(1), expireStartup = true)
    }

    @Test fun startupUsesRecoveredPrimaryWhileReserveRebindStillFails() =
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_PENDING_SWITCH,
            initialRebindFailures = setOf(1), primaryRecovers = true)

    @Test fun startupKeepsRecoveredPrimaryAfterReserveProbeAndActivationFailure() =
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_PENDING_SWITCH,
            interruptedSwitch = InterruptedStartupSwitch.ACTIVATION_FAILED)

    @Test fun startupRestoresRecoveredPrimaryWhenUncommittedReserveFails() =
        refreshAfterLocalRouteChange(RouteChangeRace.OFFLINE_PENDING_SWITCH,
            interruptedSwitch = InterruptedStartupSwitch.COMMIT_FAILED)

    @Test fun workerOnlyOfflineSampleMustNotLeaveHealthyNetworkMarkedOffline() =
        verifyWorkerOnlyOfflineSample(failSnapshot = false)

    @Test
    @Config(shadows = [FailingNetworkSnapshotShadow::class])
    fun unreadableWorkerResampleMustNotRestoreStaleOnlineSnapshot() =
        verifyWorkerOnlyOfflineSample(failSnapshot = true)

    @Test
    @Config(shadows = [FailingNetworkSnapshotShadow::class])
    fun confirmedOfflineCallbackPausesProbesEvenWhenResampleFails() =
        verifyWorkerOnlyOfflineSample(failSnapshot = false, failReadOnOfflineCallback = true)

    private fun verifyWorkerOnlyOfflineSample(failSnapshot: Boolean, failReadOnOfflineCallback: Boolean = false) {
        val host = Robolectric.buildService(VpnService::class.java).create()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host.get()
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = service.Builder().also(beforeEstablish)
        })
        val f = OwnedRedundantPolicyTest.Fixture()
        val context = host.get().applicationContext
        val monitor = PhysicalNetworks(context)
        val manager = shadowOf(context.getSystemService(ConnectivityManager::class.java))
        val looper = shadowOf(Looper.getMainLooper())
        val jobs = mutableListOf<Runnable>()
        try {
            ReflectionHelpers.setField(service, "recoveryStore", f.store)
            ReflectionHelpers.setField(service, "redundantWork", RedundantVpnWorkDispatcher(Executor { jobs += it }))
            val ownerSlot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(service, "redundantVpnOwnerSlot")
            ownerSlot.install(f.coordinator, "operation")
            val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
            val identity = RedundantPhysicalNetworkCallbackIdentity(generation, "operation", f.coordinator)
            val options = EffectiveAndroidTunnelOptions(splitSupported = true, excludeLocalNetworks = false)
            ReflectionHelpers.setField(service, "redundantTotalLossLifecycle", RedundantTotalLossLifecycle(
                currentServiceGeneration = { generation }, serviceActive = { true },
                barrierPending = { false }, logoutState = { BackgroundLogoutReadState.NONE },
                recovery = f.store::read, post = { it() }, retryCleanup = {},
                publishRestartStarting = {}, resume = {}, scheduleLogout = {},
                scheduleStateReadRetry = {}, stopIfIdle = {},
            ))
            val original = restoreWifi(context)
            monitor.start(initialState = original.copy(fingerprint = "older-online-network")) { state ->
                ReflectionHelpers.callInstanceMethod<Unit>(service, "applyRedundantPhysicalNetworks",
                    ReflectionHelpers.ClassParameter.from(RedundantPhysicalNetworkCallbackIdentity::class.java, identity),
                    ReflectionHelpers.ClassParameter.from(EffectiveAndroidTunnelOptions::class.java, options),
                    ReflectionHelpers.ClassParameter.from(RedundantConnectionCoordinator::class.java, f.coordinator),
                    ReflectionHelpers.ClassParameter.from(PhysicalNetworkState::class.java, state))
            }
            looper.idleFor(Duration.ofMillis(301))
            assertEquals(1, jobs.size)
            val callback = manager.networkCallbacks.single()
            if (failReadOnOfflineCallback) {
                jobs.removeAt(0).run()
                looper.idle()
                f.backend.reboundSlots.clear()
            }
            manager.clearAllNetworks()
            if (!failSnapshot) callback.onLost(original.networks.single())
            if (failReadOnOfflineCallback) {
                looper.idleFor(Duration.ofMillis(301))
                org.robolectric.shadow.api.Shadow.extract<FailingNetworkSnapshotShadow>(
                    context.getSystemService(ConnectivityManager::class.java)).failNextSnapshot = true
            }
            jobs.removeAt(0).run()
            assertFalse("A confirmed network loss must pause probes",
                ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
            if (failSnapshot) {
                val failingShadow = org.robolectric.shadow.api.Shadow.extract<FailingNetworkSnapshotShadow>(
                    context.getSystemService(ConnectivityManager::class.java))
                repeat(2) {
                    looper.idleFor(Duration.ofMillis(1_100))
                    failingShadow.failNextSnapshot = true
                    jobs.removeAt(0).run()
                    assertFalse(failingShadow.failNextSnapshot)
                    assertFalse("An unreadable retry revived an obsolete online snapshot",
                        ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    assertTrue(f.backend.reboundSlots.isEmpty())
                }
            }
            val restored = restoreWifi(context)
            assertEquals(original.fingerprint, restored.fingerprint)
            callback.onAvailable(restored.networks.single())
            repeat(4) {
                looper.idleFor(Duration.ofMillis(1_100))
                while (jobs.isNotEmpty()) jobs.removeAt(0).run()
            }
            assertTrue("The native backend stayed offline after the exact network returned",
                ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
            assertEquals(listOf(0, 1), f.backend.reboundSlots)
            assertEquals(1, f.tunStarts)
        } finally {
            monitor.stop()
            f.native.closeForStop()
            ReflectionHelpers.getField<android.os.Handler>(service, "restoreHandler").removeCallbacksAndMessages(null)
            ReflectionHelpers.getField<ExecutorService>(service, "redundantExecutor").shutdownNow()
            ReflectionHelpers.getField<ExecutorService>(service, "credentialExecutor").shutdownNow()
            host.destroy()
        }
    }

    @Test fun resampledNetworkMustNotRebindNewTunTwice() =
        refreshAfterLocalRouteChange(RouteChangeRace.RESAMPLED_TUN_REPLACEMENT)

    @Test fun deferredPluginUpdateCannotReuseProgressFromBeforeProbeInvalidation() =
        refreshAfterLocalRouteChange(RouteChangeRace.RESAMPLED_NETWORK_CALLBACK,
            equalStartupRoutes = true, lateCallback = true, pluginReadFailureAfterResample = true)

    @Test fun coalescedNetworkLossInvalidatesTunReplacementProgress() =
        refreshAfterLocalRouteChange(RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_LOSS)

    @Test fun directPluginNetworkLossInvalidatesTunReplacementProgress() =
        refreshAfterLocalRouteChange(RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_PLUGIN_LOSS)

    @Test fun offlineManualRebindInvalidatesTunReplacementProgress() =
        refreshAfterLocalRouteChange(RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_MANUAL_REBIND)

    private fun refreshAfterLocalRouteChange(
        race: RouteChangeRace,
        recoveryReadToFail: Int = 1,
        initialRebindFailures: Set<Int> = emptySet(),
        expireStartup: Boolean = false,
        equalStartupRoutes: Boolean = false,
        lateCallback: Boolean = false,
        pluginReadFailureAfterResample: Boolean = false,
        primaryRecovers: Boolean = false,
        interruptedSwitch: InterruptedStartupSwitch? = null,
    ) {
        val host = Robolectric.buildService(VpnService::class.java).create()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host.get()
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = service.Builder().also(beforeEstablish)
        })
        var elapsedMs = 100_000L
        val starting = race in setOf(RouteChangeRace.STARTUP_PENDING, RouteChangeRace.RESAMPLED_NETWORK_CALLBACK,
            RouteChangeRace.OFFLINE_AFTER_REBIND_FAILURE, RouteChangeRace.OFFLINE_PENDING_SWITCH)
        val f = OwnedRedundantPolicyTest.Fixture(
            initialHealthProbes = if (starting) {
                mapOf("lease-a" to BackgroundRedundantHealthProbe("dns_a", "192.0.2.1", "example.test", 4000))
            } else emptyMap(),
            monotonicMs = { elapsedMs },
        )
        val jobs = mutableListOf<Runnable>()
        val previousCredentials = ReflectionHelpers.getField<BackgroundCredentialStore?>(
            AndroidBackgroundCredentialStores, "instance")
        try {
            ReflectionHelpers.setField(service, "recoveryStore", f.store)
            ReflectionHelpers.setField(service, "redundantWork", RedundantVpnWorkDispatcher(Executor { jobs += it }))
            val ownerSlot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(service, "redundantVpnOwnerSlot")
            ownerSlot.install(f.coordinator, "operation")
            val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
            val identity = RedundantPhysicalNetworkCallbackIdentity(generation, "operation", f.coordinator)
            val options = EffectiveAndroidTunnelOptions(splitSupported = true, excludeLocalNetworks = true)
            val oldLan = if ((starting && !equalStartupRoutes) || race in setOf(
                    RouteChangeRace.RESAMPLED_TUN_REPLACEMENT, RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_LOSS,
                    RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_PLUGIN_LOSS,
                    RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_MANUAL_REBIND,
                )
            ) {
                Ipv4Prefix(0xc0a80200.toInt(), 24, "192.168.2.0/24")
            } else Ipv4Prefix(0xc0a80100.toInt(), 24, "192.168.1.0/24")
            val originalRoutes = if (race in setOf(RouteChangeRace.OFFLINE_AFTER_REBIND_FAILURE,
                    RouteChangeRace.OFFLINE_PENDING_SWITCH)
            ) emptyList() else listOf(oldLan)
            ownerSlot.updateRouteBaseline(f.coordinator, redundantVpnRouteBaseline(options, originalRoutes), options)
            val standbyRequests = mutableListOf<Runnable>()
            if (race == RouteChangeRace.STANDBY_IN_FLIGHT) {
                ReflectionHelpers.setField(f.coordinator, "standbyExecutor", Executor { standbyRequests += it })
                assertTrue(f.coordinator.acquireAndCommitStandby("replace-standby", "lease-b"))
                assertEquals(1, standbyRequests.size)
            }
            val before = f.store.read()
            var expectedRecovery = before
            val returningWithEqualRoutes = race == RouteChangeRace.LOOKUP_DURING_REBIND ||
                race == RouteChangeRace.UNREADABLE_RECOVERY
            val state = if (returningWithEqualRoutes) {
                f.coordinator.onUnderlyingNetworkChanged(false)
                restoreWifi(host.get().applicationContext).also { assertEquals(listOf(oldLan), it.localRoutes) }
            } else if (race == RouteChangeRace.STARTUP_PENDING) {
                f.coordinator.onUnderlyingNetworkChanged(false)
                f.backend.reboundSlots.clear()
                restoreWifi(host.get().applicationContext).also { assertTrue(it.available) }
            } else PhysicalNetworkState(emptyList(), emptyList(), false, "physical")

            fun deliver(networkState: PhysicalNetworkState) {
                ReflectionHelpers.callInstanceMethod<Unit>(service, "applyRedundantPhysicalNetworks",
                    ReflectionHelpers.ClassParameter.from(RedundantPhysicalNetworkCallbackIdentity::class.java, identity),
                    ReflectionHelpers.ClassParameter.from(EffectiveAndroidTunnelOptions::class.java, options),
                    ReflectionHelpers.ClassParameter.from(RedundantConnectionCoordinator::class.java, f.coordinator),
                    ReflectionHelpers.ClassParameter.from(PhysicalNetworkState::class.java, networkState))
            }
            val callback = runCatching { deliver(state) }
            assertEquals("Route refresh must not persist a full session restart", before, f.store.read())
            callback.getOrThrow()
            if (race == RouteChangeRace.STOP) {
                ReflectionHelpers.getField<RedundantOperationMutationFence>(service, "redundantMutationFence")
                    .cancel("operation")
            }
            val barrier = ReflectionHelpers.getField<RedundantStopLookupBarrier>(service, "redundantStopLookupBarrier")
            var lookup: Long? = null
            val looper = shadowOf(Looper.getMainLooper())
            if (returningWithEqualRoutes || race in setOf(RouteChangeRace.LOOKUP_BEFORE_WORK,
                    RouteChangeRace.UNREADABLE_LOGOUT, RouteChangeRace.UNREADABLE_ROUTE_PREFLIGHT,
                    RouteChangeRace.STANDBY_IN_FLIGHT, RouteChangeRace.STARTUP_PENDING)
            ) {
                ReflectionHelpers.setField(service, "redundantTotalLossLifecycle", RedundantTotalLossLifecycle(
                    currentServiceGeneration = { generation }, serviceActive = { true },
                    barrierPending = barrier::hasPending, logoutState = { BackgroundLogoutReadState.NONE },
                    recovery = f.store::read, post = { it() }, retryCleanup = {},
                    publishRestartStarting = {}, resume = {}, scheduleLogout = {},
                    scheduleStateReadRetry = {}, stopIfIdle = {},
                ))
            }
            if (race in setOf(RouteChangeRace.UNREADABLE_ROUTE_PREFLIGHT, RouteChangeRace.STANDBY_IN_FLIGHT,
                    RouteChangeRace.UNREADABLE_AFTER_NATIVE_REPLACEMENT, RouteChangeRace.STARTUP_PENDING)
            ) {
                ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance",
                    BackgroundCredentialStore(OwnedRedundantPolicyTest.PolicyRecord()))
                ReflectionHelpers.setField(service, "redundantCancelTombstones",
                    RedundantCancelTombstoneStore(AndroidRedundantCancelTombstoneBackend(host.get())))
            }
            when (race) {
                RouteChangeRace.LOOKUP_BEFORE_WORK -> {
                    val token = barrier.begin()
                    jobs.removeAt(0).run()
                    assertEquals(1, f.tunStarts)
                    assertTrue(barrier.complete(token))
                    ReflectionHelpers.callInstanceMethod<Unit>(service, "resumeDurableWorkAfterRedundantBarrier")
                }
                RouteChangeRace.LOOKUP_DURING_REBIND -> {
                    ReflectionHelpers.setField(f.store, "backend", object : EncryptedRecordBackend by f.record {
                        override fun read(): ByteArray? {
                            if (lookup == null) lookup = barrier.begin()
                            return f.record.read()
                        }
                    })
                    jobs.removeAt(0).run()
                    looper.idle()
                    assertFalse(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    assertTrue(barrier.complete(requireNotNull(lookup)))
                    ReflectionHelpers.callInstanceMethod<Unit>(service, "resumeDurableWorkAfterRedundantBarrier")
                }
                RouteChangeRace.UNREADABLE_LOGOUT -> {
                    var failRead = true
                    ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance",
                        BackgroundCredentialStore(object : EncryptedRecordBackend {
                            override fun read(): ByteArray? {
                                if (failRead) {
                                    failRead = false
                                    error("temporary keystore failure")
                                }
                                return null
                            }
                            override fun write(plaintext: ByteArray) = true
                        }))
                    jobs.removeAt(0).run()
                    looper.idle()
                    assertEquals(1, f.tunStarts)
                    assertFalse("Physical loss must reach native while Logout is unreadable",
                        ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    assertTrue("Physical loss must suppress total loss while Logout is unreadable",
                        f.coordinator.onHealthObservations(listOf(
                            SlotObservation(0, true, BackendHealth.UNHEALTHY, hardFailure = true),
                            SlotObservation(1, false, BackendHealth.UNHEALTHY, hardFailure = true),
                        )))
                    assertTrue("Credential retry must not spin the VPN worker", jobs.isEmpty())
                    looper.idleFor(Duration.ofMillis(1_100))
                }
                RouteChangeRace.UNREADABLE_RECOVERY, RouteChangeRace.UNREADABLE_ROUTE_PREFLIGHT -> {
                    var reads = 0
                    ReflectionHelpers.setField(f.store, "backend", object : EncryptedRecordBackend by f.record {
                        override fun read(): ByteArray? {
                            if (++reads == recoveryReadToFail) error("temporary recovery read failure")
                            return f.record.read()
                        }
                    })
                    jobs.removeAt(0).run()
                    assertTrue("Read $recoveryReadToFail must leave the current TUN open", f.native.isUsable("lease-a"))
                    looper.idle()
                    assertTrue("The preflight must reach the injected recovery read", reads >= recoveryReadToFail)
                    assertEquals("The read failure must not prepare a full VPN restart", before, f.store.read())
                    assertEquals(1, f.tunStarts)
                    assertTrue(f.native.isUsable("lease-a"))
                    assertTrue(f.native.isUsable("lease-b"))
                    if (returningWithEqualRoutes) {
                        assertFalse(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    } else if (recoveryReadToFail == 1) {
                        assertFalse("Physical loss must reach native despite a failed recovery read",
                            ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                        assertTrue("A failed recovery read must not leave the health detector online",
                            f.coordinator.onHealthObservations(listOf(
                                SlotObservation(0, true, BackendHealth.UNHEALTHY, hardFailure = true),
                                SlotObservation(1, false, BackendHealth.UNHEALTHY, hardFailure = true),
                            )))
                    }
                    assertTrue("Recovery retry must not spin the VPN worker", jobs.isEmpty())
                    looper.idleFor(Duration.ofMillis(1_100))
                }
                RouteChangeRace.STANDBY_IN_FLIGHT -> {
                    repeat(2) {
                        jobs.removeAt(0).run()
                        looper.idle()
                        assertEquals("Waiting for standby must not prepare a full VPN restart", before, f.store.read())
                        assertEquals(1, f.tunStarts)
                        assertTrue(f.native.isUsable("lease-a"))
                        assertTrue(f.native.isUsable("lease-b"))
                        assertFalse("Native probes must pause during physical loss",
                            ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                        assertTrue("Physical loss must suppress total loss while standby is busy",
                            f.coordinator.onHealthObservations(listOf(
                                SlotObservation(0, true, BackendHealth.UNHEALTHY, hardFailure = true),
                                SlotObservation(1, false, BackendHealth.UNHEALTHY, hardFailure = true),
                            )))
                        assertTrue("Standby wait must not spin the VPN worker", jobs.isEmpty())
                        looper.idleFor(Duration.ofMillis(1_100))
                    }
                    standbyRequests.single().run()
                    expectedRecovery = f.store.read()
                }
                RouteChangeRace.STARTUP_PENDING -> {
                    assertFalse(f.coordinator.isRunning())
                    f.backend.rebindFailures.addAll(initialRebindFailures)
                    repeat(2) { attempt ->
                        jobs.removeAt(0).run()
                        looper.idle()
                        assertEquals("Readiness must not stage a full restart", before, f.store.read())
                        assertEquals(1, f.tunStarts)
                        if (expireStartup && attempt == 1) {
                            assertEquals("No socket rebind may start at the deadline",
                                listOf(0, 1), f.backend.reboundSlots)
                            assertFalse("The original readiness deadline must still expire", f.coordinator.tick())
                            assertFalse(f.native.isUsable("lease-a"))
                            return
                        }
                        val expectedRebinds = if (attempt == 0) listOf(0, 1)
                            else listOf(0, 1) + initialRebindFailures.sorted()
                        assertEquals("Only failed sockets may be rebound on a route retry",
                            expectedRebinds, f.backend.reboundSlots)
                        if (attempt == 0 && initialRebindFailures.isNotEmpty()) {
                            assertTrue("Readiness must keep waiting for the route retry", f.coordinator.tick())
                            if (!expireStartup) f.backend.rebindFailures.clear()
                        }
                        elapsedMs += if (expireStartup) 30_000 else 3_000
                        looper.idleFor(Duration.ofMillis(1_100))
                    }
                    assertTrue(f.coordinator.onHealthObservations(listOf(
                        SlotObservation(0, true, BackendHealth.READY,
                            handshakeFresh = true, consecutiveProbeSuccesses = 1,
                            successfulProbeValidThroughElapsedMs = elapsedMs),
                    )))
                    assertTrue("Retries must not prolong readiness stabilization", f.coordinator.isRunning())
                    expectedRecovery = f.store.read()
                }
                RouteChangeRace.RESAMPLED_NETWORK_CALLBACK -> {
                    if (!pluginReadFailureAfterResample) f.backend.rebindFailures += 1
                    val newNetwork = restoreWifi(host.get().applicationContext)
                    if (!lateCallback) deliver(newNetwork)
                    jobs.removeAt(0).run()
                    looper.idle()
                    assertEquals(listOf(0, 1), f.backend.reboundSlots)
                    if (pluginReadFailureAfterResample) {
                        ReflectionHelpers.callInstanceMethod<Unit>(service, "applyPluginPhysicalNetworks",
                            ReflectionHelpers.ClassParameter.from(List::class.java, newNetwork.networks))
                        f.record.beforeRead = { error("recovery unreadable") }
                        jobs.removeAt(0).run()
                        f.record.beforeRead = {}
                        assertFalse(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                        looper.idle()
                        jobs.removeAt(0).run()
                        looper.idle()
                        assertTrue(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                        assertEquals(listOf(0, 1, 0, 1), f.backend.reboundSlots)
                        return
                    }
                    if (lateCallback) deliver(newNetwork)
                    f.backend.rebindFailures.clear()
                    jobs.removeAt(0).run()
                    looper.idle()
                    assertEquals("Only the failed socket needs a second rebind on the resampled network",
                        listOf(0, 1, 1), f.backend.reboundSlots)
                    val context = host.get().applicationContext
                    shadowOf(context.getSystemService(ConnectivityManager::class.java)).clearAllNetworks()
                    deliver(PhysicalNetworks(context).snapshotState().also { assertFalse(it.available) })
                    deliver(restoreWifi(context))
                    repeat(2) {
                        jobs.removeAt(0).run()
                        looper.idle()
                    }
                    assertEquals("A later disconnect must allow both sockets to rebind on the returning network",
                        listOf(0, 1, 1, 0, 1), f.backend.reboundSlots)
                    assertEquals(1, f.tunStarts)
                    assertEquals(before, f.store.read())
                    return
                }
                RouteChangeRace.OFFLINE_AFTER_REBIND_FAILURE -> {
                    f.backend.rebindFailures.addAll(listOf(0, 1))
                    assertFalse(f.coordinator.onUnderlyingNetworkChanged(true))
                    jobs.removeAt(0).run()
                    looper.idle()
                    assertFalse(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    assertTrue("Stale rebind failures must not abort readiness while offline", f.coordinator.tick())
                    elapsedMs += 29_999
                    assertTrue(f.coordinator.tick())
                    assertTrue(f.native.isUsable("lease-a"))
                    elapsedMs += 1
                    assertFalse("The original deadline must still expire while offline", f.coordinator.tick())
                    assertFalse(f.native.isUsable("lease-a"))
                    return
                }
                RouteChangeRace.OFFLINE_PENDING_SWITCH -> {
                    f.backend.failedActivationSlot = 1
                    assertFalse(f.coordinator.onHealthObservations(listOf(
                        SlotObservation(0, true, BackendHealth.UNHEALTHY, hardFailure = true),
                        SlotObservation(1, false, BackendHealth.READY,
                            successfulProbeValidThroughElapsedMs = elapsedMs),
                    )))
                    assertEquals("lease-b", f.coordinator.status()!!.retry.pendingNativeActiveLeaseId)
                    val activationAttempts = f.backend.activeSlots.size
                    f.backend.failedActivationSlot = null
                    jobs.removeAt(0).run()
                    looper.idle()
                    assertFalse(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    assertTrue(f.coordinator.tick())
                    assertFalse("An offline switch must not mark the VPN ready", f.coordinator.isRunning())
                    assertEquals(activationAttempts, f.backend.activeSlots.size)
                    assertEquals("lease-b", f.coordinator.status()!!.retry.pendingNativeActiveLeaseId)
                    val progress = RedundantNetworkRebindProgress()
                    if (!expireStartup || initialRebindFailures.isNotEmpty()) {
                        f.backend.rebindFailures.addAll(initialRebindFailures)
                        assertEquals(initialRebindFailures.isEmpty(),
                            f.coordinator.onUnderlyingNetworkChanged(true, progress) { true })
                        assertTrue(f.coordinator.tick())
                        assertFalse("A network callback alone cannot prove the reserve is ready", f.coordinator.isRunning())
                        assertEquals(activationAttempts, f.backend.activeSlots.size)
                        assertEquals("lease-b", f.coordinator.status()!!.retry.pendingNativeActiveLeaseId)
                    }
                    if (interruptedSwitch != null) {
                        elapsedMs += 4_000
                        val reserveActivated = interruptedSwitch == InterruptedStartupSwitch.COMMIT_FAILED
                        if (reserveActivated) f.record.failNextWrite = true else f.backend.failedActivationSlot = 1
                        assertFalse(f.coordinator.onHealthObservations(listOf(
                            SlotObservation(1, false, BackendHealth.READY,
                                standbyProbeState = StandbyProbeState.SUCCEEDED, successfulProbeValidThroughElapsedMs = elapsedMs),
                        )))
                        assertEquals("lease-b", f.coordinator.status()!!.retry.pendingNativeActiveLeaseId)
                        assertEquals(reserveActivated, f.native.healthObservations().single { it.index == 1 }.active)
                        if (reserveActivated) {
                            f.backend.rebindFailures += 1
                            assertFalse(f.coordinator.onUnderlyingNetworkChanged(true, RedundantNetworkRebindProgress()) { true })
                            elapsedMs += 4_000
                        } else {
                            f.backend.failedActivationSlot = null
                            val attempts = f.backend.activeSlots.size
                            assertTrue(f.coordinator.onHealthObservations(listOf(
                                SlotObservation(1, false, BackendHealth.UNHEALTHY, hardFailure = true),
                            )))
                            assertEquals("A failed switch cannot reuse an expired reserve proof",
                                attempts, f.backend.activeSlots.size)
                            assertFalse(f.coordinator.isRunning())
                        }
                        assertTrue(f.coordinator.onHealthObservations(listOf(
                            SlotObservation(0, !reserveActivated, BackendHealth.READY,
                                handshakeFresh = true, consecutiveProbeSuccesses = 1, successfulProbeValidThroughElapsedMs = elapsedMs),
                            SlotObservation(1, reserveActivated, BackendHealth.UNHEALTHY, hardFailure = true),
                        )))
                        assertTrue("The VPN should finish startup on its proven primary", f.coordinator.isRunning())
                        assertEquals("lease-a", f.coordinator.status()!!.localActiveLeaseId)
                        assertNull(f.coordinator.status()!!.retry.pendingNativeActiveLeaseId)
                        assertTrue(f.native.healthObservations().single { it.index == 0 }.active)
                        return
                    }
                    if (primaryRecovers) {
                        elapsedMs += 4_000
                        val recoveredPrimary = listOf(
                            SlotObservation(0, true, BackendHealth.READY,
                                handshakeFresh = true, consecutiveProbeSuccesses = 1, successfulProbeValidThroughElapsedMs = elapsedMs),
                            SlotObservation(1, false, BackendHealth.UNHEALTHY, hardFailure = true),
                        )
                        f.record.failNextWrite = true
                        assertTrue(f.coordinator.onHealthObservations(recoveredPrimary))
                        assertFalse(f.coordinator.isRunning())
                        assertEquals("lease-b", f.coordinator.status()!!.retry.pendingNativeActiveLeaseId)
                        assertTrue(f.coordinator.onHealthObservations(recoveredPrimary))
                        assertTrue("The working primary must finish startup even when the reserve cannot rebind",
                            f.coordinator.isRunning())
                        val ready = requireNotNull(f.coordinator.status())
                        assertEquals("lease-a", ready.localActiveLeaseId)
                        assertEquals("lease-a", ready.retry.pendingRoleLeaseId)
                        assertNull(ready.retry.pendingNativeActiveLeaseId)
                        assertEquals(activationAttempts, f.backend.activeSlots.size)
                        return
                    }
                    if (expireStartup) {
                        elapsedMs += 29_999
                        assertTrue(f.coordinator.tick())
                        elapsedMs += 1
                        assertFalse(f.coordinator.tick())
                        assertFalse(f.native.isUsable("lease-a"))
                        assertEquals(activationAttempts, f.backend.activeSlots.size)
                        return
                    }
                    if (initialRebindFailures.isNotEmpty()) {
                        f.backend.rebindFailures.clear()
                        assertTrue(f.coordinator.onUnderlyingNetworkChanged(true, progress) { true })
                        assertEquals(listOf(0, 1, 1), f.backend.reboundSlots)
                    }
                    elapsedMs += 4_000
                    assertTrue(f.coordinator.tick())
                    assertFalse("Rebinding the reserve still requires fresh probe evidence", f.coordinator.isRunning())
                    assertTrue(f.coordinator.onHealthObservations(listOf(
                        SlotObservation(1, false, BackendHealth.READY,
                            standbyProbeState = StandbyProbeState.SUCCEEDED, successfulProbeValidThroughElapsedMs = elapsedMs),
                    )))
                    assertTrue(f.coordinator.isRunning())
                    assertEquals("lease-b", f.coordinator.status()!!.localActiveLeaseId)
                    return
                }
                RouteChangeRace.RESAMPLED_TUN_REPLACEMENT,
                RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_LOSS,
                RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_PLUGIN_LOSS,
                RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_MANUAL_REBIND -> {
                    val context = host.get().applicationContext
                    val lostNetwork = race != RouteChangeRace.RESAMPLED_TUN_REPLACEMENT
                    val newNetwork = restoreWifi(context)
                    f.duringEstablish = {
                        if (f.tunStarts == 2) ownerSlot.updateRouteBaseline(f.coordinator,
                            redundantVpnRouteBaseline(options, newNetwork.localRoutes), options, newNetwork.fingerprint)
                    }
                    deliver(newNetwork)
                    jobs.removeAt(0).run()
                    if (lostNetwork) {
                        shadowOf(context.getSystemService(ConnectivityManager::class.java)).clearAllNetworks()
                        when (race) {
                            RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_PLUGIN_LOSS -> {
                                ReflectionHelpers.callInstanceMethod<Unit>(service, "applyPluginPhysicalNetworks",
                                    ReflectionHelpers.ClassParameter.from(List::class.java, emptyList<android.net.Network>()))
                            }
                            RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_MANUAL_REBIND -> {
                                ReflectionHelpers.callInstanceMethod<Unit>(service, "handleClientRebindUdp",
                                    ReflectionHelpers.ClassParameter.from(Intent::class.java,
                                        Intent().putExtra(EXTRA_API_VERSION, TUNNEL_API_VERSION)))
                            }
                            else -> deliver(PhysicalNetworks(context).snapshotState().also { assertFalse(it.available) })
                        }
                        if (race != RouteChangeRace.RESAMPLED_TUN_REPLACEMENT_AFTER_LOSS) {
                            jobs.removeAt(0).run()
                            assertFalse(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                            f.backend.reboundSlots.clear()
                        }
                        val returned = restoreWifi(context)
                        assertEquals(newNetwork.fingerprint, returned.fingerprint)
                        deliver(returned)
                    }
                    looper.idle()
                    assertEquals(2, f.tunStarts)
                    assertTrue(f.native.isUsable("lease-a"))
                    assertTrue(f.native.isUsable("lease-b"))
                    assertTrue(f.backend.reboundSlots.isEmpty())
                    jobs.removeAt(0).run()
                    looper.idle()
                    val expectedRebinds = if (lostNetwork) listOf(0, 1) else emptyList()
                    assertEquals(expectedRebinds, f.backend.reboundSlots)
                    assertTrue(ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
                    assertEquals(2, f.tunStarts)
                    assertEquals(before, f.store.read())
                    return
                }
                RouteChangeRace.UNREADABLE_AFTER_NATIVE_REPLACEMENT -> {
                    val activeSwitches = f.backend.activeSlots.size
                    var readFailed = false
                    ReflectionHelpers.setField(f.store, "backend", object : EncryptedRecordBackend by f.record {
                        override fun read(): ByteArray? {
                            if (!readFailed && f.backend.activeSlots.size > activeSwitches) {
                                readFailed = true
                                error("temporary recovery read failure after native switch")
                            }
                            return f.record.read()
                        }
                    })
                    jobs.removeAt(0).run()
                    assertTrue(readFailed)
                    assertEquals(2, f.tunStarts)
                    assertFalse(f.native.isUsable("lease-a"))
                    looper.idle()
                    val recovery = (f.store.read() as RecoveryStoreResult.Success).value
                    assertNotNull(recovery.redundantTransaction?.retry?.totalLossRestartReplay)
                    return
                }
                RouteChangeRace.LOOKUP_DURING_ESTABLISH -> f.duringEstablish = { lookup = barrier.begin() }
                RouteChangeRace.WIFI_RETURN -> {
                    val context = host.get().applicationContext
                    f.duringEstablish = {
                        if (f.tunStarts == 2) {
                            val returnedWifi = restoreWifi(context)
                            assertEquals(listOf(oldLan), returnedWifi.localRoutes)
                            deliver(returnedWifi)
                            ownerSlot.updateRouteBaseline(f.coordinator,
                                redundantVpnRouteBaseline(options, emptyList()), options)
                        } else if (f.tunStarts == 3) {
                            ownerSlot.updateRouteBaseline(f.coordinator,
                                redundantVpnRouteBaseline(options, listOf(oldLan)), options)
                        }
                    }
                }
                else -> Unit
            }
            looper.idle()
            repeat(3) {
                if (jobs.isNotEmpty()) jobs.removeAt(0).run()
                looper.idle()
            }
            assertTrue("Network work must settle", jobs.isEmpty())

            if (race == RouteChangeRace.WIFI_RETURN) {
                assertEquals("The Wi-Fi exclusion must be restored against the new baseline",
                    redundantVpnRouteBaseline(options, listOf(oldLan)), ownerSlot.snapshot()?.routeBaseline)
            }
            assertEquals(when {
                race == RouteChangeRace.STOP || returningWithEqualRoutes || equalStartupRoutes -> 1
                race == RouteChangeRace.WIFI_RETURN -> 3
                else -> 2
            }, f.tunStarts)
            assertEquals(expectedRecovery, f.store.read())
            assertEquals(0, f.panelCalls)
            if (race == RouteChangeRace.STOP) {
                assertTrue("The Stop fence must block the offline update",
                    ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
            }
            if (returningWithEqualRoutes) {
                assertTrue("The native backend must observe the returned network after the retry",
                    ReflectionHelpers.getField<Boolean>(f.native, "networkAvailable"))
            }
            if (race == RouteChangeRace.LOOKUP_DURING_ESTABLISH) {
                assertTrue(f.coordinator.policyFailed())
                assertFalse(f.native.isUsable("lease-a"))
                assertTrue(barrier.complete(requireNotNull(lookup)))
                val deferred = ReflectionHelpers.getField<RedundantTotalLossCommandLifecycle<Any>>(
                    service, "redundantTotalLossCommands")
                assertTrue("Replacement closed the VPN, but no restart was deferred", deferred.replay {})
                assertFalse("Recovery must be replayed only once", deferred.replay {})
                return
            }
            assertTrue(f.native.isUsable("lease-a"))
            assertTrue(f.native.isUsable("lease-b"))
        } finally {
            ReflectionHelpers.setField(AndroidBackgroundCredentialStores, "instance", previousCredentials)
            f.native.closeForStop()
            ReflectionHelpers.getField<android.os.Handler>(service, "restoreHandler").removeCallbacksAndMessages(null)
            ReflectionHelpers.getField<ExecutorService>(service, "redundantExecutor").shutdownNow()
            ReflectionHelpers.getField<ExecutorService>(service, "credentialExecutor").shutdownNow()
            host.destroy()
        }
    }

    private fun restoreWifi(context: android.content.Context): PhysicalNetworkState {
        val manager = shadowOf(context.getSystemService(ConnectivityManager::class.java))
        manager.clearAllNetworks()
        val wifi = ShadowNetwork.newInstance(253)
        manager.addNetwork(wifi, ShadowNetworkInfo.newInstance(
            NetworkInfo.DetailedState.CONNECTED, ConnectivityManager.TYPE_WIFI, 0, true, true))
        val capabilities = NetworkCapabilities()
        shadowOf(capabilities).addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        shadowOf(capabilities).addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        shadowOf(capabilities).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        manager.setNetworkCapabilities(wifi, capabilities)
        manager.setLinkProperties(wifi, LinkProperties().apply {
            interfaceName = "wlan0"
            val address = ReflectionHelpers.callConstructor(LinkAddress::class.java,
                ReflectionHelpers.ClassParameter.from(String::class.java, "192.168.1.2/24"))
            ReflectionHelpers.callInstanceMethod<Boolean>(this, "addLinkAddress",
                ReflectionHelpers.ClassParameter.from(LinkAddress::class.java, address))
        })
        return PhysicalNetworks(context).snapshotState()
    }

    @Test fun queuedOldPolicyCallbackUsesNewOptionsOfTheSameRealOwner() {
        val host = Robolectric.buildService(VpnService::class.java).create()
        val service = NelomaiVpnService(object : RuntimeVpnHostV1 {
            override val service = host.get()
            override fun builder(beforeEstablish: (VpnService.Builder) -> Unit) = service.Builder().also(beforeEstablish)
        })
        val f = OwnedRedundantPolicyTest.Fixture()
        val jobs = mutableListOf<Runnable>()
        try {
            ReflectionHelpers.setField(service, "recoveryStore", f.store)
            ReflectionHelpers.setField(service, "redundantWork", RedundantVpnWorkDispatcher(Executor { jobs += it }))
            val ownerSlot = ReflectionHelpers.getField<RedundantVpnOwnerSlot>(service, "redundantVpnOwnerSlot")
            ownerSlot.install(f.coordinator, "operation")
            val generation = ReflectionHelpers.getField<Long>(service, "serviceGeneration")
            val identity = RedundantPhysicalNetworkCallbackIdentity(generation, "operation", f.coordinator)
            val old = AndroidSplitTunnel.resolveOptions(34, AndroidTunnelOptions(splitActive = true,
                excludeLocalNetworks = true, splitTunnelRoutes = listOf("192.0.2.0/24")).toTunnelOptionsArgs())
            val new = AndroidSplitTunnel.resolveOptions(34, AndroidTunnelOptions(splitActive = true,
                excludeLocalNetworks = true, splitTunnelRoutes = listOf("198.51.100.0/24")).toTunnelOptionsArgs())
            val state = PhysicalNetworkState(emptyList(), emptyList(), false, "physical")
            // Callback was captured before Save; owner/start/service identities stay identical.
            val queuedCallback = {
                ReflectionHelpers.callInstanceMethod<Unit>(service, "applyRedundantPhysicalNetworks",
                    ReflectionHelpers.ClassParameter.from(RedundantPhysicalNetworkCallbackIdentity::class.java, identity),
                    ReflectionHelpers.ClassParameter.from(EffectiveAndroidTunnelOptions::class.java, old),
                    ReflectionHelpers.ClassParameter.from(RedundantConnectionCoordinator::class.java, f.coordinator),
                    ReflectionHelpers.ClassParameter.from(PhysicalNetworkState::class.java, state))
            }
            ownerSlot.updateRouteBaseline(f.coordinator, redundantVpnRouteBaseline(new, emptyList()), new)
            val before = f.store.read()
            val result = runCatching(queuedCallback)
            assertEquals(before, f.store.read())
            assertTrue("old callback forced recovery: ${result.exceptionOrNull()}", result.isSuccess)
            assertTrue(f.coordinator.isRunning())
            assertEquals(0, f.panelCalls)
            assertEquals(1, jobs.size) // current network notification, no recovery/start/stop work
        } finally {
            f.native.closeForStop()
            ReflectionHelpers.getField<ExecutorService>(service, "redundantExecutor").shutdownNow()
            ReflectionHelpers.getField<ExecutorService>(service, "credentialExecutor").shutdownNow()
            host.destroy()
        }
    }
}

@org.robolectric.annotation.Implements(VpnService::class)
class StartupVpnNetworkShadow : org.robolectric.shadows.ShadowVpnService() {
    @org.robolectric.annotation.Implementation
    fun setUnderlyingNetworks(networks: Array<android.net.Network>?): Boolean {
        applications++
        if (failNextApplication) {
            failNextApplication = false
            error("simulated Android VPN reporting failure")
        }
        return true
    }

    companion object {
        var applications = 0
        var failNextApplication = false
    }
}

@org.robolectric.annotation.Implements(ConnectivityManager::class)
class FailingNetworkSnapshotShadow : org.robolectric.shadows.ShadowConnectivityManager() {
    var failNextSnapshot = false

    @org.robolectric.annotation.Implementation
    protected override fun getAllNetworks(): Array<android.net.Network> {
        if (failNextSnapshot) {
            failNextSnapshot = false
            error("simulated ConnectivityManager read failure")
        }
        return super.getAllNetworks()
    }
}
