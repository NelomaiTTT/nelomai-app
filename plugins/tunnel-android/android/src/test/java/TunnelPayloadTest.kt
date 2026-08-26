package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

class TunnelPayloadTest {
    @Test
    fun operationWatchdogExpiresOnlyTheCurrentUnfinishedOperation() {
        val gate = TunnelOperationWatchdogGate()
        val completed = gate.begin()

        assertTrue(gate.complete(completed))
        assertFalse(gate.expire(completed))

        val stale = gate.begin()
        val current = gate.begin()
        assertFalse(gate.expire(stale))
        assertTrue(gate.expire(current))
    }

    @Test
    fun metricsWatchdogCannotReplaceTheLifecycleWatchdog() {
        val gates = TunnelOperationWatchdogGates()
        val lifecycle = gates.begin(TunnelOperationWatchdogScope.LIFECYCLE)
        val metrics = gates.begin(TunnelOperationWatchdogScope.METRICS)

        assertTrue(gates.complete(metrics))
        assertTrue(gates.expire(lifecycle))
    }

    @Test
    fun payloadIsWipedAfterSuccessfulUse() {
        val payload = "PrivateKey = secret".encodeToByteArray()

        TunnelPayload.consume(payload) { bytes ->
            assertEquals("PrivateKey = secret", bytes.decodeToString())
        }

        assertTrue(payload.all { it == 0.toByte() })
    }

    @Test
    fun payloadIsWipedWhenUseFails() {
        val payload = "PrivateKey = secret".encodeToByteArray()

        runCatching {
            TunnelPayload.consume(payload) {
                error("bad config")
            }
        }

        assertTrue(payload.all { it == 0.toByte() })
    }

    @Test
    fun duplicateStartCannotEnterTheNativeQueueAndRunningTunnelIsReplaced() {
        val gate = TunnelStateGate()

        assertEquals(TransitionDecision.PROCEED, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
        gate.complete(SessionState.RUNNING)
        assertEquals(TransitionDecision.REPLACE, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
    }

    @Test
    fun failedTunnelIsCleanedBeforeItIsStartedAgain() {
        val gate = TunnelStateGate(SessionState.FAILED)

        assertEquals(TransitionDecision.REPLACE, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
    }

    @Test
    fun stopIsIdempotentAndBlocksConcurrentMutation() {
        val gate = TunnelStateGate(SessionState.RUNNING)

        assertEquals(TransitionDecision.PROCEED, gate.beginStop())
        assertEquals(TransitionDecision.BUSY, gate.beginStop())
        gate.complete(SessionState.STOPPED)
        assertEquals(TransitionDecision.ALREADY_COMPLETE, gate.beginStop())
    }

    @Test
    fun rebindBlocksConcurrentStartStopAndSecondRebind() {
        val gate = TunnelStateGate(SessionState.RUNNING)

        assertEquals(TransitionDecision.PROCEED, gate.beginRebind())
        assertEquals(TransitionDecision.BUSY, gate.beginStart())
        assertEquals(TransitionDecision.BUSY, gate.beginStop())
        assertEquals(TransitionDecision.BUSY, gate.beginRebind())
        gate.complete(SessionState.RUNNING)
        assertEquals(TransitionDecision.PROCEED, gate.beginStop())
    }

    @Test
    fun cancellingRebindCannotResurrectAStoppedService() {
        val gate = TunnelStateGate(SessionState.RUNNING)

        assertEquals(TransitionDecision.PROCEED, gate.beginRebind())
        gate.complete(SessionState.STOPPED)

        assertTrue(!gate.cancelRebind())
        assertEquals(SessionState.STOPPED, gate.current())
    }

    @Test
    fun cancelledQueuedRebindCanNeverStartLater() {
        val gate = RebindQueueGate()

        assertTrue(gate.cancel())
        assertTrue(!gate.begin())
        assertTrue(!gate.cancel())
    }

    @Test
    fun runningRebindCanNoLongerBeCancelledAsQueued() {
        val gate = RebindQueueGate()

        assertTrue(gate.begin())
        assertTrue(!gate.cancel())
        assertTrue(!gate.begin())
    }

    @Test
    fun backgroundOperationGateSerializesTheWholeOperation() {
        val gate = BackgroundOperationGate()

        assertTrue(gate.begin())
        assertTrue(!gate.begin())
        gate.complete()
        assertTrue(gate.begin())
    }

    @Test
    fun backgroundStartRetriesUnavailableSavedServerOnlyWhenAlternateIsAllowed() {
        assertTrue(
            shouldRetryBackgroundStart(
                "saved-lease",
                true,
                "saved_connection_unavailable",
            ),
        )
        assertTrue(
            shouldRetryBackgroundStart(
                "saved-lease",
                true,
                "saved_stray_unavailable",
            ),
        )
        assertTrue(
            !shouldRetryBackgroundStart(
                "saved-lease",
                false,
                "saved_connection_unavailable",
            ),
        )
        assertTrue(
            shouldRetryBackgroundStart(
                "saved-lease",
                false,
                "connection_no_longer_active",
            ),
        )
        assertTrue(
            shouldRetryBackgroundStart(
                "saved-lease",
                false,
                "operation_id_conflict",
            ),
        )
    }

    @Test
    fun legacyQuickPlanWithoutEgressModeIsRejectedInsteadOfAssumingIpv4() {
        val legacy = JSONObject().apply {
            put("leaseId", "lease-ipv6")
            put("layer", "tic")
            put("ticConnectionMode", "dynamic")
            put("routeMode", "via_tak")
            put("allowAlternate", true)
        }

        assertTrue(runCatching { legacy.toStoredQuickConnection() }.isFailure)
    }

    @Test
    fun backgroundStartPreservesTheSelectedEgressMode() {
        val connection = QuickConnectionArgs().apply {
            leaseId = "lease-ipv6"
            layer = "tic"
            ticConnectionMode = "dynamic"
            routeMode = "via_tak"
            egressMode = "prefer_ipv6"
            allowAlternate = true
        }
        val payload = backgroundStartPayload(
            QuickTunnelTemplate(TunnelOptionsArgs(), connection),
            "operation-ipv6",
        )

        assertEquals("prefer_ipv6", payload.getString("egress_mode"))
        assertEquals("operation-ipv6", payload.getString("operation_id"))
    }

    @Test
    fun backgroundRecoveryUsesTheInstallSecretExpectedByThePanel() {
        val payload = backgroundRecoveryPayload("install-secret")

        assertEquals("install-secret", payload.getString("install_secret"))
        assertEquals(1, payload.length())
    }

    @Test
    fun missingBackgroundRecoveryEndpointHasANonTransientCompatibilityCode() {
        assertEquals(
            "background_recovery_unsupported",
            backgroundPanelErrorCode("background/auth/recover", 404, null),
        )
        assertEquals(
            "background_panel_error",
            backgroundPanelErrorCode("background/connections/start", 404, null),
        )
    }
}
