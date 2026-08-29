package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject

class BackgroundConnectionClientTest {
    @Test
    fun typedCredentialRotationUsesExactOperationIdsAndInstallSecret() {
        val transport = RecordingBackgroundTransport(
            JSONObject().apply {
                put("token", "staged-token")
                put("staged_expires_at", "2026-08-29T12:00:00Z")
                put("token_generation", 2)
                put("prepare_operation_id", PREPARE_ID)
                put("activation_operation_id", ACTIVATE_ID)
            },
            JSONObject().apply {
                put("token_generation", 2)
                put("active_expires_at", "2026-09-29T12:00:00Z")
            },
        )
        val client = BackgroundOperationClient(transport)

        val prepared = client.prepareToken(credential(), PREPARE_ID, ACTIVATE_ID, INSTALL_SECRET)
        val activated = client.activateToken(credential(), prepared, INSTALL_SECRET)

        assertEquals("staged-token", prepared.token)
        assertEquals(2, activated.tokenGeneration)
        assertEquals(listOf("background/token/prepare", "background/token/activate"), transport.endpoints)
        assertEquals(PREPARE_ID, transport.payloads[0]?.getString("prepare_operation_id"))
        assertEquals(ACTIVATE_ID, transport.payloads[1]?.getString("activation_operation_id"))
        assertEquals(INSTALL_SECRET, transport.payloads[0]?.getString("install_secret"))
        assertEquals(INSTALL_SECRET, transport.payloads[1]?.getString("install_secret"))
    }

    @Test
    fun typedCapabilityAndCandidatesUseDeviceAuthenticatedGets() {
        val transport = RecordingBackgroundTransport(
            JSONObject().apply {
                put("revision", 7)
                put("expires_at", "2026-08-29T12:00:00Z")
                put("connection_intent_recovery_v1", true)
            },
            JSONObject().apply {
                put("candidates", JSONArray().put(JSONObject().apply {
                    put("candidate_id", "candidate-1")
                    put("layer", "tic")
                    put("region_label", "Moscow")
                    put("probe_url", "https://probe.example/health")
                    put("expires_at", "2026-08-29T12:00:00Z")
                }))
            },
        )
        val client = BackgroundOperationClient(transport)

        val capability = client.capabilities(credential())
        val candidates = client.serverCandidates(credential(), "tic", "prefer_ipv6")

        assertTrue(capability.enabled)
        assertEquals(7, capability.revision)
        assertEquals("candidate-1", candidates.single().candidateId)
        assertEquals(listOf("GET", "GET"), transport.methods)
        assertEquals(
            "background/server-candidates?layer=tic&egress_mode=prefer_ipv6",
            transport.endpoints[1],
        )
    }

    @Test
    fun reconcileAndLogoutFinalizePreserveImmutableSignature() {
        val transport = RecordingBackgroundTransport(
            JSONObject().apply {
                put("state", "applying")
                put("cancel_requested", true)
                put("retry_count", 3)
            },
            JSONObject().apply {
                put("code", "device_revoked_cleanup_accepted")
                put("cleanup_jobs", 2)
            },
        )
        val client = BackgroundOperationClient(transport)

        val reconciled = client.reconcile(
            credential(), OPERATION_ID, "start", 1, FINGERPRINT, cancelIfAbsent = true,
        )
        val finalized = client.finalizeLogout(
            credential(), DEVICE_ID, 4, LOGOUT_ID, INSTALL_SECRET,
        )

        assertEquals("applying", reconciled.state)
        assertTrue(reconciled.cancelRequested)
        assertEquals(2, finalized.cleanupJobs)
        assertEquals(FINGERPRINT, transport.payloads[0]?.getString("request_fingerprint"))
        assertEquals(4L, transport.payloads[1]?.getLong("install_generation"))
        assertEquals(LOGOUT_ID, transport.payloads[1]?.getString("operation_id"))
    }

    @Test
    fun prepareRejectsMismatchedEchoWithoutPublishingToken() {
        val client = BackgroundOperationClient(RecordingBackgroundTransport(
            JSONObject().apply {
                put("token", "staged-token")
                put("staged_expires_at", "2026-08-29T12:00:00Z")
                put("token_generation", 2)
                put("prepare_operation_id", OPERATION_ID)
                put("activation_operation_id", ACTIVATE_ID)
            },
        ))

        try {
            client.prepareToken(credential(), PREPARE_ID, ACTIVATE_ID, INSTALL_SECRET)
            fail("mismatched operation echo must fail")
        } catch (error: BackgroundConnectionException) {
            assertEquals("invalid_background_response", error.code)
        }
    }

    @Test
    fun backgroundStartFailureIsReportedBeforeLeaseCleanupRuns() {
        val events = mutableListOf<String>()
        var scheduledCleanup: (() -> Unit)? = null

        scheduleBackgroundStartFailure(
            scheduleCleanup = { task ->
                events += "cleanup_scheduled"
                scheduledCleanup = task
            },
            cleanupLease = { events += "lease_cleaned" },
            notifyFailure = { events += "failure_reported" },
            completeOperation = { events += "operation_completed" },
            onCleanupFailure = { fail("cleanup must not fail") },
        )

        assertEquals(listOf("failure_reported", "cleanup_scheduled"), events)
        assertNotNull(scheduledCleanup)

        scheduledCleanup?.invoke()

        assertEquals(
            listOf(
                "failure_reported",
                "cleanup_scheduled",
                "lease_cleaned",
                "operation_completed",
            ),
            events,
        )
    }

    @Test
    fun failedLeaseCleanupStillCompletesTheBackgroundOperation() {
        val events = mutableListOf<String>()

        scheduleBackgroundStartFailure(
            scheduleCleanup = { task -> task() },
            cleanupLease = {
                events += "cleanup_started"
                error("panel unavailable")
            },
            notifyFailure = { events += "failure_reported" },
            completeOperation = { events += "operation_completed" },
            onCleanupFailure = { events += "cleanup_failed" },
        )

        assertEquals(
            listOf(
                "failure_reported",
                "cleanup_started",
                "cleanup_failed",
                "operation_completed",
            ),
            events,
        )
    }

    @Test
    fun cleanupFailureLoggingCannotLeaveTheBackgroundOperationLocked() {
        val events = mutableListOf<String>()
        var scheduledCleanup: (() -> Unit)? = null

        scheduleBackgroundStartFailure(
            scheduleCleanup = { task -> scheduledCleanup = task },
            cleanupLease = { error("panel unavailable") },
            notifyFailure = { events += "failure_reported" },
            completeOperation = { events += "operation_completed" },
            onCleanupFailure = { error("logger unavailable") },
        )

        scheduledCleanup?.invoke()

        assertEquals(listOf("failure_reported", "operation_completed"), events)
    }

    @Test
    fun rejectedLeaseCleanupSchedulingStillCompletesTheBackgroundOperation() {
        val events = mutableListOf<String>()

        scheduleBackgroundStartFailure(
            scheduleCleanup = {
                events += "cleanup_rejected"
                error("executor unavailable")
            },
            cleanupLease = { fail("rejected cleanup must not run") },
            notifyFailure = { events += "failure_reported" },
            completeOperation = { events += "operation_completed" },
            onCleanupFailure = { events += "cleanup_failed" },
        )

        assertEquals(
            listOf(
                "failure_reported",
                "cleanup_rejected",
                "cleanup_failed",
                "operation_completed",
            ),
            events,
        )
    }

    @Test
    fun backgroundStartTreatsEveryNonRunningResultAsFailure() {
        assertNull(backgroundStartFailureCode(SessionState.RUNNING))
        assertEquals("connection_start_failed", backgroundStartFailureCode(SessionState.FAILED))
        assertEquals("connection_start_failed", backgroundStartFailureCode(SessionState.STOPPED))
    }

    @Test
    fun currentPanelPolicyReplacesCachedPackagesAndRoutes() {
        val fallback = TunnelOptionsArgs().apply {
            splitActive = true
            excludedPackages = arrayListOf("old.package")
            splitTunnelRoutes = arrayListOf("198.51.100.0/24")
            dnsServers = arrayListOf("9.9.9.9", "149.112.112.112")
        }
        val payload = JSONObject().apply {
            put("enabled", true)
            put("mode", "exclude_selected")
            put("exclude_local_networks", false)
            put("mandatory_excluded_packages", JSONArray(listOf("mandatory.package")))
            put("selected_packages", JSONArray(listOf("selected.package", "missing.package")))
            put("excluded_ipv4_cidrs", JSONArray(listOf("203.0.113.0/24")))
            put("address_rules", JSONArray().apply {
                put(JSONObject(mapOf("kind" to "ipv4", "value" to "192.0.2.10")))
                put(JSONObject(mapOf("kind" to "domain", "value" to "example.test")))
            })
        }

        val options = backgroundTunnelOptions(
            payload,
            setOf("mandatory.package", "selected.package"),
            fallback,
        ) { listOf("192.0.2.20/32") }

        assertTrue(options.splitActive)
        assertEquals(
            listOf("mandatory.package", "selected.package"),
            options.excludedPackages,
        )
        assertTrue(options.includedPackages.isEmpty())
        assertEquals(
            listOf("203.0.113.0/24", "192.0.2.10/32", "192.0.2.20/32"),
            options.splitTunnelRoutes,
        )
        assertFalse(options.excludeLocalNetworks)
        assertEquals(listOf("9.9.9.9", "149.112.112.112"), options.dnsServers)
    }

    @Test
    fun failedDomainRefreshKeepsLastKnownRoutes() {
        val fallback = TunnelOptionsArgs().apply {
            splitActive = true
            splitTunnelRoutes = arrayListOf("198.51.100.7/32")
        }
        val payload = JSONObject().apply {
            put("enabled", true)
            put("mode", "exclude_selected")
            put("mandatory_excluded_packages", JSONArray())
            put("selected_packages", JSONArray())
            put("excluded_ipv4_cidrs", JSONArray())
            put("address_rules", JSONArray().put(
                JSONObject(mapOf("kind" to "domain", "value" to "offline.test")),
            ))
        }

        val options = backgroundTunnelOptions(payload, emptySet(), fallback) {
            error("dns unavailable")
        }

        assertEquals(listOf("198.51.100.7/32"), options.splitTunnelRoutes)
    }

    @Test
    fun emptyIncludeSelectionNeverFallsBackToAFullTunnel() {
        val payload = JSONObject().apply {
            put("enabled", true)
            put("mode", "include_selected")
            put("mandatory_excluded_packages", JSONArray())
            put("selected_packages", JSONArray(listOf("missing.package")))
            put("excluded_ipv4_cidrs", JSONArray())
            put("address_rules", JSONArray())
        }

        try {
            backgroundTunnelOptions(payload, emptySet(), TunnelOptionsArgs()) { emptyList() }
            fail("empty include selection must be rejected")
        } catch (error: BackgroundConnectionException) {
            assertEquals("empty_include_selection", error.code)
        }
    }

    @Test
    fun packagePolicyUsesTheUniqueInstalledSpelling() {
        val payload = JSONObject().apply {
            put("enabled", true)
            put("mode", "include_selected")
            put("mandatory_excluded_packages", JSONArray())
            put("selected_packages", JSONArray(listOf("eu.livesport.flashscore_com")))
            put("excluded_ipv4_cidrs", JSONArray())
            put("address_rules", JSONArray())
        }

        val options = backgroundTunnelOptions(
            payload,
            setOf("eu.livesport.FlashScore_com"),
            TunnelOptionsArgs(),
        ) { emptyList() }

        assertEquals(listOf("eu.livesport.FlashScore_com"), options.includedPackages)
    }

    @Test
    fun packagePolicyDoesNotGuessAnAmbiguousCaseInsensitiveMatch() {
        val payload = JSONObject().apply {
            put("enabled", true)
            put("mode", "include_selected")
            put("mandatory_excluded_packages", JSONArray())
            put("selected_packages", JSONArray(listOf("com.example.FOO")))
            put("excluded_ipv4_cidrs", JSONArray())
            put("address_rules", JSONArray())
        }

        try {
            backgroundTunnelOptions(
                payload,
                setOf("com.example.Foo", "com.example.foo"),
                TunnelOptionsArgs(),
            ) { emptyList() }
            fail("ambiguous include selection must be rejected")
        } catch (error: BackgroundConnectionException) {
            assertEquals("empty_include_selection", error.code)
        }
    }

    @Test
    fun serviceRestoreRetriesOnlyTransientFailures() {
        assertTrue(shouldRetryServiceRestore("background_transport_unavailable"))
        assertTrue(shouldRetryServiceRestore("connection_unavailable"))
        assertFalse(shouldRetryServiceRestore("invalid_background_token"))
        assertFalse(shouldRetryServiceRestore("vpn_permission_required"))
    }

    private fun credential() = BackgroundCredential(
        DEVICE_ID,
        "https://nelomai.example",
        "device-token",
        1_900_000_000,
    )

    companion object {
        private const val DEVICE_ID = "11111111-1111-4111-8111-111111111111"
        private const val PREPARE_ID = "22222222-2222-4222-8222-222222222222"
        private const val ACTIVATE_ID = "33333333-3333-4333-8333-333333333333"
        private const val OPERATION_ID = "44444444-4444-4444-8444-444444444444"
        private const val LOGOUT_ID = "55555555-5555-4555-8555-555555555555"
        private const val INSTALL_SECRET =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        private const val FINGERPRINT =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
}

private class RecordingBackgroundTransport(
    vararg responses: JSONObject,
) : BackgroundApiTransport {
    private val queued = ArrayDeque(responses.toList())
    val methods = mutableListOf<String>()
    val endpoints = mutableListOf<String>()
    val payloads = mutableListOf<JSONObject?>()

    override fun execute(
        credential: BackgroundCredential,
        method: String,
        endpoint: String,
        payload: JSONObject?,
    ): JSONObject {
        methods += method
        endpoints += endpoint
        payloads += payload
        return queued.removeFirst()
    }
}
