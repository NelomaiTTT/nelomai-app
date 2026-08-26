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
}
