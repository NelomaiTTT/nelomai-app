package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject

class BackgroundConnectionClientTest {
    @Test
    fun currentPanelPolicyReplacesCachedPackagesAndRoutes() {
        val fallback = TunnelOptionsArgs().apply {
            splitActive = true
            excludedPackages = arrayListOf("old.package")
            splitTunnelRoutes = arrayListOf("198.51.100.0/24")
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
    fun serviceRestoreRetriesOnlyTransientFailures() {
        assertTrue(shouldRetryServiceRestore("background_transport_unavailable"))
        assertTrue(shouldRetryServiceRestore("connection_unavailable"))
        assertFalse(shouldRetryServiceRestore("invalid_background_token"))
        assertFalse(shouldRetryServiceRestore("vpn_permission_required"))
    }
}
