package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BackgroundQuickV2Test {
    @Test fun failedPreflightRetriesWithoutSubmittingAnInvalidStart() {
        val selected = template(true)
        val failed = listOf(BackgroundProbeResult("candidate", null, "timeout", "2026-09-25T12:00:00Z"))
        val error = assertThrows(BackgroundConnectionException::class.java) {
            backgroundExactStartPayload(selected, pending(selected), failed)
        }
        assertEquals("server_probes_unavailable", error.code)
        assertEquals(ConnectionIntentDecision.RETRY_SAME_OPERATION, ConnectionIntentErrorPolicy().classify(error.code))
        assertEquals(ConnectionIntentDecision.TERMINAL, ConnectionIntentErrorPolicy().classify("invalid_probe_results"))
        val healthy = failed + BackgroundProbeResult("healthy", 12.0, null, "2026-09-25T12:00:00Z")
        assertEquals(2, backgroundExactStartPayload(selected, pending(selected), healthy).getJSONArray("probes").length())
    }

    @Test
    fun foregroundStrayReplayRetainsMeasuredSignatureEvenWithoutAlternatePreference() {
        val selected = template(true)
        val transaction = requireNotNull(
            backgroundExactStartResult(payload(), selected, pending(selected)).redundantTransaction,
        ).copy(template = selected.copy(allowAlternate = false, reserveEnabled = null))
        val quick = QuickTunnelTemplate(TunnelOptionsArgs(), QuickConnectionArgs().apply {
            layer = "stray"; ticConnectionMode = "dynamic"; routeMode = "standalone"
            egressMode = "ipv4"; allowAlternate = false
        })
        assertTrue(backgroundRedundantStartPayload(quick, transaction)
            .getBoolean("require_measured_selection"))
    }

    @Test
    fun fingerprintsMatchPanelCanonicalContractForBothReserveChoices() {
        assertEquals("a476f93c67f4f7c4c0c8a5a6fa316b871ab11e653c5ec63d64d7d61543daf281",
            androidConnectionIntentFingerprint(template(false), true, false))
        assertEquals("03bf9fabd0f53c63b5ae673eeb6d8230126aa89ec3cc998ea419d74c1cf0c2d3",
            androidConnectionIntentFingerprint(template(true), true, true))
    }

    @Test
    fun personalTicViaTakRecoveryRetainsNonMeasuredV2Signature() {
        val template = template(true).copy(layer = "tic", ticConnectionMode = "personal",
            routeMode = "via_tak", allowAlternate = false)
        val response = payload().apply {
            getJSONObject("connection").apply {
                put("layer", "tic"); put("tic_connection_mode", "personal"); put("route_mode", "via_tak")
            }
        }
        val transaction = requireNotNull(
            backgroundExactStartResult(response, template, pending(template)).redundantTransaction,
        )
        val quick = QuickTunnelTemplate(TunnelOptionsArgs(), QuickConnectionArgs().apply {
            layer = "tic"; ticConnectionMode = "personal"; routeMode = "via_tak"
            egressMode = "ipv4"; allowAlternate = false
        })
        assertFalse(backgroundRedundantStartPayload(quick, transaction)
            .getBoolean("require_measured_selection"))
    }

    @Test
    fun freshRequestCarriesReserveChoiceAndExactDurableSignature() {
        for (reserve in listOf(false, true)) {
            val template = template(reserve)
            val transaction = pending(template)
            val request = backgroundExactStartPayload(template, transaction, emptyList())
            assertEquals(2, request.getInt("recovery_contract_version"))
            assertEquals(1, request.getInt("redundancy_contract_version"))
            assertEquals(reserve, request.getBoolean("reserve_enabled"))
            assertEquals(transaction.startOperationId, request.getString("operation_id"))
            assertEquals(transaction.replay.requestFingerprint, request.getString("request_fingerprint"))
            assertTrue(request.getBoolean("require_measured_selection"))
            assertFalse(request.has("lease_id"))
        }
    }

    @Test
    fun firstResponseKeepsConfigurationsInMemoryForImmediateStart() {
        val template = template(true).copy(quickPlanRevision = "local-plan-1")
        val result = backgroundExactStartResult(payload(), template, pending(template))
        assertEquals("local-plan-1", result.quickPlanRevision)
        val transaction = requireNotNull(result.redundantTransaction)
        assertEquals(PRIMARY, transaction.slotALeaseId)
        assertEquals(STANDBY, transaction.slotBLeaseId)
        assertEquals(PRIMARY, transaction.localActiveLeaseId)
        assertEquals(SESSION, transaction.sessionId)
        assertEquals(template, transaction.template)
        assertTrue(transaction.startReserveEnabled)
        assertTrue(result.configuration.isEmpty())
        val transport = requireNotNull(result.redundantTransport)
        assertEquals("primary-secret", String(requireNotNull(transport.configurations[PRIMARY])))
        assertEquals("standby-secret", String(requireNotNull(transport.configurations[STANDBY])))
        val durable = String(AndroidRecoveryEnvelopeCodec.encode(AndroidRecoveryEnvelope.empty(1).copy(
            redundantTransaction = transaction,
        )))
        assertFalse(durable.contains("primary-secret"))
        assertFalse(durable.contains("standby-secret"))
    }

    @Test
    fun disabledV2StillUsesSessionOwnershipWithoutStandby() {
        val payload = payload()
        payload.remove("health_probe")
        payload.getJSONObject("redundancy").apply {
            put("state", "disabled")
            put("standby_desired", false)
            remove("standby")
        }
        val template = template(false)
        val result = backgroundExactStartResult(payload, template, pending(template))
        assertFalse(requireNotNull(result.redundantTransaction).startReserveEnabled)
        assertNull(result.redundantTransaction?.slotBLeaseId)
    }

    @Test
    fun malformedV2MustNeverDowngradeToSingleLease() {
        val mutations: List<(JSONObject) -> Unit> = listOf(
            { it.remove("redundancy") },
            { it.getJSONObject("redundancy").put("session_id", "not-uuid") },
            { it.getJSONObject("redundancy").put("virtual_address_v4", "bad/32") },
            { it.getJSONObject("redundancy").put("role_generation", -1) },
            { it.getJSONObject("redundancy").getJSONObject("standby")
                .getJSONObject("connection").put("lease_id", PRIMARY) },
            { it.remove("health_probe") },
        )
        for (mutate in mutations) {
            val payload = payload().also(mutate)
            try {
                backgroundExactStartResult(payload, template(true), pending(template(true)))
                fail("malformed v2 accepted")
            } catch (error: BackgroundConnectionException) {
                assertEquals("invalid_background_response", error.code)
            }
        }
    }

    private fun template(reserve: Boolean) = AndroidIntentTemplate(
        deviceId = "40000000-0000-4000-8000-000000000001",
        accountScope = "account", layer = "stray", ticConnectionMode = "dynamic",
        routeMode = "standalone", egressMode = "ipv4", allowAlternate = true,
        reserveEnabled = reserve,
    )

    private fun pending(template: AndroidIntentTemplate) = AndroidLeaseTransaction(
        generation = 1, bootCount = 7, phase = LeasePhase.START_PENDING,
        leaseId = null, stopOperationId = null,
        replay = AndroidStartReplay("30000000-0000-4000-8000-000000000001", 2,
            androidConnectionIntentFingerprint(template, true, template.reserveEnabled)),
    )

    private fun connection(lease: String) = JSONObject().apply {
        put("lease_id", lease); put("layer", "stray"); put("tic_connection_mode", "dynamic")
        put("route_mode", "standalone"); put("egress_mode", "ipv4")
    }

    private fun probe() = JSONObject().apply {
        put("kind", "dns_a"); put("target_ipv4", "9.9.9.9")
        put("query_name", "nelomai.ru"); put("timeout_ms", 4000)
    }

    private fun payload() = JSONObject().apply {
        put("connection", connection(PRIMARY))
        put("configuration", "primary-secret")
        put("health_probe", probe())
        put("redundancy", JSONObject().apply {
            put("session_id", SESSION); put("state", "ready")
            put("virtual_address_v4", "10.241.0.2/32")
            put("standby_desired", true); put("role_generation", 1); put("membership_generation", 1)
            put("standby", JSONObject().apply {
                put("connection", connection(STANDBY)); put("configuration", "standby-secret")
                put("health_probe", probe())
            })
        })
    }

    companion object {
        const val PRIMARY = "10000000-0000-4000-8000-000000000001"
        const val STANDBY = "10000000-0000-4000-8000-000000000002"
        const val SESSION = "20000000-0000-4000-8000-000000000001"
    }
}
