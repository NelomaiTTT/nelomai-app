package ru.nelomai.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class AutomaticDiagnosticsTest {
    @Test
    fun `redundant recovery and replacement counters use explicit events`() {
        val accumulator = RedundantDiagnosticsAccumulator()

        accumulator.observeState("warming")
        accumulator.observeState("ready")
        accumulator.observeState("unavailable")
        val transitionsOnly = accumulator.observeState("ready")
        assertEquals(4L, transitionsOnly.stateTransitionCount)
        assertEquals(0L, transitionsOnly.recoveryCount)
        assertEquals(0L, transitionsOnly.replacementCount)

        accumulator.observeEvent(RedundantDiagnosticEvent.FAILOVER)
        accumulator.observeEvent(RedundantDiagnosticEvent.RECOVERY)
        val explicit = accumulator.observeEvent(RedundantDiagnosticEvent.REPLACEMENT)
        assertEquals(1L, explicit.failoverCount)
        assertEquals(1L, explicit.recoveryCount)
        assertEquals(1L, explicit.replacementCount)
    }

    @Test
    fun `redundant diagnostics contain bounded counters but never configs keys or probe payload`() {
        val report = automaticDiagnosticsRedundantSnapshot(
            state = "ready",
            nativeMetrics = """{
                "dispatcher":{"outbound_packets":7,"dropped_inactive_packets":2},
                "slots":[
                    {"slot":0,"admitted":true,"latest_handshake_at_unix_ms":1234,
                     "configuration":"PrivateKey = secret",
                     "health-query-payload":"secret-probe",
                     "telemetry":{"tun_read_packets":4,"tun_read_bytes":512,
                       "udp_send_packets":4,"udp_receive_packets":3,
                       "go_heap_alloc_bytes":1048576,"go_goroutines":8,
                       "last_udp_send_error":"secret endpoint"}}
                ]
            }""",
            transitionCount = 3,
            failoverCount = 1,
            recoveryCount = 2,
            replacementCount = 1,
        ).toString()

        assertTrue(report.contains("backend_device_count"))
        assertTrue(report.contains("tun_read_packets"))
        assertTrue(report.contains("go_heap_alloc_bytes"))
        assertTrue(report.contains("go_goroutines"))
        assertFalse(report.contains("PrivateKey"))
        assertFalse(report.contains("health-query-payload"))
        assertFalse(report.contains("secret"))
        assertFalse(report.contains("last_udp_send_error"))
    }
    @Test
    fun connectionIntentDiagnosticsReportsAndNotifiesOncePerEpisode() {
        val episode = AutomaticDiagnosticsConnectionIntentEpisode()

        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(),
            episode.observeRetry(299),
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(
                queueReport = true,
                notifyUser = true,
            ),
            episode.observeRetry(300),
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(),
            episode.observeRetry(300),
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(),
            episode.observeTerminal(),
        )

        episode.reset()
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(queueReport = true),
            episode.observeTerminal(),
        )

        episode.reset()
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(
                queueReport = true,
                notifyUser = true,
            ),
            episode.observeRetry(300),
        )
    }

    @Test
    fun terminalObservationRetriesAnUndurableReportWithoutDuplicatingTheTerminalEvent() {
        val firstProcess = AutomaticDiagnosticsConnectionIntentEpisode()

        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(queueReport = true),
            firstProcess.observeTerminal(),
        )
        val restoredProcess = AutomaticDiagnosticsConnectionIntentEpisode(
            reportQueued = false,
            notificationSent = false,
            terminalObserved = true,
        )

        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(queueReport = true),
            restoredProcess.observeTerminal(),
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(),
            restoredProcess.observeRetry(300),
        )
        val afterDurableQueue = AutomaticDiagnosticsConnectionIntentEpisode(
            reportQueued = true,
            notificationSent = false,
            terminalObserved = true,
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentActions(),
            afterDurableQueue.observeTerminal(),
        )
    }

    @Test
    fun connectionIntentPayloadUsesStableReasonClassesWithoutSensitiveInput() {
        val event = automaticDiagnosticsConnectionIntentEvent(
            kind = "retry_scheduled",
            errorCode = "full_error_message private_key=https://private.example",
            attempt = 7,
            delaySeconds = 300,
        )
        val encoded = event.toString()

        assertEquals("connection.intent.retry_scheduled", event.getString("event"))
        assertEquals("other", event.getString("reason_class"))
        assertEquals(7, event.getInt("attempt"))
        assertEquals(300L, event.getLong("delay_seconds"))
        listOf(
            "private_key",
            "session_token",
            "wireguard_config",
            "full_error_message",
            "https://private.example",
        ).forEach { forbidden ->
            assertTrue("leaked $forbidden", !encoded.contains(forbidden))
        }
        assertEquals(
            "network",
            automaticDiagnosticsConnectionIntentReasonClass("transport_error"),
        )
    }

    @Test
    fun connectionIntentReportLogDropsUnstructuredAndSensitiveFields() {
        val safe = automaticDiagnosticsSafeConnectionIntentLog(
            """
            {"timestamp":"2026-08-30T10:00:00Z","event":"connection.intent.retry_scheduled","reason_class":"network","attempt":6,"delay_seconds":300,"message":"private_key=secret"}
            {"timestamp":"2026-08-30T10:00:01Z","event":"unrelated.event","message":"session_token=secret"}
            {"timestamp":"2026-08-30T10:00:02Z","event":"connection.intent.terminal_failure","reason_class":"raw backend failure https://private.example"}
            """.trimIndent(),
        )

        assertTrue(safe.contains("connection.intent.retry_scheduled"))
        assertTrue(safe.contains("connection.intent.terminal_failure"))
        assertTrue(safe.contains("\"reason_class\":\"network\""))
        assertTrue(safe.contains("\"reason_class\":\"other\""))
        listOf("private_key", "session_token", "secret", "https://private.example").forEach {
            assertTrue("leaked $it", !safe.contains(it))
        }
    }

    @Test
    fun procStatusMemoryParserReadsCurrentAndPeakRssSafely() {
        val status = """
            Name: nelomai
            VmHWM: 456789 kB
            VmRSS: 345678 kB
        """.trimIndent()

        assertEquals(
            345678L * 1024L,
            automaticDiagnosticsStatusMemoryBytes(status, "VmRSS"),
        )
        assertEquals(
            456789L * 1024L,
            automaticDiagnosticsStatusMemoryBytes(status, "VmHWM"),
        )
        assertNull(automaticDiagnosticsStatusMemoryBytes(status, "VmPeak"))
    }

    @Test
    fun startFailureRequestRoundTripsItsDurableIdentityAndState() {
        val memorySamplesJson = JSONArray().put(
            JSONObject()
                .put("timestamp_unix", 999L)
                .put("reason", "tunnel_start_memory_mappings_failure"),
        ).toString()
        val request = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "panel",
            queuedAt = 1_000,
            sent = false,
            memorySamplesJson = memorySamplesJson,
            trigger = "connection_intent_slow_recovery",
            diagnosticsEpisodeId = 17L,
        )

        val restored = StartFailureRequest.fromJson(request.toJson())

        assertEquals(request, restored)
        assertEquals(
            automaticDiagnosticsPendingReportName(
                1_000,
                request.deviceId,
                request.reportId,
            ),
            restored.reportName,
        )
        assertTrue(StartFailureRequest.fromJson(request.copy(sent = true).toJson()).sent)
        assertEquals(memorySamplesJson, restored.memorySamplesJson)
        assertEquals("connection_intent_slow_recovery", restored.trigger)
        assertEquals(17L, restored.diagnosticsEpisodeId)
    }

    @Test
    fun legacyStartFailureMarkerWithoutEpisodeIdentityRemainsReadable() {
        val encoded = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "panel",
            queuedAt = 1_000,
            sent = false,
        ).toJson()
        val legacy = JSONObject(encoded).apply {
            remove("diagnostics_episode_id")
        }

        assertNull(StartFailureRequest.fromJson(legacy.toString()).diagnosticsEpisodeId)
    }

    @Test
    fun connectionIntentQueuePolicyBindsDurableOwnershipToTheEpisodeNotTheTrigger() {
        val slowMarker = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "network",
            queuedAt = 1_000,
            sent = false,
            trigger = "connection_intent_slow_recovery",
            diagnosticsEpisodeId = 17L,
        )

        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.ALREADY_DURABLE_THIS_EPISODE,
            automaticDiagnosticsConnectionIntentQueuePolicy(
                existing = slowMarker,
                diagnosticsEpisodeId = 17L,
                now = 1_001,
                cooldownSeconds = 900,
            ),
        )
        assertTrue(
            AutomaticDiagnosticsConnectionIntentReportOutcome
                .ALREADY_DURABLE_THIS_EPISODE.ownsEpisodeReport,
        )
    }

    @Test
    fun unrelatedOrLegacyPendingMarkerSuppressesWithoutClaimingEpisodeOwnership() {
        val unrelated = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "network",
            queuedAt = 1_000,
            sent = false,
            diagnosticsEpisodeId = 16L,
        )
        val unrelatedOutcome = automaticDiagnosticsConnectionIntentQueuePolicy(
            existing = unrelated,
            diagnosticsEpisodeId = 17L,
            now = 1_001,
            cooldownSeconds = 900,
        )
        val legacyOutcome = automaticDiagnosticsConnectionIntentQueuePolicy(
            existing = unrelated.copy(diagnosticsEpisodeId = null),
            diagnosticsEpisodeId = 17L,
            now = 1_001,
            cooldownSeconds = 900,
        )

        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.SUPPRESSED_BY_POLICY,
            unrelatedOutcome,
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.SUPPRESSED_BY_POLICY,
            legacyOutcome,
        )
        assertFalse(unrelatedOutcome.ownsEpisodeReport)
        assertTrue(unrelatedOutcome.allowsTerminalHandoff)
    }

    @Test
    fun cooldownSuppressionFinishesHandoffWhileExpiredOtherEpisodeQueuesFreshReport() {
        val uploadedOtherEpisode = StartFailureRequest(
            reportId = "33333333-3333-4333-8333-333333333333",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "network",
            queuedAt = 1_000,
            sent = true,
            diagnosticsEpisodeId = 16L,
        )

        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.SUPPRESSED_BY_POLICY,
            automaticDiagnosticsConnectionIntentQueuePolicy(
                existing = uploadedOtherEpisode,
                diagnosticsEpisodeId = 17L,
                now = 1_899,
                cooldownSeconds = 900,
            ),
        )
        assertEquals(
            AutomaticDiagnosticsConnectionIntentReportOutcome.QUEUED_THIS_EPISODE,
            automaticDiagnosticsConnectionIntentQueuePolicy(
                existing = uploadedOtherEpisode,
                diagnosticsEpisodeId = 17L,
                now = 1_900,
                cooldownSeconds = 900,
            ),
        )
    }

    @Test
    fun retryScheduleCapsAtSixHours() {
        assertEquals(5 * 60L, automaticDiagnosticsRetryDelaySeconds(0))
        assertEquals(30 * 60L, automaticDiagnosticsRetryDelaySeconds(1))
        assertEquals(2 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(2))
        assertEquals(6 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(3))
        assertEquals(6 * 60 * 60L, automaticDiagnosticsRetryDelaySeconds(20))
    }

    @Test
    fun startFailureReportIsDeduplicatedWhilePendingAndRateLimitedAfterUpload() {
        assertTrue(
            automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = false,
                lastQueuedAt = 0,
                now = 1_000,
                cooldownSeconds = 900,
            ),
        )
        assertTrue(
            !automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = true,
                lastQueuedAt = 100,
                now = 2_000,
                cooldownSeconds = 900,
            ),
        )
        assertTrue(
            !automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = false,
                lastQueuedAt = 1_000,
                now = 1_899,
                cooldownSeconds = 900,
            ),
        )
        assertTrue(
            automaticDiagnosticsShouldQueueStartFailure(
                pendingExists = false,
                lastQueuedAt = 1_000,
                now = 1_900,
                cooldownSeconds = 900,
            ),
        )
    }

    @Test
    fun startFailureReportsAndPendingWorkAreScopedToTheDevice() {
        val firstDevice = "11111111-1111-4111-8111-111111111111"
        val secondDevice = "22222222-2222-4222-8222-222222222222"
        val reportName = automaticDiagnosticsPendingReportName(
            1_000,
            firstDevice,
            "33333333-3333-4333-8333-333333333333",
        )

        assertEquals(firstDevice, automaticDiagnosticsPendingReportScope(reportName))
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                emptyList(),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = firstDevice,
                pendingStartFailure = true,
            ),
        )
        assertTrue(
            !automaticDiagnosticsHasPendingWork(
                listOf(reportName),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = secondDevice,
                pendingStartFailure = false,
            ),
        )
    }

    @Test
    fun retentionPrunesOnlySentReportsOlderThanTheLatestThree() {
        val sent = listOf("0001.json.gz", "0002.json.gz", "0003.json.gz", "0004.json.gz")
        val pending = setOf("pending-0001.json.gz", "pending-0002.json.gz")

        val deleted = automaticDiagnosticsSentReportsToPrune(sent)

        assertEquals(setOf("0001.json.gz"), deleted)
        assertTrue(deleted.intersect(pending).isEmpty())
    }

    @Test
    fun reportLogContainsOnlyTheCurrentTunnelInterval() {
        val logs = """
            {"timestamp_unix":99,"kind":"before"}
            {"timestamp_unix":100,"kind":"start"}
            {"timestamp":"1970-01-01T00:02:30Z","event":"middle"}
            {"timestamp_unix":201,"kind":"after"}
        """.trimIndent()

        val filtered = automaticDiagnosticsFilterIntervalLog(logs, 100, 200)

        assertTrue(filtered.contains("start"))
        assertTrue(filtered.contains("middle"))
        assertTrue(!filtered.contains("before"))
        assertTrue(!filtered.contains("after"))
    }

    @Test
    fun startupStagesAreKeptAlongsideTheTunnelInterval() {
        val combined = automaticDiagnosticsCombineApplicationLogs(
            "{\"kind\":\"connection.started\"}\n",
            "{\"kind\":\"startup.android.activity_created\"}\n",
            1024,
        )

        assertTrue(combined.contains("connection.started"))
        assertTrue(combined.contains("startup.android.activity_created"))
    }

    @Test
    fun failedOldestReportDoesNotBlockNewerReports() {
        val reports = listOf("0001.json.gz", "0002.json.gz", "0003.json.gz")

        assertEquals("0001.json.gz", automaticDiagnosticsNextPendingReport(reports, null))
        assertEquals("0002.json.gz", automaticDiagnosticsNextPendingReport(reports, "0001.json.gz"))
        assertEquals("0003.json.gz", automaticDiagnosticsNextPendingReport(reports, "0002.json.gz"))
        assertEquals("0001.json.gz", automaticDiagnosticsNextPendingReport(reports, "0003.json.gz"))
        assertNull(automaticDiagnosticsNextPendingReport(emptyList(), "0001.json.gz"))
    }

    @Test
    fun stoppedSessionRemainsPendingWithoutAQueuedReport() {
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                emptyList(),
                stoppedSessionPending = true,
                pendingSeal = false,
                deviceId = null,
            ),
        )
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                emptyList(),
                stoppedSessionPending = false,
                pendingSeal = true,
                deviceId = null,
            ),
        )
    }

    @Test
    fun pendingReportsAreScopedToTheDeviceThatCreatedThem() {
        val firstDevice = "11111111-1111-4111-8111-111111111111"
        val secondDevice = "22222222-2222-4222-8222-222222222222"
        val report = automaticDiagnosticsPendingReportName(
            100,
            firstDevice,
            "33333333-3333-4333-8333-333333333333",
        )
        val unscoped = automaticDiagnosticsPendingReportName(
            101,
            null,
            "44444444-4444-4444-8444-444444444444",
        )

        assertEquals(firstDevice, automaticDiagnosticsPendingReportScope(report))
        assertNull(automaticDiagnosticsPendingReportScope(unscoped))
        assertTrue(
            automaticDiagnosticsHasPendingWork(
                listOf(report, unscoped),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = firstDevice,
            ),
        )
        assertTrue(
            !automaticDiagnosticsHasPendingWork(
                listOf(report, unscoped),
                stoppedSessionPending = false,
                pendingSeal = false,
                deviceId = secondDevice,
            ),
        )
    }

    @Test
    fun legacyProcessNameUsesProcCommandLineWithoutInventingVpnSuffix() {
        val packageName = "ru.nelomai.app"

        assertEquals(
            "$packageName:vpn",
            automaticDiagnosticsLegacyProcessName("$packageName:vpn\u0000ignored", packageName),
        )
        assertEquals(
            packageName,
            automaticDiagnosticsLegacyProcessName("$packageName\u0000ignored", packageName),
        )
        assertEquals(packageName, automaticDiagnosticsLegacyProcessName(null, packageName))
        assertEquals(
            packageName,
            automaticDiagnosticsLegacyProcessName("another.application", packageName),
        )
    }

    @Test
    fun tunnelStartMemoryDetailGateCapturesOneLargeGrowthOrAbsolutePeak() {
        val mebibyte = 1024L * 1024L
        val growing = TunnelStartMemoryDetailGate(0)

        assertTrue(!growing.shouldCapture(255L * mebibyte))
        assertTrue(growing.shouldCapture(256L * mebibyte))
        assertTrue(!growing.shouldCapture(700L * mebibyte))

        val alreadyLarge = TunnelStartMemoryDetailGate(null)
        assertTrue(!alreadyLarge.shouldCapture(299L * mebibyte))
        assertTrue(alreadyLarge.shouldCapture(300L * mebibyte))
        assertTrue(!alreadyLarge.shouldCapture(700L * mebibyte))
        assertTrue(alreadyLarge.hasCaptured())
    }

    @Test
    fun sessionMemoryDetailGateCapturesOneGrowthSeriesUntilReset() {
        val mebibyte = 1024L * 1024L
        val gate = AutomaticDiagnosticsSessionMemoryDetailGate(64L * mebibyte)

        gate.reset(100L * mebibyte)
        assertTrue(!gate.shouldCapture(150L * mebibyte))
        assertTrue(gate.shouldCapture(164L * mebibyte))
        assertTrue(!gate.shouldCapture(300L * mebibyte))

        gate.reset(300L * mebibyte)
        assertTrue(!gate.shouldCapture(350L * mebibyte))
        assertTrue(gate.shouldCapture(364L * mebibyte))
    }

    @Test
    fun tunnelStartMemoryDelayedStagesCoverTransientReleaseWindow() {
        assertEquals(
            listOf(
                "after_backend_100ms" to 100L,
                "after_backend_1s" to 1_000L,
                "after_backend_5s" to 5_000L,
            ),
            tunnelStartMemoryDelayedStages(),
        )
    }

    @Test
    fun memoryPressureConfirmationIsPromptWithoutBlockingTunnelStartup() {
        assertEquals(
            listOf(
                AutomaticDiagnosticsMemoryCaptureRequest(
                    sample = "initial",
                    delayMillis = 0L,
                    mode = AutomaticDiagnosticsMemoryCaptureMode.ROLLUP,
                ),
                AutomaticDiagnosticsMemoryCaptureRequest(
                    sample = "confirmation",
                    delayMillis = 500L,
                    mode = AutomaticDiagnosticsMemoryCaptureMode.ROLLUP,
                ),
                AutomaticDiagnosticsMemoryCaptureRequest(
                    sample = "settled",
                    delayMillis = 5_000L,
                    mode = AutomaticDiagnosticsMemoryCaptureMode.ROLLUP,
                ),
            ),
            tunnelStartMemoryMappingSamples(),
        )
    }

    @Test
    fun automaticMemoryPressureSeriesDoesNotReadFullSmaps() {
        var rollupReads = 0
        var mappingReads = 0
        val expectedRollup = AutomaticDiagnosticsSmapsRollup(
            residentBytes = 800L,
            proportionalBytes = 700L,
            privateCleanBytes = 20L,
            privateDirtyBytes = 500L,
            sharedCleanBytes = 100L,
            sharedDirtyBytes = 10L,
            swapBytes = 30L,
            swapProportionalBytes = 15L,
        )

        tunnelStartMemoryMappingSamples().forEach { request ->
            val capture = automaticDiagnosticsCaptureSmaps(
                mode = request.mode,
                readRollup = {
                    rollupReads += 1
                    expectedRollup
                },
                readMappings = {
                    mappingReads += 1
                    AutomaticDiagnosticsSmapsSummary(0, 0, emptyList(), emptyList())
                },
            )

            assertEquals(expectedRollup, capture.rollup)
            assertNull(capture.mappings)
            assertTrue(!capture.mappingsRequested)
        }

        assertEquals(3, rollupReads)
        assertEquals(0, mappingReads)
    }

    @Test
    fun delayedMemoryCaptureFromAnOldAttemptCannotEnterTheNextReport() {
        val generations = AutomaticDiagnosticsMemoryCaptureGeneration()
        val first = generations.begin()

        assertTrue(generations.isCurrent(first))

        val second = generations.begin()

        assertTrue(!generations.isCurrent(first))
        assertTrue(generations.isCurrent(second))

        generations.invalidate()

        assertTrue(!generations.isCurrent(second))
    }

    @Test
    fun smapsParserAggregatesSegmentsAndKeepsOnlyPrivacySafeMappingNames() {
        val smaps = """
            1000-2000 r--p 00000000 00:00 0 /data/app/secret/base.apk
            Rss:                  24 kB
            Pss:                  20 kB
            Private_Dirty:         4 kB
            2000-3000 r-xp 00000000 00:00 0 /data/app/secret/lib/arm64/libwg-go.so
            Rss:                  40 kB
            Pss:                  30 kB
            Private_Dirty:         0 kB
            3000-4000 rw-p 00000000 00:00 0 /data/app/secret/lib/arm64/libwg-go.so
            Rss:                  20 kB
            Pss:                  15 kB
            Private_Dirty:         5 kB
            4000-5000 rw-p 00000000 00:00 0
            Rss:                  70 kB
            Pss:                  60 kB
            Private_Dirty:        60 kB
            5000-6000 r--p 00000000 00:00 0 /data/user/0/private/account-name.txt
            Rss:                  55 kB
            Pss:                  50 kB
            Private_Dirty:         0 kB
        """.trimIndent()

        val mappings = automaticDiagnosticsParseSmaps(smaps.lineSequence(), maximum = 4)

        assertEquals(
            listOf("[anonymous]", "[file]", "libwg-go.so", "base.apk"),
            mappings.map { it.name },
        )
        assertEquals(60L * 1024L, mappings[0].proportionalBytes)
        assertEquals(45L * 1024L, mappings[2].proportionalBytes)
        assertEquals(60L * 1024L, mappings[2].residentBytes)
        assertEquals(5L * 1024L, mappings[2].privateDirtyBytes)
        assertTrue(mappings[2].executable)
        assertTrue(mappings.none { it.name.contains("account-name") })
        assertTrue(mappings.none { it.name.contains("/data/") })
    }

    @Test
    fun smapsParserBoundsOutputAndUsesResidentBytesAsStableTieBreaker() {
        val smaps = """
            1000-2000 r--p 00000000 00:00 0 /one/libfirst.so
            Rss:                  30 kB
            Pss:                  10 kB
            2000-3000 r--p 00000000 00:00 0 /two/libsecond.so
            Rss:                  40 kB
            Pss:                  10 kB
            3000-4000 r--p 00000000 00:00 0 /three/libthird.so
            Rss:                  50 kB
            Pss:                   5 kB
        """.trimIndent()

        val mappings = automaticDiagnosticsParseSmaps(smaps.lineSequence(), maximum = 2)

        assertEquals(listOf("libsecond.so", "libfirst.so"), mappings.map { it.name })
    }

    @Test
    fun smapsRollupParserKeepsComparableKernelCounters() {
        val rollup = """
            1000-9000 ---p 00000000 00:00 0 [rollup]
            Rss:                 800 kB
            Pss:                 700 kB
            Private_Clean:        20 kB
            Private_Dirty:       500 kB
            Shared_Clean:        100 kB
            Shared_Dirty:         10 kB
            Swap:                 30 kB
            SwapPss:              15 kB
        """.trimIndent()

        val metrics = automaticDiagnosticsParseSmapsRollup(rollup.lineSequence())

        assertEquals(800L * 1024L, metrics.residentBytes)
        assertEquals(700L * 1024L, metrics.proportionalBytes)
        assertEquals(20L * 1024L, metrics.privateCleanBytes)
        assertEquals(500L * 1024L, metrics.privateDirtyBytes)
        assertEquals(100L * 1024L, metrics.sharedCleanBytes)
        assertEquals(10L * 1024L, metrics.sharedDirtyBytes)
        assertEquals(30L * 1024L, metrics.swapBytes)
        assertEquals(15L * 1024L, metrics.swapProportionalBytes)
    }

    @Test
    fun detailedMemoryComponentPrefersSmapsRollupOverCachedActivityManager() {
        val component = automaticDiagnosticsDetailedMemoryComponent(
            processId = 42,
            liveResidentBytes = 200L,
            peakResidentBytes = 900L,
            activityManagerPssBytes = 800L,
            activityManagerCodePssBytes = 700L,
            rollup = AutomaticDiagnosticsSmapsRollup(
                residentBytes = 120L,
                proportionalBytes = 100L,
                privateCleanBytes = 10L,
                privateDirtyBytes = 60L,
                sharedCleanBytes = 40L,
                sharedDirtyBytes = 10L,
                swapBytes = 5L,
                swapProportionalBytes = 2L,
            ),
        )

        assertEquals("android_smaps", component.getString("source"))
        assertEquals(120L, component.getLong("current_resident_memory_bytes"))
        assertEquals(100L, component.getLong("current_proportional_memory_bytes"))
        assertEquals(900L, component.getLong("peak_resident_memory_bytes"))
        assertTrue(!component.has("pss_code_bytes"))
    }

    @Test
    fun detailedMemoryComponentFallsBackWhenSmapsRollupIsUnavailable() {
        val component = automaticDiagnosticsDetailedMemoryComponent(
            processId = 42,
            liveResidentBytes = 200L,
            peakResidentBytes = 900L,
            activityManagerPssBytes = 180L,
            activityManagerCodePssBytes = 70L,
            rollup = null,
        )

        assertEquals("android_activity_manager_memory_info", component.getString("source"))
        assertEquals(200L, component.getLong("current_resident_memory_bytes"))
        assertEquals(180L, component.getLong("current_proportional_memory_bytes"))
        assertEquals(70L, component.getLong("pss_code_bytes"))
        assertEquals(900L, component.getLong("peak_resident_memory_bytes"))
    }

    @Test
    fun smapsSummaryAccountsForMappingsOutsideTheBoundedTopList() {
        val smaps = """
            1000-2000 r-xp 00000000 00:00 0 /one/libfirst.so
            Rss:                 100 kB
            Pss:                  90 kB
            Private_Clean:        80 kB
            Private_Dirty:        10 kB
            Shared_Clean:         10 kB
            Shared_Dirty:          0 kB
            Swap:                   5 kB
            SwapPss:                2 kB
            1800-2000 r--p 00000000 00:00 0 /one/libfirst.so
            Rss:                   10 kB
            Pss:                    8 kB
            2000-3000 rw-p 00000000 00:00 0
            Rss:                  60 kB
            Pss:                  50 kB
            Private_Clean:         0 kB
            Private_Dirty:        50 kB
            Shared_Clean:          0 kB
            Shared_Dirty:         10 kB
            Swap:                   0 kB
            SwapPss:                0 kB
        """.trimIndent()

        val summary = automaticDiagnosticsSummarizeSmaps(
            smaps.lineSequence(),
            maximumMappings = 1,
        )

        assertEquals(3, summary.mappingCount)
        assertEquals(2, summary.mappingGroupCount)
        assertEquals(listOf("libfirst.so"), summary.topMappings.map { it.name })
        assertEquals(
            listOf("anonymous", "native_library"),
            summary.categories.map { it.category },
        )
        val anonymous = summary.categories.first { it.category == "anonymous" }
        assertEquals(60L * 1024L, anonymous.residentBytes)
        assertEquals(50L * 1024L, anonymous.proportionalBytes)
        assertEquals(50L * 1024L, anonymous.privateDirtyBytes)
        val nativeLibrary = summary.categories.first { it.category == "native_library" }
        assertEquals(80L * 1024L, nativeLibrary.privateCleanBytes)
        assertEquals(10L * 1024L, nativeLibrary.sharedCleanBytes)
        assertEquals(5L * 1024L, nativeLibrary.swapBytes)
        assertEquals(2L * 1024L, nativeLibrary.swapProportionalBytes)
    }

    @Test
    fun tunnelSessionMemorySamplesCoverEarlyAndLongRunningUiGrowth() {
        assertEquals(
            listOf(60L, 5 * 60L, 15 * 60L, 30 * 60L, 60 * 60L, 3 * 60 * 60L),
            automaticDiagnosticsMemorySampleDelaysSeconds(),
        )
    }

    @Test
    fun androidMemoryStatsAreConvertedFromKibibytesWithoutThrowing() {
        val stats = mapOf(
            "summary.graphics" to "123",
            "summary.native-heap" to "invalid",
        )

        assertEquals(
            123L * 1024L,
            automaticDiagnosticsMemoryStatBytes(stats, "summary.graphics"),
        )
        assertNull(automaticDiagnosticsMemoryStatBytes(stats, "summary.native-heap"))
        assertNull(automaticDiagnosticsMemoryStatBytes(stats, "summary.system"))
    }

    @Test
    fun memoryGrowthTrackerCapturesCumulativeGrowthAndResetsAfterRelease() {
        val mebibyte = 1024L * 1024L
        val tracker = AutomaticDiagnosticsMemoryGrowthTracker(64L * mebibyte)

        assertTrue(!tracker.observe(100L * mebibyte))
        assertTrue(!tracker.observe(150L * mebibyte))
        assertTrue(tracker.observe(164L * mebibyte))
        assertTrue(!tracker.observe(120L * mebibyte))
        assertTrue(tracker.observe(184L * mebibyte))
    }

    @Test
    fun structuredMemoryComponentsKeepAndroidPssCategories() {
        val processes = JSONArray().put(
            JSONObject()
                .put("processId", 42L)
                .put("processName", "ru.nelomai.client:vpn")
                .put("currentResidentMemoryBytes", 400L)
                .put("pssJavaHeapBytes", 100L)
                .put("pssNativeHeapBytes", 200L)
                .put("pssGraphicsBytes", 50L),
        )

        val component = automaticDiagnosticsResourceComponents(processes).getJSONObject(0)

        assertEquals(100L, component.getLong("pss_java_heap_bytes"))
        assertEquals(200L, component.getLong("pss_native_heap_bytes"))
        assertEquals(50L, component.getLong("pss_graphics_bytes"))
    }

    @Test
    fun structuredMemoryComponentsPreferLiveSmapsRollupOverCachedActivityManagerPss() {
        val processes = JSONArray().put(
            JSONObject()
                .put("processId", 42L)
                .put("processName", "ru.nelomai.client:vpn")
                .put("currentResidentMemoryBytes", 400L)
                .put("currentProportionalMemoryBytes", 500L)
                .put("currentPrivateDirtyMemoryBytes", 300L)
                .put("smapsResidentMemoryBytes", 120L)
                .put("smapsProportionalMemoryBytes", 80L)
                .put("smapsPrivateDirtyMemoryBytes", 60L)
                .put("pssCodeBytes", 200L),
        )

        val components = automaticDiagnosticsResourceComponents(processes)
        val process = components.getJSONObject(0)
        val aggregate = components.getJSONObject(1)

        assertEquals("android_smaps_rollup", process.getString("source"))
        assertEquals(120L, process.getLong("current_resident_memory_bytes"))
        assertEquals(80L, process.getLong("current_proportional_memory_bytes"))
        assertEquals(60L, process.getLong("current_private_dirty_memory_bytes"))
        assertEquals(500L, process.getLong("activity_manager_pss_bytes"))
        assertEquals(
            "android_activity_manager_memory_info",
            process.getString("pss_categories_source"),
        )
        assertEquals("android_smaps_rollup_sum", aggregate.getString("source"))
        assertEquals(120L, aggregate.getLong("current_resident_memory_bytes"))
        assertEquals(80L, aggregate.getLong("current_proportional_memory_bytes"))
    }

    @Test
    fun interruptedSessionEndsAtLastLiveObservationWithinItsInterval() {
        assertEquals(
            150L,
            automaticDiagnosticsInterruptedSessionEnd(
                startedAt = 100L,
                lastLiveAt = 150L,
                observedAt = 200L,
            ),
        )
        assertEquals(
            100L,
            automaticDiagnosticsInterruptedSessionEnd(
                startedAt = 100L,
                lastLiveAt = null,
                observedAt = 200L,
            ),
        )
        assertEquals(
            100L,
            automaticDiagnosticsInterruptedSessionEnd(
                startedAt = 100L,
                lastLiveAt = 50L,
                observedAt = 200L,
            ),
        )
        assertEquals(
            200L,
            automaticDiagnosticsInterruptedSessionEnd(
                startedAt = 100L,
                lastLiveAt = 250L,
                observedAt = 200L,
            ),
        )
    }

    @Test
    fun durableNormalStopMarkerSurvivesProcessRestartClassification() {
        val normal = automaticDiagnosticsStoppedSessionSeal(
            pending = true,
            pendingTrigger = "tunnel_stopped",
            pendingEndedAt = 175L,
            startedAt = 100L,
            lastLiveAt = 150L,
            observedAt = 200L,
        )
        val interrupted = automaticDiagnosticsStoppedSessionSeal(
            pending = false,
            pendingTrigger = null,
            pendingEndedAt = null,
            startedAt = 100L,
            lastLiveAt = 150L,
            observedAt = 200L,
        )
        val legacyNormal = automaticDiagnosticsStoppedSessionSeal(
            pending = true,
            pendingTrigger = null,
            pendingEndedAt = null,
            startedAt = 100L,
            lastLiveAt = 160L,
            observedAt = 200L,
        )
        val legacyWithoutEvidence = automaticDiagnosticsStoppedSessionSeal(
            pending = true,
            pendingTrigger = null,
            pendingEndedAt = null,
            startedAt = 100L,
            lastLiveAt = null,
            observedAt = 200L,
        )

        assertEquals("tunnel_stopped", normal.trigger)
        assertEquals(175L, normal.endedAt)
        assertEquals("tunnel_interrupted", interrupted.trigger)
        assertEquals(150L, interrupted.endedAt)
        assertEquals("tunnel_stopped", legacyNormal.trigger)
        assertEquals(160L, legacyNormal.endedAt)
        assertEquals(100L, legacyWithoutEvidence.endedAt)
    }

    @Test
    fun legacySessionWatermarkUsesLastDurableLogBeforeReplacementProcess() {
        val log = """
            {"timestamp":"2026-09-02T10:00:00Z","event":"tunnel.data_plane_snapshot"}
            malformed
            {"timestamp":"2026-09-02T10:01:00Z","event":"diagnostics.memory_snapshot"}
            {"timestamp":"2026-09-02T10:03:00Z","event":"replacement.process.event"}
        """.trimIndent()

        assertEquals(
            Instant.parse("2026-09-02T10:01:00Z").epochSecond,
            automaticDiagnosticsLatestLogTimestamp(
                log,
                startedAt = Instant.parse("2026-09-02T09:59:00Z").epochSecond,
                observedAt = Instant.parse("2026-09-02T10:02:00Z").epochSecond,
            ),
        )
    }

    @Test
    fun interruptedSessionTriggerIsAcceptedByPendingSealRecovery() {
        assertTrue(automaticDiagnosticsSessionTriggerAllowed("tunnel_interrupted"))
        assertTrue(automaticDiagnosticsSessionTriggerAllowed("tunnel_stopped"))
        assertTrue(automaticDiagnosticsSessionTriggerAllowed("six_hour_checkpoint"))
        assertFalse(automaticDiagnosticsSessionTriggerAllowed("unexpected"))
    }

    @Test
    fun interruptedSessionDoesNotAttachMemoryFromTheReplacementProcess() {
        assertFalse(automaticDiagnosticsIncludeCurrentProcessMemory("tunnel_interrupted"))
        assertTrue(automaticDiagnosticsIncludeCurrentProcessMemory("tunnel_stopped"))
        assertTrue(automaticDiagnosticsIncludeCurrentProcessMemory("six_hour_checkpoint"))
    }

    @Test
    fun interruptedSessionDoesNotInventAnEmptyAggregateProcessComponent() {
        val components = automaticDiagnosticsReportResourceComponents(
            trigger = "tunnel_interrupted",
            processes = JSONArray().put(
                JSONObject()
                    .put("processId", 42L)
                    .put("processName", "ru.nelomai:replacement")
                    .put("currentResidentMemoryBytes", 64L),
            ),
        )

        assertEquals(0, components.length())
    }

    @Test
    fun interruptedSessionMemoryTimelineDoesNotAppendAnEmptyReplacementSample() {
        val historical = JSONObject()
            .put("timestamp_unix", 150L)
            .put("reason", "periodic")
            .put(
                "components",
                JSONArray().put(
                    JSONObject()
                        .put("component", "android_vpn_process")
                        .put("source", "android_smaps_rollup"),
                ),
            )

        val samples = automaticDiagnosticsMemorySamplesForReport(
            samples = listOf(historical),
            startedAt = 100L,
            endedAt = 200L,
            finalSample = null,
            maximum = 32,
        )

        assertEquals(listOf("periodic"), samples.map { it.getString("reason") })
    }

    @Test
    fun boundedMemoryTimelinePreservesSessionBaselineAndNewestSamples() {
        val samples = (1L..4L).map { timestamp ->
            JSONObject()
                .put("timestamp_unix", timestamp)
                .put("reason", "sample_$timestamp")
        }

        val bounded = automaticDiagnosticsBoundMemorySamples(samples, maximum = 3)

        assertEquals(
            listOf(1L, 3L, 4L),
            bounded.map { it.getLong("timestamp_unix") },
        )
    }

    @Test
    fun boundedMemoryTimelinePreservesDetailedStartupMappings() {
        val samples = (1L..40L).map { timestamp ->
            JSONObject()
                .put("timestamp_unix", timestamp)
                .put(
                    "reason",
                    when (timestamp) {
                        2L -> "tunnel_start_memory_mappings_initial"
                        3L -> "tunnel_start_memory_mappings_confirmation"
                        4L -> "tunnel_start_memory_mappings_settled"
                        5L -> "tunnel_start_memory_mappings_failure"
                        else -> "sample_$timestamp"
                    },
                )
        }

        val bounded = automaticDiagnosticsBoundMemorySamples(samples, maximum = 7)

        assertEquals(
            listOf(1L, 2L, 3L, 4L, 5L, 39L, 40L),
            bounded.map { it.getLong("timestamp_unix") },
        )
    }

    @Test
    fun boundedMemoryTimelinePreservesLateSessionMappingSeries() {
        val samples = (1L..40L).map { timestamp ->
            JSONObject()
                .put("timestamp_unix", timestamp)
                .put(
                    "reason",
                    when (timestamp) {
                        20L -> "tunnel_session_memory_mappings_initial"
                        21L -> "tunnel_session_memory_mappings_confirmation"
                        22L -> "tunnel_session_memory_mappings_settled"
                        else -> "sample_$timestamp"
                    },
                )
        }

        val bounded = automaticDiagnosticsBoundMemorySamples(samples, maximum = 6)

        assertEquals(
            listOf(1L, 20L, 21L, 22L, 39L, 40L),
            bounded.map { it.getLong("timestamp_unix") },
        )
    }

    @Test
    fun boundedMemoryTimelinePreservesSessionBaselineWhenMappingsArriveFirst() {
        val samples = (1L..40L).map { timestamp ->
            JSONObject()
                .put("timestamp_unix", timestamp)
                .put(
                    "reason",
                    when (timestamp) {
                        1L -> "tunnel_start_memory_mappings_initial"
                        2L -> "tunnel_started"
                        else -> "sample_$timestamp"
                    },
                )
        }

        val bounded = automaticDiagnosticsBoundMemorySamples(samples, maximum = 3)

        assertEquals(
            listOf(1L, 2L, 40L),
            bounded.map { it.getLong("timestamp_unix") },
        )
    }

    @Test
    fun sealedMemoryTimelineKeepsOnlySamplesAfterTheClosedInterval() {
        val samples = listOf(99L, 100L, 101L).map { timestamp ->
            JSONObject()
                .put("timestamp_unix", timestamp)
                .put("reason", "sample_$timestamp")
        }

        val retained = automaticDiagnosticsMemorySamplesAfter(samples, endedAt = 100L)

        assertEquals(listOf(101L), retained.map { it.getLong("timestamp_unix") })
    }

    @Test
    fun startFailureReportUsesCapturedAttemptInsteadOfNextRetryTimeline() {
        val capturedAttempt = listOf(
            JSONObject()
                .put("timestamp_unix", 100L)
                .put("reason", "tunnel_start_memory_mappings_failure"),
        )
        val finalSample = JSONObject()
            .put("timestamp_unix", 100L)
            .put("reason", "connection_start_failed")

        val durableRequest = StartFailureRequest(
            reportId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            deviceId = "11111111-1111-4111-8111-111111111111",
            errorCode = "connection_start_failed",
            queuedAt = 100L,
            sent = false,
            memorySamplesJson = automaticDiagnosticsEncodeMemorySamples(capturedAttempt),
        )
        val restoredRequest = StartFailureRequest.fromJson(durableRequest.toJson())
        capturedAttempt.single().put("reason", "retry_was_mutated_after_snapshot")
        val reportSamples = automaticDiagnosticsMemorySamplesForReport(
            samples = automaticDiagnosticsDecodeMemorySamples(
                checkNotNull(restoredRequest.memorySamplesJson),
            ),
            startedAt = 90L,
            endedAt = 100L,
            finalSample = finalSample,
            maximum = 32,
        )

        assertEquals(
            listOf(
                "tunnel_start_memory_mappings_failure",
                "connection_start_failed",
            ),
            reportSamples.map { it.getString("reason") },
        )
    }

    @Test
    fun oversizedReportCompactionPreservesMemoryTimeline() {
        val memorySamples = JSONArray().apply {
            put(JSONObject().put("timestamp_unix", 1L).put("reason", "baseline"))
            put(JSONObject().put("timestamp_unix", 2L).put("reason", "peak"))
        }
        val payload = JSONObject()
            .put("application_log", "a".repeat(900))
            .put("helper_log", "h".repeat(200))
            .put("network_incidents", "n".repeat(200))
            .put(
                "resource_usage",
                JSONObject().put("memory_samples", memorySamples),
            )

        val compacted = automaticDiagnosticsCompactReportToBytes(payload, maximum = 700)

        assertTrue(compacted.toString().toByteArray(Charsets.UTF_8).size <= 700)
        assertEquals(
            memorySamples.toString(),
            compacted.getJSONObject("resource_usage").getJSONArray("memory_samples").toString(),
        )
        assertEquals("h".repeat(200), compacted.getString("helper_log"))
        assertEquals("n".repeat(200), compacted.getString("network_incidents"))
        assertTrue(compacted.getString("application_log").length < 900)
    }

    @Test
    fun lifecycleGatePreventsSnapshotFromOverlappingSeal() {
        val gate = Any()
        val sealEntered = CountDownLatch(1)
        val releaseSeal = CountDownLatch(1)
        val snapshotAttempted = CountDownLatch(1)
        val snapshotEntered = CountDownLatch(1)
        val sealThread = thread(start = true) {
            automaticDiagnosticsRunWithLifecycleGate(gate) {
                sealEntered.countDown()
                releaseSeal.await(2, TimeUnit.SECONDS)
            }
        }
        assertTrue(sealEntered.await(2, TimeUnit.SECONDS))
        val snapshotThread = thread(start = true) {
            snapshotAttempted.countDown()
            automaticDiagnosticsRunWithLifecycleGate(gate) {
                snapshotEntered.countDown()
            }
        }

        assertTrue(snapshotAttempted.await(2, TimeUnit.SECONDS))
        assertTrue(!snapshotEntered.await(100, TimeUnit.MILLISECONDS))
        releaseSeal.countDown()
        assertTrue(snapshotEntered.await(2, TimeUnit.SECONDS))
        sealThread.join(2_000)
        snapshotThread.join(2_000)
        assertTrue(!sealThread.isAlive)
        assertTrue(!snapshotThread.isAlive)
    }

    @Test
    fun tunnelStartMemoryDiagnosticsCannotAbortTunnelStartup() {
        val failure = containTunnelStartMemoryDiagnosticsFailure {
            throw IllegalStateException("diagnostic failure")
        }

        assertEquals("diagnostic failure", failure?.message)
    }

    @Test
    fun optionalTunnelStartupDiagnosticsCannotFailRequiredStartupHooks() {
        var requiredRan = false
        var recordedFailure: Throwable? = null

        runTunnelStartupPostActions(
            required = { requiredRan = true },
            optionalDiagnostics = { throw IllegalStateException("schedule rejected") },
            onDiagnosticsFailure = { recordedFailure = it },
        )

        assertTrue(requiredRan)
        assertEquals("schedule rejected", recordedFailure?.message)
    }

    @Test
    fun optionalTunnelStartupDiagnosticsFailureReporterIsAlsoFailOpen() {
        runTunnelStartupPostActions(
            required = {},
            optionalDiagnostics = { throw IllegalStateException("schedule rejected") },
            onDiagnosticsFailure = { throw IllegalStateException("logger rejected") },
        )
    }

    @Test
    fun failedTunnelCapturesDiagnosticsBeforeStoppingItsService() {
        val actions = mutableListOf<String>()

        runTunnelFailureCleanup(
            optionalDiagnostics = { actions += "diagnostics" },
            requiredCleanup = { actions += "service_stop" },
            onDiagnosticsFailure = { actions += "diagnostics_failure" },
        )

        assertEquals(listOf("diagnostics", "service_stop"), actions)
    }

    @Test
    fun failedTunnelStillStopsItsServiceWhenDiagnosticsThrow() {
        val actions = mutableListOf<String>()

        runTunnelFailureCleanup(
            optionalDiagnostics = {
                actions += "diagnostics"
                throw IllegalStateException("smaps unavailable")
            },
            requiredCleanup = { actions += "service_stop" },
            onDiagnosticsFailure = { actions += "diagnostics_failure" },
        )

        assertEquals(
            listOf("diagnostics", "diagnostics_failure", "service_stop"),
            actions,
        )
    }
}
