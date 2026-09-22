package ru.nelomai.tunnel

/** Bounded startup/rebind samples in the existing durable report log. */
internal class RedundantTransportDiagnostics {
    private var startedAt: Long? = null
    private var lastSampleAt: Long? = null

    fun begin(now: Long) {
        startedAt = now
        lastSampleAt = null
    }

    fun record(phase: String, nativeMetrics: String?, now: Long, force: Boolean = false) {
        val started = startedAt ?: return
        if (!force && (now - started !in 0L..30_000L ||
                lastSampleAt?.let { now - it < 5_000L } == true)) return
        lastSampleAt = now
        // Diagnostic parsing/logging must never change tunnel lifecycle results.
        runCatching {
            val slots = automaticDiagnosticsRedundantSnapshot(
                "warming", nativeMetrics, 0, 0, 0, 0,
            ).getJSONArray("slots")
            for (index in 0 until slots.length()) {
                val slot = slots.getJSONObject(index)
                val details = linkedMapOf<String, Any?>(
                    "phase" to phase,
                    "elapsed_since_start_ms" to (now - started).coerceAtLeast(0),
                    "slot" to slot.getInt("slot"),
                    "admitted" to slot.getBoolean("admitted"),
                    "latest_handshake_at_unix_ms" to slot.getLong("latest_handshake_at_unix_ms"),
                )
                val telemetry = slot.getJSONObject("telemetry")
                // The shared sanitizer only admits allowlisted numeric fields;
                // omit memory counters here, and never log raw native JSON.
                telemetry.keys().forEach { key ->
                    if (key.startsWith("udp_") || key.startsWith("last_udp_")) {
                        details[key] = telemetry.getLong(key)
                    }
                }
                TunnelLog.info("redundant.transport", details)
            }
        }
    }
}
