package ru.nelomai.tunnel

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import org.amnezia.awg.config.Config
import org.amnezia.awg.config.Peer

internal const val OWNED_POLICY_REQUEST_TIMEOUT_MILLIS = 30_000L

/** Bounded process-only cancellation tombstones. Cancels follow issuance of the
 * deadline-stamped apply Intent, so one full IPC window covers delayed delivery.
 * Never evict a live ID: saturation fences new admission for that full window. */
internal class OwnedPolicyCancellationGate {
    internal class Ticket(val operationId: String) {
        private val cancelled = java.util.concurrent.atomic.AtomicBoolean(false)
        fun isCancelled(): Boolean = cancelled.get()
        internal fun cancel() { cancelled.set(true) }
    }

    private val recent = linkedMapOf<String, Long>()
    private var active: Ticket? = null
    private var refuseUntilElapsedMs = 0L

    @Synchronized
    fun begin(operationId: String): Ticket? {
        val now = android.os.SystemClock.elapsedRealtime()
        prune(now)
        if (active != null || operationId in recent || now < refuseUntilElapsedMs) return null
        return Ticket(operationId).also { active = it }
    }

    @Synchronized
    fun cancel(operationId: String) {
        val now = android.os.SystemClock.elapsedRealtime()
        prune(now)
        val ticket = active
        if (ticket?.operationId == operationId) ticket.cancel() else remember(operationId, now)
    }

    @Synchronized
    fun reject(operationId: String) {
        if (active?.operationId == operationId) return // duplicate must not retire the active ticket
        val now = android.os.SystemClock.elapsedRealtime()
        prune(now)
        remember(operationId, now)
    }

    @Synchronized
    fun complete(ticket: Ticket) {
        if (active !== ticket) return
        active = null
        val now = android.os.SystemClock.elapsedRealtime()
        prune(now)
        remember(ticket.operationId, now)
    }

    private fun prune(now: Long) { recent.entries.removeAll { it.value <= now } }

    private fun remember(operationId: String, now: Long) {
        if (operationId in recent) return // late cancels must not extend terminal retention
        val expires = now + OWNED_POLICY_REQUEST_TIMEOUT_MILLIS
        if (recent.size < 128) recent[operationId] = expires
        else refuseUntilElapsedMs = maxOf(refuseUntilElapsedMs, expires)
    }
}

internal class OwnedPolicyReplyFence(private val binder: android.os.IBinder) : AutoCloseable {
    private val dead = java.util.concurrent.atomic.AtomicBoolean(false)
    private val recipient = android.os.IBinder.DeathRecipient { dead.set(true) }
    init { binder.linkToDeath(recipient, 0) }
    fun isCurrent(): Boolean = !dead.get() && binder.isBinderAlive
    override fun close() { runCatching { binder.unlinkToDeath(recipient, 0) } }
}

/** Only called at slot admission, where endpoint resolution already succeeded. */
internal fun resolvedRedundantConfiguration(config: Config): Config = Config.Builder()
    .setInterface(config.getInterface())
    .addPeers(config.peers.map { peer ->
        val endpoint = peer.endpoint.orElse(null)
        val numeric = endpoint?.resolved?.orElse(null)
        require(endpoint == null || numeric != null)
        Peer.parse(peer.toAwgQuickString().lineSequence().filter(String::isNotBlank).map {
            if (it.startsWith("Endpoint = ")) "Endpoint = $numeric" else it
        }.toList())
    }).build()

/** Cached inputs have numeric endpoints: applying a policy never performs DNS recovery. */
internal fun prepareOwnedRedundantConfiguration(
    bytes: ByteArray,
    options: AndroidTunnelOptions,
    egressMode: String,
    apiLevel: Int,
    packageName: String,
    privateDnsHostname: String? = null,
): PreparedRedundantConfiguration = TunnelPayload.consume(bytes) {
    val parsed = Config.parse(ByteArrayInputStream(it))
    val effective = AndroidSplitTunnel.resolveConfigurationOptions(apiLevel,
        options.toTunnelOptionsArgs(), egressMode, parsed, privateDnsHostname)
    val config = AndroidSplitTunnel.applyOptions(parsed, effective, packageName)
    PreparedRedundantConfiguration(config,
        config.toAwgUserspaceString().toByteArray(StandardCharsets.UTF_8), it.copyOf())
}

internal data class OwnedRedundantPolicyScope(
    val sessionId: String,
    val leaseId: String,
    val layer: String,
    val ticConnectionMode: String,
    val routeMode: String,
    val egressMode: String,
    val allowAlternate: Boolean = false,
)

internal enum class OwnedRedundantPolicyOutcome(val wireName: String) {
    APPLIED("applied"), UNCHANGED("unchanged"), ROLLED_BACK("rolled_back"), FAILED("failed"),
}
