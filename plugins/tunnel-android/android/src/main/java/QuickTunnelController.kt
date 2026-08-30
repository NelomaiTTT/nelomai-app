package ru.nelomai.tunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean

internal data class QuickStateAcknowledgeResult(
    val saved: Boolean,
    val pendingRevision: Long,
)

internal object QuickDesiredActiveProjection {
    fun read(store: AndroidRecoveryStore): RecoveryStoreResult<AndroidConnectionIntent> =
        when (val result = store.read()) {
            is RecoveryStoreResult.Success -> RecoveryStoreResult.Success(result.value.intent)
            is RecoveryStoreResult.Failure -> result
        }

    fun update(
        store: AndroidRecoveryStore,
        desiredActive: Boolean,
    ): RecoveryStoreResult<AndroidConnectionIntent> {
        val current = read(store)
        if (current is RecoveryStoreResult.Failure) return current
        val intent = (current as RecoveryStoreResult.Success).value
        return when (val result = store.setDesiredActive(intent.generation, desiredActive)) {
            is RecoveryStoreResult.Success -> RecoveryStoreResult.Success(result.value.intent)
            is RecoveryStoreResult.Failure -> result
        }
    }
}

object QuickTunnelController {
    internal const val ACTION_STATE_CHANGED = "ru.nelomai.tunnel.STATE_CHANGED"
    internal const val EXTRA_STATE_CHANGE_REVISION = "state_change_revision"
    private const val STATE_PREFERENCES = "nelomai-quick-tunnel-state"
    private const val STATE_CHANGED = "changed"
    private const val STATE_CHANGE_REVISION = "change-revision"
    private const val STATE_VALUE = "state"
    private const val STATE_UPDATED_AT_MILLIS = "state-updated-at-millis"
    private const val DESIRED_ACTIVE = "desired-active"
    private const val RECOVERY_PROJECTION_MIGRATED = "recovery-projection-migrated"
    internal const val TRANSITION_TIMEOUT_MILLIS = 120_000L

    @JvmStatic
    fun state(context: Context): String {
        val runtimeState = TunnelRuntime.state()
        if (runtimeState != SessionState.STOPPED) {
            return runtimeState.wireName
        }
        val preferences = preferences(context)
        val persistedState = SessionState.values().firstOrNull {
            it.wireName == preferences.getString(STATE_VALUE, SessionState.STOPPED.wireName)
        } ?: SessionState.STOPPED
        val resolvedState = resolveState(
            runtimeState,
            persistedState,
            preferences.getLong(STATE_UPDATED_AT_MILLIS, 0),
            System.currentTimeMillis(),
        )
        if (resolvedState != persistedState) {
            updateState(context, resolvedState)
        }
        return resolvedState.wireName
    }

    @JvmStatic
    fun requestToggle(context: Context): Boolean {
        return try {
            NelomaiVpnService.requestToggle(context.applicationContext)
            true
        } catch (error: Throwable) {
            TunnelLog.warning("quick_toggle.dispatch_failed", "service_start_failed", error)
            false
        }
    }

    @Synchronized
    internal fun updateState(
        context: Context,
        state: SessionState,
        desiredActive: Boolean? = null,
        changed: Boolean = false,
    ): Boolean {
        val preferences = preferences(context)
        if (desiredActive != null) {
            if (!sealRecoveryProjectionMigration(preferences)) return false
            val recoveryResult = QuickDesiredActiveProjection.update(
                AndroidRecoveryStores.open(context),
                desiredActive,
            )
            if (recoveryResult is RecoveryStoreResult.Failure) {
                TunnelLog.warning("quick_state.recovery_save_failed", recoveryResult.code)
                return false
            }
        }
        val changedRevision = if (changed) {
            val storedRevision = preferences.getLong(STATE_CHANGE_REVISION, 0L)
            val currentRevision = if (preferences.getBoolean(STATE_CHANGED, false)) {
                storedRevision.coerceAtLeast(1L)
            } else {
                storedRevision
            }
            if (currentRevision == Long.MAX_VALUE) Long.MAX_VALUE else currentRevision + 1L
        } else {
            0L
        }
        val saved = preferences.edit().apply {
            putString(STATE_VALUE, state.wireName)
            putLong(STATE_UPDATED_AT_MILLIS, System.currentTimeMillis())
            desiredActive?.let {
                remove(DESIRED_ACTIVE)
                putBoolean(RECOVERY_PROJECTION_MIGRATED, true)
            }
            if (changed) {
                putBoolean(STATE_CHANGED, true)
                putLong(STATE_CHANGE_REVISION, changedRevision)
            }
        }.commit()
        if (!saved) {
            TunnelLog.warning("quick_state.save_failed", "shared_preferences_commit_failed")
        } else if (changed) {
            runCatching {
                context.sendBroadcast(
                    Intent(ACTION_STATE_CHANGED)
                        .setPackage(context.packageName)
                        .putExtra(EXTRA_STATE_CHANGE_REVISION, changedRevision),
                )
            }.onFailure { error ->
                TunnelLog.warning("quick_state.broadcast_failed", "broadcast_failed", error)
            }
        }
        // The encrypted intent is authoritative. Once it matches the requested value,
        // a best-effort display-state failure must not turn an accepted action into a
        // reported rejection that the service could later restore unexpectedly.
        return saved || desiredActive != null
    }

    internal fun desiredActive(context: Context): Boolean {
        if (!migrateLegacyDesiredActive(context)) return false
        return when (
            val result = QuickDesiredActiveProjection.read(AndroidRecoveryStores.open(context))
        ) {
            is RecoveryStoreResult.Success -> result.value.desiredActive
            is RecoveryStoreResult.Failure -> {
                TunnelLog.warning("quick_state.recovery_read_failed", result.code)
                false
            }
        }
    }

    internal fun generation(context: Context): Long? {
        if (!migrateLegacyDesiredActive(context)) return null
        return when (
            val result = QuickDesiredActiveProjection.read(AndroidRecoveryStores.open(context))
        ) {
            is RecoveryStoreResult.Success -> result.value.generation
            is RecoveryStoreResult.Failure -> null
        }
    }

    @JvmStatic
    fun takeStateChange(context: Context): Boolean = takeStateChangeRevision(context) > 0L

    fun takeStateChangeRevision(context: Context): Long {
        val preferences = preferences(context)
        return if (preferences.getBoolean(STATE_CHANGED, false)) {
            preferences.getLong(STATE_CHANGE_REVISION, 0L).coerceAtLeast(1L)
        } else {
            0L
        }
    }

    @Synchronized
    internal fun acknowledgeStateChange(
        context: Context,
        acknowledgedRevision: Long,
    ): QuickStateAcknowledgeResult {
        val preferences = preferences(context)
        if (!preferences.getBoolean(STATE_CHANGED, false)) {
            return QuickStateAcknowledgeResult(saved = true, pendingRevision = 0L)
        }
        val currentRevision = preferences.getLong(STATE_CHANGE_REVISION, 0L).coerceAtLeast(1L)
        if (acknowledgedRevision != currentRevision) {
            return QuickStateAcknowledgeResult(
                saved = true,
                pendingRevision = currentRevision,
            )
        }
        val saved = preferences.edit().remove(STATE_CHANGED).commit()
        if (!saved) {
            TunnelLog.warning("quick_state.change_clear_failed", "shared_preferences_commit_failed")
        }
        return QuickStateAcknowledgeResult(
            saved = saved,
            pendingRevision = if (saved) 0L else currentRevision,
        )
    }

    @JvmStatic
    @Synchronized
    fun clearStateChange(context: Context): Boolean {
        val preferences = preferences(context)
        val recoveryResult = QuickDesiredActiveProjection.update(
            AndroidRecoveryStores.open(context),
            desiredActive = false,
        )
        if (recoveryResult is RecoveryStoreResult.Failure) {
            TunnelLog.warning("quick_state.recovery_clear_failed", recoveryResult.code)
            return false
        }
        val revision = preferences.getLong(STATE_CHANGE_REVISION, 0L)
        val saved = preferences.edit().clear().apply {
            if (revision > 0L) putLong(STATE_CHANGE_REVISION, revision)
        }.commit()
        if (!saved) {
            TunnelLog.warning("quick_state.clear_failed", "shared_preferences_commit_failed")
        }
        return saved
    }

    internal fun resolveState(
        runtimeState: SessionState,
        persistedState: SessionState,
        updatedAtMillis: Long,
        nowMillis: Long,
    ): SessionState {
        if (runtimeState != SessionState.STOPPED) return runtimeState
        if (persistedState !in setOf(SessionState.STARTING, SessionState.STOPPING)) {
            return persistedState
        }
        val transitionAge = nowMillis - updatedAtMillis
        return if (
            updatedAtMillis <= 0 ||
            transitionAge < 0 ||
            transitionAge >= TRANSITION_TIMEOUT_MILLIS
        ) {
            SessionState.STOPPED
        } else {
            persistedState
        }
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(STATE_PREFERENCES, Context.MODE_PRIVATE)

    @Synchronized
    private fun migrateLegacyDesiredActive(context: Context): Boolean {
        val preferences = preferences(context)
        if (preferences.getBoolean(RECOVERY_PROJECTION_MIGRATED, false)) return true
        val legacyDesiredActive = preferences.getBoolean(DESIRED_ACTIVE, false)
        if (!sealRecoveryProjectionMigration(preferences)) return false
        if (legacyDesiredActive) {
            val result = migrateLegacyQuickDesiredActive(
                AndroidRecoveryStores.open(context),
                legacyDesiredActive,
            )
            if (result is RecoveryStoreResult.Failure) {
                TunnelLog.warning("quick_state.recovery_migration_failed", result.code)
                return false
            }
        }
        if (!preferences.edit().remove(DESIRED_ACTIVE).commit()) {
            TunnelLog.warning("quick_state.legacy_cleanup_failed")
        }
        return true
    }

    private fun sealRecoveryProjectionMigration(
        preferences: android.content.SharedPreferences,
    ): Boolean {
        if (preferences.getBoolean(RECOVERY_PROJECTION_MIGRATED, false)) return true
        val saved = preferences.edit()
            .putBoolean(RECOVERY_PROJECTION_MIGRATED, true)
            .commit()
        if (!saved) {
            TunnelLog.warning("quick_state.recovery_migration_marker_failed")
        }
        return saved
    }
}

internal fun migrateLegacyQuickDesiredActive(
    store: AndroidRecoveryStore,
    legacyDesiredActive: Boolean,
): RecoveryStoreResult<AndroidConnectionIntent> = if (legacyDesiredActive) {
    QuickDesiredActiveProjection.update(store, desiredActive = false)
} else {
    QuickDesiredActiveProjection.read(store)
}

internal class QuickStateChangeGate(initialRevision: Long = 0L) {
    private val observedRevision = java.util.concurrent.atomic.AtomicLong(initialRevision)
    private val acknowledgedRevision = java.util.concurrent.atomic.AtomicLong(0)

    fun observe(revision: Long) {
        if (revision <= 0L) return
        observedRevision.updateAndGet { current -> maxOf(current, revision) }
    }

    fun seedPersisted(revision: Long) {
        observe(revision)
    }

    fun current(): Boolean = observedRevision.get() > acknowledgedRevision.get()

    fun snapshot(): Long = observedRevision.get()

    fun acknowledgeThrough(revision: Long) {
        val observed = observedRevision.get()
        val bounded = revision.coerceIn(0L, observed)
        acknowledgedRevision.updateAndGet { current -> maxOf(current, bounded) }
    }

    fun clearPending() {
        acknowledgedRevision.set(observedRevision.get())
    }
}

internal object QuickStateChangeNotifications {
    val gate = QuickStateChangeGate()
    private val registered = AtomicBoolean(false)
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == QuickTunnelController.ACTION_STATE_CHANGED) {
                gate.observe(
                    intent.getLongExtra(
                        QuickTunnelController.EXTRA_STATE_CHANGE_REVISION,
                        0L,
                    ),
                )
            }
        }
    }

    fun initialize(context: Context) {
        val applicationContext = context.applicationContext
        if (registered.compareAndSet(false, true)) {
            try {
                ContextCompat.registerReceiver(
                    applicationContext,
                    receiver,
                    IntentFilter(QuickTunnelController.ACTION_STATE_CHANGED),
                    ContextCompat.RECEIVER_NOT_EXPORTED,
                )
            } catch (error: Throwable) {
                registered.set(false)
                TunnelLog.warning(
                    "quick_state.receiver_registration_failed",
                    "receiver_registration_failed",
                    error,
                )
            }
        }
        gate.seedPersisted(
            QuickTunnelController.takeStateChangeRevision(applicationContext),
        )
    }
}
