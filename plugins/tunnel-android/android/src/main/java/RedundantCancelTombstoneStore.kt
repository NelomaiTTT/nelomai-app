package ru.nelomai.tunnel

import android.content.Context
import java.util.UUID

private const val REDUNDANT_CANCEL_PREFERENCES = "nelomai-redundant-cancel"
private const val REDUNDANT_CANCEL_RECORD = "tombstone"
private const val REDUNDANT_CANCEL_FORMAT = "1"

internal data class RedundantCancelTombstone(
    val startOperationId: String,
    val stopOperationId: String,
)

internal interface RedundantCancelTombstoneBackend {
    fun read(): String?
    fun compareAndWrite(expected: String?, value: String): Boolean
    fun compareAndClear(expected: String): Boolean
}

internal class RedundantCancelTombstoneStore(
    private val backend: RedundantCancelTombstoneBackend,
    private val operationId: () -> String = { UUID.randomUUID().toString() },
) {
    fun read(): RecoveryStoreResult<RedundantCancelTombstone?> = try {
        RecoveryStoreResult.Success(backend.read()?.let(::decode))
    } catch (_: Throwable) {
        RecoveryStoreResult.Failure("redundant_cancel_tombstone_corrupt")
    }

    fun persist(startOperationId: String): RecoveryStoreResult<RedundantCancelTombstone> {
        repeat(2) {
            val encoded = try {
                backend.read()
            } catch (_: Throwable) {
                return RecoveryStoreResult.Failure("redundant_cancel_tombstone_read_failed")
            }
            val current = try {
                encoded?.let(::decode)
            } catch (_: Throwable) {
                return RecoveryStoreResult.Failure("redundant_cancel_tombstone_corrupt")
            }
            if (current != null) {
                return if (current.startOperationId == startOperationId) {
                    RecoveryStoreResult.Success(current)
                } else {
                    RecoveryStoreResult.Failure("redundant_cancel_tombstone_busy")
                }
            }
            val tombstone = RedundantCancelTombstone(startOperationId, operationId())
            val replacement = try {
                encode(tombstone)
            } catch (_: Throwable) {
                return RecoveryStoreResult.Failure("invalid_redundant_cancel_tombstone")
            }
            val saved = try {
                backend.compareAndWrite(encoded, replacement)
            } catch (_: Throwable) {
                false
            }
            if (saved) return RecoveryStoreResult.Success(tombstone)
        }
        return RecoveryStoreResult.Failure("redundant_cancel_tombstone_conflict")
    }

    fun clear(expected: RedundantCancelTombstone): Boolean = try {
        backend.compareAndClear(encode(expected))
    } catch (_: Throwable) {
        false
    }

    private fun encode(tombstone: RedundantCancelTombstone): String {
        requireValidId(tombstone.startOperationId)
        requireValidId(tombstone.stopOperationId)
        return listOf(
            REDUNDANT_CANCEL_FORMAT,
            tombstone.startOperationId,
            tombstone.stopOperationId,
        ).joinToString("\n")
    }

    private fun decode(value: String): RedundantCancelTombstone {
        val fields = value.split('\n')
        require(fields.size == 3 && fields[0] == REDUNDANT_CANCEL_FORMAT)
        requireValidId(fields[1])
        requireValidId(fields[2])
        return RedundantCancelTombstone(fields[1], fields[2])
    }

    private fun requireValidId(value: String) {
        require(value.isNotBlank() && value.length <= 128 && '\n' !in value && '\r' !in value)
    }
}

internal class AndroidRedundantCancelTombstoneBackend(context: Context) :
    RedundantCancelTombstoneBackend {
    private val preferences = context.applicationContext.getSharedPreferences(
        REDUNDANT_CANCEL_PREFERENCES,
        Context.MODE_PRIVATE,
    )

    override fun read(): String? = preferences.getString(REDUNDANT_CANCEL_RECORD, null)

    override fun compareAndWrite(expected: String?, value: String): Boolean =
        synchronized(PROCESS_GATE) {
            if (preferences.getString(REDUNDANT_CANCEL_RECORD, null) != expected) {
                return@synchronized false
            }
            preferences.edit().putString(REDUNDANT_CANCEL_RECORD, value).commit()
        }

    override fun compareAndClear(expected: String): Boolean = synchronized(PROCESS_GATE) {
        if (preferences.getString(REDUNDANT_CANCEL_RECORD, null) != expected) {
            return@synchronized false
        }
        preferences.edit().remove(REDUNDANT_CANCEL_RECORD).commit()
    }

    private companion object {
        val PROCESS_GATE = Any()
    }
}

internal enum class RedundantPrimaryReadyDisposition {
    RUNNING,
    CANCELLED,
    FAIL_CLOSED,
}

internal fun redundantPrimaryReadyDisposition(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
): RedundantPrimaryReadyDisposition = when (recovery) {
    is RecoveryStoreResult.Failure -> RedundantPrimaryReadyDisposition.FAIL_CLOSED
    is RecoveryStoreResult.Success -> recovery.value.redundantTransaction?.let { transaction ->
        if (transaction.desiredActive && transaction.retry.stopState == RedundantStopState.NONE) {
            RedundantPrimaryReadyDisposition.RUNNING
        } else {
            RedundantPrimaryReadyDisposition.CANCELLED
        }
    } ?: RedundantPrimaryReadyDisposition.CANCELLED
}

internal enum class RedundantStopCompletionDisposition {
    PUBLISH_STOPPED,
    STALE_ONLY,
    RETRY,
}

internal fun redundantStopCompletionDisposition(
    ownerServiceGeneration: Long,
    currentServiceGeneration: Long,
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
): RedundantStopCompletionDisposition {
    if (ownerServiceGeneration != currentServiceGeneration) {
        return RedundantStopCompletionDisposition.STALE_ONLY
    }
    val envelope = when (recovery) {
        is RecoveryStoreResult.Failure -> return RedundantStopCompletionDisposition.RETRY
        is RecoveryStoreResult.Success -> recovery.value
    }
    return if (envelope.redundantTransaction == null &&
        envelope.leaseTransaction == null &&
        !envelope.intent.desiredActive
    ) {
        RedundantStopCompletionDisposition.PUBLISH_STOPPED
    } else {
        RedundantStopCompletionDisposition.STALE_ONLY
    }
}

internal fun redundantStopOperationId(
    pendingStopOperationId: String?,
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    pendingStartOperationId: String?,
    ownerStartOperationId: String?,
): String? = pendingStopOperationId
    ?: (recovery as? RecoveryStoreResult.Success)
        ?.value?.redundantTransaction?.startOperationId
    ?: pendingStartOperationId
    ?: ownerStartOperationId

internal fun redundantCleanupBlocksNewStarts(
    pendingStop: Boolean,
    tombstoneUnreadable: Boolean,
): Boolean = pendingStop || tombstoneUnreadable

internal fun activeRedundantTransactionForWork(
    recovery: RecoveryStoreResult<AndroidRecoveryEnvelope>,
    expectedStartOperationId: String?,
    pendingStop: Boolean,
    tombstoneUnreadable: Boolean,
): AndroidRedundantTransaction? {
    if (redundantCleanupBlocksNewStarts(pendingStop, tombstoneUnreadable)) return null
    val transaction = (recovery as? RecoveryStoreResult.Success)
        ?.value?.redundantTransaction ?: return null
    if (!transaction.desiredActive || transaction.retry.stopState != RedundantStopState.NONE) {
        return null
    }
    return transaction.takeIf {
        expectedStartOperationId == null || it.startOperationId == expectedStartOperationId
    }
}

internal data class RedundantPhysicalNetworkCallbackIdentity(
    val serviceGeneration: Long,
    val startOperationId: String,
) {
    fun isCurrent(
        currentServiceGeneration: Long,
        installedStartOperationId: String?,
        pendingStop: Boolean,
        tombstoneUnreadable: Boolean,
    ): Boolean = serviceGeneration == currentServiceGeneration &&
        startOperationId == installedStartOperationId &&
        !redundantCleanupBlocksNewStarts(pendingStop, tombstoneUnreadable)

    fun applyIfCurrent(
        mutationFence: RedundantOperationMutationFence,
        currentServiceGeneration: Long,
        installedStartOperationId: String?,
        pendingStop: Boolean,
        tombstoneUnreadable: Boolean,
        action: () -> Unit,
    ): Boolean = mutationFence.runIfActive(startOperationId) {
        if (isCurrent(
                currentServiceGeneration,
                installedStartOperationId,
                pendingStop,
                tombstoneUnreadable,
            )
        ) {
            action()
            true
        } else {
            false
        }
    }
}

internal fun shouldAcknowledgeRedundantQuickStop(
    tombstonePersisted: Boolean,
): Boolean = tombstonePersisted

internal fun shouldApplyConnectionIntentStep(
    pendingStop: Boolean,
    tombstoneUnreadable: Boolean,
    envelope: AndroidRecoveryEnvelope?,
): Boolean = !redundantCleanupBlocksNewStarts(pendingStop, tombstoneUnreadable) &&
    envelope != null && envelope.redundantTransaction == null

internal fun shouldCompleteRedundantCancellation(
    tombstonePersisted: Boolean,
    localClosed: Boolean,
    cleanupStopped: Boolean,
): Boolean = tombstonePersisted && (localClosed || cleanupStopped)

internal enum class RedundantTombstoneClearDisposition {
    CONFIRMED,
    RETRY,
    REPLAY_SUPERSEDING,
    STALE,
}

internal fun redundantTombstoneClearDisposition(
    cleared: Boolean,
    durable: RecoveryStoreResult<RedundantCancelTombstone?>,
    ownerServiceGeneration: Long,
    currentServiceGeneration: Long,
    expected: RedundantCancelTombstone,
): RedundantTombstoneClearDisposition = when {
    cleared -> RedundantTombstoneClearDisposition.CONFIRMED
    durable is RecoveryStoreResult.Failure -> RedundantTombstoneClearDisposition.RETRY
    (durable as RecoveryStoreResult.Success).value == expected -> {
        RedundantTombstoneClearDisposition.RETRY
    }
    durable.value == null -> RedundantTombstoneClearDisposition.CONFIRMED
    ownerServiceGeneration == currentServiceGeneration -> {
        RedundantTombstoneClearDisposition.REPLAY_SUPERSEDING
    }
    else -> RedundantTombstoneClearDisposition.STALE
}
