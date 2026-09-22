package ru.nelomai.tunnel

import java.util.UUID
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

/** Existing state-machine tests run the real completion inline. Concurrency tests
 * construct the coordinator with a real worker and a blocked transport instead. */
internal fun testRedundantCoordinator(
    store: AndroidRecoveryStore,
    panel: RedundantConnectionPanel,
    native: RedundantConnectionNative,
    operationId: () -> String = { UUID.randomUUID().toString() },
    epochNowMs: () -> Long = System::currentTimeMillis,
    monotonicMs: () -> Long = { TimeUnit.NANOSECONDS.toMillis(System.nanoTime()) },
    healthMonitor: RedundantHealthMonitor = RedundantHealthMonitor(),
    onReserveStateChanged: (RedundantReserveState?) -> Unit = {},
    onDiagnosticEvent: (RedundantDiagnosticEvent) -> Unit = {},
    expectedStartOperationId: String? = null,
    mutationFence: RedundantOperationMutationFence = RedundantOperationMutationFence(),
    onAllSlotsStalled: () -> Unit = {},
    onRecoveryReadiness: (Boolean) -> Unit = {},
): RedundantConnectionCoordinator = RedundantConnectionCoordinator(
    store, panel, native, operationId, epochNowMs, monotonicMs, healthMonitor,
    onReserveStateChanged, onDiagnosticEvent, expectedStartOperationId,
    mutationFence, onAllSlotsStalled, onRecoveryReadiness,
    standbyExecutor = Executor { it.run() },
)
