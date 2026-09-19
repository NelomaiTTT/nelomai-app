package ru.nelomai.client

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Process-local fence between an accepted quick action and VPN idle recycle. */
object RuntimeDispatchGuard {
    private val pending = AtomicInteger(0)

    fun begin(): AutoCloseable {
        pending.incrementAndGet()
        val open = AtomicBoolean(true)
        return AutoCloseable {
            if (open.compareAndSet(true, false)) pending.decrementAndGet()
        }
    }

    fun hasPending(): Boolean = pending.get() > 0
}
