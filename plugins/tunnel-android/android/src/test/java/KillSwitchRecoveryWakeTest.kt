package ru.nelomai.tunnel

import org.junit.Assert.*
import org.junit.Test

class KillSwitchRecoveryWakeTest {
    @Test fun wakeBypassesPassiveDelayOnceAndCoalescesAnAlreadyQueuedAttempt() {
        val queue = ArrayDeque<Runnable>()
        var attempts = 0
        var timers = 0
        val dispatcher = AndroidConnectionIntentAttemptDispatcher(
            execute = queue::addLast, persistedDelayMillis = { 300_000L },
            scheduleAfter = { timers++ }, attempt = { attempts++ })
        dispatcher.request()
        dispatcher.request(wake = true)
        dispatcher.request(wake = true)
        assertEquals(1, queue.size)
        queue.removeFirst().run()
        assertEquals(1, attempts)
        assertTrue(queue.isEmpty())
        assertEquals(0, timers)
        dispatcher.request()
        queue.removeFirst().run()
        assertEquals(1, attempts)
        assertEquals(1, timers)
    }

    @Test fun wakeDuringRunningAttemptDoesNotQueueASecondAttempt() {
        val queue = ArrayDeque<Runnable>()
        var attempts = 0
        lateinit var dispatcher: AndroidConnectionIntentAttemptDispatcher
        dispatcher = AndroidConnectionIntentAttemptDispatcher(
            execute = queue::addLast, persistedDelayMillis = { 0 }, scheduleAfter = { fail() },
            attempt = { attempts++; dispatcher.request(wake = true); dispatcher.request(wake = true) })
        dispatcher.request(wake = true)
        queue.removeFirst().run()
        assertEquals(1, attempts)
        assertTrue(queue.isEmpty())
    }
}
