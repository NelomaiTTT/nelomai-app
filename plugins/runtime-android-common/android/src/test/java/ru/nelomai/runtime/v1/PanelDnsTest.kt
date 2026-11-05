package ru.nelomai.runtime.v1

import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class PanelDnsTest {
    @Test fun healthyDnsWinsAndCompletedAnswersAreNotCached() {
        val calls = AtomicInteger()
        val dns = PanelDns { listOf(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, calls.incrementAndGet().toByte()))) }
        for (index in 1..3) assertEquals("192.0.2.$index", dns.lookup("nelomai.ru").single().hostAddress)
        assertEquals(3, calls.get())
    }

    @Test fun failedAndEmptyDnsNeverInsertTheIpBeforeTheExplicitLastRoute() {
        for (empty in listOf(false, true)) {
            val dns = PanelDns { if (empty) emptyList() else throw UnknownHostException("outage") }
            for (host in listOf("nelomai.ru", "nelomai.top")) {
                assertThrows(UnknownHostException::class.java) { dns.lookup(host) }
                assertEquals("45.144.221.68", dns.directAddresses(host).single().hostAddress)
            }
        }
    }

    @Test fun directIpDoesNotResolveAndIsRestrictedToExactPanelNames() {
        val dns = PanelDns { error("direct IP must not use DNS") }
        assertEquals("45.144.221.68", dns.directAddresses("NELOMAI.TOP").single().hostAddress)
        for (host in listOf("example.test", "x.nelomai.ru", "nelomai.top.evil.test")) {
            assertThrows(UnknownHostException::class.java) { dns.directAddresses(host) }
        }
    }

    @Test fun unrelatedHostsKeepTheirOrdinaryLookup() {
        var observed = ""
        val dns = PanelDns { host -> observed = host; throw UnknownHostException("normal failure") }
        assertThrows(UnknownHostException::class.java) { dns.lookup("private-panel.test") }
        assertEquals("private-panel.test", observed)
    }

    @Test fun stalledLookupIsBoundedAndCoalescedAcrossConcurrentAndLaterCallers() {
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val dns = PanelDns { calls.incrementAndGet(); release.await(); listOf(InetAddress.getLoopbackAddress()) }
        val callers = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        try {
            val futures = (1..8).map { callers.submit<Boolean> {
                start.await()
                try { dns.lookup("nelomai.ru"); false } catch (_: UnknownHostException) { true }
            } }
            start.countDown()
            for (future in futures) assertTrue(future.get(3, TimeUnit.SECONDS))
            assertEquals(1, calls.get())
            assertThrows(UnknownHostException::class.java) { dns.lookup("nelomai.ru") }
            assertEquals("a timed-out OS query must not spawn another job", 1, calls.get())
            assertEquals("45.144.221.68", dns.directAddresses("nelomai.ru").single().hostAddress)
        } finally { release.countDown(); callers.shutdownNow() }
    }

    @Test fun interruptedWaitPreservesCancellationWithoutAnIpAnswer() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val outcome = java.util.concurrent.CompletableFuture<Boolean>()
        val dns = PanelDns { entered.countDown(); release.await(); emptyList() }
        val caller = Thread {
            try { dns.lookup("nelomai.top"); outcome.complete(false) }
            catch (_: UnknownHostException) { outcome.complete(Thread.currentThread().isInterrupted) }
        }
        try {
            caller.start(); assertTrue(entered.await(1, TimeUnit.SECONDS)); caller.interrupt()
            assertTrue(outcome.get(1, TimeUnit.SECONDS))
        } finally { release.countDown(); caller.join(1000) }
    }
}
