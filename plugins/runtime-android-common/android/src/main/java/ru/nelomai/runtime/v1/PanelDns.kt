package ru.nelomai.runtime.v1

import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Locale
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Explicit routing marker: retain the HTTPS URL/identity and replace only DNS. */
object PanelDirectIpRoute

class PanelDns(private val systemLookup: (String) -> List<InetAddress> = { InetAddress.getAllByName(it).toList() }) {
    private val inFlight = ConcurrentHashMap<String, FutureTask<List<InetAddress>>>()

    fun lookup(hostname: String): List<InetAddress> {
        val key = hostname.lowercase(Locale.ROOT)
        if (!isPanelHost(key)) return systemLookup(hostname)
        val candidate = object : FutureTask<List<InetAddress>>(Callable { systemLookup(hostname) }) {
            override fun done() { inFlight.remove(key, this) }
        }
        val task = inFlight.putIfAbsent(key, candidate) ?: candidate.also { workers.execute(it) }
        try {
            return task.get(1, TimeUnit.SECONDS).takeIf { it.isNotEmpty() }
                ?: throw UnknownHostException("Empty panel DNS answer")
        } catch (error: TimeoutException) {
            // OS resolution may ignore interrupts. Keep this one job shared until it finishes.
            throw UnknownHostException("Panel DNS deadline").apply { initCause(error) }
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw UnknownHostException("Panel DNS interrupted").apply { initCause(error) }
        } catch (error: ExecutionException) {
            throw (error.cause ?: error)
        } finally {
            if (task.isDone) inFlight.remove(key, task)
        }
    }

    fun directAddresses(hostname: String): List<InetAddress> {
        if (!isPanelHost(hostname)) throw UnknownHostException("No direct address for this host")
        return listOf(InetAddress.getByAddress(hostname, byteArrayOf(45, 144.toByte(), 221.toByte(), 68)))
    }

    companion object {
        private val workers = Executors.newFixedThreadPool(2) { task ->
            Thread(task, "panel-dns").apply { isDaemon = true }
        }
        val Default = PanelDns()
        fun isPanelHost(hostname: String): Boolean = hostname.equals("nelomai.ru", true) || hostname.equals("nelomai.top", true)
    }
}
