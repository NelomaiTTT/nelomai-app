package ru.nelomai.tunnel

import android.os.ParcelFileDescriptor
import java.io.IOException

/** Descriptor ownership only. Intent, recovery and readiness stay with their existing owners. */
internal class ServiceTunRetention(private var enabled: Boolean, private val changed: () -> Unit = {}) {
    private val gate = Any()
    private var epoch = 0L
    private var accepting = true
    private var destroyed = false
    private var usable = false
    private var armed = false
    private var startId: String? = null
    private var armedBeforeStart = false
    private var startRejected = false
    private var currentOwner: Any? = null
    private var current: ParcelFileDescriptor? = null
    private var source: (() -> ParcelFileDescriptor?)? = null
    private val owned = mutableListOf<ParcelFileDescriptor>()
    private var closeFailure: IOException? = null

    fun ticket(): Long = synchronized(gate) { epoch }

    fun allowStart(expectedEpoch: Long = ticket()) = synchronized(gate) {
        if (expectedEpoch != epoch) throw IOException("TUN start cancelled")
        closeFailure?.let { throw IOException("TUN cleanup unconfirmed", it) }
        if (destroyed) throw IOException("VPN owner closed")
        accepting = true
    }

    fun beginStart(id: String?) = synchronized(gate) {
        checkAccepting()
        if (id != null && startId == id) {
            if (startRejected) throw IOException("TUN start cancelled")
            return@synchronized
        }
        startId = id
        armedBeforeStart = armed
        startRejected = false
    }

    fun rejectStart(id: String, transportStopped: Boolean = false) = synchronized(gate) {
        if (startId != id || !accepting || destroyed) return@synchronized
        // A failed initial Start may have already observed a handshake. Roll back
        // only its new protection; recovery cannot disarm an earlier session.
        armed = armedBeforeStart
        startRejected = true
        if (transportStopped && !armed) release(owned.toList())
    }

    fun establish(owner: Any, establish: () -> ParcelFileDescriptor?): ParcelFileDescriptor? {
        val expected = synchronized(gate) {
            checkAccepting()
            epoch
        }
        // Android establishment may block. Stop fences its result without waiting for it.
        val tun = establish() ?: return null
        return synchronized(gate) {
            if (epoch != expected || !accepting || destroyed) {
                owned.add(tun)
                release(listOf(tun))
                throw IOException("TUN establishment cancelled")
            }
            currentOwner = owner
            source = null
            usable = false
            if (!enabled) return@synchronized tun
            // Keep the original; transfer only a duplicate to native. If duplication
            // fails during recovery, the newly established interface still has an owner.
            owned.add(tun)
            current = tun
            currentOwner = owner
            try {
                release(owned.filter { it !== tun })
                tun.dup()
            } catch (failure: Throwable) {
                if (!armed) {
                    try { release(listOf(tun)) }
                    catch (cleanup: Throwable) { if (cleanup !== failure) failure.addSuppressed(cleanup) }
                }
                throw failure
            }
        }
    }

    fun accepts(owner: Any, expectedEpoch: Long): Boolean = synchronized(gate) {
        if (expectedEpoch != epoch || !accepting || destroyed || closeFailure != null) return@synchronized false
        if (!enabled) return@synchronized currentOwner === owner
        currentOwner === owner && current?.fileDescriptor?.valid() == true
    }

    fun ready(owner: Any, expectedEpoch: Long = ticket()): Boolean {
        val needsCopy = synchronized(gate) {
            if (startRejected || expectedEpoch != epoch || !accepting || destroyed ||
                closeFailure != null || currentOwner !== owner) return false
            usable = true
            enabled && current?.fileDescriptor?.valid() != true
        }
        // Preference may have been enabled while this initial Start was pending.
        // Duplicate through the short backend gate without nesting descriptor locks.
        if (needsCopy) {
            try { setEnabled(true) }
            catch (_: IOException) { synchronized(gate) { usable = false }; return false }
        }
        return synchronized(gate) {
            if (startRejected || !accepts(owner, expectedEpoch)) return@synchronized false
            usable = true
            armed = enabled
            changed()
            true
        }
    }

    fun transportClosed(owner: Any) = synchronized(gate) {
        // An old backend must not release its replacement. Armed protection belongs
        // to the service, including after full native close or terminal recovery failure.
        if (currentOwner === owner) {
            usable = false
            if (!armed) release(owned.toList())
            changed()
        }
    }

    fun unavailable(owner: Any) = synchronized(gate) {
        if (currentOwner === owner) { usable = false; changed() }
    }

    fun state(): String = synchronized(gate) {
        when {
            closeFailure != null -> "unknown"
            !armed || !enabled -> "off"
            current?.fileDescriptor?.valid() != true -> "unknown"
            usable -> "armed"
            else -> "blocked"
        }
    }

    fun stopRequested(ticket: Long): Boolean = synchronized(gate) { !accepting && epoch == ticket && !destroyed }

    fun stopped(): Boolean = synchronized(gate) { !accepting && owned.isEmpty() }

    fun enabled(): Boolean = synchronized(gate) { enabled }

    fun registerSource(owner: Any, ticket: Long, duplicate: () -> ParcelFileDescriptor?) = synchronized(gate) {
        if (epoch == ticket && accepting && !destroyed && currentOwner === owner) source = duplicate
    }

    fun setEnabled(value: Boolean, duplicateActiveTun: (() -> ParcelFileDescriptor?)? = null) {
        var duplicate: (() -> ParcelFileDescriptor?)? = null
        val expected: Pair<Long, Any?> = synchronized(gate) {
            if (!value) {
                // The caller routes blocked disable through explicit Stop first.
                if (armed && !usable) throw IOException("Blocked protection requires local Stop")
                release(owned.toList())
                enabled = false
                armed = false
                armedBeforeStart = false
                changed()
                return
            }
            enabled = true // Explicit enable intent survives an arming failure.
            if (!usable || armed) return
            checkAccepting()
            duplicate = duplicateActiveTun ?: source
            epoch to currentOwner
        }
        // Acquire through the backend's short descriptor gate, outside this gate.
        val copy = duplicate?.invoke() ?: throw IOException("Active TUN unavailable")
        synchronized(gate) {
            owned.add(copy)
            if (epoch != expected.first || currentOwner !== expected.second ||
                !accepting || destroyed || !usable || !enabled) {
                release(listOf(copy))
                throw IOException("TUN enable cancelled")
            }
            current = copy
            armed = true
            changed()
        }
    }

    fun hasTun(): Boolean = synchronized(gate) { owned.isNotEmpty() }

    fun retryStop(expectedEpoch: Long): Boolean = synchronized(gate) {
        if (epoch != expectedEpoch || accepting) return@synchronized false
        release(owned.toList())
        owned.isEmpty()
    }

    fun stop(permanent: Boolean = false) = synchronized(gate) {
        if (accepting) epoch++
        accepting = false
        destroyed = destroyed || permanent
        armed = false
        usable = false
        startId = null
        source = null
        try { release(owned.toList()) } finally { changed() }
    }

    private fun checkAccepting() {
        closeFailure?.let { throw IOException("TUN cleanup unconfirmed", it) }
        if (!accepting || destroyed) throw IOException("VPN owner closed")
    }

    private fun release(descriptors: List<ParcelFileDescriptor>) {
        var failure: IOException? = null
        for (descriptor in descriptors) {
            try {
                val fd = descriptor.fileDescriptor
                descriptor.close()
                if (fd.valid()) throw IOException("TUN descriptor remained open")
                owned.remove(descriptor)
                if (current === descriptor) current = null
            } catch (error: IOException) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
        }
        if (failure != null || owned.isEmpty()) closeFailure = failure
        failure?.let { throw it }
    }
}
