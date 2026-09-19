package ru.nelomai.runtime.v1

import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.util.Properties

/** Cross-process native callback fence, not an auth record. A delayed Firebase
 * callback can never re-enable delivery after the common owner's revoke. */
class RuntimePushGate(private val dataRoot: File) {
    private fun <T> state(write: Boolean = false, action: (Properties) -> T): T = synchronized(processGate) {
        val directory = File(dataRoot, "common").apply { check(isDirectory || mkdirs()) }
        RandomAccessFile(File(directory, "push-v1.lock"), "rw").channel.use { channel -> channel.lock().use {
            val file = File(directory, "push-v1.properties")
            val properties = Properties()
            if (file.exists()) { check(file.length() <= 65536); file.inputStream().use(properties::load) }
            val result = action(properties)
            if (write) {
                val temporary = File(directory, "push-v1.pending")
                FileOutputStream(temporary).use { output -> properties.store(output, null); output.fd.sync() }
                check(temporary.renameTo(file)) { "push_state_write_failed" }
            }
            result
        } }
    }
    fun epoch(): Long = state { it.getProperty("epoch", "0").toLong() }
    fun enabled(): Boolean = state { it.getProperty("enabled", "false").toBoolean() }
    fun enable(epoch: Long): Boolean = state(true) {
        if (it.getProperty("epoch", "0").toLong() != epoch) false
        else { it.setProperty("enabled", "true"); true }
    }
    fun disable() { state(true) { it.setProperty("enabled", "false") } }
    fun revoke(epoch: Long) { state(true) {
        val current = it.getProperty("epoch", "0").toLong()
        it.setProperty("epoch", maxOf(Math.addExact(current, 1), epoch).toString())
        it.setProperty("enabled", "false"); it.remove("pending_token")
    } }
    fun pendingToken(): String? = state { it.getProperty("pending_token") }
    fun saveToken(token: String) { require(token.isNotBlank() && token.length <= 8192); state(true) { it.setProperty("pending_token", token) } }
    fun confirm(epoch: Long, token: String): Boolean = state(true) {
        if (it.getProperty("epoch", "0").toLong() != epoch || !it.getProperty("enabled", "false").toBoolean()) false
        else { if (it.getProperty("pending_token") == token) it.remove("pending_token"); true }
    }
    companion object { private val processGate = Any() }
}
