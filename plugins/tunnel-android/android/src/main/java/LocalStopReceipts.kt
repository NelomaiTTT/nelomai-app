package ru.nelomai.tunnel

import android.content.Context
import java.io.File
import java.io.IOException
import java.util.UUID

/** Cross-process completion for a waiting Stop when its ResultReceiver reply is lost. */
internal class LocalStopReceipts(private val directory: File) {
    fun create(): String? = runCatching {
        if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) return null
        val staleBefore = System.currentTimeMillis() - 10 * 60_000L
        directory.listFiles()?.forEach { if (it.lastModified() < staleBefore) it.delete() }
        val id = UUID.randomUUID().toString()
        id.takeIf { pending(it).createNewFile() }
    }.getOrNull()

    fun confirm(id: String?) {
        if (id == null) return
        runCatching {
            if (UUID.fromString(id).toString() == id) pending(id).renameTo(confirmed(id))
        }
    }

    fun consume(id: String?): Boolean {
        if (id == null) return false
        return runCatching {
            // Delete pending first: a late service completion cannot then
            // publish a receipt after the caller has removed its files.
            pending(id).delete()
            val receipt = confirmed(id)
            val stopped = receipt.isFile
            receipt.delete()
            stopped
        }.getOrDefault(false)
    }

    fun invalidateConfirmed() {
        if (!directory.exists()) return
        val receipts = directory.listFiles { _, name -> name.startsWith("confirmed-") }
            ?: throw IOException("Local Stop receipts cannot be read")
        for (receipt in receipts) {
            if (!receipt.delete() && receipt.exists()) throw IOException("Local Stop receipt cannot be invalidated")
        }
    }

    private fun pending(id: String) = File(directory, "pending-$id")
    private fun confirmed(id: String) = File(directory, "confirmed-$id")

    companion object {
        fun open(context: Context) =
            LocalStopReceipts(File(context.cacheDir, AndroidRuntimeNamespace.record("local-stop-receipts")))
    }
}
