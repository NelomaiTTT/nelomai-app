package ru.nelomai.client

import android.content.Context
import java.io.File

object RuntimeNativeHost {
    init { System.loadLibrary("nelomai_android_container") }
    external fun nativeOpen(context: Context, dataRoot: String, resourceRoot: String, callbacks: RuntimeNativeCallbacks): Long
    external fun nativeSelection(host: Long): String
    /** Takes ownership of fd on success and failure; all identity fields are checked in Rust. */
    external fun nativeAttach(host: Long, fd: Int, peerPid: Int, peerUid: Int, request: String): String
    external fun nativeClose(host: Long)
}

object RuntimeContainerAssets {
    fun prepare(context: Context): File {
        val target = File(context.filesDir, "runtime-container")
        copy(context, "runtime", target)
        return target
    }
    private fun copy(context: Context, source: String, target: File) {
        val children = context.assets.list(source).orEmpty()
        if (children.isEmpty()) {
            target.parentFile!!.mkdirs()
            if (source.endsWith(".so") && source.contains("/jni/arm64-v8a/")) {
                // Hash the installed library that System.loadLibrary will use,
                // not merely a second asset copy with the expected filename.
                val libraries = File(context.applicationInfo.nativeLibraryDir).canonicalFile
                val installed = File(libraries, target.name).canonicalFile
                check(installed.parentFile == libraries && installed.isFile)
                installed.inputStream().use { input -> target.outputStream().use { input.copyTo(it) } }
            } else context.assets.open(source).use { input -> target.outputStream().use { input.copyTo(it) } }
        } else {
            target.mkdirs()
            children.forEach { name ->
                require(name != "." && name != ".." && '/' !in name && '\\' !in name)
                copy(context, "$source/$name", File(target, name))
            }
        }
    }
}
