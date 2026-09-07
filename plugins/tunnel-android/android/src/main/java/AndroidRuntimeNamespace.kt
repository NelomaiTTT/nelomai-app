package ru.nelomai.tunnel

import android.content.Context
import java.io.File

/** Artifact compile-time identity, never derived from Intent/UI preferences. */
internal object AndroidRuntimeNamespace {
    val slot: String get() = BuildConfig.RUNTIME_SLOT
    val version: String get() = BuildConfig.RUNTIME_VERSION
    fun record(name: String): String = "runtime.$slot.state.$version.$name"
    fun directory(context: Context): File = File(context.filesDir, "runtime/$slot/state/$version")
}
