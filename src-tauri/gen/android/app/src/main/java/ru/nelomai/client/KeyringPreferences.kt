package ru.nelomai.client

import android.content.*
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.Process

/** Rust's Android keyring receives applicationContext in both owner and runtime.
 * Keep one SharedPreferences cache/writer for its encrypted vault, across processes.
 * Keystore encryption, record names and on-disk format remain unchanged. */
class NelomaiApplication : android.app.Application() {
    internal fun ownerKeyringPreferences(): SharedPreferences =
        super.getSharedPreferences("keyring-default", Context.MODE_PRIVATE)
    override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
        if (name == "keyring-default") KeyringPreferences(contentResolver, packageName)
        else super.getSharedPreferences(name, mode)
}

class KeyringPreferencesProvider : ContentProvider() {
    override fun onCreate() = true
    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        check(Binder.getCallingUid() == Process.myUid()) { "keyring_caller_rejected" }
        // Bypass the remote facade only inside the single owner process.
        val prefs = (requireNotNull(context).applicationContext as NelomaiApplication).ownerKeyringPreferences()
        return synchronized(this) {
            when (method) {
                "read" -> Bundle().apply {
                    val key = requireNotNull(arg)
                    putBoolean("present", prefs.contains(key))
                    putString("value", prefs.getString(key, null))
                }
                "all" -> Bundle().apply {
                    for ((key, value) in prefs.all) putString(key, value as String?)
                }
                "commit" -> {
                    val changes = requireNotNull(extras)
                    val editor = prefs.edit()
                    for (key in changes.keySet()) {
                        val value = changes.getString(key)
                        if (value == null) editor.remove(key) else editor.putString(key, value)
                    }
                    Bundle().apply { putBoolean("committed", editor.commit()) }
                }
                else -> throw IllegalArgumentException("keyring_operation_rejected")
            }
        }
    }
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = throw UnsupportedOperationException()
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
}

/** String-only API used by android-native-keyring-store. No local value cache. */
private class KeyringPreferences(private val resolver: ContentResolver, packageName: String) : SharedPreferences {
    private val uri = Uri.parse("content://$packageName.keyring-preferences")
    private fun call(method: String, key: String? = null, changes: Bundle? = null): Bundle =
        requireNotNull(resolver.call(uri, method, key, changes)) { "keyring_owner_unavailable" }
    override fun getAll(): MutableMap<String, *> = call("all").let { data ->
        data.keySet().associateWith { data.getString(it) }.toMutableMap()
    }
    override fun getString(key: String?, defValue: String?): String? {
        val result = call("read", requireNotNull(key))
        return if (result.getBoolean("present")) result.getString("value") else defValue
    }
    override fun contains(key: String?): Boolean = call("read", requireNotNull(key)).getBoolean("present")
    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        private val changes = Bundle()
        override fun putString(key: String?, value: String?): SharedPreferences.Editor = apply { changes.putString(requireNotNull(key), value) }
        override fun remove(key: String?): SharedPreferences.Editor = putString(key, null)
        override fun commit(): Boolean = call("commit", changes = changes).getBoolean("committed")
        override fun apply() { check(commit()) { "keyring_commit_failed" } }
        override fun clear(): SharedPreferences.Editor = throw UnsupportedOperationException("keyring_bulk_clear_rejected")
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = throw UnsupportedOperationException()
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor = throw UnsupportedOperationException()
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor = throw UnsupportedOperationException()
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = throw UnsupportedOperationException()
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = throw UnsupportedOperationException()
    }
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = throw UnsupportedOperationException()
    override fun getInt(key: String?, defValue: Int): Int = throw UnsupportedOperationException()
    override fun getLong(key: String?, defValue: Long): Long = throw UnsupportedOperationException()
    override fun getFloat(key: String?, defValue: Float): Float = throw UnsupportedOperationException()
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = throw UnsupportedOperationException()
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = throw UnsupportedOperationException()
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = throw UnsupportedOperationException()
}
