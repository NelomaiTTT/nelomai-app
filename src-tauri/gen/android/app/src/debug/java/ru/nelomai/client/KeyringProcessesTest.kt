package ru.nelomai.client

import android.content.*
import android.os.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Hardware regression: two real processes must see each other's committed changes. */
class KeyringProcessesTest : android.app.Instrumentation() {
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); start() }
    override fun onStart() {
        val out = Bundle()
        val ready = CountDownLatch(1)
        var peer: IBinder? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) { peer = service; ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName?) { peer = null }
        }
        val prefs = targetContext.applicationContext.getSharedPreferences("keyring-default", 0)
        val suffix = java.util.UUID.randomUUID().toString()
        val a = "__nelomai_test_a_$suffix"
        val b = "__nelomai_test_b_$suffix"
        fun request(code: Int, key: String, value: String? = null): String? {
            val data = Parcel.obtain(); val reply = Parcel.obtain()
            try {
                data.writeString(key); data.writeString(value)
                check(requireNotNull(peer).transact(code, data, reply, 0))
                reply.readException(); return reply.readString()
            } finally { data.recycle(); reply.recycle() }
        }
        try {
            check(targetContext.bindService(Intent(targetContext, KeyringTestPeer::class.java), connection, Context.BIND_AUTO_CREATE))
            check(ready.await(5, TimeUnit.SECONDS))
            request(1, a) // Warm both process-local caches before either write.
            check(prefs.edit().putString(a, "owner").commit())
            request(2, b, "child")
            check(prefs.getString(b, null) == "child") { "owner_missed_child_commit" }
            check(request(1, a) == "owner") { "child_overwrote_owner_commit" }
            out.putString("result", "PASS: cross-process reads and disjoint writes preserved")
        } catch (e: Throwable) { out.putString("result", "FAIL: " + e.message) }
        finally {
            // Only disposable non-secret test entries; never clear the store.
            runCatching { request(3, a); request(3, b) }
            prefs.edit().remove(a).remove(b).commit()
            runCatching { targetContext.unbindService(connection) }
            targetContext.stopService(Intent(targetContext, KeyringTestPeer::class.java))
        }
        finish(0, out)
    }
}

class KeyringTestPeer : android.app.Service() {
    override fun onBind(intent: Intent?): IBinder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            require(Binder.getCallingUid() == Process.myUid())
            val key = requireNotNull(data.readString())
            require(key.startsWith("__nelomai_test_"))
            val value = data.readString()
            val prefs = applicationContext.getSharedPreferences("keyring-default", 0)
            val result = when(code) {
                1 -> prefs.getString(key, null)
                2 -> { check(prefs.edit().putString(key, value).commit()); "written" }
                3 -> { check(prefs.edit().remove(key).commit()); "removed" }
                else -> error("unsupported_test_operation")
            }
            reply!!.writeNoException(); reply.writeString(result); return true
        }
    }
}
