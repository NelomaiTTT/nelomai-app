package ru.nelomai.push

import android.content.Context
import com.google.firebase.messaging.FirebaseMessaging
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Called only by the common broker, not a runtime command. */
object CommonPushCleanup {
    @JvmStatic fun cleanup(context: Context): Boolean {
        FirebaseRuntime.disable(context)
        if (FirebaseRuntime.initialize(context) == null) return true
        val completion = CompletableFuture<Boolean>()
        FirebaseMessaging.getInstance().deleteToken().addOnCompleteListener { completion.complete(it.isSuccessful) }
        return completion.get(10, TimeUnit.SECONDS)
    }
}
