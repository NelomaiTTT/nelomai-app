package ru.nelomai.runtime.v1

import android.app.Activity
import android.content.Intent
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Host-owned recovery UI; no runtime, credentials, selection writes or VPN actions. */
object RuntimeActivityRecovery {
    const val RETRY_BUTTON = 0x00d10007
    const val MANUAL_RETRY = "nelomai_manual_runtime_retry"
    const val OWNER_RECOVERY = "nelomai_owner_recovery"

    fun bootstrapIntent(activity: Activity): Intent =
        Intent().setClassName(activity.packageName, "ru.nelomai.client.RuntimeBootstrapActivity")

    @JvmOverloads
    fun showFailure(activity: Activity, allowRetry: Boolean, ownerRecovery: Boolean = false) {
        var dispatched = false
        activity.setContentView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 64, 32, 32)
            addView(TextView(activity).apply {
                text = if (allowRetry) "Не удалось запустить Nelomai. Повторите запуск. Данные сохранены."
                    else "Не удалось завершить запуск Nelomai. Данные сохранены. Откройте диагностику."
            })
            if (allowRetry) addView(Button(activity).apply {
                id = RETRY_BUTTON
                text = "Повторить"
                setOnClickListener {
                    if (!dispatched && !activity.isFinishing && !activity.isDestroyed) {
                        dispatched = true
                        isEnabled = false
                        // A fresh intent obtains a new owner snapshot and endpoint. Never
                        // forward consumed extras or invoke the runtime restart manager.
                        try {
                            val launch = bootstrapIntent(activity)
                            if (ownerRecovery) {
                                launch.putExtra(OWNER_RECOVERY, true).addFlags(Intent.FLAG_ACTIVITY_FORWARD_RESULT)
                            } else {
                                launch.putExtra(MANUAL_RETRY, true)
                            }
                            activity.startActivity(launch)
                            activity.finish()
                        } catch (_: RuntimeException) {
                            // Dispatch failed: keep a usable diagnostics screen, no loop.
                            text = "Не удалось повторить запуск"
                        }
                    }
                }
            })
            addView(Button(activity).apply {
                id = 0x00d10006
                text = "Диагностика"
                setOnClickListener { SupportDiagnosticsEntry.open(activity) }
            })
        })
    }
}
