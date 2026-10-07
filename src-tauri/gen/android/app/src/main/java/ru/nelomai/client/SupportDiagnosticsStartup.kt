package ru.nelomai.client

import android.app.Activity
import android.util.Log
import ru.nelomai.runtime.v1.RuntimeActivityRecovery

internal enum class SupportStartupStage(val code: String) {
    LAUNCHER_OWNER_START("startup.launcher.owner_start_failed"),
    LAUNCHER_OWNER_READ("startup.launcher.owner_read_failed"),
    BOOTSTRAP_OWNER_READ("startup.bootstrap.owner_read_failed"),
    BOOTSTRAP_PROCESS_CLAIM("startup.bootstrap.process_claim_failed"),
    BOOTSTRAP_OWNER_ATTACH("startup.bootstrap.owner_attach_failed"),
    BOOTSTRAP_ACTIVITY_PREPARE("startup.bootstrap.activity_prepare_failed"),
    BOOTSTRAP_ACTIVITY_START("startup.bootstrap.activity_start_failed"),
}

internal object SupportDiagnosticsStartup {
    const val OPEN_BUTTON = 0x00d10006
    fun showFailure(activity: Activity, stage: SupportStartupStage, error: Throwable) {
        val cause = (error as? java.lang.reflect.InvocationTargetException)?.targetException ?: error
        // Exception messages/bootstrap payloads can contain credentials. Log only a fixed stage and class.
        Log.e("NelomaiStartup", "code=${stage.code} error_class=${cause.javaClass.name}")
        RuntimeActivityRecovery.showFailure(activity, allowRetry = stage in setOf(
            SupportStartupStage.LAUNCHER_OWNER_START, SupportStartupStage.LAUNCHER_OWNER_READ,
            SupportStartupStage.BOOTSTRAP_OWNER_READ, SupportStartupStage.BOOTSTRAP_OWNER_ATTACH))
    }
}
