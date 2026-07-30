package ru.nelomai.tunnel

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.text.Collator
import java.util.Locale

data class InstalledApplication(
    val packageId: String,
    val displayName: String,
    val system: Boolean,
)

internal data class InstalledApplicationCandidate(
    val packageId: String,
    val displayName: String,
    val system: Boolean,
)

internal object InstalledApplications {
    fun query(context: Context): List<InstalledApplication> {
        val packageManager = context.packageManager
        val applications = linkedMapOf<String, ApplicationInfo>()
        installedApplications(packageManager).forEach { application ->
            applications[application.packageName] = application
        }
        launcherApplications(packageManager).forEach { application ->
            applications.putIfAbsent(application.packageName, application)
        }

        val candidates = applications.values.map { application ->
            InstalledApplicationCandidate(
                packageId = application.packageName,
                displayName = safeLabel(packageManager, application),
                system = application.flags and (
                    ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                ) != 0,
            )
        }
        return normalize(candidates, context.packageName)
    }

    internal fun normalize(
        candidates: List<InstalledApplicationCandidate>,
        ownPackageId: String,
        locale: Locale = Locale.getDefault(),
    ): List<InstalledApplication> {
        val collator = Collator.getInstance(locale).apply {
            strength = Collator.PRIMARY
        }
        return candidates
            .asSequence()
            .filter { it.packageId.isNotBlank() && it.packageId != ownPackageId }
            .groupBy { it.packageId }
            .map { (packageId, duplicates) ->
                val displayName = duplicates
                    .asSequence()
                    .map { it.displayName.trim().ifEmpty { packageId } }
                    .sortedWith { left, right ->
                        collator.compare(left, right).takeIf { it != 0 }
                            ?: left.compareTo(right)
                    }
                    .first()
                InstalledApplication(
                    packageId = packageId,
                    displayName = displayName,
                    system = duplicates.any { it.system },
                )
            }
            .sortedWith { left, right ->
                collator.compare(left.displayName, right.displayName).takeIf { it != 0 }
                    ?: left.packageId.compareTo(right.packageId)
            }
    }

    private fun safeLabel(
        packageManager: PackageManager,
        application: ApplicationInfo,
    ): String = runCatching {
        packageManager.getApplicationLabel(application).toString().trim()
    }.getOrNull().orEmpty().ifEmpty { application.packageName }

    @Suppress("DEPRECATION")
    private fun installedApplications(packageManager: PackageManager): List<ApplicationInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
        } else {
            packageManager.getInstalledApplications(0)
        }

    @Suppress("DEPRECATION")
    private fun launcherApplications(packageManager: PackageManager): List<ApplicationInfo> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val activities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(
                launcherIntent,
                PackageManager.ResolveInfoFlags.of(0),
            )
        } else {
            packageManager.queryIntentActivities(launcherIntent, 0)
        }
        return activities.mapNotNull { it.activityInfo?.applicationInfo }
    }
}
