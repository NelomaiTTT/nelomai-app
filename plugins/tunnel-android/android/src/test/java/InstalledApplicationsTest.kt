package ru.nelomai.tunnel

import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test

class InstalledApplicationsTest {
    @Test
    fun normalizesDuplicatesClassificationAndLocalizedOrder() {
        val applications = InstalledApplications.normalize(
            candidates = listOf(
                InstalledApplicationCandidate(
                    packageId = "ru.nelomai.app",
                    displayName = "Nelomai",
                    system = false,
                ),
                InstalledApplicationCandidate(
                    packageId = "com.example.beta",
                    displayName = "Beta",
                    system = false,
                ),
                InstalledApplicationCandidate(
                    packageId = "com.example.alpha",
                    displayName = "alpha",
                    system = false,
                ),
                InstalledApplicationCandidate(
                    packageId = "com.example.system",
                    displayName = "System",
                    system = false,
                ),
                InstalledApplicationCandidate(
                    packageId = "com.example.system",
                    displayName = "System",
                    system = true,
                ),
                InstalledApplicationCandidate(
                    packageId = "com.example.fallback",
                    displayName = "   ",
                    system = false,
                ),
            ),
            ownPackageId = "ru.nelomai.app",
            locale = Locale.ENGLISH,
        )

        assertEquals(
            listOf(
                InstalledApplication(
                    packageId = "com.example.alpha",
                    displayName = "alpha",
                    system = false,
                ),
                InstalledApplication(
                    packageId = "com.example.beta",
                    displayName = "Beta",
                    system = false,
                ),
                InstalledApplication(
                    packageId = "com.example.fallback",
                    displayName = "com.example.fallback",
                    system = false,
                ),
                InstalledApplication(
                    packageId = "com.example.system",
                    displayName = "System",
                    system = true,
                ),
            ),
            applications,
        )
    }
}
