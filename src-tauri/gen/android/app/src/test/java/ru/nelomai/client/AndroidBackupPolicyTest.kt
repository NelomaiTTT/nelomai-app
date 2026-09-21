package ru.nelomai.client

import android.content.res.XmlResourceParser
import androidx.annotation.XmlRes
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AndroidBackupPolicyTest {
    @Test
    fun preAndroid12BackupExcludesOperationalDataButKeepsFilePreferencesEligible() {
        val policy = policy(R.xml.diagnostics_backup_rules)

        assertFalse(policy.isBackupEligible("full-backup", "sharedpref", "keyring-default.xml"))
        assertFalse(policy.isBackupEligible("full-backup", "sharedpref", "nelomai-connection-recovery.xml"))
        assertFalse(policy.isBackupEligible("full-backup", "sharedpref", "runtime.latest.state.0.2.20.nelomai-background-credential.xml"))
        assertFalse(policy.isBackupEligible("full-backup", "sharedpref", "runtime.stable.state.0.2.19.native-migration-receipt-nelomai-quick-tunnel-plan.xml"))
        assertFalse(policy.isBackupEligible("full-backup", "file", "runtime-container"))
        assertFalse(policy.isBackupEligible("full-backup", "file", "runtime-container/lib/runtime.so"))
        assertFalse(policy.isBackupEligible("full-backup", "file", "common/runtime-inventory-v1.json"))
        assertFalse(policy.isBackupEligible("full-backup", "file", "common/push-v1.properties"))
        assertFalse(policy.isBackupEligible("full-backup", "file", "diagnostics/automatic/report.json"))
        assertFalse(policy.isBackupEligible("full-backup", "file", "runtime/latest/state/session.json"))
        assertFalse(policy.isBackupEligible("full-backup", "file", "runtime/stable/state/session.json"))
        assertTrue(policy.isBackupEligible("full-backup", "file", "preferences.json"))
        assertTrue(policy.isBackupEligible("full-backup", "file", "runtime/latest/preferences-v1.json"))
        assertTrue(policy.isBackupEligible("full-backup", "file", "runtime/stable/0.2.19/preferences-v1.json"))
    }

    @Test
    fun android12CloudAndDeviceTransferApplyTheSameBoundedExclusions() {
        val policy = policy(R.xml.diagnostics_data_extraction_rules)

        for (destination in listOf("cloud-backup", "device-transfer")) {
            assertFalse(policy.isBackupEligible(destination, "sharedpref", "keyring-default.xml"))
            assertFalse(policy.isBackupEligible(destination, "sharedpref", "nelomai-background-credential.xml"))
            assertFalse(policy.isBackupEligible(destination, "sharedpref", "runtime.latest.state.0.2.21.nelomai-quick-tunnel-plan.xml"))
            assertFalse(policy.isBackupEligible(destination, "sharedpref", "runtime.stable.state.0.2.18.native-migration-receipt-nelomai-connection-recovery.xml"))
            assertFalse(policy.isBackupEligible(destination, "file", "runtime-container"))
            assertFalse(policy.isBackupEligible(destination, "file", "runtime-container/lib/runtime.so"))
            assertFalse(policy.isBackupEligible(destination, "file", "common/auth-migration-v1.json"))
            assertFalse(policy.isBackupEligible(destination, "file", "common/owner.lock"))
            assertFalse(policy.isBackupEligible(destination, "file", "diagnostics/automatic/report.json"))
            assertFalse(policy.isBackupEligible(destination, "file", "runtime/latest/state/session.json"))
            assertFalse(policy.isBackupEligible(destination, "file", "runtime/stable/state/session.json"))
            assertTrue(policy.isBackupEligible(destination, "file", "preferences.json"))
            assertTrue(policy.isBackupEligible(destination, "file", "runtime/latest/preferences-v1.json"))
            assertTrue(policy.isBackupEligible(destination, "file", "runtime/stable/0.2.17/preferences-v1.json"))
        }
    }

    private fun policy(@XmlRes resource: Int): BackupPolicy {
        val rules = mutableListOf<BackupRule>()
        RuntimeEnvironment.getApplication().resources.getXml(resource).use { parser ->
            var destination = "full-backup"
            while (parser.next() != XmlResourceParser.END_DOCUMENT) {
                if (parser.eventType != XmlResourceParser.START_TAG) continue
                when (parser.name) {
                    "cloud-backup", "device-transfer" -> destination = parser.name
                    "include", "exclude" -> rules += BackupRule(
                        destination = destination,
                        domain = parser.getAttributeValue(null, "domain"),
                        path = parser.getAttributeValue(null, "path").trimEnd('/'),
                        included = parser.name == "include",
                    )
                }
            }
        }
        return BackupPolicy(rules)
    }

    private data class BackupRule(
        val destination: String,
        val domain: String,
        val path: String,
        val included: Boolean,
    )

    private class BackupPolicy(private val rules: List<BackupRule>) {
        fun isBackupEligible(destination: String, domain: String, path: String): Boolean {
            val destinationRules = rules.filter { it.destination == destination }
            val inclusions = destinationRules.filter { it.included }
            if (inclusions.isNotEmpty() && inclusions.none { it.matches(domain, path) }) return false
            return destinationRules.none { !it.included && it.matches(domain, path) }
        }

        private fun BackupRule.matches(candidateDomain: String, candidatePath: String): Boolean {
            if (domain != candidateDomain) return false
            val normalizedRule = path.trim('/')
            val normalizedCandidate = candidatePath.trim('/')
            return normalizedRule.isEmpty() || normalizedRule == "." ||
                normalizedCandidate == normalizedRule || normalizedCandidate.startsWith("$normalizedRule/")
        }
    }
}
