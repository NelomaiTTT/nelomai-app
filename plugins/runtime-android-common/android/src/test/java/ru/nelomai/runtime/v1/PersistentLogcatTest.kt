package ru.nelomai.runtime.v1

import org.junit.Assert.*
import org.junit.Test
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class PersistentLogcatTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun onlyBrokerCollectsWhileRuntimeAndVpnRemainFreeToFreeze() {
        val root = temporary.newFolder()
        for (process in listOf("ru.nelomai.client:runtime", "ru.nelomai.client:vpn", null, "")) {
            PersistentLogcat.collectInProcess(process, "ru.nelomai.client") {
                LogcatJournal(root).append("unexpected child collector")
            }
        }
        assertEquals("", LogcatJournal.snapshot(root))
        PersistentLogcat.collectInProcess("ru.nelomai.client", "ru.nelomai.client") {
            LogcatJournal(root).append("broker initial")
        }
        // A restarted broker resumes the persisted journal, without needing a
        // waiter thread in another process or a new service binding.
        PersistentLogcat.collectInProcess("ru.nelomai.client", "ru.nelomai.client") {
            LogcatJournal(root).append("broker restarted")
        }
        assertEquals("broker initial\nbroker restarted\n", LogcatJournal.snapshot(root))
    }

    @Test fun commandIsCompatibleWithOldAndroidAndCapturesStartupAcrossProcesses() {
        assertFalse(PersistentLogcat.command(24, 12345).any { it.startsWith("--uid") })
        assertFalse(PersistentLogcat.command(30, 12345).any { it.startsWith("--uid") })
        assertTrue(PersistentLogcat.command(31, 12345).contains("--uid=12345"))
        assertTrue(PersistentLogcat.command(36, 12345).contains("*:V"))
        assertFalse(PersistentLogcat.command(36, 12345).any { it.startsWith("--pid") })
    }

    @Test fun rotationKeepsTwoBoundedSegmentsAcrossReopen() {
        val root = temporary.newFolder()
        LogcatJournal(root, 64).also { journal ->
            repeat(20) { journal.append("event-$it ${"x".repeat(20)}") }
        }
        val text = LogcatJournal.snapshot(root, 128)
        assertTrue(text.contains("event-19"))
        assertFalse(text.contains("event-0 "))
        assertTrue(text.toByteArray().size <= 128)
        LogcatJournal(root, 64).append("reopened")
        assertTrue(LogcatJournal.snapshot(root, 128).endsWith("reopened\n"))
    }

    @Test fun secretsAreRemovedBeforeTheyReachDisk() {
        val root = temporary.newFolder()
        LogcatJournal(root).also { journal ->
            journal.append("Authorization: Bearer secret-value")
            journal.append("{\"refresh_token\":\"refresh-secret\",\"password\":\"two words\"}")
            journal.append("PrivateKey = private-material")
            journal.append("https://host.test/path?token=query-secret#fragment")
            journal.append("owner.open duration_ms=12 ready=true")
        }
        val text = LogcatJournal.snapshot(root)
        for (secret in listOf("secret-value", "refresh-secret", "two words", "private-material", "query-secret", "fragment")) {
            assertFalse(secret, text.contains(secret))
        }
        assertTrue(text.contains("owner.open duration_ms=12 ready=true"))
    }

    @Test fun longUtf8LinesRemainBoundedAndValid() {
        val root = temporary.newFolder()
        LogcatJournal(root, 64).append("я".repeat(5000))
        val text = LogcatJournal.snapshot(root, 128)
        assertTrue(text.toByteArray().size <= 64)
        assertFalse(text.contains('\uFFFD'))
        assertTrue(text.endsWith("\n"))
    }

    @Test fun snapshotsDuringRotationStayValidAndBounded() {
        val root = temporary.newFolder()
        val writer = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val writing = writer.submit {
                val journal = LogcatJournal(root, 128)
                repeat(500) { journal.append("событие $it готово") }
            }
            repeat(100) {
                val text = LogcatJournal.snapshot(root, 256)
                assertTrue(text.toByteArray(Charsets.UTF_8).size <= 256)
                assertFalse(text.contains('\uFFFD'))
                assertTrue(text.isEmpty() || text.endsWith("\n"))
            }
            writing.get(10, java.util.concurrent.TimeUnit.SECONDS)
            assertTrue(LogcatJournal.snapshot(root).contains("событие 499 готово"))
        } finally { writer.shutdownNow() }
    }

    @Test fun multilineKeyAndTokenMaterialIsNotRetained() {
        assertFalse(sanitizeLogcatLine("I tag: ${"A".repeat(43)}=").contains("A".repeat(43)))
        assertFalse(sanitizeLogcatLine("I tag: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature").contains("eyJhbGci"))
        assertFalse(sanitizeLogcatLine("I tag: cookie: session=abc; other=xyz").contains("abc"))
        assertFalse(sanitizeLogcatLine("I tag: ${"Abcd0123".repeat(8)}").contains("Abcd0123"))
    }

    @Test fun escapedJsonSecretsAreRedacted() {
        val value = """I tag: body="{\"password\":\"short secret\"}""""
        assertFalse(sanitizeLogcatLine(value).contains("short secret"))
    }
}
