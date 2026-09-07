package ru.nelomai.client

import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class RuntimeApkValidationTest {
    @Test fun rejectsSiblingPathsAndMismatchedInstalledSigners() {
        val root = Files.createTempDirectory("runtime-apk-test").toFile()
        try {
            val updates = root.resolve("updates").apply { mkdir() }
            val apk = updates.resolve("update.apk").apply { writeBytes(byteArrayOf(1)) }
            val sibling = root.resolve("other.apk").apply { writeBytes(byteArrayOf(1)) }
            assertEquals(apk.canonicalFile, RuntimeApkValidation.path(updates, apk.path))
            assertThrows(IllegalArgumentException::class.java) { RuntimeApkValidation.path(updates, sibling.path) }
            assertTrue(RuntimeApkValidation.signers(setOf("a".repeat(64)), setOf("a".repeat(64)), "a".repeat(64)))
            assertFalse(RuntimeApkValidation.signers(setOf("a".repeat(64)), setOf("b".repeat(64)), "a".repeat(64)))
            assertFalse(RuntimeApkValidation.signers(emptySet(), emptySet(), "a".repeat(64)))
        } finally { root.deleteRecursively() }
    }
}
