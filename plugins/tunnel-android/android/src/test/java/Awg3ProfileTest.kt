package ru.nelomai.tunnel

import org.amnezia.awg.config.Config
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class Awg3ProfileTest {
    @Test
    fun userspaceSnapshotMatchesParsedInterfaceWithoutExposingKey() {
        val config = parseConfig()
        val expected = Awg3ProfileSnapshot.fromInterface(config.getInterface())
        val runtime = Awg3ProfileSnapshot.fromUserspace(config.toAwgUserspaceString())

        assertEquals(expected.fingerprint, runtime.fingerprint)
        assertTrue(expected.differingFields(runtime).isEmpty())
        assertTrue(expected.values.getValue("header_protection_key").startsWith("sha256:"))
        assertTrue(expected.safeSummary.contains("s1=132"))
        assertTrue(expected.safeSummary.contains("header_protection_key=present"))
        assertFalse(expected.safeSummary.contains("02020202"))
    }

    @Test
    fun mismatchNamesOnlySafeProfileFields() {
        val expected = Awg3ProfileSnapshot.fromInterface(parseConfig().getInterface())
        val runtime = Awg3ProfileSnapshot.fromUserspace(
            parseConfig().toAwgUserspaceString().replace("s1=132", "s1=167"),
        )

        assertNotEquals(expected.fingerprint, runtime.fingerprint)
        assertEquals(listOf("s1"), expected.differingFields(runtime))
    }

    private fun parseConfig(): Config = Config.parse(
        ByteArrayInputStream(
            """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.240.3.2/32
            Jc = 5
            Jmin = 48
            Jmax = 192
            S1 = 132
            S2 = 67
            S3 = 28
            S4 = 30
            H1 = 2853124550-2853128645
            H2 = 2853128646-2853132741
            H3 = 2853132742-2853136837
            H4 = 2853136838-2853140933
            HeaderProtectionKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
            ContentPaddingAddition = 0-32

            [Peer]
            PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:20003
            """.trimIndent().toByteArray(),
        ),
    )
}
