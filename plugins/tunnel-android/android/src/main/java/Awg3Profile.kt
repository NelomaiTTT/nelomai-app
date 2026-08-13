package ru.nelomai.tunnel

import org.amnezia.awg.config.Interface
import java.security.MessageDigest

private val AWG3_PROFILE_FIELDS = listOf(
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "header_protection_key",
    "content_padding_addition",
)

private fun sha256(value: String): String = "sha256:" + MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(Charsets.UTF_8))
    .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

private fun protectedValue(field: String, value: String): String =
    if (field == "header_protection_key" && value.isNotEmpty()) sha256(value) else value

internal data class Awg3ProfileSnapshot(
    val values: Map<String, String>,
) {
    val fingerprint: String = sha256(canonical())

    val safeSummary: String = AWG3_PROFILE_FIELDS
        .filterNot { it == "header_protection_key" }
        .joinToString(" ") { field -> "$field=${values[field].orEmpty()}" } +
        " header_protection_key=${if (values["header_protection_key"].isNullOrEmpty()) "absent" else "present"}"

    fun differingFields(other: Awg3ProfileSnapshot): List<String> =
        AWG3_PROFILE_FIELDS.filter { values[it].orEmpty() != other.values[it].orEmpty() }

    private fun canonical(): String = AWG3_PROFILE_FIELDS
        .joinToString("\n") { field -> "$field=${values[field].orEmpty()}" }

    companion object {
        fun fromInterface(source: Interface): Awg3ProfileSnapshot = Awg3ProfileSnapshot(
            mapOf(
                "jc" to source.junkPacketCount.map { it.toString() }.orElse(""),
                "jmin" to source.junkPacketMinSize.map { it.toString() }.orElse(""),
                "jmax" to source.junkPacketMaxSize.map { it.toString() }.orElse(""),
                "s1" to source.initPacketJunkSize.map { it.toString() }.orElse(""),
                "s2" to source.responsePacketJunkSize.map { it.toString() }.orElse(""),
                "s3" to source.cookieReplyPacketJunkSize.map { it.toString() }.orElse(""),
                "s4" to source.transportPacketJunkSize.map { it.toString() }.orElse(""),
                "h1" to source.initPacketMagicHeader.orElse(""),
                "h2" to source.responsePacketMagicHeader.orElse(""),
                "h3" to source.underloadPacketMagicHeader.orElse(""),
                "h4" to source.transportPacketMagicHeader.orElse(""),
                "header_protection_key" to source.headerProtectionKey
                    .map { protectedValue("header_protection_key", it.toHex()) }
                    .orElse(""),
                "content_padding_addition" to source.contentPaddingAddition.orElse(""),
            ),
        )

        fun fromUserspace(runtimeConfig: String): Awg3ProfileSnapshot {
            val parsed = mutableMapOf<String, String>()
            runtimeConfig.lineSequence().forEach { line ->
                val separator = line.indexOf('=')
                if (separator <= 0) return@forEach
                val key = line.substring(0, separator).trim().lowercase()
                if (key in AWG3_PROFILE_FIELDS && key !in parsed) {
                    parsed[key] = protectedValue(
                        key,
                        line.substring(separator + 1).trim(),
                    )
                }
            }
            return Awg3ProfileSnapshot(parsed)
        }
    }
}
