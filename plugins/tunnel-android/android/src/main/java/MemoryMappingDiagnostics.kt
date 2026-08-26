package ru.nelomai.tunnel

internal data class AutomaticDiagnosticsSmapsRollup(
    val residentBytes: Long,
    val proportionalBytes: Long,
    val privateCleanBytes: Long,
    val privateDirtyBytes: Long,
    val sharedCleanBytes: Long,
    val sharedDirtyBytes: Long,
    val swapBytes: Long,
    val swapProportionalBytes: Long,
)

internal data class AutomaticDiagnosticsMemoryMapping(
    val category: String,
    val name: String,
    val residentBytes: Long,
    val proportionalBytes: Long,
    val privateCleanBytes: Long,
    val privateDirtyBytes: Long,
    val sharedCleanBytes: Long,
    val sharedDirtyBytes: Long,
    val swapBytes: Long,
    val swapProportionalBytes: Long,
    val executable: Boolean,
)

internal data class AutomaticDiagnosticsMemoryCategory(
    val category: String,
    val residentBytes: Long,
    val proportionalBytes: Long,
    val privateCleanBytes: Long,
    val privateDirtyBytes: Long,
    val sharedCleanBytes: Long,
    val sharedDirtyBytes: Long,
    val swapBytes: Long,
    val swapProportionalBytes: Long,
)

internal data class AutomaticDiagnosticsSmapsSummary(
    val mappingCount: Int,
    val mappingGroupCount: Int,
    val topMappings: List<AutomaticDiagnosticsMemoryMapping>,
    val categories: List<AutomaticDiagnosticsMemoryCategory>,
)

private data class MutableAutomaticDiagnosticsMemoryMapping(
    val category: String,
    val name: String,
    var residentBytes: Long = 0,
    var proportionalBytes: Long = 0,
    var privateCleanBytes: Long = 0,
    var privateDirtyBytes: Long = 0,
    var sharedCleanBytes: Long = 0,
    var sharedDirtyBytes: Long = 0,
    var swapBytes: Long = 0,
    var swapProportionalBytes: Long = 0,
    var executable: Boolean = false,
)

private val SMAPS_HEADER = Regex(
    "^[0-9a-fA-F]+-[0-9a-fA-F]+\\s+([rwxps-]{4})\\s+\\S+\\s+\\S+\\s+\\d+\\s*(.*)$",
)

internal fun automaticDiagnosticsParseSmapsRollup(
    lines: Sequence<String>,
): AutomaticDiagnosticsSmapsRollup {
    val metrics = mutableMapOf<String, Long>()
    val fields = setOf(
        "Rss",
        "Pss",
        "Private_Clean",
        "Private_Dirty",
        "Shared_Clean",
        "Shared_Dirty",
        "Swap",
        "SwapPss",
    )
    lines.forEach { line ->
        val field = line.substringBefore(':')
        if (field in fields) {
            automaticDiagnosticsStatusMemoryBytes(line, field)?.let { metrics[field] = it }
        }
    }
    return AutomaticDiagnosticsSmapsRollup(
        residentBytes = metrics["Rss"] ?: 0,
        proportionalBytes = metrics["Pss"] ?: 0,
        privateCleanBytes = metrics["Private_Clean"] ?: 0,
        privateDirtyBytes = metrics["Private_Dirty"] ?: 0,
        sharedCleanBytes = metrics["Shared_Clean"] ?: 0,
        sharedDirtyBytes = metrics["Shared_Dirty"] ?: 0,
        swapBytes = metrics["Swap"] ?: 0,
        swapProportionalBytes = metrics["SwapPss"] ?: 0,
    )
}

private fun safeMappingIdentity(path: String): Pair<String, String> {
    val normalized = path.removeSuffix(" (deleted)").trim()
    if (normalized.isEmpty()) return "anonymous" to "[anonymous]"
    if (normalized.startsWith("[")) {
        return when {
            normalized == "[heap]" -> "heap" to "[heap]"
            normalized.startsWith("[stack") -> "stack" to "[stack]"
            normalized.startsWith("[anon:") -> "anonymous" to normalized.take(96)
            normalized in setOf("[vdso]", "[vvar]", "[vectors]") -> {
                "runtime_code" to normalized
            }
            else -> "kernel" to "[kernel]"
        }
    }
    if (normalized.startsWith("/memfd:") || normalized.startsWith("memfd:")) {
        return "shared_memory" to "[memfd]"
    }
    if (normalized.startsWith("/dev/ashmem")) {
        return "shared_memory" to "[ashmem]"
    }
    val basename = normalized.substringAfterLast('/').take(96)
    val lowercase = basename.lowercase()
    return when {
        lowercase.endsWith(".so") || ".so." in lowercase -> {
            "native_library" to basename
        }
        lowercase.endsWith(".apk") -> "apk" to basename
        listOf(".dex", ".oat", ".vdex", ".art", ".jar").any(lowercase::endsWith) -> {
            "runtime_code" to basename
        }
        else -> "file" to "[file]"
    }
}

internal fun automaticDiagnosticsParseSmaps(
    lines: Sequence<String>,
    maximum: Int,
): List<AutomaticDiagnosticsMemoryMapping> =
    automaticDiagnosticsSummarizeSmaps(lines, maximum).topMappings

internal fun automaticDiagnosticsSummarizeSmaps(
    lines: Sequence<String>,
    maximumMappings: Int,
): AutomaticDiagnosticsSmapsSummary {
    val grouped = linkedMapOf<Pair<String, String>, MutableAutomaticDiagnosticsMemoryMapping>()
    var current: MutableAutomaticDiagnosticsMemoryMapping? = null
    var mappingCount = 0

    lines.forEach { line ->
        val header = SMAPS_HEADER.matchEntire(line)
        if (header != null) {
            mappingCount += 1
            val permissions = header.groupValues[1]
            val (category, name) = safeMappingIdentity(header.groupValues[2])
            current = grouped.getOrPut(category to name) {
                MutableAutomaticDiagnosticsMemoryMapping(category, name)
            }.also { mapping ->
                mapping.executable = mapping.executable || permissions.getOrNull(2) == 'x'
            }
            return@forEach
        }
        val mapping = current ?: return@forEach
        when {
            line.startsWith("Rss:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "Rss")?.let {
                    mapping.residentBytes = mapping.residentBytes.saturatingMemoryAdd(it)
                }
            }
            line.startsWith("Pss:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "Pss")?.let {
                    mapping.proportionalBytes = mapping.proportionalBytes.saturatingMemoryAdd(it)
                }
            }
            line.startsWith("Private_Clean:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "Private_Clean")?.let {
                    mapping.privateCleanBytes = mapping.privateCleanBytes.saturatingMemoryAdd(it)
                }
            }
            line.startsWith("Private_Dirty:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "Private_Dirty")?.let {
                    mapping.privateDirtyBytes = mapping.privateDirtyBytes.saturatingMemoryAdd(it)
                }
            }
            line.startsWith("Shared_Clean:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "Shared_Clean")?.let {
                    mapping.sharedCleanBytes = mapping.sharedCleanBytes.saturatingMemoryAdd(it)
                }
            }
            line.startsWith("Shared_Dirty:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "Shared_Dirty")?.let {
                    mapping.sharedDirtyBytes = mapping.sharedDirtyBytes.saturatingMemoryAdd(it)
                }
            }
            line.startsWith("Swap:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "Swap")?.let {
                    mapping.swapBytes = mapping.swapBytes.saturatingMemoryAdd(it)
                }
            }
            line.startsWith("SwapPss:") -> {
                automaticDiagnosticsStatusMemoryBytes(line, "SwapPss")?.let {
                    mapping.swapProportionalBytes =
                        mapping.swapProportionalBytes.saturatingMemoryAdd(it)
                }
            }
        }
    }

    fun MutableAutomaticDiagnosticsMemoryMapping.toMapping() =
        AutomaticDiagnosticsMemoryMapping(
            category = category,
            name = name,
            residentBytes = residentBytes,
            proportionalBytes = proportionalBytes,
            privateCleanBytes = privateCleanBytes,
            privateDirtyBytes = privateDirtyBytes,
            sharedCleanBytes = sharedCleanBytes,
            sharedDirtyBytes = sharedDirtyBytes,
            swapBytes = swapBytes,
            swapProportionalBytes = swapProportionalBytes,
            executable = executable,
        )

    val topMappings = grouped.values
        .asSequence()
        .sortedWith(
            compareByDescending<MutableAutomaticDiagnosticsMemoryMapping> {
                it.proportionalBytes
            }.thenByDescending { it.residentBytes }
                .thenBy { it.name },
        )
        .take(maximumMappings.coerceAtLeast(0))
        .map(MutableAutomaticDiagnosticsMemoryMapping::toMapping)
        .toList()

    val categories = grouped.values
        .groupBy { it.category }
        .toSortedMap()
        .map { (category, mappings) ->
            AutomaticDiagnosticsMemoryCategory(
                category = category,
                residentBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.residentBytes)
                },
                proportionalBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.proportionalBytes)
                },
                privateCleanBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.privateCleanBytes)
                },
                privateDirtyBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.privateDirtyBytes)
                },
                sharedCleanBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.sharedCleanBytes)
                },
                sharedDirtyBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.sharedDirtyBytes)
                },
                swapBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.swapBytes)
                },
                swapProportionalBytes = mappings.fold(0L) { total, mapping ->
                    total.saturatingMemoryAdd(mapping.swapProportionalBytes)
                },
            )
        }
    return AutomaticDiagnosticsSmapsSummary(
        mappingCount = mappingCount,
        mappingGroupCount = grouped.size,
        topMappings = topMappings,
        categories = categories,
    )
}

private fun Long.saturatingMemoryAdd(value: Long): Long =
    if (Long.MAX_VALUE - this < value) Long.MAX_VALUE else this + value
