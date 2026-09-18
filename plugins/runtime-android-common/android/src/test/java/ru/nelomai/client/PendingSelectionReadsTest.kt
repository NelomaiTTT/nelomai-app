package ru.nelomai.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PendingSelectionReadsTest {
    @Test fun boundedPendingReadsRejectOverflowWithoutThrowing() {
        val reads = PendingSelectionReads<Int>(2)
        val results = mutableListOf<Result<Int>>()
        assertTrue(reads.offer { results += it })
        assertTrue(reads.offer { results += it })
        assertFalse(reads.offer { results += it })

        reads.complete(Result.success(7))
        assertEquals(2, results.size)
        assertEquals(listOf(7, 7), results.map { it.getOrThrow() })
        assertEquals(0, reads.size())
    }
}
