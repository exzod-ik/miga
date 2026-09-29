package org.miga.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowTableTest {
    @Test fun capacityGenerationExpiryAndReverseKey() {
        var time = 0L
        val table = FlowTable(Clock { time }, 2, 1000)
        val first = FlowKey(6, 0x0a000001, 1000, 0x08080808, 443)
        val second = first.copy(sourcePort = 1001)
        val third = first.copy(sourcePort = 1002)
        assertEquals(first, first.reverse().reverse())
        table.remember(first, 1)
        table.remember(second, 1)
        assertTrue(table.contains(first, 1))
        table.remember(third, 1)
        assertFalse(table.contains(second, 1)) // Least recently used entry evicted.
        assertEquals(2, table.size)
        assertFalse(table.contains(first, 2)) // Changed configuration generation.
        time = 1000
        assertFalse(table.contains(third, 1))
        table.remember(first, 3)
        time = 999
        assertFalse(table.contains(first, 3)) // Clock moved backwards.
        table.clear()
        assertEquals(0, table.size)
    }
}
