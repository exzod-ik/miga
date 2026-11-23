package org.miga.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DataPathHealthTest {
    @Test fun reconnectsAfterThreeUnansweredChecks() {
        val health = DataPathHealth()
        var probes = 0
        fun check(now: Long) = health.check(now, 1) { probes++ }
        assertFalse(check(0))
        health.sent(0)
        assertFalse(check(14_999))
        assertFalse(check(15_000))
        assertFalse(check(19_999))
        assertFalse(check(20_000))
        assertFalse(check(25_000))
        assertTrue(check(30_000))
        assertEquals(3, probes)
    }

    @Test fun replyAndSessionChangeClearPendingFailures() {
        val health = DataPathHealth()
        var probes = 0
        health.sent(0)
        for (now in listOf(15_000L, 20_000L, 25_000L)) assertFalse(health.check(now, 1) { probes++ })
        assertFalse(health.check(30_000, 2) { probes++ })
        health.replied()
        assertFalse(health.check(35_000, 2) { probes++ })
        assertEquals(4, probes)
    }

    @Test fun idleAndLegacyTransportsDoNotProbe() {
        val health = DataPathHealth()
        health.sent(0)
        assertFalse(health.check(15_000, 0) { error("legacy transport") })
        assertFalse(health.check(60_000, 1) { error("no recent traffic") })
    }
}
