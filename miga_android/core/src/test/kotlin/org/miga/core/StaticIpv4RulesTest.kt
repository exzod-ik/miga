package org.miga.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class StaticIpv4RulesTest {
    private fun ip(text: String) = Ipv4Interval.address(text).toInt()

    @Test fun addressCidrAndRangeBoundaries() {
        val single = Ipv4Interval.parse("8.8.8.8")
        assertEquals("8.8.8.8", Ipv4Interval.canonical(single))
        assertEquals(true, single.contains(ip("8.8.8.8")))
        assertEquals(false, single.contains(ip("8.8.8.9")))
        val cidr = Ipv4Interval.parse("8.8.9.5/23")
        assertEquals("8.8.8.0-8.8.9.255", Ipv4Interval.canonical(cidr))
        assertEquals("8.8.8.0/23", Ipv4Interval.normalize("8.8.9.5/23"))
        assertEquals(true, cidr.contains(ip("8.8.8.0")))
        assertEquals(true, cidr.contains(ip("8.8.9.255")))
        assertEquals(false, cidr.contains(ip("8.8.10.0")))
        val range = Ipv4Interval.parse("8.8.8.10-8.8.8.20")
        assertEquals(true, range.contains(ip("8.8.8.10")))
        assertEquals(true, range.contains(ip("8.8.8.20")))
        assertEquals(false, range.contains(ip("8.8.8.21")))
    }

    @Test fun rejectsExcludedInvalidAndCrossProfileOverlap() {
        listOf("10.0.0.1", "8.0.0.0/4", "8.8.8.20-8.8.8.10", "256.1.1.1",
            "8.8.8.8/33", "1.2.3", "8.8.8.8-10.0.0.1").forEach { value ->
            assertThrows(IllegalArgumentException::class.java) { Ipv4Interval.parse(value) }
        }
        val a = StaticIpv4Rule("a", "profile-a", Ipv4Interval.parse("8.8.8.0/24"))
        val b = StaticIpv4Rule("b", "profile-b", Ipv4Interval.parse("8.8.8.255"))
        assertThrows(IllegalArgumentException::class.java) { StaticIpv4RuleSet(listOf(a, b)) }
        val same = StaticIpv4Rule("b", "profile-a", b.interval)
        assertEquals("profile-a", StaticIpv4RuleSet(listOf(same, a)).profileFor(ip("8.8.8.255")))
    }

    @Test fun applicationPriorityUnknownUidAndDirectChoice() {
        val rules = StaticIpv4RuleSet(listOf(StaticIpv4Rule("a", "ip-profile", Ipv4Interval.parse("8.8.8.8"))))
        val policy = StaticRoutePolicy(mapOf(100 to "app-profile", 101 to null), rules)
        assertEquals(RouteDecision.Server("app-profile"), policy.decide(100, ip("8.8.8.8")))
        assertEquals(RouteDecision.Server("ip-profile"), policy.decide(102, ip("8.8.8.8")))
        assertEquals(RouteDecision.Direct, policy.decide(102, ip("9.9.9.9")))
        assertEquals(RouteDecision.UnknownOwner, policy.decide(-1, ip("9.9.9.9")))
        assertEquals(RouteDecision.AmbiguousOwner, policy.decide(101, ip("8.8.8.8")))
        assertNull(rules.profileFor(ip("9.9.9.9")))
    }
}
