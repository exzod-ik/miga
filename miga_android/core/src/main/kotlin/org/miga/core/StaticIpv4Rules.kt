package org.miga.core

/** Normalized inclusive IPv4 interval. Values are unsigned, stored in Long. */
data class Ipv4Interval(val first: Long, val last: Long) {
    init { require(first in 0..MAX && last in first..MAX) }

    fun contains(ip: Int): Boolean = (ip.toLong() and MAX) in first..last
    fun overlaps(other: Ipv4Interval): Boolean = first <= other.last && other.first <= last

    companion object {
        private const val MAX = 0xffff_ffffL

        fun address(text: String): Long {
            val parts = text.trim().split('.')
            require(parts.size == 4 && parts.all { part ->
                part.isNotEmpty() && part.length <= 3 && part.all { it in '0'..'9' } &&
                    part.toIntOrNull() in 0..255
            }) { "Enter a valid IPv4 address" }
            return parts.fold(0L) { value, part -> (value shl 8) or part.toLong() }
        }

        fun parse(text: String): Ipv4Interval {
            val value = text.trim()
            val range = value.split('-')
            val interval = when {
                range.size == 2 -> Ipv4Interval(address(range[0]), address(range[1]))
                range.size != 1 -> throw IllegalArgumentException("Enter an IPv4 address, CIDR, or range")
                '/' in value -> {
                    val cidr = value.split('/')
                    require(cidr.size == 2 && cidr[1].all { it in '0'..'9' }) { "Invalid CIDR" }
                    val prefix = cidr[1].toIntOrNull()
                    require(prefix != null && prefix in 0..32) { "Invalid CIDR prefix" }
                    val mask = if (prefix == 0) 0L else (MAX shl (32 - prefix)) and MAX
                    val first = address(cidr[0]) and mask
                    Ipv4Interval(first, first or (MAX xor mask))
                }
                else -> address(value).let { Ipv4Interval(it, it) }
            }
            require(PublicRoutes.excluded.none { excluded ->
                val mask = if (excluded.prefix == 0) 0L else (MAX shl (32 - excluded.prefix)) and MAX
                val first = (excluded.address.toLong() and MAX) and mask
                interval.overlaps(Ipv4Interval(first, first or (MAX xor mask)))
            }) { "Rule includes an excluded IPv4 destination" }
            return interval
        }

        fun canonical(interval: Ipv4Interval): String =
            if (interval.first == interval.last) dotted(interval.first)
            else "${dotted(interval.first)}-${dotted(interval.last)}"

        fun normalize(text: String): String {
            val interval = parse(text)
            val value = text.trim()
            if ('/' !in value) return canonical(interval)
            val prefix = value.substringAfter('/').toInt()
            return "${dotted(interval.first)}/$prefix"
        }

        private fun dotted(value: Long): String = (24 downTo 0 step 8)
            .joinToString(".") { ((value ushr it) and 255).toString() }
    }
}

data class StaticIpv4Rule(val id: String, val profileId: String, val interval: Ipv4Interval)

class StaticIpv4RuleSet(rules: List<StaticIpv4Rule>) {
    private val rows = rules.toList()

    init {
        require(rows.map { it.id }.toSet().size == rows.size) { "Duplicate rule ID" }
        for (i in rows.indices) for (j in i + 1 until rows.size) {
            require(rows[i].profileId == rows[j].profileId || !rows[i].interval.overlaps(rows[j].interval)) {
                "IPv4 rules for different profiles overlap"
            }
        }
    }

    fun profileFor(ip: Int): String? = rows.firstOrNull { it.interval.contains(ip) }?.profileId
}

sealed interface RouteDecision {
    data class Server(val profileId: String) : RouteDecision
    data object Direct : RouteDecision
    data object UnknownOwner : RouteDecision
    data object AmbiguousOwner : RouteDecision
    data object AmbiguousDns : RouteDecision
}

/** DNS is selected separately before this ordinary-flow policy is called. */
class StaticRoutePolicy(private val uidProfiles: Map<Int, String?>, private val rules: StaticIpv4RuleSet) {
    fun decide(uid: Int, destinationIp: Int): RouteDecision {
        if (uid < 0) return RouteDecision.UnknownOwner
        if (uid in uidProfiles) {
            return uidProfiles[uid]?.let(RouteDecision::Server) ?: RouteDecision.AmbiguousOwner
        }
        return rules.profileFor(destinationIp)?.let(RouteDecision::Server) ?: RouteDecision.Direct
    }
}
