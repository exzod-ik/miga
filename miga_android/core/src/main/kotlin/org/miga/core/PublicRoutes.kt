package org.miga.core

data class Ipv4Cidr(val address: Int, val prefix: Int)

/** Exact complement of non-public destinations used by this VPN. */
object PublicRoutes {
    val excluded = listOf(
        Ipv4Cidr(0x00000000, 8), Ipv4Cidr(0x0a000000, 8),
        Ipv4Cidr(0x64400000, 10), Ipv4Cidr(0x7f000000, 8),
        Ipv4Cidr(0xa9fe0000.toInt(), 16), Ipv4Cidr(0xac100000.toInt(), 12),
        Ipv4Cidr(0xc0000000.toInt(), 24), Ipv4Cidr(0xc0000200.toInt(), 24),
        Ipv4Cidr(0xc0a80000.toInt(), 16), Ipv4Cidr(0xc6336400.toInt(), 24),
        Ipv4Cidr(0xc6120000.toInt(), 15), Ipv4Cidr(0xcb007100.toInt(), 24),
        Ipv4Cidr(0xe0000000.toInt(), 3),
    )

    fun contains(cidr: Ipv4Cidr, address: Int): Boolean {
        val mask = if (cidr.prefix == 0) 0 else (-1 shl (32 - cidr.prefix))
        return (address and mask) == (cidr.address and mask)
    }

    fun publicCidrs(): List<Ipv4Cidr> {
        var routes = listOf(Ipv4Cidr(0, 0))
        for (excludedRoute in excluded) routes = routes.flatMap { subtract(it, excludedRoute) }
        return routes
    }

    private fun subtract(route: Ipv4Cidr, excludedRoute: Ipv4Cidr): List<Ipv4Cidr> {
        if (!contains(route, excludedRoute.address)) return listOf(route)
        if (route.prefix >= excludedRoute.prefix) return emptyList()
        val next = route.prefix + 1
        val sibling = Ipv4Cidr(route.address or (1 shl (32 - next)), next)
        val first = Ipv4Cidr(route.address, next)
        return subtract(first, excludedRoute) + subtract(sibling, excludedRoute)
    }

    fun isPublic(address: Int) = excluded.none { contains(it, address) }
}
