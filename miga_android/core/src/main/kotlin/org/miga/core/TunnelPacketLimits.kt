package org.miga.core

/** Local TUN policy. This does not claim a measured physical path MTU. */
object TunnelPacketLimits {
    const val TUN_MTU = 1400
    const val MAX_INNER_PACKET = TUN_MTU
    const val MAX_WIRE_PAYLOAD = MAX_INNER_PACKET // Legacy transform preserves length.
    const val RECEIVE_BUFFER = MAX_WIRE_PAYLOAD + 1 // Sentinel detects oversized datagrams.
    const val OUTER_IPV4_UDP_OVERHEAD = 28
    const val MAX_OUTER_IPV4_PACKET = MAX_WIRE_PAYLOAD + OUTER_IPV4_UDP_OVERHEAD
    const val TUNNEL_MAX_MSS = 1400
}
