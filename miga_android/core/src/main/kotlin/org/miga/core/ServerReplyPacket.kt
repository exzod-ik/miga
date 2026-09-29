package org.miga.core

/** The legacy server rewrites packet addresses and ports without updating inner checksums. */
internal object ServerReplyPacket {
    fun parse(decoded: ByteArray): Ipv4Packet? {
        Ipv4Packet.parse(decoded)?.let { return it }
        val packet = Ipv4Packet.parse(decoded, verifyChecksums = false) ?: return null
        val repaired = packet.bytes
        Checksum.writeIpv4(repaired, packet.headerLength)
        Checksum.writeTransport(repaired, packet.headerLength, packet.protocol)
        return Ipv4Packet.parse(repaired)
    }
}
