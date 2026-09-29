package org.miga.core

import org.junit.Test

class Ipv4PacketTest {
    private fun packet(protocol: Int, ihl: Int = 20, payload: Int = 0): ByteArray {
        val transport = if (protocol == 6) 20 else 8
        val data = ByteArray(ihl + transport + payload)
        data[0] = (0x40 or (ihl / 4)).toByte()
        Ipv4Packet.put16(data, 2, data.size)
        data[8] = 64
        data[9] = protocol.toByte()
        data[12] = 10; data[13] = 1; data[14] = 2; data[15] = 3
        data[16] = 8; data[17] = 8; data[18] = 8; data[19] = 8
        Ipv4Packet.put16(data, ihl, 1234)
        Ipv4Packet.put16(data, ihl + 2, 53)
        if (protocol == 6) data[ihl + 12] = 0x50
        else Ipv4Packet.put16(data, ihl + 4, transport + payload)
        Checksum.writeTransport(data, ihl, protocol)
        Checksum.writeIpv4(data, ihl)
        return data
    }

    @Test fun validTcpUdpAndIpv4Options() {
        for (protocol in listOf(6, 17)) for (ihl in listOf(20, 24, 60)) {
            val bytes = packet(protocol, ihl)
            val parsed = assertNotNull(Ipv4Packet.parse(bytes))
            assertEquals(ihl, parsed.headerLength)
            assertEquals(1234, parsed.sourcePort)
            assertEquals(53, parsed.destinationPort)
        }
        assertNotNull(Ipv4Packet.parse(packet(17, payload = 0))) // Empty inner UDP payload is valid.
    }

    @Test fun truncationFragmentsAndCorruptionAreRejected() {
        val tcp = packet(6)
        for (length in 0 until tcp.size) assertNull(Ipv4Packet.parse(tcp.copyOf(length)))
        val badIhl = tcp.copyOf(); badIhl[0] = 0x44; assertNull(Ipv4Packet.parse(badIhl))
        val badVersion = tcp.copyOf(); badVersion[0] = 0x65; assertNull(Ipv4Packet.parse(badVersion))
        val fragment = tcp.copyOf(); fragment[6] = 0x20; assertNull(Ipv4Packet.parse(fragment))
        val badOffset = tcp.copyOf(); badOffset[32] = 0x40; assertNull(Ipv4Packet.parse(badOffset))
        val badChecksum = tcp.copyOf(); badChecksum[19] = 9; assertNull(Ipv4Packet.parse(badChecksum))
        val udp = packet(17)
        val badUdpLength = udp.copyOf(); Ipv4Packet.put16(badUdpLength, 24, 7)
        assertNull(Ipv4Packet.parse(badUdpLength))
        val badTransportChecksum = udp.copyOf(); badTransportChecksum[23] = 99
        assertNull(Ipv4Packet.parse(badTransportChecksum))
        val unknown = packet(17); unknown[9] = 1; Checksum.writeIpv4(unknown, 20)
        assertNull(Ipv4Packet.parse(unknown))
    }

    @Test fun serverReplyChecksumRepairKeepsStructuralValidation() {
        for (protocol in listOf(6, 17)) {
            val reply = packet(protocol, ihl = 24, payload = 3)
            reply[12] = 9 // source address and destination port were rewritten by the server
            Ipv4Packet.put16(reply, 26, 4321)
            assertNull(Ipv4Packet.parse(reply))
            val repaired = assertNotNull(ServerReplyPacket.parse(reply))
            assertEquals(4321, repaired.destinationPort)
            assertNotNull(Ipv4Packet.parse(repaired.bytes))

            val fragment = reply.copyOf(); fragment[6] = 0x20
            assertNull(ServerReplyPacket.parse(fragment))
            assertNull(ServerReplyPacket.parse(reply.copyOf(reply.size - 1)))
        }
    }

    @Test fun synMssClampRecomputesChecksum() {
        val data = packet(6, 24).copyOf(48)
        Ipv4Packet.put16(data, 2, data.size)
        data[36] = 0x60 // TCP data offset = 6
        data[37] = 2 // SYN
        data[44] = 2; data[45] = 4; data[46] = 0x05; data[47] = 0xb4.toByte() // 1460
        Checksum.writeTransport(data, 24, 6)
        Checksum.writeIpv4(data, 24)
        val parsed = assertNotNull(Ipv4Packet.parse(data))
        val clamped = assertNotNull(parsed.clampMss(1360))
        assertEquals(1360, Ipv4Packet.u16(clamped, 46))
        assertNotNull(Ipv4Packet.parse(clamped))
        assertContentEquals(data, parsed.bytes)
        assertContentEquals(clamped, assertNotNull(Ipv4Packet.parse(clamped)).clampMss(1400))
    }
}
