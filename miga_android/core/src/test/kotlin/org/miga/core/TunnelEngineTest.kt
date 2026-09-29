package org.miga.core

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Test

class TunnelEngineTest {
    private val xor = ByteArray(128) { it.toByte() }
    private val swap = ByteArray(8) { (it * 17).toByte() }
    private val codec = LegacyMigaCodec(xor, swap)
    private val serverIp = 0x08080808

    private fun packet(protocol: Int, source: Int, destination: Int, sourcePort: Int, destinationPort: Int, payload: Int = 0): ByteArray {
        val ihl = 20
        val header = if (protocol == 6) 20 else 8
        val bytes = ByteArray(ihl + header + payload)
        bytes[0] = 0x45
        Ipv4Packet.put16(bytes, 2, bytes.size)
        bytes[8] = 64
        bytes[9] = protocol.toByte()
        for (i in 0..3) {
            bytes[12 + i] = (source ushr (24 - 8 * i)).toByte()
            bytes[16 + i] = (destination ushr (24 - 8 * i)).toByte()
        }
        Ipv4Packet.put16(bytes, ihl, sourcePort)
        Ipv4Packet.put16(bytes, ihl + 2, destinationPort)
        if (protocol == 6) bytes[ihl + 12] = 0x50 else Ipv4Packet.put16(bytes, ihl + 4, 8 + payload)
        Checksum.writeTransport(bytes, ihl, protocol)
        Checksum.writeIpv4(bytes, ihl)
        return bytes
    }

    private class FakeDevice : PacketDevice {
        val incoming = LinkedBlockingQueue<ByteArray>()
        val written = LinkedBlockingQueue<ByteArray>()
        @Volatile var closed = false
        val reads = AtomicInteger()
        val threeReads = CountDownLatch(3)
        override fun read(): ByteArray? {
            while (!closed) incoming.poll(20, TimeUnit.MILLISECONDS)?.let {
                reads.incrementAndGet(); threeReads.countDown(); return it
            }
            return null
        }
        override fun write(packet: ByteArray) { written.add(packet) }
        override fun close() { closed = true }
    }

    private class FakeTransport : DatagramTransport {
        val incoming = LinkedBlockingQueue<ReceivedDatagram>()
        val sent = LinkedBlockingQueue<Pair<ByteArray, Int>>()
        @Volatile var closed = false
        val sendEntered = CountDownLatch(1)
        var sendGate: CountDownLatch? = null
        override fun receive(): ReceivedDatagram? {
            while (!closed) incoming.poll(20, TimeUnit.MILLISECONDS)?.let { return it }
            return null
        }
        override fun send(bytes: ByteArray, destinationPort: Int) {
            sendEntered.countDown()
            sendGate?.await()
            sent.add(bytes to destinationPort)
        }
        override fun close() { closed = true }
    }

    private fun awaitStats(queue: LinkedBlockingQueue<TunnelStats>, predicate: (TunnelStats) -> Boolean): TunnelStats {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (true) {
            val remaining = deadline - System.nanoTime()
            check(remaining > 0) { "Timed out waiting for packet statistics" }
            val value = queue.poll(remaining, TimeUnit.NANOSECONDS) ?: error("Timed out waiting for packet statistics")
            if (predicate(value)) return value
        }
    }

    @Test fun tcpAndUdpRoundTripDifferentPortsAndBadReplies() {
        for (protocol in listOf(6, 17)) {
            val device = FakeDevice()
            val transport = FakeTransport()
            val snapshots = LinkedBlockingQueue<TunnelStats>()
            var chosen = 6000
            val engine = TunnelEngine(device, transport, codec, serverIp, 6000, 6001,
                { chosen++ }, { 1000 }, { snapshots.add(it) })
            engine.start()
            try {
                val outbound = packet(protocol, 0x0afe5302, serverIp, 1111, 443)
                device.incoming.add(outbound)
                val sent = assertNotNull(transport.sent.poll(2, TimeUnit.SECONDS))
                assertEquals(6000, sent.second)
                assertContentEquals(outbound, codec.decode(sent.first, 6000))
                val reply = packet(protocol, serverIp, 0x0afe5302, 443, 1111)
                Ipv4Packet.put16(reply, 10, 0)
                Ipv4Packet.put16(reply, 20 + if (protocol == 6) 16 else 6, 0)
                transport.incoming.add(ReceivedDatagram(codec.encode(reply, 6001), serverIp, 6001))
                Checksum.writeIpv4(reply, 20)
                Checksum.writeTransport(reply, 20, protocol)
                assertContentEquals(reply, device.written.poll(2, TimeUnit.SECONDS))
                transport.incoming.add(ReceivedDatagram(codec.encode(reply, 6000), 0x01010101, 6000))
                transport.incoming.add(ReceivedDatagram(byteArrayOf(1, 2, 3), serverIp, 6000))
                val alien = packet(protocol, serverIp, 0x0afe5302, 443, 9999)
                transport.incoming.add(ReceivedDatagram(codec.encode(alien, 6000), serverIp, 6000))
                val last = awaitStats(snapshots) {
                    it.unknownEndpoint == 1L && it.malformed == 1L && it.unknownFlow == 1L
                }
                assertEquals(1L, last.received)
                assertEquals(1L, last.unknownEndpoint)
                assertEquals(1L, last.malformed)
                assertEquals(1L, last.unknownFlow)
            } finally { engine.close() }
            assertEquals(true, device.closed)
            assertEquals(true, transport.closed)
        }
    }

    @Test fun routeBoundariesAndQueueCapacity() {
        val routes = PublicRoutes.publicCidrs()
        for (excluded in PublicRoutes.excluded) {
            assertEquals(false, routes.any { PublicRoutes.contains(it, excluded.address) })
            val last = excluded.address.toLong().and(0xffffffffL) + (1L shl (32 - excluded.prefix)) - 1
            assertEquals(false, routes.any { PublicRoutes.contains(it, last.toInt()) })
            val before = excluded.address.toLong().and(0xffffffffL) - 1
            val after = last + 1
            if (before >= 0) assertEquals(PublicRoutes.isPublic(before.toInt()), routes.any { PublicRoutes.contains(it, before.toInt()) })
            if (after <= 0xffffffffL) assertEquals(PublicRoutes.isPublic(after.toInt()), routes.any { PublicRoutes.contains(it, after.toInt()) })
        }
        for (ip in listOf(0x01010101, 0x08080808, 0x09090909, 0xdfffffff.toInt())) {
            assertEquals(true, routes.any { PublicRoutes.contains(it, ip) })
        }
        val device = FakeDevice()
        val transport = FakeTransport()
        val stats = LinkedBlockingQueue<TunnelStats>()
        val sendGate = CountDownLatch(1)
        transport.sendGate = sendGate
        val engine = TunnelEngine(device, transport, codec, serverIp, 6000, 6000,
            { 6000 }, { 1000 }, { stats.add(it) }, queueCapacity = 1)
        engine.start()
        repeat(1000) { device.incoming.add(packet(17, 0x0afe5302, serverIp, 1111, 443)) }
        check(transport.sendEntered.await(2, TimeUnit.SECONDS))
        check(device.threeReads.await(2, TimeUnit.SECONDS))
        sendGate.countDown()
        awaitStats(stats) { it.queueDrops > 0 }
        engine.close()
        assertEquals(true, stats.any { it.queueDrops > 0 })
    }

    @Test fun completeMtuPacketPassesAndBothOversizeDirectionsDrop() {
        val device = FakeDevice()
        val transport = FakeTransport()
        val stats = LinkedBlockingQueue<TunnelStats>()
        val engine = TunnelEngine(device, transport, codec, serverIp, 6000, 6000,
            { 6000 }, { 1000 }, { stats.add(it) })
        engine.start()
        try {
            val innerSize = TunnelPacketLimits.TUN_MTU
            assertEquals(1428, TunnelPacketLimits.MAX_OUTER_IPV4_PACKET)
            val payloadSize = innerSize - 28
            val outgoing = packet(17, 0x0afe5302, serverIp, 1111, 443, payloadSize)
            assertEquals(innerSize, outgoing.size)
            device.incoming.add(outgoing)
            val sent = assertNotNull(transport.sent.poll(2, TimeUnit.SECONDS))
            assertEquals(innerSize, sent.first.size)
            assertContentEquals(outgoing, codec.decode(sent.first, sent.second))
            val reply = packet(17, serverIp, 0x0afe5302, 443, 1111, payloadSize)
            transport.incoming.add(ReceivedDatagram(codec.encode(reply, 6000), serverIp, 6000))
            assertContentEquals(reply, device.written.poll(2, TimeUnit.SECONDS))
            device.incoming.add(packet(17, 0x0afe5302, serverIp, 1111, 443, payloadSize + 1))
            transport.incoming.add(ReceivedDatagram(ByteArray(TunnelPacketLimits.RECEIVE_BUFFER), serverIp, 6000))
            val result = awaitStats(stats) { it.sent == 1L && it.received == 1L && it.oversized == 2L }
            assertEquals(2L, result.oversized)
            assertNull(transport.sent.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }
}
