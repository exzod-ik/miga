package org.miga.core

import java.io.Closeable
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MultiTunnelEngineTest {
    private class Device : PacketDevice {
        val input = LinkedBlockingQueue<ByteArray>()
        val output = LinkedBlockingQueue<ByteArray>()
        val readObserved = LinkedBlockingQueue<Unit>()
        @Volatile var closed = false
        override fun read(): ByteArray? {
            while (!closed) input.poll(10, TimeUnit.MILLISECONDS)?.let { readObserved.add(Unit); return it }
            return null
        }
        override fun write(packet: ByteArray) { output.add(packet) }
        override fun close() { closed = true }
    }
    private class Transport : DatagramTransport {
        val input = LinkedBlockingQueue<ReceivedDatagram>()
        val output = LinkedBlockingQueue<ByteArray>()
        @Volatile var closed = false
        @Volatile var failSend = false
        @Volatile var failReceive = false
        @Volatile var endReceive = false
        var sendGate: CountDownLatch? = null
        val sendEntered = CountDownLatch(1)
        val blockedSendEntered = LinkedBlockingQueue<Unit>()
        var lateFailureGate: CountDownLatch? = null
        val receiveEntered = CountDownLatch(1)
        override fun receive(): ReceivedDatagram? {
            lateFailureGate?.let { gate ->
                receiveEntered.countDown()
                gate.await()
                throw java.io.IOException("late failure from old reader")
            }
            while (!closed) {
                if (failReceive) throw java.io.IOException("simulated receive failure")
                if (endReceive) return null
                input.poll(10, TimeUnit.MILLISECONDS)?.let { return it }
            }
            return null
        }
        override fun send(bytes: ByteArray, destinationPort: Int) {
            if (failSend) throw java.io.IOException("simulated transport failure")
            sendEntered.countDown()
            sendGate?.let { blockedSendEntered.add(Unit); it.await() }
            output.add(bytes)
        }
        override fun close() { closed = true; sendGate?.countDown() }
    }
    private fun packet(src: Int, dst: Int, srcPort: Int, dstPort: Int, protocol: Int = 17,
                       payload: ByteArray = byteArrayOf()): ByteArray {
        val bytes = ByteArray((if (protocol == 17) 28 else 40) + payload.size)
        bytes[0] = 0x45
        Ipv4Packet.put16(bytes, 2, bytes.size)
        bytes[8] = 64
        bytes[9] = protocol.toByte()
        for (i in 0..3) {
            bytes[12+i] = (src ushr (24-8*i)).toByte()
            bytes[16+i] = (dst ushr (24-8*i)).toByte()
        }
        Ipv4Packet.put16(bytes, 20, srcPort)
        Ipv4Packet.put16(bytes, 22, dstPort)
        if (protocol == 17) Ipv4Packet.put16(bytes, 24, 8 + payload.size) else bytes[32] = 0x50
        payload.copyInto(bytes, if (protocol == 17) 28 else 40)
        Checksum.writeTransport(bytes, 20, protocol)
        Checksum.writeIpv4(bytes, 20)
        return bytes
    }
    private val codec = LegacyMigaCodec(ByteArray(128), ByteArray(8))
    private fun server(id: String, generation: Long, transport: Transport, ip: Int, port: Int) =
        ServerTransport(id, generation, transport, codec, ip, port, port, { port })

    private fun awaitStat(queue: LinkedBlockingQueue<TunnelStats>, predicate: (TunnelStats) -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (true) {
            val remaining = deadline - System.nanoTime()
            check(remaining > 0) { "Timed out waiting for statistics" }
            val value = queue.poll(remaining, TimeUnit.NANOSECONDS) ?: error("Timed out waiting for statistics")
            if (predicate(value)) return
        }
    }

    private fun awaitDnsStale(engine: MultiTunnelEngine, previous: Long) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (engine.dnsCounters.stale <= previous) {
            check(System.nanoTime() < deadline) { "Timed out waiting for duplicate DNS answer" }
            Thread.yield()
        }
    }

    private fun dns(id: Int, response: Boolean, ip: Int = 0): ByteArray =
        dnsSet(id, response, if (response) listOf(ip) else emptyList())

    private fun dnsSet(id: Int, response: Boolean, ips: List<Int>,
                       domain: String = "www.example.com"): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun word(value: Int) { out.write(value ushr 8); out.write(value) }
        word(id); word(if (response) 0x8000 else 0); word(1); word(if (response) ips.size else 0)
        word(0); word(0)
        for (part in domain.split('.')) { out.write(part.length); out.write(part.toByteArray()) }
        out.write(0); word(1); word(1)
        ips.forEach { ip ->
            word(0xc00c); word(1); word(1); word(0); word(60); word(4)
            for (shift in 24 downTo 0 step 8) out.write(ip ushr shift)
        }
        return out.toByteArray()
    }

    private fun framed(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes

    private fun tcpPacket(src: Int, dst: Int, srcPort: Int, dstPort: Int,
                          sequence: Long, flags: Int = 0x10,
                          payload: ByteArray = byteArrayOf()): ByteArray {
        val bytes = packet(src, dst, srcPort, dstPort, 6, payload)
        Ipv4Packet.put16(bytes, 24, (sequence ushr 16).toInt())
        Ipv4Packet.put16(bytes, 26, sequence.toInt())
        bytes[33] = flags.toByte()
        Checksum.writeTransport(bytes, 20, 6)
        return bytes
    }

    @Test fun resetOrTimedOutDnsFlowLeavesIndependentDnsAndDirectUsable() {
        for (reset in listOf(true, false)) {
            val now = AtomicLong(1000)
            val device = Device(); val primary = Transport(); val secondary = Transport()
            val directPackets = LinkedBlockingQueue<ByteArray>()
            val direct = object : DirectPacketStack {
                override fun send(packet: ByteArray): Boolean = directPackets.add(packet)
                override fun close() = Unit
            }
            val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 11 else 22 }, mapOf(11 to "primary"), "primary", { now.get() },
                { _, _, _ -> }, { _, _ -> }, allowDirect = true,
                domainRules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com"))))
            engine.start()
            try {
                engine.attach(server("primary", 1, primary, 0x04040404, 6000))
                engine.attach(server("secondary", 2, secondary, 0x05050505, 7000))
                engine.attachDirect(direct, 3)
                val unrelated = framed(dnsSet(9, false, emptyList(), "unrelated.example.net"))
                device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53, 100, payload = unrelated))
                assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
                if (reset) {
                    primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                        53, 12345, 200, flags = 0x14), 6000), 0x04040404, 6000))
                    assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
                } else now.set(31_001)
                val directPacket = packet(0x0afe5302, 0x04040404, 34567, 443)
                device.input.add(directPacket)
                assertContentEquals(directPacket, directPackets.poll(2, TimeUnit.SECONDS))
                device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12346, 53, 100,
                    payload = framed(dns(10, false))))
                assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
                primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                    53, 12346, 200, payload = framed(dns(10, true, 0x08080808))), 6000),
                    0x04040404, 6000))
                assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            } finally { engine.close() }
        }
    }

    @Test fun dnsHalfCloseKeepsPendingResponse() {
        val device = Device(); val primary = Transport()
        val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 11 else 22 }, mapOf(11 to "primary"), "primary", { 1000 },
            { _, _, _ -> }, { _, _ -> }, allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com"))))
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            val query = framed(dns(7, false))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53, 100, payload = query))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53,
                100L + query.size, flags = 0x11))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                53, 12345, 200, payload = framed(dns(7, true, 0x08080808))), 6000),
                0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
        } finally { engine.close() }
    }

    @Test fun primaryFinAfterAnswerKeepsAuxiliaryResolutionAndRoute() {
        val device = Device(); val primary = Transport(); val secondary = Transport()
        val queries = LinkedBlockingQueue<DnsRouting.TcpQuery>()
        val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 11 else 22 }, mapOf(11 to "primary"), "primary", { 1000 },
            { _, _, _ -> }, { _, _ -> }, allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com"))),
            auxiliaryDnsTcp = { queries.add(it) })
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            engine.attach(server("secondary", 2, secondary, 0x05050505, 7000))
            val query = framed(dns(7, false))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53, 100, payload = query))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            val auxiliary = assertNotNull(queries.poll(2, TimeUnit.SECONDS))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53,
                100L + query.size, flags = 0x11))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                53, 12345, 200, flags = 0x11, payload = framed(dns(7, true, 0x08080808))),
                6000), 0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            assertTrue(engine.auxiliaryDnsAnswer(auxiliary, dns(7, true, 0x09090909)))
            device.input.add(packet(0x0afe5302, 0x08080808, 34567, 443, 6))
            val selected = codec.decode(secondary.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(0x09090909, FlowKey.from(Ipv4Packet.parse(selected)!!).destinationIp)
        } finally { engine.close() }
    }

    @Test fun lateRejectedTcpAnswerPreservesNewerRouteInEngine() {
        val device = Device(); val primary = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            override fun send(packet: ByteArray): Boolean = directPackets.add(packet)
            override fun close() = Unit
        }
        val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 11 else 22 }, mapOf(11 to "primary"), "primary", { 1000 },
            { _, _, _ -> }, { _, _ -> }, allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "primary", "www.example.com"))))
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            engine.attachDirect(direct, 3)
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53, 100,
                payload = framed(dns(1, false))))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                53, 12345, 200, flags = 0x14), 6000), 0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12346, 53, 100,
                payload = framed(dns(2, false))))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                53, 12346, 200, payload = framed(dns(2, true, 0x08080808))), 6000),
                0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            val stale = engine.dnsCounters.stale
            primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                53, 12345, 200, payload = framed(dns(1, true, 0x08080808))), 6000),
                0x04040404, 6000))
            awaitDnsStale(engine, stale)
            device.input.add(packet(0x0afe5302, 0x08080808, 34567, 443, 6))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            assertNull(directPackets.poll(200, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun halfSequenceSpaceSegmentDoesNotStopOtherDnsFlow() {
        val device = Device(); val primary = Transport()
        val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 11 else 22 }, mapOf(11 to "primary"), "primary", { 1000 },
            { _, _, _ -> }, { _, _ -> }, allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com"))))
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53, 0,
                payload = byteArrayOf(0)))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12345, 53,
                0x8000_0001L, payload = ByteArray(12)))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12346, 53, 100,
                payload = framed(dns(10, false))))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                53, 12346, 200, payload = framed(dns(10, true, 0x08080808))), 6000),
                0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
        } finally { engine.close() }
    }

    @Test fun tcpQuestionOverflowDropsUndecodableAnswerAndCannotUseDirect() {
        val device = Device(); val primary = Transport(); val secondary = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            override fun send(packet: ByteArray): Boolean = directPackets.add(packet)
            override fun close() = Unit
        }
        val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 11 else 22 }, mapOf(11 to "primary"), "primary", { 1000 },
            { _, _, _ -> }, { _, _ -> }, allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com"))))
        fun framed(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            engine.attach(server("secondary", 2, secondary, 0x05050505, 7000))
            engine.attachDirect(direct, 3)
            var sequence = 100
            repeat(33) { id ->
                val frame = framed(dns(id, false))
                val query = packet(0x0afe5302, 0x01010101, 12345, 53, 6, frame)
                Ipv4Packet.put16(query, 24, sequence ushr 16)
                Ipv4Packet.put16(query, 26, sequence)
                Checksum.writeTransport(query, 20, 6)
                device.input.add(query)
                if (id < 32) assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
                sequence += frame.size
            }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (engine.dnsCounters.limits == 0L) check(System.nanoTime() < deadline)
            val answer = packet(0x01010101, 0x0afe5302, 53, 12345, 6,
                framed(dns(0, true, 0x08080808)))
            Ipv4Packet.put16(answer, 26, 200)
            Checksum.writeTransport(answer, 20, 6)
            primary.input.add(ReceivedDatagram(codec.encode(answer, 6000), 0x04040404, 6000))
            assertNull(device.output.poll(200, TimeUnit.MILLISECONDS))
            device.input.add(packet(0x0afe5302, 0x08080808, 34567, 443, 6))
            assertNull(directPackets.poll(200, TimeUnit.MILLISECONDS))
            val unrelated = packet(0x0afe5302, 0x04040404, 34568, 443)
            device.input.add(unrelated)
            assertContentEquals(unrelated, directPackets.poll(2, TimeUnit.SECONDS))
            device.input.add(tcpPacket(0x0afe5302, 0x01010101, 12346, 53, 100,
                payload = framed(dns(40, false))))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(tcpPacket(0x01010101, 0x0afe5302,
                53, 12346, 200, payload = framed(dns(40, true, 0x07070707))), 6000),
                0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
        } finally { engine.close() }
    }

    @Test fun auxiliaryTcpUsesSelectedTunnelAndDoesNotReplacePrimaryAnswer() {
        val device = Device(); val primary = Transport(); val secondary = Transport()
        val queries = LinkedBlockingQueue<DnsRouting.TcpQuery>()
        val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 11 else 22 }, mapOf(11 to "primary"), "primary", { 1000 },
            { _, _, _ -> }, { _, _ -> }, allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("domain", "secondary", "www.example.com"))),
            auxiliaryDnsTcp = { queries.add(it) })
        fun framed(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            engine.attach(server("secondary", 2, secondary, 0x05050505, 7000))
            device.input.add(packet(0x0afe5302, 0x01010101, 12345, 53, 6,
                framed(dns(33, false))))
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            val query = assertNotNull(queries.poll(2, TimeUnit.SECONDS))
            assertEquals("secondary", query.profileId)
            assertTrue(engine.registerAuxiliaryDnsPort(23456, "secondary", 2))
            assertFalse(engine.auxiliaryDnsPortObserved(23456, "secondary", 2))
            val syn = packet(0x0afe5302, 0x01010101, 23456, 53, 6)
            syn[33] = 2
            Checksum.writeTransport(syn, 20, 6)
            device.input.add(syn)
            val auxiliarySyn = codec.decode(secondary.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(23456, FlowKey.from(Ipv4Packet.parse(auxiliarySyn)!!).sourcePort)
            assertTrue(engine.auxiliaryDnsPortObserved(23456, "secondary", 2))
            primary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                53, 12345, 6, framed(dns(33, true, 0x08080808))), 6000), 0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            assertTrue(engine.auxiliaryDnsAnswer(query, dns(33, true, 0x09090909)))
            device.input.add(packet(0x0afe5302, 0x08080808, 34567, 443, 6))
            val selected = codec.decode(secondary.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(0x09090909, FlowKey.from(Ipv4Packet.parse(selected)!!).destinationIp)
            engine.unregisterAuxiliaryDnsPort(23456, "secondary", 2)
            engine.detach("secondary", 2)
            assertFalse(engine.registerAuxiliaryDnsPort(23457, "secondary", 2))
            device.input.add(packet(0x0afe5302, 0x01010101, 23456, 53, 6))
            assertNull(primary.output.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun reorderedAnswersKeepPacketIdentityAndHigherPriorityRoutes() {
        val device = Device(); val primary = Transport(); val secondary = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            override fun send(packet: ByteArray): Boolean { directPackets.add(packet); return true }
            override fun close() {}
        }
        val engine = MultiTunnelEngine(device,
            { flow -> when (flow.sourcePort) { 1003 -> 12; 1005 -> -1; else -> 11 } },
            mapOf(12 to "primary"), "primary", { 1000 }, { _, _, _ -> }, { _, _ -> },
            rules = StaticIpv4RuleSet(listOf(StaticIpv4Rule("static", "primary",
                Ipv4Interval.parse("9.9.9.9")))), allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("domain", "secondary", "www.example.com"))))
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            engine.attach(server("secondary", 2, secondary, 0x05050505, 7000))
            engine.attachDirect(direct, 1)
            fun answer(id: Int, secondaryOrder: List<Int>) {
                device.input.add(packet(0x0afe5302, 0x01010101, 12345, 53,
                    payload = dns(id, false)))
                val one = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
                val two = codec.decode(secondary.output.poll(2, TimeUnit.SECONDS), 7000)
                val oneId = DnsParser.parse(one.copyOfRange(28, one.size))!!.id
                val twoId = DnsParser.parse(two.copyOfRange(28, two.size))!!.id
                secondary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                    53, 12345, payload = dnsSet(twoId, true, secondaryOrder)), 7000), 0x05050505, 7000))
                primary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                    53, 12345, payload = dnsSet(oneId, true, listOf(0x08080808, 0x09090909))),
                    6000), 0x04040404, 6000))
                val reply = device.output.poll(2, TimeUnit.SECONDS)
                assertEquals(id, DnsParser.parse(reply.copyOfRange(28, reply.size))!!.id)
                assertNotNull(Ipv4Packet.parse(reply))
            }
            answer(21, listOf(0x09090909, 0x08080808))
            answer(22, listOf(0x08080808, 0x09090909))
            device.input.add(packet(0x0afe5302, 0x08080808, 1001, 443)) // domain
            device.input.add(packet(0x0afe5302, 0x09090909, 1002, 443)) // static
            device.input.add(packet(0x0afe5302, 0x08080808, 1003, 443)) // app
            device.input.add(packet(0x0afe5302, 0x07070707, 1004, 443)) // DIRECT
            device.input.add(packet(0x0afe5302, 0x08080808, 1005, 443)) // unknown owner
            val domainPacket = codec.decode(secondary.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(0x08080808, FlowKey.from(Ipv4Packet.parse(domainPacket)!!).destinationIp)
            val staticPacket = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
            val appPacket = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
            assertEquals(setOf(0x09090909, 0x08080808),
                setOf(FlowKey.from(Ipv4Packet.parse(staticPacket)!!).destinationIp,
                    FlowKey.from(Ipv4Packet.parse(appPacket)!!).destinationIp))
            assertEquals(0x07070707, FlowKey.from(Ipv4Packet.parse(directPackets.poll(2, TimeUnit.SECONDS))!!).destinationIp)
            assertNull(secondary.output.poll(100, TimeUnit.MILLISECONDS))
            val unchecksummed = packet(0x08080808, 0x0afe5302, 443, 1001)
            Ipv4Packet.put16(unchecksummed, 10, 0)
            Ipv4Packet.put16(unchecksummed, 26, 0)
            secondary.input.add(ReceivedDatagram(codec.encode(unchecksummed, 7000), 0x05050505, 7000))
            val restored = device.output.poll(2, TimeUnit.SECONDS)
            assertEquals(0x08080808, FlowKey.from(Ipv4Packet.parse(restored)!!).sourceIp)
        } finally { engine.close() }
    }

    @Test fun applicationAssignmentWinsWhileOrdinaryDomainRouteIsUnresolved() {
        val device = Device(); val primary = Transport(); val secondary = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            override fun send(packet: ByteArray): Boolean { directPackets.add(packet); return true }
            override fun close() {}
        }
        val engine = MultiTunnelEngine(device, { flow -> when (flow.sourcePort) {
            1003 -> 12; 12345 -> 13; else -> 11 } },
            mapOf(12 to "secondary", 13 to "primary"), "primary", { 1000 }, { _, _, _ -> }, { _, _ -> },
            allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("domain", "secondary", "www.example.com"))))
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            engine.attach(server("secondary", 2, secondary, 0x05050505, 7000))
            engine.attachDirect(direct, 1)
            device.input.add(packet(0x0afe5302, 0x01010101, 12345, 53, payload = dns(33, false)))
            val mainQuery = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
            assertNotNull(secondary.output.poll(2, TimeUnit.SECONDS)) // auxiliary query is unanswered
            val wireId = DnsParser.parse(mainQuery.copyOfRange(28, mainQuery.size))!!.id
            primary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302, 53, 12345,
                payload = dns(wireId, true, 0x08080808)), 6000), 0x04040404, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            device.input.add(packet(0x0afe5302, 0x08080808, 1001, 443))
            device.input.add(packet(0x0afe5302, 0x08080808, 1003, 443))
            val assigned = codec.decode(secondary.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(1003, FlowKey.from(Ipv4Packet.parse(assigned)!!).sourcePort)
            assertNull(secondary.output.poll(100, TimeUnit.MILLISECONDS))
            assertNull(directPackets.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun dnsAuxiliaryBeforePrimaryRoutesAndRewritesPinnedFlow() {
        val device = Device(); val primary = Transport(); val auxiliary = Transport()
        val engine = MultiTunnelEngine(device, { flow -> if (flow.destinationPort == 53) 12 else 11 },
            mapOf(12 to "one"), "one", { 1000 }, { _, _, _ -> }, { _, _ -> },
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "two", "*.example.com"))), allowDirect = true)
        engine.start()
        try {
            engine.attach(server("one", 1, primary, 0x08080808, 6000))
            engine.attach(server("two", 2, auxiliary, 0x09090909, 7000))
            device.input.add(packet(0x0afe5302, 0x01010101, 12345, 53, payload = dns(42, false)))
            val oneQuery = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
            val twoQuery = codec.decode(auxiliary.output.poll(2, TimeUnit.SECONDS), 7000)
            val oneId = DnsParser.parse(oneQuery.copyOfRange(28, oneQuery.size))!!.id
            val twoId = DnsParser.parse(twoQuery.copyOfRange(28, twoQuery.size))!!.id
            auxiliary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302, 53, 12345,
                payload = dns(twoId, true, 0x09090909)), 7000), 0x09090909, 7000))
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302, 53, 12345,
                payload = dns(oneId, true, 0x08080808)), 6000), 0x08080808, 6000))
            val answer = device.output.poll(2, TimeUnit.SECONDS)
            assertNotNull(answer)
            assertEquals(42, DnsParser.parse(answer.copyOfRange(28, answer.size))!!.id)
            assertNotNull(Ipv4Packet.parse(answer))
            device.input.add(packet(0x0afe5302, 0x08080808, 12346, 443))
            val sent = codec.decode(auxiliary.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(0x09090909, FlowKey.from(Ipv4Packet.parse(sent)!!).destinationIp)
            auxiliary.input.add(ReceivedDatagram(codec.encode(packet(0x09090909, 0x0afe5302, 443, 12346),
                7000), 0x09090909, 7000))
            val restored = device.output.poll(2, TimeUnit.SECONDS)
            assertEquals(0x08080808, FlowKey.from(Ipv4Packet.parse(restored)!!).sourceIp)
            device.input.add(packet(0x0afe5302, 0x01010101, 12345, 53, payload = dns(43, false)))
            val changedPrimary = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
            val changedAuxiliary = codec.decode(auxiliary.output.poll(2, TimeUnit.SECONDS), 7000)
            val primaryWire = DnsParser.parse(changedPrimary.copyOfRange(28, changedPrimary.size))!!.id
            val auxiliaryWire = DnsParser.parse(changedAuxiliary.copyOfRange(28, changedAuxiliary.size))!!.id
            auxiliary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                53, 12345, payload = dns(auxiliaryWire, true, 0x07070707)), 7000), 0x09090909, 7000))
            primary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                53, 12345, payload = dns(primaryWire, true, 0x08080808)), 6000), 0x08080808, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            device.input.add(packet(0x0afe5302, 0x08080808, 12346, 443)) // established pin
            device.input.add(packet(0x0afe5302, 0x08080808, 12347, 443)) // new ambiguous flow
            val retained = codec.decode(auxiliary.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(0x09090909, FlowKey.from(Ipv4Packet.parse(retained)!!).destinationIp)
            assertNull(auxiliary.output.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun detachedAuxiliaryCannotSendOldDnsRouteToDirectOrOldTransport() {
        val device = Device(); val primary = Transport(); val secondary = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            override fun send(packet: ByteArray): Boolean { directPackets.add(packet); return true }
            override fun close() {}
        }
        val engine = MultiTunnelEngine(device, { flow -> when (flow.sourcePort) {
            12348 -> 12; 12345 -> 13; else -> 11 } },
            mapOf(12 to "primary", 13 to "primary"), "primary", { 1000 }, { _, _, _ -> }, { _, _ -> },
            allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com"))))
        engine.start()
        try {
            engine.attach(server("primary", 1, primary, 0x04040404, 6000))
            engine.attach(server("secondary", 2, secondary, 0x05050505, 7000))
            engine.attachDirect(direct, 1)
            device.input.add(packet(0x0afe5302, 0x01010101, 12345, 53, payload = dns(42, false)))
            val oldPrimary = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
            val oldSecondary = codec.decode(secondary.output.poll(2, TimeUnit.SECONDS), 7000)
            val primaryId = DnsParser.parse(oldPrimary.copyOfRange(28, oldPrimary.size))!!.id
            val secondaryId = DnsParser.parse(oldSecondary.copyOfRange(28, oldSecondary.size))!!.id
            val oldAuxiliaryAnswer = ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                53, 12345, payload = dns(secondaryId, true, 0x09090909)), 7000), 0x05050505, 7000)
            secondary.input.add(oldAuxiliaryAnswer)
            secondary.input.add(oldAuxiliaryAnswer)
            awaitDnsStale(engine, 0)
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            val unrelatedFlow = packet(0x0afe5302, 0x06060606, 12348, 443)
            device.input.add(unrelatedFlow)
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS))
            engine.detach("secondary", 2)
            val replacement = Transport()
            engine.attach(server("secondary", 3, replacement, 0x05050505, 7000))
            primary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                53, 12345, payload = dns(primaryId, true, 0x08080808)), 6000), 0x04040404, 6000))
            val delivered = device.output.poll(2, TimeUnit.SECONDS)
            assertEquals(42, DnsParser.parse(delivered.copyOfRange(28, delivered.size))!!.id)
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            device.input.add(packet(0x0afe5302, 0x08080808, 12346, 443)) // stale domain route
            device.input.add(packet(0x0afe5302, 0x07070707, 12347, 443)) // queue barrier
            val directPacket = directPackets.poll(2, TimeUnit.SECONDS)
            assertEquals(0x07070707, FlowKey.from(Ipv4Packet.parse(directPacket)!!).destinationIp)
            assertNull(directPackets.poll(100, TimeUnit.MILLISECONDS))
            assertNull(secondary.output.poll(100, TimeUnit.MILLISECONDS))
            assertNull(replacement.output.poll(100, TimeUnit.MILLISECONDS))

            device.input.add(unrelatedFlow)
            assertNotNull(primary.output.poll(2, TimeUnit.SECONDS)) // established pin on another profile survives
            device.input.add(packet(0x0afe5302, 0x01010101, 12345, 53, payload = dns(43, false)))
            val newPrimary = codec.decode(primary.output.poll(2, TimeUnit.SECONDS), 6000)
            val newSecondary = codec.decode(replacement.output.poll(2, TimeUnit.SECONDS), 7000)
            val newPrimaryId = DnsParser.parse(newPrimary.copyOfRange(28, newPrimary.size))!!.id
            val newSecondaryId = DnsParser.parse(newSecondary.copyOfRange(28, newSecondary.size))!!.id
            val newAuxiliaryAnswer = ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                53, 12345, payload = dns(newSecondaryId, true, 0x09090909)), 7000), 0x05050505, 7000)
            val stale = engine.dnsCounters.stale
            replacement.input.add(newAuxiliaryAnswer)
            replacement.input.add(newAuxiliaryAnswer)
            awaitDnsStale(engine, stale)
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            primary.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302,
                53, 12345, payload = dns(newPrimaryId, true, 0x08080808)), 6000), 0x04040404, 6000))
            val freshAnswer = device.output.poll(2, TimeUnit.SECONDS)
            assertEquals(43, DnsParser.parse(freshAnswer.copyOfRange(28, freshAnswer.size))!!.id)
            device.input.add(packet(0x0afe5302, 0x08080808, 12349, 443))
            val routed = codec.decode(replacement.output.poll(2, TimeUnit.SECONDS), 7000)
            assertEquals(0x09090909, FlowKey.from(Ipv4Packet.parse(routed)!!).destinationIp)
        } finally { engine.close() }
    }

    @Test fun twoProfilesPinFlowsAndRejectAlienOrOldReplies() {
        val device = Device()
        val first = Transport(); val second = Transport()
        val lookups = AtomicInteger()
        val engine = MultiTunnelEngine(device, { flow -> lookups.incrementAndGet(); if (flow.sourcePort == 1001) 11 else 22 },
            mapOf(11 to "one", 22 to "two"), "one", { 1000 }, { _, _, _ -> }, { _, _ -> })
        engine.start()
        try {
            engine.attach(server("one", 1, first, 0x08080808, 6000))
            engine.attach(server("two", 1, second, 0x09090909, 7000))
            val a = packet(0x0afe5302, 0x04040404, 1001, 443)
            val b = packet(0x0afe5302, 0x05050505, 1002, 443, protocol = 6)
            device.input.add(a); device.input.add(b); device.input.add(a)
            assertNotNull(first.output.poll(2, TimeUnit.SECONDS))
            assertNotNull(first.output.poll(2, TimeUnit.SECONDS))
            assertNotNull(second.output.poll(2, TimeUnit.SECONDS))
            assertEquals(2, lookups.get())
            val reply = packet(0x04040404, 0x0afe5302, 443, 1001)
            second.input.add(ReceivedDatagram(codec.encode(reply, 7000), 0x09090909, 7000))
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            first.input.add(ReceivedDatagram(codec.encode(reply, 6000), 0x08080808, 6000))
            assertContentEquals(reply, device.output.poll(2, TimeUnit.SECONDS))
            engine.detach("one", 1)
            val replacement = Transport()
            engine.attach(server("one", 2, replacement, 0x08080808, 6000))
            replacement.input.add(ReceivedDatagram(codec.encode(reply, 6000), 0x08080808, 6000))
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            device.input.add(b)
            assertNotNull(second.output.poll(2, TimeUnit.SECONDS))
            assertEquals(2, lookups.get())
        } finally { engine.close() }
    }

    @Test fun invalidUidExceptionConflictAndDnsPolicyFailClosed() {
        val device = Device(); val first = Transport(); val second = Transport()
        val calls = AtomicInteger()
        val engine = MultiTunnelEngine(device, { flow ->
            calls.incrementAndGet()
            if (flow.sourcePort == 1002) throw IllegalStateException("lookup failed")
            if (flow.sourcePort == 1003) 33 else -1
        }, mapOf(33 to null), "one", { 1000 }, { _, _, _ -> }, { _, _ -> })
        engine.start()
        try {
            engine.attach(server("one", 1, first, 0x08080808, 6000))
            engine.attach(server("two", 1, second, 0x09090909, 7000))
            for (port in 1001..1003) device.input.add(packet(0x0afe5302, 0x04040404, port, 443))
            device.input.add(packet(0x0afe5302, 0x01010101, 1004, 53,
                payload = dns(9, false)))
            assertNull(first.output.poll(100, TimeUnit.MILLISECONDS))
            assertNull(second.output.poll(100, TimeUnit.MILLISECONDS))
            assertEquals(4, calls.get()) // DNS also checks the sender's UID.
            assertEquals(3L, engine.unknownOwnerDrops)
        } finally { engine.close() }
    }

    @Test fun failedServerDoesNotFailOverAndKnownFlowKeepsOtherRoute() {
        val device = Device(); val first = Transport(); val second = Transport()
        val failures = LinkedBlockingQueue<String>()
        val engine = MultiTunnelEngine(device, { flow -> if (flow.sourcePort == 1001) 11 else 22 },
            mapOf(11 to "one", 22 to "two"), "one", { 1000 }, { _, _, _ -> },
            { id, _ -> failures.add(id) })
        engine.start()
        try {
            engine.attach(server("one", 1, first, 0x08080808, 6000))
            engine.attach(server("two", 1, second, 0x09090909, 7000))
            first.failSend = true
            device.input.add(packet(0x0afe5302, 0x04040404, 1001, 443))
            assertEquals("one", failures.poll(2, TimeUnit.SECONDS))
            engine.detach("one", 1)
            device.input.add(packet(0x0afe5302, 0x04040404, 1001, 443))
            device.input.add(packet(0x0afe5302, 0x05050505, 1002, 443))
            assertNotNull(second.output.poll(2, TimeUnit.SECONDS))
            assertNull(second.output.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun unknownCacheExpiresAndFlowTableEvictsBySizeAndAge() {
        val device = Device(); val transport = Transport()
        val now = AtomicLong(1000)
        val lookups = AtomicInteger()
        val engine = MultiTunnelEngine(device, { flow ->
            lookups.incrementAndGet(); if (flow.sourcePort == 1000) -1 else 11
        }, mapOf(11 to "one"), "one", { now.get() }, { _, _, _ -> }, { _, _ -> }, maxFlows = 1,
            flowTtlMillis = 100)
        engine.start()
        try {
            engine.attach(server("one", 1, transport, 0x08080808, 6000))
            val unknown = packet(0x0afe5302, 0x04040404, 1000, 443)
            val first = packet(0x0afe5302, 0x04040404, 1001, 443)
            val second = packet(0x0afe5302, 0x04040404, 1002, 443)
            device.input.add(unknown); device.input.add(unknown); device.input.add(first)
            assertNotNull(transport.output.poll(2, TimeUnit.SECONDS))
            assertEquals(2, lookups.get())
            device.input.add(second)
            assertNotNull(transport.output.poll(2, TimeUnit.SECONDS))
            device.input.add(first) // maxFlows=1 evicted this pin.
            assertNotNull(transport.output.poll(2, TimeUnit.SECONDS))
            assertEquals(4, lookups.get())
            now.addAndGet(5_001)
            device.input.add(unknown); device.input.add(first)
            assertNotNull(transport.output.poll(2, TimeUnit.SECONDS))
            assertEquals(6, lookups.get())
        } finally { engine.close() }
    }

    @Test fun repeatedValidInboundPacketsExtendFlowBeyondOriginalTtl() {
        val device = Device(); val transport = Transport(); val now = AtomicLong(1000)
        val engine = MultiTunnelEngine(device, { 11 }, mapOf(11 to "one"), "one", { now.get() },
            { _, _, _ -> }, { _, _ -> }, flowTtlMillis = 100)
        engine.start()
        try {
            engine.attach(server("one", 1, transport, 0x08080808, 6000))
            device.input.add(packet(0x0afe5302, 0x04040404, 1001, 443))
            assertNotNull(transport.output.poll(2, TimeUnit.SECONDS))
            val reply = packet(0x04040404, 0x0afe5302, 443, 1001)
            for (time in listOf(1050L, 1101L, 1180L)) {
                now.set(time)
                transport.input.add(ReceivedDatagram(codec.encode(reply, 6000), 0x08080808, 6000))
                assertContentEquals(reply, device.output.poll(2, TimeUnit.SECONDS))
            }
        } finally { engine.close() }
    }

    @Test fun idleFlowExpiresAndForeignOrOldGenerationCannotRefreshIt() {
        val device = Device(); val first = Transport(); val foreign = Transport(); val now = AtomicLong(1000)
        val oneStats = LinkedBlockingQueue<TunnelStats>()
        val otherStats = LinkedBlockingQueue<TunnelStats>()
        val replacementStats = LinkedBlockingQueue<TunnelStats>()
        val engine = MultiTunnelEngine(device, { 11 }, mapOf(11 to "one"), "one", { now.get() },
            { id, generation, stats ->
                if (id == "two") otherStats.add(stats)
                else if (generation == 2L) replacementStats.add(stats) else oneStats.add(stats)
            },
            { _, _ -> }, flowTtlMillis = 100)
        engine.start()
        try {
            engine.attach(server("one", 1, first, 0x08080808, 6000))
            engine.attach(server("two", 1, foreign, 0x09090909, 7000))
            val outbound = packet(0x0afe5302, 0x04040404, 1001, 443)
            val reply = packet(0x04040404, 0x0afe5302, 443, 1001)
            device.input.add(outbound)
            assertNotNull(first.output.poll(2, TimeUnit.SECONDS))
            now.set(1050)
            foreign.input.add(ReceivedDatagram(codec.encode(reply, 7000), 0x09090909, 7000))
            awaitStat(otherStats) { it.unknownFlow == 1L }
            now.set(1101)
            first.input.add(ReceivedDatagram(codec.encode(reply, 6000), 0x08080808, 6000))
            awaitStat(oneStats) { it.unknownFlow == 1L }
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            device.input.add(outbound)
            assertNotNull(first.output.poll(2, TimeUnit.SECONDS))
            engine.detach("one", 1)
            val replacement = Transport()
            engine.attach(server("one", 2, replacement, 0x08080808, 6000))
            now.set(1150)
            replacement.input.add(ReceivedDatagram(codec.encode(reply, 6000), 0x08080808, 6000))
            awaitStat(replacementStats) { it.unknownFlow == 1L }
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun fullPacketQueueStillDeliversReceiveFailureAndAllowsRetry() {
        val device = Device()
        val gate = CountDownLatch(1)
        val first = Transport().apply { sendGate = gate }
        val replacement = Transport()
        val failures = LinkedBlockingQueue<Pair<String, Long>>()
        val scheduled = mutableListOf<() -> Unit>()
        val engine = MultiTunnelEngine(device, { 11 }, mapOf(11 to "one"), "one", { 1000 },
            { _, _, _ -> }, { id, token -> failures.add(id to token) }, queueCapacity = 1)
        engine.start()
        var opens = 0
        val controller = ConnectionController(RetryScheduler { _, task ->
            scheduled.add(task)
            Closeable { scheduled.remove(task) }
        }, { 0 }, { _: Int -> 1L }, { _: Int, token: Long ->
            val transport = if (opens++ == 0) first else replacement
            engine.attach(server("one", token, transport, 0x08080808, 6000))
            Closeable { engine.detach("one", token) }
        }, { _, _ -> })
        try {
            controller.available(1, 0)
            device.input.add(packet(0x0afe5302, 0x04040404, 1001, 443))
            assertTrue(first.sendEntered.await(2, TimeUnit.SECONDS))
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            device.input.add(byteArrayOf(1)) // Worker is blocked; this fills its one-slot queue.
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            first.failReceive = true
            val failure = failures.poll(2, TimeUnit.SECONDS)
            assertEquals("one" to controller.token, failure)
            controller.failed(failure!!.second)
            assertEquals(1, scheduled.size)
            scheduled.single().invoke()
            device.input.add(packet(0x0afe5302, 0x05050505, 1002, 443))
            assertNotNull(replacement.output.poll(2, TimeUnit.SECONDS))
        } finally { controller.close(); engine.close() }
    }

    @Test fun oldReaderFailureAndStopWithFullQueueNeverStartAnotherTransport() {
        val device = Device()
        val oldGate = CountDownLatch(1)
        val first = Transport().apply { lateFailureGate = oldGate }
        val next = Transport()
        val failures = LinkedBlockingQueue<Pair<String, Long>>()
        val engine = MultiTunnelEngine(device, { 11 }, mapOf(11 to "one"), "one", { 1000 },
            { _, _, _ -> }, { id, token -> failures.add(id to token) }, queueCapacity = 1)
        engine.start()
        try {
            engine.attach(server("one", 1, first, 0x08080808, 6000))
            assertTrue(first.receiveEntered.await(2, TimeUnit.SECONDS))
            engine.detach("one", 1)
            engine.attach(server("one", 2, next, 0x08080808, 6000))
            oldGate.countDown()
            device.input.add(packet(0x0afe5302, 0x04040404, 1001, 443))
            assertNotNull(next.output.poll(2, TimeUnit.SECONDS))
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            assertNull(failures.poll(100, TimeUnit.MILLISECONDS))
            val busyGate = CountDownLatch(1)
            next.sendGate = busyGate
            device.input.add(packet(0x0afe5302, 0x05050505, 1002, 443))
            assertNotNull(next.blockedSendEntered.poll(2, TimeUnit.SECONDS))
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            device.input.add(byteArrayOf(1))
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            engine.close()
            next.failReceive = true
            assertNull(failures.poll(100, TimeUnit.MILLISECONDS))
        } finally { oldGate.countDown(); engine.close() }
    }

    @Test fun unexpectedReceiveEndFailsActiveTransportButDetachEndDoesNot() {
        val device = Device(); val first = Transport(); val failures = LinkedBlockingQueue<Pair<String, Long>>()
        val engine = MultiTunnelEngine(device, { 11 }, mapOf(11 to "one"), "one", { 1000 },
            { _, _, _ -> }, { id, token -> failures.add(id to token) })
        engine.start()
        try {
            engine.attach(server("one", 1, first, 0x08080808, 6000))
            first.endReceive = true
            assertEquals("one" to 1L, failures.poll(2, TimeUnit.SECONDS))
            engine.detach("one", 1)
            val next = Transport()
            engine.attach(server("one", 2, next, 0x08080808, 6000))
            engine.detach("one", 2)
            assertNull(failures.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun oldBlockedSendCannotPublishStatisticsForReplacementGeneration() {
        val device = Device(); val gate = CountDownLatch(1)
        val old = Transport().apply { sendGate = gate }
        val replacement = Transport()
        val snapshots = LinkedBlockingQueue<Pair<Long, TunnelStats>>()
        val engine = MultiTunnelEngine(device, { 11 }, mapOf(11 to "one"), "one", { 1000 },
            { _, generation, stats -> snapshots.add(generation to stats) }, { _, _ -> })
        engine.start()
        try {
            engine.attach(server("one", 1, old, 0x08080808, 6000))
            device.input.add(packet(0x0afe5302, 0x04040404, 1001, 443))
            assertNotNull(old.blockedSendEntered.poll(2, TimeUnit.SECONDS))
            engine.detach("one", 1) // Releases the blocked old send.
            engine.attach(server("one", 2, replacement, 0x08080808, 6000))
            device.input.add(packet(0x0afe5302, 0x05050505, 1002, 443))
            assertNotNull(replacement.output.poll(2, TimeUnit.SECONDS))
            val latest = assertNotNull(snapshots.poll(2, TimeUnit.SECONDS))
            assertEquals(2L, latest.first)
            assertEquals(1L, latest.second.sent)
            assertNull(snapshots.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun stopWithFullQueueCancelsRetryAndCannotReopen() {
        val device = Device(); val gate = CountDownLatch(1)
        val first = Transport().apply { sendGate = gate }
        val failures = LinkedBlockingQueue<Pair<String, Long>>()
        val scheduled = mutableListOf<() -> Unit>()
        val engine = MultiTunnelEngine(device, { 11 }, mapOf(11 to "one"), "one", { 1000 },
            { _, _, _ -> }, { id, token -> failures.add(id to token) }, queueCapacity = 1)
        engine.start()
        var opens = 0
        val controller = ConnectionController(RetryScheduler { _, task ->
            scheduled.add(task)
            Closeable { /* Deliberately fire a stale callback after Stop. */ }
        }, { 0 }, { _: Int -> 1L }, { _: Int, token: Long ->
            opens++
            engine.attach(server("one", token, first, 0x08080808, 6000))
            Closeable { engine.detach("one", token) }
        }, { _, _ -> })
        try {
            controller.available(1, 0)
            device.input.add(packet(0x0afe5302, 0x04040404, 1001, 443))
            assertTrue(first.sendEntered.await(2, TimeUnit.SECONDS))
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            device.input.add(byteArrayOf(1))
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            first.failReceive = true
            val failure = assertNotNull(failures.poll(2, TimeUnit.SECONDS))
            controller.failed(failure.second)
            assertEquals(1, scheduled.size)
            controller.close()
            engine.close()
            scheduled.single().invoke()
            assertEquals(1, opens)
            assertNull(failures.poll(100, TimeUnit.MILLISECONDS))
        } finally { controller.close(); engine.close() }
    }

    @Test fun packetWorkerAppliesIpRulesPinsDirectAndRejectsStaleReplies() {
        val device = Device()
        val app = Transport(); val ip = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            @Volatile var closed = false
            override fun send(packet: ByteArray): Boolean { directPackets.add(packet); return true }
            override fun close() { closed = true }
        }
        val ownerUid = AtomicInteger(11)
        val lookups = AtomicInteger()
        val rules = StaticIpv4RuleSet(listOf(StaticIpv4Rule("rule", "ip", Ipv4Interval.parse("8.8.8.8"))))
        val engine = MultiTunnelEngine(device, { key ->
            lookups.incrementAndGet()
            when (key.sourcePort) {
                1001 -> 11
                1004 -> -1
                1005 -> 22
                else -> ownerUid.get()
            }
        }, mapOf(11 to "app", 22 to null), "app", { 1000 }, { _, _, _ -> }, { _, _ -> },
            rules = rules, allowDirect = true)
        engine.start()
        try {
            engine.attach(server("app", 1, app, 0x04040404, 6000))
            engine.attach(server("ip", 1, ip, 0x05050505, 7000))
            engine.attachDirect(direct, 9)
            val assigned = packet(0x0afe5302, 0x08080808, 1001, 443)
            val byIp = packet(0x0afe5302, 0x08080808, 1002, 443)
            val byDirect = packet(0x0afe5302, 0x09090909, 1003, 443)
            ownerUid.set(44)
            device.input.add(assigned); device.input.add(byIp); device.input.add(byDirect)
            assertNotNull(app.output.poll(2, TimeUnit.SECONDS))
            assertNotNull(ip.output.poll(2, TimeUnit.SECONDS))
            assertContentEquals(byDirect, directPackets.poll(2, TimeUnit.SECONDS))
            ownerUid.set(11)
            device.input.add(byDirect)
            assertContentEquals(byDirect, directPackets.poll(2, TimeUnit.SECONDS))
            assertEquals(3, lookups.get())
            device.input.add(packet(0x0afe5302, 0x09090909, 1004, 443))
            device.input.add(packet(0x0afe5302, 0x08080808, 1005, 443))
            assertNotNull(device.readObserved.poll(2, TimeUnit.SECONDS))
            val reply = packet(0x09090909, 0x0afe5302, 443, 1003)
            engine.offerDirectResponse(9, reply)
            assertContentEquals(reply, device.output.poll(2, TimeUnit.SECONDS))
            engine.detachDirect(9)
            assertTrue(direct.closed)
            engine.offerDirectResponse(9, reply)
            assertNull(device.output.poll(100, TimeUnit.MILLISECONDS))
            ownerUid.set(44)
            engine.detach("ip", 1)
            device.input.add(packet(0x0afe5302, 0x08080808, 1006, 443))
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (engine.directCounters.serverUnavailable == 0L && System.nanoTime() < deadline)
                Thread.sleep(10)
            assertEquals(1L, engine.directCounters.serverUnavailable)
            assertNull(directPackets.poll(100, TimeUnit.MILLISECONDS))
            assertEquals(1L, engine.directCounters.received)
            assertEquals(1L, engine.directCounters.rejectedReplies)
            assertEquals(1L, engine.directCounters.ambiguousOwner)
        } finally { engine.close() }
    }

    @Test fun dnsRuleSelectionUsesSenderThenDomainAndLeavesUnruledQueryDirect() {
        val device = Device(); val one = Transport(); val two = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            override fun send(packet: ByteArray): Boolean = directPackets.add(packet)
            override fun close() = Unit
        }
        val engine = MultiTunnelEngine(device, { flow -> if (flow.sourcePort == 1001) 11 else 22 },
            mapOf(11 to "one"), "ignored", { 1000 }, { _, _, _ -> }, { _, _ -> },
            allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("rule", "two", "www.example.com"))))
        engine.start()
        try {
            engine.attach(server("one", 1, one, 0x08080808, 6000))
            engine.attach(server("two", 2, two, 0x09090909, 7000))
            engine.attachDirect(direct, 3)
            device.input.add(packet(0x0afe5302, 0x01010101, 1001, 53, payload = dns(7, false)))
            val appPrimary = codec.decode(one.output.poll(2, TimeUnit.SECONDS), 6000)
            assertNotNull(two.output.poll(2, TimeUnit.SECONDS))
            val appId = DnsParser.parse(appPrimary.copyOfRange(28, appPrimary.size))!!.id
            one.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302, 53,
                1001, payload = dns(appId, true, 0x08080808)), 6000), 0x08080808, 6000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            device.input.add(packet(0x0afe5302, 0x01010101, 1002, 53, payload = dns(7, false)))
            assertNotNull(one.output.poll(2, TimeUnit.SECONDS))
            val domainPrimary = codec.decode(two.output.poll(2, TimeUnit.SECONDS), 7000)
            val domainId = DnsParser.parse(domainPrimary.copyOfRange(28, domainPrimary.size))!!.id
            two.input.add(ReceivedDatagram(codec.encode(packet(0x01010101, 0x0afe5302, 53,
                1002, payload = dns(domainId, true, 0x09090909)), 7000), 0x09090909, 7000))
            assertNotNull(device.output.poll(2, TimeUnit.SECONDS))
            val unruled = packet(0x0afe5302, 0x01010101, 1003, 53,
                payload = dnsSet(8, false, emptyList(), "unruled.example.net"))
            device.input.add(unruled)
            assertContentEquals(unruled, directPackets.poll(2, TimeUnit.SECONDS))
            val directReply = packet(0x01010101, 0x0afe5302, 53, 1003,
                payload = dnsSet(8, true, listOf(0x07070707), "unruled.example.net"))
            engine.offerDirectResponse(3, directReply)
            assertContentEquals(directReply, device.output.poll(2, TimeUnit.SECONDS))
            assertNull(one.output.poll(100, TimeUnit.MILLISECONDS))
            assertNull(two.output.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }

    @Test fun assignedApplicationDnsAndTrafficWinWhileBrowserUsesDirect() {
        val device = Device(); val app = Transport(); val rules = Transport()
        val directPackets = LinkedBlockingQueue<ByteArray>()
        val direct = object : DirectPacketStack {
            override fun send(packet: ByteArray): Boolean = directPackets.add(packet)
            override fun close() = Unit
        }
        val engine = MultiTunnelEngine(device, { flow -> if (flow.sourcePort == 1001 ||
            flow.sourcePort == 1002) 11 else 22 }, mapOf(11 to "app"), "app", { 1000 },
            { _, _, _ -> }, { _, _ -> },
            rules = StaticIpv4RuleSet(listOf(StaticIpv4Rule("ip", "rules", Ipv4Interval.parse("9.9.9.9")))),
            allowDirect = true,
            domainRules = DomainRuleSet(listOf(DomainRule("domain", "rules", "other.example"))))
        engine.start()
        try {
            engine.attach(server("app", 1, app, 0x04040404, 6000))
            engine.attach(server("rules", 2, rules, 0x05050505, 7000))
            engine.attachDirect(direct, 3)
            val appDns = packet(0x0afe5302, 0x01010101, 1001, 53,
                payload = dnsSet(7, false, emptyList(), "youtube.com"))
            val browserDns = packet(0x0afe5302, 0x01010101, 2001, 53,
                payload = dnsSet(8, false, emptyList(), "youtube.com"))
            device.input.add(appDns)
            assertNotNull(app.output.poll(2, TimeUnit.SECONDS))
            assertNotNull(rules.output.poll(2, TimeUnit.SECONDS)) // auxiliary observation
            device.input.add(browserDns)
            assertContentEquals(browserDns, directPackets.poll(2, TimeUnit.SECONDS))
            val appTraffic = packet(0x0afe5302, 0x09090909, 1002, 443)
            val browserTraffic = packet(0x0afe5302, 0x08080808, 2002, 443)
            val browserIpRule = packet(0x0afe5302, 0x09090909, 2003, 443)
            device.input.add(appTraffic)
            assertContentEquals(appTraffic, codec.decode(app.output.poll(2, TimeUnit.SECONDS), 6000))
            device.input.add(browserTraffic)
            assertContentEquals(browserTraffic, directPackets.poll(2, TimeUnit.SECONDS))
            device.input.add(browserIpRule)
            assertContentEquals(browserIpRule, codec.decode(rules.output.poll(2, TimeUnit.SECONDS), 7000))
            assertNull(directPackets.poll(100, TimeUnit.MILLISECONDS))
        } finally { engine.close() }
    }
}
