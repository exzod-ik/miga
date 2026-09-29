package org.miga.core

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsRoutingTest {
    private fun word(out: ByteArrayOutputStream, value: Int) { out.write(value ushr 8); out.write(value) }
    private fun name(out: ByteArrayOutputStream, value: String) {
        value.split('.').forEach { label -> out.write(label.length); out.write(label.toByteArray()) }
        out.write(0)
    }
    private fun dns(id: Int, response: Boolean, ips: List<Int> = emptyList(), ttl: Int = 60,
                    flags: Int = 0, domain: String = "www.example.com"): ByteArray {
        val out = ByteArrayOutputStream()
        word(out, id); word(out, (if (response) 0x8000 else 0) or flags)
        word(out, 1); word(out, if (response) ips.size else 0); word(out, 0); word(out, 0)
        name(out, domain); word(out, 1); word(out, 1)
        if (response) ips.forEach { ip ->
            word(out, 0xc00c); word(out, 1); word(out, 1)
            word(out, ttl ushr 16); word(out, ttl); word(out, 4)
            for (shift in 24 downTo 0 step 8) out.write(ip ushr shift)
        }
        return out.toByteArray()
    }
    private fun udp(payload: ByteArray, src: Int = 0x0afe5302, dst: Int = 0x01010101,
                    srcPort: Int = 12345, dstPort: Int = 53): Ipv4Packet {
        val bytes = ByteArray(28 + payload.size)
        bytes[0] = 0x45; Ipv4Packet.put16(bytes, 2, bytes.size); bytes[8] = 64; bytes[9] = 17
        for (i in 0..3) { bytes[12+i] = (src ushr (24-8*i)).toByte(); bytes[16+i] = (dst ushr (24-8*i)).toByte() }
        Ipv4Packet.put16(bytes, 20, srcPort); Ipv4Packet.put16(bytes, 22, dstPort)
        Ipv4Packet.put16(bytes, 24, 8 + payload.size)
        payload.copyInto(bytes, 28)
        Checksum.writeTransport(bytes, 20, 17); Checksum.writeIpv4(bytes, 20)
        return Ipv4Packet.parse(bytes)!!
    }

    private fun tcp(payload: ByteArray, src: Int, dst: Int, srcPort: Int, dstPort: Int,
                    sequence: Int): Ipv4Packet {
        val bytes = ByteArray(40 + payload.size)
        bytes[0] = 0x45; Ipv4Packet.put16(bytes, 2, bytes.size); bytes[8] = 64; bytes[9] = 6
        for (i in 0..3) { bytes[12+i] = (src ushr (24-8*i)).toByte(); bytes[16+i] = (dst ushr (24-8*i)).toByte() }
        Ipv4Packet.put16(bytes, 20, srcPort); Ipv4Packet.put16(bytes, 22, dstPort)
        Ipv4Packet.put16(bytes, 24, sequence ushr 16); Ipv4Packet.put16(bytes, 26, sequence)
        bytes[32] = 0x50; payload.copyInto(bytes, 40)
        Checksum.writeTransport(bytes, 20, 6); Checksum.writeIpv4(bytes, 20)
        return Ipv4Packet.parse(bytes)!!
    }

    private fun resolve(routing: DnsRouting, servers: Map<String, Long>, id: Int,
                        primaryIps: List<Int>, secondaryIps: List<Int> = primaryIps,
                        ttl: Int = 60, domain: String = "www.example.com"): List<DnsRouting.Send> {
        val sends = routing.query(udp(dns(id, false, domain = domain)), servers)!!
        for (send in sends) {
            val wire = DnsParser.parse(send.packet.copyOfRange(28, send.packet.size))!!.id
            routing.answer(udp(dns(wire, true,
                if (send.profileId == "primary") primaryIps else secondaryIps, ttl, domain = domain),
                src = 0x01010101, dst = 0x0afe5302, srcPort = 53, dstPort = 12345),
                send.profileId, send.generation)
        }
        return sends
    }

    private fun reply(routing: DnsRouting, send: DnsRouting.Send, ip: Int): DnsRouting.Answer {
        val wire = DnsParser.parse(send.packet.copyOfRange(28, send.packet.size))!!.id
        return routing.answer(udp(dns(wire, true, listOf(ip)), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345), send.profileId, send.generation)!!
    }

    @Test fun udpPairedAnswersKeepEachArrivalDeadline() {
        val servers = mapOf("primary" to 1L, "secondary" to 2L)
        for (auxiliaryFirst in listOf(false, true)) {
            var now = 1000L
            val routing = DnsRouting({ now }, DomainRuleSet(listOf(
                DomainRule("rule", "secondary", "www.example.com"))), "primary")
            fun exchange(id: Int, delay: Long, firstTtl: Int, secondTtl: Int) {
                val sends = routing.query(udp(dns(id, false)), servers)!!
                fun answer(profile: String, ttl: Int) {
                    val send = sends.single { it.profileId == profile }
                    val wire = DnsParser.parse(send.packet.copyOfRange(28, send.packet.size))!!.id
                    val ip = if (profile == "primary") 0x08080808 else 0x09090909
                    routing.answer(udp(dns(wire, true, listOf(ip), ttl), src = 0x01010101,
                        dst = 0x0afe5302, srcPort = 53, dstPort = 12345), profile, send.generation)
                }
                answer(if (auxiliaryFirst) "secondary" else "primary", firstTtl)
                now += delay
                answer(if (auxiliaryFirst) "primary" else "secondary", secondTtl)
            }
            exchange(1, 1500, 1, 60)
            assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, servers))
            exchange(2, 500, 2, 60)
            assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
                routing.lookup(0x08080808, null, servers))
            now += 1500
            assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, servers))
            exchange(3, 0, 60, 60)
            assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
                routing.lookup(0x08080808, null, servers))
        }
    }

    @Test fun tcpPairedAnswersKeepEachArrivalDeadline() {
        val servers = mapOf("primary" to 1L, "secondary" to 2L)
        for (auxiliaryFirst in listOf(false, true)) {
            var now = 1000L
            val routing = DnsRouting({ now }, DomainRuleSet(listOf(
                DomainRule("rule", "secondary", "www.example.com"))), "primary")
            var outgoingSequence = 100
            var incomingSequence = 200
            fun frame(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
            fun exchange(id: Int, delay: Long, firstTtl: Int, secondTtl: Int) {
                val query = frame(dns(id, false))
                val task = routing.observeTcp(tcp(query, 0x0afe5302, 0x01010101,
                    12345, 53, outgoingSequence), true, 1, servers).single()
                outgoingSequence += query.size
                fun primary(ttl: Int) {
                    val answer = frame(dns(id, true, listOf(0x08080808), ttl))
                    routing.observeTcp(tcp(answer, 0x01010101, 0x0afe5302,
                        53, 12345, incomingSequence), false, 1)
                    incomingSequence += answer.size
                }
                fun secondary(ttl: Int) {
                    assertTrue(routing.auxiliaryTcpAnswer(task.token, "secondary", 2,
                        dns(id, true, listOf(0x09090909), ttl)))
                }
                if (auxiliaryFirst) secondary(firstTtl) else primary(firstTtl)
                now += delay
                if (auxiliaryFirst) primary(secondTtl) else secondary(secondTtl)
            }
            exchange(1, 1500, 1, 60)
            assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, servers))
            exchange(2, 500, 2, 60)
            assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
                routing.lookup(0x08080808, null, servers))
            now += 1500
            assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, servers))
            exchange(3, 0, 60, 60)
            assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
                routing.lookup(0x08080808, null, servers))
        }
    }

    @Test fun tcpCloseAfterPrimaryKeepsAuxiliaryButEarlyResetCancelsIt() {
        val servers = mapOf("primary" to 1L, "secondary" to 2L)
        fun frame(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        fun flagged(packet: Ipv4Packet, flags: Int): Ipv4Packet {
            val bytes = packet.bytes.copyOf(); bytes[33] = flags.toByte()
            Checksum.writeTransport(bytes, 20, 6)
            return Ipv4Packet.parse(bytes)!!
        }
        for (closeWithReset in listOf(false, true)) {
            val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
                DomainRule("rule", "secondary", "www.example.com"))), "primary")
            val query = frame(dns(7, false))
            val task = routing.observeTcpChecked(tcp(query, 0x0afe5302, 0x01010101,
                12345, 53, 100), true, 1, servers).queries.single()
            if (!closeWithReset) assertTrue(routing.observeTcpChecked(flagged(tcp(byteArrayOf(),
                0x0afe5302, 0x01010101, 12345, 53, 100 + query.size), 0x11),
                true, 1, servers).accepted)
            val response = flagged(tcp(frame(dns(7, true, listOf(0x08080808))),
                0x01010101, 0x0afe5302, 53, 12345, 200),
                if (closeWithReset) 0x10 else 0x11)
            assertTrue(routing.observeTcpChecked(response, false, 1).accepted)
            if (closeWithReset) assertTrue(routing.observeTcpChecked(flagged(tcp(byteArrayOf(),
                0x01010101, 0x0afe5302, 53, 12345, 300), 0x14), false, 1).accepted)
            assertTrue(routing.auxiliaryTcpAnswer(task.token, "secondary", 2,
                dns(7, true, listOf(0x09090909))))
            assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
                routing.lookup(0x08080808, null, servers))
        }

        val early = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("rule", "secondary", "www.example.com"))), "primary")
        val task = early.observeTcpChecked(tcp(frame(dns(8, false)), 0x0afe5302, 0x01010101,
            12345, 53, 100), true, 1, servers).queries.single()
        early.observeTcpChecked(flagged(tcp(byteArrayOf(), 0x01010101, 0x0afe5302,
            53, 12345, 200), 0x14), false, 1)
        assertFalse(early.auxiliaryTcpAnswer(task.token, "secondary", 2,
            dns(8, true, listOf(0x09090909))))
    }

    @Test fun rejectedAndUnmatchedOldAnswersDoNotOverwriteFreshRoute() {
        val servers = mapOf("primary" to 1L)
        fun frame(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("rule", "primary", "www.example.com"))), "primary")
        routing.observeTcpChecked(tcp(frame(dns(1, false)), 0x0afe5302, 0x01010101,
            12345, 53, 100), true, 1, servers)
        val rst = tcp(byteArrayOf(), 0x01010101, 0x0afe5302, 53, 12345, 200).bytes.copyOf()
        rst[33] = 0x14; Checksum.writeTransport(rst, 20, 6)
        routing.observeTcpChecked(Ipv4Packet.parse(rst)!!, false, 1)
        routing.observeTcpChecked(tcp(frame(dns(2, false)), 0x0afe5302, 0x01010101,
            12346, 53, 100), true, 1, servers)
        routing.observeTcpChecked(tcp(frame(dns(2, true, listOf(0x08080808))),
            0x01010101, 0x0afe5302, 53, 12346, 200), false, 1)
        val match = DnsRouting.Lookup.Match("primary", 0x08080808)
        assertEquals(match, routing.lookup(0x08080808, null, servers))
        assertFalse(routing.observeTcpChecked(tcp(frame(dns(1, true, listOf(0x08080808))),
            0x01010101, 0x0afe5302, 53, 12345, 200), false, 1).accepted)
        assertEquals(match, routing.lookup(0x08080808, null, servers))
        routing.observeTcpChecked(tcp(frame(dns(3, false)), 0x0afe5302, 0x01010101,
            12347, 53, 100), true, 1, servers)
        assertFalse(routing.observeTcpChecked(tcp(frame(dns(4, true, listOf(0x08080808))),
            0x01010101, 0x0afe5302, 53, 12347, 200), false, 1).accepted)
        assertEquals(match, routing.lookup(0x08080808, null, servers))
    }

    @Test fun tcpObserverLossFromConnectionEvictionOrBadFramesStaysLocal() {
        val rules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com")))
        val servers = mapOf("primary" to 1L, "secondary" to 2L)
        fun frame(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        val routing = DnsRouting({ 1000 }, rules, "primary")
        repeat(129) { index ->
            routing.observeTcp(tcp(frame(dns(index, false)), 0x0afe5302, 0x01010101,
                12000 + index, 53, 100), true, 1, servers)
        }
        assertFalse(routing.observeTcpChecked(tcp(frame(dns(0, true, listOf(0x08080808))),
            0x01010101, 0x0afe5302, 53, 12000, 200), false, 1).accepted)
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, servers))
        assertEquals(DnsRouting.Lookup.None, routing.lookup(0x04040404, null, servers))

        for (badFrame in listOf(byteArrayOf(0x10, 0x01), frame(ByteArray(12)))) {
            val malformed = DnsRouting({ 1000 }, rules, "primary")
            assertFalse(malformed.observeTcpChecked(tcp(badFrame, 0x0afe5302, 0x01010101,
                12345, 53, 100), true, 1, servers).accepted)
            assertEquals(DnsRouting.Lookup.None,
                malformed.lookup(0x04040404, null, servers))
        }
    }

    @Test fun rejectedTcpTableLimitFailsClosedOnlyForBoundedInterval() {
        var now = 1000L
        val rules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "www.example.com")))
        val routing = DnsRouting({ now }, rules, "primary")
        val servers = mapOf("primary" to 1L, "secondary" to 2L)
        val badFrame = byteArrayOf(0x10, 0x01)
        repeat(257) { index ->
            assertFalse(routing.observeTcpChecked(tcp(badFrame, 0x0afe5302, 0x01010101,
                12000 + index, 53, 100), true, 1, servers).accepted)
        }
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x04040404, null, servers))
        now += 120_001
        assertEquals(DnsRouting.Lookup.None, routing.lookup(0x04040404, null, servers))
        val query = dns(99, false)
        assertTrue(routing.observeTcpChecked(tcp(byteArrayOf(0, query.size.toByte()) + query,
            0x0afe5302, 0x01010101, 13000, 53, 100), true, 1, servers).accepted)
    }

    @Test fun wildcardAndAmbiguityAreLabelAware() {
        assertEquals("*.xn--bcher-kva.example", DomainNames.pattern("*.BÜCHER.Example."))
        assertTrue(DomainNames.matches("*.example.com", "A.Example.Com."))
        assertTrue(DomainNames.matches("*.example.com", "example.com"))
        assertFalse(DomainNames.matches("*.example.com", "notexample.com"))
        assertThrows(IllegalArgumentException::class.java) {
            DomainRuleSet(listOf(DomainRule("a", "one", "*.example.com"),
                DomainRule("b", "two", "x.example.com")))
        }
    }

    @Test fun parserRejectsTruncationAndCompressionLoopAndIgnoresAdditional() {
        val valid = dns(7, true, listOf(0x08080808, 0x09090909))
        assertEquals(2, DnsParser.parse(valid)!!.addresses.size)
        assertNull(DnsParser.parse(valid.copyOf(valid.size - 1)))
        val loop = dns(7, false).clone()
        loop[12] = 0xc0.toByte(); loop[13] = 12
        assertNull(DnsParser.parse(loop))
        assertTrue(DnsParser.parse(dns(7, true, emptyList(), flags = 3))!!.addresses.isEmpty())
        assertTrue(DnsParser.parse(dns(7, true, listOf(0x08080808), flags = 0x0200))!!.addresses.isEmpty())
        val opt = dns(7, true, listOf(0x08080808)).toMutableList()
        opt[11] = 1 // one additional OPT record with a root owner
        opt.addAll(listOf<Byte>(0, 0, 41, 4, 0, 0, 0, 0, 0, 0, 0))
        assertEquals(1, DnsParser.parse(opt.toByteArray())!!.addresses.size)
    }

    @Test fun cnameChainUsesMinimumTtlAndIgnoresUnrelatedAdditionalA() {
        val out = ByteArrayOutputStream()
        word(out, 9); word(out, 0x8000); word(out, 1); word(out, 2); word(out, 0); word(out, 1)
        name(out, "www.example.com"); word(out, 1); word(out, 1)
        word(out, 0xc00c); word(out, 5); word(out, 1); word(out, 0); word(out, 20)
        val target = ByteArrayOutputStream().also { name(it, "cdn.example.com") }.toByteArray()
        word(out, target.size); out.write(target)
        name(out, "cdn.example.com"); word(out, 1); word(out, 1); word(out, 0); word(out, 60)
        word(out, 4); out.write(byteArrayOf(8, 8, 8, 8))
        name(out, "other.example.com"); word(out, 1); word(out, 1); word(out, 0); word(out, 60)
        word(out, 4); out.write(byteArrayOf(9, 9, 9, 9))
        assertEquals(listOf(DnsAddress(0x08080808, 20)), DnsParser.parse(out.toByteArray())!!.addresses)
    }

    @Test fun auxiliaryBeforePrimaryRestoresIdAndMapsBothDirections() {
        var now = 1000L
        val rules = DomainRuleSet(listOf(DomainRule("a", "secondary", "*.example.com")))
        val routing = DnsRouting({ now }, rules, "primary")
        val query = udp(dns(42, false))
        val sends = routing.query(query, mapOf("primary" to 1, "secondary" to 2))!!
        assertEquals(2, sends.size)
        val auxId = DnsParser.parse(sends.single { it.profileId == "secondary" }.packet.copyOfRange(28,
            sends.single { it.profileId == "secondary" }.packet.size))!!.id
        val primaryId = DnsParser.parse(sends.single { it.profileId == "primary" }.packet.copyOfRange(28,
            sends.single { it.profileId == "primary" }.packet.size))!!.id
        val aux = routing.answer(udp(dns(auxId, true, listOf(0x09090909)), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345), "secondary", 2)!!
        assertNull(aux.packet)
        val primary = routing.answer(udp(dns(primaryId, true, listOf(0x08080808)), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345), "primary", 1)!!
        assertEquals(42, DnsParser.parse(primary.packet!!.copyOfRange(28, primary.packet.size))!!.id)
        assertNotNull(Ipv4Packet.parse(primary.packet))
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
            routing.lookup(0x08080808, null, mapOf("primary" to 1, "secondary" to 2)))
        assertNull(routing.answer(udp(dns(primaryId, true, listOf(0x08080808)), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345), "primary", 1)!!.packet)
        val original = udp(ByteArray(4), dst = 0x08080808, dstPort = 443)
        val rewritten = PacketRewrite.address(original, 0x09090909, true)
        assertNotNull(Ipv4Packet.parse(rewritten))
        val reverse = udp(ByteArray(4), src = 0x09090909, dst = 0x0afe5302, srcPort = 443)
        assertNotNull(Ipv4Packet.parse(PacketRewrite.address(reverse, 0x08080808, false)))
        now += 60_000
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null,
            mapOf("primary" to 1, "secondary" to 2)))
    }

    @Test fun sharedIpAcrossProfilesFailsClosedAndTtlZeroDoesNotCache() {
        val rules = DomainRuleSet(listOf(DomainRule("a", "one", "www.example.com")))
        val routing = DnsRouting({ 1000 }, rules, "one")
        val query = udp(dns(1, false))
        val send = routing.query(query, mapOf("one" to 1))!!.single()
        val wireId = DnsParser.parse(send.packet.copyOfRange(28, send.packet.size))!!.id
        routing.answer(udp(dns(wireId, true, listOf(0x08080808), ttl = 0), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345), "one", 1)
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, mapOf("one" to 1)))
    }

    @Test fun commonCdnAddressWithDifferentDomainProfilesIsAmbiguous() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "one", "www.example.com"),
            DomainRule("b", "two", "cdn.example.com"))), "one")
        val servers = mapOf("one" to 1L, "two" to 2L)
        fun resolve(domain: String, id: Int) {
            val sends = routing.query(udp(dns(id, false, domain = domain), srcPort = 10000 + id), servers)!!
            for (send in sends) {
                val wire = DnsParser.parse(send.packet.copyOfRange(28, send.packet.size))!!.id
                routing.answer(udp(dns(wire, true, listOf(0x08080808), domain = domain),
                    src = 0x01010101, dst = 0x0afe5302, srcPort = 53, dstPort = 10000 + id),
                    send.profileId, send.generation)
            }
        }
        resolve("www.example.com", 1); resolve("cdn.example.com", 2)
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, servers))
    }

    @Test fun tcpFramesCanSpanSegmentsAndShareAConnection() {
        val first = dns(1, false); val second = dns(2, false)
        fun frame(data: ByteArray) = byteArrayOf((data.size ushr 8).toByte(), data.size.toByte()) + data
        val stream = frame(first) + frame(second)
        val framer = DnsTcpFramer()
        assertTrue(framer.offer(100, stream.copyOfRange(0, 5)).isEmpty())
        val messages = framer.offer(105, stream.copyOfRange(5, stream.size))
        assertEquals(listOf(1, 2), messages.map { DnsParser.parse(it)!!.id })
        assertTrue(framer.offer(100, stream).isEmpty()) // retransmission
        assertTrue(framer.offer(1000, byteArrayOf(0, 1, 0)).isEmpty()) // gap stays pending
        framer.begin(2000)
        assertEquals(listOf(1), framer.offer(2000, frame(first)).map { DnsParser.parse(it)!!.id })
    }

    @Test fun tcpFramerReordersSegmentsAndHandlesSequenceWrap() {
        val message = dns(17, false)
        val frame = byteArrayOf(0, message.size.toByte()) + message
        val start = 0xffff_fff8L
        val framer = DnsTcpFramer()
        framer.begin(start)
        assertTrue(framer.offer(8, frame.copyOfRange(16, frame.size)).isEmpty())
        assertTrue(framer.offer(start, frame.copyOfRange(0, 8)).isEmpty())
        assertEquals(1, framer.offer(0, frame.copyOfRange(8, 16)).size)
        assertTrue(framer.offer(8, frame.copyOfRange(16, frame.size)).isEmpty())
    }

    @Test fun tcpFramerRejectsHalfSequenceSpaceWithoutIndexOverflow() {
        val framer = DnsTcpFramer()
        framer.begin(0)
        assertTrue(framer.offer(0x8000_0000L, ByteArray(12)).isEmpty())
        assertTrue(framer.failed)
        framer.begin(0xffff_fff0L)
        val message = dns(17, false)
        val frame = byteArrayOf(0, message.size.toByte()) + message
        assertEquals(1, framer.offer(0xffff_fff0L, frame).size)
        assertFalse(framer.failed)
    }

    @Test fun auxiliaryTcpAnswerBeforeAndAfterPrimaryMapsOnlyMatchingGeneration() {
        val rules = DomainRuleSet(listOf(DomainRule("rule", "secondary", "*.example.com")))
        fun frame(message: ByteArray) = byteArrayOf((message.size ushr 8).toByte(), message.size.toByte()) + message
        for (auxiliaryFirst in listOf(false, true)) {
            val routing = DnsRouting({ 1000 }, rules, "primary")
            val query = dns(33, false)
            val tasks = routing.observeTcp(tcp(frame(query), 0x0afe5302, 0x01010101,
                12345, 53, 100), true, 11, mapOf("primary" to 11, "secondary" to 22))
            assertEquals(1, tasks.size)
            val task = tasks.single()
            assertFalse(routing.auxiliaryTcpAnswer(task.token, "secondary", 23,
                dns(33, true, listOf(0x09090909))))
            val secondary = { assertTrue(routing.auxiliaryTcpAnswer(task.token, "secondary", 22,
                dns(33, true, listOf(0x09090909)))) }
            val primary = { routing.observeTcp(tcp(frame(dns(33, true, listOf(0x08080808))),
                0x01010101, 0x0afe5302, 53, 12345, 400), false, 11) }
            if (auxiliaryFirst) { secondary(); primary() } else { primary(); secondary() }
            assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
                routing.lookup(0x08080808, null, mapOf("primary" to 11, "secondary" to 22)))
            routing.detach("secondary", 22)
            assertEquals(DnsRouting.Lookup.Ambiguous,
                routing.lookup(0x08080808, null, mapOf("primary" to 11, "secondary" to 23)))
        }
    }

    @Test fun sameTcpDnsIdAndQuestionFromTwoClientsKeepSeparateAuxiliaryAnswers() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("rule", "secondary", "www.example.com"))), "primary")
        fun frame(message: ByteArray) = byteArrayOf((message.size ushr 8).toByte(), message.size.toByte()) + message
        fun query(port: Int) = routing.observeTcp(tcp(frame(dns(55, false)), 0x0afe5302,
            0x01010101, port, 53, 100), true, 1,
            mapOf("primary" to 1, "secondary" to 2)).single()
        fun primary(port: Int, ip: Int) {
            routing.observeTcp(tcp(frame(dns(55, true, listOf(ip))), 0x01010101,
                0x0afe5302, 53, port, 200), false, 1)
        }
        val first = query(12345)
        val second = query(12346)
        assertNotEquals(first.token, second.token)
        primary(12345, 0x08080808)
        assertTrue(routing.auxiliaryTcpAnswer(second.token, "secondary", 2,
            dns(55, true, listOf(0x09090909))))
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("primary" to 1, "secondary" to 2)))
        assertTrue(routing.auxiliaryTcpAnswer(first.token, "secondary", 2,
            dns(55, true, listOf(0x07070707))))
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x07070707),
            routing.lookup(0x08080808, null, mapOf("primary" to 1, "secondary" to 2)))
        primary(12346, 0x0b0b0b0b)
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
            routing.lookup(0x0b0b0b0b, null, mapOf("primary" to 1, "secondary" to 2)))
    }

    @Test fun oldGenerationAndTimedOutRepliesCannotPopulateNewSession() {
        var now = 1000L
        val routing = DnsRouting({ now }, DomainRuleSet(listOf(
            DomainRule("a", "one", "www.example.com"))), "one", maxPending = 1)
        val packet = udp(dns(7, false))
        val sent = routing.query(packet, mapOf("one" to 1))!!.single()
        assertTrue(routing.query(packet, mapOf("one" to 1))!!.isEmpty())
        val wireId = DnsParser.parse(sent.packet.copyOfRange(28, sent.packet.size))!!.id
        val answer = udp(dns(wireId, true, listOf(0x08080808)), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345)
        assertNull(routing.answer(answer, "one", 2)!!.packet)
        now += 10_000
        assertNull(routing.answer(answer, "one", 1)!!.packet)
        assertEquals(DnsRouting.Lookup.None, routing.lookup(0x08080808, null, mapOf("one" to 2)))
        routing.clear()
        assertEquals(0, routing.counters.pending)
    }

    @Test fun detachedSelectedServerLeavesFailClosedAddress() {
        val rules = DomainRuleSet(listOf(DomainRule("a", "secondary", "www.example.com")))
        val routing = DnsRouting({ 1000 }, rules, "primary")
        val sends = routing.query(udp(dns(7, false)), mapOf("primary" to 1, "secondary" to 2))!!
        for (send in sends) {
            val id = DnsParser.parse(send.packet.copyOfRange(28, send.packet.size))!!.id
            val answer = udp(dns(id, true, listOf(if (send.profileId == "primary") 0x08080808 else 0x09090909)),
                src = 0x01010101, dst = 0x0afe5302, srcPort = 53, dstPort = 12345)
            routing.answer(answer, send.profileId, send.generation)
        }
        assertTrue(routing.lookup(0x08080808, null, mapOf("primary" to 1, "secondary" to 2))
            is DnsRouting.Lookup.Match)
        routing.detach("secondary", 2)
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("primary" to 1)))
    }

    @Test fun identicalDnsIdsFromTwoApplicationFlowsRemainDistinct() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "one", "www.example.com"))), "one")
        val first = routing.query(udp(dns(77, false), srcPort = 10001), mapOf("one" to 1))!!.single()
        val second = routing.query(udp(dns(77, false), srcPort = 10002), mapOf("one" to 1))!!.single()
        val firstId = DnsParser.parse(first.packet.copyOfRange(28, first.packet.size))!!.id
        val secondId = DnsParser.parse(second.packet.copyOfRange(28, second.packet.size))!!.id
        assertNotEquals(firstId, secondId)
        val secondReply = routing.answer(udp(dns(secondId, true, listOf(0x08080808)),
            src = 0x01010101, dst = 0x0afe5302, srcPort = 53, dstPort = 10002), "one", 1)!!
        val firstReply = routing.answer(udp(dns(firstId, true, listOf(0x08080808)),
            src = 0x01010101, dst = 0x0afe5302, srcPort = 53, dstPort = 10001), "one", 1)!!
        assertEquals(77, DnsParser.parse(secondReply.packet!!.copyOfRange(28, secondReply.packet.size))!!.id)
        assertEquals(77, DnsParser.parse(firstReply.packet!!.copyOfRange(28, firstReply.packet.size))!!.id)
        assertEquals(2L, routing.counters.completed)
    }

    @Test fun unavailableDomainServerMustNotReturnNoRuleAndRecoversOnNewAnswer() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        resolve(routing, mapOf("primary" to 1), 1, listOf(0x08080808))
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("primary" to 1)))
        resolve(routing, mapOf("primary" to 1, "secondary" to 2), 2,
            listOf(0x08080808), listOf(0x09090909))
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
            routing.lookup(0x08080808, null, mapOf("primary" to 1, "secondary" to 2)))
    }

    @Test fun detachedOrMissingAuxiliaryBeforePrimaryAndLostAuxiliaryStayBlocked() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        val servers = mapOf("primary" to 1L, "secondary" to 2L)
        val sends = routing.query(udp(dns(1, false)), servers)!!
        routing.detach("secondary", 2)
        val primary = sends.single { it.profileId == "primary" }
        val wire = DnsParser.parse(primary.packet.copyOfRange(28, primary.packet.size))!!.id
        routing.answer(udp(dns(wire, true, listOf(0x08080808)), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345), "primary", 1)
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("primary" to 1)))
        val lost = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        val onlyPrimaryReply = lost.query(udp(dns(2, false)), servers)!!.single { it.profileId == "primary" }
        val secondWire = DnsParser.parse(onlyPrimaryReply.packet.copyOfRange(28, onlyPrimaryReply.packet.size))!!.id
        lost.answer(udp(dns(secondWire, true, listOf(0x08080808)), src = 0x01010101,
            dst = 0x0afe5302, srcPort = 53, dstPort = 12345), "primary", 1)
        assertEquals(DnsRouting.Lookup.Ambiguous, lost.lookup(0x08080808, null, servers))
    }

    @Test fun storedAuxiliaryAnswerCannotUndoDetachWhenPrimaryArrivesLater() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        val sends = routing.query(udp(dns(1, false)),
            mapOf("primary" to 1L, "secondary" to 2L))!!
        val primary = sends.single { it.profileId == "primary" }
        val secondary = sends.single { it.profileId == "secondary" }
        assertTrue(reply(routing, secondary, 0x09090909).accepted)
        routing.detach("secondary", 2)
        assertTrue(reply(routing, primary, 0x08080808).accepted)
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("primary" to 1L)))
        assertNull(reply(routing, primary, 0x08080808).packet)
        assertEquals(1L, routing.counters.completed)
    }

    @Test fun replacingAuxiliaryGenerationCannotCompleteOldPendingRequest() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        val old = routing.query(udp(dns(1, false)),
            mapOf("primary" to 1L, "secondary" to 2L))!!
        val oldPrimary = old.single { it.profileId == "primary" }
        val oldSecondary = old.single { it.profileId == "secondary" }
        assertTrue(reply(routing, oldSecondary, 0x09090909).accepted)
        routing.detach("secondary", 2)
        val active = mapOf("primary" to 1L, "secondary" to 3L)
        assertTrue(reply(routing, oldPrimary, 0x08080808).accepted)
        assertNull(reply(routing, oldSecondary, 0x09090909).packet)
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, active))

        val fresh = routing.query(udp(dns(2, false)), active)!!
        assertTrue(reply(routing, fresh.single { it.profileId == "primary" }, 0x08080808).accepted)
        assertTrue(reply(routing, fresh.single { it.profileId == "secondary" }, 0x07070707).accepted)
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x07070707),
            routing.lookup(0x08080808, null, active))
        assertEquals(2L, routing.counters.completed)
    }

    @Test fun lateAuxiliaryAfterPrimaryAndDetachCannotResolveRoute() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        val sends = routing.query(udp(dns(1, false)),
            mapOf("primary" to 1L, "secondary" to 2L))!!
        val primary = sends.single { it.profileId == "primary" }
        val secondary = sends.single { it.profileId == "secondary" }
        assertTrue(reply(routing, primary, 0x08080808).accepted)
        routing.detach("secondary", 2)
        assertFalse(reply(routing, secondary, 0x09090909).accepted)
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("primary" to 1L, "secondary" to 3L)))
        assertEquals(1L, routing.counters.completed)
    }

    @Test fun repeatedSameAnswerRefreshesTtlWithoutSaturatingCache() {
        var now = 1000L
        val routing = DnsRouting({ now }, DomainRuleSet(listOf(
            DomainRule("a", "primary", "www.example.com"))), "primary", maxRecords = 2)
        val servers = mapOf("primary" to 1L)
        repeat(3) { resolve(routing, servers, it, listOf(0x08080808), ttl = 2) }
        assertEquals(1, routing.counters.active)
        assertEquals(0L, routing.counters.limits)
        now += 1500
        resolve(routing, servers, 4, listOf(0x08080808), ttl = 2)
        now += 1500
        assertEquals(DnsRouting.Lookup.Match("primary", 0x08080808),
            routing.lookup(0x08080808, null, servers))
        now += 500
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, servers))
        resolve(routing, servers, 5, listOf(0x08080808), ttl = 2)
        assertEquals(DnsRouting.Lookup.Match("primary", 0x08080808),
            routing.lookup(0x08080808, null, servers))
    }

    @Test fun fullCacheBlocksOnlyNewKnownAddressAndKeepsMemoryBounded() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "primary", "www.example.com"))), "primary", maxRecords = 1)
        val servers = mapOf("primary" to 1L)
        resolve(routing, servers, 1, listOf(0x08080808))
        resolve(routing, servers, 2, listOf(0x09090909))
        repeat(10) { resolve(routing, servers, 10 + it, listOf(0x09090909)) }
        assertEquals(1, routing.counters.active)
        assertEquals(DnsRouting.Lookup.Match("primary", 0x08080808),
            routing.lookup(0x08080808, null, servers))
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x09090909, null, servers))
        assertEquals(DnsRouting.Lookup.None, routing.lookup(0x04040404, null, servers))
    }

    @Test fun lastResortGlobalDenialOnlyAfterBothBoundedTablesFill() {
        var now = 1000L
        val routing = DnsRouting({ now }, DomainRuleSet(listOf(
            DomainRule("a", "primary", "www.example.com"))), "primary", maxRecords = 1)
        val servers = mapOf("primary" to 1L)
        for (index in 1..33) {
            resolve(routing, servers, index, listOf(0x08080000 or index), ttl = 1)
        }
        assertEquals(DnsRouting.Lookup.None, routing.lookup(0x04040404, null, servers))
        resolve(routing, servers, 34, listOf(0x08080022), ttl = 1)
        assertEquals(1, routing.counters.active)
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x04040404, null, servers))
        now += 1000
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x04040404, null, servers))
    }

    @Test fun unrelatedDnsAnswersCannotCrowdOutRuledAddress() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "primary", "www.example.com"))), "primary", maxRecords = 1)
        val servers = mapOf("primary" to 1L)
        repeat(40) { index ->
            resolve(routing, servers, index, listOf(0x08080000 or (index + 1)),
                domain = "unrelated$index.example.com")
        }
        assertEquals(DnsRouting.Lookup.None, routing.lookup(0x04040404, null, servers))
        resolve(routing, servers, 100, listOf(0x08080808))
        assertEquals(DnsRouting.Lookup.Match("primary", 0x08080808),
            routing.lookup(0x08080808, null, servers))
        assertEquals(1, routing.counters.active)
    }

    @Test fun reorderedSameSetRemainsIdentityWhileUnequalSetsRemainUnresolved() {
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        val servers = mapOf("primary" to 1L, "secondary" to 2L)
        resolve(routing, servers, 1, listOf(0x08080808, 0x09090909))
        resolve(routing, servers, 2, listOf(0x08080808, 0x09090909),
            listOf(0x09090909, 0x08080808))
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x08080808),
            routing.lookup(0x08080808, null, servers))
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x09090909),
            routing.lookup(0x09090909, null, servers))
        assertEquals(4, routing.counters.active) // primary and secondary, two visible IPs each
        val unequal = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        resolve(unequal, servers, 3, listOf(0x08080808, 0x09090909), listOf(0x08080808))
        assertEquals(DnsRouting.Lookup.Match("secondary", 0x08080808),
            unequal.lookup(0x08080808, null, servers))
        assertEquals(DnsRouting.Lookup.Ambiguous, unequal.lookup(0x09090909, null, servers))
        val different = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary")
        resolve(different, servers, 4, listOf(0x08080808, 0x09090909),
            listOf(0x04040404, 0x05050505))
        assertEquals(DnsRouting.Lookup.Ambiguous, different.lookup(0x08080808, null, servers))
        assertEquals(DnsRouting.Lookup.Ambiguous, different.lookup(0x09090909, null, servers))
    }

    @Test fun secondaryRuleSeenOverTcpDeniesDirectAndDuplicatePrimaryTcpAnswerRefreshes() {
        fun frame(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("a", "secondary", "www.example.com"))), "primary", maxRecords = 1)
        val query = frame(dns(9, false)); val response = frame(dns(9, true, listOf(0x08080808)))
        routing.observeTcp(tcp(query, 0x0afe5302, 0x01010101, 12345, 53, 100), true, 1)
        routing.observeTcp(tcp(response, 0x01010101, 0x0afe5302, 53, 12345, 200), false, 1)
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("primary" to 1, "secondary" to 2)))
        assertEquals(1, routing.counters.active)
        val nextQuery = frame(dns(10, false)); val nextAnswer = frame(dns(10, true, listOf(0x08080808)))
        routing.observeTcp(tcp(nextQuery, 0x0afe5302, 0x01010101, 12345, 53,
            100 + query.size), true, 1)
        routing.observeTcp(tcp(nextAnswer, 0x01010101, 0x0afe5302, 53, 12345,
            200 + response.size), false, 1)
        assertEquals(1, routing.counters.active)
        assertEquals(0L, routing.counters.limits)
    }

    @Test fun repeatedPrimaryTcpAnswerUpsertsOnePositiveRecord() {
        var now = 1000L
        fun frame(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        val routing = DnsRouting({ now }, DomainRuleSet(listOf(
            DomainRule("a", "primary", "www.example.com"))), "primary", maxRecords = 1)
        var outgoingSequence = 100
        var incomingSequence = 200
        repeat(3) { index ->
            val query = frame(dns(index + 1, false))
            val answer = frame(dns(index + 1, true, listOf(0x08080808), ttl = 2))
            routing.observeTcp(tcp(query, 0x0afe5302, 0x01010101, 12345, 53,
                outgoingSequence), true, 1)
            routing.observeTcp(tcp(answer, 0x01010101, 0x0afe5302, 53, 12345,
                incomingSequence), false, 1)
            outgoingSequence += query.size; incomingSequence += answer.size
            now += 500
        }
        assertEquals(1, routing.counters.active)
        assertEquals(0L, routing.counters.limits)
        assertEquals(DnsRouting.Lookup.Match("primary", 0x08080808),
            routing.lookup(0x08080808, null, mapOf("primary" to 1)))
        now += 1500
        assertEquals(DnsRouting.Lookup.Ambiguous, routing.lookup(0x08080808, null, mapOf("primary" to 1)))
    }

    @Test fun concurrentQueriesKeepTheirOwnPrimaryAndWireIdentity() {
        val rules = DomainRuleSet(listOf(DomainRule("a", "one", "www.example.com")))
        val routing = DnsRouting({ 1000 }, rules, "legacy")
        val servers = mapOf("one" to 1L, "two" to 2L)
        val first = routing.query(udp(dns(7, false), srcPort = 12001), servers, "one")!!
        val second = routing.query(udp(dns(7, false), srcPort = 12002), servers, "two")!!
        assertEquals(setOf("one", "two"), first.map { it.profileId }.toSet())
        assertEquals(setOf("one", "two"), second.map { it.profileId }.toSet())
        fun response(send: DnsRouting.Send, port: Int): DnsRouting.Answer {
            val wire = DnsParser.parse(send.packet.copyOfRange(28, send.packet.size))!!.id
            return routing.answer(udp(dns(wire, true, listOf(0x08080808)),
                src = 0x01010101, dst = 0x0afe5302, srcPort = 53, dstPort = port),
                send.profileId, send.generation)!!
        }
        assertNull(response(first.single { it.profileId == "two" }, 12001).packet)
        assertNull(response(second.single { it.profileId == "one" }, 12002).packet)
        val firstAnswer = response(first.single { it.profileId == "one" }, 12001).packet!!
        val secondAnswer = response(second.single { it.profileId == "two" }, 12002).packet!!
        assertEquals(7, DnsParser.parse(firstAnswer.copyOfRange(28, firstAnswer.size))!!.id)
        assertEquals(7, DnsParser.parse(secondAnswer.copyOfRange(28, secondAnswer.size))!!.id)
        assertNull(response(first.single { it.profileId == "one" }, 12001).packet)
    }

    @Test fun tcpPrimaryDetachRejectsOldConnectionAfterReattach() {
        fun frame(bytes: ByteArray) = byteArrayOf((bytes.size ushr 8).toByte(), bytes.size.toByte()) + bytes
        val routing = DnsRouting({ 1000 }, DomainRuleSet(listOf(
            DomainRule("rule", "two", "www.example.com"))), "legacy")
        val query = tcp(frame(dns(4, false)), 0x0afe5302, 0x01010101, 12345, 53, 100)
        routing.observeTcpChecked(query, true, 1, mapOf("one" to 1, "two" to 2), "one", true)
        routing.detach("one", 1)
        val old = tcp(frame(dns(4, true, listOf(0x08080808))),
            0x01010101, 0x0afe5302, 53, 12345, 200)
        assertFalse(routing.observeTcpChecked(old, false, 1, primary = "one").accepted)
        assertEquals(DnsRouting.Lookup.Ambiguous,
            routing.lookup(0x08080808, null, mapOf("one" to 3, "two" to 2)))
    }
}
