package org.miga.core

import java.io.Closeable
import java.io.IOException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

fun interface ConnectionOwnerResolver { fun ownerUid(flow: FlowKey): Int }

interface DirectPacketStack : Closeable {
    /** Must use a bounded queue and return false when it cannot accept a packet. */
    fun send(packet: ByteArray): Boolean
}

data class DirectCounters(
    val sent: Long = 0,
    val received: Long = 0,
    val unavailable: Long = 0,
    val queueDrops: Long = 0,
    val ambiguousOwner: Long = 0,
    val serverUnavailable: Long = 0,
    val rejectedReplies: Long = 0,
)

data class ServerTransport(
    val profileId: String,
    val generation: Long,
    val transport: DatagramTransport,
    val codec: LegacyMigaCodec,
    val serverIp: Int,
    val firstPort: Int,
    val lastPort: Int,
    val portPicker: () -> Int,
)

/** One TUN reader and writer. UDP readers only enqueue tagged datagrams. */
class MultiTunnelEngine(
    private val device: PacketDevice,
    private val owner: ConnectionOwnerResolver,
    private val uidProfiles: Map<Int, String?>,
    private val dnsProfileId: String,
    private val clock: Clock,
    private val onStats: (String, Long, TunnelStats) -> Unit,
    private val onFailure: (String, Long) -> Unit,
    private val onFatal: () -> Unit = {},
    queueCapacity: Int = 128,
    private val maxFlows: Int = 4096,
    private val flowTtlMillis: Long = 120_000,
    rules: StaticIpv4RuleSet = StaticIpv4RuleSet(emptyList()),
    private val allowDirect: Boolean = false,
    domainRules: DomainRuleSet? = null,
    private val auxiliaryDnsTcp: ((DnsRouting.TcpQuery) -> Unit)? = null,
) : Closeable {
    init { require(queueCapacity > 0 && maxFlows > 0 && flowTtlMillis > 0) }

    private sealed interface Event {
        data class Out(val bytes: ByteArray) : Event
        data class In(val id: String, val generation: Long, val datagram: ReceivedDatagram) : Event
        data class DirectIn(val generation: Long, val bytes: ByteArray) : Event
    }
    private data class Active(val server: ServerTransport, val reader: Thread)
    private data class DirectActive(val stack: DirectPacketStack, val generation: Long)
    private data class AuxiliaryPort(val profileId: String, val generation: Long, var observed: Boolean = false)
    private data class Pin(val id: String?, val generation: Long, var seen: Long, val actualIp: Int? = null)
    private sealed interface Target {
        data class Server(val value: ServerTransport) : Target
        data class Direct(val value: DirectActive) : Target
    }
    private val lock = Any()
    private val active = mutableMapOf<String, Active>()
    private var direct: DirectActive? = null
    private val routePolicy = StaticRoutePolicy(uidProfiles.toMap(), rules)
    private val dnsRules = domainRules ?: DomainRuleSet(emptyList())
    private val dnsRouting = DnsRouting(clock, dnsRules, dnsProfileId)
    private val pins = LinkedHashMap<FlowKey, Pin>(16, .75f, true)
    private val wireToOriginal = HashMap<FlowKey, FlowKey>()
    private val unknown = LinkedHashMap<FlowKey, Long>(16, .75f, true)
    private val auxiliaryPorts = HashMap<Int, AuxiliaryPort>()
    private val retiredAuxiliaryPorts = LinkedHashMap<Int, Long>()
    private val queue = ArrayBlockingQueue<Event>(queueCapacity)
    private val running = AtomicBoolean(false)
    private val queueDrops = AtomicLong()
    private var tunReader: Thread? = null
    private var worker: Thread? = null
    private val stats = mutableMapOf<String, TunnelStats>()
    private var unknownOwner = 0L
    private var directCounts = DirectCounters()
    val unknownOwnerDrops: Long get() = synchronized(lock) { unknownOwner }
    val directCounters: DirectCounters get() = synchronized(lock) { directCounts }
    val dnsCounters: DnsCounters get() = dnsRouting?.counters ?: DnsCounters()

    /** Register before the OS TCP stack emits SYN through this VPN. */
    fun registerAuxiliaryDnsPort(port: Int, profile: String, generation: Long): Boolean = synchronized(lock) {
        if (!running.get() || port !in 1..65535 || auxiliaryPorts.size >= 32 ||
            port in auxiliaryPorts || active[profile]?.server?.generation != generation) false
        else {
            pins.entries.removeIf { it.key.protocol == 6 && it.key.sourcePort == port &&
                it.key.destinationPort == 53 && it.key.destinationIp == DNS_ADDRESS }
            retiredAuxiliaryPorts.remove(port)
            auxiliaryPorts[port] = AuxiliaryPort(profile, generation)
            true
        }
    }

    fun unregisterAuxiliaryDnsPort(port: Int, profile: String, generation: Long) = synchronized(lock) {
        if (auxiliaryPorts[port]?.let { it.profileId == profile && it.generation == generation } == true)
            auxiliaryPorts.remove(port).also { retireAuxiliaryPort(port) }
    }

    fun auxiliaryDnsPortObserved(port: Int, profile: String, generation: Long): Boolean =
        synchronized(lock) { auxiliaryPorts[port]?.let {
            it.profileId == profile && it.generation == generation && it.observed
        } == true }

    fun auxiliaryDnsAnswer(query: DnsRouting.TcpQuery, answer: ByteArray): Boolean =
        dnsRouting?.auxiliaryTcpAnswer(query.token, query.profileId, query.generation, answer) ?: false

    fun start() {
        check(running.compareAndSet(false, true))
        worker = Thread(::process, "miga-multi-worker").also { it.start() }
        tunReader = Thread(::readTun, "miga-tun-reader").also { it.start() }
    }

    fun attach(server: ServerTransport) {
        require(server.firstPort in 1..65535 && server.lastPort in server.firstPort..65535)
        check(running.get())
        val reader = Thread({ readUdp(server) }, "miga-udp-${server.profileId.take(8)}")
        synchronized(lock) {
            check(server.profileId !in active)
            active[server.profileId] = Active(server, reader)
            stats[server.profileId] = TunnelStats()
        }
        reader.start()
    }

    fun detach(id: String, generation: Long) {
        val old = synchronized(lock) {
            val current = active[id] ?: return
            if (current.server.generation != generation) return
            active.remove(id)
            auxiliaryPorts.entries.removeIf {
                if (it.value.profileId == id && it.value.generation == generation) {
                    retireAuxiliaryPort(it.key); true
                } else false
            }
            pins.entries.removeIf { it.value.id == id }
            wireToOriginal.entries.removeIf { it.value !in pins }
            dnsRouting?.detach(id, generation)
            current
        }
        try { old.server.transport.close() }
        finally { if (old.reader !== Thread.currentThread()) old.reader.join(1_500) }
    }

    fun attachDirect(stack: DirectPacketStack, generation: Long) {
        check(allowDirect && running.get())
        synchronized(lock) {
            check(direct == null)
            direct = DirectActive(stack, generation)
        }
    }

    fun detachDirect(generation: Long) {
        val previous = synchronized(lock) {
            val current = direct ?: return
            if (current.generation != generation) return
            direct = null
            pins.entries.removeIf { it.value.id == null }
            current
        }
        previous.stack.close()
    }

    fun offerDirectResponse(generation: Long, bytes: ByteArray) {
        if (!running.get()) return
        if (!queue.offer(Event.DirectIn(generation, bytes))) {
            queueDrops.incrementAndGet()
            synchronized(lock) { directCounts = directCounts.copy(queueDrops = directCounts.queueDrops + 1) }
        }
    }

    private fun readTun() {
        try {
            while (running.get()) {
                val bytes = device.read()
                if (bytes == null) { if (running.get()) onFatal(); break }
                if (!queue.offer(Event.Out(bytes))) queueDrops.incrementAndGet()
            }
        } catch (_: Exception) { if (running.get()) onFatal() }
    }

    private fun readUdp(server: ServerTransport) {
        try {
            while (running.get()) {
                val received = server.transport.receive()
                if (received == null) {
                    signalFailure(server.profileId, server.generation)
                    break
                }
                if (!queue.offer(Event.In(server.profileId, server.generation, received))) queueDrops.incrementAndGet()
            }
        } catch (_: Exception) {
            signalFailure(server.profileId, server.generation)
        }
    }

    private fun signalFailure(id: String, generation: Long) {
        val current = synchronized(lock) { running.get() && active[id]?.server?.generation == generation }
        if (current) onFailure(id, generation)
    }

    private fun process() {
        while (running.get()) {
            val event = try { queue.take() } catch (_: InterruptedException) { break }
            if (!running.get()) break
            when (event) {
                is Event.Out -> outgoing(event.bytes)
                is Event.In -> incoming(event)
                is Event.DirectIn -> incomingDirect(event)
            }
        }
    }

    private fun outgoing(bytes: ByteArray) {
        val packet = if (bytes.size <= TunnelPacketLimits.MAX_INNER_PACKET) Ipv4Packet.parse(bytes) else null
        if (packet == null) { queueDrops.incrementAndGet(); return }
        val key = FlowKey.from(packet)
        val now = clock.elapsedMillis()
        if (packet.protocol == 17 && key.destinationPort == 53 &&
            key.destinationIp == DNS_ADDRESS) {
            val message = DnsParser.parse(packet.bytes.copyOfRange(packet.headerLength + 8, packet.bytes.size))
            if (message == null || message.response || message.truncated) return
            val uid = try { owner.ownerUid(key) } catch (_: Exception) { -1 }
            if (uid < 0 || uid in uidProfiles && uidProfiles[uid] == null) return
            val selected = uidProfiles[uid] ?: dnsRules.profileFor(message.question.name)
            if (selected == null) {
                val target = choose(key, now)
                if (target is Target.Direct) {
                    val accepted = try { target.value.stack.send(bytes) } catch (_: Exception) { false }
                    synchronized(lock) { directCounts = directCounts.copy(
                        sent = directCounts.sent + if (accepted) 1 else 0,
                        queueDrops = directCounts.queueDrops + if (accepted) 0 else 1) }
                }
                return
            }
            val servers = synchronized(lock) { active.mapValues { it.value.server.generation } }
            val sends = dnsRouting.query(packet, servers, selected) ?: emptyList()
            for (send in sends) {
                val server = synchronized(lock) { active[send.profileId]?.server?.takeIf { it.generation == send.generation } }
                    ?: continue
                try {
                    val port = server.portPicker(); require(port in server.firstPort..server.lastPort)
                    server.transport.send(server.codec.encode(send.packet, port), port)
                    update(server.profileId, server.generation) { it.copy(sent = it.sent + 1,
                        unansweredSinceMillis = if (it.unansweredSinceMillis == 0L) now else it.unansweredSinceMillis) }
                } catch (_: Exception) { signalFailure(server.profileId, server.generation) }
            }
            return
        }
        val target = choose(key, now) ?: return
        if (target is Target.Direct) {
            val accepted = try { target.value.stack.send(bytes) } catch (_: Exception) { false }
            synchronized(lock) {
                if (direct?.generation == target.value.generation) directCounts = directCounts.copy(
                    sent = directCounts.sent + if (accepted) 1 else 0,
                    queueDrops = directCounts.queueDrops + if (accepted) 0 else 1)
            }
            return
        }
        val server = (target as Target.Server).value
        val maxMss = (TunnelPacketLimits.MAX_INNER_PACKET - packet.headerLength - packet.transportHeaderLength)
            .coerceAtMost(TunnelPacketLimits.TUNNEL_MAX_MSS)
        if (maxMss < 1) return
        val clamped = packet.clampMss(maxMss) ?: return
        val actualIp = synchronized(lock) { pins[key]?.actualIp }
        val payload = if (actualIp != null && actualIp != key.destinationIp)
            PacketRewrite.address(Ipv4Packet.parse(clamped) ?: return, actualIp, true) else clamped
        if (packet.protocol == 6 && key.destinationPort == 53 && key.destinationIp == DNS_ADDRESS) {
            val generations = synchronized(lock) { active.mapValues { it.value.server.generation } }
            val observation = dnsRouting.observeTcpChecked(packet, true, server.generation,
                generations, server.profileId, applicationRule = true)
            if (observation?.accepted == false) return
            observation?.queries?.forEach {
                runCatching { auxiliaryDnsTcp?.invoke(it) }
            }
        }
        try {
            val port = server.portPicker()
            require(port in server.firstPort..server.lastPort)
            server.transport.send(server.codec.encode(payload, port), port)
            if (packet.protocol == 6 && packet.bytes[packet.headerLength + 13].toInt() and 2 != 0 &&
                key.destinationPort == 53 && key.destinationIp == DNS_ADDRESS &&
                key.sourceIp == VPN_ADDRESS) synchronized(lock) {
                auxiliaryPorts[key.sourcePort]?.takeIf {
                    it.profileId == server.profileId && it.generation == server.generation
                }?.observed = true
            }
            update(server.profileId, server.generation) { it.copy(sent = it.sent + 1,
                unansweredSinceMillis = if (it.unansweredSinceMillis == 0L) now else it.unansweredSinceMillis) }
        } catch (_: Exception) { signalFailure(server.profileId, server.generation) }
    }

    private fun choose(key: FlowKey, now: Long): Target? {
        val pinned = synchronized(lock) {
            prune(now)
            pins[key]?.also { it.seen = now }
        }
        if (pinned != null) return synchronized(lock) { targetFor(pinned) }
        if (key.protocol == 6 && key.sourceIp == VPN_ADDRESS && key.destinationIp == DNS_ADDRESS &&
            key.destinationPort == 53 && synchronized(lock) {
                retiredAuxiliaryPorts[key.sourcePort]?.let { now < it } == true
            }) return null
        if (synchronized(lock) { unknown[key]?.let { now >= it && now - it < 5_000 } == true }) return null
        var mappedIp: Int? = null
        val auxiliary = if (key.protocol == 6 && key.destinationPort == 53 &&
            key.destinationIp == DNS_ADDRESS && key.sourceIp == VPN_ADDRESS)
            synchronized(lock) { auxiliaryPorts[key.sourcePort] } else null
        val decision = if (auxiliary != null) RouteDecision.Server(auxiliary.profileId)
            else if (key.destinationPort == 53 && key.destinationIp == DNS_ADDRESS) {
                val uid = try { owner.ownerUid(key) } catch (_: Exception) { -1 }
                when {
                    uid < 0 -> RouteDecision.UnknownOwner
                    uid in uidProfiles -> uidProfiles[uid]?.let(RouteDecision::Server)
                        ?: RouteDecision.AmbiguousOwner
                    // The domain is unknown at TCP SYN. Without an application assignment,
                    // a domain rule cannot safely select this connection's server.
                    key.protocol == 6 && dnsRules.isNotEmpty() -> RouteDecision.AmbiguousDns
                    else -> RouteDecision.Direct
                }
            } else {
            val uid = try { owner.ownerUid(key) } catch (_: Exception) { -1 }
            val basic = routePolicy.decide(uid, key.destinationIp)
            val lookup = when (basic) {
                is RouteDecision.Server -> if (uid in uidProfiles) dnsRouting?.lookup(key.destinationIp, basic.profileId,
                    synchronized(lock) { active.mapValues { it.value.server.generation } }) else null
                RouteDecision.Direct -> dnsRouting?.lookup(key.destinationIp, null,
                    synchronized(lock) { active.mapValues { it.value.server.generation } })
                else -> null
            }
            when (lookup) {
                is DnsRouting.Lookup.Match -> { mappedIp = lookup.actualIp
                    if (basic == RouteDecision.Direct) RouteDecision.Server(lookup.profileId) else basic }
                DnsRouting.Lookup.Ambiguous -> if (basic is RouteDecision.Server) basic
                    else RouteDecision.AmbiguousDns
                else -> basic
            }
        }
        return synchronized(lock) {
            pins[key]?.let { return@synchronized targetFor(it) }
            val target = when (decision) {
                is RouteDecision.Server -> active[decision.profileId]?.server?.takeIf {
                    auxiliary == null || it.generation == auxiliary.generation
                }?.let(Target::Server).also {
                    if (it == null) directCounts = directCounts.copy(serverUnavailable = directCounts.serverUnavailable + 1)
                }
                RouteDecision.Direct -> if (allowDirect) direct?.let(Target::Direct).also {
                    if (it == null) directCounts = directCounts.copy(unavailable = directCounts.unavailable + 1)
                } else {
                    unknownOwner++
                    unknown[key] = now
                    if (unknown.size > 1024) unknown.remove(unknown.keys.first())
                    null
                }
                RouteDecision.UnknownOwner, RouteDecision.AmbiguousOwner, RouteDecision.AmbiguousDns -> {
                    unknownOwner++
                    if (decision == RouteDecision.AmbiguousOwner)
                        directCounts = directCounts.copy(ambiguousOwner = directCounts.ambiguousOwner + 1)
                    unknown[key] = now
                    if (unknown.size > 1024) unknown.remove(unknown.keys.first())
                    null
                }
            }
            if (target != null) {
                pins[key] = when (target) {
                    is Target.Server -> Pin(target.value.profileId, target.value.generation, now, mappedIp)
                    is Target.Direct -> Pin(null, target.value.generation, now)
                }
                if (mappedIp != null && mappedIp != key.destinationIp) {
                    val wire = key.copy(destinationIp = mappedIp)
                    val previous = wireToOriginal[wire]
                    if (previous != null && previous != key) { pins.remove(key); return@synchronized null }
                    wireToOriginal[wire] = key
                }
                if (pins.size > maxFlows) pins.remove(pins.keys.first())
                wireToOriginal.entries.removeIf { it.value !in pins }
            }
            target
        }
    }

    private fun targetFor(pin: Pin): Target? = if (pin.id == null)
        direct?.takeIf { it.generation == pin.generation }?.let(Target::Direct)
    else active[pin.id]?.server?.takeIf { it.generation == pin.generation }?.let(Target::Server)

    private fun incomingDirect(event: Event.DirectIn) {
        if (event.bytes.isEmpty() || event.bytes.size > TunnelPacketLimits.MAX_INNER_PACKET) {
            rejectDirectReply(); return
        }
        val packet = Ipv4Packet.parse(event.bytes) ?: run { rejectDirectReply(); return }
        val key = FlowKey.from(packet).reverse()
        val now = clock.elapsedMillis()
        val owned = synchronized(lock) {
            val pin = pins[key]
            if (direct?.generation != event.generation || pin == null || pin.id != null ||
                pin.generation != event.generation || now < pin.seen || now - pin.seen >= flowTtlMillis) false
            else { pin.seen = now; true }
        }
        if (!owned) { rejectDirectReply(); return }
        try { device.write(event.bytes) }
        catch (_: IOException) { onFatal(); return }
        synchronized(lock) {
            if (direct?.generation == event.generation)
                directCounts = directCounts.copy(received = directCounts.received + 1)
        }
    }

    private fun rejectDirectReply() = synchronized(lock) {
        directCounts = directCounts.copy(rejectedReplies = directCounts.rejectedReplies + 1)
    }

    private fun incoming(event: Event.In) {
        val server = synchronized(lock) { active[event.id]?.server?.takeIf { it.generation == event.generation } } ?: return
        val datagram = event.datagram
        if (datagram.sourceIp != server.serverIp || datagram.sourcePort !in server.firstPort..server.lastPort) {
            update(event.id, event.generation) { it.copy(unknownEndpoint = it.unknownEndpoint + 1) }; return
        }
        if (datagram.bytes.isEmpty() || datagram.bytes.size > TunnelPacketLimits.MAX_INNER_PACKET) {
            update(event.id, event.generation) { it.copy(oversized = it.oversized + 1) }; return
        }
        val packet = ServerReplyPacket.parse(server.codec.decode(datagram.bytes, datagram.sourcePort))
        if (packet == null) { update(event.id, event.generation) { it.copy(malformed = it.malformed + 1) }; return }
        if (packet.protocol == 17 && packet.sourcePort == 53 &&
            FlowKey.from(packet).sourceIp == DNS_ADDRESS) {
            val answer = dnsRouting.answer(packet, event.id, event.generation)
            if (answer != null) {
                answer.packet?.let {
                    try { device.write(it) } catch (_: IOException) { onFatal(); return }
                    update(event.id, event.generation) { stat -> stat.copy(received = stat.received + 1,
                        lastReplyMillis = clock.elapsedMillis(), unansweredSinceMillis = 0) }
                }
                return
            }
        }
        val wireKey = FlowKey.from(packet).reverse()
        val key = synchronized(lock) { wireToOriginal[wireKey] } ?: wireKey
        val now = clock.elapsedMillis()
        val owned = synchronized(lock) {
            val pin = pins[key]
            pin != null && pin.id == event.id && pin.generation == event.generation &&
                now >= pin.seen && now - pin.seen < flowTtlMillis
        }
        if (!owned) { update(event.id, event.generation) { it.copy(unknownFlow = it.unknownFlow + 1) }; return }
        val maxMss = (TunnelPacketLimits.MAX_INNER_PACKET - packet.headerLength - packet.transportHeaderLength)
            .coerceAtMost(TunnelPacketLimits.TUNNEL_MAX_MSS)
        val clamped = if (maxMss > 0) packet.clampMss(maxMss) else null
        val payload = if (clamped != null && key != wireKey)
            PacketRewrite.address(Ipv4Packet.parse(clamped) ?: return, key.destinationIp, false) else clamped
        if (payload == null) { update(event.id, event.generation) { it.copy(malformed = it.malformed + 1) }; return }
        val stillOwned = synchronized(lock) {
            val pin = pins[key]
            if (active[event.id]?.server?.generation != event.generation || pin == null ||
                pin.id != event.id || pin.generation != event.generation ||
                now < pin.seen || now - pin.seen >= flowTtlMillis) false
            else { pin.seen = now; true }
        }
        if (!stillOwned) return
        if (packet.protocol == 6 && key.destinationPort == 53 && key.destinationIp == DNS_ADDRESS) {
            if (!dnsRouting.observeTcpChecked(packet, false, event.generation,
                primary = event.id).accepted) return
        }
        try { device.write(payload) }
        catch (_: IOException) { onFatal(); return }
        update(event.id, event.generation) { it.copy(received = it.received + 1, lastReplyMillis = now, unansweredSinceMillis = 0) }
    }

    private fun update(id: String, generation: Long, change: (TunnelStats) -> TunnelStats) {
        val next = synchronized(lock) {
            if (active[id]?.server?.generation != generation) return@synchronized null
            val updated = change(stats[id] ?: TunnelStats()).copy(queueDrops = queueDrops.get())
            stats[id] = updated
            updated
        } ?: return
        onStats(id, generation, next)
    }

    private fun prune(now: Long) {
        pins.entries.removeIf { now < it.value.seen || now - it.value.seen >= flowTtlMillis }
        wireToOriginal.entries.removeIf { it.value !in pins }
        unknown.entries.removeIf { now < it.value || now - it.value >= 5_000 }
        retiredAuxiliaryPorts.entries.removeIf { now >= it.value }
    }

    private fun retireAuxiliaryPort(port: Int) {
        retiredAuxiliaryPorts[port] = clock.elapsedMillis() + 30_000
        if (retiredAuxiliaryPorts.size > 128) retiredAuxiliaryPorts.remove(retiredAuxiliaryPorts.keys.first())
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        val (old, oldDirect) = synchronized(lock) {
            val servers = active.values.toList()
            val stack = direct
            active.clear(); direct = null; pins.clear(); wireToOriginal.clear(); unknown.clear()
            auxiliaryPorts.clear(); retiredAuxiliaryPorts.clear()
            dnsRouting?.clear()
            servers to stack
        }
        val errors = mutableListOf<Throwable>()
        old.forEach { runCatching { it.server.transport.close() }.onFailure(errors::add) }
        runCatching { oldDirect?.stack?.close() }.onFailure(errors::add)
        runCatching { device.close() }.onFailure(errors::add)
        worker?.interrupt()
        (old.map { it.reader } + listOfNotNull(tunReader, worker)).forEach {
            if (it !== Thread.currentThread()) runCatching { it.join(1_500) }.onFailure(errors::add)
        }
        queue.clear()
        if (errors.isNotEmpty()) throw IOException("Multi-server tunnel cleanup failed").also { failure ->
            errors.forEach(failure::addSuppressed)
        }
    }

    companion object { private const val DNS_ADDRESS = 0x01010101; private const val VPN_ADDRESS = 0x0afe5302 }
}
