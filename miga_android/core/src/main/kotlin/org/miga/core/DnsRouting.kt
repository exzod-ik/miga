package org.miga.core

data class DnsCounters(val pending: Int = 0, val completed: Long = 0, val auxiliary: Long = 0,
                       val timeouts: Long = 0, val malformed: Long = 0, val stale: Long = 0,
                       val active: Int = 0, val expired: Long = 0, val ambiguous: Long = 0,
                       val limits: Long = 0)

/** Accessed only by the packet worker; registrations precede transport sends. */
class DnsRouting(private val clock: Clock, private val rules: DomainRuleSet,
                 private val primaryProfile: String, private val maxPending: Int = 256,
                 private val maxRecords: Int = 2048) {
    init { require(maxPending > 0 && maxRecords > 0) }
    data class Send(val profileId: String, val generation: Long, val packet: ByteArray)
    data class Answer(val packet: ByteArray?, val accepted: Boolean)
    sealed interface Lookup {
        data class Match(val profileId: String, val actualIp: Int) : Lookup
        data object None : Lookup
        data object Ambiguous : Lookup
    }
    private data class Leg(val id: String, val generation: Long, val wireId: Int)
    private data class TimedAddresses(val addresses: List<DnsAddress>, val received: Long)
    private data class Pending(val key: FlowKey, val question: DnsQuestion, val originalId: Int,
                               val primaryProfile: String,
                               val created: Long, val order: Long, val legs: MutableList<Leg>,
                               var primary: TimedAddresses? = null, var delivered: Boolean = false,
                               val auxiliary: MutableMap<String, TimedAddresses> = mutableMapOf())
    private data class Record(val domain: String, val profile: String, val generation: Long,
                              val exposedIp: Int, val actualIp: Int?, val deadline: Long,
                              val waiting: Boolean = false, val conflict: Boolean = false,
                              val sourceTime: Long = 0)
    private data class RecordKey(val domain: String, val profile: String, val exposedIp: Int)
    data class TcpQuery(val token: Long, val profileId: String, val generation: Long,
                        val message: ByteArray)
    data class TcpObservation(val queries: List<TcpQuery>, val accepted: Boolean)
    private data class TcpPending(val token: Long, val flow: FlowKey, val id: Int,
                                  val question: DnsQuestion, val primaryProfile: String,
                                  val legs: Map<String, Long>, val created: Long,
                                  var primary: TimedAddresses? = null,
                                  val auxiliary: MutableMap<String, TimedAddresses> = mutableMapOf())
    private data class TcpState(val generation: Long, val primaryProfile: String,
                                val applicationRule: Boolean, var seen: Long,
                                val outgoing: DnsTcpFramer = DnsTcpFramer(),
                                val incoming: DnsTcpFramer = DnsTcpFramer(),
                                var outgoingFinished: Boolean = false,
                                var incomingFinished: Boolean = false,
                                val questions: MutableMap<Pair<Int, DnsQuestion>, ArrayDeque<Long>> = LinkedHashMap())
    private data class RejectedTcp(val until: Long, val incoming: DnsTcpFramer)
    private fun unresolved(state: TcpState) = state.questions.isNotEmpty() ||
        state.outgoing.incomplete || state.incoming.incomplete
    private val pending = ArrayList<Pending>()
    private val records = LinkedHashMap<RecordKey, Record>()
    // An overflowed ruled address must remain denied even when its full mapping cannot fit.
    private val overflow = LinkedHashMap<RecordKey, Long>()
    private val maxOverflow = maxOf(32, maxRecords)
    private val tcp = LinkedHashMap<FlowKey, TcpState>()
    private val rejectedTcp = LinkedHashMap<FlowKey, RejectedTcp>()
    private val tcpPending = LinkedHashMap<Long, TcpPending>()
    private var nextOrder = 0L
    private var nextId = 0
    private var saturatedUntil = 0L
    private var tcpDropUntil = 0L
    private var totals = DnsCounters()
    val counters: DnsCounters get() = synchronized(this) {
        prune(); totals.copy(pending = pending.size, active = records.size)
    }

    @Synchronized
    fun query(packet: Ipv4Packet, servers: Map<String, Long>, selectedProfile: String? = primaryProfile): List<Send>? {
        if (packet.protocol != 17 || packet.destinationPort != 53) return null
        val offset = packet.headerLength + 8
        val dns = DnsParser.parse(packet.bytes.copyOfRange(offset, packet.bytes.size))
        if (dns == null || dns.response || dns.truncated) { totals = totals.copy(malformed = totals.malformed + 1); return emptyList() }
        prune()
        if (selectedProfile == null) return null
        if (pending.size >= maxPending || selectedProfile !in servers) {
            totals = totals.copy(limits = totals.limits + 1); return emptyList()
        }
        val ordered = listOf(selectedProfile) + (servers.keys - selectedProfile).sorted()
        val legs = ArrayList<Leg>()
        for (id in ordered) {
            val used = pending.flatMap { it.legs }.filter { it.id == id }.map { it.wireId }.toSet() +
                legs.filter { it.id == id }.map { it.wireId }
            var candidate: Int? = null
            for (attempt in 0 until 65536) {
                nextId = (nextId + 1) and 65535
                if (nextId !in used) { candidate = nextId; break }
            }
            if (candidate == null) { totals = totals.copy(limits = totals.limits + 1); return emptyList() }
            legs.add(Leg(id, servers.getValue(id), candidate!!))
        }
        pending.add(Pending(FlowKey.from(packet), dns.question, dns.id, selectedProfile,
            clock.elapsedMillis(), ++nextOrder, legs))
        totals = totals.copy(auxiliary = totals.auxiliary + legs.size - 1)
        return legs.map { leg -> Send(leg.id, leg.generation, PacketRewrite.dnsId(packet, leg.wireId)) }
    }

    @Synchronized
    fun answer(packet: Ipv4Packet, profile: String, generation: Long): Answer? {
        if (packet.protocol != 17 || packet.sourcePort != 53) return null
        val dns = DnsParser.parse(packet.bytes.copyOfRange(packet.headerLength + 8, packet.bytes.size))
        if (dns == null || !dns.response) { totals = totals.copy(malformed = totals.malformed + 1); return Answer(null, false) }
        prune()
        val reverse = FlowKey.from(packet).reverse()
        val request = pending.firstOrNull { row -> row.key == reverse && row.question == dns.question &&
            row.legs.any { it.id == profile && it.generation == generation && it.wireId == dns.id } }
        if (request == null) { totals = totals.copy(stale = totals.stale + 1); return Answer(null, false) }
        if (dns.truncated || dns.rcode != 0) {
            if (profile == request.primaryProfile && !request.delivered) {
                request.delivered = true; totals = totals.copy(completed = totals.completed + 1)
                return Answer(PacketRewrite.dnsId(packet, request.originalId), true)
            }
            return Answer(null, false)
        }
        if (profile == request.primaryProfile) {
            if (request.delivered) { totals = totals.copy(stale = totals.stale + 1); return Answer(null, false) }
            request.primary = TimedAddresses(dns.addresses, clock.elapsedMillis()); request.delivered = true
            totals = totals.copy(completed = totals.completed + 1)
            val selected = rules.profileFor(request.question.name)
            if (selected != null && selected != request.primaryProfile) {
                val selectedGeneration = request.legs.firstOrNull { it.id == selected }?.generation
                    ?: generation
                reserve(request.question.name, selected, selectedGeneration, request.primary!!,
                    request.order)
            }
            save(request, request.primaryProfile, generation, request.primary!!)
            request.auxiliary.forEach { (id, addresses) ->
                val leg = request.legs.first { it.id == id }; save(request, id, leg.generation, addresses)
            }
            return Answer(PacketRewrite.dnsId(packet, request.originalId), true)
        }
        if (profile in request.auxiliary) { totals = totals.copy(stale = totals.stale + 1); return Answer(null, false) }
        request.auxiliary[profile] = TimedAddresses(dns.addresses, clock.elapsedMillis())
        if (request.primary != null) save(request, profile, generation, request.auxiliary.getValue(profile))
        return Answer(null, true)
    }

    private fun save(request: Pending, profile: String, generation: Long, addresses: TimedAddresses) {
        val primary = request.primary ?: return
        val primaryByIp = primary.addresses.associateBy { it.address }
        val actualByIp = addresses.addresses.associateBy { it.address }
        val common = primaryByIp.keys intersect actualByIp.keys
        val remainingPrimary = primaryByIp.keys - common
        val remainingActual = actualByIp.keys - common
        val uniqueReplacement = remainingPrimary.size == 1 && remainingActual.size == 1
        for (answer in primary.addresses) {
            if (!PublicRoutes.isPublic(answer.address)) continue
            val matched = actualByIp[answer.address]
            val replacement = if (matched == null && uniqueReplacement && answer.address in remainingPrimary)
                actualByIp[remainingActual.first()] else null
            val actual = matched ?: replacement
            val ttl = minOf(answer.ttl, actual?.ttl ?: answer.ttl)
            val target = actual?.address?.takeIf(PublicRoutes::isPublic)
            val deadline = minOf(primary.received + minOf(answer.ttl, 3600L) * 1000,
                addresses.received + minOf(actual?.ttl ?: answer.ttl, 3600L) * 1000)
            putRecord(request.question.name, profile, generation, answer.address, target, ttl,
                positiveDeadline = deadline, sourceTime = request.order)
        }
    }

    private fun reserve(domain: String, profile: String, generation: Long, primary: TimedAddresses,
                        sourceTime: Long = clock.elapsedMillis()) {
        for (address in primary.addresses) if (PublicRoutes.isPublic(address.address))
            putRecord(domain, profile, generation, address.address, null, address.ttl, waiting = true,
                positiveDeadline = primary.received + minOf(address.ttl, 3600L) * 1000,
                sourceTime = sourceTime)
    }

    private fun putRecord(domain: String, profile: String, generation: Long, exposedIp: Int,
                          actualIp: Int?, ttl: Long, waiting: Boolean = false,
                          positiveDeadline: Long = clock.elapsedMillis() + minOf(ttl, 3600L) * 1000,
                          sourceTime: Long = ++nextOrder) {
        val now = clock.elapsedMillis()
        val usableActual = actualIp?.takeIf { ttl > 0 && now < positiveDeadline }
        val deadline = if (usableActual == null) maxOf(now + 10_000L, positiveDeadline)
            else positiveDeadline
        val key = RecordKey(domain, profile, exposedIp)
        val previous = records[key]
        if (previous != null && previous.sourceTime > sourceTime) return
        if (previous == null) {
            if (records.size >= maxRecords) {
                if (rules.profileFor(domain) == profile) {
                    val lowerPriority = records.entries.firstOrNull {
                        rules.profileFor(it.key.domain) != it.key.profile
                    }?.key
                    if (lowerPriority != null) records.remove(lowerPriority)
                } else {
                    // App assignments already select their server; an optional mapping must not
                    // consume the denial reserve for observed domain rules.
                    totals = totals.copy(limits = totals.limits + 1)
                    return
                }
            }
            if (records.size >= maxRecords) {
                val priorOverflow = overflow[key]
                if (priorOverflow != null) overflow[key] = maxOf(priorOverflow, deadline)
                else if (overflow.size < maxOverflow) overflow[key] = deadline
                else limit(Long.MAX_VALUE)
                return
            }
            overflow.remove(key)
            records[key] = Record(domain, profile, generation, exposedIp, usableActual, deadline,
                waiting = waiting || usableActual == null, sourceTime = sourceTime)
            return
        }
        val sameGeneration = previous.generation == generation
        val conflict = sameGeneration && (previous.conflict ||
            !waiting && previous.actualIp != null && usableActual != null && previous.actualIp != usableActual)
        val target = when {
            conflict -> null
            waiting && sameGeneration && previous.actualIp != null -> previous.actualIp
            else -> usableActual
        }
        records[key] = Record(domain, profile, generation, exposedIp, target,
            if (conflict) maxOf(previous.deadline, deadline) else deadline,
            waiting = waiting || usableActual == null || conflict, conflict = conflict,
            sourceTime = sourceTime)
    }

    @Synchronized
    fun lookup(ip: Int, preferredProfile: String?, generations: Map<String, Long>): Lookup {
        prune()
        if (clock.elapsedMillis() < saturatedUntil) {
            totals = totals.copy(ambiguous = totals.ambiguous + 1); return Lookup.Ambiguous
        }
        val blocked = overflow.keys.any { it.exposedIp == ip &&
            (preferredProfile == null && rules.profileFor(it.domain) == it.profile ||
                preferredProfile != null && it.profile == preferredProfile) }
        if (blocked) { totals = totals.copy(ambiguous = totals.ambiguous + 1); return Lookup.Ambiguous }
        val candidates = records.values.filter { it.exposedIp == ip &&
            (it.waiting || it.conflict || generations[it.profile] == it.generation) &&
            (preferredProfile == null && rules.profileFor(it.domain) == it.profile ||
                preferredProfile != null && it.profile == preferredProfile) }
        if (candidates.isEmpty()) return Lookup.None
        if (candidates.any { it.waiting || it.conflict || it.actualIp == null }) {
            totals = totals.copy(ambiguous = totals.ambiguous + 1); return Lookup.Ambiguous
        }
        val targets = candidates.map { it.profile to it.actualIp!! }.toSet()
        return if (targets.size == 1) targets.first().let { Lookup.Match(it.first, it.second) }
            else { totals = totals.copy(ambiguous = totals.ambiguous + 1); Lookup.Ambiguous }
    }

    private fun rejectTcp(flow: FlowKey, state: TcpState? = tcp.remove(flow)) {
        tcp.remove(flow)
        // A completed primary answer can still be paired with its auxiliary reply after TCP closes.
        tcpPending.entries.removeIf { it.value.flow == flow && it.value.primary == null }
        val until = clock.elapsedMillis() + 120_000L
        if (flow in rejectedTcp || rejectedTcp.size < 256)
            rejectedTcp[flow] = RejectedTcp(until, state?.incoming ?: rejectedTcp[flow]?.incoming ?: DnsTcpFramer())
        else {
            // A full tombstone table cannot safely forget a flow that may still reply.
            tcpDropUntil = maxOf(tcpDropUntil, until)
            saturatedUntil = maxOf(saturatedUntil, until)
            totals = totals.copy(limits = totals.limits + 1)
        }
    }

    private fun denyRejectedAnswer(dns: DnsMessage) {
        if (!dns.response || dns.truncated || dns.rcode != 0) return
        val selected = rules.profileFor(dns.question.name) ?: return
        val now = clock.elapsedMillis()
        for (address in dns.addresses) {
            if (!PublicRoutes.isPublic(address.address)) continue
            val key = RecordKey(dns.question.name, selected, address.address)
            val current = records[key]
            // A stale rejected flow must not replace a newer successful resolution.
            if (current != null && current.actualIp != null && !current.waiting &&
                !current.conflict && now < current.deadline) continue
            putRecord(dns.question.name, selected, 0, address.address, null,
                address.ttl, waiting = true)
        }
    }

    private fun observeRejected(flow: FlowKey, packet: Ipv4Packet, outgoing: Boolean, sequence: Long) {
        if (outgoing) return
        val rejected = rejectedTcp[flow] ?: return
        val payload = packet.bytes.copyOfRange(packet.headerLength + packet.transportHeaderLength, packet.bytes.size)
        for (frame in rejected.incoming.offer(sequence, payload)) {
            totals = totals.copy(stale = totals.stale + 1)
            val dns = DnsParser.parse(frame) ?: continue
            denyRejectedAnswer(dns)
        }
    }

    /** TCP payload is observed only; the packet and its sequence numbers are never changed. */
    @Synchronized
    fun observeTcp(packet: Ipv4Packet, outgoing: Boolean, generation: Long,
                   servers: Map<String, Long> = emptyMap(), primary: String = primaryProfile,
                   applicationRule: Boolean = false): List<TcpQuery> =
        observeTcpChecked(packet, outgoing, generation, servers, primary, applicationRule).queries

    @Synchronized
    fun observeTcpChecked(packet: Ipv4Packet, outgoing: Boolean, generation: Long,
                          servers: Map<String, Long> = emptyMap(), primary: String = primaryProfile,
                          applicationRule: Boolean = false): TcpObservation {
        if (packet.protocol != 6 || (if (outgoing) packet.destinationPort else packet.sourcePort) != 53)
            return TcpObservation(emptyList(), true)
        prune()
        val flow = if (outgoing) FlowKey.from(packet) else FlowKey.from(packet).reverse()
        val bytes = packet.bytes
        val seqOffset = packet.headerLength + 4
        val sequence = ((Ipv4Packet.u16(bytes, seqOffset).toLong() shl 16) or
            Ipv4Packet.u16(bytes, seqOffset + 2).toLong())
        val flags = bytes[packet.headerLength + 13].toInt() and 255
        val syn = flags and 2 != 0
        val rst = flags and 4 != 0
        val fin = flags and 1 != 0
        if (rst) { rejectTcp(flow); return TcpObservation(emptyList(), true) }
        if (syn && outgoing) rejectedTcp.remove(flow)
        if (clock.elapsedMillis() < tcpDropUntil) return TcpObservation(emptyList(), false)
        if (flow in rejectedTcp) {
            observeRejected(flow, packet, outgoing, sequence)
            return TcpObservation(emptyList(), false)
        }
        if (!outgoing && flow !in tcp) {
            rejectTcp(flow)
            observeRejected(flow, packet, false, sequence)
            return TcpObservation(emptyList(), false)
        }
        val state = tcp[flow]?.takeIf { it.generation == generation && it.primaryProfile == primary } ?: run {
            if (flow in tcp) {
                rejectTcp(flow)
                return TcpObservation(emptyList(), false)
            }
            if (tcp.size >= 128) {
                val displaced = tcp.entries.firstOrNull { !unresolved(it.value) } ?: tcp.entries.first()
                if (unresolved(displaced.value)) rejectTcp(displaced.key, displaced.value)
                else tcp.remove(displaced.key)
                totals = totals.copy(limits = totals.limits + 1)
                if (clock.elapsedMillis() < tcpDropUntil) return TcpObservation(emptyList(), false)
            }
            TcpState(generation, primary, applicationRule, clock.elapsedMillis()).also { tcp[flow] = it }
        }
        state.seen = clock.elapsedMillis()
        val stream = if (outgoing) state.outgoing else state.incoming
        if (syn) {
            if (outgoing) {
                tcpPending.entries.removeIf { it.value.flow == flow }
                state.questions.clear()
            }
            stream.begin((sequence + 1) and 0xffff_ffffL)
        }
        val payload = bytes.copyOfRange(packet.headerLength + packet.transportHeaderLength, bytes.size)
        val frames = stream.offer((sequence + if (syn) 1 else 0) and 0xffff_ffffL, payload)
        if (stream.failed) {
            rejectTcp(flow, state); totals = totals.copy(limits = totals.limits + 1)
            return TcpObservation(emptyList(), false)
        }
        val queries = ArrayList<TcpQuery>()
        for (frame in frames) {
            val dns = DnsParser.parse(frame)
            if (dns == null) {
                rejectTcp(flow, state); totals = totals.copy(malformed = totals.malformed + 1)
                return TcpObservation(emptyList(), false)
            }
            val identity = dns.id to dns.question
            if (outgoing && !dns.response) {
                val secondary = servers.filterKeys { it != state.primaryProfile }
                val token = ++nextOrder
                if (state.questions.values.sumOf { it.size } >= 32) {
                    rejectTcp(flow, state)
                    totals = totals.copy(limits = totals.limits + 1)
                    return TcpObservation(emptyList(), false)
                }
                state.questions.getOrPut(identity) { ArrayDeque() }.addLast(token)
                if (dns.question.type == 1 && dns.question.klass == 1 && secondary.isNotEmpty()) {
                    if (tcpPending.size >= maxPending) {
                        totals = totals.copy(limits = totals.limits + 1)
                    } else {
                        tcpPending[token] = TcpPending(token, flow, dns.id, dns.question,
                            state.primaryProfile, secondary, clock.elapsedMillis())
                        secondary.forEach { (id, legGeneration) ->
                            queries.add(TcpQuery(token, id, legGeneration, frame.copyOf()))
                        }
                    }
                }
            } else if (!outgoing && dns.response && state.questions[identity]?.isNotEmpty() == true) {
                val tokens = state.questions.getValue(identity)
                val token = tokens.removeFirst()
                if (tokens.isEmpty()) state.questions.remove(identity)
                totals = totals.copy(completed = totals.completed + 1)
                if (!dns.truncated && dns.rcode == 0) {
                    val selected = rules.profileFor(dns.question.name)
                    if (selected == state.primaryProfile || state.applicationRule) for (address in dns.addresses) {
                        if (!PublicRoutes.isPublic(address.address)) continue
                        putRecord(dns.question.name, state.primaryProfile, generation, address.address,
                            address.address, address.ttl,
                            sourceTime = token)
                    }
                    if (selected != null && selected != state.primaryProfile) {
                        val selectedGeneration = tcpPending[token]?.legs?.get(selected) ?: servers[selected] ?: 0L
                        reserve(dns.question.name, selected, selectedGeneration,
                            TimedAddresses(dns.addresses, clock.elapsedMillis()),
                            token)
                    }
                    tcpPending[token]?.let { pending ->
                        pending.primary = TimedAddresses(dns.addresses, clock.elapsedMillis())
                        pending.auxiliary.toMap().forEach { (id, addresses) -> saveTcp(pending, id, addresses) }
                    }
                }
                if (dns.truncated || dns.rcode != 0) tcpPending.remove(token)
            } else if (!outgoing && dns.response) {
                rejectTcp(flow, state); totals = totals.copy(stale = totals.stale + 1)
                denyRejectedAnswer(dns)
                return TcpObservation(emptyList(), false)
            }
        }
        if (fin) {
            if (outgoing) state.outgoingFinished = true else state.incomingFinished = true
            if (state.outgoingFinished && state.incomingFinished) rejectTcp(flow, state)
        }
        return TcpObservation(queries, true)
    }

    @Synchronized
    fun auxiliaryTcpAnswer(token: Long, profile: String, generation: Long, message: ByteArray): Boolean {
        prune()
        val pending = tcpPending[token] ?: return false
        if (pending.legs[profile] != generation || profile in pending.auxiliary) return false
        val dns = DnsParser.parse(message) ?: return false
        if (!dns.response || dns.truncated || dns.rcode != 0 || dns.id != pending.id ||
            dns.question != pending.question) return false
        val addresses = TimedAddresses(dns.addresses, clock.elapsedMillis())
        pending.auxiliary[profile] = addresses
        pending.primary?.let { saveTcp(pending, profile, addresses) }
        return true
    }

    private fun saveTcp(pending: TcpPending, profile: String, auxiliary: TimedAddresses) {
        val primary = pending.primary ?: return
        val request = Pending(pending.flow, pending.question, pending.id, pending.primaryProfile,
            pending.created, pending.token,
            mutableListOf(Leg(pending.primaryProfile, 0, pending.id),
                Leg(profile, pending.legs.getValue(profile), pending.id)), primary = primary)
        save(request, profile, pending.legs.getValue(profile), auxiliary)
        if (pending.auxiliary.keys.containsAll(pending.legs.keys)) tcpPending.remove(pending.token)
    }

    @Synchronized
    fun detach(id: String, generation: Long) {
        pending.removeIf { request -> request.primaryProfile == id &&
            request.legs.any { it.id == id && it.generation == generation } }
        pending.forEach { request ->
            if (request.legs.removeIf { it.id == id && it.generation == generation })
                request.auxiliary.remove(id)
        }
        for ((key, record) in records) {
            if (record.profile == id && record.generation == generation)
                records[key] = record.copy(waiting = true)
        }
        tcp.entries.filter { it.value.primaryProfile == id && it.value.generation == generation }
            .forEach { rejectTcp(it.key, it.value) }
        tcpPending.entries.removeIf { it.value.primaryProfile == id ||
            it.value.legs[id] == generation }
    }

    @Synchronized
    fun clear() { pending.clear(); records.clear(); overflow.clear(); tcp.clear(); tcpPending.clear()
        rejectedTcp.clear(); saturatedUntil = 0; tcpDropUntil = 0 }

    private fun limit(deadline: Long) {
        totals = totals.copy(limits = totals.limits + 1)
        saturatedUntil = maxOf(saturatedUntil, deadline)
    }

    private fun prune() {
        val now = clock.elapsedMillis()
        val before = pending.size; pending.removeIf { now < it.created || now - it.created >= 10_000 }
        var expired = 0
        val iterator = records.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now < entry.value.deadline) continue
            expired++
            if (rules.profileFor(entry.value.domain) == entry.value.profile) {
                // Keep a bounded denial for an observed ruled IP after its positive TTL ends.
                entry.setValue(entry.value.copy(actualIp = null, deadline = Long.MAX_VALUE,
                    waiting = true, conflict = false))
            } else iterator.remove()
        }
        var denied = 0
        val overflowIterator = overflow.entries.iterator()
        while (overflowIterator.hasNext()) {
            val entry = overflowIterator.next()
            if (now < entry.value) continue
            denied++
            if (rules.profileFor(entry.key.domain) == entry.key.profile)
                entry.setValue(Long.MAX_VALUE)
            else overflowIterator.remove()
        }
        tcp.entries.filter { now < it.value.seen || now - it.value.seen >= 30_000 }
            .forEach { if (unresolved(it.value)) rejectTcp(it.key, it.value) else tcp.remove(it.key) }
        rejectedTcp.entries.removeIf { now >= it.value.until }
        tcpPending.entries.removeIf { now < it.value.created || now - it.value.created >= 10_000 }
        totals = totals.copy(timeouts = totals.timeouts + before - pending.size,
            expired = totals.expired + expired + denied)
    }
}

object PacketRewrite {
    fun dnsId(packet: Ipv4Packet, id: Int): ByteArray {
        val copy = packet.bytes.copyOf(); Ipv4Packet.put16(copy, packet.headerLength + 8, id)
        Checksum.writeTransport(copy, packet.headerLength, packet.protocol)
        return copy
    }

    fun address(packet: Ipv4Packet, ip: Int, destination: Boolean): ByteArray {
        val copy = packet.bytes.copyOf(); val offset = if (destination) 16 else 12
        Ipv4Packet.put16(copy, offset, ip ushr 16); Ipv4Packet.put16(copy, offset + 2, ip)
        Checksum.writeIpv4(copy, packet.headerLength)
        Checksum.writeTransport(copy, packet.headerLength, packet.protocol)
        return copy
    }
}
