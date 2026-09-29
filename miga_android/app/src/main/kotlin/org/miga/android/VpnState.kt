package org.miga.android

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.miga.core.TunnelStats
import org.miga.core.ConnectionState
import org.miga.core.DirectCounters
import org.miga.core.DnsCounters

enum class Phase { IDLE, STOPPED, PREPARING, STARTING, RUNNING, PARTIAL, NO_RESPONSE, REPLIED, NETWORK_LOST, WAITING, RETRYING, STOPPING, UNAVAILABLE, REVOKED }

data class ServerStatus(val state: ConnectionState, val stats: TunnelStats = TunnelStats(), val noResponse: Boolean = false)
data class VpnStatus(val phase: Phase, val message: String, val stats: TunnelStats = TunnelStats(),
                     val servers: Map<String, ServerStatus> = emptyMap(), val unknownOwnerDrops: Long = 0,
                     val directState: ConnectionState? = null, val direct: DirectCounters = DirectCounters(),
                     val dns: DnsCounters = DnsCounters())

object VpnState {
    private var offlineDrops = 0L
    private var observedReplies = 0L
    private val mutable = MutableStateFlow(VpnStatus(Phase.IDLE, "VPN is off"))
    val status = mutable.asStateFlow()
    fun begin() {
        offlineDrops = 0
        beginTransport()
        mutable.value = VpnStatus(Phase.STARTING, "Starting local tunnel")
    }
    fun beginTransport() {
        observedReplies = 0
        mutable.value = mutable.value.copy(stats = TunnelStats(queueDrops = offlineDrops))
    }
    fun addOfflineDrops(count: Long) {
        offlineDrops += count
        mutable.value = mutable.value.copy(stats = mutable.value.stats.copy(queueDrops = mutable.value.stats.queueDrops + count))
    }
    fun update(phase: Phase, message: String) {
        val current = mutable.value
        val stats = if (phase in setOf(Phase.WAITING, Phase.NETWORK_LOST, Phase.RETRYING, Phase.STARTING))
            current.stats.copy(lastReplyMillis = 0, unansweredSinceMillis = 0)
        else current.stats
        mutable.value = current.copy(phase = phase, message = message, stats = stats)
    }
    fun updateStats(stats: TunnelStats) {
        val current = mutable.value
        val merged = stats.copy(queueDrops = stats.queueDrops + offlineDrops)
        val newReply = stats.received > observedReplies
        observedReplies = maxOf(observedReplies, stats.received)
        mutable.value = if (newReply && current.phase in listOf(Phase.RUNNING, Phase.NO_RESPONSE))
            current.copy(phase = Phase.REPLIED, message = "Valid server reply received", stats = merged)
        else current.copy(stats = merged)
    }

    fun updateServerState(id: String, state: ConnectionState) {
        val current = mutable.value
        val previous = current.servers[id]
        mutable.value = current.copy(servers = current.servers + (id to ServerStatus(state,
            if (state == ConnectionState.RUNNING) previous?.stats ?: TunnelStats() else TunnelStats())))
    }

    fun updateServerStats(id: String, stats: TunnelStats) {
        val current = mutable.value
        val previous = current.servers[id] ?: return
        if (previous.state != ConnectionState.RUNNING) return
        val next = current.servers + (id to previous.copy(stats = stats,
            noResponse = previous.noResponse && stats.received <= previous.stats.received))
        val aggregate = next.values.fold(TunnelStats()) { total, server ->
            total.copy(sent = total.sent + server.stats.sent, received = total.received + server.stats.received,
                malformed = total.malformed + server.stats.malformed,
                fragments = total.fragments + server.stats.fragments,
                unknownEndpoint = total.unknownEndpoint + server.stats.unknownEndpoint,
                unknownFlow = total.unknownFlow + server.stats.unknownFlow,
                oversized = total.oversized + server.stats.oversized,
                queueDrops = total.queueDrops + server.stats.queueDrops)
        }
        mutable.value = current.copy(servers = next, stats = aggregate)
    }

    fun addUnknownOwnerDrops(count: Long) {
        mutable.value = mutable.value.copy(unknownOwnerDrops = count)
    }
    fun updateDirectState(state: ConnectionState?) {
        mutable.value = mutable.value.copy(directState = state)
    }
    fun updateDirectCounters(counters: DirectCounters) {
        mutable.value = mutable.value.copy(direct = counters)
    }
    fun updateDnsCounters(counters: DnsCounters) {
        mutable.value = mutable.value.copy(dns = counters)
    }

    fun checkNoResponse(now: Long) {
        val current = mutable.value
        mutable.value = current.copy(servers = current.servers.mapValues { (_, server) ->
            server.copy(noResponse = server.state == ConnectionState.RUNNING &&
                server.stats.unansweredSinceMillis > 0 && now - server.stats.unansweredSinceMillis > 15_000)
        })
    }
}
