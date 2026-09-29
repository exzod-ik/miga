package org.miga.core

import java.io.Closeable

/** Serialized by its caller. A rank is an explicit preference, not callback arrival order. */
class ConnectionController<N : Any>(
    private val scheduler: RetryScheduler,
    private val jitter: (Long) -> Long,
    private val order: (N) -> Long,
    private val open: (N, Long) -> Closeable,
    private val onState: (ConnectionState, N?) -> Unit,
) : Closeable {
    private val candidates = linkedMapOf<N, Int>()
    private var selected: N? = null
    private var connection: Closeable? = null
    private var pending: Closeable? = null
    private var retrySerial = 0L
    private var attempt = 0
    private var generation = 0L
    private var stopped = false
    private var opening = false

    val token: Long get() = generation
    val activeNetwork: N? get() = if (connection != null) selected else null

    fun available(network: N, rank: Int?) {
        if (stopped) return
        if (rank == null) candidates.remove(network) else candidates[network] = rank
        reconcile()
    }

    fun lost(network: N) { available(network, null) }

    fun failed(token: Long) {
        if (stopped || token != generation || connection == null) return
        closeConnection()
        retry()
    }

    private fun preferred(): N? {
        val current = selected
        val bestRank = candidates.values.minOrNull() ?: return null
        if (current != null && candidates[current] == bestRank) return current
        // Caller supplies a stable network handle. A tie never depends on callback order.
        return candidates.filterValues { it == bestRank }.keys.minBy { order(it) }
    }

    private fun reconcile() {
        val best = preferred()
        if (best == null) {
            cancelPending()
            closeConnection()
            selected = null
            attempt = 0
            onState(ConnectionState.WAITING_NETWORK, null)
            return
        }
        if (best != selected) {
            cancelPending()
            closeConnection()
            selected = best
            attempt = 0
        }
        if (connection != null || pending != null || opening) return
        connect()
    }

    private fun connect() {
        val network = selected ?: return
        if (stopped || opening || connection != null) return
        opening = true
        val next = ++generation
        try {
            onState(ConnectionState.CONNECTING, network)
            if (stopped || selected != network || generation != next) return
            val opened = open(network, next)
            if (stopped || selected != network || generation != next) opened.close()
            else {
                connection = opened
                attempt = 0
                onState(ConnectionState.RUNNING, network)
            }
        } catch (_: Exception) {
            if (connection != null) closeConnection()
            if (!stopped) retry()
        } finally {
            opening = false
            if (!stopped && connection == null && pending == null && selected != null) connect()
        }
    }

    private fun retry() {
        if (selected == null) { onState(ConnectionState.WAITING_NETWORK, null); return }
        cancelPending()
        val base = (1_000L shl attempt.coerceAtMost(5)).coerceAtMost(30_000L)
        attempt++
        val delay = (base + jitter(base)).coerceIn(500L, 45_000L)
        onState(ConnectionState.RETRYING, selected)
        val serial = retrySerial
        pending = scheduler.schedule(delay) {
            if (serial != retrySerial) return@schedule
            pending = null
            if (!stopped && connection == null) connect()
        }
    }

    private fun cancelPending() { retrySerial++; pending?.close(); pending = null }
    private fun closeConnection() {
        val old = connection
        connection = null
        generation++
        old?.close()
    }

    override fun close() {
        if (stopped) return
        stopped = true
        cancelPending()
        closeConnection()
        candidates.clear()
        selected = null
    }
}

enum class ConnectionState { WAITING_NETWORK, CONNECTING, RETRYING, RUNNING }

fun interface RetryScheduler { fun schedule(delayMillis: Long, task: () -> Unit): Closeable }
