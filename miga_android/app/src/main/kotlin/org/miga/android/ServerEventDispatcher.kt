package org.miga.android

import java.io.Closeable
import org.miga.core.StatsTaskScheduler
import org.miga.core.TunnelStats

/** Coalesces all profiles into one delayed statistics task and one urgent failure task. */
class ServerEventDispatcher(
    private val profileIds: Set<String>,
    private val scheduler: StatsTaskScheduler,
    private val publish: (String, Long, TunnelStats) -> Unit,
    private val fail: (String, Long) -> Unit,
    private val intervalMillis: Long = 250,
) : Closeable {
    init { require(profileIds.isNotEmpty() && intervalMillis > 0) }

    private data class Snapshot(val generation: Long, val stats: TunnelStats)
    private val lock = Any()
    private val generations = mutableMapOf<String, Long>()
    private val latest = mutableMapOf<String, Snapshot>()
    private val failures = mutableMapOf<String, Long>()
    private val failedGenerations = mutableMapOf<String, Long>()
    private var active = true
    private var statsQueued = false
    private var failureQueued = false

    private val statsTask = Runnable {
        val batch = synchronized(lock) {
            statsQueued = false
            if (!active) emptyMap() else latest.toMap().also { latest.clear() }
        }
        batch.forEach { (id, snapshot) ->
            if (synchronized(lock) { active && generations[id] == snapshot.generation })
                publish(id, snapshot.generation, snapshot.stats)
        }
    }

    private val failureTask = Runnable {
        val batch = synchronized(lock) {
            failureQueued = false
            if (!active) emptyMap() else failures.toMap().also { failures.clear() }
        }
        batch.forEach { (id, generation) ->
            if (synchronized(lock) { active && generations[id] == generation }) fail(id, generation)
        }
    }

    fun advance(id: String, generation: Long) = synchronized(lock) {
        if (!active || id !in profileIds || generation <= (generations[id] ?: Long.MIN_VALUE)) return@synchronized
        generations[id] = generation
        latest.remove(id)
        failures.remove(id)
        failedGenerations.remove(id)
    }

    fun offerStats(id: String, generation: Long, stats: TunnelStats) = synchronized(lock) {
        if (!accept(id, generation)) return@synchronized
        latest[id] = Snapshot(generation, stats)
        if (!statsQueued) { statsQueued = true; scheduler.post(statsTask, intervalMillis) }
    }

    fun offerFailure(id: String, generation: Long) = synchronized(lock) {
        if (!accept(id, generation)) return@synchronized
        if (failedGenerations[id] == generation) return@synchronized
        failedGenerations[id] = generation
        failures[id] = generation
        if (!failureQueued) { failureQueued = true; scheduler.post(failureTask, 0) }
    }

    private fun accept(id: String, generation: Long): Boolean {
        if (!active || id !in profileIds) return false
        val current = generations[id]
        if (current != null && generation < current) return false
        if (current == null || generation > current) {
            generations[id] = generation
            latest.remove(id)
            failures.remove(id)
            failedGenerations.remove(id)
        }
        return true
    }

    override fun close() = synchronized(lock) {
        if (!active) return@synchronized
        active = false
        latest.clear()
        failures.clear()
        failedGenerations.clear()
        generations.clear()
        if (statsQueued) scheduler.remove(statsTask)
        if (failureQueued) scheduler.remove(failureTask)
        statsQueued = false
        failureQueued = false
    }
}
