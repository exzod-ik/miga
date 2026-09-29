package org.miga.core

import java.io.Closeable

/** Posts tasks asynchronously on the UI thread; remove cancels a task that has not started. */
interface StatsTaskScheduler {
    fun post(task: Runnable, delayMillis: Long)
    fun remove(task: Runnable)
}

/** Keeps one latest snapshot and one delayed UI task; errors use a separate immediate task. */
class LatestStatsDispatcher(
    private val scheduler: StatsTaskScheduler,
    private val publish: (TunnelStats) -> Unit,
    private val urgentError: (TunnelStats) -> Unit,
    private val intervalMillis: Long = 250,
) : Closeable {
    init { require(intervalMillis > 0) }

    private val lock = Any()
    private var active = true
    private var failed = false
    private var latest: TunnelStats? = null
    private var latestError: TunnelStats? = null
    private var statsQueued = false
    private var errorQueued = false

    private val statsTask = Runnable {
        val snapshot = synchronized(lock) {
            statsQueued = false
            if (active && !failed) latest.also { latest = null } else null
        }
        if (snapshot != null) publish(snapshot)
    }

    private val errorTask = Runnable {
        val error = synchronized(lock) {
            errorQueued = false
            if (active) latestError.also { latestError = null } else null
        }
        if (error != null) urgentError(error)
    }

    fun offer(snapshot: TunnelStats) = synchronized(lock) {
        if (!active) return@synchronized
        if (snapshot.error != null) {
            failed = true
            latest = null
            if (statsQueued) { scheduler.remove(statsTask); statsQueued = false }
            latestError = snapshot
            if (!errorQueued) { errorQueued = true; scheduler.post(errorTask, 0) }
        } else if (!failed) {
            latest = snapshot
            if (!statsQueued) { statsQueued = true; scheduler.post(statsTask, intervalMillis) }
        }
    }

    override fun close() = synchronized(lock) {
        active = false
        latest = null
        latestError = null
        if (statsQueued) scheduler.remove(statsTask)
        if (errorQueued) scheduler.remove(errorTask)
        statsQueued = false
        errorQueued = false
    }
}
