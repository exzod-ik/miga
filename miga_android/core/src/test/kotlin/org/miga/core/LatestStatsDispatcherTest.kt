package org.miga.core

import org.junit.Assert.assertTrue
import org.junit.Test

class LatestStatsDispatcherTest {
    private class ManualScheduler : StatsTaskScheduler {
        private data class Entry(val task: Runnable, val due: Long)
        private val tasks = mutableListOf<Entry>()
        var now = 0L
            private set
        val pendingCount get() = tasks.size
        val pendingTasks get() = tasks.map { it.task }

        override fun post(task: Runnable, delayMillis: Long) { tasks.add(Entry(task, now + delayMillis)) }
        override fun remove(task: Runnable) { tasks.removeAll { it.task === task } }

        fun advanceBy(millis: Long) {
            now += millis
            while (true) {
                val next = tasks.withIndex().filter { it.value.due <= now }
                    .minByOrNull { it.value.due } ?: break
                tasks.removeAt(next.index)
                next.value.task.run()
            }
        }
    }

    @Test fun burstKeepsOneTaskAndPublishesOnlyLatestSnapshot() {
        val scheduler = ManualScheduler()
        val published = mutableListOf<Long>()
        val delivery = LatestStatsDispatcher(scheduler, { published.add(it.sent) }, { error("unexpected error") })
        repeat(10_000) { delivery.offer(TunnelStats(sent = it.toLong())) }
        assertEquals(1, scheduler.pendingCount)
        assertTrue(published.isEmpty())
        scheduler.advanceBy(249)
        assertTrue(published.isEmpty())
        scheduler.advanceBy(1)
        assertEquals(listOf(9_999L), published)
        assertEquals(0, scheduler.pendingCount)
        repeat(1_000) { delivery.offer(TunnelStats(sent = (10_000 + it).toLong())) }
        assertEquals(1, scheduler.pendingCount)
        scheduler.advanceBy(250)
        assertEquals(listOf(9_999L, 10_999L), published)
        assertEquals(0, scheduler.pendingCount)
    }

    @Test fun errorCancelsPeriodicTaskAndRunsImmediately() {
        val scheduler = ManualScheduler()
        val published = mutableListOf<Long>()
        val errors = mutableListOf<String?>()
        val delivery = LatestStatsDispatcher(scheduler, { published.add(it.sent) }, { errors.add(it.error) })
        delivery.offer(TunnelStats(sent = 1))
        delivery.offer(TunnelStats(error = "first"))
        delivery.offer(TunnelStats(error = "latest"))
        assertEquals(1, scheduler.pendingCount)
        scheduler.advanceBy(0)
        assertEquals(listOf("latest"), errors)
        assertTrue(published.isEmpty())
        scheduler.advanceBy(250)
        assertTrue(published.isEmpty())
        assertEquals(0, scheduler.pendingCount)
    }

    @Test fun stopAndNewSessionCannotPublishOldSnapshot() {
        val scheduler = ManualScheduler()
        val oldPublished = mutableListOf<Long>()
        val newPublished = mutableListOf<Long>()
        val old = LatestStatsDispatcher(scheduler, { oldPublished.add(it.sent) }, { error("unexpected error") })
        old.offer(TunnelStats(sent = 10))
        val staleRunnable = scheduler.pendingTasks.single()
        old.close()
        old.offer(TunnelStats(sent = 11))
        assertEquals(0, scheduler.pendingCount)
        staleRunnable.run() // Simulates a task already removed from the scheduler queue.
        val replacement = LatestStatsDispatcher(scheduler, { newPublished.add(it.sent) }, { error("unexpected error") })
        replacement.offer(TunnelStats(sent = 20))
        scheduler.advanceBy(250)
        assertTrue(oldPublished.isEmpty())
        assertEquals(listOf(20L), newPublished)
        assertEquals(0, scheduler.pendingCount)
    }
}
