package org.miga.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.miga.core.StatsTaskScheduler
import org.miga.core.TunnelStats

class ServerEventDispatcherTest {
    private class Scheduler : StatsTaskScheduler {
        private val pending = linkedMapOf<Runnable, Long>()
        var maximumPending = 0
            private set
        val pendingCount: Int get() = pending.size
        override fun post(task: Runnable, delayMillis: Long) {
            pending[task] = delayMillis
            maximumPending = maxOf(maximumPending, pending.size)
        }
        override fun remove(task: Runnable) { pending.remove(task) }
        fun runNext() {
            val task = pending.minByOrNull { it.value }?.key ?: error("No task pending")
            pending.remove(task)
            task.run()
        }
    }

    @Test fun largeTwoServerBurstKeepsOneStatsTaskAndPublishesLatest() {
        val scheduler = Scheduler()
        val published = mutableMapOf<String, TunnelStats>()
        val dispatcher = ServerEventDispatcher(setOf("one", "two"), scheduler,
            { id, _, stats -> published[id] = stats }, { _, _ -> })
        repeat(10_000) { index ->
            dispatcher.offerStats("one", 1, TunnelStats(sent = index.toLong()))
            dispatcher.offerStats("two", 1, TunnelStats(received = index.toLong()))
        }
        assertEquals(1, scheduler.pendingCount)
        assertEquals(1, scheduler.maximumPending)
        scheduler.runNext()
        assertEquals(9_999L, published.getValue("one").sent)
        assertEquals(9_999L, published.getValue("two").received)
        assertEquals(0, scheduler.pendingCount)
        dispatcher.close()
    }

    @Test fun newGenerationReplacesOldAndFailureBypassesStatsDelay() {
        val scheduler = Scheduler()
        val published = mutableListOf<Triple<String, Long, Long>>()
        val failures = mutableListOf<Pair<String, Long>>()
        val dispatcher = ServerEventDispatcher(setOf("one", "two"), scheduler,
            { id, generation, stats -> published.add(Triple(id, generation, stats.sent)) },
            { id, generation -> failures.add(id to generation) })
        dispatcher.offerStats("one", 1, TunnelStats(sent = 1))
        dispatcher.advance("one", 2)
        dispatcher.offerStats("one", 1, TunnelStats(sent = 999))
        dispatcher.offerStats("one", 2, TunnelStats(sent = 2))
        dispatcher.offerStats("two", 4, TunnelStats(sent = 40))
        repeat(10_000) { dispatcher.offerFailure("one", 2) }
        assertEquals(2, scheduler.pendingCount)
        assertEquals(2, scheduler.maximumPending)
        scheduler.runNext() // zero-delay failure precedes delayed statistics.
        assertEquals(listOf("one" to 2L), failures)
        assertTrue(published.isEmpty())
        scheduler.runNext()
        assertEquals(listOf(Triple("one", 2L, 2L), Triple("two", 4L, 40L)), published)
        dispatcher.close()
    }

    @Test fun stopCancelsPendingWorkAndOldCallbacksCannotRestartIt() {
        val scheduler = Scheduler()
        val published = mutableListOf<String>()
        val dispatcher = ServerEventDispatcher(setOf("one", "two"), scheduler,
            { id, _, _ -> published.add(id) }, { id, _ -> published.add("failure:$id") })
        dispatcher.offerStats("one", 1, TunnelStats(sent = 1))
        dispatcher.offerFailure("two", 1)
        assertEquals(2, scheduler.pendingCount)
        dispatcher.close()
        assertEquals(0, scheduler.pendingCount)
        dispatcher.offerStats("one", 2, TunnelStats(sent = 2))
        dispatcher.offerFailure("two", 2)
        assertEquals(0, scheduler.pendingCount)
        assertTrue(published.isEmpty())
    }
}
