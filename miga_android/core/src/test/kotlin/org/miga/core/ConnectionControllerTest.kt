package org.miga.core

import java.io.Closeable
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionControllerTest {
    private class Scheduler : RetryScheduler {
        data class Job(val delay: Long, val run: () -> Unit, var cancelled: Boolean = false)
        val jobs = mutableListOf<Job>()
        override fun schedule(delayMillis: Long, task: () -> Unit): Closeable {
            val job = Job(delayMillis, task)
            jobs.add(job)
            return Closeable { job.cancelled = true }
        }
        fun fire() { val job = jobs.last(); if (!job.cancelled) job.run() }
    }

    @Test fun lossReturnAndPrimarySwitchCloseOldConnection() {
        val scheduler = Scheduler()
        val opened = mutableListOf<String>()
        val closed = mutableListOf<String>()
        val states = mutableListOf<ConnectionState>()
        val control = ConnectionController(scheduler, { 0 }, { it: String -> it.hashCode().toLong() },
            { network: String, _: Long -> opened.add(network); Closeable { closed.add(network) } },
            { state, _ -> states.add(state) })
        control.available("cell", 2)
        control.available("wifi", 0)
        assertEquals(listOf("cell", "wifi"), opened)
        assertEquals(listOf("cell"), closed)
        control.available("wifi", 0) // duplicate callback
        assertEquals(2, opened.size)
        control.lost("wifi")
        assertEquals("cell", control.activeNetwork)
        control.lost("cell")
        assertEquals(null, control.activeNetwork)
        assertEquals(ConnectionState.WAITING_NETWORK, states.last())
        control.available("wifi", 0)
        assertEquals("wifi", control.activeNetwork)
        control.close()
        assertEquals(listOf("cell", "wifi", "cell", "wifi"), closed)
    }

    @Test fun failureBackoffAndStopCancelTimersAndStaleCallbacks() {
        val scheduler = Scheduler()
        var failures = 2
        var opens = 0
        var closes = 0
        val control = ConnectionController(scheduler, { 0 }, { it: String -> it.hashCode().toLong() },
            { _: String, _: Long ->
                opens++
                if (failures-- > 0) error("synthetic bind failure")
                Closeable { closes++ }
            }, { _: ConnectionState, _: String? -> })
        control.available("wifi", 0)
        assertEquals(1_000L, scheduler.jobs.last().delay)
        scheduler.fire()
        assertEquals(2_000L, scheduler.jobs.last().delay)
        scheduler.fire()
        assertEquals(3, opens)
        assertEquals("wifi", control.activeNetwork)
        val oldToken = control.token - 1
        control.failed(oldToken)
        assertEquals(0, closes)
        control.failed(control.token)
        assertEquals(1, closes)
        assertEquals(1_000L, scheduler.jobs.last().delay) // success reset backoff
        control.close()
        assertTrue(scheduler.jobs.last().cancelled)
        scheduler.fire()
        assertEquals(3, opens)
    }

    @Test fun stopDuringConnectingPreventsLateOpen() {
        val scheduler = Scheduler()
        var opens = 0
        lateinit var control: ConnectionController<String>
        control = ConnectionController(scheduler, { 0 }, { it: String -> it.hashCode().toLong() },
            { _: String, _: Long -> opens++; Closeable {} },
            { state: ConnectionState, _: String? -> if (state == ConnectionState.CONNECTING) control.close() })
        control.available("wifi", 0)
        assertEquals(0, opens)
        assertEquals(null, control.activeNetwork)
    }
    @Test fun reorderedCallbacksAndStoppedSessionCannotReopen() {
        val scheduler = Scheduler()
        val opened = mutableListOf<String>()
        val control = ConnectionController(scheduler, { 0 }, { it: String -> it.hashCode().toLong() },
            { network: String, _: Long -> opened.add(network); Closeable {} },
            { _: ConnectionState, _: String? -> })
        control.available("wifi", 0)
        val firstToken = control.token
        control.available("cell", 2) // Later cellular callback cannot replace preferred Wi-Fi.
        control.available("wifi", 0)
        control.lost("cell")
        assertEquals(listOf("wifi"), opened)
        control.lost("wifi")
        control.available("cell", 2) // Return after loss.
        assertEquals("cell", control.activeNetwork)
        control.failed(firstToken) // Delayed failure from the closed socket.
        assertEquals("cell", control.activeNetwork)
        control.close()
        control.available("wifi", 0) // Late callback after explicit Stop.
        scheduler.jobs.lastOrNull()?.run?.invoke() // Even a queued timer cannot reopen.
        assertEquals(listOf("wifi", "cell"), opened)
    }
    @Test fun cancelledOldTimerCannotStartOnNewNetwork() {
        val scheduler = Scheduler()
        val opened = mutableListOf<String>()
        var failWifi = true
        val control = ConnectionController(scheduler, { 0 }, { it: String -> it.hashCode().toLong() },
            { network: String, _: Long ->
                opened.add(network)
                if (network == "wifi" && failWifi) error("temporary")
                Closeable {}
            }, { _: ConnectionState, _: String? -> })
        control.available("wifi", 0)
        val stale = scheduler.jobs.last()
        control.lost("wifi")
        control.available("cell", 2)
        stale.run() // Simulates an already-dispatched timer after cancellation.
        assertEquals(listOf("wifi", "cell"), opened)
        control.close()
    }
    @Test fun unavailableNetworkCancelsRetryWithoutPolling() {
        val scheduler = Scheduler()
        var opens = 0
        val control = ConnectionController(scheduler, { 0 }, { it: String -> it.hashCode().toLong() },
            { _: String, _: Long -> opens++; error("protect failed") },
            { _: ConnectionState, _: String? -> })
        control.available("wifi", 0)
        control.lost("wifi")
        assertTrue(scheduler.jobs.last().cancelled)
        assertFalse(control.activeNetwork != null)
        scheduler.fire()
        assertEquals(1, opens)
        control.close()
    }
}
