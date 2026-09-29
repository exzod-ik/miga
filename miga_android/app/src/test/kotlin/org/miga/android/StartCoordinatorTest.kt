package org.miga.android

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class StartCoordinatorTest {
    @Test fun stopWhileSnapshotSuspendedPreventsServiceStart() = runBlocking {
        val coordinator = StartCoordinator()
        val id = coordinator.begin()!!
        val snapshot = CompletableDeferred<String>()
        var launches = 0
        val job = launch(start = CoroutineStart.UNDISPATCHED) {
            val settings = coordinator.prepare(id) { snapshot.await() }
            if (settings != null && coordinator.isCurrent(id)) launches++
        }
        coordinator.cancel()
        snapshot.complete("old settings")
        job.join()
        assertEquals(0, launches)
    }

    @Test fun latePermissionCallbacksAfterStopAreIgnored() {
        val coordinator = StartCoordinator()
        val id = coordinator.begin()!!
        coordinator.expectVpnResult(id)
        coordinator.cancel()
        assertNull(coordinator.vpnResult())
    }

    @Test fun oldPermissionResultDoesNotCompleteNewRequestAfterRecreation() {
        val coordinator = StartCoordinator() // Retained by the ViewModel across Activity recreation.
        val old = coordinator.begin()!!
        coordinator.expectVpnResult(old)
        coordinator.cancel()
        val current = coordinator.begin()!!
        coordinator.expectVpnResult(current)
        assertNull(coordinator.vpnResult())
        assertFalse(coordinator.finish(old))
        assertEquals(current, coordinator.vpnResult())
        assertEquals(true, coordinator.finish(current))
    }

    @Test fun oldSnapshotAndCleanupCannotInterfereWithNewStart() = runBlocking {
        val coordinator = StartCoordinator()
        val old = coordinator.begin()!!
        val oldSnapshot = CompletableDeferred<String>()
        val newSnapshot = CompletableDeferred<String>()
        val started = mutableListOf<String>()
        val oldJob = launch(start = CoroutineStart.UNDISPATCHED) {
            coordinator.prepare(old) { oldSnapshot.await() }?.let { if (coordinator.isCurrent(old)) started.add(it) }
        }
        coordinator.cancel()
        val current = coordinator.begin()!!
        val newJob = launch(start = CoroutineStart.UNDISPATCHED) {
            coordinator.prepare(current) { newSnapshot.await() }?.let { if (coordinator.isCurrent(current)) started.add(it) }
        }
        val settings = SessionSettings(mapOf("id" to ServerSession("8.8.8.8", 0x08080808, 5000, 5000,
            ByteArray(128), ByteArray(8))), mapOf("example.app" to "id"), "id")
        PendingSession.put(current, settings)
        oldSnapshot.complete("old")
        oldJob.join()
        PendingSession.discard(old)
        assertNull(PendingSession.take(old))
        assertSame(settings, PendingSession.take(current))
        newSnapshot.complete("new")
        newJob.join()
        assertEquals(listOf("new"), started)
        assertFalse(coordinator.isCurrent(old))
    }

    @Test fun repeatedStartHasOnlyOneActiveRequest() {
        val coordinator = StartCoordinator()
        val first = coordinator.begin()!!
        assertNull(coordinator.begin())
        assertEquals(true, coordinator.finish(first))
        val next = coordinator.begin()!!
        assertEquals(first + 1, next)
    }
}
