package org.miga.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UiStateTest {
    @Test fun sshIsRequiredOnlyForNewOrChangedServerAddress() {
        val profile = ServerProfile("id", "One", "8.8.8.8", 2000, 2001, "ref")
        assertTrue(serverNeedsSsh(null, "8.8.8.8"))
        assertFalse(serverNeedsSsh(profile, "8.8.8.8"))
        assertFalse(serverNeedsSsh(profile, "008.008.008.008"))
        assertTrue(serverNeedsSsh(profile, "8.8.4.4"))
    }

    @Test fun buttonAndEditLockFollowServicePhase() {
        assertFalse(tunnelOn(Phase.IDLE))
        assertFalse(tunnelOn(Phase.PREPARING))
        assertFalse(tunnelOn(Phase.STARTING))
        assertTrue(editsLocked(Phase.PREPARING))
        assertTrue(editsLocked(Phase.STARTING))
        listOf(Phase.RUNNING, Phase.REPLIED, Phase.NO_RESPONSE, Phase.PARTIAL,
            Phase.NETWORK_LOST, Phase.WAITING, Phase.RETRYING).forEach {
            assertTrue(tunnelOn(it))
            assertTrue(editsLocked(it))
        }
        assertFalse(tunnelOn(Phase.STOPPING))
        assertTrue(editsLocked(Phase.STOPPING))
        assertFalse(editsLocked(Phase.STOPPED))
    }

    @Test fun themeFallsBackToSystem() {
        assertEquals(ThemeChoice.SYSTEM, ThemeChoice.fromStored(null))
        assertEquals(ThemeChoice.SYSTEM, ThemeChoice.fromStored("UNKNOWN"))
        assertEquals(ThemeChoice.LIGHT, ThemeChoice.fromStored("LIGHT"))
        assertEquals(ThemeChoice.DARK, ThemeChoice.fromStored("DARK"))
    }
}
