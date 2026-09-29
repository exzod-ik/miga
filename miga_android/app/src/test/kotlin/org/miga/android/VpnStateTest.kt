package org.miga.android

import org.junit.Assert.assertEquals
import org.junit.Test
import org.miga.core.TunnelStats
import org.miga.core.ConnectionState

class VpnStateTest {
    @Test fun overallStatusPreservesServersAndUnknownOwnerDropsAcrossTransitions() {
        VpnState.begin()
        VpnState.updateServerState("one", ConnectionState.WAITING_NETWORK)
        VpnState.updateServerState("two", ConnectionState.WAITING_NETWORK)
        VpnState.addUnknownOwnerDrops(7)
        VpnState.updateServerState("one", ConnectionState.CONNECTING)
        VpnState.update(Phase.STARTING, "one connecting")
        VpnState.updateServerState("one", ConnectionState.RUNNING)
        VpnState.updateServerState("two", ConnectionState.RUNNING)
        VpnState.update(Phase.RUNNING, "both running")
        assertEquals(2, VpnState.status.value.servers.size)
        assertEquals(7L, VpnState.status.value.unknownOwnerDrops)
        VpnState.updateServerStats("two", TunnelStats(sent = 1, received = 1, lastReplyMillis = 1000))
        VpnState.updateServerState("one", ConnectionState.RETRYING)
        VpnState.update(Phase.PARTIAL, "one retrying")
        assertEquals(1L, VpnState.status.value.servers.getValue("two").stats.received)
        VpnState.updateServerState("one", ConnectionState.CONNECTING)
        VpnState.updateServerState("one", ConnectionState.RUNNING)
        VpnState.updateServerStats("one", TunnelStats(sent = 1, unansweredSinceMillis = 2000))
        VpnState.update(Phase.RUNNING, "both local transports running")
        VpnState.checkNoResponse(20_000)
        VpnState.update(Phase.PARTIAL, "one has no reply")
        assertEquals(true, VpnState.status.value.servers.getValue("one").noResponse)
        VpnState.updateServerStats("one", TunnelStats(sent = 2, unansweredSinceMillis = 2000))
        assertEquals(true, VpnState.status.value.servers.getValue("one").noResponse)
        VpnState.updateServerStats("one", TunnelStats(sent = 2, received = 1, lastReplyMillis = 20_000))
        assertEquals(false, VpnState.status.value.servers.getValue("one").noResponse)
        assertEquals(1L, VpnState.status.value.servers.getValue("two").stats.received)
        VpnState.update(Phase.STOPPED, "stopped")
        VpnState.begin()
        assertEquals(emptyMap<String, ServerStatus>(), VpnState.status.value.servers)
        assertEquals(0L, VpnState.status.value.unknownOwnerDrops)
        assertEquals(TunnelStats(), VpnState.status.value.stats)
    }
    @Test fun perServerNoResponseClearsOnlyOnNewValidReply() {
        VpnState.begin()
        VpnState.updateServerState("one", ConnectionState.RUNNING)
        VpnState.updateServerStats("one", TunnelStats(sent = 1, received = 1, lastReplyMillis = 1000))
        VpnState.updateServerStats("one", TunnelStats(sent = 2, received = 1,
            lastReplyMillis = 1000, unansweredSinceMillis = 2000))
        VpnState.checkNoResponse(20_000)
        assertEquals(true, VpnState.status.value.servers["one"]!!.noResponse)
        VpnState.updateServerStats("one", TunnelStats(sent = 3, received = 1,
            lastReplyMillis = 1000, unansweredSinceMillis = 2000))
        assertEquals(true, VpnState.status.value.servers["one"]!!.noResponse)
        VpnState.updateServerStats("one", TunnelStats(sent = 3, received = 2, lastReplyMillis = 20_000))
        assertEquals(false, VpnState.status.value.servers["one"]!!.noResponse)
    }
    @Test fun staleReplyAndOutboundStatsDoNotClearNoResponse() {
        VpnState.begin()
        VpnState.update(Phase.RUNNING, "running")
        VpnState.updateStats(TunnelStats(sent = 1, received = 1, lastReplyMillis = 1000))
        assertEquals(Phase.REPLIED, VpnState.status.value.phase)
        VpnState.update(Phase.NO_RESPONSE, "timeout")
        VpnState.updateStats(TunnelStats(sent = 2, received = 1, queueDrops = 3,
            lastReplyMillis = 1000, unansweredSinceMillis = 2000))
        assertEquals(Phase.NO_RESPONSE, VpnState.status.value.phase)
    }

    @Test fun newReplyRestoresRepliedEvenWithSameClockTick() {
        VpnState.begin()
        VpnState.update(Phase.RUNNING, "running")
        VpnState.updateStats(TunnelStats(received = 1, lastReplyMillis = 1000))
        VpnState.update(Phase.NO_RESPONSE, "timeout")
        VpnState.updateStats(TunnelStats(sent = 2, received = 2, lastReplyMillis = 1000))
        assertEquals(Phase.REPLIED, VpnState.status.value.phase)
    }

    @Test fun newTransportAndSessionDoNotInheritReply() {
        VpnState.begin()
        VpnState.update(Phase.RUNNING, "running")
        VpnState.updateStats(TunnelStats(received = 2, lastReplyMillis = 1000))
        VpnState.beginTransport()
        VpnState.update(Phase.RUNNING, "new transport")
        VpnState.updateStats(TunnelStats(sent = 1, received = 0))
        assertEquals(Phase.RUNNING, VpnState.status.value.phase)
        assertEquals(0L, VpnState.status.value.stats.lastReplyMillis)
        VpnState.updateStats(TunnelStats(sent = 1, received = 1, lastReplyMillis = 1000))
        assertEquals(Phase.REPLIED, VpnState.status.value.phase)
        VpnState.begin()
        VpnState.update(Phase.RUNNING, "new session")
        VpnState.updateStats(TunnelStats(sent = 1, received = 0))
        assertEquals(Phase.RUNNING, VpnState.status.value.phase)
        assertEquals(0L, VpnState.status.value.stats.lastReplyMillis)
    }
}
