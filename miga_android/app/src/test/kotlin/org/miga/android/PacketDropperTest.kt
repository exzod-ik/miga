package org.miga.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.miga.core.PacketDevice

class PacketDropperTest {
    @Test fun offlinePacketsAreDrainedWithoutAReplayQueueAndReaderStops() {
        val input = LinkedBlockingQueue<ByteArray>()
        val reads = CountDownLatch(3)
        val closed = CountDownLatch(1)
        val device = object : PacketDevice {
            override fun read(): ByteArray? {
                val packet = input.take()
                if (packet.isEmpty()) return null
                reads.countDown()
                return packet
            }
            override fun write(packet: ByteArray) = error("Offline reader must never write")
            override fun close() { closed.countDown(); input.offer(byteArrayOf()) }
        }
        val dropper = PacketDropper(device)
        dropper.start()
        repeat(3) { input.offer(byteArrayOf(1)) }
        assertTrue(reads.await(2, TimeUnit.SECONDS))
        dropper.close()
        assertTrue(closed.await(2, TimeUnit.SECONDS))
        assertEquals(3L, dropper.dropped.get())
    }
}
