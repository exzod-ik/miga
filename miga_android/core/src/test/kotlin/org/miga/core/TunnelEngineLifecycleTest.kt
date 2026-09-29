package org.miga.core

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelEngineLifecycleTest {
    private val codec = LegacyMigaCodec(ByteArray(128), ByteArray(8))

    private class BlockingDevice(private val failRead: Boolean = false, private val failClose: Boolean = false) : PacketDevice {
        val entered = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val releaseRead = CountDownLatch(1)
        val closeCalls = AtomicInteger()
        override fun read(): ByteArray? {
            entered.countDown()
            try {
                releaseRead.await()
                if (failRead) throw IOException("synthetic TUN failure")
                return null
            } finally { finished.countDown() }
        }
        override fun write(packet: ByteArray) = Unit
        override fun close() {
            closeCalls.incrementAndGet()
            releaseRead.countDown()
            closed.countDown()
            if (failClose) throw IOException("synthetic close failure")
        }
    }

    private class BlockingTransport : DatagramTransport {
        val entered = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val releaseRead = CountDownLatch(1)
        val closeCalls = AtomicInteger()
        override fun receive(): ReceivedDatagram? {
            entered.countDown()
            try { releaseRead.await(); return null }
            finally { finished.countDown() }
        }
        override fun send(bytes: ByteArray, destinationPort: Int) = Unit
        override fun close() {
            closeCalls.incrementAndGet()
            releaseRead.countDown()
            closed.countDown()
        }
    }

    private class DelayedExitTransport : DatagramTransport {
        val entered = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val allowExit = CountDownLatch(1)
        val exited = CountDownLatch(1)
        override fun receive(): ReceivedDatagram? {
            entered.countDown()
            while (true) {
                try { allowExit.await(); break }
                catch (_: InterruptedException) { /* Deliberately hold the peer for the test. */ }
            }
            exited.countDown()
            return null
        }
        override fun send(bytes: ByteArray, destinationPort: Int) = Unit
        override fun close() { closed.countDown() }
    }

    private fun engine(device: PacketDevice, transport: DatagramTransport, onStats: (TunnelStats) -> Unit = {}): TunnelEngine =
        TunnelEngine(device, transport, codec, 0x08080808, 6000, 6000,
            { 6000 }, Clock { 1000 }, onStats)

    private fun await(latch: CountDownLatch) = assertTrue(latch.await(2, TimeUnit.SECONDS))

    @Test fun noDataIsNotFailureAndCloseUnblocksBothReaders() {
        val device = BlockingDevice()
        val transport = BlockingTransport()
        val failure = CountDownLatch(1)
        val engine = engine(device, transport) { if (it.error != null) failure.countDown() }
        engine.start()
        await(device.entered); await(transport.entered)
        assertFalse(failure.await(150, TimeUnit.MILLISECONDS))
        engine.close()
        await(device.finished); await(transport.finished)
        assertEquals(1, device.closeCalls.get())
        assertEquals(1, transport.closeCalls.get())
    }

    @Test fun oneCloseFailureDoesNotSkipOtherResourceOrPreventRepeatedClose() {
        val device = BlockingDevice(failClose = true)
        val transport = BlockingTransport()
        val engine = engine(device, transport)
        engine.start()
        await(device.entered); await(transport.entered)
        assertFailsWith<IOException> { engine.close() }
        await(device.finished); await(transport.finished); await(transport.closed)
        assertNotNull(engine.cleanupError)
        engine.close()
        assertEquals(1, device.closeCalls.get())
        assertEquals(1, transport.closeCalls.get())
    }

    @Test fun concurrentCloseRunsCleanupOnce() {
        val device = BlockingDevice()
        val transport = BlockingTransport()
        val engine = engine(device, transport)
        engine.start()
        await(device.entered); await(transport.entered)
        val go = CountDownLatch(1)
        val done = CountDownLatch(2)
        val failures = LinkedBlockingQueue<Throwable>()
        repeat(2) {
            Thread {
                try { go.await(); engine.close() }
                catch (ex: Throwable) { failures.add(ex) }
                finally { done.countDown() }
            }.start()
        }
        go.countDown()
        await(done)
        assertTrue(failures.isEmpty())
        await(device.finished); await(transport.finished)
        assertEquals(1, device.closeCalls.get())
        assertEquals(1, transport.closeCalls.get())
    }

    @Test fun readerFailureCleansUpWithoutJoiningItself() {
        val device = BlockingDevice(failRead = true)
        val transport = BlockingTransport()
        val failure = CountDownLatch(1)
        val engine = engine(device, transport) { if (it.error != null) failure.countDown() }
        engine.start()
        await(device.entered); await(transport.entered)
        device.releaseRead.countDown()
        await(failure); await(device.closed); await(transport.closed)
        await(device.finished); await(transport.finished)
        engine.close()
    }

    @Test fun workerFailureCleansUpWithoutJoiningItself() {
        val input = LinkedBlockingQueue<ByteArray>()
        val deviceClosed = CountDownLatch(1)
        val device = object : PacketDevice {
            override fun read(): ByteArray? = input.take().takeIf { it.isNotEmpty() }
            override fun write(packet: ByteArray) = Unit
            override fun close() { deviceClosed.countDown(); input.offer(byteArrayOf()) }
        }
        val transport = object : DatagramTransport {
            val closed = CountDownLatch(1)
            override fun receive(): ReceivedDatagram? { closed.await(); return null }
            override fun send(bytes: ByteArray, destinationPort: Int): Unit = throw IOException("synthetic send failure")
            override fun close() { closed.countDown() }
        }
        val failure = CountDownLatch(1)
        val engine = engine(device, transport) { if (it.error != null) failure.countDown() }
        engine.start()
        val packet = ByteArray(28)
        packet[0] = 0x45
        Ipv4Packet.put16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 17
        packet[12] = 10; packet[13] = 1; packet[14] = 2; packet[15] = 3
        packet[16] = 8; packet[17] = 8; packet[18] = 8; packet[19] = 8
        Ipv4Packet.put16(packet, 20, 1111)
        Ipv4Packet.put16(packet, 22, 443)
        Ipv4Packet.put16(packet, 24, 8)
        Checksum.writeTransport(packet, 20, 17)
        Checksum.writeIpv4(packet, 20)
        input.add(packet)
        await(failure); await(deviceClosed); await(transport.closed)
        engine.close()
    }

    @Test fun internalFailureWaitsForPeerWithoutSelfInterrupt() {
        val device = BlockingDevice(failRead = true)
        val transport = DelayedExitTransport()
        val callback = CountDownLatch(1)
        val engine = engine(device, transport) { if (it.error != null) callback.countDown() }
        engine.start()
        await(device.entered); await(transport.entered)
        device.releaseRead.countDown()
        await(transport.closed)
        assertFalse(callback.await(150, TimeUnit.MILLISECONDS))
        assertFalse(engine.cleanupCompleted)
        transport.allowExit.countDown()
        await(transport.exited); await(callback)
        assertTrue(engine.cleanupCompleted)
        assertNull(engine.cleanupError)
    }

    @Test fun concurrentExternalCloseKeepsWaitingAfterCallerInterrupt() {
        val device = BlockingDevice()
        val transport = DelayedExitTransport()
        val engine = engine(device, transport)
        engine.start()
        await(device.entered); await(transport.entered)
        val completed = CountDownLatch(2)
        val failures = LinkedBlockingQueue<Throwable>()
        val preserved = CountDownLatch(1)
        val first = Thread {
            try {
                engine.close()
                if (Thread.currentThread().isInterrupted) preserved.countDown()
            } catch (ex: Throwable) { failures.add(ex) }
            finally { completed.countDown() }
        }
        first.start()
        await(transport.closed)
        first.interrupt()
        val second = Thread {
            try { engine.close() } catch (ex: Throwable) { failures.add(ex) }
            finally { completed.countDown() }
        }
        second.start()
        assertFalse(completed.await(150, TimeUnit.MILLISECONDS))
        assertFalse(engine.cleanupCompleted)
        transport.allowExit.countDown()
        await(transport.exited); await(completed); await(preserved)
        assertTrue(failures.isEmpty())
        assertTrue(engine.cleanupCompleted)
        assertNull(engine.cleanupError)
    }

    @Test fun timeoutIsNotReportedAsCompletedCleanup() {
        val device = BlockingDevice()
        val transport = DelayedExitTransport()
        val engine = TunnelEngine(device, transport, codec, 0x08080808, 6000, 6000,
            { 6000 }, Clock { 1000 }, {}, shutdownTimeoutMillis = 100)
        engine.start()
        await(device.entered); await(transport.entered)
        assertFailsWith<IOException> { engine.close() }
        assertFalse(engine.cleanupCompleted)
        assertNotNull(engine.cleanupError)
        transport.allowExit.countDown()
        await(transport.exited)
    }
}
