package org.miga.core

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalDirectSocksStallTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val user = "local-test-user-1"
    private val password = "local-test-pass-1"

    private class BlockingRemote(private val floodInput: Boolean = false) : Socket() {
        val writeEntered = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val inputReads = AtomicInteger()

        override fun connect(endpoint: SocketAddress, timeout: Int) { }

        override fun getInputStream(): InputStream = if (floodInput) object : InputStream() {
            override fun read(): Int = if (closed.count == 0L) -1 else 42
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                if (closed.count == 0L) return -1
                bytes.fill(42, offset, offset + length)
                inputReads.incrementAndGet()
                return length
            }
        } else ByteArrayInputStream(byteArrayOf())

        override fun getOutputStream(): OutputStream = object : OutputStream() {
            override fun write(value: Int) {
                writeEntered.countDown()
                closed.await()
                throw IOException("remote socket closed")
            }
            override fun write(bytes: ByteArray, offset: Int, length: Int) = write(0)
        }

        override fun close() { closed.countDown() }
    }

    private fun proxy(remote: BlockingRemote, maxSessions: Int = 32) = LocalDirectSocks(
        object : DirectSocketFactory {
            override fun tcp(): Socket = remote
            override fun udp(): DatagramSocket = error("unused")
        }, user, password, maxSessions = maxSessions, idleMillis = 1_000,
        allowLoopbackForTests = true)

    private fun authenticate(proxy: LocalDirectSocks): Socket {
        val client = Socket(loopback, proxy.port)
        client.soTimeout = 4_000
        val input = DataInputStream(client.getInputStream())
        val output = client.getOutputStream()
        output.write(byteArrayOf(5, 1, 2))
        assertArrayEquals(byteArrayOf(5, 2), ByteArray(2).also(input::readFully))
        output.write(byteArrayOf(1, user.length.toByte()) + user.toByteArray() +
            byteArrayOf(password.length.toByte()) + password.toByteArray())
        assertArrayEquals(byteArrayOf(1, 0), ByteArray(2).also(input::readFully))
        return client
    }

    private fun connect(proxy: LocalDirectSocks): Socket = authenticate(proxy).also { client ->
        client.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, 0, 80))
        val response = ByteArray(10).also(DataInputStream(client.getInputStream())::readFully)
        assertEquals(0, response[1].toInt())
    }

    @Test fun halfClosedBlockedWriteExpires() {
        val remote = BlockingRemote()
        proxy(remote).use { proxy ->
            connect(proxy).use { client ->
                assertEquals(-1, client.getInputStream().read())
                client.getOutputStream().write(42)
                assertTrue(remote.writeEntered.await(2, TimeUnit.SECONDS))
                assertTrue("Blocked write outlived idle deadline",
                    remote.closed.await(2, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun bothBlockedWritesExpireWithoutProgress() {
        val remote = BlockingRemote(floodInput = true)
        proxy(remote).use { proxy ->
            connect(proxy).use { client ->
                client.receiveBufferSize = 1_024
                client.getOutputStream().write(42)
                assertTrue(remote.writeEntered.await(2, TimeUnit.SECONDS))
                assertTrue("Return direction did not send enough to fill the unread client",
                    await(1_000) { remote.inputReads.get() > 16 })
                assertTrue("Both blocked writes outlived idle deadline",
                    remote.closed.await(2, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun stopUnblocksWriteAndFinishesWorkers() {
        val remote = BlockingRemote()
        val proxy = proxy(remote)
        val client = connect(proxy)
        try {
            client.getOutputStream().write(42)
            assertTrue(remote.writeEntered.await(2, TimeUnit.SECONDS))
            val workers = Thread.getAllStackTraces().keys.filter { it.name.startsWith("miga-direct-") }
            proxy.close()
            assertTrue(remote.closed.await(1, TimeUnit.SECONDS))
            workers.forEach { it.join(2_000); assertFalse("Worker remains: ${it.name}", it.isAlive) }
        } finally { client.close(); proxy.close() }
    }

    @Test fun expiredBlockedSessionReleasesItsOnlySlot() {
        val remote = BlockingRemote()
        proxy(remote, maxSessions = 1).use { proxy ->
            connect(proxy).use { client ->
                client.getOutputStream().write(42)
                assertTrue(remote.writeEntered.await(2, TimeUnit.SECONDS))
                assertTrue(remote.closed.await(2, TimeUnit.SECONDS))
                assertTrue("Expired session retained its slot", await(2_000) {
                    runCatching { authenticate(proxy).use { } }.isSuccess
                })
            }
        }
    }

    private fun await(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(25)
        }
        return condition()
    }
}
