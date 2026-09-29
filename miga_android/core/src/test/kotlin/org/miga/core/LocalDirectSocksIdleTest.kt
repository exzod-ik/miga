package org.miga.core

import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalDirectSocksIdleTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val user = "direct-idle-user"
    private val password = "direct-idle-pass"
    private val factory = object : DirectSocketFactory {
        override fun tcp() = Socket()
        override fun udp() = DatagramSocket()
    }

    private fun proxy() = LocalDirectSocks(factory, user, password, idleMillis = 1_000,
        allowLoopbackForTests = true)

    private fun connect(proxy: LocalDirectSocks, destinationPort: Int): Socket {
        val client = Socket(loopback, proxy.port)
        client.soTimeout = 5_000
        val input = DataInputStream(client.getInputStream())
        val output = client.getOutputStream()
        output.write(byteArrayOf(5, 1, 2))
        assertArrayEquals(byteArrayOf(5, 2), ByteArray(2).also(input::readFully))
        output.write(byteArrayOf(1, user.length.toByte()) + user.toByteArray() +
            byteArrayOf(password.length.toByte()) + password.toByteArray())
        assertArrayEquals(byteArrayOf(1, 0), ByteArray(2).also(input::readFully))
        output.write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1,
            (destinationPort ushr 8).toByte(), destinationPort.toByte()))
        val response = ByteArray(10).also(input::readFully)
        assertEquals(0, response[1].toInt())
        return client
    }

    @Test fun activeDownloadOutlivesIdleWithoutUpload() {
        ServerSocket(0, 1, loopback).use { server ->
            val worker = thread {
                server.accept().use { remote ->
                    repeat(22) {
                        remote.getOutputStream().write(it)
                        Thread.sleep(100)
                    }
                }
            }
            try {
                proxy().use { proxy ->
                    connect(proxy, server.localPort).use { client ->
                        repeat(22) { assertEquals(it, client.getInputStream().read()) }
                    }
                }
            } finally { worker.join(4_000) }
            assertFalse(worker.isAlive)
        }
    }

    @Test fun activeUploadOutlivesIdleWithoutResponse() {
        ServerSocket(0, 1, loopback).use { server ->
            val worker = thread {
                server.accept().use { remote ->
                    remote.soTimeout = 5_000
                    repeat(22) { assertEquals(it, remote.getInputStream().read()) }
                    remote.getOutputStream().write(99)
                }
            }
            try {
                proxy().use { proxy ->
                    connect(proxy, server.localPort).use { client ->
                        repeat(22) {
                            client.getOutputStream().write(it)
                            Thread.sleep(100)
                        }
                        assertEquals(99, client.getInputStream().read())
                    }
                }
            } finally { worker.join(4_000) }
            assertFalse(worker.isAlive)
        }
    }

    @Test fun halfClosedUploadAllowsLongActiveDownload() {
        ServerSocket(0, 1, loopback).use { server ->
            val worker = thread {
                server.accept().use { remote ->
                    remote.soTimeout = 5_000
                    assertEquals(7, remote.getInputStream().read())
                    assertEquals(-1, remote.getInputStream().read())
                    repeat(32) {
                        remote.getOutputStream().write(it)
                        Thread.sleep(100)
                    }
                }
            }
            try {
                proxy().use { proxy ->
                    connect(proxy, server.localPort).use { client ->
                        client.getOutputStream().write(7)
                        client.shutdownOutput()
                        repeat(32) { assertEquals(it, client.getInputStream().read()) }
                        assertEquals(-1, client.getInputStream().read())
                    }
                }
            } finally { worker.join(5_000) }
            assertFalse(worker.isAlive)
        }
    }

    @Test fun fullyIdleTcpConnectionExpires() {
        ServerSocket(0, 1, loopback).use { server ->
            val remoteClosed = CountDownLatch(1)
            val worker = thread {
                server.accept().use { remote ->
                    remote.soTimeout = 4_000
                    if (remote.getInputStream().read() == -1) remoteClosed.countDown()
                }
            }
            try {
                proxy().use { proxy ->
                    connect(proxy, server.localPort).use { client ->
                        assertEquals(-1, client.getInputStream().read())
                        assertTrue(remoteClosed.await(2, TimeUnit.SECONDS))
                    }
                }
            } finally { worker.join(4_000) }
            assertFalse(worker.isAlive)
        }
    }

    @Test fun stopEndsActiveAndWaitingSessionsAndTheirWorkers() {
        ServerSocket(0, 1, loopback).use { server ->
            val accepted = CountDownLatch(1)
            val worker = thread {
                server.accept().use { remote ->
                    accepted.countDown()
                    try {
                        while (true) {
                            remote.getOutputStream().write(42)
                            Thread.sleep(50)
                        }
                    } catch (_: IOException) { }
                }
            }
            val proxy = proxy()
            val active = connect(proxy, server.localPort)
            val waiting = Socket(loopback, proxy.port)
            try {
                assertTrue(accepted.await(2, TimeUnit.SECONDS))
                active.soTimeout = 3_000
                waiting.soTimeout = 3_000
                assertEquals(42, active.getInputStream().read())
                val workers = Thread.getAllStackTraces().keys.filter { it.name.startsWith("miga-direct-") }
                proxy.close()
                assertEquals(-1, waiting.getInputStream().read())
                while (active.getInputStream().read() >= 0) { /* drain bytes already queued */ }
                workers.forEach { it.join(2_000); assertFalse("Worker remains: ${it.name}", it.isAlive) }
            } finally {
                active.close()
                waiting.close()
                proxy.close()
                worker.join(3_000)
            }
            assertFalse(worker.isAlive)
        }
    }
}
