package org.miga.core

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalDirectSocksTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val username = "local-test-user-1"
    private val password = "local-test-pass-1"
    private val factory = object : DirectSocketFactory {
        override fun tcp() = Socket()
        override fun udp() = DatagramSocket()
    }

    private fun handshake(proxy: LocalDirectSocks): Socket {
        val socket = Socket(loopback, proxy.port)
        socket.soTimeout = 3_000
        val out = socket.getOutputStream()
        val input = DataInputStream(socket.getInputStream())
        out.write(byteArrayOf(5, 1, 2))
        assertArrayEquals(byteArrayOf(5, 2), ByteArray(2).also(input::readFully))
        out.write(byteArrayOf(1, username.length.toByte()) + username.toByteArray() +
            byteArrayOf(password.length.toByte()) + password.toByteArray())
        assertArrayEquals(byteArrayOf(1, 0), ByteArray(2).also(input::readFully))
        return socket
    }

    private fun request(socket: Socket, command: Int, port: Int): Int {
        socket.getOutputStream().write(byteArrayOf(5, command.toByte(), 0, 1, 127, 0, 0, 1,
            (port ushr 8).toByte(), port.toByte()))
        val reply = ByteArray(10)
        DataInputStream(socket.getInputStream()).readFully(reply)
        assertEquals(5, reply[0].toInt())
        assertEquals(0, reply[1].toInt())
        return ((reply[8].toInt() and 255) shl 8) or (reply[9].toInt() and 255)
    }

    @Test fun tcpConnectForwardsRealBytesInBothDirections() {
        ServerSocket(0, 1, loopback).use { echo ->
            val worker = thread {
                echo.accept().use { connection ->
                    val bytes = ByteArray(5)
                    DataInputStream(connection.getInputStream()).readFully(bytes)
                    connection.getOutputStream().write(bytes.reversedArray())
                }
            }
            LocalDirectSocks(factory, username, password, allowLoopbackForTests = true).use { proxy ->
                handshake(proxy).use { client ->
                    request(client, 1, echo.localPort)
                    client.getOutputStream().write("hello".toByteArray())
                    val response = ByteArray(5)
                    DataInputStream(client.getInputStream()).readFully(response)
                    assertEquals("olleh", response.toString(Charsets.UTF_8))
                    assertEquals(1, proxy.tcpConnections.get())
                }
            }
            worker.join(3_000)
            assertTrue(!worker.isAlive)
        }
    }

    @Test fun udpAssociateHandlesUnconnectedDatagramsAndReturnPackets() {
        DatagramSocket(0, loopback).use { echo ->
            echo.soTimeout = 3_000
            val worker = thread {
                val packet = DatagramPacket(ByteArray(128), 128)
                echo.receive(packet)
                echo.send(DatagramPacket(packet.data, packet.length, packet.address, packet.port))
            }
            LocalDirectSocks(factory, username, password, allowLoopbackForTests = true).use { proxy ->
                handshake(proxy).use { control ->
                    val relayPort = request(control, 3, 0)
                    DatagramSocket(0, loopback).use { udp ->
                        udp.soTimeout = 3_000
                        val payload = "udp-echo".toByteArray()
                        val header = byteArrayOf(0, 0, 0, 1, 127, 0, 0, 1,
                            (echo.localPort ushr 8).toByte(), echo.localPort.toByte())
                        val bytes = header + payload
                        udp.send(DatagramPacket(bytes, bytes.size, loopback, relayPort))
                        val reply = DatagramPacket(ByteArray(128), 128)
                        udp.receive(reply)
                        assertArrayEquals(payload, reply.data.copyOfRange(10, reply.length))
                        assertEquals(1, proxy.udpPackets.get())
                    }
                }
            }
            worker.join(3_000)
            assertTrue(!worker.isAlive)
        }
    }

    @Test fun sessionLimitAndCloseAreFinite() {
        LocalDirectSocks(factory, username, password, maxSessions = 1, idleMillis = 1_000,
            allowLoopbackForTests = true).use { proxy ->
            handshake(proxy).use { first ->
                Socket(loopback, proxy.port).use { second ->
                    second.soTimeout = 3_000
                    assertEquals(-1, second.getInputStream().read())
                }
                assertTrue(proxy.refused.get() >= 1)
                first.close()
            }
        }
    }

    @Test fun stopClosesOpenUdpAssociationAndRejectsNewConnections() {
        val proxy = LocalDirectSocks(factory, username, password, idleMillis = 1_000,
            allowLoopbackForTests = true)
        val control = handshake(proxy)
        try {
            request(control, 3, 0)
            proxy.close()
            assertEquals(-1, control.getInputStream().read())
            assertTrue(proxy.runCatchingClosed())
        } finally { control.close(); proxy.close() }
    }

    private fun LocalDirectSocks.runCatchingClosed(): Boolean =
        runCatching { Socket(loopback, port).use { } }.isFailure
}
