package org.miga.core

import java.io.Closeable

interface PacketDevice : Closeable {
    /** Returns null after close. */
    fun read(): ByteArray?
    fun write(packet: ByteArray)
}

data class ReceivedDatagram(val bytes: ByteArray, val sourceIp: Int, val sourcePort: Int)

interface DatagramTransport : Closeable {
    fun receive(): ReceivedDatagram?
    fun send(bytes: ByteArray, destinationPort: Int)
}

data class TunnelStats(
    val sent: Long = 0, val received: Long = 0, val malformed: Long = 0,
    val fragments: Long = 0, val unknownEndpoint: Long = 0,
    val unknownFlow: Long = 0, val oversized: Long = 0,
    val queueDrops: Long = 0, val unansweredSinceMillis: Long = 0, val lastReplyMillis: Long = 0,
    val error: String? = null,
)
