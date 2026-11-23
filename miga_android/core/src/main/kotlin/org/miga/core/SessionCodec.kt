package org.miga.core

interface SessionCodec {
    val port: Int
    fun encode(packet: ByteArray, port: Int): ByteArray?
    fun decode(datagram: ByteArray, port: Int): ByteArray?
}
