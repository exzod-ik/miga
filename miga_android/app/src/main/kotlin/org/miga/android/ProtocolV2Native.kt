package org.miga.android

internal object ProtocolV2Native {
    init { System.loadLibrary("miga-v2") }
    external fun open(invitation: String, ip: Int, data: Int, control: Int): Long
    external fun port(handle: Long): Int
    external fun sendStale(handle: Long): Boolean
    external fun dataSent(handle: Long, port: Int)
    external fun probeGeneration(handle: Long): Long
    external fun sendProbe(handle: Long, generation: Long, ip: Int)
    external fun encode(handle: Long, packet: ByteArray, port: Int): ByteArray?
    external fun decode(handle: Long, packet: ByteArray, port: Int): ByteArray?
    external fun close(handle: Long)
}
