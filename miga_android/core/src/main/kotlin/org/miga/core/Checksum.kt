package org.miga.core

import org.miga.core.Ipv4Packet.Companion.put16
import org.miga.core.Ipv4Packet.Companion.u16

object Checksum {
    private fun sum(data: ByteArray, start: Int, length: Int, seed: Long = 0): Long {
        var result = seed
        var i = start
        while (i + 1 < start + length) { result += u16(data, i); i += 2 }
        if (i < start + length) result += (data[i].toInt() and 255) shl 8
        return result
    }

    private fun finish(value: Long): Int {
        var folded = value
        while (folded ushr 16 != 0L) folded = (folded and 65535L) + (folded ushr 16)
        return folded.inv().toInt() and 65535
    }

    fun valid(data: ByteArray, start: Int, length: Int) = finish(sum(data, start, length)) == 0

    private fun pseudoSum(data: ByteArray, protocol: Int, length: Int): Long =
        sum(data, 12, 8) + protocol + length

    fun validTransport(data: ByteArray, offset: Int, protocol: Int): Boolean {
        val length = data.size - offset
        if (protocol == 17 && u16(data, offset + 6) == 0) return true // IPv4 UDP checksum optional
        return finish(sum(data, offset, length, pseudoSum(data, protocol, length))) == 0
    }

    fun writeTransport(data: ByteArray, offset: Int, protocol: Int) {
        val length = data.size - offset
        val checksumOffset = offset + if (protocol == 6) 16 else 6
        put16(data, checksumOffset, 0)
        var value = finish(sum(data, offset, length, pseudoSum(data, protocol, length)))
        if (protocol == 17 && value == 0) value = 65535
        put16(data, checksumOffset, value)
    }

    fun writeIpv4(data: ByteArray, headerLength: Int) {
        put16(data, 10, 0)
        put16(data, 10, finish(sum(data, 0, headerLength)))
    }
}
