package org.miga.core

/** Bounded, byte-oriented IPv4 parser. Inner fragments are intentionally rejected. */
data class Ipv4Packet(
    val bytes: ByteArray,
    val headerLength: Int,
    val protocol: Int,
    val sourcePort: Int,
    val destinationPort: Int,
    val transportHeaderLength: Int,
) {
    companion object {
        fun parse(input: ByteArray, verifyChecksums: Boolean = true): Ipv4Packet? {
            if (input.size !in 20..65535 || (input[0].toInt() ushr 4 and 15) != 4) return null
            val ihl = (input[0].toInt() and 15) * 4
            if (ihl !in 20..60 || input.size < ihl || u16(input, 2) != input.size) return null
            if (u16(input, 6) and 0xbfff != 0) return null // reserved, offset or MF; DF is allowed
            val protocol = u8(input, 9)
            if (protocol != 6 && protocol != 17) return null
            if (verifyChecksums && !Checksum.valid(input, 0, ihl)) return null
            val length = input.size - ihl
            val headerLength = when (protocol) {
                6 -> {
                    if (length < 20) return null
                    val offset = (u8(input, ihl + 12) ushr 4) * 4
                    if (offset !in 20..60 || offset > length) return null
                    var option = ihl + 20
                    while (option < ihl + offset) {
                        val kind = u8(input, option)
                        if (kind == 0) break
                        if (kind == 1) { option++; continue }
                        if (option + 1 >= ihl + offset) return null
                        val optionLength = u8(input, option + 1)
                        if (optionLength < 2 || option + optionLength > ihl + offset) return null
                        if (kind == 2 && optionLength != 4) return null
                        option += optionLength
                    }
                    offset
                }
                else -> {
                    if (length < 8 || u16(input, ihl + 4) != length) return null
                    8
                }
            }
            if (verifyChecksums && !Checksum.validTransport(input, ihl, protocol)) return null
            return Ipv4Packet(input.copyOf(), ihl, protocol, u16(input, ihl), u16(input, ihl + 2), headerLength)
        }

        internal fun u8(data: ByteArray, offset: Int) = data[offset].toInt() and 255
        internal fun u16(data: ByteArray, offset: Int) = (u8(data, offset) shl 8) or u8(data, offset + 1)
        internal fun put16(data: ByteArray, offset: Int, value: Int) {
            data[offset] = (value ushr 8).toByte(); data[offset + 1] = value.toByte()
        }
    }

    /** Clamps a well-formed MSS option in SYN or SYN-ACK and recalculates TCP checksum. */
    fun clampMss(maxMss: Int): ByteArray? {
        require(maxMss in 1..65535)
        if (protocol != 6 || (bytes[headerLength + 13].toInt() and 2) == 0) return bytes.copyOf()
        val copy = bytes.copyOf()
        var offset = headerLength + 20
        val end = headerLength + transportHeaderLength
        while (offset < end) {
            val kind = u8(copy, offset)
            if (kind == 0) break
            if (kind == 1) { offset++; continue }
            if (offset + 1 >= end) return null
            val optionLength = u8(copy, offset + 1)
            if (optionLength < 2 || offset + optionLength > end) return null
            if (kind == 2) {
                if (optionLength != 4) return null
                if (u16(copy, offset + 2) > maxMss) {
                    put16(copy, offset + 2, maxMss)
                    put16(copy, headerLength + 16, 0)
                    Checksum.writeTransport(copy, headerLength, 6)
                }
                break
            }
            offset += optionLength
        }
        return copy
    }
}
