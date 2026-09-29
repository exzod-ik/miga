package org.miga.core

/** Existing XOR and adjacent-swap wire transform. This provides no authentication or integrity. */
class LegacyMigaCodec(xorKey: ByteArray, swapKey: ByteArray) {
    private val xor = xorKey.copyOf()
    private val swap = swapKey.copyOf()

    init {
        require(xor.size == 128) { "XOR key must contain 128 bytes" }
        require(swap.size == 8) { "Swap key must contain 8 bytes" }
    }

    /** [port] is the numeric UDP destination port, in host order. */
    fun encode(packet: ByteArray, port: Int): ByteArray = transform(packet, port, true)

    /** [port] is the numeric UDP source port from recvfrom, in host order. */
    fun decode(datagram: ByteArray, port: Int): ByteArray = transform(datagram, port, false)

    private fun transform(input: ByteArray, port: Int, forward: Boolean): ByteArray {
        require(port in 1..65535) { "Invalid UDP port" }
        require(input.isNotEmpty() && input.size <= MAX_PACKET_SIZE) { "Invalid payload size" }
        val data = input.copyOf()
        var bits = 0L
        for (i in 0 until 8) bits = bits or ((swap[i].toLong() and 255L) shl (8 * i))
        var repeatedPort = 0L
        for (i in 0 until 4) repeatedPort = repeatedPort or (port.toLong() shl (16 * i))
        bits = bits xor repeatedPort
        if (forward) {
            for (i in data.indices) data[i] = (data[i].toInt() xor xor[i % xor.size].toInt()).toByte()
            for (i in 0 until data.lastIndex) if (((bits ushr (i % 64)) and 1L) != 0L) data.swap(i, i + 1)
        } else {
            for (i in data.lastIndex downTo 1) if (((bits ushr ((i - 1) % 64)) and 1L) != 0L) data.swap(i - 1, i)
            for (i in data.indices) data[i] = (data[i].toInt() xor xor[i % xor.size].toInt()).toByte()
        }
        return data
    }

    private fun ByteArray.swap(a: Int, b: Int) { val x = this[a]; this[a] = this[b]; this[b] = x }

    companion object { const val MAX_PACKET_SIZE = 65535 }
}
