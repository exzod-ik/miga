package org.miga.core

/** Bounded DNS/TCP observer. TCP itself remains owned by the OS or the application. */
class DnsTcpFramer(private val maxFrame: Int = DnsParser.MAX_BYTES) {
    private data class Segment(val sequence: Long, val bytes: ByteArray)
    private var nextSequence: Long? = null
    private val buffer = ArrayList<Byte>()
    private val pending = ArrayList<Segment>()
    private var pendingBytes = 0
    private val mask = 0xffff_ffffL
    private val window = maxFrame * 2 + 2
    var failed = false
        private set
    val incomplete: Boolean get() = buffer.isNotEmpty() || pending.isNotEmpty()

    fun begin(sequence: Long) {
        clear()
        failed = false
        nextSequence = sequence and mask
    }

    fun offer(sequence: Long, bytes: ByteArray): List<ByteArray> {
        require(sequence in 0..mask)
        if (bytes.isEmpty()) return emptyList()
        if (nextSequence == null) nextSequence = sequence
        val result = ArrayList<ByteArray>()
        accept(sequence, bytes, result, allowQueue = true)
        while (true) {
            val index = pending.indexOfFirst {
                val delta = distance(it.sequence, nextSequence!!)
                delta != Int.MIN_VALUE && delta <= 0
            }
            if (index < 0) break
            val segment = pending.removeAt(index)
            pendingBytes -= segment.bytes.size
            accept(segment.sequence, segment.bytes, result, allowQueue = false)
        }
        return result
    }

    private fun accept(sequence: Long, bytes: ByteArray, result: MutableList<ByteArray>,
                       allowQueue: Boolean) {
        val delta = distance(sequence, nextSequence!!)
        // Exactly half the sequence space has no unambiguous ordering.
        if (delta == Int.MIN_VALUE) { failed = true; return }
        if (delta > 0) {
            if (allowQueue && delta <= window && bytes.size + pendingBytes <= window &&
                pending.size < 32 && pending.none { it.sequence == sequence && it.bytes.contentEquals(bytes) }) {
                pending.add(Segment(sequence, bytes.copyOf()))
                pendingBytes += bytes.size
            } else if (pending.none { it.sequence == sequence && it.bytes.contentEquals(bytes) }) failed = true
            return
        }
        val skip = -delta.toLong()
        if (skip >= bytes.size) return
        val count = bytes.size - skip.toInt()
        if (buffer.size.toLong() + count > window) { clear(); failed = true; return }
        for (index in skip.toInt() until bytes.size) buffer.add(bytes[index])
        nextSequence = (nextSequence!! + count) and mask
        while (buffer.size >= 2) {
            val length = ((buffer[0].toInt() and 255) shl 8) or (buffer[1].toInt() and 255)
            if (length !in 12..maxFrame) { clear(); failed = true; return }
            if (buffer.size < length + 2) break
            result.add(ByteArray(length) { buffer[it + 2] })
            buffer.subList(0, length + 2).clear()
        }
    }

    private fun distance(sequence: Long, expected: Long): Int =
        (((sequence - expected + 0x8000_0000L) and mask) - 0x8000_0000L).toInt()

    fun clear() { nextSequence = null; buffer.clear(); pending.clear(); pendingBytes = 0 }
}
