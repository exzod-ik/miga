package org.miga.core

import java.util.Locale

/** Strict bounded DNS decoder. Only answer-section A records reachable from the question are trusted. */
data class DnsQuestion(val name: String, val type: Int, val klass: Int)
data class DnsAddress(val address: Int, val ttl: Long)
data class DnsMessage(val id: Int, val response: Boolean, val truncated: Boolean, val rcode: Int,
                      val question: DnsQuestion, val addresses: List<DnsAddress>)

object DnsParser {
    const val MAX_BYTES = 4096
    private const val MAX_RECORDS = 64
    private const val MAX_DEPTH = 16

    fun parse(data: ByteArray): DnsMessage? = try { decode(data) } catch (_: IllegalArgumentException) { null }

    private fun decode(data: ByteArray): DnsMessage {
        require(data.size in 12..MAX_BYTES)
        fun u8(at: Int): Int { require(at in data.indices); return data[at].toInt() and 255 }
        fun u16(at: Int): Int = (u8(at) shl 8) or u8(at + 1)
        fun u32(at: Int): Long = ((u16(at).toLong() shl 16) or u16(at + 2).toLong())
        fun name(start: Int): Pair<String, Int> {
            var pos = start; var end = -1; var jumps = 0; var total = 0
            val labels = ArrayList<String>(8)
            val visited = HashSet<Int>()
            while (true) {
                require(pos in data.indices && visited.add(pos) && jumps <= MAX_DEPTH)
                val size = u8(pos)
                when {
                    size == 0 -> { if (end < 0) end = pos + 1; break }
                    size and 0xc0 == 0xc0 -> {
                        val pointer = ((size and 0x3f) shl 8) or u8(pos + 1)
                        require(pointer < pos)
                        if (end < 0) end = pos + 2
                        pos = pointer; jumps++
                    }
                    size and 0xc0 == 0 && size in 1..63 -> {
                        require(pos + 1 + size <= data.size)
                        val label = (pos + 1 until pos + 1 + size).map { u8(it).toChar() }.joinToString("")
                        require(label.all { it.code in 33..126 })
                        labels.add(label); total += size + 1; require(total <= 253)
                        pos += size + 1
                    }
                    else -> throw IllegalArgumentException()
                }
            }
            return labels.joinToString(".").lowercase(Locale.ROOT) to end
        }
        val flags = u16(2)
        require(flags and 0x7800 == 0 && u16(4) == 1)
        val count = u16(6) + u16(8) + u16(10)
        require(count <= MAX_RECORDS)
        var offset = 12
        val (rawQuestion, next) = name(offset); require(rawQuestion.isNotEmpty()); offset = next
        val question = DnsQuestion(DomainNames.normalize(rawQuestion), u16(offset), u16(offset + 2)); offset += 4
        data class Record(val owner: String, val type: Int, val ttl: Long, val target: String?, val ip: Int?)
        val answers = ArrayList<Record>()
        for (index in 0 until count) {
            val (owner, afterName) = name(offset); offset = afterName
            val type = u16(offset); val klass = u16(offset + 2); val ttl = u32(offset + 4)
            val length = u16(offset + 8); offset += 10
            require(offset + length <= data.size)
            if (index < u16(6) && klass == 1) {
                if (type == 1) require(length == 4)
                val target = if (type == 5) name(offset).also { require(it.second == offset + length) }.first else null
                val ip = if (type == 1 && length == 4) u32(offset).toInt() else null
                answers.add(Record(owner, type, ttl, target, ip))
            }
            offset += length
        }
        require(offset == data.size)
        val found = ArrayList<DnsAddress>()
        if (flags and 0x8000 != 0 && flags and 0x0200 == 0 && flags and 15 == 0 && question.type == 1 && question.klass == 1) {
            var current = question.name; var ttl = Long.MAX_VALUE
            val seen = HashSet<String>()
            for (depth in 0 until MAX_DEPTH) {
                if (!seen.add(current)) break
                answers.filter { it.owner == current && it.type == 1 && it.ip != null }.forEach {
                    found.add(DnsAddress(it.ip!!, minOf(ttl, it.ttl)))
                }
                val cname = answers.firstOrNull { it.owner == current && it.type == 5 && it.target != null }
                    ?: break
                ttl = minOf(ttl, cname.ttl); current = cname.target!!
            }
        }
        return DnsMessage(u16(0), flags and 0x8000 != 0, flags and 0x0200 != 0,
            flags and 15, question, found.distinctBy { it.address })
    }
}
