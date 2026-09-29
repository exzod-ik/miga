package org.miga.core

fun interface Clock { fun elapsedMillis(): Long }

data class FlowKey(val protocol: Int, val sourceIp: Int, val sourcePort: Int, val destinationIp: Int, val destinationPort: Int) {
    fun reverse() = FlowKey(protocol, destinationIp, destinationPort, sourceIp, sourcePort)

    companion object {
        fun from(packet: Ipv4Packet): FlowKey {
            val bytes = packet.bytes
            fun address(offset: Int): Int = (Ipv4Packet.u16(bytes, offset) shl 16) or Ipv4Packet.u16(bytes, offset + 2)
            return FlowKey(packet.protocol, address(12), packet.sourcePort, address(16), packet.destinationPort)
        }
    }
}

/** Single-owner table with bounded capacity, age and configuration generation. */
class FlowTable(private val clock: Clock, private val maxEntries: Int, private val ttlMillis: Long) {
    init { require(maxEntries > 0 && ttlMillis > 0) }

    private data class Entry(val generation: Long, var lastSeen: Long)
    private val entries = LinkedHashMap<FlowKey, Entry>(16, 0.75f, true)

    val size: Int get() = entries.size

    fun remember(key: FlowKey, generation: Long) {
        val now = clock.elapsedMillis()
        prune(now)
        entries[key] = Entry(generation, now)
        if (entries.size > maxEntries) entries.remove(entries.keys.first())
    }

    fun contains(key: FlowKey, generation: Long): Boolean {
        val now = clock.elapsedMillis()
        val entry = entries[key] ?: return false
        if (entry.generation != generation || now < entry.lastSeen || now - entry.lastSeen >= ttlMillis) {
            entries.remove(key)
            return false
        }
        entry.lastSeen = now
        return true
    }

    fun clear() = entries.clear()

    private fun prune(now: Long) {
        val iterator = entries.values.iterator()
        while (iterator.hasNext()) {
            val seen = iterator.next().lastSeen
            if (now < seen || now - seen >= ttlMillis) iterator.remove()
        }
    }
}
