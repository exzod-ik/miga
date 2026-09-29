package org.miga.core

import org.junit.Test

class LegacyMigaCodecTest {
    private val xor = ByteArray(128) { (it * 37 + 11).toByte() }
    private val swap = ByteArray(8) { (it * 29 + 3).toByte() }
    private val codec = LegacyMigaCodec(xor, swap)

    @Test fun cppWireVectorsInBothDirections() {
        val resource = requireNotNull(javaClass.getResourceAsStream("/legacy-vectors.csv"))
        resource.bufferedReader().useLines { lines ->
            lines.forEach { line ->
                val (lengthText, portText, hex) = line.split(',')
                val length = lengthText.toInt()
                val port = portText.toInt()
                val plain = ByteArray(length) { (it * 13 + 7).toByte() }
                val expected = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                assertContentEquals(expected, codec.encode(plain, port), "C++ encode $length/$port")
                assertContentEquals(plain, codec.decode(expected, port), "C++ decode $length/$port")
            }
        }
    }

    @Test fun wrongNonceIsDetectableByValidation() {
        val packet = ByteArray(65) { it.toByte() }
        assertNotEquals(codec.encode(packet, 1).toList(), codec.encode(packet, 4660).toList())
        assertNotEquals(packet.toList(), codec.decode(codec.encode(packet, 1), 4660).toList())
    }

    @Test fun inputAndKeysAreValidated() {
        assertFailsWith<IllegalArgumentException> { LegacyMigaCodec(ByteArray(127), swap) }
        assertFailsWith<IllegalArgumentException> { LegacyMigaCodec(xor, ByteArray(9)) }
        assertFailsWith<IllegalArgumentException> { codec.decode(byteArrayOf(), 1) }
        assertFailsWith<IllegalArgumentException> { codec.encode(byteArrayOf(1), 0) }
        assertFailsWith<IllegalArgumentException> { codec.encode(ByteArray(65536), 1) }
        assertEquals(65535, codec.encode(ByteArray(65535), 1).size)
    }
}
