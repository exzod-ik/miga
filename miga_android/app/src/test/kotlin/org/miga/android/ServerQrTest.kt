package org.miga.android

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ServerQrTest {
    private val xor = Base64.getEncoder().encodeToString(ByteArray(128) { it.toByte() })
    private val swap = Base64.getEncoder().encodeToString(ByteArray(8) { it.toByte() })

    @Test fun decodesDesktopPayload() {
        val qr = parseServerQr("""{"type":"miga-server","version":1,"address":"8.8.8.8","ports":[10000,15000],"xor":"$xor","swap":"$swap"}""")
        assertEquals("8.8.8.8", qr.address)
        assertEquals(10000, qr.firstPort)
        assertEquals(15000, qr.lastPort)
        assertEquals(xor, qr.xor)
    }

    @Test fun rejectsWrongFormatAndInvalidKeys() {
        assertThrows(IllegalArgumentException::class.java) { parseServerQr("https://example.com") }
        assertThrows(IllegalArgumentException::class.java) {
            parseServerQr("""{"type":"miga-server","version":1,"address":"8.8.8.8","ports":[10000,15000],"xor":"bad","swap":"$swap"}""")
        }
    }
}
