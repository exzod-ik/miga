package org.miga.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class ServerConfigSshTest {
    private val xor = Base64.getEncoder().encodeToString(ByteArray(128) { it.toByte() })
    private val swap = Base64.getEncoder().encodeToString(ByteArray(8) { it.toByte() })

    @Test fun readsOnlyClientFieldsFromServerConfig() {
        val settings = ServerConfigSsh.parse(config(2000, 2010, xor, swap))
        assertEquals(2000, settings.firstPort)
        assertEquals(2010, settings.lastPort)
        assertEquals(128, settings.keys.xor.size)
        assertEquals(8, settings.keys.swap.size)
    }

    @Test fun rejectsBadPortsAndKeys() {
        assertThrows(IllegalArgumentException::class.java) { ServerConfigSsh.parse(config(3000, 2000, xor, swap)) }
        assertThrows(IllegalArgumentException::class.java) { ServerConfigSsh.parse(config(2000, 2010, "bad", swap)) }
        assertThrows(IllegalArgumentException::class.java) { ServerConfigSsh.parse(config(2000, 2010, xor, "bad")) }
    }

    private fun config(first: Int, last: Int, xorKey: String, swapKey: String) =
        """{"client_ports":{"start":$first,"end":$last},"encryption":{"xor_key":"$xorKey","swap_key":"$swapKey"},"dns_server":"8.8.8.8"}"""
}
