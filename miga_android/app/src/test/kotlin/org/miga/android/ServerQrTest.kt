package org.miga.android

import org.junit.Assert.*
import org.junit.Test

class ServerQrTest {
    @Test fun decodesInvitation() {
        val text = testInvitation("8.8.8.8", 10000, 15000)
        val parsed = parseServerQr(text)
        assertEquals("8.8.8.8", parsed.address)
        assertEquals(10000, parsed.firstPort)
        assertEquals(text, parsed.invitation)
    }
    @Test fun readsInvitationFileWithBomAndTrailingNewline() {
        val text = testInvitation()
        val input = ("\uFEFF" + text + "\r\n").byteInputStream()
        assertEquals(parseServerQr(text), readInvitationFile(input))
    }

    @Test fun rejectsOversizedAndInvalidInvitationFiles() {
        val oversized = (testInvitation() + " ".repeat(16384)).byteInputStream()
        assertThrows(IllegalArgumentException::class.java) { readInvitationFile(oversized) }
        assertThrows(IllegalArgumentException::class.java) { readInvitationFile("miga-server".byteInputStream()) }
    }

    @Test fun rejectsOldPayloadAndInvalidInvitation() {
        for (text in listOf("{}", "miga-server", "miga2:bad", testInvitation() + "="))
            assertThrows(Exception::class.java) { parseServerQr(text) }
    }
    @Test fun oldSettingsRemainUntouched() {
        for (version in 1..4) {
            val raw = java.io.ByteArrayOutputStream()
            java.io.DataOutputStream(raw).use { it.writeInt(version) }
            assertThrows(SettingsCorrupt::class.java) { SettingsCodec.decode(java.util.Base64.getEncoder().encodeToString(raw.toByteArray())) }
        }
    }
}
