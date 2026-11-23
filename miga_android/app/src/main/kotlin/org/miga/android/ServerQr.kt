package org.miga.android

import org.json.JSONObject
import java.io.InputStream
import java.util.Base64

internal data class ServerQr(val address: String, val firstPort: Int, val lastPort: Int, val invitation: String)

internal fun readInvitationFile(input: InputStream): ServerQr {
    val bytes = ByteArray(16384 + 1)
    var length = 0
    while (length < bytes.size) {
        val read = input.read(bytes, length, bytes.size - length)
        if (read < 0) break
        length += read
    }
    require(length < bytes.size) { "Файл приглашения слишком большой" }
    return parseServerQr(bytes.decodeToString(endIndex = length, throwOnInvalidSequence = true).removePrefix("\uFEFF").trim())
}

internal fun parseServerQr(text: String): ServerQr {
    require(text.length <= 4096 && text.startsWith("miga2:")) { "Требуется приглашение miga2:" }
    val encoded = text.substring(6)
    require(encoded.matches(Regex("[A-Za-z0-9_-]+"))) { "Неверное приглашение" }
    val bytes = Base64.getUrlDecoder().decode(encoded)
    require(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == encoded) { "Неверное приглашение" }
    val root = JSONObject(bytes.toString(Charsets.UTF_8))
    require(root.keys().asSequence().toSet() == setOf("v", "host", "ports", "server_key", "server_secret", "client_id", "client_secret") && root.get("v") == 2) { "Неверный формат приглашения" }
    for ((field, size) in listOf("server_key" to 32, "server_secret" to 32, "client_id" to 16, "client_secret" to 32)) {
        val value = root.getString(field)
        val decoded = Base64.getUrlDecoder().decode(value)
        require(decoded.size == size && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == value) { "Неверное приглашение" }
    }
    val ports = root.getJSONArray("ports")
    require(ports.length() == 2 && ports.get(0) is Int && ports.get(1) is Int && ports.getInt(0) >= 1024) { "Неверный диапазон управления" }
    val endpoint = SessionValidator.endpoint(root.getString("host"), ports.getInt(0).toString(), ports.getInt(1).toString())
    return ServerQr(endpoint.first, endpoint.second, endpoint.third, text)
}
