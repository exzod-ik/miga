package org.miga.android

import org.json.JSONObject

internal data class ServerQr(val address: String, val firstPort: Int, val lastPort: Int,
                             val xor: String, val swap: String)

internal fun parseServerQr(text: String): ServerQr {
    require(text.length <= 4096) { "QR-код слишком длинный" }
    val root = try { JSONObject(text) }
        catch (_: Exception) { throw IllegalArgumentException("Это не QR-код сервера M.I.G.A.") }
    require(root.optString("type") == "miga-server" && root.optInt("version") == 1) {
        "Это не QR-код сервера M.I.G.A."
    }
    val ports = root.optJSONArray("ports") ?: throw IllegalArgumentException("Не указан диапазон портов")
    require(ports.length() == 2) { "Неверный диапазон портов" }
    val address = root.getString("address")
    val first = ports.getInt(0)
    val last = ports.getInt(1)
    val endpoint = SessionValidator.endpoint(address, first.toString(), last.toString())
    val xor = root.getString("xor")
    val swap = root.getString("swap")
    SessionValidator.keyBase64(xor, 128)
    SessionValidator.keyBase64(swap, 8)
    return ServerQr(endpoint.first, endpoint.second, endpoint.third, xor, swap)
}
