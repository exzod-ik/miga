package org.miga.android

import java.util.Base64

internal fun testInvitation(address: String = "8.8.8.8", first: Int = 12000, last: Int = first): String {
    fun b(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    val key = b(ByteArray(32) { (it + 1).toByte() })
    val id = b(ByteArray(16) { (it + 2).toByte() })
    val json = """{"v":2,"host":"$address","ports":[$first,$last],"server_key":"$key","server_secret":"$key","client_id":"$id","client_secret":"$key"}"""
    return "miga2:" + b(json.toByteArray())
}
