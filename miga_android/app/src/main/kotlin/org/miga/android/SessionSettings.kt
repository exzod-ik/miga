package org.miga.android

import org.miga.core.PublicRoutes
import org.miga.core.StaticIpv4Rule
import org.miga.core.DomainRule
import java.util.Base64

class SessionSettings(
    profiles: Map<String, ServerSession>,
    assignments: Map<String, String>,
    val dnsProfileId: String? = null, // Legacy document field; ignored by routing.
    val captureMode: CaptureMode = CaptureMode.ASSIGNED_APPS,
    ipv4Rules: List<StaticIpv4Rule> = emptyList(),
    domainRules: List<DomainRule> = emptyList(),
) {
    private val profileSnapshot = profiles.toMap()
    private val assignmentSnapshot = assignments.toMap()
    val profiles: Map<String, ServerSession> get() = profileSnapshot.toMap()
    val assignments: Map<String, String> get() = assignmentSnapshot.toMap()
    val packages: Set<String> get() = assignments.keys
    private val rulesSnapshot = ipv4Rules.toList()
    val ipv4Rules: List<StaticIpv4Rule> get() = rulesSnapshot.toList()
    private val domainsSnapshot = domainRules.toList()
    val domainRules: List<DomainRule> get() = domainsSnapshot.toList()
    // Compatibility accessors for the single-profile validator and its regression tests.
    private val first: ServerSession get() = profiles.values.first()
    val serverAddress: String get() = first.serverAddress
    val serverIp: Int get() = first.serverIp
    val firstPort: Int get() = first.firstPort
    val lastPort: Int get() = first.lastPort
    val xorKey: ByteArray get() = first.xorKey.copyOf()
    val swapKey: ByteArray get() = first.swapKey.copyOf()
}

class ServerSession(
    val serverAddress: String,
    val serverIp: Int,
    val firstPort: Int,
    val lastPort: Int,
    xorKey: ByteArray,
    swapKey: ByteArray,
) {
    private val xorSnapshot = xorKey.copyOf()
    private val swapSnapshot = swapKey.copyOf()
    val xorKey: ByteArray get() = xorSnapshot.copyOf()
    val swapKey: ByteArray get() = swapSnapshot.copyOf()
}

object PendingSession {
    private data class Entry(val requestId: Long, val settings: SessionSettings)
    private var value: Entry? = null
    @Synchronized fun put(requestId: Long, settings: SessionSettings) { value = Entry(requestId, settings) }
    @Synchronized fun discard(requestId: Long) {
        if (value?.requestId == requestId) value = null
    }
    @Synchronized fun take(requestId: Long): SessionSettings? {
        if (value?.requestId != requestId) return null
        return value?.settings.also { value = null }
    }
}

object SessionValidator {
    fun endpoint(address: String, first: String, last: String): Triple<String, Int, Int> {
        val octets = address.trim().split('.')
        require(octets.size == 4 && octets.all { it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) && it.toIntOrNull() in 0..255 }) { "Enter a numeric IPv4 server address" }
        val ip = octets.fold(0) { result, part -> (result shl 8) or part.toInt() }
        require(PublicRoutes.isPublic(ip)) { "Server must have a public IPv4 address" }
        val start = first.toIntOrNull()
        val end = last.toIntOrNull()
        require(start != null && end != null && start in 1..65535 && end in start..65535) { "Enter a valid UDP port range" }
        return Triple(octets.joinToString(".") { it.toInt().toString() }, start, end)
    }

    fun keyBase64(value: String, bytes: Int): ByteArray {
        val decoded = try { Base64.getDecoder().decode(value.trim()) }
        catch (_: IllegalArgumentException) { throw IllegalArgumentException("Key must be valid Base64") }
        require(decoded.size == bytes) { "Key must decode to exactly $bytes bytes" }
        return decoded
    }

    fun server(profile: ServerProfile, secret: SecretKeys): ServerSession {
        val (address, first, last) = endpoint(profile.address, profile.firstPort.toString(), profile.lastPort.toString())
        require(secret.xor.size == 128 && secret.swap.size == 8) { "Stored key length is invalid; replace the keys" }
        val ip = address.split('.').fold(0) { result, part -> (result shl 8) or part.toInt() }
        return ServerSession(address, ip, first, last, secret.xor.copyOf(), secret.swap.copyOf())
    }
}
