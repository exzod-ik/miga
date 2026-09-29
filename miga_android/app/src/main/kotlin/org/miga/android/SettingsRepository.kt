package org.miga.android

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64
import java.util.UUID
import org.miga.core.Ipv4Interval
import org.miga.core.StaticIpv4Rule
import org.miga.core.StaticIpv4RuleSet
import org.miga.core.DomainNames
import org.miga.core.DomainRule
import org.miga.core.DomainRuleSet

data class ServerProfile(
    val id: String,
    val name: String,
    val address: String,
    val firstPort: Int,
    val lastPort: Int,
    val secretRef: String,
)

enum class CaptureMode { ASSIGNED_APPS, PUBLIC_IPV4_RULES }

data class SavedIpv4Rule(val id: String, val profileId: String, val expression: String)
data class SavedDomainRule(val id: String, val profileId: String, val pattern: String)

data class SavedSettings(
    val schemaVersion: Int = 4,
    val profiles: List<ServerProfile> = emptyList(),
    val activeProfileId: String? = null,
    val assignments: Map<String, String> = emptyMap(),
    val dnsProfileId: String? = null,
    val captureMode: CaptureMode = CaptureMode.ASSIGNED_APPS,
    val ipv4Rules: List<SavedIpv4Rule> = emptyList(),
    val domainRules: List<SavedDomainRule> = emptyList(),
) {
    val selectedPackages: Set<String> get() = assignments.keys
}

data class SecretKeys(val xor: ByteArray, val swap: ByteArray)

interface SettingsStore {
    suspend fun read(): String?
    suspend fun write(value: String)
}

interface SecretStore {
    suspend fun put(ref: String, keys: SecretKeys)
    suspend fun get(ref: String): SecretKeys
    suspend fun delete(ref: String)
}

class SettingsCorrupt(message: String) : Exception(message)
class SecretUnavailable : Exception("Saved keys are unavailable; enter them again")

/** A single versioned binary document in DataStore. Secret bytes never enter this codec. */
object SettingsCodec {
    fun encode(settings: SavedSettings): String {
        validate(settings)
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeInt(settings.schemaVersion)
            out.writeInt(settings.profiles.size)
            settings.profiles.forEach { profile ->
                out.writeUTF(profile.id)
                out.writeUTF(profile.name)
                out.writeUTF(profile.address)
                out.writeInt(profile.firstPort)
                out.writeInt(profile.lastPort)
                out.writeUTF(profile.secretRef)
            }
            out.writeBoolean(settings.activeProfileId != null)
            settings.activeProfileId?.let(out::writeUTF)
            out.writeInt(settings.assignments.size)
            settings.assignments.toSortedMap().forEach { (name, id) -> out.writeUTF(name); out.writeUTF(id) }
            out.writeBoolean(settings.dnsProfileId != null)
            settings.dnsProfileId?.let(out::writeUTF)
            out.writeUTF(settings.captureMode.name)
            out.writeInt(settings.ipv4Rules.size)
            settings.ipv4Rules.forEach { rule ->
                out.writeUTF(rule.id)
                out.writeUTF(rule.profileId)
                out.writeUTF(rule.expression)
            }
            out.writeInt(settings.domainRules.size)
            settings.domainRules.forEach { rule ->
                out.writeUTF(rule.id); out.writeUTF(rule.profileId); out.writeUTF(rule.pattern)
            }
        }
        return Base64.getEncoder().encodeToString(bytes.toByteArray())
    }

    fun decode(raw: String?): SavedSettings {
        if (raw == null) return SavedSettings()
        try {
            val bytes = Base64.getDecoder().decode(raw)
            if (bytes.size > 1_000_000) throw SettingsCorrupt("Settings are too large")
            val input = DataInputStream(ByteArrayInputStream(bytes))
            val version = input.readInt()
            if (version !in 1..4) throw SettingsCorrupt("Unsupported settings version $version; settings were kept")
            val count = input.readInt()
            if (count !in 0..100) throw SettingsCorrupt("Invalid profile count")
            val profiles = List(count) {
                ServerProfile(input.readUTF(), input.readUTF(), input.readUTF(), input.readInt(), input.readInt(), input.readUTF())
            }
            val active = if (input.readBoolean()) input.readUTF() else null
            val selectedCount = input.readInt()
            if (selectedCount !in 0..1000) throw SettingsCorrupt("Invalid application count")
            val assignments = if (version == 1) {
                val packages = List(selectedCount) { input.readUTF() }
                if (packages.size != packages.toSet().size || (packages.isNotEmpty() && active == null))
                    throw SettingsCorrupt("Ambiguous legacy application selection")
                packages.associateWith { active!! }
            } else List(selectedCount) { input.readUTF() to input.readUTF() }.also { rows ->
                if (rows.map { it.first }.toSet().size != rows.size) throw SettingsCorrupt("Duplicate application assignment")
            }.toMap()
            val dns = if (version == 1) active?.takeIf { it in assignments.values }
                else if (input.readBoolean()) input.readUTF() else null
            val mode = if (version >= 3) CaptureMode.valueOf(input.readUTF()) else CaptureMode.ASSIGNED_APPS
            val rules = if (version >= 3) {
                val size = input.readInt()
                if (size !in 0..1000) throw SettingsCorrupt("Invalid IPv4 rule count")
                List(size) { SavedIpv4Rule(input.readUTF(), input.readUTF(), input.readUTF()) }
            } else emptyList()
            val domains = if (version >= 4) {
                val size = input.readInt()
                if (size !in 0..1000) throw SettingsCorrupt("Invalid domain rule count")
                List(size) { SavedDomainRule(input.readUTF(), input.readUTF(), input.readUTF()) }
            } else emptyList()
            if (input.available() != 0) throw SettingsCorrupt("Invalid settings document")
            return SavedSettings(4, profiles, active, assignments, dns, mode, rules, domains).also(::validate)
        } catch (ex: SettingsCorrupt) {
            throw ex
        } catch (_: Exception) {
            throw SettingsCorrupt("Settings are damaged; existing data was kept")
        }
    }

    fun validate(settings: SavedSettings) {
        if (settings.schemaVersion != 4) throw SettingsCorrupt("Unsupported settings version; settings were kept")
        if (settings.profiles.size > 100 || settings.profiles.map { it.id }.toSet().size != settings.profiles.size ||
            settings.profiles.map { it.secretRef }.toSet().size != settings.profiles.size) throw SettingsCorrupt("Invalid profiles")
        settings.profiles.forEach {
            if (runCatching { UUID.fromString(it.id) }.getOrNull()?.toString() != it.id ||
                runCatching { UUID.fromString(it.secretRef) }.getOrNull()?.toString() != it.secretRef ||
                it.name.isBlank() || it.name.length > 80) throw SettingsCorrupt("Invalid profile identity or name")
            try { SessionValidator.endpoint(it.address, it.firstPort.toString(), it.lastPort.toString()) }
            catch (_: IllegalArgumentException) { throw SettingsCorrupt("Invalid server endpoint") }
        }
        if (settings.activeProfileId != null && settings.profiles.none { it.id == settings.activeProfileId })
            throw SettingsCorrupt("Active profile is missing")
        if (settings.assignments.size > 1000 || settings.assignments.keys.any { !it.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+")) } ||
            settings.assignments.values.any { id -> settings.profiles.none { it.id == id } })
            throw SettingsCorrupt("Invalid application assignment")
        val used = settings.assignments.values.toSet() + settings.ipv4Rules.map { it.profileId } +
            settings.domainRules.map { it.profileId }
        // Legacy DNS selection is retained in the document format, but never selects a route.
        if (settings.ipv4Rules.size > 1000) throw SettingsCorrupt("Invalid IPv4 rule count")
        val parsed = try {
            settings.ipv4Rules.map { rule ->
                if (runCatching { UUID.fromString(rule.id) }.getOrNull()?.toString() != rule.id ||
                    settings.profiles.none { it.id == rule.profileId }) throw IllegalArgumentException()
                val interval = Ipv4Interval.parse(rule.expression)
                if (Ipv4Interval.normalize(rule.expression) != rule.expression) throw IllegalArgumentException()
                StaticIpv4Rule(rule.id, rule.profileId, interval)
            }
        } catch (_: IllegalArgumentException) { throw SettingsCorrupt("Invalid IPv4 rule") }
        try { StaticIpv4RuleSet(parsed) }
        catch (_: IllegalArgumentException) { throw SettingsCorrupt("IPv4 rules for different profiles overlap") }
        if (settings.domainRules.size > 1000) throw SettingsCorrupt("Invalid domain rule count")
        val domains = try { settings.domainRules.map { rule ->
            if (runCatching { UUID.fromString(rule.id) }.getOrNull()?.toString() != rule.id ||
                settings.profiles.none { it.id == rule.profileId }) throw IllegalArgumentException()
            DomainRule(rule.id, rule.profileId, rule.pattern)
        } } catch (_: IllegalArgumentException) { throw SettingsCorrupt("Invalid domain rule") }
        try { DomainRuleSet(domains) }
        catch (_: IllegalArgumentException) { throw SettingsCorrupt("Domain rules overlap or are duplicated") }
    }
}

class SettingsRepository(
    private val settingsStore: SettingsStore,
    private val secretStore: SecretStore,
    private val isSessionActive: () -> Boolean,
) {
    private val mutex = Mutex()
    suspend fun load(): SavedSettings = mutex.withLock { SettingsCodec.decode(settingsStore.read()) }

    private fun requireDisconnected() {
        check(!isSessionActive()) { "Disconnect the tunnel before changing settings" }
    }

    suspend fun saveProfile(id: String?, name: String, address: String, first: String, last: String,
                            replacement: SecretKeys?): SavedSettings = mutex.withLock {
        requireDisconnected()
        val old = SettingsCodec.decode(settingsStore.read())
        val existing = old.profiles.firstOrNull { it.id == id }
        require(id == null || existing != null) { "Profile no longer exists" }
        require(name.isNotBlank() && name.length <= 80) { "Enter a profile name (up to 80 characters)" }
        val endpoint = SessionValidator.endpoint(address, first, last)
        require(existing != null || replacement != null) { "Enter both keys" }
        replacement?.let { require(it.xor.size == 128 && it.swap.size == 8) { "Invalid key length" } }
        val newRef = if (replacement != null) UUID.randomUUID().toString() else existing!!.secretRef
        val profile = ServerProfile(existing?.id ?: UUID.randomUUID().toString(), name.trim(), endpoint.first,
            endpoint.second, endpoint.third, newRef)
        val profiles = if (existing == null) old.profiles + profile else old.profiles.map { if (it.id == id) profile else it }
        val updated = old.copy(profiles = profiles, activeProfileId = old.activeProfileId ?: profile.id)
        val encoded = SettingsCodec.encode(updated)
        currentCoroutineContext().ensureActive()
        // Once a new key may exist, finish the write before observing caller cancellation.
        // A write exception does not prove that DataStore did not commit: keep the new key.
        withContext(NonCancellable) {
            if (replacement != null) secretStore.put(newRef, replacement)
            settingsStore.write(encoded)
            if (existing != null && replacement != null) {
                try { secretStore.delete(existing.secretRef) }
                catch (ex: CancellationException) { throw ex }
                catch (_: Exception) { /* An unused old key is safe to retain. */ }
            }
            updated
        }
    }

    suspend fun renameProfile(id: String, name: String, address: String): SavedSettings = mutex.withLock {
        requireDisconnected()
        val old = SettingsCodec.decode(settingsStore.read())
        val existing = old.profiles.firstOrNull { it.id == id }
            ?: throw IllegalArgumentException("Profile no longer exists")
        require(name.isNotBlank() && name.length <= 80) { "Enter a profile name (up to 80 characters)" }
        require(SessionValidator.endpoint(address, "1", "1").first == existing.address) {
            "Server address changed; connect by SSH to load its settings"
        }
        val updated = old.copy(profiles = old.profiles.map { if (it.id == id) it.copy(name = name.trim()) else it })
        val encoded = SettingsCodec.encode(updated)
        currentCoroutineContext().ensureActive()
        withContext(NonCancellable) { settingsStore.write(encoded); updated }
    }

    suspend fun deleteProfile(id: String): SavedSettings = mutex.withLock {
        requireDisconnected()
        val old = SettingsCodec.decode(settingsStore.read())
        val profile = old.profiles.firstOrNull { it.id == id } ?: throw IllegalArgumentException("Profile no longer exists")
        require(id !in old.assignments.values && old.ipv4Rules.none { it.profileId == id } &&
            old.domainRules.none { it.profileId == id }) {
            "Remove application assignments, IPv4 rules, and domain rules before deleting this profile"
        }
        val remaining = old.profiles.filterNot { it.id == id }
        val updated = old.copy(profiles = remaining,
            activeProfileId = if (old.activeProfileId == id) remaining.firstOrNull()?.id else old.activeProfileId)
        val encoded = SettingsCodec.encode(updated)
        currentCoroutineContext().ensureActive()
        withContext(NonCancellable) {
            settingsStore.write(encoded)
            // If write throws, its commit status is unknown. Retain the old key.
            try { secretStore.delete(profile.secretRef) }
            catch (ex: CancellationException) { throw ex }
            catch (_: Exception) { /* An unused key is safe to retain. */ }
            updated
        }
    }

    suspend fun selectProfile(id: String): SavedSettings = mutate {
        require(it.profiles.any { profile -> profile.id == id }) { "Profile no longer exists" }
        it.copy(activeProfileId = id)
    }


    suspend fun togglePackage(name: String): SavedSettings = mutate {
        require(name.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))) { "Invalid package name" }
        val id = it.activeProfileId ?: throw IllegalArgumentException("Choose a profile")
        val assignments = if (name in it.assignments) it.assignments - name else it.assignments + (name to id)
        val used = assignments.values.toSet() + it.ipv4Rules.map { rule -> rule.profileId } +
            it.domainRules.map { rule -> rule.profileId }
        it.copy(assignments = assignments, dnsProfileId = it.dnsProfileId?.takeIf { dns -> dns in used }
            ?: id.takeIf { it in used } ?: used.sorted().firstOrNull())
    }

    suspend fun assignPackage(name: String, profileId: String?): SavedSettings = mutate {
        require(name.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))) { "Invalid package name" }
        require(profileId == null || it.profiles.any { profile -> profile.id == profileId }) { "Profile no longer exists" }
        val assignments = if (profileId == null) it.assignments - name else it.assignments + (name to profileId)
        val used = assignments.values.toSet() + it.ipv4Rules.map { rule -> rule.profileId } +
            it.domainRules.map { rule -> rule.profileId }
        it.copy(assignments = assignments, dnsProfileId = it.dnsProfileId?.takeIf { dns -> dns in used }
            ?: it.activeProfileId?.takeIf { active -> active in used } ?: used.sorted().firstOrNull())
    }

    suspend fun selectDnsProfile(id: String): SavedSettings = mutate {
        require(id in it.assignments.values || it.ipv4Rules.any { rule -> rule.profileId == id } ||
            it.domainRules.any { rule -> rule.profileId == id }) {
            "Assign an application, IPv4, or domain rule to this DNS profile first"
        }
        it.copy(dnsProfileId = id)
    }

    suspend fun saveIpv4Rule(id: String?, profileId: String, expression: String): SavedSettings = mutate { old ->
        require(old.profiles.any { it.id == profileId }) { "Profile no longer exists" }
        val canonical = Ipv4Interval.normalize(expression)
        val existing = old.ipv4Rules.firstOrNull { it.id == id }
        require(id == null || existing != null) { "Rule no longer exists" }
        val rule = SavedIpv4Rule(existing?.id ?: UUID.randomUUID().toString(), profileId, canonical)
        val rules = if (existing == null) old.ipv4Rules + rule else old.ipv4Rules.map { if (it.id == id) rule else it }
        val used = old.assignments.values.toSet() + rules.map { it.profileId } + old.domainRules.map { it.profileId }
        old.copy(ipv4Rules = rules, dnsProfileId = old.dnsProfileId?.takeIf { it in used } ?: profileId)
    }

    suspend fun deleteIpv4Rule(id: String): SavedSettings = mutate { old ->
        require(old.ipv4Rules.any { it.id == id }) { "Rule no longer exists" }
        val rules = old.ipv4Rules.filterNot { it.id == id }
        val used = old.assignments.values.toSet() + rules.map { it.profileId } + old.domainRules.map { it.profileId }
        old.copy(ipv4Rules = rules, dnsProfileId = old.dnsProfileId?.takeIf { it in used }
            ?: old.activeProfileId?.takeIf { it in used } ?: used.sorted().firstOrNull())
    }

    suspend fun saveDomainRule(id: String?, profileId: String, pattern: String): SavedSettings = mutate { old ->
        require(old.profiles.any { it.id == profileId }) { "Profile no longer exists" }
        val existing = old.domainRules.firstOrNull { it.id == id }
        require(id == null || existing != null) { "Rule no longer exists" }
        val rule = SavedDomainRule(existing?.id ?: UUID.randomUUID().toString(), profileId,
            DomainNames.pattern(pattern))
        val rules = if (existing == null) old.domainRules + rule else old.domainRules.map { if (it.id == id) rule else it }
        val used = old.assignments.values.toSet() + old.ipv4Rules.map { it.profileId } + rules.map { it.profileId }
        old.copy(domainRules = rules, dnsProfileId = old.dnsProfileId?.takeIf { it in used } ?: profileId)
    }

    suspend fun deleteDomainRule(id: String): SavedSettings = mutate { old ->
        require(old.domainRules.any { it.id == id }) { "Rule no longer exists" }
        val rules = old.domainRules.filterNot { it.id == id }
        val used = old.assignments.values.toSet() + old.ipv4Rules.map { it.profileId } + rules.map { it.profileId }
        old.copy(domainRules = rules, dnsProfileId = old.dnsProfileId?.takeIf { it in used }
            ?: old.activeProfileId?.takeIf { it in used } ?: used.sorted().firstOrNull())
    }

    private suspend fun mutate(change: (SavedSettings) -> SavedSettings): SavedSettings = mutex.withLock {
        requireDisconnected()
        val updated = change(SettingsCodec.decode(settingsStore.read()))
        val encoded = SettingsCodec.encode(updated)
        currentCoroutineContext().ensureActive()
        withContext(NonCancellable) {
            settingsStore.write(encoded)
            updated
        }
    }

    suspend fun snapshot(availablePackages: Set<String>, directAvailable: Boolean): SessionSettings = mutex.withLock {
        val saved = SettingsCodec.decode(settingsStore.read())
        val mode = if (directAvailable) CaptureMode.PUBLIC_IPV4_RULES else CaptureMode.ASSIGNED_APPS
        if (mode == CaptureMode.ASSIGNED_APPS)
            require(saved.assignments.isNotEmpty()) { "Choose at least one application" }
        else require(saved.assignments.isNotEmpty() || saved.ipv4Rules.isNotEmpty() || saved.domainRules.isNotEmpty()) {
            "Choose an application or add an IPv4 or domain rule before public capture"
        }
        val missing = saved.assignments.keys - availablePackages
        require(missing.isEmpty()) { "Selected applications are unavailable: ${missing.sorted().joinToString()}" }
        val needed = saved.assignments.values.toSet() +
            if (mode == CaptureMode.PUBLIC_IPV4_RULES)
                saved.ipv4Rules.map { it.profileId } + saved.domainRules.map { it.profileId }
            else emptySet()
        val profiles = saved.profiles.filter { it.id in needed }.associate { profile ->
            profile.id to SessionValidator.server(profile, secretStore.get(profile.secretRef))
        }
        val rules = if (mode == CaptureMode.PUBLIC_IPV4_RULES)
            saved.ipv4Rules.map { StaticIpv4Rule(it.id, it.profileId, Ipv4Interval.parse(it.expression)) }
        else emptyList()
        val domains = if (mode == CaptureMode.PUBLIC_IPV4_RULES)
            saved.domainRules.map { DomainRule(it.id, it.profileId, it.pattern) }
        else emptyList()
        SessionSettings(profiles, saved.assignments.toMap(), captureMode = mode,
            ipv4Rules = rules, domainRules = domains)
    }
}
